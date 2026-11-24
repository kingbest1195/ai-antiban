use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::guard::{Gate, NetworkGuard, gate_closed, shutdown_aborted};
use crate::proxy::route_watch::RouteWatch;
use crate::proxy::upstream::handshakes::configure_tcp_stream;
use crate::proxy::upstream::{
    ChainedError, UpstreamStream, connect_via_chained_proxy, connect_via_route_with_chained,
};
use crate::routing::{Route, RouteDownReason, RouteSelection};

use super::responses::{
    KILLSWITCH_MESSAGE, is_peer_gone, killswitch_engaged, killswitch_stopped, send_bad_gateway,
    send_forbidden, send_routing_changed, send_status,
};
use super::{
    CHAINED_CONNECT_TIMEOUT_SECS, ProxyServer, ROUTE_ENTRY_TIMEOUT_SECS, TunnelPolicy,
    UPSTREAM_CONNECT_TIMEOUT_SECS,
};

impl ProxyServer {
    /// Direct connection for transit traffic: cached DNS, SSRF check of every answer and Happy
    /// Eyeballs across address families (see [`Transit::connect_direct`]).
    pub(super) async fn connect_direct(
        &self,
        host: &str,
        port: u16,
    ) -> Result<TcpStream, std::io::Error> {
        self.direct_connects.fetch_add(1, Ordering::SeqCst);
        self.transit.connect_direct(host, port).await
    }

    /// Outbound connection for transit or direct-mode traffic: through the chained proxy when
    /// there is one, with a single fallback to a direct connection if the proxy cannot be reached
    /// (not if it answers with an error status).
    pub(super) async fn connect_transit(
        &self,
        host: &str,
        port: u16,
    ) -> Result<UpstreamStream, std::io::Error> {
        self.connect_transit_with_port(host, port, self.bound_addr.port())
            .await
    }

    /// Same as [`Self::connect_transit`], but uses an explicit `gateway_port` for self-loop
    /// filtering (used by per-profile alias listeners so they exclude the main gateway port).
    pub(super) async fn connect_transit_with_port(
        &self,
        host: &str,
        port: u16,
        gateway_port: u16,
    ) -> Result<UpstreamStream, std::io::Error> {
        if let Some(cp) = self.transit.chained_proxy(gateway_port) {
            match connect_via_chained_proxy(
                &cp,
                host,
                port,
                Duration::from_secs(CHAINED_CONNECT_TIMEOUT_SECS),
                gateway_port,
            )
            .await
            {
                Ok(s) => return Ok(s),
                Err(ChainedError::Refused { status }) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("the upstream proxy refused the tunnel (status {status})"),
                    ));
                }
                Err(ChainedError::Unreachable(_)) => {} // fall back to direct, once
            }
        }
        self.connect_direct(host, port)
            .await
            .map(UpstreamStream::Plain)
    }

    /// Transit (non-AI) CONNECT: no audit, no gate. The relay never looks at the guard, so a
    /// network re-check (`Gate::Pending`) neither delays new transit connections nor cuts running ones.
    pub(super) async fn transit_tunnel(
        &self,
        client: &mut TcpStream,
        host: &str,
        port: u16,
    ) -> Result<(), std::io::Error> {
        configure_tcp_stream(client);
        // The manual kill-switch ("СТОП СЕТИ") stops transit traffic too; subscribe first so a
        // switch-on during the connect is noticed.
        let mut kill_rx = self.guard.subscribe_killswitch();
        let mut shutdown_rx = self.guard.subscribe_shutdown_abort();
        if *kill_rx.borrow_and_update() || *shutdown_rx.borrow_and_update() {
            return send_status(client, "503 Service Unavailable", KILLSWITCH_MESSAGE).await;
        }
        let connected = if let Some(redirect_addr) = self.upstream_redirect {
            self.direct_connects.fetch_add(1, Ordering::SeqCst);
            tokio::time::timeout(
                Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
                TcpStream::connect(redirect_addr),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "upstream redirect connect timeout",
                )
            })
            .and_then(|r| r)
            .map(|s| {
                configure_tcp_stream(&s);
                UpstreamStream::Plain(s)
            })
        } else {
            self.connect_transit(host, port).await
        };
        let mut target = match connected {
            Ok(s) => s,
            Err(e) => {
                let err_msg = format!("Failed to connect to target {host}:{port}: {e}");
                send_bad_gateway(client, &err_msg).await?;
                return Err(e);
            }
        };
        if self.guard.is_manual_killswitch() {
            return send_status(client, "503 Service Unavailable", KILLSWITCH_MESSAGE).await;
        }
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;
        let res = tokio::select! {
            res = tokio::io::copy_bidirectional(client, &mut target) => res.map(|_| ()),
            _ = killswitch_engaged(&mut kill_rx) => Err(killswitch_stopped()),
            _ = shutdown_aborted(&mut shutdown_rx) => Err(tunnel_stalled()),
        };
        match res {
            Err(e) if is_peer_gone(&e) => Ok(()),
            other => other,
        }
    }

    /// Opens the outbound connection and relays. `selection` is the route snapshot the audit used:
    /// it is re-read right before connecting (a different result means the user changed routing in
    /// the meantime: refuse, the client reconnects) and watched while the tunnel lives.
    pub(super) async fn tunnel_to_target(
        &self,
        client: &mut TcpStream,
        host: &str,
        port: u16,
        provider: Option<ProviderId>,
        selection: &RouteSelection,
    ) -> Result<(), std::io::Error> {
        if provider.is_none() && !matches!(selection, RouteSelection::Route(_)) {
            return self.transit_tunnel(client, host, port).await;
        }
        configure_tcp_stream(client);
        let route: Option<&Route> = match selection {
            RouteSelection::Route(r) => Some(r),
            _ => None,
        };
        let _tunnel_guard =
            if route.is_some() || provider.is_some() || ProviderId::from_host(host).is_some() {
                Some(self.state.stats().enter_tunnel())
            } else {
                None
            };

        // Subscribe first, then verify: nothing can change unnoticed from here on.
        let watch = provider.map(|p| RouteWatch::new(&self.state, p, selection.clone()));
        if let Some(w) = &watch
            && w.is_stale().await
        {
            return send_routing_changed(client).await;
        }

        if let Some(r) = route {
            let chained = self.transit.chained_proxy(self.bound_addr.port());
            let mut target = match connect_via_route_with_chained(
                r,
                host,
                port,
                Duration::from_secs(ROUTE_ENTRY_TIMEOUT_SECS),
                self.bound_addr.port(),
                chained.as_deref(),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    let provider = provider
                        .or_else(|| ProviderId::from_host(host))
                        .unwrap_or(ProviderId::Anthropic);
                    let detail = e.to_string();
                    return self
                        .refuse_route_down(
                            client,
                            host,
                            provider,
                            &r.id,
                            RouteDownReason::Unreachable,
                            Some(&detail),
                            false,
                        )
                        .await;
                }
            };
            self.state.route_health().mark_reachable(&r.id);
            // The kill-switch may have been engaged while we were connecting.
            if self.guard.is_manual_killswitch() {
                return send_forbidden(client, "Network kill-switch is engaged in Zastava.").await;
            }
            if let Some(w) = &watch
                && w.is_stale().await
            {
                return send_routing_changed(client).await;
            }
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            client.flush().await?;
            let res = pump(
                client,
                &mut target,
                &self.guard,
                TunnelPolicy::KillSwitchOnly,
                provider,
                watch,
            )
            .await;
            return match res {
                Err(e) if is_peer_gone(&e) => Ok(()),
                other => other,
            };
        }

        let abort_rx = self.guard.subscribe_tunnel_abort();
        let connect_res = if let Some(redirect_addr) = self.upstream_redirect {
            self.direct_connects.fetch_add(1, Ordering::SeqCst);
            tokio::time::timeout(
                Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
                TcpStream::connect(redirect_addr),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "upstream redirect connect timeout",
                )
            })
            .and_then(|r| r)
            .map(|s| {
                configure_tcp_stream(&s);
                UpstreamStream::Plain(s)
            })
        } else {
            self.connect_transit(host, port).await
        };

        let mut target = match connect_res {
            Ok(s) => s,
            Err(e) => {
                if provider.is_some() {
                    self.guard.wake_immediate_probe().await;
                }
                let err_msg = format!("Failed to connect to target {host}:{port}: {e}");
                send_bad_gateway(client, &err_msg).await?;
                return Err(e);
            }
        };

        if let Some(w) = &watch
            && w.is_stale().await
        {
            return send_routing_changed(client).await;
        }
        let gate_open = match provider {
            Some(p) => self.guard.gate_for(p) == Gate::Open,
            None => self.guard.gate() == Gate::Open,
        };
        if !gate_open
            || self.guard.is_manual_killswitch()
            || abort_rx.has_changed().unwrap_or(false)
        {
            return send_forbidden(
                client,
                "Network change blocked by Zastava Risk Auditor: connection interrupted during check.",
            )
            .await;
        }
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;

        pump(
            client,
            &mut target,
            &self.guard,
            TunnelPolicy::FollowGate,
            provider,
            watch,
        )
        .await
    }
}

/// Bidirectional relay that obeys the network guard. Direct tunnels (`FollowGate`): while the gate
/// is closed no byte is forwarded, and the session aborts when the route changes, the gate closes or
/// the manual kill-switch is engaged. Routed tunnels (`KillSwitchOnly`) are only stopped by the
/// manual kill-switch. Both end as soon as the routing of their provider changes (`watch`).
pub(super) async fn pump(
    client: &mut TcpStream,
    target: &mut UpstreamStream,
    guard: &Arc<NetworkGuard>,
    policy: TunnelPolicy,
    provider: Option<ProviderId>,
    watch: Option<RouteWatch>,
) -> Result<(), std::io::Error> {
    let relay = relay(client, target, guard, policy, provider);
    match watch {
        Some(mut w) => {
            tokio::select! {
                res = relay => res,
                _ = w.stale() => Err(tunnel_route_changed()),
            }
        }
        None => relay.await,
    }
}

async fn relay(
    client: &mut TcpStream,
    target: &mut UpstreamStream,
    guard: &Arc<NetworkGuard>,
    policy: TunnelPolicy,
    provider: Option<ProviderId>,
) -> Result<(), std::io::Error> {
    let (mut cr, mut cw) = client.split();
    if let UpstreamStream::Plain(tcp) = target {
        // Zero-overhead split for plain TCP (direct, SOCKS5, HTTP entries).
        let (mut tr, mut tw) = tcp.split();
        let c2t = forward(&mut cr, &mut tw, guard, policy, provider);
        let t2c = forward(&mut tr, &mut cw, guard, policy, provider);
        tokio::try_join!(c2t, t2c)?;
    } else {
        let (mut tr, mut tw) = tokio::io::split(target);
        let c2t = forward(&mut cr, &mut tw, guard, policy, provider);
        let t2c = forward(&mut tr, &mut cw, guard, policy, provider);
        tokio::try_join!(c2t, t2c)?;
    }
    Ok(())
}

fn tunnel_route_changed() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "tunnel aborted: the routing of this service changed",
    )
}

fn tunnel_stalled() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "tunnel aborted: network route changed or closed",
    )
}

async fn forward<R, W>(
    reader: &mut R,
    writer: &mut W,
    guard: &Arc<NetworkGuard>,
    policy: TunnelPolicy,
    provider: Option<ProviderId>,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match policy {
        TunnelPolicy::FollowGate => forward_follow_gate(reader, writer, guard, provider).await,
        TunnelPolicy::KillSwitchOnly => forward_killswitch_only(reader, writer, guard).await,
    }
}

async fn forward_follow_gate<R, W>(
    reader: &mut R,
    writer: &mut W,
    guard: &Arc<NetworkGuard>,
    provider: Option<ProviderId>,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut rx = match provider {
        Some(p) => guard.subscribe_for(p),
        None => guard.subscribe(),
    };
    let mut abort_rx = guard.subscribe_tunnel_abort();
    let mut kill_rx = guard.subscribe_killswitch();
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        // The manual kill-switch or any gate exit from Open immediately tears down direct tunnels.
        if *kill_rx.borrow_and_update()
            || *rx.borrow_and_update() != Gate::Open
            || abort_rx.has_changed().unwrap_or(false)
        {
            return Err(tunnel_stalled());
        }

        let n = tokio::select! {
            res = reader.read(&mut buf) => res?,
            _ = gate_closed(&mut rx) => {
                return Err(tunnel_stalled());
            }
            _ = abort_rx.changed() => {
                return Err(tunnel_stalled());
            }
            changed = kill_rx.changed() => {
                if changed.is_err() || *kill_rx.borrow_and_update() {
                    return Err(tunnel_stalled());
                }
                continue;
            }
        };

        if n == 0 {
            let _ = writer.flush().await;
            let _ = writer.shutdown().await;
            return Ok(());
        }

        // Data read right before the freeze is held back and the tunnel is torn down immediately.
        let current_gate = match provider {
            Some(p) => guard.gate_for(p),
            None => guard.gate(),
        };
        if current_gate != Gate::Open
            || *rx.borrow_and_update() != Gate::Open
            || guard.is_manual_killswitch()
            || abort_rx.has_changed().unwrap_or(false)
        {
            return Err(tunnel_stalled());
        }
        writer.write_all(&buf[..n]).await?;
    }
}

async fn forward_killswitch_only<R, W>(
    reader: &mut R,
    writer: &mut W,
    guard: &Arc<NetworkGuard>,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut kill_rx = guard.subscribe_killswitch();
    let mut shutdown_rx = guard.subscribe_shutdown_abort();
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        if *kill_rx.borrow_and_update() || *shutdown_rx.borrow_and_update() {
            return Err(tunnel_stalled());
        }
        let n = tokio::select! {
            res = reader.read(&mut buf) => res?,
            changed = kill_rx.changed() => {
                if changed.is_err() || *kill_rx.borrow_and_update() {
                    return Err(tunnel_stalled());
                }
                continue;
            }
            _ = shutdown_aborted(&mut shutdown_rx) => {
                return Err(tunnel_stalled());
            }
        };
        if n == 0 {
            let _ = writer.flush().await;
            let _ = writer.shutdown().await;
            return Ok(());
        }
        if guard.is_manual_killswitch() || *shutdown_rx.borrow_and_update() {
            return Err(tunnel_stalled());
        }
        writer.write_all(&buf[..n]).await?;
    }
}
