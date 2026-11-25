use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::guard::{Gate, shutdown_aborted};
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
#[cfg(test)]
pub(super) use super::tunnel_relay::pump;
#[cfg(not(any(test, feature = "test-support")))]
use super::tunnel_relay::pump;
#[cfg(any(test, feature = "test-support"))]
use super::tunnel_relay::pump_with_drain;
use super::tunnel_relay::tunnel_stalled;
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
        self.connect_via_chained_or_direct(host, port, gateway_port, true)
            .await
    }

    /// Outbound connection for AI / payment / Clean Room direct-mode traffic: routes through the
    /// chained proxy when active and FAILS CLOSED if the chained proxy is unreachable or refuses
    /// (zero fallback to `connect_direct`). Goes direct only when no chained proxy is active.
    pub(super) async fn connect_ai_transit(
        &self,
        host: &str,
        port: u16,
    ) -> Result<UpstreamStream, std::io::Error> {
        self.connect_ai_transit_with_port(host, port, self.bound_addr.port())
            .await
    }

    pub(super) async fn connect_ai_transit_with_port(
        &self,
        host: &str,
        port: u16,
        gateway_port: u16,
    ) -> Result<UpstreamStream, std::io::Error> {
        self.connect_via_chained_or_direct(host, port, gateway_port, false)
            .await
    }

    async fn connect_via_chained_or_direct(
        &self,
        host: &str,
        port: u16,
        gateway_port: u16,
        allow_direct_fallback: bool,
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
                Err(ChainedError::Unreachable(err)) => {
                    if !allow_direct_fallback {
                        return Err(std::io::Error::new(
                            err.kind(),
                            format!("upstream chained proxy unreachable (fail-closed): {err}"),
                        ));
                    }
                }
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
        // Scope `manual_killswitch` strictly to AI/payment/KYC hosts — never block or 503
        // non-AI transit apps (Discord, PUBG, RDP). Shutdown still aborts all tunnels.
        let guard_kill = crate::auditor::geo_matrix::is_payment_or_kyc_host(host);
        let mut kill_rx = self.guard.subscribe_killswitch();
        let mut shutdown_rx = self.guard.subscribe_shutdown_abort();
        if *shutdown_rx.borrow_and_update() || (guard_kill && *kill_rx.borrow_and_update()) {
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
        } else if guard_kill {
            self.connect_ai_transit(host, port).await
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
        if guard_kill && self.guard.is_manual_killswitch() {
            return send_status(client, "503 Service Unavailable", KILLSWITCH_MESSAGE).await;
        }
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;
        let res = if guard_kill {
            tokio::select! {
                res = tokio::io::copy_bidirectional(client, &mut target) => res.map(|_| ()),
                _ = killswitch_engaged(&mut kill_rx) => Err(killswitch_stopped()),
                _ = shutdown_aborted(&mut shutdown_rx) => Err(tunnel_stalled()),
            }
        } else {
            tokio::select! {
                res = tokio::io::copy_bidirectional(client, &mut target) => res.map(|_| ()),
                _ = shutdown_aborted(&mut shutdown_rx) => Err(tunnel_stalled()),
            }
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
            let target_res = {
                #[cfg(any(test, feature = "test-support"))]
                if let Some(tls) = &self.route_tls_override {
                    crate::proxy::upstream::connect_via_route_with_tls(
                        r,
                        host,
                        port,
                        Duration::from_secs(ROUTE_ENTRY_TIMEOUT_SECS),
                        tls,
                        self.bound_addr.port(),
                        chained.as_deref(),
                    )
                    .await
                } else {
                    connect_via_route_with_chained(
                        r,
                        host,
                        port,
                        Duration::from_secs(ROUTE_ENTRY_TIMEOUT_SECS),
                        self.bound_addr.port(),
                        chained.as_deref(),
                    )
                    .await
                }
                #[cfg(not(any(test, feature = "test-support")))]
                {
                    connect_via_route_with_chained(
                        r,
                        host,
                        port,
                        Duration::from_secs(ROUTE_ENTRY_TIMEOUT_SECS),
                        self.bound_addr.port(),
                        chained.as_deref(),
                    )
                    .await
                }
            };
            let mut target = match target_res {
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
            let res = {
                #[cfg(any(test, feature = "test-support"))]
                {
                    pump_with_drain(
                        client,
                        &mut target,
                        &self.guard,
                        TunnelPolicy::KillSwitchOnly,
                        provider,
                        watch,
                        self.half_close_drain_timeout,
                    )
                    .await
                }
                #[cfg(not(any(test, feature = "test-support")))]
                {
                    pump(
                        client,
                        &mut target,
                        &self.guard,
                        TunnelPolicy::KillSwitchOnly,
                        provider,
                        watch,
                    )
                    .await
                }
            };
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
            self.connect_ai_transit(host, port).await
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

        #[cfg(any(test, feature = "test-support"))]
        {
            pump_with_drain(
                client,
                &mut target,
                &self.guard,
                TunnelPolicy::FollowGate,
                provider,
                watch,
                self.half_close_drain_timeout,
            )
            .await
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
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
}
