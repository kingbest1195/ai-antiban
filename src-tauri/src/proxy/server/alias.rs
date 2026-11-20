//! Per-profile loopback alias routing (P0 Zero Non-AI Split-IP Leak).
//!
//! Traffic arriving on a profile alias listener NEVER falls back to `transit_tunnel` or
//! `RouteSelection::Direct`. All AI and non-AI `CONNECT` and `plain HTTP` requests route
//! strictly through `alias_route_id` (or `FollowGate` when explicitly bound to `DIRECT_ROUTE_ID`).

use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::network::current_timestamp;
use crate::proxy::guard::Gate;
use crate::proxy::http_forward::{ParsedRequest, RequestForm, relay_exchange};
use crate::proxy::upstream::{UpstreamStream, connect_via_route_with_chained};
use crate::routing::{DIRECT_ROUTE_ID, Route, RouteDownReason, RouteSelection};

use super::responses::{
    KILLSWITCH_MESSAGE, is_peer_gone, killswitch_engaged, killswitch_stopped, send_bad_gateway,
    send_canary_intercepted, send_forbidden, send_routing_changed, send_status,
};
use super::tunnel::pump;
use super::{
    PLAIN_HTTP_IDLE_TIMEOUT_SECS, ProxyServer, ROUTE_ENTRY_TIMEOUT_SECS, TunnelPolicy,
    UPSTREAM_CONNECT_TIMEOUT_SECS,
};

impl ProxyServer {
    pub(super) async fn resolve_alias_selection(
        &self,
    ) -> Result<RouteSelection, (RouteDownReason, String)> {
        let Some(route_id) = self.alias_route_id.as_deref() else {
            return Err((RouteDownReason::Missing, "unassigned".to_string()));
        };
        if route_id == DIRECT_ROUTE_ID {
            return Ok(RouteSelection::Direct);
        }
        let Some(route) = self.state.get_route(route_id).await else {
            return Err((RouteDownReason::Missing, route_id.to_string()));
        };
        if let Err(reason) = route.check_usable(current_timestamp()) {
            return Err((reason, route.id));
        }
        Ok(RouteSelection::Route(route))
    }

    pub(super) async fn handle_alias_connect(
        &self,
        client: &mut TcpStream,
        host: &str,
        port: u16,
        provider_opt: Option<ProviderId>,
        is_canary: bool,
    ) -> Result<(), std::io::Error> {
        if self.guard.is_manual_killswitch() {
            if is_canary {
                return send_canary_intercepted(client).await;
            }
            return send_forbidden(
                client,
                "Network kill-switch is engaged in Zastava: alias traffic is stopped.",
            )
            .await;
        }

        let provider = provider_opt.unwrap_or(ProviderId::Anthropic);
        let mut routing_rx = self.state.subscribe_routing();
        let selection = match self.resolve_alias_selection().await {
            Ok(sel) => sel,
            Err((reason, route_id)) => {
                return self
                    .refuse_route_down(client, host, provider, &route_id, reason, None, is_canary)
                    .await;
            }
        };

        match selection {
            RouteSelection::Route(r) => {
                let chained = self.transit.chained_proxy(self.bound_addr.port());
                let mut target = match connect_via_route_with_chained(
                    &r,
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
                        let detail = e.to_string();
                        return self
                            .refuse_route_down(
                                client,
                                host,
                                provider,
                                &r.id,
                                RouteDownReason::Unreachable,
                                Some(&detail),
                                is_canary,
                            )
                            .await;
                    }
                };
                self.state.route_health().mark_reachable(&r.id);
                if self.guard.is_manual_killswitch() {
                    return send_forbidden(client, "Network kill-switch is engaged in Zastava.")
                        .await;
                }
                if alias_route_is_stale(&self.state, &r).await {
                    return send_routing_changed(client).await;
                }
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                client.flush().await?;
                tokio::select! {
                    res = pump(
                        client,
                        &mut target,
                        &self.guard,
                        TunnelPolicy::KillSwitchOnly,
                        provider_opt,
                        None,
                    ) => res,
                    _ = wait_alias_route_stale(&self.state, &r, &mut routing_rx) => {
                        Err(alias_route_changed())
                    }
                }
            }
            RouteSelection::Direct => {
                self.guard.ensure_fresh().await;
                if self.guard.gate_for(provider) != Gate::Open {
                    return send_forbidden(
                        client,
                        "Alias direct gate is closed by Zastava Network Guard.",
                    )
                    .await;
                }
                let tcp = match self.connect_alias_direct(host, port).await {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = format!("Failed to connect to target {host}:{port}: {e}");
                        send_bad_gateway(client, &msg).await?;
                        return Err(e);
                    }
                };
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                client.flush().await?;
                let mut target = UpstreamStream::Plain(tcp);
                pump(
                    client,
                    &mut target,
                    &self.guard,
                    TunnelPolicy::FollowGate,
                    provider_opt,
                    None,
                )
                .await
            }
            RouteSelection::Missing(id) => {
                self.refuse_route_down(
                    client,
                    host,
                    provider,
                    &id,
                    RouteDownReason::Missing,
                    None,
                    is_canary,
                )
                .await
            }
            RouteSelection::Invalid(why) => {
                self.refuse_route_down(
                    client,
                    host,
                    provider,
                    "invalid",
                    RouteDownReason::Invalid,
                    Some(&why),
                    is_canary,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_alias_plain_http(
        &self,
        client: &mut TcpStream,
        req: &ParsedRequest,
        body_prefix: &[u8],
    ) -> Result<(), std::io::Error> {
        let mut kill_rx = self.guard.subscribe_killswitch();
        if *kill_rx.borrow_and_update() {
            return send_status(client, "503 Service Unavailable", KILLSWITCH_MESSAGE).await;
        }
        let mut routing_rx = self.state.subscribe_routing();

        let selection = match self.resolve_alias_selection().await {
            Ok(sel) => sel,
            Err((reason, _)) => {
                return send_forbidden(
                    client,
                    &format!(
                        "Zastava alias route unavailable: {}. Connection NOT sent directly.",
                        reason.message()
                    ),
                )
                .await;
            }
        };

        let (mut target, route_snapshot) = match selection {
            RouteSelection::Route(r) => {
                let chained = self.transit.chained_proxy(self.bound_addr.port());
                match connect_via_route_with_chained(
                    &r,
                    &req.host,
                    req.port,
                    Duration::from_secs(ROUTE_ENTRY_TIMEOUT_SECS),
                    self.bound_addr.port(),
                    chained.as_deref(),
                )
                .await
                {
                    Ok(s) => {
                        if alias_route_is_stale(&self.state, &r).await {
                            return send_routing_changed(client).await;
                        }
                        (s, Some(r))
                    }
                    Err(e) => {
                        let msg = format!(
                            "Zastava alias route {} unreachable for {}:{}: {e}",
                            r.id, req.host, req.port
                        );
                        send_bad_gateway(client, &msg).await?;
                        return Err(std::io::Error::other(msg));
                    }
                }
            }
            RouteSelection::Direct => {
                self.guard.ensure_fresh().await;
                if self.guard.gate_for(ProviderId::Anthropic) != Gate::Open {
                    return send_forbidden(
                        client,
                        "Alias direct gate is closed by Zastava Network Guard.",
                    )
                    .await;
                }
                match self.connect_alias_direct(&req.host, req.port).await {
                    Ok(s) => (UpstreamStream::Plain(s), None),
                    Err(e) => {
                        let msg =
                            format!("Failed to connect to target {}:{}: {e}", req.host, req.port);
                        send_bad_gateway(client, &msg).await?;
                        return Err(e);
                    }
                }
            }
            RouteSelection::Missing(_) | RouteSelection::Invalid(_) => {
                return send_forbidden(client, "Zastava alias route unavailable.").await;
            }
        };

        let head = req.build_head(RequestForm::Origin);
        let write_res = match &mut target {
            UpstreamStream::Plain(tcp) => tcp.write_all(&head).await,
            UpstreamStream::Tls(tls) => tls.write_all(&head).await,
        };
        if let Err(e) = write_res {
            send_bad_gateway(client, "Failed to send request to target via alias.").await?;
            return Err(e);
        }

        let relay_res = match &mut target {
            UpstreamStream::Plain(tcp) => {
                let relay = relay_exchange(
                    client,
                    tcp,
                    &req.body,
                    body_prefix,
                    Duration::from_secs(PLAIN_HTTP_IDLE_TIMEOUT_SECS),
                );
                tokio::select! {
                    res = relay => res,
                    _ = killswitch_engaged(&mut kill_rx) => Err(killswitch_stopped()),
                    _ = wait_optional_alias_route_stale(&self.state, route_snapshot.as_ref(), &mut routing_rx) => {
                        Err(alias_route_changed())
                    }
                }
            }
            UpstreamStream::Tls(tls) => {
                let relay = relay_exchange(
                    client,
                    tls.as_mut(),
                    &req.body,
                    body_prefix,
                    Duration::from_secs(PLAIN_HTTP_IDLE_TIMEOUT_SECS),
                );
                tokio::select! {
                    res = relay => res,
                    _ = killswitch_engaged(&mut kill_rx) => Err(killswitch_stopped()),
                    _ = wait_optional_alias_route_stale(&self.state, route_snapshot.as_ref(), &mut routing_rx) => {
                        Err(alias_route_changed())
                    }
                }
            }
        };

        match relay_res {
            Err(e) if is_peer_gone(&e) => Ok(()),
            other => other,
        }
    }

    async fn connect_alias_direct(
        &self,
        host: &str,
        port: u16,
    ) -> Result<TcpStream, std::io::Error> {
        if let Some(redirect_addr) = self.upstream_redirect {
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
        } else {
            self.connect_direct(host, port).await
        }
    }
}

fn alias_route_changed() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "alias tunnel aborted: bound route changed or disabled",
    )
}

async fn alias_route_is_stale(state: &crate::state::AppState, expected: &Route) -> bool {
    let Some(current) = state.get_route(&expected.id).await else {
        return true;
    };
    if &current != expected {
        return true;
    }
    current.check_usable(current_timestamp()).is_err()
}

async fn wait_alias_route_stale(
    state: &crate::state::AppState,
    expected: &Route,
    rx: &mut tokio::sync::watch::Receiver<u64>,
) {
    if alias_route_is_stale(state, expected).await {
        return;
    }
    loop {
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    std::future::pending::<()>().await;
                }
                if alias_route_is_stale(state, expected).await {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                if alias_route_is_stale(state, expected).await {
                    return;
                }
            }
        }
    }
}

async fn wait_optional_alias_route_stale(
    state: &crate::state::AppState,
    expected: Option<&Route>,
    rx: &mut tokio::sync::watch::Receiver<u64>,
) {
    match expected {
        Some(r) => wait_alias_route_stale(state, r, rx).await,
        None => std::future::pending::<()>().await,
    }
}
