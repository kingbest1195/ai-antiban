use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tauri::Emitter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::Auditor;
use crate::proxy::guard::{Gate, NetworkGuard, gate_closed, wait_open};
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, HoldQueue, HoldResolution, PHASE_READY, RiskInterceptPayload,
    build_gate_reason,
};
use crate::proxy::http_forward::{
    MAX_HEAD_BYTES, ParsedRequest, RequestForm, find_head_end, parse_request, relay_exchange,
    split_authority,
};
use crate::proxy::pac::generate_pac_script;
use crate::proxy::route_watch::RouteWatch;
use crate::proxy::transit::Transit;
use crate::proxy::upstream::{
    ChainedError, UpstreamStream, connect_chained_tcp, connect_via_chained_proxy, connect_via_route,
};
use crate::routing::{INVALID_PROFILE_ROUTE_ID, Route, RouteDownReason, RouteSelection};
use crate::state::{AppState, IpHistoryEntry};

pub const DEFAULT_PROXY_PORT: u16 = 8899;
pub const FALLBACK_PROXY_PORT: u16 = 8900;
const FIRST_REQUEST_TIMEOUT_SECS: u64 = 10;
const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 15;
/// A plain HTTP exchange with no byte from either side for this long is abandoned. Not applied to
/// CONNECT tunnels (long downloads, SSH and the like may be silent).
const PLAIN_HTTP_IDLE_TIMEOUT_SECS: u64 = 60;
/// Connect (+ CONNECT handshake) timeout for the chained proxy; after it transit traffic falls
/// back to a direct connection once.
const CHAINED_CONNECT_TIMEOUT_SECS: u64 = 8;
const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const ALLOWED_TUNNEL_PORTS: &[u16] = &[80, 443, 8443];
/// Per-entry connect timeout when tunneling through a route.
const ROUTE_ENTRY_TIMEOUT_SECS: u64 = 8;
/// The crash-test canary is only reported as PROTECTED when its route really carries a tunnel.
const CANARY_PROBE_TIMEOUT_MS: u64 = 600;
const CANARY_PROBE_HOST: &str = "1.1.1.1";
/// `route://unavailable` is emitted at most once per route in this window.
const ROUTE_ALERT_THROTTLE_SECS: u64 = 30;
/// Stats verdict for connections refused because their route is down (fail-closed).
pub const VERDICT_ROUTE_DOWN: &str = "ROUTE_DOWN";

/// Payload of the `route://unavailable` event (no secrets).
#[derive(Debug, Clone, Serialize)]
pub struct RouteUnavailablePayload {
    pub route_id: String,
    pub provider: String,
    /// `disabled` | `expired` | `no_entries` | `missing` | `unreachable`
    pub reason: String,
    pub message: String,
}

/// How an established tunnel reacts to the network guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelPolicy {
    /// Direct traffic: frozen while the gate is closed, aborted on network change or kill-switch.
    FollowGate,
    /// Routed traffic (fixed exit): only the manual kill-switch stops it.
    KillSwitchOnly,
    // Both policies additionally end when the provider's routing changes (see `RouteWatch`).
}

pub struct ProxyServer {
    pub bound_addr: SocketAddr,
    listener: TcpListener,
    auditor: Auditor,
    state: AppState,
    pub hold_queue: Arc<HoldQueue>,
    pub guard: Arc<NetworkGuard>,
    pub coverage: Arc<crate::proxy::CoverageTracker>,
    app_handle: Option<tauri::AppHandle>,
    pub upstream_redirect: Option<SocketAddr>,
    conn_limiter: Arc<Semaphore>,
    route_alerts: std::sync::Mutex<HashMap<String, Instant>>,
    direct_connects: AtomicU64,
    /// Outbound side for transit (non-AI) traffic: DNS cache, Happy Eyeballs, chained proxy.
    transit: Arc<Transit>,
    hold_ttl: Duration,
}

impl ProxyServer {
    /// Attempts to bind to 127.0.0.1:8899, with fallback to 8900 or ephemeral port.
    pub async fn bind(
        auditor: Auditor,
        state: AppState,
        hold_queue: Arc<HoldQueue>,
        app_handle: Option<tauri::AppHandle>,
    ) -> Result<Self, std::io::Error> {
        let listener = match TcpListener::bind(format!("127.0.0.1:{DEFAULT_PROXY_PORT}")).await {
            Ok(l) => l,
            Err(_) => match TcpListener::bind(format!("127.0.0.1:{FALLBACK_PROXY_PORT}")).await {
                Ok(l) => l,
                Err(_) => TcpListener::bind("127.0.0.1:0").await?,
            },
        };

        let bound_addr = listener.local_addr()?;
        auditor.resolver.set_gateway_port(bound_addr.port());
        let coverage = Arc::new(crate::proxy::CoverageTracker::new());
        coverage.set_gateway_addr(bound_addr);

        Ok(Self {
            bound_addr,
            listener,
            auditor,
            state,
            hold_queue,
            guard: Arc::new(NetworkGuard::new()),
            coverage,
            app_handle,
            upstream_redirect: None,
            conn_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            route_alerts: std::sync::Mutex::new(HashMap::new()),
            direct_connects: AtomicU64::new(0),
            transit: Arc::new(Transit::system()),
            hold_ttl: Duration::from_secs(DEFAULT_HOLD_TTL_SECS),
        })
    }

    /// Binds to an ephemeral port (127.0.0.1:0) for isolated integration testing.
    pub async fn bind_ephemeral(
        auditor: Auditor,
        state: AppState,
        hold_queue: Arc<HoldQueue>,
        upstream_redirect: Option<SocketAddr>,
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let bound_addr = listener.local_addr()?;
        auditor.resolver.set_gateway_port(bound_addr.port());
        let coverage = Arc::new(crate::proxy::CoverageTracker::new());
        coverage.set_gateway_addr(bound_addr);

        Ok(Self {
            bound_addr,
            listener,
            auditor,
            state,
            hold_queue,
            guard: Arc::new(NetworkGuard::new()),
            coverage,
            app_handle: None,
            upstream_redirect,
            conn_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            route_alerts: std::sync::Mutex::new(HashMap::new()),
            direct_connects: AtomicU64::new(0),
            transit: Arc::new(Transit::system()),
            hold_ttl: Duration::from_secs(DEFAULT_HOLD_TTL_SECS),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_hold_ttl(mut self, ttl: Duration) -> Self {
        self.hold_ttl = ttl;
        self
    }

    /// Replaces the outbound side for transit traffic (test seam: resolver, dialer, clock and
    /// chained proxy are injected; the SSRF policy itself is not part of it).
    pub fn with_transit(mut self, transit: Transit) -> Self {
        self.transit = Arc::new(transit);
        self
    }

    /// Number of direct (non-routed) outbound connections attempted, including the test redirect.
    pub fn direct_connect_count(&self) -> u64 {
        self.direct_connects.load(Ordering::SeqCst)
    }

    /// Runs the proxy accept loop in the background.
    pub async fn run(self: Arc<Self>) {
        loop {
            match self.listener.accept().await {
                Ok((stream, client_addr)) => {
                    let permit = match Arc::clone(&self.conn_limiter).try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("Proxy connection limit reached, dropping {client_addr}");
                            continue;
                        }
                    };
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(err) = server.handle_connection(stream, client_addr).await {
                            eprintln!("Proxy connection error from {client_addr}: {err}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Proxy accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    async fn handle_connection(
        &self,
        mut client: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let mut buffer = [0u8; 4096];
        let bytes_read = match tokio::time::timeout(
            Duration::from_secs(FIRST_REQUEST_TIMEOUT_SECS),
            client.read(&mut buffer),
        )
        .await
        {
            Ok(res) => res?,
            Err(_) => return Ok(()), // idle / slow client: drop silently
        };
        if bytes_read == 0 {
            return Ok(());
        }

        let request_str = String::from_utf8_lossy(&buffer[..bytes_read]);
        let mut lines = request_str.lines();
        let request_line = match lines.next() {
            Some(l) => l,
            None => return Ok(()),
        };

        let user_agent = lines
            .find(|line| line.to_ascii_lowercase().starts_with("user-agent:"))
            .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()));

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");

        // 1. Route GET /proxy.pac or /pac.js (supports relative "/proxy.pac" or full "http://127.0.0.1:8899/proxy.pac").
        // An absolute URI counts only when it points at the gateway itself: a request for some
        // other site's /proxy.pac is plain HTTP to forward.
        if method == "GET" && self.is_pac_target(target) {
            // A PAC download is counted apart from AI requests.
            self.coverage.record_incoming(
                client_addr.port(),
                user_agent,
                crate::proxy::coverage::TrafficKind::PacFetch,
            );
            return self.handle_pac_request(&mut client).await;
        }

        // 2. Route CONNECT <host>:<port>
        if method == "CONNECT" {
            return self
                .handle_connect_request(&mut client, target, client_addr.port(), user_agent)
                .await;
        }

        // 3. Absolute-form request (`GET http://host/path`): plain HTTP through the gateway.
        if is_absolute_http_target(target) {
            return self
                .handle_plain_http(&mut client, &buffer[..bytes_read], client_addr.port())
                .await;
        }

        // 4. Generic HTTP health / info response: only for requests to the gateway itself
        // (origin-form `GET /` and the like).
        send_gateway_info(&mut client).await
    }

    /// Builds the live PAC script excluding domains of any disabled providers.
    pub async fn build_pac_script(&self) -> String {
        let matrix = self.auditor.rules.provider_matrix.read().await;
        let st = self.state.get_data().await;
        let domains = crate::proxy::pac::get_all_ai_domains_filtered(
            &matrix,
            &st.custom_ai_domains,
            &st.disabled_providers,
        );

        let gateway_port = self.bound_addr.port();
        let chained_proxy = crate::sysproxy::get_chained_proxy().filter(|cp| {
            let port = cp
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .unwrap_or(0);
            port != gateway_port && port != 0
        });

        generate_pac_script(
            &domains,
            &self.bound_addr.to_string(),
            chained_proxy.as_deref(),
        )
    }

    async fn try_silent_recovery_on_startup(
        &self,
        provider: ProviderId,
        selection: &RouteSelection,
        routed: bool,
    ) -> bool {
        if self.guard.is_manual_killswitch()
            || self.guard.pause_mode() != crate::proxy::guard::PauseMode::None
            || self.guard.has_baseline().await
            || !self.state.is_provider_blocked(provider.as_str()).await
        {
            return false;
        }
        let Ok(report) = self
            .auditor
            .evaluate_all_with(provider, &self.state, selection, false)
            .await
        else {
            return false;
        };
        let st = self.state.get_data().await;
        if crate::proxy::guard::report_allowed_for_state(&report, &st, routed) {
            let _ = self.state.unblock_provider(provider.as_str()).await;
            self.guard.ensure_open_for_verified(&report.telemetry).await;
            return true;
        }
        false
    }

    async fn handle_pac_request(&self, client: &mut TcpStream) -> Result<(), std::io::Error> {
        let pac_script = self.build_pac_script().await;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            pac_script.len(),
            pac_script
        );

        client.write_all(response.as_bytes()).await?;
        client.flush().await?;
        Ok(())
    }

    /// True for `/proxy.pac` / `/pac.js` asked of the gateway: origin-form, or an absolute URI whose
    /// authority is the gateway.
    fn is_pac_target(&self, target: &str) -> bool {
        let path = if is_absolute_http_target(target) {
            let rest = &target[7..];
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, ""),
            };
            if !self.is_gateway_authority(authority) {
                return false;
            }
            path
        } else {
            target
        };
        path.starts_with("/proxy.pac")
            || path.contains("/proxy.pac")
            || path.starts_with("/pac.js")
            || path.contains("/pac.js")
    }

    /// True when `authority` (`host[:port]`) addresses this gateway (loopback name / address with
    /// the bound port).
    fn is_gateway_authority(&self, authority: &str) -> bool {
        let Some((host, port)) = split_authority(authority) else {
            return false;
        };
        if port.unwrap_or(80) != self.bound_addr.port() {
            return false;
        }
        host == "localhost"
            || host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback() || ip == self.bound_addr.ip())
    }

    /// Plain HTTP forwarding (`GET http://host/path`, POST, HEAD, ...) for public non-AI hosts.
    /// Hosts of AI services are never forwarded this way: they work over HTTPS and must pass the
    /// gateway's policy (audit, route, gate). Requests addressed to the gateway itself are not
    /// forwarded (loop) and get the info page.
    async fn handle_plain_http(
        &self,
        client: &mut TcpStream,
        first: &[u8],
        _peer_port: u16,
    ) -> Result<(), std::io::Error> {
        let mut buf = first.to_vec();
        let head_end = loop {
            if let Some(n) = find_head_end(&buf) {
                break n;
            }
            if buf.len() >= MAX_HEAD_BYTES {
                return send_status(
                    client,
                    "431 Request Header Fields Too Large",
                    "Request head is too large.",
                )
                .await;
            }
            let mut chunk = [0u8; 4096];
            let n = match tokio::time::timeout(
                Duration::from_secs(FIRST_REQUEST_TIMEOUT_SECS),
                client.read(&mut chunk),
            )
            .await
            {
                Ok(res) => res?,
                Err(_) => return Ok(()),
            };
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };

        let req = match parse_request(&buf[..head_end]) {
            Ok(r) => r,
            Err(e) => {
                let status = match e {
                    crate::proxy::http_forward::HeadError::Malformed(_) => "400 Bad Request",
                    crate::proxy::http_forward::HeadError::Unsupported(_) => "501 Not Implemented",
                };
                return send_status(client, status, e.message()).await;
            }
        };
        let (host, port) = (req.host.clone(), req.port);

        // A request for the gateway's own address: the info page, never a forward (no loop).
        let own_authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        if self.is_gateway_authority(&own_authority) {
            return send_gateway_info(client).await;
        }

        // Same policy as a CONNECT to this host: port, internal names, loopback / private IPs.
        // The port list (80 / 443 / 8443) is deliberately not widened for plain HTTP: the gateway
        // must not become a port scanner or a bridge to arbitrary local-style services.
        if let Err(reason) = validate_tunnel_target(&host, port, self.bound_addr.port()) {
            return send_forbidden(client, reason).await;
        }

        let custom_domains = self.state.get_custom_ai_domains().await;
        if let Some(provider) = ProviderId::from_host_with_custom(&host, &custom_domains)
            && !self.state.is_provider_disabled(provider.as_str()).await
        {
            self.state
                .stats()
                .record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
            return send_forbidden(
                client,
                "AI services are reachable over HTTPS only: Zastava does not forward plain HTTP requests to them.",
            )
            .await;
        }

        self.state.stats().record_direct_bypassed_host(&host);
        self.forward_plain_http(client, &req, &buf[head_end..])
            .await
    }

    /// Connects to the chained proxy and sends the absolute-form request head. `None` when there
    /// is no chained proxy or it cannot be reached (the caller then goes direct, once).
    async fn open_chained_plain(&self, req: &ParsedRequest) -> Option<TcpStream> {
        if self.upstream_redirect.is_some() {
            return None;
        }
        let gateway_port = self.bound_addr.port();
        let cp = self.transit.chained_proxy(gateway_port)?;
        let mut s = connect_chained_tcp(
            &cp,
            Duration::from_secs(CHAINED_CONNECT_TIMEOUT_SECS),
            gateway_port,
        )
        .await
        .ok()?;
        s.write_all(&req.build_head(RequestForm::Absolute))
            .await
            .ok()?;
        Some(s)
    }

    async fn forward_plain_http(
        &self,
        client: &mut TcpStream,
        req: &ParsedRequest,
        body_prefix: &[u8],
    ) -> Result<(), std::io::Error> {
        // The manual kill-switch ("СТОП СЕТИ") stops everything that goes through Zastava.
        let mut kill_rx = self.guard.subscribe_killswitch();
        if *kill_rx.borrow_and_update() {
            return send_status(client, "503 Service Unavailable", KILLSWITCH_MESSAGE).await;
        }

        // Through the chained proxy first (absolute-form, the proxy does the rest). Only a failure
        // to connect / send the head counts as "unreachable": the answer of the proxy is final.
        let chained_stream = self.open_chained_plain(req).await;

        let mut upstream = match chained_stream {
            Some(s) => s,
            None => {
                let connected = if let Some(redirect_addr) = self.upstream_redirect {
                    self.direct_connects.fetch_add(1, Ordering::SeqCst);
                    TcpStream::connect(redirect_addr).await
                } else {
                    self.connect_direct(&req.host, req.port).await
                };
                let mut s = match connected {
                    Ok(s) => s,
                    Err(e) => {
                        let msg =
                            format!("Failed to connect to target {}:{}: {e}", req.host, req.port);
                        send_bad_gateway(client, &msg).await?;
                        return Err(e);
                    }
                };
                if let Err(e) = s.write_all(&req.build_head(RequestForm::Origin)).await {
                    send_bad_gateway(client, "Failed to send the request to the target.").await?;
                    return Err(e);
                }
                s
            }
        };

        // Transit traffic is not tied to the gate: a network re-check never cuts a transfer.
        // Only the manual kill-switch cuts it (and the idle timeout).
        let relay = relay_exchange(
            client,
            &mut upstream,
            &req.body,
            body_prefix,
            Duration::from_secs(PLAIN_HTTP_IDLE_TIMEOUT_SECS),
        );
        let res = tokio::select! {
            res = relay => res,
            _ = killswitch_engaged(&mut kill_rx) => Err(killswitch_stopped()),
        };
        match res {
            Err(e) if is_peer_gone(&e) => Ok(()),
            other => other,
        }
    }

    async fn handle_connect_request(
        &self,
        client: &mut TcpStream,
        raw_target: &str,
        peer_port: u16,
        user_agent: Option<String>,
    ) -> Result<(), std::io::Error> {
        let (host, port) = parse_host_port(raw_target);

        if let Err(reason) = validate_tunnel_target(&host, port, self.bound_addr.port()) {
            return send_forbidden(client, reason).await;
        }

        let is_canary = host == "canary-test.anthropic.zastava.local";
        let st_snapshot = self.state.get_data().await;
        let provider_opt = ProviderId::from_host_with_custom(&host, &st_snapshot.custom_ai_domains)
            .filter(|p| !st_snapshot.is_provider_disabled(p.as_str()));

        let provider = match provider_opt {
            Some(p) => {
                // Only a tunnel to an enabled AI host is an AI request (the canary is Zastava's
                // own probe). Disabled providers & transit traffic pass through directly.
                if !is_canary {
                    self.coverage.record_incoming(
                        peer_port,
                        user_agent,
                        crate::proxy::coverage::TrafficKind::AiRequest,
                    );
                }
                p
            }
            None => {
                // Direct pass-through for non-AI or monitoring-disabled domains: allows terminal
                // users to set HTTPS_PROXY cleanly without interfering with excluded providers.
                self.state.stats().record_direct_bypassed_host(&host);
                return self
                    .tunnel_to_target(client, &host, port, None, &RouteSelection::Direct)
                    .await;
            }
        };

        // Route selection (fail-closed): once a route is chosen for this provider, the connection
        // either goes through it or is refused — never directly. This one snapshot is used for the
        // audit AND for the tunnel; the tunnel re-checks it right before it connects and watches it
        // for as long as it lives (`RouteWatch`).
        let selection = self.state.route_selection(provider.as_str()).await;
        let route: Option<Route> = match &selection {
            RouteSelection::Direct => None,
            RouteSelection::Missing(id) => {
                return self
                    .refuse_route_down(
                        client,
                        &host,
                        provider,
                        id,
                        RouteDownReason::Missing,
                        None,
                        is_canary,
                    )
                    .await;
            }
            RouteSelection::Invalid(why) => {
                return self
                    .refuse_route_down(
                        client,
                        &host,
                        provider,
                        INVALID_PROFILE_ROUTE_ID,
                        RouteDownReason::Invalid,
                        Some(why),
                        is_canary,
                    )
                    .await;
            }
            RouteSelection::Route(r) => {
                if let Err(reason) = r.check_usable(crate::auditor::network::current_timestamp()) {
                    return self
                        .refuse_route_down(client, &host, provider, &r.id, reason, None, is_canary)
                        .await;
                }
                Some(r.clone())
            }
        };

        if route.is_some() {
            // Fixed exit IP: local network / VPN changes do not concern this provider.
            // Only the manual kill-switch ("СТОП СЕТИ") stops it.
            if self.guard.is_manual_killswitch() {
                self.state
                    .stats()
                    .record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
                if is_canary {
                    return send_canary_intercepted(client).await;
                }
                return send_forbidden(
                    client,
                    "Network kill-switch is engaged in Zastava: all AI traffic is stopped.",
                )
                .await;
            }
        } else {
            // Step 0: Fast Kernel Route Check & Network guard — a sudden IP change freezes every connection until the
            // user confirms the new network (or the old IP comes back).
            if !self.state.is_split_tunnel_mode().await
                && self.guard.check_route_fingerprint_sync(None)
            {
                self.auditor.resolver.invalidate_direct_cache().await;
                self.guard
                    .clear_pause_on_network_change(Some(&self.state), false)
                    .await;
            }

            self.guard.ensure_fresh().await;
            match self.guard.gate_for(provider) {
                Gate::Open => {}
                Gate::Pending => {
                    self.state.stats().record_intercepted(
                        &host,
                        provider.as_str(),
                        "BLOCKED",
                        "??",
                    );
                    if is_canary {
                        return send_canary_intercepted(client).await;
                    }
                    if self.guard.await_decision_for(provider).await != Gate::Open {
                        return send_forbidden(
                        client,
                        "Network change blocked by Zastava Risk Auditor: connection was not confirmed.",
                    )
                    .await;
                    }
                }
                Gate::Blocked => {
                    if !self
                        .try_silent_recovery_on_startup(provider, &selection, route.is_some())
                        .await
                    {
                        self.state.stats().record_intercepted(
                            &host,
                            provider.as_str(),
                            "BLOCKED",
                            "??",
                        );
                        if is_canary {
                            return send_canary_intercepted(client).await;
                        }
                        return send_forbidden(
                        client,
                        "Network change blocked by Zastava Risk Auditor: switch back to the trusted IP or confirm the new network.",
                    )
                    .await;
                    }
                }
            }
        }

        // Step 1: Check if provider is blocked
        if self.state.is_provider_blocked(provider.as_str()).await
            && !self
                .try_silent_recovery_on_startup(provider, &selection, route.is_some())
                .await
        {
            self.state
                .stats()
                .record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
            if is_canary {
                return send_canary_intercepted(client).await;
            }
            return send_forbidden(
                client,
                "Requests to this provider are blocked until network change.",
            )
            .await;
        }

        // Step 2: Check if provider has active session allowance
        if self
            .state
            .is_provider_session_allowed(provider.as_str())
            .await
        {
            if is_canary {
                return self
                    .canary_protected(client, &host, provider, route.as_ref(), "ALLOWED")
                    .await;
            }
            self.state
                .stats()
                .record_protected(&host, provider.as_str(), "ALLOWED");
            return self
                .tunnel_to_target(client, &host, port, Some(provider), &selection)
                .await;
        }

        // Step 3: Run comprehensive risk audit (on this provider's own egress).
        // If `guard.restore_epoch()` advances mid-audit (network recovered cleanly while probing
        // the old network), re-run once against the restored state/cache before deciding.
        let mut attempt = 0u8;
        let (report, st_after_audit) = loop {
            let pre_audit_epoch = self.guard.restore_epoch();
            let eval_res = self
                .auditor
                .evaluate_all_with(provider, &self.state, &selection, false)
                .await;
            match eval_res {
                Ok(r) => {
                    let st_now = self.state.get_data().await;
                    if route.is_none()
                        && attempt == 0
                        && self.guard.restore_epoch() != pre_audit_epoch
                        && !crate::proxy::guard::report_allowed_for_state(&r, &st_now, false)
                    {
                        attempt += 1;
                        continue;
                    }
                    break (r, st_now);
                }
                Err(e) if route.is_some() => {
                    let r = route.as_ref().expect("checked");
                    return self
                        .refuse_route_down(
                            client,
                            &host,
                            provider,
                            &r.id,
                            RouteDownReason::Unreachable,
                            Some(&e),
                            is_canary,
                        )
                        .await;
                }
                Err(e) => {
                    if route.is_none()
                        && attempt == 0
                        && self.guard.restore_epoch() != pre_audit_epoch
                    {
                        attempt += 1;
                        continue;
                    }
                    eprintln!("Auditor evaluation failed: {e}");
                    self.state
                        .stats()
                        .record_intercepted(&host, provider.as_str(), "ERROR", "??");
                    if is_canary {
                        return send_canary_intercepted(client).await;
                    }
                    // In case of auditor error, fall back to hold for safety
                    return send_forbidden(client, &format!("Audit error: {e}")).await;
                }
            }
        };

        // Step 4: Allow silently when verdict is Green, Yellow (`no_critical_and_geo_ok`),
        // `(provider, exit_ip)` is in `trusted_exceptions`, or IP matches pinned IP on allowed geo.
        if crate::proxy::guard::report_allowed_for_state(&report, &st_after_audit, route.is_some())
        {
            if is_canary {
                return self
                    .canary_protected(
                        client,
                        &host,
                        provider,
                        route.as_ref(),
                        &report.telemetry.country_code,
                    )
                    .await;
            }
            if crate::proxy::guard::report_no_critical_and_geo_ok(&report)
                || crate::proxy::guard::is_report_pinned_travel_only(&report, &st_after_audit)
            {
                let entry = IpHistoryEntry::new(
                    report.telemetry.ip.clone(),
                    report.telemetry.country_code.clone(),
                    report.telemetry.asn,
                    report.telemetry.resolved_at,
                );
                let _ = self
                    .state
                    .record_ip_history_for_selection(provider.as_str(), &selection, entry)
                    .await;
            }
            self.state.stats().record_protected(
                &host,
                provider.as_str(),
                &report.telemetry.country_code,
            );
            return self
                .tunnel_to_target(client, &host, port, Some(provider), &selection)
                .await;
        }

        // If critical/blocked and is canary test, immediately return intercepted status (<5ms response)
        if is_canary {
            self.state.stats().record_intercepted(
                &host,
                provider.as_str(),
                "BLOCKED",
                &report.telemetry.country_code,
            );
            return send_canary_intercepted(client).await;
        }

        // Already-blocked alert suppression: never pop up a new alert if provider is already blocked.
        if st_after_audit.blocked_providers.contains(provider.as_str())
            || self.guard.gate_for(provider) == Gate::Blocked
        {
            self.state.stats().record_intercepted(
                &host,
                provider.as_str(),
                "BLOCKED",
                &report.telemetry.country_code,
            );
            return send_forbidden(
                client,
                "Requests to this provider are blocked until network change.",
            )
            .await;
        }

        // Step 5: Non-excepted Critical / Blocked Geo / Strict Pinning mismatch -> apply preset InterceptionBehavior
        match st_after_audit.interception_behavior {
            crate::state::InterceptionBehavior::AutoLockSilent
            | crate::state::InterceptionBehavior::AutoAllowTrusted => {
                self.state.stats().record_intercepted(
                    &host,
                    provider.as_str(),
                    "BLOCKED",
                    &report.telemetry.country_code,
                );
                let _ = self.state.block_provider(provider.as_str()).await;
                self.guard.sync_gates_with_state(&self.state).await;
                return send_forbidden(client, "Auto-locked by Zastava rule").await;
            }
            crate::state::InterceptionBehavior::AskPopup => {
                // proceed with hold_queue and show_and_position_alert_popup
            }
        }

        self.state.stats().record_intercepted(
            &host,
            provider.as_str(),
            "HELD",
            &report.telemetry.country_code,
        );
        let hold_epoch = self.guard.restore_epoch();
        let (hold_id, rx, is_leader) = self
            .hold_queue
            .register_or_coalesce_provider(Uuid::new_v4().to_string(), provider.as_str())
            .await;

        if is_leader {
            let payload = RiskInterceptPayload {
                id: hold_id.clone(),
                provider,
                host: host.clone(),
                report: Some(report.clone()),
                ttl_seconds: DEFAULT_HOLD_TTL_SECS,
                scope: "provider".to_string(),
                network_change: None,
                is_simulation: false,
                detected_at_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                phase: PHASE_READY.to_string(),
                gate_reason: Some(build_gate_reason(Some(&report), None, false)),
            };

            // Emit event to UI and bring emergency modal to front once per active provider hold.
            self.hold_queue.set_alert(payload.clone());
            if let Some(app) = &self.app_handle {
                let _ = app.emit("interceptor://risk-detected", &payload);
                crate::show_and_position_alert_popup(app);
            }
        }

        // Wait up to hold_ttl (default 60s) for user action
        let resolution = tokio::time::timeout(self.hold_ttl, rx).await;

        match resolution {
            Ok(Ok(HoldResolution::Allow)) => {
                if self.guard.is_manual_killswitch() {
                    return send_forbidden(
                        client,
                        "Network kill-switch is engaged in Zastava.",
                    )
                    .await;
                }
                let entry = IpHistoryEntry::new(
                    report.telemetry.ip.clone(),
                    report.telemetry.country_code.clone(),
                    report.telemetry.asn,
                    report.telemetry.resolved_at,
                );
                let _ = self
                    .state
                    .record_ip_history_for_selection(provider.as_str(), &selection, entry)
                    .await;
                self.state.stats().record_protected(
                    &host,
                    provider.as_str(),
                    &report.telemetry.country_code,
                );
                self.tunnel_to_target(client, &host, port, Some(provider), &selection)
                    .await
            }
            Ok(Ok(HoldResolution::Superseded)) => {
                self.hold_queue.remove(&hold_id).await;
                if let Some(app) = &self.app_handle
                    && self.hold_queue.current_alert().is_none()
                {
                    crate::popup::hide_alert_popup(app);
                    let _ = app.emit("interceptor://resolved", "");
                }
                let st_now = self.state.get_data().await;
                let provider_disabled = st_now.is_provider_disabled(provider.as_str());
                let provider_routed =
                    crate::routing::select_route_id(&st_now, provider.as_str()).is_some();
                if !self.guard.is_manual_killswitch() && provider_routed && route.is_none() {
                    return send_routing_changed(client).await;
                }
                if !self.guard.is_manual_killswitch()
                    && (provider_disabled
                        || (!st_now.blocked_providers.contains(provider.as_str())
                            && self.guard.gate_for(provider) == Gate::Open))
                {
                    self.state
                        .stats()
                        .record_protected(&host, provider.as_str(), "OK");
                    return self
                        .tunnel_to_target(client, &host, port, Some(provider), &selection)
                        .await;
                }
                send_forbidden(
                    client,
                    "Connection hold superseded by network or policy update.",
                )
                .await
            }
            Ok(Ok(HoldResolution::Block)) => {
                self.hold_queue.remove(&hold_id).await;
                let st_now = self.state.get_data().await;
                let now_allowed = self.guard.restore_epoch() != hold_epoch
                    || st_now.is_provider_disabled(provider.as_str())
                    || crate::routing::select_route_id(&st_now, provider.as_str()).is_some()
                    || st_now
                        .session_allowed_providers
                        .contains(provider.as_str())
                    || crate::proxy::guard::report_allowed_for_state(
                        &report,
                        &st_now,
                        route.is_some(),
                    );
                if !now_allowed && !st_now.blocked_providers.contains(provider.as_str()) {
                    let _ = self.state.block_provider(provider.as_str()).await;
                    self.guard.sync_gates_with_state(&self.state).await;
                }
                send_forbidden(
                    client,
                    "Connection held and blocked by Zastava Risk Auditor.",
                )
                .await
            }
            Ok(Err(_)) => {
                self.hold_queue.remove(&hold_id).await;
                let st_now = self.state.get_data().await;
                if self.guard.restore_epoch() != hold_epoch
                    && !self.guard.is_manual_killswitch()
                    && !st_now.blocked_providers.contains(provider.as_str())
                    && self.guard.gate_for(provider) == Gate::Open
                {
                    return self
                        .tunnel_to_target(client, &host, port, Some(provider), &selection)
                        .await;
                }
                send_forbidden(
                    client,
                    "Connection held and blocked by Zastava Risk Auditor.",
                )
                .await
            }
            Err(_) => {
                let st_now = self.state.get_data().await;
                let epoch_changed = self.guard.restore_epoch() != hold_epoch;
                let provider_disabled = st_now.is_provider_disabled(provider.as_str());
                let provider_routed =
                    crate::routing::select_route_id(&st_now, provider.as_str()).is_some();
                let session_allowed = st_now
                    .session_allowed_providers
                    .contains(provider.as_str());
                let now_allowed = epoch_changed
                    || provider_disabled
                    || provider_routed
                    || session_allowed
                    || crate::proxy::guard::report_allowed_for_state(
                        &report,
                        &st_now,
                        route.is_some(),
                    );

                if now_allowed {
                    self.hold_queue
                        .resolve(&hold_id, HoldResolution::Superseded)
                        .await;
                    if let Some(app) = &self.app_handle
                        && self.hold_queue.current_alert().is_none()
                    {
                        crate::popup::hide_alert_popup(app);
                        let _ = app.emit("interceptor://resolved", "");
                    }
                    if !self.guard.is_manual_killswitch() && provider_routed && route.is_none() {
                        return send_routing_changed(client).await;
                    }
                    if !self.guard.is_manual_killswitch()
                        && (provider_disabled
                            || (!st_now.blocked_providers.contains(provider.as_str())
                                && self.guard.gate_for(provider) == Gate::Open))
                    {
                        self.state
                            .stats()
                            .record_protected(&host, provider.as_str(), "OK");
                        return self
                            .tunnel_to_target(client, &host, port, Some(provider), &selection)
                            .await;
                    }
                    return send_forbidden(
                        client,
                        "Connection hold superseded by network or policy update.",
                    )
                    .await;
                }

                // Hold TTL expired without a user decision: resolve any coalesced waiters as Block
                // and persist the block so critical providers do not stay inconsistently open.
                let timed_out_active = self
                    .hold_queue
                    .resolve(&hold_id, HoldResolution::Block)
                    .await;
                if timed_out_active
                    || (!session_allowed
                        && !st_now.is_ip_trusted_for_provider(
                            provider.as_str(),
                            &report.telemetry.ip,
                        ))
                {
                    let _ = self.state.block_provider(provider.as_str()).await;
                    self.guard.sync_gates_with_state(&self.state).await;
                }
                if let Some(app) = &self.app_handle
                    && self.hold_queue.current_alert().is_none()
                {
                    crate::popup::hide_alert_popup(app);
                    let _ = app.emit("interceptor://resolved", "");
                }
                send_forbidden(
                    client,
                    "Connection held and blocked by Zastava Risk Auditor.",
                )
                .await
            }
        }
    }

    /// Direct connection for transit traffic: cached DNS, SSRF check of every answer and Happy
    /// Eyeballs across address families (see [`Transit::connect_direct`]).
    async fn connect_direct(&self, host: &str, port: u16) -> Result<TcpStream, std::io::Error> {
        self.direct_connects.fetch_add(1, Ordering::SeqCst);
        self.transit.connect_direct(host, port).await
    }

    /// Outbound connection for a transit (non-AI) CONNECT: through the chained proxy when there is
    /// one, with a single fallback to a direct connection if the proxy cannot be reached (not if
    /// it answers with an error status).
    async fn connect_transit(
        &self,
        host: &str,
        port: u16,
    ) -> Result<UpstreamStream, std::io::Error> {
        let gateway_port = self.bound_addr.port();
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
    async fn transit_tunnel(
        &self,
        client: &mut TcpStream,
        host: &str,
        port: u16,
    ) -> Result<(), std::io::Error> {
        // The manual kill-switch ("СТОП СЕТИ") stops transit traffic too; subscribe first so a
        // switch-on during the connect is noticed.
        let mut kill_rx = self.guard.subscribe_killswitch();
        if *kill_rx.borrow_and_update() {
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
            .map(UpstreamStream::Plain)
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
        };
        match res {
            Err(e) if is_peer_gone(&e) => Ok(()),
            other => other,
        }
    }

    /// Fail-closed refusal for a provider whose route cannot carry traffic: records a
    /// `ROUTE_DOWN` verdict, emits `route://unavailable` (throttled) and answers 502/403.
    #[allow(clippy::too_many_arguments)]
    async fn refuse_route_down(
        &self,
        client: &mut TcpStream,
        host: &str,
        provider: ProviderId,
        route_id: &str,
        reason: RouteDownReason,
        detail: Option<&str>,
        is_canary: bool,
    ) -> Result<(), std::io::Error> {
        self.state
            .stats()
            .record_intercepted(host, provider.as_str(), VERDICT_ROUTE_DOWN, "??");
        if reason == RouteDownReason::Unreachable {
            self.state
                .route_health()
                .mark_unreachable(route_id, detail.unwrap_or(reason.message()));
        }
        self.emit_route_unavailable(route_id, provider, reason, detail);
        if is_canary {
            return send_canary_intercepted(client).await;
        }
        // The client of the gateway only gets a generic reason: no entry node addresses, no key
        // details (those stay in the UI event and the route health).
        let msg = format!(
            "Zastava route for {} is unavailable: {}. The connection was NOT sent directly (fail-closed).",
            provider.as_str(),
            reason.message()
        );
        if reason == RouteDownReason::Unreachable {
            send_bad_gateway(client, &msg).await
        } else {
            send_forbidden(client, &msg).await
        }
    }

    fn emit_route_unavailable(
        &self,
        route_id: &str,
        provider: ProviderId,
        reason: RouteDownReason,
        detail: Option<&str>,
    ) {
        let now = Instant::now();
        {
            let Ok(mut alerts) = self.route_alerts.lock() else {
                return;
            };
            if let Some(last) = alerts.get(route_id)
                && now.duration_since(*last) < Duration::from_secs(ROUTE_ALERT_THROTTLE_SECS)
            {
                return;
            }
            alerts.insert(route_id.to_string(), now);
        }
        if let Some(app) = &self.app_handle {
            let payload = RouteUnavailablePayload {
                route_id: route_id.to_string(),
                provider: provider.as_str().to_string(),
                reason: reason.as_str().to_string(),
                message: detail
                    .unwrap_or(reason.message_ru())
                    .chars()
                    .take(300)
                    .collect(),
            };
            let _ = app.emit("route://unavailable", &payload);
        }
    }

    /// Crash-test canary: PROTECTED only when the provider's route really carries a tunnel.
    async fn canary_protected(
        &self,
        client: &mut TcpStream,
        host: &str,
        provider: ProviderId,
        route: Option<&Route>,
        country: &str,
    ) -> Result<(), std::io::Error> {
        if let Some(r) = route {
            let probe = connect_via_route(
                r,
                CANARY_PROBE_HOST,
                443,
                Duration::from_millis(CANARY_PROBE_TIMEOUT_MS),
                self.bound_addr.port(),
            )
            .await;
            match probe {
                Ok(_) => self.state.route_health().mark_reachable(&r.id),
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
                            true,
                        )
                        .await;
                }
            }
        }
        self.state
            .stats()
            .record_protected(host, provider.as_str(), country);
        send_canary_protected(client).await
    }

    /// Opens the outbound connection and relays. `selection` is the route snapshot the audit used:
    /// it is re-read right before connecting (a different result means the user changed routing in
    /// the meantime: refuse, the client reconnects) and watched while the tunnel lives.
    async fn tunnel_to_target(
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
            let mut target = match connect_via_route(
                r,
                host,
                port,
                Duration::from_secs(ROUTE_ENTRY_TIMEOUT_SECS),
                self.bound_addr.port(),
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
            return pump(
                client,
                &mut target,
                &self.guard,
                TunnelPolicy::KillSwitchOnly,
                provider,
                watch,
            )
            .await;
        }

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
        } else {
            self.connect_direct(host, port).await
        };

        let target_stream = match connect_res {
            Ok(s) => s,
            Err(e) => {
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
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;

        let mut target = UpstreamStream::Plain(target_stream);
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

const KILLSWITCH_MESSAGE: &str = "Сеть остановлена вручную";

/// Completes when the manual kill-switch is (or becomes) engaged. Lowering the flag later does
/// not matter: the caller has already dropped its connection.
async fn killswitch_engaged(rx: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

fn killswitch_stopped() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "connection stopped by the manual kill-switch",
    )
}

fn is_absolute_http_target(target: &str) -> bool {
    target
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
}

/// A peer that went away mid-transfer is the normal end of a transit connection, not an error.
fn is_peer_gone(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

async fn send_gateway_info(client: &mut TcpStream) -> Result<(), std::io::Error> {
    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nConnection: close\r\n\r\nZastava Gateway Active\n";
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

async fn send_status(
    client: &mut TcpStream,
    status: &str,
    reason: &str,
) -> Result<(), std::io::Error> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}",
        reason.len(),
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

async fn send_bad_gateway(client: &mut TcpStream, reason: &str) -> Result<(), std::io::Error> {
    let resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reason.len(),
        reason
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

async fn send_routing_changed(client: &mut TcpStream) -> Result<(), std::io::Error> {
    let reason =
        "Zastava routing for this service changed while the connection was being set up: retry.";
    let resp = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reason.len(),
        reason
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

async fn send_canary_intercepted(client: &mut TcpStream) -> Result<(), std::io::Error> {
    let resp = "HTTP/1.1 503 Service Unavailable\r\nX-Zastava-Status: INTERCEPTED_BY_KILLSWITCH\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

async fn send_canary_protected(client: &mut TcpStream) -> Result<(), std::io::Error> {
    let resp = "HTTP/1.1 200 OK\r\nX-Zastava-Status: PROTECTED\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

/// Bidirectional relay that obeys the network guard. Direct tunnels (`FollowGate`): while the gate
/// is closed no byte is forwarded, and the session aborts when the route changes, the gate closes or
/// the manual kill-switch is engaged. Routed tunnels (`KillSwitchOnly`) are only stopped by the
/// manual kill-switch. Both end as soon as the routing of their provider changes (`watch`).
async fn pump(
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
    match target {
        // Zero-overhead split for plain TCP (direct, SOCKS5, HTTP entries).
        UpstreamStream::Plain(tcp) => {
            let (mut tr, mut tw) = tcp.split();
            let c2t = forward(&mut cr, &mut tw, guard, policy, provider);
            let t2c = forward(&mut tr, &mut cw, guard, policy, provider);
            tokio::try_join!(c2t, t2c)?;
        }
        UpstreamStream::Tls(tls) => {
            let (mut tr, mut tw) = tokio::io::split(tls.as_mut());
            let c2t = forward(&mut cr, &mut tw, guard, policy, provider);
            let t2c = forward(&mut tr, &mut cw, guard, policy, provider);
            tokio::try_join!(c2t, t2c)?;
        }
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
    let mut buf = vec![0u8; 16 * 1024];

    loop {
        // The manual kill-switch stops direct tunnels as well, whatever the gate says.
        if *kill_rx.borrow_and_update() {
            return Err(tunnel_stalled());
        }
        if !wait_open(&mut rx).await {
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
            let _ = writer.shutdown().await;
            return Ok(());
        }

        // Data read right before the freeze is held back until the user decides.
        let current_gate = match provider {
            Some(p) => guard.gate_for(p),
            None => guard.gate(),
        };
        if !wait_open(&mut rx).await || current_gate != Gate::Open || guard.is_manual_killswitch() {
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
    let mut buf = vec![0u8; 16 * 1024];

    loop {
        if *kill_rx.borrow_and_update() {
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
        };
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        if guard.is_manual_killswitch() {
            return Err(tunnel_stalled());
        }
        writer.write_all(&buf[..n]).await?;
    }
}

pub fn parse_host_port(target: &str) -> (String, u16) {
    let trimmed = target.trim();
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some((ipv6_host, after_bracket)) = rest.split_once(']')
    {
        let port = after_bracket
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(443);
        return (ipv6_host.trim().to_string(), port);
    }

    // If there are multiple colons (unbracketed IPv6 literal without port)
    if trimmed.matches(':').count() > 1 {
        return (trimmed.to_string(), 443);
    }

    if let Some((h, p)) = trimmed.rsplit_once(':') {
        let port = p.parse::<u16>().unwrap_or(443);
        let clean_host = h.trim().trim_end_matches('.').to_string();
        (clean_host, port)
    } else {
        (trimmed.trim_end_matches('.').to_string(), 443)
    }
}

/// IPv4 address embedded in an IPv6 one: IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
/// (`::a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`).
pub fn embedded_ipv4(v6: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if v6.is_loopback() || v6.is_unspecified() {
        return None;
    }
    let s = v6.segments();
    // Covers both `::ffff:a.b.c.d` and the deprecated `::a.b.c.d` (excluding `::` and `::1`).
    if let Some(v4) = v6.to_ipv4() {
        return Some(v4);
    }
    // NAT64 well-known prefix 64:ff9b::/96.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
        return Some(std::net::Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    // 6to4: the IPv4 address sits in bits 16..48.
    if s[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    None
}

/// Checks whether an IP address is loopback, private (RFC1918 / RFC4193), link-local,
/// cloud metadata (`169.254.169.254`), broadcast, multicast, unspecified, reserved
/// (`0.0.0.0/8`, `240.0.0.0/4`) or an IPv6 form that embeds such an IPv4 address.
pub fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // "This network" (0.0.0.0/8) and reserved / future use (240.0.0.0/4)
                || octets[0] == 0
                || octets[0] >= 240
                // Shared address space (RFC 6598: 100.64.0.0/10)
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
                // IETF protocol assignments & benchmarking (192.0.0.0/24, 198.18.0.0/15)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        }
        IpAddr::V6(v6) => {
            if let Some(inner) = embedded_ipv4(v6) {
                return is_forbidden_ip(&IpAddr::V4(inner));
            }
            let s = v6.segments();
            let seg0 = s[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique Local (fc00::/7)
                || (seg0 & 0xfe00) == 0xfc00
                // Link-Local unicast (fe80::/10)
                || (seg0 & 0xffc0) == 0xfe80
                // Local-use NAT64 (64:ff9b:1::/48)
                || (seg0 == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001)
                // Discard-only (100::/64)
                || (seg0 == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                // Documentation (2001:db8::/32)
                || (seg0 == 0x2001 && s[1] == 0x0db8)
        }
    }
}

/// Returns true if the IP belongs to the benchmarking / TUN FakeIP network range (`198.18.0.0/15`).
/// Used by VPN / TUN software such as sing-box, Throne, Nekoray, Hiddify, Clash in FakeIP mode.
pub fn is_tun_fake_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                let octets = mapped_v4.octets();
                octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
            } else {
                false
            }
        }
    }
}

/// True for `localhost` and local / internal DNS suffixes (`.local`, `.internal`, `.home.arpa`, …).
pub fn is_internal_hostname(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h.ends_with(".home.arpa")
        || h == "metadata.google.internal"
}

/// Validates target host and port against SSRF, local proxy recursion, and port scanning.
pub fn validate_tunnel_target(
    host: &str,
    port: u16,
    bound_proxy_port: u16,
) -> Result<(), &'static str> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return Err("Invalid empty target host.");
    }

    // Safely allow the local VPN crash-test canary hostname through validation
    if h == "canary-test.anthropic.zastava.local" {
        return Ok(());
    }

    if port == bound_proxy_port
        || port == DEFAULT_PROXY_PORT
        || port == FALLBACK_PROXY_PORT
        || !ALLOWED_TUNNEL_PORTS.contains(&port)
    {
        return Err("SSRF Protection: target port is not permitted by Zastava Gateway.");
    }

    if is_internal_hostname(&h) {
        return Err("SSRF Protection: local and internal hostnames are forbidden.");
    }

    if let Ok(ip) = h.parse::<IpAddr>()
        && is_forbidden_ip(&ip)
    {
        return Err(
            "SSRF Protection: direct connections to loopback or private IPs are forbidden.",
        );
    }

    Ok(())
}

async fn send_forbidden(client: &mut TcpStream, reason: &str) -> Result<(), std::io::Error> {
    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reason.len(),
        reason
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}

#[cfg(test)]
mod transit_tests;

#[cfg(test)]
mod coverage_count_tests {
    use super::*;
    use crate::proxy::coverage::{CoverageEnv, PacSource};
    use crate::proxy::hold_queue::HoldQueue;
    use crate::state::AppState;
    use crate::sysproxy::browser_policies::FakePolicyStore;
    use crate::sysproxy::platform::FakePlatform;

    fn offline_test_auditor() -> Auditor {
        use crate::auditor::AuditEnv;
        use crate::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
        use crate::auditor::seams::{HttpProbeOutcome, LookupOutcome};

        let env = AuditEnv {
            dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
            probe: Arc::new(FakeProbe::new(HttpProbeOutcome::Timeout)),
            udp: Arc::new(FakeUdp::new()),
            system: Arc::new(FakeSystem::healthy()),
        };
        Auditor::with_env(env).expect("offline test auditor")
    }

    async fn started() -> Arc<ProxyServer> {
        crate::sysproxy::force_os_dry_run();
        let auditor = offline_test_auditor();
        let server = Arc::new(
            ProxyServer::bind_ephemeral(
                auditor,
                AppState::new_in_memory(),
                Arc::new(HoldQueue::new()),
                None,
            )
            .await
            .expect("bind"),
        );
        let srv = Arc::clone(&server);
        tokio::spawn(async move { srv.run().await });
        server
    }

    async fn request(addr: SocketAddr, text: &str) -> Option<String> {
        let mut c = TcpStream::connect(addr).await.ok()?;
        c.write_all(text.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut buf)).await;
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    #[tokio::test]
    async fn proxy_pac_is_counted_apart_and_gateway_addr_is_the_real_one() {
        let server = started().await;
        let addr = server.bound_addr;
        let req = format!(
            "GET http://{addr}/proxy.pac HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: curl/8.7.1\r\nConnection: close\r\n\r\n"
        );
        let Some(resp) = request(addr, &req).await else {
            return; // loopback is not available in this sandbox
        };
        assert!(resp.contains("HTTP/1.1 200 OK"), "{resp}");
        // The health page is not an AI request either.
        let _ = request(addr, "GET / HTTP/1.1\r\nUser-Agent: curl/8.7.1\r\n\r\n").await;

        let platform = FakePlatform::new();
        let policy_store = FakePolicyStore::new();
        let env = CoverageEnv {
            platform: &platform,
            policy_store: &*policy_store,
            files: None,
            pac_source: PacSource::Services,
            sysproxy_enabled: false,
            cli_protection_enabled: false,
            chained_proxy: None,
            jetbrains_xml_confirmed: false,
        };
        let snap = server.coverage.snapshot(&env, true);
        let curl = snap.apps.iter().find(|a| a.id == "curl").unwrap();
        assert_eq!(curl.pac_fetches, 1);
        assert_eq!(curl.ai_requests, 0);
        assert_ne!(
            curl.status,
            crate::proxy::coverage::CoverageStatus::Confirmed
        );
        assert_eq!(snap.gateway_addr, Some(addr.to_string()));
        assert_eq!(snap.pac_url, Some(format!("http://{addr}/proxy.pac")));
    }

    #[tokio::test]
    async fn browser_extension_connect_and_ws_tunnel_for_ai_apis_succeeds() {
        let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        crate::sysproxy::force_os_dry_run();
        let auditor = Auditor::new().expect("auditor");
        let state = AppState::new_in_memory();
        for p in ["anthropic", "openai", "gemini"] {
            state.allow_provider_for_session(p).await.unwrap();
        }
        let server = Arc::new(
            ProxyServer::bind_ephemeral(
                auditor,
                state,
                Arc::new(HoldQueue::new()),
                Some(echo_addr),
            )
            .await
            .expect("bind"),
        );
        let addr = server.bound_addr;
        let srv = Arc::clone(&server);
        let srv_task = tokio::spawn(async move { srv.run().await });

        let cases = [
            (
                "api.anthropic.com",
                "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
            ),
            (
                "claude.ai",
                "moz-extension://12345678-1234-1234-1234-123456789abc",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
            ),
            (
                "api.openai.com",
                "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
            ),
            (
                "chatgpt.com",
                "chrome-extension://cccccccccccccccccccccccccccccccc",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
            ),
            (
                "gemini.google.com",
                "chrome-extension://dddddddddddddddddddddddddddddddd",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
            ),
            (
                "generativelanguage.googleapis.com",
                "moz-extension://87654321-4321-4321-4321-cba987654321",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
            ),
            (
                "clients6.google.com",
                "chrome-extension://eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
            ),
            (
                "aistudio.google.com",
                "chrome-extension://ffffffffffffffffffffffffffffffff",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
            ),
        ];

        for (host, origin, ua) in cases {
            let mut client = match TcpStream::connect(addr).await {
                Ok(c) => c,
                Err(_) => return,
            };
            let req = format!(
                "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nOrigin: {origin}\r\nUser-Agent: {ua}\r\nProxy-Connection: keep-alive\r\n\r\n"
            );
            client.write_all(req.as_bytes()).await.unwrap();

            let mut head_buf = [0u8; 256];
            let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut head_buf))
                .await
                .unwrap()
                .unwrap();
            let head = String::from_utf8_lossy(&head_buf[..n]);
            assert!(
                head.starts_with("HTTP/1.1 200 Connection Established"),
                "failed CONNECT for {host} ({origin}): {head}"
            );

            // Simulate WebSocket/HTTPS frame tunneled through the established CONNECT tunnel.
            let payload = format!(
                "GET /v1/ws HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nUpgrade: websocket\r\n\r\n"
            );
            client.write_all(payload.as_bytes()).await.unwrap();
            let mut echo = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut echo))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(String::from_utf8_lossy(&echo), payload);
        }

        // Allow spawned coverage lookup/recording to settle, then verify no misclassifications.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let platform = FakePlatform::new();
        let policy_store = FakePolicyStore::new();
        let env = CoverageEnv {
            platform: &platform,
            policy_store: &*policy_store,
            files: None,
            pac_source: PacSource::Services,
            sysproxy_enabled: true,
            cli_protection_enabled: false,
            chained_proxy: None,
            jetbrains_xml_confirmed: false,
        };
        let snap = server.coverage.snapshot(&env, true);
        let browsers = snap.apps.iter().find(|a| a.id == "browsers").unwrap();
        assert!(
            browsers.ai_requests >= 8
                || browsers.status == crate::proxy::coverage::CoverageStatus::Confirmed,
            "expected browser extension requests to be recorded under browsers: {browsers:?}"
        );

        srv_task.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn pac_excludes_disabled_providers_and_disables_cache() {
        let server = started().await;
        server
            .state
            .set_provider_monitoring("gemini", false)
            .await
            .unwrap();
        let addr = server.bound_addr;
        let req = format!(
            "GET http://{addr}/proxy.pac HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        );
        let Some(resp) = request(addr, &req).await else {
            return;
        };
        assert!(resp.contains("Cache-Control: no-store"), "{resp}");
        assert!(resp.contains("anthropic.com"), "{resp}");
        assert!(!resp.contains("gemini.google.com"), "{resp}");
        assert!(!resp.contains("google.com"), "{resp}");
    }

    #[tokio::test]
    async fn disabled_provider_connect_is_bypassed_without_blocking_or_ai_coverage() {
        let server = started().await;
        // Disable gemini and mark it blocked (e.g. from before) + engage AskPopup:
        // disabling cleared its block and CONNECT must treat gemini hosts as direct pass-through
        // without opening hold_queue or counting as AI coverage.
        server
            .state
            .set_provider_monitoring("gemini", false)
            .await
            .unwrap();
        let addr = server.bound_addr;
        let req = "CONNECT gemini.google.com:443 HTTP/1.1\r\nHost: gemini.google.com:443\r\nUser-Agent: curl/8.7.1\r\n\r\n";
        let Ok(mut conn) = TcpStream::connect(addr).await else {
            return;
        };
        let _ = conn.write_all(req.as_bytes()).await;
        let mut head = [0u8; 256];
        let _ = tokio::time::timeout(Duration::from_millis(500), conn.read(&mut head)).await;
        assert!(server.hold_queue.current_alert().is_none());
        let stats = server.state.stats().snapshot().await;
        assert!(
            stats.direct_bypassed_requests >= 1
                && stats
                    .recent_events
                    .iter()
                    .any(|e| e.host == "gemini.google.com"),
            "expected disabled gemini host to record direct bypass: {stats:?}"
        );
    }

    #[test]
    fn report_allowed_for_state_allows_yellow_and_trusted_exceptions_without_blocking() {
        use crate::auditor::{CheckResult, NetworkTelemetry, OverallStatus, RiskReport};
        use crate::state::AppStateData;

        let ok = CheckResult::ok("T", "ok");
        let base_tel = NetworkTelemetry {
            ip: "5.5.5.5".to_string(),
            country_code: "KZ".to_string(),
            hostname: None,
            asn: Some(1),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: 0,
        };
        let yellow_report = RiskReport {
            provider: ProviderId::Anthropic,
            overall_status: OverallStatus::Yellow,
            trust_score: 70,
            telemetry: base_tel.clone(),
            geo_result: CheckResult::ok("GEO_LOCATION", "KZ"),
            pinning_result: ok.clone(),
            travel_result: ok.clone(),
            dnsbl_result: ok.clone(),
            dnsbl_clean_count: "0/0".to_string(),
            asn_result: ok.clone(),
            ipv6_result: ok.clone(),
            timezone_result: CheckResult::warning("TIMEZONE_MISMATCH", "TZ offset", None),
            ipv6_exit: false,
            checks: vec![
                CheckResult::ok("GEO_LOCATION", "KZ"),
                CheckResult::warning("TIMEZONE_MISMATCH", "TZ offset", None),
            ],
            unknown_count: 0,
            applicable_count: 14,
            incomplete: false,
        };
        let st = AppStateData::default();
        assert!(crate::proxy::guard::report_allowed_for_state(
            &yellow_report,
            &st,
            false
        ));

        let mut red_report = yellow_report.clone();
        red_report.overall_status = OverallStatus::Red;
        red_report.telemetry.country_code = "RU".to_string();
        red_report.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
        red_report.checks = vec![red_report.geo_result.clone()];
        assert!(!crate::proxy::guard::report_allowed_for_state(
            &red_report,
            &st,
            false
        ));

        let mut st_except = st.clone();
        st_except
            .trusted_exceptions
            .insert("anthropic".to_string(), vec!["5.5.5.5".to_string()]);
        assert!(crate::proxy::guard::report_allowed_for_state(
            &red_report,
            &st_except,
            false
        ));
    }

    #[tokio::test]
    async fn concurrent_critical_connects_coalesce_hold_and_resolve_together() {
        crate::sysproxy::force_os_dry_run();
        let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = s.read(&mut buf).await
                        && n > 0
                    {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        let auditor = offline_test_auditor();
        let ru_tel = crate::auditor::NetworkTelemetry {
            ip: "5.5.5.5".to_string(),
            country_code: "RU".to_string(),
            hostname: None,
            asn: Some(9009),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: crate::auditor::network::current_timestamp(),
        };
        auditor.resolver.set_cached(ru_tel).await;

        let state = AppState::new_in_memory();
        let hq = Arc::new(HoldQueue::new());
        let server = Arc::new(
            ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::clone(&hq), Some(echo_addr))
                .await
                .expect("bind"),
        );
        let addr = server.bound_addr;
        let srv = Arc::clone(&server);
        let srv_task = tokio::spawn(async move { srv.run().await });

        let mut c1 = match TcpStream::connect(addr).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut c2 = TcpStream::connect(addr).await.unwrap();
        let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
        c1.write_all(req.as_bytes()).await.unwrap();
        c2.write_all(req.as_bytes()).await.unwrap();

        let mut alert_id = None;
        for _ in 0..200 {
            if let Some(alert) = hq.current_alert() {
                alert_id = Some(alert.id);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let alert_id = alert_id.expect("single coalesced alert created");
        // Give the second CONNECT a moment to coalesce into the same hold entry.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(hq.active_entry_count().await, 1);

        // Resolving the single hold ID unblocks BOTH parallel CONNECTs.
        assert!(hq.resolve(&alert_id, HoldResolution::Allow).await);

        let mut b1 = [0u8; 128];
        let mut b2 = [0u8; 128];
        let n1 = tokio::time::timeout(Duration::from_secs(2), c1.read(&mut b1))
            .await
            .unwrap()
            .unwrap();
        let n2 = tokio::time::timeout(Duration::from_secs(2), c2.read(&mut b2))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&b1[..n1]).starts_with("HTTP/1.1 200"));
        assert!(String::from_utf8_lossy(&b2[..n2]).starts_with("HTTP/1.1 200"));

        srv_task.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn critical_hold_timeout_blocks_provider_and_closes_gate() {
        crate::sysproxy::force_os_dry_run();
        let auditor = offline_test_auditor();
        let ru_tel = crate::auditor::NetworkTelemetry {
            ip: "5.5.5.5".to_string(),
            country_code: "RU".to_string(),
            hostname: None,
            asn: Some(9009),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: crate::auditor::network::current_timestamp(),
        };
        auditor.resolver.set_cached(ru_tel).await;

        let state = AppState::new_in_memory();
        let hq = Arc::new(HoldQueue::new());
        let server = Arc::new(
            ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::clone(&hq), None)
                .await
                .expect("bind")
                .with_hold_ttl(Duration::from_millis(80)),
        );
        let addr = server.bound_addr;
        let srv = Arc::clone(&server);
        let srv_task = tokio::spawn(async move { srv.run().await });

        let mut client = match TcpStream::connect(addr).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(8), client.read_to_end(&mut buf))
            .await
            .expect("client gets 403 after hold timeout")
            .unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("HTTP/1.1 403 Forbidden"), "{resp}");
        assert!(state.is_provider_blocked("anthropic").await);
        assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
        assert!(hq.current_alert().is_none());

        srv_task.abort();
    }

    #[tokio::test]
    async fn active_per_provider_hold_from_vpn_jump_cannot_reblock_after_restore_to_pinned_ip() {
        crate::sysproxy::force_os_dry_run();
        let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = s.read(&mut buf).await
                        && n > 0
                    {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        let auditor = offline_test_auditor();
        let ru_tel = crate::auditor::NetworkTelemetry {
            ip: "5.5.5.5".to_string(),
            country_code: "RU".to_string(),
            hostname: None,
            asn: Some(9009),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: crate::auditor::network::current_timestamp(),
        };
        auditor.resolver.set_cached(ru_tel).await;

        let state = AppState::new_in_memory();
        state
            .set_pinned_ip(Some("145.241.193.245".to_string()))
            .await
            .unwrap();
        state.set_strict_pinning_enabled(true).await.unwrap();

        let hq = Arc::new(HoldQueue::new());
        let server = Arc::new(
            ProxyServer::bind_ephemeral(
                auditor.clone(),
                state.clone(),
                Arc::clone(&hq),
                Some(echo_addr),
            )
            .await
            .expect("bind")
            .with_hold_ttl(Duration::from_millis(160)),
        );
        server
            .guard
            .install_noop_env_for_test(auditor.clone(), state.clone(), Arc::clone(&hq));
        let epoch_before = server.guard.restore_epoch();

        let addr = server.bound_addr;
        let srv = Arc::clone(&server);
        let srv_task = tokio::spawn(async move { srv.run().await });

        let mut client = match TcpStream::connect(addr).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();

        // Wait for the per-provider hold to be registered in HoldQueue.
        let mut hold_seen = false;
        for _ in 0..400 {
            if hq.current_alert().is_some() && hq.active_entry_count().await == 1 {
                hold_seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(hold_seen, "expected active per-provider hold in HoldQueue");

        // Now simulate returning to the clean pinned IP (`restore_locked`): bumps `restore_epoch`
        // and calls `cancel_all_superseded()` before the hold timer expires.
        server.guard.restore_for_test().await;
        assert_eq!(server.guard.restore_epoch(), epoch_before + 1);
        assert_eq!(hq.active_entry_count().await, 0);
        assert!(hq.current_alert().is_none());

        let mut head = [0u8; 128];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut head))
            .await
            .expect("superseded hold must unblock immediately without waiting for TTL")
            .unwrap();
        assert!(
            String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"),
            "expected 200 Connection Established after restore, got: {}",
            String::from_utf8_lossy(&head[..n])
        );

        // Wait well past the original hold TTL to prove no orphaned timeout relapses into block.
        tokio::time::sleep(Duration::from_millis(260)).await;
        assert!(!state.is_provider_blocked("anthropic").await);
        assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
        assert!(
            state
                .get_data()
                .await
                .ip_history
                .values()
                .all(Vec::is_empty),
            "superseded hold must NOT record stale pre-restore IP into ip_history"
        );

        srv_task.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn hold_timeout_with_changed_restore_epoch_or_trusted_exception_never_blocks() {
        crate::sysproxy::force_os_dry_run();
        let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let _ = s.read(&mut buf).await;
                });
            }
        });

        // Case 1: `restore_epoch` bumped directly before `Err(_)` fires -> must NOT block.
        let auditor = offline_test_auditor();
        let ru_tel = crate::auditor::NetworkTelemetry {
            ip: "5.5.5.5".to_string(),
            country_code: "RU".to_string(),
            hostname: None,
            asn: Some(9009),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: crate::auditor::network::current_timestamp(),
        };
        auditor.resolver.set_cached(ru_tel.clone()).await;

        let state = AppState::new_in_memory();
        let hq = Arc::new(HoldQueue::new());
        let server = Arc::new(
            ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::clone(&hq), Some(echo_addr))
                .await
                .expect("bind")
                .with_hold_ttl(Duration::from_millis(120)),
        );
        let addr = server.bound_addr;
        let srv = Arc::clone(&server);
        let srv_task = tokio::spawn(async move { srv.run().await });

        let mut c1 = match TcpStream::connect(addr).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
        c1.write_all(req.as_bytes()).await.unwrap();

        let mut seen1 = false;
        for _ in 0..400 {
            if hq.current_alert().is_some() {
                seen1 = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(seen1, "expected active hold before timeout");
        // Bump restore_epoch without draining `hq` to directly exercise the `Err(_)` epoch guard.
        server.guard.bump_restore_epoch_for_test();

        let mut head = [0u8; 128];
        let n = tokio::time::timeout(Duration::from_secs(2), c1.read(&mut head))
            .await
            .expect("timeout handler finishes")
            .unwrap();
        assert!(
            String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"),
            "unexpected response: {}",
            String::from_utf8_lossy(&head[..n])
        );
        assert!(!state.is_provider_blocked("anthropic").await);
        assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
        srv_task.abort();

        // Case 2: `(provider, exit_ip)` becomes trusted before timeout expires -> must NOT block.
        let auditor2 = offline_test_auditor();
        auditor2.resolver.set_cached(ru_tel).await;
        let state2 = AppState::new_in_memory();
        let hq2 = Arc::new(HoldQueue::new());
        let server2 = Arc::new(
            ProxyServer::bind_ephemeral(
                auditor2,
                state2.clone(),
                Arc::clone(&hq2),
                Some(echo_addr),
            )
            .await
            .expect("bind")
            .with_hold_ttl(Duration::from_millis(120)),
        );
        let addr2 = server2.bound_addr;
        let srv2 = Arc::clone(&server2);
        let srv_task2 = tokio::spawn(async move { srv2.run().await });

        let mut c2 = TcpStream::connect(addr2).await.unwrap();
        c2.write_all(req.as_bytes()).await.unwrap();
        let mut seen2 = false;
        for _ in 0..400 {
            if hq2.current_alert().is_some() {
                seen2 = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(seen2, "expected active hold2 before timeout");
        state2
            .add_trusted_exception("anthropic", "5.5.5.5")
            .await
            .unwrap();

        let mut head2 = [0u8; 128];
        let n2 = tokio::time::timeout(Duration::from_secs(2), c2.read(&mut head2))
            .await
            .expect("timeout handler finishes")
            .unwrap();
        assert!(
            String::from_utf8_lossy(&head2[..n2]).starts_with("HTTP/1.1 200"),
            "unexpected response: {}",
            String::from_utf8_lossy(&head2[..n2])
        );
        assert!(!state2.is_provider_blocked("anthropic").await);
        assert_eq!(server2.guard.gate_for(ProviderId::Anthropic), Gate::Open);

        srv_task2.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn manual_killswitch_blocks_even_disabled_provider_on_superseded_hold() {
        crate::sysproxy::force_os_dry_run();
        let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let _ = s.read(&mut buf).await;
                });
            }
        });

        let auditor = offline_test_auditor();
        let ru_tel = crate::auditor::NetworkTelemetry {
            ip: "5.5.5.5".to_string(),
            country_code: "RU".to_string(),
            hostname: None,
            asn: Some(9009),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: crate::auditor::network::current_timestamp(),
        };
        auditor.resolver.set_cached(ru_tel).await;

        let state = AppState::new_in_memory();
        let hq = Arc::new(HoldQueue::new());
        let server = Arc::new(
            ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::clone(&hq), Some(echo_addr))
                .await
                .expect("bind")
                .with_hold_ttl(Duration::from_secs(5)),
        );
        let addr = server.bound_addr;
        let srv = Arc::clone(&server);
        let srv_task = tokio::spawn(async move { srv.run().await });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();

        let mut hold_seen = false;
        for _ in 0..400 {
            if hq.current_alert().is_some() {
                hold_seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(hold_seen, "expected active hold");

        // Disable monitoring AND engage manual kill-switch, then supersede the hold.
        state.set_provider_monitoring("anthropic", false).await.unwrap();
        server.guard.set_manual_killswitch(true, &state).await;
        hq.cancel_all_superseded().await;

        let mut head = [0u8; 128];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut head))
            .await
            .expect("superseded hold completes")
            .unwrap();
        let resp = String::from_utf8_lossy(&head[..n]);
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "manual killswitch must block even disabled provider, got: {resp}"
        );
        srv_task.abort();
        echo_task.abort();
    }
}
