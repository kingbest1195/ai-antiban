use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::Serialize;
use tauri::Emitter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::{Auditor, OverallStatus};
use crate::proxy::guard::{gate_closed, wait_open, Gate, NetworkGuard};
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, HoldQueue, HoldResolution, PHASE_READY, RiskInterceptPayload,
};
use crate::proxy::pac::generate_pac_script;
use crate::proxy::route_watch::RouteWatch;
use crate::proxy::upstream::{connect_via_route, UpstreamStream};
use crate::routing::{Route, RouteDownReason, RouteSelection, INVALID_PROFILE_ROUTE_ID};
use crate::state::{AppState, IpHistoryEntry};

pub const DEFAULT_PROXY_PORT: u16 = 8899;
pub const FALLBACK_PROXY_PORT: u16 = 8900;
const FIRST_REQUEST_TIMEOUT_SECS: u64 = 10;
const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 15;
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

        Ok(Self {
            bound_addr,
            listener,
            auditor,
            state,
            hold_queue,
            guard: Arc::new(NetworkGuard::new()),
            coverage: Arc::new(crate::proxy::CoverageTracker::new()),
            app_handle,
            upstream_redirect: None,
            conn_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            route_alerts: std::sync::Mutex::new(HashMap::new()),
            direct_connects: AtomicU64::new(0),
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

        Ok(Self {
            bound_addr,
            listener,
            auditor,
            state,
            hold_queue,
            guard: Arc::new(NetworkGuard::new()),
            coverage: Arc::new(crate::proxy::CoverageTracker::new()),
            app_handle: None,
            upstream_redirect,
            conn_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            route_alerts: std::sync::Mutex::new(HashMap::new()),
            direct_connects: AtomicU64::new(0),
        })
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

        self.coverage.record_incoming(client_addr.port(), user_agent);

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");

        // 1. Route GET /proxy.pac or /pac.js (supports relative "/proxy.pac" or full "http://127.0.0.1:8899/proxy.pac")
        if method == "GET"
            && (target.starts_with("/proxy.pac")
                || target.contains("/proxy.pac")
                || target.starts_with("/pac.js")
                || target.contains("/pac.js"))
        {
            return self.handle_pac_request(&mut client).await;
        }

        // 2. Route CONNECT <host>:<port>
        if method == "CONNECT" {
            return self.handle_connect_request(&mut client, target).await;
        }

        // Generic HTTP health / info response
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nConnection: close\r\n\r\nZastava Gateway Active\n";
        client.write_all(resp.as_bytes()).await?;
        client.flush().await?;
        Ok(())
    }

    async fn handle_pac_request(&self, client: &mut TcpStream) -> Result<(), std::io::Error> {
        let matrix = self.auditor.rules.provider_matrix.read().await;
        let custom_domains = self.state.get_custom_ai_domains().await;
        let domains = crate::proxy::pac::get_all_ai_domains_with_custom(&matrix, &custom_domains);

        let gateway_port = self.bound_addr.port();
        let chained_proxy = crate::sysproxy::get_chained_proxy().filter(|cp| {
            let port = cp.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(0);
            port != gateway_port && port != 0
        });

        let pac_script = generate_pac_script(
            &domains,
            &self.bound_addr.to_string(),
            chained_proxy.as_deref(),
        );

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            pac_script.len(),
            pac_script
        );

        client.write_all(response.as_bytes()).await?;
        client.flush().await?;
        Ok(())
    }

    async fn handle_connect_request(
        &self,
        client: &mut TcpStream,
        raw_target: &str,
    ) -> Result<(), std::io::Error> {
        let (host, port) = parse_host_port(raw_target);

        if let Err(reason) = validate_tunnel_target(&host, port, self.bound_addr.port()) {
            return send_forbidden(client, reason).await;
        }

        let is_canary = host == "canary-test.anthropic.zastava.local";
        let custom_domains = self.state.get_custom_ai_domains().await;
        let provider_opt = ProviderId::from_host_with_custom(&host, &custom_domains);

        let provider = match provider_opt {
            Some(p) => p,
            None => {
                // Direct pass-through for safe public non-AI domains: allows terminal users to set
                // HTTPS_PROXY=http://127.0.0.1:8899 safely without breaking git, npm, brew, etc.
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
                    .refuse_route_down(client, &host, provider, id, RouteDownReason::Missing, None, is_canary)
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
                self.state.stats().record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
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
        if self.guard.check_route_fingerprint_sync(None) {
            self.auditor.resolver.invalidate_cache().await;
        }

        self.guard.ensure_fresh().await;
        match self.guard.gate() {
            Gate::Open => {}
            Gate::Pending => {
                self.state.stats().record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
                if is_canary {
                    return send_canary_intercepted(client).await;
                }
                if self.guard.await_decision().await != Gate::Open {
                    return send_forbidden(
                        client,
                        "Network change blocked by Zastava Risk Auditor: connection was not confirmed.",
                    )
                    .await;
                }
            }
            Gate::Blocked => {
                self.state.stats().record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
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

        // Step 1: Check if provider is blocked
        if self.state.is_provider_blocked(provider.as_str()).await {
            self.state.stats().record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
            if is_canary {
                return send_canary_intercepted(client).await;
            }
            return send_forbidden(client, "Requests to this provider are blocked until network change.").await;
        }

        // Step 2: Check if provider has active session allowance
        if self.state.is_provider_session_allowed(provider.as_str()).await {
            if is_canary {
                return self
                    .canary_protected(client, &host, provider, route.as_ref(), "ALLOWED")
                    .await;
            }
            self.state.stats().record_protected(&host, provider.as_str(), "ALLOWED");
            return self.tunnel_to_target(client, &host, port, Some(provider), &selection).await;
        }

        // Step 3: Run comprehensive risk audit (on this provider's own egress)
        let report = match self
            .auditor
            .evaluate_all_with(provider, &self.state, &selection, false)
            .await
        {
            Ok(r) => r,
            Err(e) if route.is_some() => {
                let r = route.as_ref().expect("checked");
                return self
                    .refuse_route_down(client, &host, provider, &r.id, RouteDownReason::Unreachable, Some(&e), is_canary)
                    .await;
            }
            Err(e) => {
                eprintln!("Auditor evaluation failed: {e}");
                self.state.stats().record_intercepted(&host, provider.as_str(), "ERROR", "??");
                if is_canary {
                    return send_canary_intercepted(client).await;
                }
                // In case of auditor error, fall back to hold for safety
                return send_forbidden(client, &format!("Audit error: {e}")).await;
            }
        };

        // Step 4: If verdict is Green -> allow and record history
        if report.overall_status == OverallStatus::Green {
            if is_canary {
                return self
                    .canary_protected(client, &host, provider, route.as_ref(), &report.telemetry.country_code)
                    .await;
            }
            let entry = IpHistoryEntry::new(
                report.telemetry.ip.clone(),
                report.telemetry.country_code.clone(),
                report.telemetry.asn,
                report.telemetry.resolved_at,
            );
            let _ = self.state.record_ip_history(provider.as_str(), entry).await;
            self.state.stats().record_protected(&host, provider.as_str(), &report.telemetry.country_code);
            return self.tunnel_to_target(client, &host, port, Some(provider), &selection).await;
        }

        // If not Green and is canary test, immediately return intercepted status (<5ms response)
        if is_canary {
            self.state.stats().record_intercepted(&host, provider.as_str(), "BLOCKED", &report.telemetry.country_code);
            return send_canary_intercepted(client).await;
        }

        // Step 5: If verdict is Yellow or Red -> check preset InterceptionBehavior
        match self.state.get_interception_behavior().await {
            crate::state::InterceptionBehavior::AutoLockSilent => {
                self.state.stats().record_intercepted(&host, provider.as_str(), "BLOCKED", &report.telemetry.country_code);
                let _ = self.state.block_provider(provider.as_str()).await;
                return send_forbidden(client, "Auto-locked by Zastava silent rule").await;
            }
            crate::state::InterceptionBehavior::AutoAllowTrusted => {
                let matrix = self.auditor.rules.provider_matrix.read().await;
                let cc = report.telemetry.country_code.trim().to_uppercase();
                let is_sanctioned = matrix.global_blocked_countries.iter().any(|b| b.eq_ignore_ascii_case(&cc));
                if !is_sanctioned {
                    let entry = IpHistoryEntry::new(
                        report.telemetry.ip.clone(),
                        report.telemetry.country_code.clone(),
                        report.telemetry.asn,
                        report.telemetry.resolved_at,
                    );
                    let _ = self.state.record_ip_history(provider.as_str(), entry).await;
                    self.state.stats().record_protected(&host, provider.as_str(), &report.telemetry.country_code);
                    return self.tunnel_to_target(client, &host, port, Some(provider), &selection).await;
                } else {
                    self.state.stats().record_intercepted(&host, provider.as_str(), "BLOCKED", &report.telemetry.country_code);
                    let _ = self.state.block_provider(provider.as_str()).await;
                    return send_forbidden(client, "Auto-locked by Zastava silent rule (sanctioned country)").await;
                }
            }
            crate::state::InterceptionBehavior::AskPopup => {
                // proceed with hold_queue and show_and_position_alert_popup
            }
        }

        self.state.stats().record_intercepted(&host, provider.as_str(), "HELD", &report.telemetry.country_code);
        let hold_id = Uuid::new_v4().to_string();
        let rx = self.hold_queue.register(hold_id.clone(), provider.as_str()).await;

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
        };

        // Emit event to UI and bring emergency modal to front
        if let Some(app) = &self.app_handle {
            self.hold_queue.set_alert(payload.clone());
            let _ = app.emit("interceptor://risk-detected", &payload);
            crate::show_and_position_alert_popup(app);
        }

        // Wait up to 60 seconds for user action
        let resolution = tokio::time::timeout(
            Duration::from_secs(DEFAULT_HOLD_TTL_SECS),
            rx,
        ).await;

        match resolution {
            Ok(Ok(HoldResolution::Allow)) => {
                let entry = IpHistoryEntry::new(
                    report.telemetry.ip.clone(),
                    report.telemetry.country_code.clone(),
                    report.telemetry.asn,
                    report.telemetry.resolved_at,
                );
                let _ = self.state.record_ip_history(provider.as_str(), entry).await;
                self.state.stats().record_protected(&host, provider.as_str(), &report.telemetry.country_code);
                self.tunnel_to_target(client, &host, port, Some(provider), &selection).await
            }
            _ => {
                self.hold_queue.remove(&hold_id).await;
                send_forbidden(
                    client,
                    "Connection held and blocked by Zastava Risk Auditor.",
                ).await
            }
        }
    }

    async fn connect_direct(&self, host: &str, port: u16) -> Result<TcpStream, std::io::Error> {
        self.direct_connects.fetch_add(1, Ordering::SeqCst);
        let addrs: Vec<SocketAddr> = match tokio::time::timeout(
            Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
            tokio::net::lookup_host((host, port)),
        )
        .await
        {
            Ok(Ok(resolved)) => resolved.collect(),
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DNS lookup timeout",
                ));
            }
        };

        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No valid upstream addresses resolved.",
            ));
        }

        let host_is_raw_ip = host.parse::<IpAddr>().is_ok();
        for addr in &addrs {
            if is_forbidden_ip(&addr.ip()) {
                if !host_is_raw_ip && is_tun_fake_ip(&addr.ip()) {
                    // Allowed: DNS resolved to a TUN FakeIP pool (198.18.0.0/15) used by sing-box/Throne/Nekoray/Hiddify
                    continue;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "SSRF Protection: resolved IP belongs to a restricted local or private network.",
                ));
            }
        }

        match tokio::time::timeout(
            Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
            TcpStream::connect(addrs.as_slice()),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream connect timeout",
            )),
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
            if let Some(last) = alerts.get(route_id) {
                if now.duration_since(*last) < Duration::from_secs(ROUTE_ALERT_THROTTLE_SECS) {
                    return;
                }
            }
            alerts.insert(route_id.to_string(), now);
        }
        if let Some(app) = &self.app_handle {
            let payload = RouteUnavailablePayload {
                route_id: route_id.to_string(),
                provider: provider.as_str().to_string(),
                reason: reason.as_str().to_string(),
                message: detail.unwrap_or(reason.message_ru()).chars().take(300).collect(),
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
                        .refuse_route_down(client, host, provider, &r.id, RouteDownReason::Unreachable, Some(&detail), true)
                        .await;
                }
            }
        }
        self.state.stats().record_protected(host, provider.as_str(), country);
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
        let route: Option<&Route> = match selection {
            RouteSelection::Route(r) => Some(r),
            _ => None,
        };
        let _tunnel_guard = if route.is_some() || provider.is_some() || ProviderId::from_host(host).is_some() {
            Some(self.state.stats().enter_tunnel())
        } else {
            None
        };

        // Subscribe first, then verify: nothing can change unnoticed from here on.
        let watch = provider.map(|p| RouteWatch::new(&self.state, p, selection.clone()));
        if let Some(w) = &watch {
            if w.is_stale().await {
                return send_routing_changed(client).await;
            }
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
                        .refuse_route_down(client, host, provider, &r.id, RouteDownReason::Unreachable, Some(&detail), false)
                        .await;
                }
            };
            self.state.route_health().mark_reachable(&r.id);
            // The kill-switch may have been engaged while we were connecting.
            if self.guard.is_manual_killswitch() {
                return send_forbidden(client, "Network kill-switch is engaged in Zastava.").await;
            }
            if let Some(w) = &watch {
                if w.is_stale().await {
                    return send_routing_changed(client).await;
                }
            }
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            client.flush().await?;
            return pump(client, &mut target, &self.guard, TunnelPolicy::KillSwitchOnly, watch).await;
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

        if let Some(w) = &watch {
            if w.is_stale().await {
                return send_routing_changed(client).await;
            }
        }
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;

        let mut target = UpstreamStream::Plain(target_stream);
        pump(client, &mut target, &self.guard, TunnelPolicy::FollowGate, watch).await
    }
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
    let reason = "Zastava routing for this service changed while the connection was being set up: retry.";
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
    watch: Option<RouteWatch>,
) -> Result<(), std::io::Error> {
    let relay = relay(client, target, guard, policy);
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
) -> Result<(), std::io::Error> {
    let (mut cr, mut cw) = client.split();
    match target {
        // Zero-overhead split for plain TCP (direct, SOCKS5, HTTP entries).
        UpstreamStream::Plain(tcp) => {
            let (mut tr, mut tw) = tcp.split();
            let c2t = forward(&mut cr, &mut tw, guard, policy);
            let t2c = forward(&mut tr, &mut cw, guard, policy);
            tokio::try_join!(c2t, t2c)?;
        }
        UpstreamStream::Tls(tls) => {
            let (mut tr, mut tw) = tokio::io::split(tls.as_mut());
            let c2t = forward(&mut cr, &mut tw, guard, policy);
            let t2c = forward(&mut tr, &mut cw, guard, policy);
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
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match policy {
        TunnelPolicy::FollowGate => forward_follow_gate(reader, writer, guard).await,
        TunnelPolicy::KillSwitchOnly => forward_killswitch_only(reader, writer, guard).await,
    }
}

async fn forward_follow_gate<R, W>(
    reader: &mut R,
    writer: &mut W,
    guard: &Arc<NetworkGuard>,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut rx = guard.subscribe();
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
        if !wait_open(&mut rx).await || guard.gate() != Gate::Open || guard.is_manual_killswitch() {
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
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((ipv6_host, after_bracket)) = rest.split_once(']') {
            let port = after_bracket
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(443);
            return (ipv6_host.trim().to_string(), port);
        }
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

    if let Ok(ip) = h.parse::<IpAddr>() {
        if is_forbidden_ip(&ip) {
            return Err("SSRF Protection: direct connections to loopback or private IPs are forbidden.");
        }
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
