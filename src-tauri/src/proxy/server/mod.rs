mod connect;
mod connect_hold;
mod http_handler;
mod responses;
mod route_guard;
mod ssrf;
mod tunnel;

pub use ssrf::{
    DEFAULT_PROXY_PORT, FALLBACK_PROXY_PORT, embedded_ipv4, is_forbidden_ip,
    is_internal_hostname, is_tun_fake_ip, parse_host_port, validate_tunnel_target,
};

use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::auditor::Auditor;
use crate::proxy::guard::NetworkGuard;
use crate::proxy::hold_queue::{DEFAULT_HOLD_TTL_SECS, HoldQueue};
use crate::proxy::transit::Transit;
use crate::state::AppState;

use responses::{is_absolute_http_target, send_gateway_info};

#[cfg(test)]
use crate::auditor::geo_matrix::ProviderId;
#[cfg(test)]
use crate::proxy::guard::Gate;
#[cfg(test)]
use crate::proxy::hold_queue::HoldResolution;
#[cfg(test)]
use std::net::IpAddr;
#[cfg(test)]
use tokio::io::AsyncWriteExt;

const FIRST_REQUEST_TIMEOUT_SECS: u64 = 10;
const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 15;
/// A plain HTTP exchange with no byte from either side for this long is abandoned. Not applied to
/// CONNECT tunnels (long downloads, SSH and the like may be silent).
const PLAIN_HTTP_IDLE_TIMEOUT_SECS: u64 = 60;
/// Connect (+ CONNECT handshake) timeout for the chained proxy; after it transit traffic falls
/// back to a direct connection once.
const CHAINED_CONNECT_TIMEOUT_SECS: u64 = 8;
const MAX_CONCURRENT_CONNECTIONS: usize = 256;
/// Per-entry connect timeout when tunneling through a route (DNS + direct + optional chained fallback).
const ROUTE_ENTRY_TIMEOUT_SECS: u64 = 12;
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

}

#[cfg(test)]
#[path = "../server_tests/mod.rs"]
mod tests;
