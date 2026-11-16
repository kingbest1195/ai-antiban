use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::auditor::geo_matrix::{
    CheckResult, CheckStatus, ProviderId, UnknownReason, evaluate_provider_geo,
};
use crate::auditor::rules::ProviderMatrix;
use crate::auditor::seams::{HttpProbeOutcome, IpProbe};
use crate::routing::net::resolve_entry_checked;
use crate::routing::{Entry, EntryProto, Route, route_fingerprint, route_id_for_raw_key};
use crate::state::UpstreamProxyConfig;

pub const CACHE_TTL_SECONDS: u64 = 15;
pub const REQUEST_TIMEOUT_MS: u64 = 3500;

/// Neutral browser-like User-Agent for telemetry and exit probes (never identifies Zastava).
pub const NEUTRAL_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

pub const SUSPICIOUS_ANONYMIZER_MARKERS: &[&str] = &[
    "tor-exit",
    "anonymizer",
    "openproxy",
    "public-vpn",
    "socks-proxy",
    "vpn-exit",
    "exit-node",
    "torproject",
    "tor-node",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkTelemetry {
    pub ip: String,
    pub country_code: String,
    #[serde(default)]
    pub hostname: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub timezone: Option<String>,
    pub resolved_at: u64,
}

impl NetworkTelemetry {
    pub fn is_fresh(&self, ttl_seconds: u64) -> bool {
        let now = current_timestamp();
        now.saturating_sub(self.resolved_at) < ttl_seconds
    }

    pub fn has_provider_metadata(&self) -> bool {
        self.asn.is_some() || self.isp.is_some() || self.org.is_some()
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Builds a `reqwest::Client` that routes all traffic through a legacy single upstream proxy.
/// The upstream host must be an IP literal here (no name resolution takes place).
pub fn build_upstream_client(cfg: &UpstreamProxyConfig) -> Result<reqwest::Client, String> {
    let route = Route::from_legacy(cfg, 0)
        .ok_or_else(|| format!("Unsupported upstream proxy protocol: {}", cfg.protocol))?;
    let entry = route.entries.first().ok_or("route has no entries")?;
    let ip: IpAddr = entry
        .host
        .parse()
        .map_err(|_| "The legacy upstream client needs an IP address".to_string())?;
    let builder = entry_client_builder(entry, SocketAddr::new(ip, entry.port))?;
    builder
        .build()
        .map_err(|e| format!("Failed to build proxy reqwest client: {e}"))
}

fn url_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// reqwest builder going through `entry`, mirroring the gateway transport. `addr` is the entry
/// address that was already resolved and checked: the client connects to it and never resolves the
/// entry name on its own.
/// * `socks5` -> `socks5h://` (target names resolved by the node, like the gateway's ATYP=domain);
/// * `http`   -> `http://` proxy with `Proxy-Authorization: Basic`;
/// * `https`  -> `https://` proxy: reqwest 0.12 (`rustls-tls`, webpki roots) opens TLS to the proxy
///   with full certificate verification and ALPN http/1.1, then sends `CONNECT` with Basic auth.
///   The proxy URL host is the TLS server name and a DNS override pins it to `addr`.
///
/// Credentials never go into error messages.
fn entry_client_builder(entry: &Entry, addr: SocketAddr) -> Result<reqwest::ClientBuilder, String> {
    let scheme = match entry.proto {
        EntryProto::Socks5 => "socks5h",
        EntryProto::Http => "http",
        EntryProto::Https => "https",
    };
    let url_name = match entry.proto {
        EntryProto::Https => url_host(entry.tls_server_name()),
        _ => url_host(&addr.ip().to_string()),
    };
    let mut proxy_url = url::Url::parse(&format!("{scheme}://{url_name}:{}", entry.port))
        .map_err(|_| "Invalid entry address for the audit client".to_string())?;

    if entry.proto == EntryProto::Socks5 {
        // reqwest takes SOCKS credentials from the URL userinfo only.
        if let Some(u) = entry.username.as_deref() {
            proxy_url
                .set_username(u)
                .map_err(|_| "Invalid entry username".to_string())?;
            proxy_url
                .set_password(entry.password.as_deref())
                .map_err(|_| "Invalid entry password".to_string())?;
        }
    }

    let mut proxy = reqwest::Proxy::all(proxy_url.as_str())
        .map_err(|_| format!("Failed to configure {scheme} entry proxy for the audit client"))?;
    if entry.proto != EntryProto::Socks5
        && let Some(u) = entry.username.as_deref()
    {
        proxy = proxy.basic_auth(u, entry.password.as_deref().unwrap_or(""));
    }

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS))
        .pool_max_idle_per_host(0)
        .user_agent(NEUTRAL_USER_AGENT)
        .proxy(proxy);
    if entry.proto == EntryProto::Https {
        let name = entry.tls_server_name();
        if name.parse::<IpAddr>().is_err() {
            builder = builder.resolve(name, addr);
        }
    }
    Ok(builder)
}

/// Audit client going through the given route entry (same entry the gateway uses). The entry host
/// is resolved here, every address is checked against the entry policy (see
/// [`crate::routing::net`]) and the client is pinned to the checked address.
pub async fn build_entry_client(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
) -> Result<reqwest::Client, String> {
    let addr = checked_entry_addr(entry, allow_local, gateway_port).await?;
    entry_client_builder(entry, addr)?
        .build()
        .map_err(|e| format!("Failed to build audit client: {e}"))
}

fn format_checked_entry_error(endpoint: &str, err: &std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        format!("Entry node {endpoint} rejected: {err}")
    } else {
        format!("Entry node {endpoint} DNS lookup failed: {err}")
    }
}

async fn checked_entry_addr(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
) -> Result<SocketAddr, String> {
    let addrs = resolve_entry_checked(entry, allow_local, gateway_port)
        .await
        .map_err(|e| format_checked_entry_error(&entry.endpoint(), &e))?;
    addrs
        .first()
        .copied()
        .ok_or_else(|| format!("Entry {} did not resolve", entry.endpoint()))
}

/// Test-only: same as [`build_entry_client`] but trusting an extra root (local TLS stub).
#[cfg(test)]
async fn build_entry_client_with_root(
    entry: &Entry,
    root: reqwest::Certificate,
) -> Result<reqwest::Client, String> {
    let addr = checked_entry_addr(entry, true, 0).await?;
    entry_client_builder(entry, addr)?
        .add_root_certificate(root)
        .build()
        .map_err(|e| format!("Failed to build audit client: {e}"))
}

// Models for ipwho.is
#[derive(Deserialize)]
struct IpWhoIsResponse {
    ip: Option<String>,
    country_code: Option<String>,
    connection: Option<IpWhoIsConnection>,
    timezone: Option<IpWhoIsTimezone>,
}

#[derive(Deserialize)]
struct IpWhoIsConnection {
    asn: Option<u32>,
    org: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
}

#[derive(Deserialize)]
struct IpWhoIsTimezone {
    id: Option<String>,
}

// Models for ipinfo.io
#[derive(Deserialize)]
struct IpInfoResponse {
    ip: Option<String>,
    hostname: Option<String>,
    country: Option<String>,
    org: Option<String>,
    timezone: Option<String>,
}

// Models for freeipapi.com
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FreeIpApiResponse {
    ip_address: Option<String>,
    country_code: Option<String>,
    asn: Option<String>,
    asn_organization: Option<String>,
    time_zones: Option<Vec<String>>,
}

/// Cache key: `None` = direct egress, `Some(route id)` = egress through that route.
type CacheKey = Option<String>;

/// Cached telemetry plus the fingerprint of the route nodes it was measured through (`None` for
/// direct egress and for test-injected values).
#[derive(Clone)]
struct CachedTelemetry {
    telemetry: NetworkTelemetry,
    route_fp: Option<u64>,
}

#[derive(Clone)]
pub struct NetworkResolver {
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<CacheKey, CachedTelemetry>>>,
    resolve_lock: Arc<tokio::sync::Mutex<()>>,
    /// Monotonic generation bumped on every `invalidate_cache()` / `invalidate_route()` call so
    /// an in-flight `cascade_query` that started before invalidation never poisons `cache`.
    cache_generation: Arc<AtomicU64>,
    /// Port of the local gateway (0 = unknown), used to refuse entry nodes that point back at it.
    gateway_port: Arc<AtomicU16>,
    /// Provider-independent check results (DNSBL, IPv6, OS); dropped together with the telemetry
    /// whenever the network changes.
    check_cache: Arc<crate::auditor::cache::CheckCache>,
}

impl Default for NetworkResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkResolver {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS))
            // Fresh socket per lookup: a pooled keep-alive connection could still use the old route
            // after a VPN switch and report the previous IP / ASN.
            .pool_max_idle_per_host(0)
            .user_agent(NEUTRAL_USER_AGENT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            resolve_lock: Arc::new(tokio::sync::Mutex::new(())),
            cache_generation: Arc::new(AtomicU64::new(0)),
            gateway_port: Arc::new(AtomicU16::new(0)),
            check_cache: Arc::default(),
        }
    }

    /// The TTL cache of the provider-independent checks, shared by every audit of this resolver.
    pub fn check_cache(&self) -> &Arc<crate::auditor::cache::CheckCache> {
        &self.check_cache
    }

    /// Registers the port of the local gateway (called by the proxy server when it binds).
    pub fn set_gateway_port(&self, port: u16) {
        self.gateway_port.store(port, Ordering::SeqCst);
    }

    pub fn gateway_port(&self) -> u16 {
        self.gateway_port.load(Ordering::SeqCst)
    }

    /// Invalidate all cached telemetry (direct and every route).
    pub async fn invalidate_cache(&self) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        self.cache.write().await.clear();
        self.check_cache.clear().await;
    }

    /// Invalidate only the direct-path telemetry cache (preserving per-route remote egress telemetry
    /// when only the local host VPN/network interface changes).
    pub async fn invalidate_direct_cache(&self) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        self.cache.write().await.remove(&None);
        self.check_cache.clear().await;
    }

    /// Resolve direct egress telemetry using a pluggable `IpProbe` (for offline tests with
    /// `Auditor::with_env`), honoring `cache[&None]` so pre-seeded `set_cached` telemetry works.
    pub async fn resolve_direct_via_probe(
        &self,
        probe: &dyn IpProbe,
        force_refresh: bool,
    ) -> Result<NetworkTelemetry, String> {
        self.resolve_cached_or_fetch(None, None, force_refresh, || async {
            let limit = Duration::from_millis(REQUEST_TIMEOUT_MS);
            if let HttpProbeOutcome::Response { status: 200..=299, body } =
                probe.get("https://ipwho.is/", limit).await
                && let Ok(parsed) = serde_json::from_str::<IpWhoIsResponse>(&body)
                && let (Some(ip), Some(cc)) = (parsed.ip, parsed.country_code)
            {
                let (asn, org, isp, hostname) = match parsed.connection {
                    Some(conn) => (conn.asn, conn.org, conn.isp, conn.domain),
                    None => (None, None, None, None),
                };
                return Ok(NetworkTelemetry {
                    ip,
                    country_code: cc.to_uppercase(),
                    hostname,
                    asn,
                    org,
                    isp,
                    timezone: parsed.timezone.and_then(|tz| tz.id),
                    resolved_at: current_timestamp(),
                });
            }

            if let HttpProbeOutcome::Response { status: 200..=299, body } =
                probe.get("https://1.1.1.1/cdn-cgi/trace", limit).await
                && let Some(trace) = parse_cloudflare_trace(&body)
                && let Some(cc) = trace.loc
            {
                return Ok(NetworkTelemetry {
                    ip: trace.ip,
                    country_code: cc.to_uppercase(),
                    hostname: None,
                    asn: None,
                    org: None,
                    isp: None,
                    timezone: None,
                    resolved_at: current_timestamp(),
                });
            }

            Err("All offline geo probes failed".to_string())
        })
        .await
    }

    /// Invalidate cached telemetry of one route.
    pub async fn invalidate_route(&self, route_id: &str) {
        self.cache_generation.fetch_add(1, Ordering::SeqCst);
        self.cache.write().await.remove(&Some(route_id.to_string()));
    }

    /// Returns the cached direct-path country code when direct telemetry is fresh and matches `ip`.
    pub async fn cached_direct_country(&self, ip: &str) -> Option<String> {
        let target = ip.trim();
        if target.is_empty() {
            return None;
        }
        let r = self.cache.read().await;
        let entry = r.get(&None)?;
        if entry.telemetry.ip.trim() == target && entry.telemetry.is_fresh(CACHE_TTL_SECONDS) {
            let cc = entry.telemetry.country_code.trim();
            if !cc.is_empty() {
                return Some(cc.to_uppercase());
            }
        }
        None
    }

    /// Pre-populate or override cached direct telemetry (deterministic tests and simulation)
    pub async fn set_cached(&self, telemetry: NetworkTelemetry) {
        self.cache.write().await.insert(
            None,
            CachedTelemetry {
                telemetry,
                route_fp: None,
            },
        );
    }

    /// Pre-populate cached telemetry for a route id (`None` = direct).
    pub async fn set_cached_for_route(
        &self,
        route_id: Option<String>,
        telemetry: NetworkTelemetry,
    ) {
        self.cache.write().await.insert(
            route_id,
            CachedTelemetry {
                telemetry,
                route_fp: None,
            },
        );
    }

    /// Legacy: pre-populate cached telemetry for an upstream raw key (mapped to its route id).
    pub async fn set_cached_for_key(&self, key: Option<String>, telemetry: NetworkTelemetry) {
        let route_id = key.map(|k| route_id_for_raw_key(&k));
        self.set_cached_for_route(route_id, telemetry).await;
    }

    /// Resolve network telemetry using fresh cache or cascading endpoints (direct egress)
    pub async fn resolve(&self, force_refresh: bool) -> Result<NetworkTelemetry, String> {
        self.resolve_with_route(force_refresh, None).await
    }

    /// Legacy: resolve through a single upstream config (when enabled).
    pub async fn resolve_with_upstream(
        &self,
        force_refresh: bool,
        upstream: Option<&UpstreamProxyConfig>,
    ) -> Result<NetworkTelemetry, String> {
        let route = upstream
            .filter(|c| c.enabled)
            .and_then(|c| Route::from_legacy(c, 0));
        self.resolve_with_route(force_refresh, route.as_ref()).await
    }

    async fn cached(
        &self,
        key: &CacheKey,
        force_refresh: bool,
        locked: bool,
        route_fp: Option<u64>,
    ) -> Option<NetworkTelemetry> {
        let r = self.cache.read().await;
        let entry = r.get(key)?;
        // The route was re-imported with different nodes / credentials: the entry is stale.
        if let (Some(cached_fp), Some(fp)) = (entry.route_fp, route_fp)
            && cached_fp != fp
        {
            return None;
        }
        let telemetry = &entry.telemetry;
        let ttl = if !telemetry.has_provider_metadata() {
            2
        } else if force_refresh {
            8
        } else {
            CACHE_TTL_SECONDS
        };
        let usable = telemetry.is_fresh(ttl)
            && if force_refresh {
                // Inside the lock a concurrent forced refresh may just have filled the cache.
                locked && telemetry.has_provider_metadata()
            } else {
                true
            };
        usable.then(|| telemetry.clone())
    }

    async fn resolve_cached_or_fetch<F, Fut>(
        &self,
        key: CacheKey,
        fp: Option<u64>,
        force_refresh: bool,
        fetch: F,
    ) -> Result<NetworkTelemetry, String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<NetworkTelemetry, String>>,
    {
        if !force_refresh && let Some(t) = self.cached(&key, false, false, fp).await {
            return Ok(t);
        }

        // Coalesce concurrent cold-start / multi-provider probes so we don't fire 4 simultaneous
        // requests to ipwho.is / ipinfo.io and trigger rate limits or timeouts on startup.
        let _guard = self.resolve_lock.lock().await;
        let generation = self.cache_generation.load(Ordering::SeqCst);
        if let Some(t) = self.cached(&key, force_refresh, true, fp).await {
            return Ok(t);
        }

        let telemetry = fetch().await?;

        let mut cache = self.cache.write().await;
        if self.cache_generation.load(Ordering::SeqCst) == generation {
            cache.insert(
                key,
                CachedTelemetry {
                    telemetry: telemetry.clone(),
                    route_fp: fp,
                },
            );
        }
        Ok(telemetry)
    }

    /// Resolve egress telemetry directly (`None`) or through a route's entries (tried in order).
    pub async fn resolve_with_route(
        &self,
        force_refresh: bool,
        route: Option<&Route>,
    ) -> Result<NetworkTelemetry, String> {
        let key: CacheKey = route.map(|r| r.id.clone());
        let fp = route.map(route_fingerprint);
        self.resolve_cached_or_fetch(key, fp, force_refresh, || async {
            match route {
                None => self.cascade_query(&self.client).await,
                Some(r) => self.cascade_via_route(r).await,
            }
        })
        .await
    }

    async fn cascade_via_route(&self, route: &Route) -> Result<NetworkTelemetry, String> {
        if route.entries.is_empty() {
            return Err("route has no entry nodes".to_string());
        }
        let mut errors = Vec::new();
        let allow_local = route.allows_local_entries();
        let gateway_port = self.gateway_port();
        for (i, entry) in route.entries.iter().enumerate() {
            let res = match build_entry_client(entry, allow_local, gateway_port).await {
                Ok(client) => self.cascade_query(&client).await,
                Err(e) => Err(e),
            };
            match res {
                Ok(t) => return Ok(t),
                Err(e) => errors.push(format!("entry #{} {}: {e}", i + 1, entry.endpoint())),
            }
        }
        Err(format!("Route egress lookup failed: {}", errors.join("; ")))
    }

    async fn cascade_query(&self, client: &reqwest::Client) -> Result<NetworkTelemetry, String> {
        let mut errors = Vec::new();

        // 1. Primary: ipwho.is
        match self.query_ipwhois(client).await {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(format!("ipwho.is failed: {e}")),
        }

        // 2. Fallback 1: ipinfo.io
        match self.query_ipinfo(client).await {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(format!("ipinfo.io failed: {e}")),
        }

        // 3. Fallback 2: freeipapi.com (rich metadata with ASN/ISP/Timezone)
        match self.query_freeipapi(client).await {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(format!("freeipapi.com failed: {e}")),
        }

        // 4. Fallback 3: 1.1.1.1/cdn-cgi/trace
        match self.query_cloudflare_trace(client).await {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(format!("1.1.1.1/cdn-cgi/trace failed: {e}")),
        }

        Err(format!("All geo resolvers failed: {}", errors.join("; ")))
    }

    async fn query_ipwhois(&self, client: &reqwest::Client) -> Result<NetworkTelemetry, String> {
        let resp = client
            .get("https://ipwho.is/")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let parsed: IpWhoIsResponse = resp.json().await.map_err(|e| e.to_string())?;

        let ip = parsed.ip.ok_or("ipwho.is missing 'ip'")?;
        let country_code = parsed
            .country_code
            .ok_or("ipwho.is missing 'country_code'")?
            .to_uppercase();

        let (asn, org, isp, domain) = match parsed.connection {
            Some(conn) => (conn.asn, conn.org, conn.isp, conn.domain),
            None => (None, None, None, None),
        };

        let timezone = parsed.timezone.and_then(|tz| tz.id);

        Ok(NetworkTelemetry {
            ip,
            country_code,
            hostname: domain,
            asn,
            org,
            isp,
            timezone,
            resolved_at: current_timestamp(),
        })
    }

    async fn query_ipinfo(&self, client: &reqwest::Client) -> Result<NetworkTelemetry, String> {
        let resp = client
            .get("https://ipinfo.io/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let parsed: IpInfoResponse = resp.json().await.map_err(|e| e.to_string())?;

        let ip = parsed.ip.ok_or("ipinfo.io missing 'ip'")?;
        let country_code = parsed
            .country
            .ok_or("ipinfo.io missing 'country'")?
            .to_uppercase();

        let mut asn = None;
        let mut org_name = None;

        if let Some(org_str) = parsed.org {
            // E.g. "AS20473 The Constant Company, LLC"
            let trimmed = org_str.trim();
            if let Some(rest) = trimmed.strip_prefix("AS") {
                let mut parts = rest.splitn(2, ' ');
                if let Some(asn_str) = parts.next() {
                    asn = asn_str.parse::<u32>().ok();
                }
                if let Some(name) = parts.next() {
                    org_name = Some(name.to_string());
                }
            } else {
                org_name = Some(trimmed.to_string());
            }
        }

        Ok(NetworkTelemetry {
            ip,
            country_code,
            hostname: parsed.hostname,
            asn,
            org: org_name.clone(),
            isp: org_name,
            timezone: parsed.timezone,
            resolved_at: current_timestamp(),
        })
    }

    async fn query_freeipapi(&self, client: &reqwest::Client) -> Result<NetworkTelemetry, String> {
        let resp = client
            .get("https://freeipapi.com/api/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let parsed: FreeIpApiResponse = resp.json().await.map_err(|e| e.to_string())?;

        let ip = parsed
            .ip_address
            .ok_or("freeipapi.com missing 'ipAddress'")?;
        let country_code = parsed
            .country_code
            .ok_or("freeipapi.com missing 'countryCode'")?
            .to_uppercase();

        let asn = parsed.asn.and_then(|s| {
            let trimmed = s.trim();
            let digits = trimmed.strip_prefix("AS").unwrap_or(trimmed);
            digits.parse::<u32>().ok()
        });
        let org = parsed.asn_organization;
        let timezone = parsed.time_zones.and_then(|mut v| {
            if v.is_empty() {
                None
            } else {
                Some(v.remove(0))
            }
        });

        Ok(NetworkTelemetry {
            ip,
            country_code,
            hostname: None,
            asn,
            org: org.clone(),
            isp: org,
            timezone,
            resolved_at: current_timestamp(),
        })
    }

    async fn query_cloudflare_trace(
        &self,
        client: &reqwest::Client,
    ) -> Result<NetworkTelemetry, String> {
        let resp = client
            .get("https://1.1.1.1/cdn-cgi/trace")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let text = resp.text().await.map_err(|e| e.to_string())?;
        let trace = parse_cloudflare_trace(&text)
            .ok_or_else(|| "1.1.1.1/cdn-cgi/trace missing 'ip'".to_string())?;
        let country_code = trace
            .loc
            .ok_or_else(|| "1.1.1.1/cdn-cgi/trace missing 'loc'".to_string())?;

        Ok(NetworkTelemetry {
            ip: trace.ip,
            country_code,
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        })
    }

    /// Probes the actual exit observed by the active AI provider (via its bound route if any,
    /// or the system direct client otherwise) to catch split-tunnel / QUIC / PAC leaks.
    pub async fn probe_provider_exit(
        &self,
        provider: ProviderId,
        route: Option<&Route>,
        telemetry: &NetworkTelemetry,
        matrix: &ProviderMatrix,
    ) -> CheckResult {
        self.probe_provider_exit_with_probe(provider, route, telemetry, matrix, None)
            .await
    }

    /// Variant of [`Self::probe_provider_exit`] that routes direct (unbound) probes through an
    /// injected [`IpProbe`] when provided by `Auditor::with_env` tests.
    pub async fn probe_provider_exit_with_probe(
        &self,
        provider: ProviderId,
        route: Option<&Route>,
        telemetry: &NetworkTelemetry,
        matrix: &ProviderMatrix,
        direct_probe: Option<&dyn IpProbe>,
    ) -> CheckResult {
        let url_override = default_exit_probe_url(provider, route.is_some());
        self.probe_provider_exit_inner(
            provider,
            route,
            telemetry,
            matrix,
            url_override,
            None,
            direct_probe,
            Duration::from_millis(REQUEST_TIMEOUT_MS),
        )
        .await
    }

    /// Testable core of [`Self::probe_provider_exit`]: probes `probe_url` directly or through
    /// `route`'s entry nodes (falling back to `client_override` / custom `timeout` in tests).
    #[allow(clippy::too_many_arguments)]
    pub async fn probe_provider_exit_with_url(
        &self,
        provider: ProviderId,
        route: Option<&Route>,
        telemetry: &NetworkTelemetry,
        matrix: &ProviderMatrix,
        probe_url: &str,
        client_override: Option<&reqwest::Client>,
        timeout: Duration,
    ) -> CheckResult {
        self.probe_provider_exit_inner(
            provider,
            route,
            telemetry,
            matrix,
            probe_url,
            client_override,
            None,
            timeout,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn probe_provider_exit_inner(
        &self,
        provider: ProviderId,
        route: Option<&Route>,
        telemetry: &NetworkTelemetry,
        matrix: &ProviderMatrix,
        probe_url: &str,
        client_override: Option<&reqwest::Client>,
        direct_probe: Option<&dyn IpProbe>,
        timeout: Duration,
    ) -> CheckResult {
        if provider == ProviderId::Gemini && route.is_none() {
            return CheckResult::unknown(
                "PROVIDER_EXIT_NOT_APPLICABLE",
                "Выход не проверен напрямую: Google Gemini не отдает /cdn-cgi/trace на прямом маршруте.",
                UnknownReason::NotApplicable,
            )
            .with_measured_via("gemini (без отдельного маршрута)");
        }

        // Never send unbound (route: None) probes to provider domains (claude.ai / chatgpt.com)
        // from the user's real IP; use neutral IP/geo endpoints (or chained proxy if configured).
        let effective_url = if route.is_none() && is_provider_domain_url(probe_url) {
            NEUTRAL_EXIT_PROBE_URL
        } else {
            probe_url
        };

        let gateway_port = self.gateway_port();
        let chained_client = if route.is_none() && client_override.is_none() && direct_probe.is_none()
        {
            crate::sysproxy::get_chained_proxy()
                .filter(|cp| {
                    !crate::sysproxy::is_gateway_host_port(
                        cp,
                        (gateway_port > 0).then_some(gateway_port),
                    )
                })
                .and_then(|cp| build_chained_probe_client(&cp, timeout))
        } else {
            None
        };

        let via_host = if route.is_some() {
            match provider {
                ProviderId::Anthropic => "claude.ai",
                ProviderId::Openai => "chatgpt.com",
                ProviderId::Gemini => "gemini (ipinfo.io)",
            }
        } else {
            "1.1.1.1"
        };
        let via_label = if route.is_some() {
            format!("{via_host} (маршрут ключа)")
        } else if chained_client.is_some() {
            format!("{via_host} (chained proxy)")
        } else {
            via_host.to_string()
        };

        let response = if let Some(c) = client_override {
            probe_url_with_client(c, effective_url, timeout).await
        } else if let Some(r) = route {
            if r.entries.is_empty() {
                return CheckResult::unknown(
                    "PROVIDER_EXIT_NO_ROUTE_ENTRY",
                    format!(
                        "Не удалось проверить реальный выход {}: у маршрута нет входных узлов.",
                        provider.display_name()
                    ),
                    UnknownReason::NoData,
                )
                .with_measured_via(via_label);
            }
            let allow_local = r.allows_local_entries();
            let mut last_err = ProbeFetchError::Unreachable("no route entry attempted".into());
            let mut fetched = None;
            for entry in &r.entries {
                match build_entry_client(entry, allow_local, gateway_port).await {
                    Ok(c) => match probe_url_with_client(&c, effective_url, timeout).await {
                        Ok(payload) => {
                            fetched = Some(payload);
                            break;
                        }
                        Err(e) => last_err = e,
                    },
                    Err(e) => last_err = ProbeFetchError::Unreachable(e),
                }
            }
            match fetched {
                Some(ok) => Ok(ok),
                None => Err(last_err),
            }
        } else if let Some(probe) = direct_probe {
            match probe.get(effective_url, timeout).await {
                HttpProbeOutcome::Response { status, body } => Ok((status, body)),
                HttpProbeOutcome::Timeout => Err(ProbeFetchError::Timeout),
                HttpProbeOutcome::ConnectFailed
                | HttpProbeOutcome::ReadFailed
                | HttpProbeOutcome::ClientError => {
                    Err(ProbeFetchError::Unreachable("probe transport error".into()))
                }
            }
        } else if let Some(c) = chained_client.as_ref() {
            probe_url_with_client(c, effective_url, timeout).await
        } else {
            probe_url_with_client(&self.client, effective_url, timeout).await
        };

        let (status, body) = match response {
            Ok(pair) => pair,
            Err(ProbeFetchError::Timeout) => {
                return CheckResult::unknown(
                    "PROVIDER_EXIT_TIMEOUT",
                    format!(
                        "Таймаут проверки реального выхода {} через {}: источник не ответил вовремя.",
                        provider.display_name(),
                        via_host
                    ),
                    UnknownReason::Timeout,
                )
                .with_measured_via(via_label);
            }
            Err(ProbeFetchError::Unreachable(e)) => {
                return CheckResult::unknown(
                    "PROVIDER_EXIT_UNREACHABLE",
                    format!(
                        "Не удалось проверить реальный выход {} через {}: {e}",
                        provider.display_name(),
                        via_host
                    ),
                    UnknownReason::NetworkError,
                )
                .with_measured_via(via_label);
            }
        };

        if status == 403 || !(200..300).contains(&status) || looks_like_html(&body) {
            return CheckResult::unknown(
                "PROVIDER_EXIT_REFUSED",
                format!(
                    "Источник {} отклонил проверку реального выхода (HTTP {status} или anti-bot страница).",
                    via_host
                ),
                UnknownReason::SourceRefused,
            )
            .with_measured_via(via_label);
        }

        let (exit_ip, trace_loc, colo) = if provider == ProviderId::Gemini {
            match parse_gemini_exit_probe(&body) {
                Some((ip, loc)) => (ip, loc, None),
                None => {
                    return CheckResult::unknown(
                        "PROVIDER_EXIT_REFUSED",
                        format!(
                            "Не удалось разобрать ответ проверки реального выхода {}.",
                            via_host
                        ),
                        UnknownReason::SourceRefused,
                    )
                    .with_measured_via(via_label);
                }
            }
        } else {
            match parse_cloudflare_trace(&body) {
                Some(trace) => (trace.ip, trace.loc, trace.colo),
                None => {
                    return CheckResult::unknown(
                        "PROVIDER_EXIT_REFUSED",
                        format!(
                            "Ответ {} не содержит корректного поля ip= для проверки выхода.",
                            via_host
                        ),
                        UnknownReason::SourceRefused,
                    )
                    .with_measured_via(via_label);
                }
            }
        };

        let effective_cc = trace_loc
            .as_deref()
            .filter(|cc| !cc.is_empty() && !matches!(*cc, "XX" | "ZZ"))
            .unwrap_or(&telemetry.country_code);
        let geo = evaluate_provider_geo(matrix, provider, effective_cc);
        if geo.status == CheckStatus::Critical {
            return CheckResult::critical(
                "PROVIDER_EXIT_BLOCKED_COUNTRY",
                format!(
                    "Реальный выход {} ({}) определен как {} ({exit_ip}): {}",
                    provider.display_name(),
                    via_host,
                    effective_cc,
                    geo.message
                ),
                geo.guide_ref,
            )
            .with_measured_via(via_label);
        }

        if route.is_none() && exit_ip != telemetry.ip {
            return CheckResult::warning(
                "PROVIDER_EXIT_SPLIT_MISMATCH",
                format!(
                    "Маршрут ИИ ({exit_ip}, {effective_cc}) и общий выход ({}) различаются (split tunnel/PAC) — проверьте настройки прокси и QUIC/DoH.",
                    telemetry.ip
                ),
                geo.guide_ref,
            )
            .with_measured_via(via_label);
        }

        if geo.status == CheckStatus::Warning {
            return CheckResult::warning(
                "PROVIDER_EXIT_GEO_WARNING",
                format!(
                    "Реальный выход {} ({exit_ip}, {effective_cc}): {}",
                    via_host, geo.message
                ),
                geo.guide_ref,
            )
            .with_measured_via(via_label);
        }

        let colo_note = colo
            .as_deref()
            .map(|c| format!(", POP {c}"))
            .unwrap_or_default();
        let route_note = if route.is_some() && exit_ip != telemetry.ip {
            format!("; отличается от общей телеметрии маршрута {}", telemetry.ip)
        } else {
            String::new()
        };
        CheckResult::ok(
            "PROVIDER_EXIT_VERIFIED",
            format!(
                "Реальный выход {} подтвержден: {exit_ip} ({effective_cc}{colo_note}){route_note}.",
                provider.display_name()
            ),
        )
        .with_measured_via(via_label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareTrace {
    pub ip: String,
    pub loc: Option<String>,
    pub colo: Option<String>,
}

/// Parses a Cloudflare `/cdn-cgi/trace` key=value response, validating that `ip=` is a real IP address.
pub fn parse_cloudflare_trace(text: &str) -> Option<CloudflareTrace> {
    let mut ip: Option<String> = None;
    let mut loc: Option<String> = None;
    let mut colo: Option<String> = None;

    for line in text.lines() {
        if let Some(val) = line.strip_prefix("ip=") {
            let trimmed = val.trim();
            if trimmed.parse::<IpAddr>().is_ok() {
                ip = Some(trimmed.to_string());
            }
        } else if let Some(val) = line.strip_prefix("loc=") {
            let trimmed = val.trim().to_uppercase();
            if !trimmed.is_empty() {
                loc = Some(trimmed);
            }
        } else if let Some(val) = line.strip_prefix("colo=") {
            let trimmed = val.trim().to_uppercase();
            if !trimmed.is_empty() {
                colo = Some(trimmed);
            }
        }
    }

    ip.map(|ip| CloudflareTrace { ip, loc, colo })
}

fn looks_like_html(body: &str) -> bool {
    let trimmed = body.trim_start();
    trimmed.starts_with('<')
        || trimmed.get(..64).is_some_and(|head| {
            let lower = head.to_ascii_lowercase();
            lower.contains("<!doctype") || lower.contains("<html")
        })
}

fn parse_gemini_exit_probe(body: &str) -> Option<(String, Option<String>)> {
    if let Ok(parsed) = serde_json::from_str::<IpInfoResponse>(body)
        && let Some(ip) = parsed.ip.filter(|s| s.trim().parse::<IpAddr>().is_ok())
    {
        let loc = parsed.country.map(|c| c.trim().to_uppercase());
        return Some((ip.trim().to_string(), loc));
    }
    let trimmed = body.trim();
    if trimmed.parse::<IpAddr>().is_ok() {
        return Some((trimmed.to_string(), None));
    }
    None
}

const NEUTRAL_EXIT_PROBE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";

fn is_provider_domain_url(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .is_some_and(|h| {
            h == "claude.ai"
                || h.ends_with(".claude.ai")
                || h == "chatgpt.com"
                || h.ends_with(".chatgpt.com")
        })
}

fn build_chained_probe_client(chained: &str, timeout: Duration) -> Option<reqwest::Client> {
    let proxy_url = if chained.contains("://") {
        chained.to_string()
    } else {
        format!("http://{chained}")
    };
    let proxy = reqwest::Proxy::all(&proxy_url).ok()?;
    reqwest::Client::builder()
        .timeout(timeout)
        .pool_max_idle_per_host(0)
        .user_agent(NEUTRAL_USER_AGENT)
        .proxy(proxy)
        .build()
        .ok()
}

fn default_exit_probe_url(provider: ProviderId, has_route: bool) -> &'static str {
    if !has_route {
        return NEUTRAL_EXIT_PROBE_URL;
    }
    match provider {
        ProviderId::Anthropic => "https://claude.ai/cdn-cgi/trace",
        ProviderId::Openai => "https://chatgpt.com/cdn-cgi/trace",
        ProviderId::Gemini => "https://ipinfo.io/json",
    }
}

enum ProbeFetchError {
    Timeout,
    Unreachable(String),
}

async fn probe_url_with_client(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
) -> Result<(u16, String), ProbeFetchError> {
    let resp = client.get(url).timeout(timeout).send().await.map_err(|e| {
        if e.is_timeout() {
            ProbeFetchError::Timeout
        } else {
            ProbeFetchError::Unreachable(e.to_string())
        }
    })?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|e| {
        if e.is_timeout() {
            ProbeFetchError::Timeout
        } else {
            ProbeFetchError::Unreachable(e.to_string())
        }
    })?;
    Ok((status, body))
}

/// Gate 10: Evaluates reverse DNS / hostname / ISP / org for suspicious proxy and anonymizer markers.
pub fn evaluate_reverse_dns_ptr(telemetry: &NetworkTelemetry) -> CheckResult {
    let mut examined = Vec::new();
    if let Some(h) = &telemetry.hostname {
        examined.push(h.as_str());
    }
    if let Some(isp) = &telemetry.isp {
        examined.push(isp.as_str());
    }
    if let Some(org) = &telemetry.org {
        examined.push(org.as_str());
    }

    for text in examined {
        let lower = text.to_lowercase();
        for &marker in SUSPICIOUS_ANONYMIZER_MARKERS {
            if lower.contains(marker) {
                return CheckResult::warning(
                    "REVERSE_DNS_ANONYMIZER_MARKER",
                    format!(
                        "В данных узла ({text}) обнаружен маркер публичного анонимайзера «{marker}». Антифрод-системы ИИ блокируют такие адреса. Рекомендуется сменить сервер на чистый VPS."
                    ),
                    Some(crate::auditor::geo_matrix::GUIDE_PERSONAL_VPN.to_string()),
                );
            }
        }
    }

    fn non_empty(v: &Option<String>) -> Option<&str> {
        v.as_deref().filter(|t| !t.trim().is_empty())
    }
    let Some(detail) = non_empty(&telemetry.hostname)
        .or(non_empty(&telemetry.isp))
        .or(non_empty(&telemetry.org))
    else {
        return CheckResult::unknown(
            "REVERSE_DNS_NO_DATA",
            "Reverse DNS не проверен: источник геолокации не передал имя узла, провайдера и организацию.",
            UnknownReason::NoData,
        );
    };

    CheckResult::ok(
        "REVERSE_DNS_CLEAN",
        format!(
            "В имени узла/провайдера выходного IP ({detail}) нет маркеров публичных анонимайзеров из встроенного списка. PTR-запись не запрашивалась: проверены данные сервиса геолокации."
        ),
    )
}

/// Gate 11: Verifies whether the exit IP geolocation across independent telemetry endpoints
/// and DNS resolution is consistent (detects cross-country DNS splits or transparent DNS hijacking).
pub fn evaluate_dns_country_consistency(
    telemetry: &NetworkTelemetry,
    secondary_country: Option<&str>,
) -> CheckResult {
    let exit_country = telemetry.country_code.trim().to_uppercase();

    // 1. Check if a secondary independent telemetry source reports a mismatched country
    if let Some(sec_country) = secondary_country {
        let sec = sec_country.trim().to_uppercase();
        if !sec.is_empty() && sec != exit_country {
            return CheckResult::warning(
                "DNS_COUNTRY_SPLIT",
                format!(
                    "Обнаружен рассинхрон юрисдикций: выходной IP находится в {exit_country}, а вторичный резолвер сообщает о локации {sec}. Это может указывать на утечку DNS или прозрачный DNS-прокси."
                ),
                Some(crate::auditor::geo_matrix::GUIDE_OS_PRIVACY.to_string()),
            );
        }
    }

    if secondary_country.is_none_or(|c| c.trim().is_empty()) {
        // No independent source to compare with: nothing was verified.
        return CheckResult::unknown(
            "DNS_COUNTRY_NO_SOURCE",
            "Согласованность страны DNS и выходного узла не проверена: нет независимого источника для сравнения.",
            UnknownReason::NoData,
        );
    }

    CheckResult::ok(
        "DNS_COUNTRY_CONSISTENT",
        format!(
            "Географическая юрисдикция DNS и выходного узла ({exit_country}) полностью согласованы."
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_freshness() {
        let mut tel = NetworkTelemetry {
            ip: "185.1.1.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(20473),
            org: Some("Choopa".to_string()),
            isp: Some("Choopa".to_string()),
            timezone: Some("Europe/Amsterdam".to_string()),
            resolved_at: current_timestamp(),
        };

        assert!(tel.is_fresh(30));

        // Expired telemetry
        tel.resolved_at = current_timestamp().saturating_sub(35);
        assert!(!tel.is_fresh(30));
    }

    #[test]
    fn test_ipinfo_org_parsing() {
        let org_str = "AS20473 The Constant Company, LLC";
        let rest = org_str.strip_prefix("AS").unwrap();
        let mut parts = rest.splitn(2, ' ');
        let asn: u32 = parts.next().unwrap().parse().unwrap();
        let org = parts.next().unwrap();
        assert_eq!(asn, 20473);
        assert_eq!(org, "The Constant Company, LLC");
    }

    #[test]
    fn test_build_upstream_client() {
        let socks_cfg = UpstreamProxyConfig {
            enabled: true,
            raw_key: "socks5://u:p@127.0.0.1:1080".to_string(),
            protocol: "socks5".to_string(),
            host: "127.0.0.1".to_string(),
            port: 1080,
            username: Some("u".to_string()),
            password: Some("p".to_string()),
            label: None,
        };
        assert!(build_upstream_client(&socks_cfg).is_ok());

        let http_cfg = UpstreamProxyConfig {
            enabled: true,
            raw_key: "http://127.0.0.1:8080".to_string(),
            protocol: "http".to_string(),
            host: "127.0.0.1".to_string(),
            port: 8080,
            username: None,
            password: None,
            label: None,
        };
        assert!(build_upstream_client(&http_cfg).is_ok());
    }

    #[tokio::test]
    async fn test_resolver_cache_with_upstream_key() {
        let resolver = NetworkResolver::new();

        let tel_direct = NetworkTelemetry {
            ip: "109.1.1.1".to_string(),
            country_code: "RU".to_string(),
            hostname: None,
            asn: Some(1234),
            org: Some("Rostelecom".to_string()),
            isp: Some("Rostelecom".to_string()),
            timezone: Some("Europe/Moscow".to_string()),
            resolved_at: current_timestamp(),
        };

        let tel_nl = NetworkTelemetry {
            ip: "185.10.10.1".to_string(),
            country_code: "NL".to_string(),
            hostname: Some("nl-exit-01.cleanhost.net".to_string()),
            asn: Some(20473),
            org: Some("Choopa".to_string()),
            isp: Some("Choopa".to_string()),
            timezone: Some("Europe/Amsterdam".to_string()),
            resolved_at: current_timestamp(),
        };

        // Cache direct IP
        resolver.set_cached(tel_direct.clone()).await;
        let res1 = resolver.resolve(false).await.unwrap();
        assert_eq!(res1.ip, "109.1.1.1");

        // Cache NL upstream proxy IP under specific proxy key
        let key = Some("socks5://185.10.10.1:1080".to_string());
        resolver
            .set_cached_for_key(key.clone(), tel_nl.clone())
            .await;

        let cfg = UpstreamProxyConfig {
            enabled: true,
            raw_key: "socks5://185.10.10.1:1080".to_string(),
            protocol: "socks5".to_string(),
            host: "185.10.10.1".to_string(),
            port: 1080,
            username: None,
            password: None,
            label: None,
        };

        let res2 = resolver
            .resolve_with_upstream(false, Some(&cfg))
            .await
            .unwrap();
        assert_eq!(res2.ip, "185.10.10.1");
        assert_eq!(res2.country_code, "NL");
    }

    #[test]
    fn test_reverse_dns_ptr_detection() {
        let bad_tel = NetworkTelemetry {
            ip: "185.220.101.5".to_string(),
            country_code: "DE".to_string(),
            hostname: Some("tor-exit-node-03.anonymizer.org".to_string()),
            asn: Some(1234),
            org: Some("Privacy Inc".to_string()),
            isp: Some("Tor Exit Relay".to_string()),
            timezone: Some("Europe/Berlin".to_string()),
            resolved_at: current_timestamp(),
        };
        let bad_res = evaluate_reverse_dns_ptr(&bad_tel);
        assert_eq!(
            bad_res.status,
            crate::auditor::geo_matrix::CheckStatus::Warning
        );
        assert_eq!(bad_res.code, "REVERSE_DNS_ANONYMIZER_MARKER");

        let clean_tel = NetworkTelemetry {
            ip: "95.217.1.1".to_string(),
            country_code: "FI".to_string(),
            hostname: Some("static.95-217-1-1.clients.your-server.de".to_string()),
            asn: Some(24940),
            org: Some("Hetzner Online GmbH".to_string()),
            isp: Some("Hetzner Online GmbH".to_string()),
            timezone: Some("Europe/Helsinki".to_string()),
            resolved_at: current_timestamp(),
        };
        let clean_res = evaluate_reverse_dns_ptr(&clean_tel);
        assert_eq!(
            clean_res.status,
            crate::auditor::geo_matrix::CheckStatus::Ok
        );
        assert_eq!(clean_res.code, "REVERSE_DNS_CLEAN");
    }

    #[test]
    fn test_dns_country_consistency() {
        let tel = NetworkTelemetry {
            ip: "185.10.10.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(20473),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        };

        // Split country
        let split_res = evaluate_dns_country_consistency(&tel, Some("RU"));
        assert_eq!(
            split_res.status,
            crate::auditor::geo_matrix::CheckStatus::Warning
        );
        assert_eq!(split_res.code, "DNS_COUNTRY_SPLIT");

        // Matching country
        let clean_res = evaluate_dns_country_consistency(&tel, Some("NL"));
        assert_eq!(
            clean_res.status,
            crate::auditor::geo_matrix::CheckStatus::Ok
        );
        assert_eq!(clean_res.code, "DNS_COUNTRY_CONSISTENT");

        // No independent source: unknown, never "consistent"
        let none_res = evaluate_dns_country_consistency(&tel, None);
        assert_eq!(
            none_res.status,
            crate::auditor::geo_matrix::CheckStatus::Unknown
        );
        assert_eq!(none_res.reason, Some(UnknownReason::NoData));
    }

    #[test]
    fn test_reverse_dns_without_any_data_is_unknown() {
        let bare = NetworkTelemetry {
            ip: "185.10.10.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(1),
            org: None,
            isp: Some("  ".to_string()),
            timezone: None,
            resolved_at: current_timestamp(),
        };
        let res = evaluate_reverse_dns_ptr(&bare);
        assert_eq!(res.status, crate::auditor::geo_matrix::CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::NoData));
    }

    #[test]
    fn test_has_provider_metadata() {
        let bare = NetworkTelemetry {
            ip: "185.10.10.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        };
        assert!(!bare.has_provider_metadata());

        let rich = NetworkTelemetry {
            asn: Some(20473),
            ..bare
        };
        assert!(rich.has_provider_metadata());
    }

    /// reqwest 0.12 + rustls can use an `https://` proxy: TLS to the entry (verified against the
    /// trusted root, SNI from the key), `CONNECT` with Basic auth, then TLS to the target inside.
    #[tokio::test]
    async fn test_entry_client_through_https_proxy_stub() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "audit.test".to_string()])
                .unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let server_cfg = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut outer = acceptor.accept(tcp).await.unwrap();
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if outer.read(&mut b).await.unwrap() == 0 {
                    return;
                }
                head.push(b[0]);
            }
            let _ = seen_tx.send(String::from_utf8_lossy(&head).to_string());
            outer
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            // Inner TLS: we are now the target audit.test.
            let mut inner = acceptor.accept(outer).await.unwrap();
            let mut req = [0u8; 1024];
            let _ = inner.read(&mut req).await.unwrap();
            inner
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            let _ = inner.shutdown().await;
        });

        let entry = Entry {
            proto: EntryProto::Https,
            host: "127.0.0.1".to_string(),
            port,
            username: Some("alice".to_string()),
            password: Some("wonderland".to_string()),
            sni: Some("localhost".to_string()),
        };
        let root = reqwest::Certificate::from_der(ca.der()).unwrap();
        let client = build_entry_client_with_root(&entry, root).await.unwrap();
        let body = match client.get("https://audit.test/").send().await {
            Ok(r) => r.text().await.unwrap(),
            Err(e) if format!("{e:?}").contains("PermissionDenied") => return,
            Err(e) => panic!("request through https proxy failed: {e:?}"),
        };
        assert_eq!(body, "ok");
        let seen = seen_rx.await.unwrap();
        assert!(
            seen.starts_with("CONNECT audit.test:443 HTTP/1.1"),
            "{seen}"
        );
        // base64("alice:wonderland")
        assert!(seen.contains("YWxpY2U6d29uZGVybGFuZA=="), "{seen}");

        // Without the test root (production path) the private CA is rejected.
        let prod = build_entry_client(&entry, true, 0).await.unwrap();
        assert!(prod.get("https://audit.test/").send().await.is_err());
    }

    #[tokio::test]
    async fn test_resolver_cache_keyed_by_route_id() {
        let resolver = NetworkResolver::new();
        let tel = |ip: &str| NetworkTelemetry {
            ip: ip.to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(1),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        };
        resolver.set_cached(tel("109.1.1.1")).await;
        resolver
            .set_cached_for_route(Some("route-a".into()), tel("185.1.1.1"))
            .await;
        resolver
            .set_cached_for_route(Some("route-b".into()), tel("185.2.2.2"))
            .await;
        let mk = |id: &str| Route {
            id: id.to_string(),
            label: id.to_string(),
            country: None,
            exit_ip: None,
            expires_at: None,
            entries: vec![],
            raw_key: String::new(),
            enabled: true,
            added_at: 0,
        };
        assert_eq!(resolver.resolve(false).await.unwrap().ip, "109.1.1.1");
        assert_eq!(
            resolver
                .resolve_with_route(false, Some(&mk("route-a")))
                .await
                .unwrap()
                .ip,
            "185.1.1.1"
        );
        assert_eq!(
            resolver
                .resolve_with_route(false, Some(&mk("route-b")))
                .await
                .unwrap()
                .ip,
            "185.2.2.2"
        );
        resolver.invalidate_route("route-a").await;
        // No entries -> cannot resolve, and never falls back to the direct cache.
        assert!(
            resolver
                .resolve_with_route(false, Some(&mk("route-a")))
                .await
                .is_err()
        );
    }

    async fn spawn_http_mock(
        status: &'static str,
        content_type: &'static str,
        body: &'static str,
        delay: Duration,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://127.0.0.1:{}/cdn-cgi/trace", addr.port())
    }

    #[tokio::test]
    async fn probe_provider_exit_matches_telemetry_ip_and_sets_measured_via() {
        let url = spawn_http_mock(
            "200 OK",
            "text/plain",
            "fl=1\nip=185.10.20.30\nloc=NL\ncolo=AMS\n",
            Duration::ZERO,
        )
        .await;
        let resolver = NetworkResolver::new();
        let matrix = ProviderMatrix::load_bundled().unwrap();
        let telemetry = NetworkTelemetry {
            ip: "185.10.20.30".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(20473),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let res = resolver
            .probe_provider_exit_with_url(
                ProviderId::Anthropic,
                None,
                &telemetry,
                &matrix,
                &url,
                Some(&client),
                Duration::from_secs(2),
            )
            .await;
        assert_eq!(res.status, CheckStatus::Ok);
        assert_eq!(res.code, "PROVIDER_EXIT_VERIFIED");
        assert_eq!(res.measured_via.as_deref(), Some("1.1.1.1"));
        assert!(res.message.contains("185.10.20.30"));
        assert!(res.message.contains("AMS"));
    }

    #[tokio::test]
    async fn probe_provider_exit_warns_on_split_tunnel_ip_mismatch() {
        let url = spawn_http_mock(
            "200 OK",
            "text/plain",
            "fl=1\nip=95.10.20.30\nloc=DE\ncolo=FRA\n",
            Duration::ZERO,
        )
        .await;
        let resolver = NetworkResolver::new();
        let matrix = ProviderMatrix::load_bundled().unwrap();
        let telemetry = NetworkTelemetry {
            ip: "185.10.20.30".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(20473),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let res = resolver
            .probe_provider_exit_with_url(
                ProviderId::Anthropic,
                None,
                &telemetry,
                &matrix,
                &url,
                Some(&client),
                Duration::from_secs(2),
            )
            .await;
        assert_eq!(res.status, CheckStatus::Warning);
        assert_eq!(res.code, "PROVIDER_EXIT_SPLIT_MISMATCH");
        assert!(res.message.contains("split tunnel/PAC"));
    }

    #[tokio::test]
    async fn probe_provider_exit_returns_source_refused_on_403_and_html_challenge() {
        let url_403 = spawn_http_mock(
            "403 Forbidden",
            "text/plain",
            "Just a moment...",
            Duration::ZERO,
        )
        .await;
        let url_html = spawn_http_mock(
            "200 OK",
            "text/html",
            "<!doctype html><html><body>Challenge</body></html>",
            Duration::ZERO,
        )
        .await;
        let resolver = NetworkResolver::new();
        let matrix = ProviderMatrix::load_bundled().unwrap();
        let telemetry = NetworkTelemetry {
            ip: "185.10.20.30".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();

        for url in [url_403, url_html] {
            let res = resolver
                .probe_provider_exit_with_url(
                    ProviderId::Openai,
                    None,
                    &telemetry,
                    &matrix,
                    &url,
                    Some(&client),
                    Duration::from_secs(2),
                )
                .await;
            assert_eq!(res.status, CheckStatus::Unknown);
            assert_eq!(res.reason, Some(UnknownReason::SourceRefused));
            assert_eq!(res.measured_via.as_deref(), Some("1.1.1.1"));
        }
    }

    #[tokio::test]
    async fn probe_provider_exit_returns_timeout_when_server_stalls() {
        let url = spawn_http_mock(
            "200 OK",
            "text/plain",
            "ip=185.10.20.30\nloc=NL\n",
            Duration::from_millis(300),
        )
        .await;
        let resolver = NetworkResolver::new();
        let matrix = ProviderMatrix::load_bundled().unwrap();
        let telemetry = NetworkTelemetry {
            ip: "185.10.20.30".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let res = resolver
            .probe_provider_exit_with_url(
                ProviderId::Anthropic,
                None,
                &telemetry,
                &matrix,
                &url,
                Some(&client),
                Duration::from_millis(50),
            )
            .await;
        assert_eq!(res.status, CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::Timeout));
    }

    #[tokio::test]
    async fn probe_provider_exit_gemini_direct_is_not_applicable_and_bound_route_uses_route_label()
    {
        let url = spawn_http_mock(
            "200 OK",
            "application/json",
            r#"{"ip":"185.55.66.77","country":"DE"}"#,
            Duration::ZERO,
        )
        .await;
        let resolver = NetworkResolver::new();
        let matrix = ProviderMatrix::load_bundled().unwrap();
        let telemetry = NetworkTelemetry {
            ip: "185.55.66.77".to_string(),
            country_code: "DE".to_string(),
            hostname: None,
            asn: Some(24940),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        };
        let direct = resolver
            .probe_provider_exit(ProviderId::Gemini, None, &telemetry, &matrix)
            .await;
        assert_eq!(direct.status, CheckStatus::Unknown);
        assert_eq!(direct.reason, Some(UnknownReason::NotApplicable));

        let route = Route {
            id: "r1".to_string(),
            label: "DE VPS".to_string(),
            country: Some("DE".to_string()),
            exit_ip: None,
            expires_at: None,
            entries: vec![],
            raw_key: String::new(),
            enabled: true,
            added_at: 0,
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let bound = resolver
            .probe_provider_exit_with_url(
                ProviderId::Gemini,
                Some(&route),
                &telemetry,
                &matrix,
                &url,
                Some(&client),
                Duration::from_secs(2),
            )
            .await;
        assert_eq!(bound.status, CheckStatus::Ok);
        assert_eq!(
            bound.measured_via.as_deref(),
            Some("gemini (ipinfo.io) (маршрут ключа)")
        );
    }

    #[tokio::test]
    async fn resolver_and_entry_clients_use_neutral_user_agent_without_zastava() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        assert!(!NEUTRAL_USER_AGENT.to_ascii_lowercase().contains("zastava"));

        // 1. Direct client in NetworkResolver::new
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
            }
        });

        let resolver = NetworkResolver::new();
        let _ = resolver
            .client
            .get(format!("http://127.0.0.1:{port}/test"))
            .send()
            .await
            .unwrap();
        let raw_req = rx.await.unwrap();
        let lower = raw_req.to_ascii_lowercase();
        assert!(
            !lower.contains("zastava"),
            "User-Agent must never reveal Zastava: {raw_req}"
        );
        assert!(
            raw_req.contains(NEUTRAL_USER_AGENT),
            "Expected neutral UA in request: {raw_req}"
        );

        // 2. Entry proxy client in entry_client_builder
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let (ptx, prx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = proxy_listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let _ = ptx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
            }
        });
        let entry = Entry {
            proto: EntryProto::Http,
            host: "127.0.0.1".to_string(),
            port: proxy_port,
            username: None,
            password: None,
            sni: None,
        };
        let entry_client = build_entry_client(&entry, true, 0).await.unwrap();
        let _ = entry_client.get("http://probe.invalid/").send().await;
        let proxy_req = prx.await.unwrap();
        assert!(!proxy_req.to_ascii_lowercase().contains("zastava"));
        assert!(proxy_req.contains(NEUTRAL_USER_AGENT));
    }

    #[tokio::test]
    async fn probe_provider_exit_with_no_route_never_contacts_claude_or_chatgpt() {
        use std::sync::Mutex;

        struct RecordingProbe {
            urls: Mutex<Vec<String>>,
        }
        impl IpProbe for RecordingProbe {
            fn get<'a>(
                &'a self,
                url: &'a str,
                _limit: Duration,
            ) -> crate::auditor::seams::BoxFuture<'a, HttpProbeOutcome> {
                self.urls.lock().unwrap().push(url.to_string());
                Box::pin(async move {
                    HttpProbeOutcome::Response {
                        status: 200,
                        body: "fl=1\nip=185.10.20.30\nloc=NL\ncolo=AMS\n".to_string(),
                    }
                })
            }
        }

        assert_eq!(
            default_exit_probe_url(ProviderId::Anthropic, false),
            "https://1.1.1.1/cdn-cgi/trace"
        );
        assert_eq!(
            default_exit_probe_url(ProviderId::Openai, false),
            "https://1.1.1.1/cdn-cgi/trace"
        );
        assert_eq!(
            default_exit_probe_url(ProviderId::Anthropic, true),
            "https://claude.ai/cdn-cgi/trace"
        );
        assert_eq!(
            default_exit_probe_url(ProviderId::Openai, true),
            "https://chatgpt.com/cdn-cgi/trace"
        );

        let resolver = NetworkResolver::new();
        let matrix = ProviderMatrix::load_bundled().unwrap();
        let telemetry = NetworkTelemetry {
            ip: "185.10.20.30".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(20473),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        };
        let probe = RecordingProbe {
            urls: Mutex::new(Vec::new()),
        };

        for pid in [
            ProviderId::Anthropic,
            ProviderId::Openai,
            ProviderId::Gemini,
        ] {
            let _ = resolver
                .probe_provider_exit_with_probe(pid, None, &telemetry, &matrix, Some(&probe))
                .await;
        }

        let urls = probe.urls.lock().unwrap();
        assert!(!urls.is_empty());
        for u in urls.iter() {
            assert!(
                !u.contains("claude.ai") && !u.contains("chatgpt.com"),
                "Unbound probe must NEVER contact provider domains directly: {u}"
            );
            assert_eq!(u, "https://1.1.1.1/cdn-cgi/trace");
        }
    }

    #[test]
    fn checked_entry_error_separates_dns_failure_from_policy_rejection() {
        let dns_err = std::io::Error::from_raw_os_error(11001);
        let dns_msg = format_checked_entry_error("node.example:443", &dns_err);
        assert!(dns_msg.contains("DNS lookup failed:"), "{dns_msg}");
        assert!(!dns_msg.contains("rejected:"), "{dns_msg}");

        let policy_err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "entry node points to the Zastava gateway itself",
        );
        let policy_msg = format_checked_entry_error("127.0.0.1:8899", &policy_err);
        assert!(policy_msg.contains("rejected:"), "{policy_msg}");
        assert!(!policy_msg.contains("DNS lookup failed:"), "{policy_msg}");
    }

    #[tokio::test]
    async fn invalidate_cache_mid_flight_discards_stale_telemetry_and_clears_check_cache() {
        use std::sync::atomic::AtomicUsize;

        let resolver = NetworkResolver::new();
        let _ = resolver
            .check_cache()
            .os
            .get_or_compute("tz:stale", Duration::from_secs(60), |_| true, async {
                CheckResult::ok("T", "stale")
            })
            .await;
        assert!(resolver.check_cache().os.contains_key("tz:stale").await);

        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let started_bg = Arc::clone(&started);
        let release_bg = Arc::clone(&release);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_bg = Arc::clone(&calls);

        let resolver_bg = resolver.clone();
        let inflight = tokio::spawn(async move {
            resolver_bg
                .resolve_cached_or_fetch(None, None, false, || async move {
                    calls_bg.fetch_add(1, Ordering::SeqCst);
                    started_bg.notify_one();
                    release_bg.notified().await;
                    Ok(NetworkTelemetry {
                        ip: "5.5.5.5".to_string(),
                        country_code: "RU".to_string(),
                        hostname: None,
                        asn: Some(9009),
                        org: None,
                        isp: Some("OldVPN".to_string()),
                        timezone: None,
                        resolved_at: current_timestamp(),
                    })
                })
                .await
        });

        // Wait until the slow resolve is mid-flight inside `resolve_lock`, then invalidate.
        started.notified().await;
        resolver.invalidate_cache().await;
        assert!(
            resolver.check_cache().os.is_empty().await,
            "invalidate_cache must clear CheckCache immediately"
        );

        release.notify_one();
        let stale_ret = inflight.await.unwrap().unwrap();
        assert_eq!(stale_ret.ip, "5.5.5.5");

        // Stale result MUST NOT poison `self.cache` for subsequent lookups.
        assert!(
            resolver.cached_direct_country("5.5.5.5").await.is_none(),
            "stale IP must be discarded instead of poisoning cache"
        );

        let calls_next = Arc::clone(&calls);
        let fresh = resolver
            .resolve_cached_or_fetch(None, None, false, || async move {
                calls_next.fetch_add(1, Ordering::SeqCst);
                Ok(NetworkTelemetry {
                    ip: "145.241.193.245".to_string(),
                    country_code: "GB".to_string(),
                    hostname: None,
                    asn: Some(31898),
                    org: None,
                    isp: Some("PinnedVPS".to_string()),
                    timezone: None,
                    resolved_at: current_timestamp(),
                })
            })
            .await
            .unwrap();
        assert_eq!(fresh.ip, "145.241.193.245");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            resolver
                .cached_direct_country("145.241.193.245")
                .await
                .as_deref(),
            Some("GB")
        );

        // Next lookup uses the newly populated clean cache without re-fetching.
        let calls_cached = Arc::clone(&calls);
        let hit = resolver
            .resolve_cached_or_fetch(None, None, false, || async move {
                calls_cached.fetch_add(1, Ordering::SeqCst);
                Err("should hit cache".to_string())
            })
            .await
            .unwrap();
        assert_eq!(hit.ip, "145.241.193.245");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
