//! Telemetry cache, request coalescing, and direct/route resolution entrypoints.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;

use super::cascade::IpWhoIsResponse;
use super::exit_probe::parse_cloudflare_trace;
use super::{
    CACHE_TTL_SECONDS, NEUTRAL_USER_AGENT, NetworkTelemetry, REQUEST_TIMEOUT_MS, current_timestamp,
};
use crate::auditor::seams::{HttpProbeOutcome, IpProbe};
use crate::routing::{Route, route_fingerprint, route_id_for_raw_key};
use crate::state::UpstreamProxyConfig;

/// Cache key: `None` = direct egress, `Some(route id)` = egress through that route.
pub(super) type CacheKey = Option<String>;

/// Cached telemetry plus the fingerprint of the route nodes it was measured through (`None` for
/// direct egress and for test-injected values).
#[derive(Clone)]
struct CachedTelemetry {
    telemetry: NetworkTelemetry,
    route_fp: Option<u64>,
}

#[derive(Clone)]
pub struct NetworkResolver {
    pub(super) client: reqwest::Client,
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

    pub(super) async fn resolve_cached_or_fetch<F, Fut>(
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
}
