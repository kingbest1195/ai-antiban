//! TTL cache for the checks whose outcome does not depend on the AI provider (DNSBL, IPv6 probe,
//! OS checks). One instance is shared by the three providers' audits, so a full audit runs each of
//! them once instead of three times, and a slow DNS cannot multiply the timeouts.
//!
//! Only valid results are kept for the full TTL. An `Unknown` (the check could not be performed)
//! is remembered for a few seconds at most, so that concurrent audits do not repeat the same
//! failing probe, but a failure never turns into a long-lived answer.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::auditor::geo_matrix::{CheckResult, SourceState, UnknownReason};
use crate::auditor::ip_type::TorListCache;
use crate::auditor::probes::whoami::{GeoInfo, ResolverView};

/// DNSBL answer per exit IP.
pub const DNSBL_TTL: Duration = Duration::from_secs(600);
/// IPv6 leak probe.
pub const IPV6_TTL: Duration = Duration::from_secs(60);
/// `scutil`/time zone/locale/location checks.
pub const OS_TTL: Duration = Duration::from_secs(45);
/// Resolver seen by the whoami sources (shared by the DNS-resolver and DNS-country checks).
pub const WHOAMI_TTL: Duration = Duration::from_secs(60);
/// Country of a resolver address.
pub const GEO_TTL: Duration = Duration::from_secs(600);
/// STUN (UDP) probe: rare requests, per HTTP exit address.
pub const UDP_TTL: Duration = Duration::from_secs(60);
/// Reverse DNS PTR result per exit IP/metadata.
pub const RDNS_TTL: Duration = Duration::from_secs(600);
/// How long a failed (`Unknown`) outcome is reused.
pub const UNKNOWN_TTL: Duration = Duration::from_secs(5);
/// Cooldown for failed/unmeasured whoami DNS resolver probes so transient VPN flaps don't thrash every 10s.
pub const RESOLVER_UNKNOWN_TTL: Duration = Duration::from_secs(25);
/// Extended cooldown when Akamai A succeeds while Google TXT fails (e.g. VPN stub DNS rejecting TXT)
/// and system DNS servers have not changed.
pub const RESOLVER_TXT_FAILED_TTL: Duration = Duration::from_secs(120);
/// Cooldown for failed external list/reputation lookups (DNSBL, Tor, rDNS) over double-tunnel VPNs.
pub const EXTERNAL_LIST_UNKNOWN_TTL: Duration = Duration::from_secs(30);

const MAX_ENTRIES: usize = 64;

struct Entry<V> {
    stored_at: Instant,
    ttl: Duration,
    value: V,
}

/// Single-flight TTL cache: concurrent callers for the same cache wait for the one running probe
/// and then reuse its result.
pub struct TtlCache<V> {
    entries: Mutex<HashMap<String, Entry<V>>>,
}

impl<V> Default for TtlCache<V> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<V: Clone> TtlCache<V> {
    /// Returns the fresh cached value for `key`, or runs `compute` and stores its value for `ttl`
    /// when `is_valid(&value)`, for [`UNKNOWN_TTL`] otherwise.
    pub async fn get_or_compute<Fut>(
        &self,
        key: &str,
        ttl: Duration,
        is_valid: impl Fn(&V) -> bool,
        compute: Fut,
    ) -> V
    where
        Fut: std::future::Future<Output = V>,
    {
        self.get_or_compute_with_unknown_ttl(key, ttl, UNKNOWN_TTL, is_valid, compute)
            .await
    }

    /// Like [`Self::get_or_compute`] with an explicit `unknown_ttl` when `is_valid(&value)` is false.
    pub async fn get_or_compute_with_unknown_ttl<Fut>(
        &self,
        key: &str,
        ttl: Duration,
        unknown_ttl: Duration,
        is_valid: impl Fn(&V) -> bool,
        compute: Fut,
    ) -> V
    where
        Fut: std::future::Future<Output = V>,
    {
        self.get_or_compute_with_ttl_fn(
            key,
            |value| {
                if is_valid(value) {
                    ttl
                } else {
                    unknown_ttl.min(ttl)
                }
            },
            compute,
        )
        .await
    }

    /// Like [`Self::get_or_compute`] where `ttl_for(&value)` selects the cache lifetime per outcome.
    pub async fn get_or_compute_with_ttl_fn<Fut>(
        &self,
        key: &str,
        ttl_for: impl Fn(&V) -> Duration,
        compute: Fut,
    ) -> V
    where
        Fut: std::future::Future<Output = V>,
    {
        // Held across `compute` on purpose (single-flight); dropping the future releases it.
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        if let Some(e) = entries
            .get(key)
            .filter(|e| now.saturating_duration_since(e.stored_at) < e.ttl)
        {
            return e.value.clone();
        }
        let value = compute.await;
        let now = Instant::now();
        entries.retain(|_, e| now.saturating_duration_since(e.stored_at) < e.ttl);
        if entries.len() >= MAX_ENTRIES {
            entries.clear();
        }
        let ttl = ttl_for(&value);
        entries.insert(
            key.to_string(),
            Entry {
                stored_at: now,
                ttl,
                value: value.clone(),
            },
        );
        value
    }

    pub async fn clear(&self) {
        self.entries.lock().await.clear();
    }

    pub async fn is_empty(&self) -> bool {
        self.entries.lock().await.is_empty()
    }

    pub async fn contains_key(&self, key: &str) -> bool {
        self.entries.lock().await.contains_key(key)
    }
}

/// Cache of a plain check result: `Unknown` is not a valid (long-lived) answer.
pub async fn cached_check<Fut>(
    cache: &TtlCache<CheckResult>,
    key: &str,
    ttl: Duration,
    compute: Fut,
) -> CheckResult
where
    Fut: std::future::Future<Output = CheckResult>,
{
    cache
        .get_or_compute(key, ttl, |r| !r.is_unknown(), compute)
        .await
}

/// Returns `true` when Akamai A succeeded while Google TXT failed (single-source unmeasured),
/// indicating a stub DNS resolver blocking TXT queries while A records resolve normally.
fn is_single_source_txt_failed(view: &ResolverView) -> bool {
    let ResolverView::Unmeasured(u) = view else {
        return false;
    };
    if u.code != "DNS_WHOAMI_SINGLE_SOURCE" {
        return false;
    }
    let akamai_ok = u
        .sources
        .iter()
        .any(|s| s.source == "Akamai" && s.state == SourceState::Answered);
    let google_failed = u
        .sources
        .iter()
        .any(|s| s.source == "Google" && s.state == SourceState::Failed);
    akamai_ok && google_failed
}

/// Resolver-specific TTL cache that extends cooldown to [`RESOLVER_TXT_FAILED_TTL`] when only
/// Google TXT fails while Akamai A succeeds and the system DNS servers remain unchanged.
#[derive(Default)]
pub struct ResolverCache {
    inner: TtlCache<ResolverView>,
    last_dns_sig: std::sync::Mutex<Option<String>>,
}

impl ResolverCache {
    pub async fn get_or_compute_with_unknown_ttl<Fut>(
        &self,
        key: &str,
        ttl: Duration,
        unknown_ttl: Duration,
        is_valid: impl Fn(&ResolverView) -> bool,
        compute: Fut,
    ) -> ResolverView
    where
        Fut: std::future::Future<Output = ResolverView>,
    {
        let dns_sig = crate::auditor::seams::last_known_nameserver_sig();
        self.get_or_compute_with_dns_sig(key, ttl, unknown_ttl, &dns_sig, is_valid, compute)
            .await
    }

    pub async fn get_or_compute_with_dns_sig<Fut>(
        &self,
        key: &str,
        ttl: Duration,
        unknown_ttl: Duration,
        dns_sig: &str,
        is_valid: impl Fn(&ResolverView) -> bool,
        compute: Fut,
    ) -> ResolverView
    where
        Fut: std::future::Future<Output = ResolverView>,
    {
        if !dns_sig.is_empty() {
            let changed = {
                let guard = self.last_dns_sig.lock().unwrap_or_else(|e| e.into_inner());
                guard.as_deref().is_some_and(|prev| prev != dns_sig)
            };
            if changed {
                self.inner.clear().await;
            }
        }
        let val = self
            .inner
            .get_or_compute_with_ttl_fn(
                key,
                |v| {
                    if is_valid(v) {
                        ttl
                    } else if is_single_source_txt_failed(v) {
                        RESOLVER_TXT_FAILED_TTL
                    } else {
                        unknown_ttl.min(ttl)
                    }
                },
                compute,
            )
            .await;
        let post_sig = crate::auditor::seams::last_known_nameserver_sig();
        let recorded_sig = if !post_sig.is_empty() {
            post_sig
        } else {
            dns_sig.to_string()
        };
        if !recorded_sig.is_empty() {
            *self.last_dns_sig.lock().unwrap_or_else(|e| e.into_inner()) = Some(recorded_sig);
        }
        val
    }

    pub async fn clear(&self) {
        self.inner.clear().await;
        *self.last_dns_sig.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.is_empty().await
    }
}

/// The caches of the provider-independent checks.
#[derive(Default)]
pub struct CheckCache {
    /// Per exit IP: (verdict, summary label).
    pub dnsbl: TtlCache<(CheckResult, String)>,
    pub ipv6: TtlCache<CheckResult>,
    /// `scutil`, time zone, locale and location checks (key = check + its inputs).
    pub os: TtlCache<CheckResult>,
    /// The DNS resolver that sees the requests (whoami), under one key.
    pub resolver: ResolverCache,
    /// Per resolver address: its country (and ASN / organisation), or why it could not be found.
    pub geo: TtlCache<Result<GeoInfo, UnknownReason>>,
    /// STUN verdict per HTTP exit address.
    pub udp: TtlCache<CheckResult>,
    /// Reverse DNS PTR verdict per exit IP/metadata.
    pub rdns: TtlCache<CheckResult>,
    /// The Tor exit list (one entry, 6 h). Not cleared when the network changes: it does not
    /// depend on the network, and a refetch on every switch would only add requests.
    pub tor: TorListCache,
}

impl CheckCache {
    /// Forget everything (the network changed).
    pub async fn clear(&self) {
        self.dnsbl.clear().await;
        self.ipv6.clear().await;
        self.os.clear().await;
        self.resolver.clear().await;
        self.geo.clear().await;
        self.udp.clear().await;
        self.rdns.clear().await;
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
