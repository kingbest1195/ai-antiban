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

use crate::auditor::geo_matrix::CheckResult;

/// DNSBL answer per exit IP.
pub const DNSBL_TTL: Duration = Duration::from_secs(600);
/// IPv6 leak probe.
pub const IPV6_TTL: Duration = Duration::from_secs(60);
/// `scutil`/time zone/locale/location checks.
pub const OS_TTL: Duration = Duration::from_secs(45);
/// How long a failed (`Unknown`) outcome is reused.
pub const UNKNOWN_TTL: Duration = Duration::from_secs(5);

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
        let ttl = if is_valid(&value) {
            ttl
        } else {
            UNKNOWN_TTL.min(ttl)
        };
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

/// The caches of the provider-independent checks.
#[derive(Default)]
pub struct CheckCache {
    /// Per exit IP: (verdict, summary label).
    pub dnsbl: TtlCache<(CheckResult, String)>,
    pub ipv6: TtlCache<CheckResult>,
    /// `scutil`, time zone, locale and location checks (key = check + its inputs).
    pub os: TtlCache<CheckResult>,
}

impl CheckCache {
    /// Forget everything (the network changed).
    pub async fn clear(&self) {
        self.dnsbl.clear().await;
        self.ipv6.clear().await;
        self.os.clear().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::geo_matrix::UnknownReason;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn run(
        cache: &TtlCache<CheckResult>,
        calls: &AtomicUsize,
        key: &str,
        ttl: Duration,
        make: impl Fn() -> CheckResult,
    ) -> CheckResult {
        cached_check(cache, key, ttl, async {
            calls.fetch_add(1, Ordering::SeqCst);
            make()
        })
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn valid_result_is_reused_until_ttl_expires() {
        let cache = TtlCache::default();
        let calls = AtomicUsize::new(0);
        let ok = || CheckResult::ok("A", "a");
        run(&cache, &calls, "k", IPV6_TTL, ok).await;
        tokio::time::advance(Duration::from_secs(59)).await;
        run(&cache, &calls, "k", IPV6_TTL, ok).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        run(&cache, &calls, "k", IPV6_TTL, ok).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_is_only_remembered_for_a_few_seconds() {
        let cache = TtlCache::default();
        let calls = AtomicUsize::new(0);
        let unknown = || CheckResult::unknown("U", "u", UnknownReason::Timeout);
        run(&cache, &calls, "k", DNSBL_TTL, unknown).await;
        tokio::time::advance(Duration::from_secs(3)).await;
        let r = run(&cache, &calls, "k", DNSBL_TTL, unknown).await;
        assert!(r.is_unknown());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "reused within the short window"
        );
        tokio::time::advance(Duration::from_secs(3)).await;
        run(&cache, &calls, "k", DNSBL_TTL, unknown).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a failure is retried, not kept for 10 min"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keys_are_independent_and_clear_invalidates() {
        let cache = TtlCache::default();
        let calls = AtomicUsize::new(0);
        let ok = || CheckResult::ok("A", "a");
        run(&cache, &calls, "a", OS_TTL, ok).await;
        run(&cache, &calls, "b", OS_TTL, ok).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        cache.clear().await;
        run(&cache, &calls, "a", OS_TTL, ok).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_share_one_probe() {
        let cache = std::sync::Arc::new(TtlCache::default());
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let (cache, calls) = (cache.clone(), calls.clone());
            tasks.push(tokio::spawn(async move {
                cached_check(&cache, "ip", DNSBL_TTL, async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    CheckResult::ok("A", "a")
                })
                .await
            }));
        }
        for t in tasks {
            assert!(t.await.unwrap().status.is_ok());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
