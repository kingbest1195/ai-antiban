use super::*;
use crate::auditor::geo_matrix::{SourceState, SourceView, UnknownReason};
use crate::auditor::probes::whoami::Unmeasured;
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

fn single_source_txt_failed_view() -> ResolverView {
    ResolverView::Unmeasured(Unmeasured {
        code: "DNS_WHOAMI_SINGLE_SOURCE",
        reason: UnknownReason::NoData,
        detail: "ответил только один источник (Akamai), Google недоступен".into(),
        sources: vec![
            SourceView {
                source: "Akamai".into(),
                state: SourceState::Answered,
                addr: Some("1.1.1.1".into()),
                operator: Some("Cloudflare".into()),
                country: None,
            },
            SourceView {
                source: "Google".into(),
                state: SourceState::Failed,
                addr: None,
                operator: None,
                country: None,
            },
        ],
    })
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

#[tokio::test(start_paused = true)]
async fn resolver_unknown_ttl_avoids_thrashing_every_few_seconds() {
    let cache = TtlCache::default();
    let calls = AtomicUsize::new(0);
    let run_probe = || {
        cache.get_or_compute_with_unknown_ttl(
            "whoami",
            WHOAMI_TTL,
            RESOLVER_UNKNOWN_TTL,
            |r: &CheckResult| !r.is_unknown(),
            async {
                calls.fetch_add(1, Ordering::SeqCst);
                CheckResult::unknown("DNS_WHOAMI_TIMEOUT", "t", UnknownReason::Timeout)
            },
        )
    };
    run_probe().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    run_probe().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "reused across 10s poll");
    tokio::time::advance(Duration::from_secs(16)).await;
    run_probe().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "retried after 25s cooldown"
    );
}

#[tokio::test(start_paused = true)]
async fn resolver_cache_extends_cooldown_to_120s_when_txt_fails_and_invalidates_on_dns_change_or_clear()
 {
    let cache = ResolverCache::default();
    let calls = AtomicUsize::new(0);
    let query = |sig: &str| {
        let sig = sig.to_string();
        let cache = &cache;
        let calls = &calls;
        async move {
            cache
                .get_or_compute_with_dns_sig(
                    "whoami",
                    WHOAMI_TTL,
                    RESOLVER_UNKNOWN_TTL,
                    &sig,
                    |v| v.is_located(),
                    async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        single_source_txt_failed_view()
                    },
                )
                .await
        }
    };

    query("10.8.0.1").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Still cached at 90s when DNS servers are unchanged (> 25s, < 120s).
    tokio::time::advance(Duration::from_secs(90)).await;
    query("10.8.0.1").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Retried once 120s expires.
    tokio::time::advance(Duration::from_secs(31)).await;
    query("10.8.0.1").await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // Changing DNS servers immediately invalidates before 120s.
    tokio::time::advance(Duration::from_secs(5)).await;
    query("1.1.1.1").await;
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    // Explicit clear() (CheckCache::clear on network/DNS invalidation) immediately invalidates.
    cache.clear().await;
    query("1.1.1.1").await;
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}
