use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FakeClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl FakeClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        })
    }
    fn advance(&self, d: Duration) {
        *self.offset.lock().unwrap() += d;
    }
    fn as_fn(self: &Arc<Self>) -> ClockFn {
        let me = Arc::clone(self);
        Arc::new(move || me.base + *me.offset.lock().unwrap())
    }
}

fn counting_resolver(
    calls: Arc<AtomicUsize>,
    answer: impl Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync + 'static,
) -> ResolveFn {
    let answer = Arc::new(answer);
    Arc::new(move |host: String| {
        calls.fetch_add(1, Ordering::SeqCst);
        let res = answer(&host);
        Box::pin(async move { res })
    })
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn cache_hit_avoids_second_lookup_and_ignores_case_and_trailing_dot() {
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = FakeClock::new();
    let cache = DnsCache::new(
        counting_resolver(calls.clone(), |_| Ok(vec![ip("93.184.216.34")])),
        clock.as_fn(),
    );
    assert_eq!(
        &*cache.resolve("Example.org").await.unwrap(),
        &[ip("93.184.216.34")]
    );
    assert_eq!(
        &*cache.resolve("example.org.").await.unwrap(),
        &[ip("93.184.216.34")]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn positive_entry_expires_after_ttl() {
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = FakeClock::new();
    let cache = DnsCache::new(
        counting_resolver(calls.clone(), |_| Ok(vec![ip("93.184.216.34")])),
        clock.as_fn(),
    );
    cache.resolve("example.org").await.unwrap();
    clock.advance(DNS_POSITIVE_TTL - Duration::from_secs(1));
    cache.resolve("example.org").await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "still fresh just before the TTL"
    );
    clock.advance(Duration::from_secs(2));
    cache.resolve("example.org").await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "expired entry is looked up again"
    );
}

#[tokio::test]
async fn negative_answer_is_cached_only_for_a_few_seconds() {
    const { assert!(DNS_NEGATIVE_TTL.as_secs() <= 5) };
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = FakeClock::new();
    let cache = DnsCache::new(
        counting_resolver(calls.clone(), |_| {
            Err(io::Error::new(io::ErrorKind::NotFound, "nxdomain"))
        }),
        clock.as_fn(),
    );
    assert!(cache.resolve("nope.example").await.is_err());
    let again = cache.resolve("nope.example").await.unwrap_err();
    assert_eq!(again.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "negative answer served from the cache"
    );
    clock.advance(DNS_NEGATIVE_TTL + Duration::from_millis(1));
    assert!(cache.resolve("nope.example").await.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "negative entry expired quickly"
    );
}

#[tokio::test]
async fn empty_answer_is_a_failure_not_a_hit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = DnsCache::new(
        counting_resolver(calls.clone(), |_| Ok(vec![])),
        FakeClock::new().as_fn(),
    );
    let err = cache.resolve("empty.example").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[tokio::test]
async fn least_recently_used_entry_is_evicted_at_capacity() {
    let calls = Arc::new(AtomicUsize::new(0));
    let clock = FakeClock::new();
    let cache = DnsCache::with_limits(
        counting_resolver(calls.clone(), |_| Ok(vec![ip("93.184.216.34")])),
        clock.as_fn(),
        DNS_POSITIVE_TTL,
        DNS_NEGATIVE_TTL,
        2,
    );
    cache.resolve("a.example").await.unwrap();
    cache.resolve("b.example").await.unwrap();
    cache.resolve("a.example").await.unwrap(); // a is now more recent than b
    cache.resolve("c.example").await.unwrap(); // evicts b
    assert_eq!(cache.len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    cache.resolve("a.example").await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3, "a survived");
    cache.resolve("b.example").await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 4, "b was evicted");
}

#[tokio::test]
async fn default_capacity_is_bounded() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cache = DnsCache::new(
        counting_resolver(calls, |_| Ok(vec![ip("93.184.216.34")])),
        FakeClock::new().as_fn(),
    );
    for i in 0..(DNS_CACHE_CAPACITY + 50) {
        cache.resolve(&format!("h{i}.example")).await.unwrap();
    }
    assert_eq!(cache.len(), DNS_CACHE_CAPACITY);
}

#[tokio::test]
async fn slow_resolver_does_not_block_other_lookups() {
    // A lookup that never finishes must not hold the cache lock.
    let slow: ResolveFn = Arc::new(|host: String| {
        Box::pin(async move {
            if host == "slow.example" {
                std::future::pending::<()>().await;
            }
            Ok(vec!["93.184.216.34".parse().unwrap()])
        })
    });
    let cache = Arc::new(DnsCache::new(slow, Arc::new(Instant::now)));
    let c2 = Arc::clone(&cache);
    let stuck = tokio::spawn(async move {
        let _ = c2.resolve("slow.example").await;
    });
    tokio::task::yield_now().await;
    let quick =
        tokio::time::timeout(Duration::from_secs(1), cache.resolve("fast.example")).await;
    assert!(
        quick
            .expect("fast lookup must not wait for the slow one")
            .is_ok()
    );
    stuck.abort();
}

#[test]
fn ordering_puts_ipv6_first_and_alternates() {
    let ips = [
        ip("93.184.216.34"),
        ip("93.184.216.35"),
        ip("2606:2800:220:1::1"),
        ip("2606:2800:220:1::2"),
        ip("93.184.216.34"),
    ];
    assert_eq!(
        order_addresses(&ips),
        vec![
            ip("2606:2800:220:1::1"),
            ip("93.184.216.34"),
            ip("2606:2800:220:1::2"),
            ip("93.184.216.35"),
        ]
    );
    assert_eq!(order_addresses(&[ip("1.1.1.1")]), vec![ip("1.1.1.1")]);
    assert!(order_addresses(&[]).is_empty());
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[tokio::test(start_paused = true)]
async fn blackholed_ipv6_is_beaten_by_ipv4_within_one_step() {
    let started = tokio::time::Instant::now();
    let got = race_connect(
        vec![sa("[2606:2800:220:1::1]:443"), sa("93.184.216.34:443")],
        HAPPY_EYEBALLS_STEP,
        CONNECT_TOTAL_TIMEOUT,
        |addr| async move {
            if addr.is_ipv6() {
                std::future::pending::<io::Result<SocketAddr>>().await
            } else {
                Ok(addr)
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(got, sa("93.184.216.34:443"));
    let took = started.elapsed();
    assert!(
        took >= HAPPY_EYEBALLS_STEP,
        "IPv4 must not jump the queue: {took:?}"
    );
    assert!(took <= Duration::from_millis(350), "{took:?}");
}

#[tokio::test(start_paused = true)]
async fn failed_attempt_starts_the_next_candidate_at_once() {
    let started = tokio::time::Instant::now();
    let got = race_connect(
        vec![sa("[2606:2800:220:1::1]:443"), sa("93.184.216.34:443")],
        HAPPY_EYEBALLS_STEP,
        CONNECT_TOTAL_TIMEOUT,
        |addr| async move {
            if addr.is_ipv6() {
                Err(io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "no v6 route",
                ))
            } else {
                Ok(addr)
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(got, sa("93.184.216.34:443"));
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(start_paused = true)]
async fn slow_first_attempt_still_wins_if_it_connects_before_the_second() {
    let got = race_connect(
        vec![sa("[2606:2800:220:1::1]:443"), sa("93.184.216.34:443")],
        HAPPY_EYEBALLS_STEP,
        CONNECT_TOTAL_TIMEOUT,
        |addr| async move {
            if addr.is_ipv6() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(addr)
        },
    )
    .await
    .unwrap();
    assert!(got.is_ipv6());
}

#[tokio::test(start_paused = true)]
async fn losing_attempts_are_cancelled() {
    struct Flag(Arc<AtomicUsize>);
    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let d = dropped.clone();
    let got = race_connect(
        vec![sa("[2606:2800:220:1::1]:443"), sa("93.184.216.34:443")],
        HAPPY_EYEBALLS_STEP,
        CONNECT_TOTAL_TIMEOUT,
        move |addr| {
            let flag = Flag(d.clone());
            async move {
                let _flag = flag;
                if addr.is_ipv6() {
                    std::future::pending::<io::Result<SocketAddr>>().await
                } else {
                    Ok(addr)
                }
            }
        },
    )
    .await
    .unwrap();
    assert!(got.is_ipv4());
    tokio::task::yield_now().await;
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        2,
        "the hung IPv6 attempt was dropped"
    );
}

#[tokio::test(start_paused = true)]
async fn all_failures_report_the_last_error() {
    let err = race_connect(
        vec![sa("[2606:2800:220:1::1]:443"), sa("93.184.216.34:443")],
        HAPPY_EYEBALLS_STEP,
        CONNECT_TOTAL_TIMEOUT,
        |addr| async move {
            Err::<SocketAddr, _>(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("refused {}", addr.is_ipv6()),
            ))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
}

#[tokio::test(start_paused = true)]
async fn the_whole_race_is_bounded() {
    let started = tokio::time::Instant::now();
    let err = race_connect(
        vec![sa("[2606:2800:220:1::1]:443"), sa("93.184.216.34:443")],
        HAPPY_EYEBALLS_STEP,
        CONNECT_TOTAL_TIMEOUT,
        |_| std::future::pending::<io::Result<SocketAddr>>(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() <= Duration::from_secs(10) + Duration::from_millis(50));
}

#[test]
fn resolved_private_answers_are_refused_but_tun_fakeip_is_allowed_for_names() {
    assert!(check_resolved("a.example", &[ip("93.184.216.34")]).is_ok());
    assert!(check_resolved("a.example", &[ip("10.0.0.5")]).is_err());
    assert!(check_resolved("a.example", &[ip("93.184.216.34"), ip("127.0.0.1")]).is_err());
    assert!(check_resolved("a.example", &[ip("198.18.0.7")]).is_ok());
    assert!(check_resolved("198.18.0.7", &[ip("198.18.0.7")]).is_err());
}

#[test]
fn gateway_is_never_a_chained_proxy() {
    let t = Transit::system().with_chained(Arc::new(|| Some("127.0.0.1:8899".to_string())));
    assert_eq!(t.chained_proxy(8899), None);
    let t = Transit::system().with_chained(Arc::new(|| Some("127.0.0.1:41999".to_string())));
    assert_eq!(t.chained_proxy(8899).as_deref(), Some("127.0.0.1:41999"));
    let t = Transit::system().with_chained(Arc::new(|| Some("  ".to_string())));
    assert_eq!(t.chained_proxy(8899), None);
    let t = Transit::system().with_chained(Arc::new(|| None));
    assert_eq!(t.chained_proxy(8899), None);
}
