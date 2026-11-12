//! Egress for transit (non-AI) traffic: DNS cache with TTL, Happy Eyeballs (RFC 8305) and the
//! source of the chained upstream proxy.
//!
//! Everything that touches the outside world (resolver, dialer, clock, chained-proxy lookup) is
//! injectable, so the tests run on local sockets and virtual time only.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::proxy::server::{is_forbidden_ip, is_tun_fake_ip};

/// How long a successful lookup is served from the cache.
pub const DNS_POSITIVE_TTL: Duration = Duration::from_secs(60);
/// How long a failed lookup is remembered (short: a flapping resolver must recover quickly).
pub const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(5);
/// Maximum number of cached hosts; the least recently used one is evicted.
pub const DNS_CACHE_CAPACITY: usize = 512;
/// A single name lookup is abandoned after this long.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Delay before the next candidate address is tried (RFC 8305 "Connection Attempt Delay").
pub const HAPPY_EYEBALLS_STEP: Duration = Duration::from_millis(250);
/// Upper bound for the whole connection race.
pub const CONNECT_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

pub type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;
pub type ResolveFn = Arc<dyn Fn(String) -> ResolveFuture + Send + Sync>;
pub type DialFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;
pub type DialFn = Arc<dyn Fn(SocketAddr) -> DialFuture + Send + Sync>;
pub type ClockFn = Arc<dyn Fn() -> Instant + Send + Sync>;
pub type ChainedFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Clone)]
enum Outcome {
    Addrs(Arc<[IpAddr]>),
    Failed(io::ErrorKind, String),
}

struct CacheEntry {
    outcome: Outcome,
    expires: Instant,
    used: u64,
}

#[derive(Default)]
struct CacheInner {
    map: HashMap<String, CacheEntry>,
    tick: u64,
}

/// Name -> addresses cache. The lock is held only for the map access, never across a lookup.
pub struct DnsCache {
    inner: Mutex<CacheInner>,
    clock: ClockFn,
    resolver: ResolveFn,
    positive_ttl: Duration,
    negative_ttl: Duration,
    capacity: usize,
}

impl DnsCache {
    pub fn new(resolver: ResolveFn, clock: ClockFn) -> Self {
        Self::with_limits(
            resolver,
            clock,
            DNS_POSITIVE_TTL,
            DNS_NEGATIVE_TTL,
            DNS_CACHE_CAPACITY,
        )
    }

    pub fn with_limits(
        resolver: ResolveFn,
        clock: ClockFn,
        positive_ttl: Duration,
        negative_ttl: Duration,
        capacity: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(CacheInner::default()),
            clock,
            resolver,
            positive_ttl,
            negative_ttl,
            capacity: capacity.max(1),
        }
    }

    /// Number of cached entries (positive and negative).
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lookup(&self, key: &str) -> Option<Outcome> {
        let now = (self.clock)();
        let mut g = self.lock();
        g.tick += 1;
        let tick = g.tick;
        match g.map.get_mut(key) {
            Some(e) if e.expires > now => {
                e.used = tick;
                Some(e.outcome.clone())
            }
            Some(_) => {
                g.map.remove(key);
                None
            }
            None => None,
        }
    }

    fn store(&self, key: String, outcome: Outcome) {
        let now = (self.clock)();
        let ttl = match outcome {
            Outcome::Addrs(_) => self.positive_ttl,
            Outcome::Failed(..) => self.negative_ttl,
        };
        let mut g = self.lock();
        g.tick += 1;
        let tick = g.tick;
        if !g.map.contains_key(&key) && g.map.len() >= self.capacity {
            // Expired entries go first, then the least recently used one.
            g.map.retain(|_, e| e.expires > now);
            if g.map.len() >= self.capacity
                && let Some(oldest) = g
                    .map
                    .iter()
                    .min_by_key(|(_, e)| e.used)
                    .map(|(k, _)| k.clone())
            {
                g.map.remove(&oldest);
            }
        }
        g.map.insert(
            key,
            CacheEntry {
                outcome,
                expires: now + ttl,
                used: tick,
            },
        );
    }

    /// Addresses of `host` (cached). A failed lookup is cached for a few seconds as well.
    pub async fn resolve(&self, host: &str) -> io::Result<Arc<[IpAddr]>> {
        let key = normalize_host(host);
        if let Some(hit) = self.lookup(&key) {
            return outcome_to_result(hit);
        }
        let fresh =
            match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, (self.resolver)(key.clone())).await {
                Ok(Ok(ips)) if !ips.is_empty() => Outcome::Addrs(Arc::from(ips)),
                Ok(Ok(_)) => Outcome::Failed(
                    io::ErrorKind::NotFound,
                    "no valid upstream addresses resolved".into(),
                ),
                Ok(Err(e)) => Outcome::Failed(e.kind(), e.to_string()),
                Err(_) => Outcome::Failed(io::ErrorKind::TimedOut, "DNS lookup timeout".into()),
            };
        self.store(key, fresh.clone());
        outcome_to_result(fresh)
    }
}

fn outcome_to_result(o: Outcome) -> io::Result<Arc<[IpAddr]>> {
    match o {
        Outcome::Addrs(a) => Ok(a),
        Outcome::Failed(kind, msg) => Err(io::Error::new(kind, msg)),
    }
}

/// RFC 8305 section 4: IPv6 first, then the families alternate; duplicates are dropped and the
/// order inside a family is kept.
pub fn order_addresses(ips: &[IpAddr]) -> Vec<IpAddr> {
    let mut v6: Vec<IpAddr> = Vec::new();
    let mut v4: Vec<IpAddr> = Vec::new();
    for ip in ips {
        let list = if ip.is_ipv6() { &mut v6 } else { &mut v4 };
        if !list.contains(ip) {
            list.push(*ip);
        }
    }
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let (mut a, mut b) = (v6.into_iter(), v4.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => {
                out.extend(x);
                out.extend(y);
            }
        }
    }
    out
}

/// Happy Eyeballs race: the first candidate starts at once, each next one after `step` or as soon
/// as the previous attempt failed. The first success wins; the others are cancelled (dropping the
/// `JoinSet` aborts them). The whole race is bounded by `total`.
pub async fn race_connect<T, F, Fut>(
    addrs: Vec<SocketAddr>,
    step: Duration,
    total: Duration,
    dial: F,
) -> io::Result<T>
where
    T: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>> + Send + 'static,
{
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No valid upstream addresses resolved.",
        ));
    }
    let race = async {
        let mut set: JoinSet<io::Result<T>> = JoinSet::new();
        let mut queue = addrs.into_iter();
        let mut last_err: Option<io::Error> = None;
        if let Some(first) = queue.next() {
            set.spawn(dial(first));
        }
        loop {
            let more = queue.len() > 0;
            tokio::select! {
                joined = set.join_next(), if !set.is_empty() => {
                    match joined {
                        Some(Ok(Ok(stream))) => return Ok(stream),
                        Some(Ok(Err(e))) => last_err = Some(e),
                        Some(Err(join_err)) => {
                            last_err = Some(io::Error::other(format!("connect attempt failed: {join_err}")));
                        }
                        None => {}
                    }
                    // The failed attempt is replaced at once, not after the step delay.
                    if let Some(next) = queue.next() {
                        set.spawn(dial(next));
                    } else if set.is_empty() {
                        return Err(last_err.take().unwrap_or_else(|| {
                            io::Error::new(io::ErrorKind::ConnectionRefused, "all connection attempts failed")
                        }));
                    }
                }
                _ = tokio::time::sleep(step), if more => {
                    if let Some(next) = queue.next() {
                        set.spawn(dial(next));
                    }
                }
            }
        }
    };
    match tokio::time::timeout(total, race).await {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "upstream connect timeout",
        )),
    }
}

/// Resolved addresses of a host name that must never be dialed (SSRF protection). A TUN FakeIP
/// answer (198.18.0.0/15) is allowed for names, not for raw IPs.
pub fn check_resolved(host: &str, ips: &[IpAddr]) -> io::Result<()> {
    let host_is_raw_ip = host.parse::<IpAddr>().is_ok();
    for ip in ips {
        if is_forbidden_ip(ip) {
            if !host_is_raw_ip && is_tun_fake_ip(ip) {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SSRF Protection: resolved IP belongs to a restricted local or private network.",
            ));
        }
    }
    Ok(())
}

fn system_resolver() -> ResolveFn {
    Arc::new(|host: String| {
        Box::pin(async move {
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;
            Ok(found.map(|a| a.ip()).collect::<Vec<_>>())
        })
    })
}

fn system_dial() -> DialFn {
    Arc::new(|addr: SocketAddr| {
        Box::pin(async move {
            let stream = TcpStream::connect(addr).await?;
            let _ = stream.set_nodelay(true);
            Ok(stream)
        })
    })
}

/// Outbound side of the gateway for non-AI traffic.
pub struct Transit {
    dns: DnsCache,
    dial: DialFn,
    chained: ChainedFn,
    step: Duration,
    total: Duration,
}

impl Default for Transit {
    fn default() -> Self {
        Self::system()
    }
}

impl Transit {
    /// Production wiring: system resolver, real sockets, real clock, chained proxy from the
    /// system proxy state.
    pub fn system() -> Self {
        Self::with_backends(system_resolver(), system_dial(), Arc::new(Instant::now))
    }

    /// Custom resolver / dialer / clock (tests). The chained proxy is taken from the system state
    /// until [`Transit::with_chained`] replaces it.
    pub fn with_backends(resolver: ResolveFn, dial: DialFn, clock: ClockFn) -> Self {
        Self {
            dns: DnsCache::new(resolver, clock),
            dial,
            chained: Arc::new(crate::sysproxy::get_chained_proxy),
            step: HAPPY_EYEBALLS_STEP,
            total: CONNECT_TOTAL_TIMEOUT,
        }
    }

    pub fn with_chained(mut self, chained: ChainedFn) -> Self {
        self.chained = chained;
        self
    }

    pub fn dns(&self) -> &DnsCache {
        &self.dns
    }

    /// The external upstream proxy for transit traffic (`host:port`), never the gateway itself.
    pub fn chained_proxy(&self, gateway_port: u16) -> Option<String> {
        let cp = (self.chained)()?.trim().to_string();
        if cp.is_empty() || crate::sysproxy::is_gateway_host_port(&cp, Some(gateway_port)) {
            return None;
        }
        Some(cp)
    }

    /// Direct connection: cached DNS, SSRF check of every answer, Happy Eyeballs across families.
    pub async fn connect_direct(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let ips: Arc<[IpAddr]> = match host.parse::<IpAddr>() {
            Ok(ip) => Arc::from(vec![ip]),
            Err(_) => self.dns.resolve(host).await?,
        };
        check_resolved(host, &ips)?;
        let addrs: Vec<SocketAddr> = order_addresses(&ips)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        let dial = Arc::clone(&self.dial);
        race_connect(addrs, self.step, self.total, move |a| dial(a)).await
    }
}

#[cfg(test)]
mod tests {
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
}
