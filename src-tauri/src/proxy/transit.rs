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
#[path = "transit_tests.rs"]
mod tests;
