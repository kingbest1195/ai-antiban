use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a successful lookup is served from the cache.
pub const DNS_POSITIVE_TTL: Duration = Duration::from_secs(60);
/// How long a failed lookup is remembered (short: a flapping resolver must recover quickly).
pub const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(5);
/// Maximum number of cached hosts; the least recently used one is evicted.
pub const DNS_CACHE_CAPACITY: usize = 512;
/// A single name lookup is abandoned after this long.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

pub type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;
pub type ResolveFn = Arc<dyn Fn(String) -> ResolveFuture + Send + Sync>;
pub type ClockFn = Arc<dyn Fn() -> Instant + Send + Sync>;

static GLOBAL_DNS_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Invalidates all [`DnsCache`] instances (e.g. on VPN, network, or system proxy switch).
pub fn invalidate_all_dns_caches() {
    GLOBAL_DNS_EPOCH.fetch_add(1, Ordering::Release);
}

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
    epoch: u64,
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
            inner: Mutex::new(CacheInner {
                map: HashMap::new(),
                tick: 0,
                epoch: GLOBAL_DNS_EPOCH.load(Ordering::Acquire),
            }),
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
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let cur = GLOBAL_DNS_EPOCH.load(Ordering::Acquire);
        if g.epoch != cur {
            g.map.clear();
            g.epoch = cur;
        }
        g
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
