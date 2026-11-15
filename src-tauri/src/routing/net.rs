//! Address policy for entry nodes: resolve once, check every address, connect to the checked one.
//!
//! * Keys that come from outside (`zastava://…`) may only point to public addresses.
//! * Keys the user typed in URL form (`socks5://`, `http://`, `https://`) may also point to
//!   loopback / private addresses: that is the user's own local proxy (Xray, sing-box, …).
//! * Nothing may point back to the gateway itself (loop), and link-local / metadata / multicast /
//!   reserved ranges stay forbidden for everyone.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use super::Entry;
use crate::auditor::dnsbl::parse_doh_json_a_response;
use crate::auditor::network::NEUTRAL_USER_AGENT;
use crate::auditor::seams::{LookupOutcome, is_usable_nameserver};
use crate::proxy::server::{
    DEFAULT_PROXY_PORT, FALLBACK_PROXY_PORT, embedded_ipv4, is_forbidden_ip, is_tun_fake_ip,
};

/// DNS lookup limit for entry hosts.
pub const ENTRY_DNS_TIMEOUT: Duration = Duration::from_secs(4);
const SYSTEM_DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1500);
const SYSTEM_DNS_RETRY_DELAY: Duration = Duration::from_millis(150);
const HICKORY_DNS_TIMEOUT: Duration = Duration::from_millis(1500);
const DOH_DNS_TIMEOUT: Duration = Duration::from_millis(2000);
const ENTRY_DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const ENTRY_DNS_STALE_TTL: Duration = Duration::from_secs(900);
const CLOUDFLARE_DOH_JSON_URL: &str = "https://1.1.1.1/dns-query";
const GOOGLE_DOH_JSON_URL: &str = "https://dns.google/resolve";

fn unwrap_embedded(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => embedded_ipv4(v6).map(IpAddr::V4).unwrap_or(*ip),
        IpAddr::V4(_) => *ip,
    }
}

/// Loopback, private (RFC 1918 / ULA) and shared (RFC 6598, e.g. a tailnet) addresses: the
/// "user's own network" that manual URL keys may point to.
pub fn is_user_local_ip(ip: &IpAddr) -> bool {
    match unwrap_embedded(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback() || v4.is_private() || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn is_loopback_or_unspecified(ip: &IpAddr) -> bool {
    match unwrap_embedded(ip) {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// True when `ip:port` is (or may be) the gateway itself. `gateway_port == 0` means "unknown":
/// then both default gateway ports are assumed.
pub fn is_gateway_loop(ip: &IpAddr, port: u16, gateway_port: u16) -> bool {
    if !is_loopback_or_unspecified(ip) {
        return false;
    }
    if gateway_port != 0 {
        port == gateway_port
    } else {
        port == DEFAULT_PROXY_PORT || port == FALLBACK_PROXY_PORT
    }
}

/// Checks one resolved entry address. `via_hostname`: the address came from a DNS name (a TUN
/// FakeIP answer is then acceptable, as for direct connections).
pub fn check_entry_ip(
    ip: &IpAddr,
    port: u16,
    via_hostname: bool,
    allow_local: bool,
    gateway_port: u16,
) -> Result<(), &'static str> {
    if is_gateway_loop(ip, port, gateway_port) {
        return Err("entry node points to the Zastava gateway itself");
    }
    if !is_forbidden_ip(ip) {
        return Ok(());
    }
    if via_hostname && is_tun_fake_ip(ip) {
        return Ok(());
    }
    if allow_local && is_user_local_ip(ip) {
        return Ok(());
    }
    Err("entry node address belongs to a restricted local or reserved network")
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EntryCacheKey {
    host: String,
    port: u16,
    allow_local: bool,
    gateway_port: u16,
}

#[derive(Debug, Clone)]
struct CachedEntryAddrs {
    addrs: Vec<SocketAddr>,
    resolved_at: tokio::time::Instant,
}

#[derive(Default)]
struct EntryDnsCache {
    entries: RwLock<HashMap<EntryCacheKey, CachedEntryAddrs>>,
}

impl EntryDnsCache {
    fn get_within(&self, key: &EntryCacheKey, max_age: Duration) -> Option<Vec<SocketAddr>> {
        let now = tokio::time::Instant::now();
        let guard = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let cached = guard.get(key)?;
        if now.saturating_duration_since(cached.resolved_at) < max_age {
            Some(cached.addrs.clone())
        } else {
            None
        }
    }

    fn insert(&self, key: EntryCacheKey, addrs: Vec<SocketAddr>) {
        let mut guard = self.entries.write().unwrap_or_else(|e| e.into_inner());
        guard.insert(
            key,
            CachedEntryAddrs {
                addrs,
                resolved_at: tokio::time::Instant::now(),
            },
        );
    }
}

fn global_entry_dns_cache() -> &'static EntryDnsCache {
    static CACHE: OnceLock<EntryDnsCache> = OnceLock::new();
    CACHE.get_or_init(EntryDnsCache::default)
}

fn doh_http_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .no_proxy()
                .timeout(DOH_DNS_TIMEOUT)
                .user_agent(NEUTRAL_USER_AGENT)
                .build()
                .ok()
        })
        .as_ref()
}

trait EntryDnsBackend: Send + Sync {
    fn system_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

    fn fallback_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;
}

struct ProdEntryDnsBackend;

impl EntryDnsBackend for ProdEntryDnsBackend {
    fn system_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let resolved = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "entry DNS lookup timed out"))??;
            Ok(resolved.collect())
        })
    }

    fn fallback_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let mut last_err: Option<io::Error> = None;

            // 1. Hickory using OS system nameservers (bypasses Windows Dnscache negative cache).
            match hickory_resolve_addrs(host, port, true).await {
                Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
                Ok(_) => {}
                Err(e) => last_err = Some(e),
            }

            // 2. Hickory using public resolvers (1.1.1.1 / 8.8.8.8) when TUN/split-DNS breaks OS DNS.
            match hickory_resolve_addrs(host, port, false).await {
                Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
                Ok(_) => {}
                Err(e) => last_err = Some(e),
            }

            // 3. DoH fallback (Cloudflare 1.1.1.1 IP literal first, then dns.google).
            match doh_resolve_addrs(host, port).await {
                Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
                Ok(_) => {}
                Err(e) => last_err = Some(e),
            }

            Err(last_err.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "entry DNS fallback found no addresses")
            }))
        })
    }
}

fn build_hickory_entry_resolver(use_system_conf: bool) -> Option<hickory_resolver::TokioResolver> {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    let cfg = if use_system_conf {
        let (mut sys_cfg, _) = hickory_resolver::system_conf::read_system_conf().ok()?;
        sys_cfg
            .name_servers
            .retain(|ns| is_usable_nameserver(&ns.ip));
        if sys_cfg.name_servers.is_empty() {
            return None;
        }
        sys_cfg
    } else {
        let servers = vec![
            NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ];
        ResolverConfig::from_parts(None, vec![], servers)
    };

    let mut builder = TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        opts.cache_size = 0;
        opts.attempts = 2;
        opts.timeout = HICKORY_DNS_TIMEOUT;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.num_concurrent_reqs = 2;
    }
    builder.build().ok()
}

async fn hickory_resolve_addrs(
    host: &str,
    port: u16,
    use_system_conf: bool,
) -> io::Result<Vec<SocketAddr>> {
    use hickory_resolver::net::NetError;
    use hickory_resolver::proto::rr::{RData, RecordType};

    let Some(resolver) = build_hickory_entry_resolver(use_system_conf) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no usable DNS nameservers configured",
        ));
    };

    let fqdn = format!("{}.", host.trim_end_matches('.'));
    let (res_a, res_aaaa) = tokio::join!(
        tokio::time::timeout(HICKORY_DNS_TIMEOUT, resolver.lookup(&fqdn, RecordType::A)),
        tokio::time::timeout(HICKORY_DNS_TIMEOUT, resolver.lookup(&fqdn, RecordType::AAAA)),
    );

    let mut addrs = Vec::new();
    let mut saw_timeout = false;
    let mut last_err: Option<String> = None;

    for (res, is_v6) in [(res_a, false), (res_aaaa, true)] {
        match res {
            Ok(Ok(lookup)) => {
                for r in lookup.answers() {
                    match (&r.data, is_v6) {
                        (RData::A(a), false) => addrs.push(SocketAddr::new(IpAddr::V4(a.0), port)),
                        (RData::AAAA(aaaa), true) => {
                            addrs.push(SocketAddr::new(IpAddr::V6(aaaa.0), port))
                        }
                        _ => {}
                    }
                }
            }
            Ok(Err(NetError::Timeout)) | Err(_) => saw_timeout = true,
            Ok(Err(e)) => last_err = Some(e.to_string()),
        }
    }

    if !addrs.is_empty() {
        return Ok(addrs);
    }
    if saw_timeout {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "hickory DNS fallback timed out",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        last_err.unwrap_or_else(|| "hickory DNS fallback returned no records".to_string()),
    ))
}

async fn doh_resolve_addrs_from_url(
    client: &reqwest::Client,
    doh_url: &str,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let resp = client
        .get(doh_url)
        .query(&[("name", host), ("type", "A")])
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .timeout(DOH_DNS_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            let kind = if e.is_timeout() {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::Other
            };
            io::Error::new(kind, format!("DoH request failed: {e}"))
        })?;
    if !resp.status().is_success() {
        return Err(io::Error::other(format!(
            "DoH endpoint returned HTTP {}",
            resp.status()
        )));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| io::Error::other(format!("DoH response read failed: {e}")))?;
    match parse_doh_json_a_response(&body) {
        LookupOutcome::Addrs(ips) => Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()),
        LookupOutcome::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DoH returned no addresses",
        )),
        LookupOutcome::Timeout => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "DoH lookup timed out",
        )),
        LookupOutcome::Failed => Err(io::Error::other("DoH response parse failed")),
    }
}

async fn doh_resolve_addrs(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let client = doh_http_client()
        .ok_or_else(|| io::Error::other("DoH HTTP client could not be initialized"))?;
    let mut last_err: Option<io::Error> = None;
    for url in [CLOUDFLARE_DOH_JSON_URL, GOOGLE_DOH_JSON_URL] {
        match doh_resolve_addrs_from_url(client, url, host, port).await {
            Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
            Ok(_) => {}
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DoH found no records")))
}

fn validate_entry_addrs(
    addrs: &[SocketAddr],
    via_hostname: bool,
    allow_local: bool,
    gateway_port: u16,
) -> io::Result<()> {
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "entry host did not resolve to any address",
        ));
    }
    for a in addrs {
        check_entry_ip(&a.ip(), a.port(), via_hostname, allow_local, gateway_port)
            .map_err(|m| io::Error::new(io::ErrorKind::PermissionDenied, m))?;
    }
    Ok(())
}

async fn resolve_entry_checked_with(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
    backend: &dyn EntryDnsBackend,
    cache: &EntryDnsCache,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = entry.host.parse::<IpAddr>() {
        let addrs = vec![SocketAddr::new(ip, entry.port)];
        validate_entry_addrs(&addrs, false, allow_local, gateway_port)?;
        return Ok(addrs);
    }

    let key = EntryCacheKey {
        host: entry.host.to_ascii_lowercase(),
        port: entry.port,
        allow_local,
        gateway_port,
    };

    if let Some(cached) = cache.get_within(&key, ENTRY_DNS_CACHE_TTL)
        && validate_entry_addrs(&cached, true, allow_local, gateway_port).is_ok()
    {
        return Ok(cached);
    }

    let mut last_err: Option<io::Error> = None;
    for attempt in 0..2 {
        if attempt > 0 {
            tokio::time::sleep(SYSTEM_DNS_RETRY_DELAY).await;
        }
        match backend
            .system_lookup(&entry.host, entry.port, SYSTEM_DNS_ATTEMPT_TIMEOUT)
            .await
        {
            Ok(addrs) if !addrs.is_empty() => {
                validate_entry_addrs(&addrs, true, allow_local, gateway_port)?;
                cache.insert(key, addrs.clone());
                return Ok(addrs);
            }
            Ok(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::NotFound,
                    "entry host did not resolve to any address",
                ));
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    match backend.fallback_lookup(&entry.host, entry.port).await {
        Ok(addrs) if !addrs.is_empty() => {
            validate_entry_addrs(&addrs, true, allow_local, gateway_port)?;
            cache.insert(key, addrs.clone());
            crate::diagnostics::record(
                "routing:dns",
                &format!(
                    "entry {} resolved via DNS fallback after system lookup failed",
                    entry.host
                ),
            );
            return Ok(addrs);
        }
        Ok(_) => {
            if last_err.is_none() {
                last_err = Some(io::Error::new(
                    io::ErrorKind::NotFound,
                    "entry host did not resolve to any address",
                ));
            }
        }
        Err(e) => {
            if last_err.is_none() {
                last_err = Some(e);
            }
        }
    }

    if let Some(stale) = cache.get_within(&key, ENTRY_DNS_STALE_TTL)
        && validate_entry_addrs(&stale, true, allow_local, gateway_port).is_ok()
    {
        crate::diagnostics::record(
            "routing:dns",
            &format!(
                "entry {} using stale cached DNS after lookup failure",
                entry.host
            ),
        );
        return Ok(stale);
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "entry host did not resolve to any address",
        )
    }))
}

/// Resolves the entry host (once) and verifies EVERY returned address. The caller must connect to
/// one of the returned `SocketAddr`s and never resolve the name again.
///
/// Uses a short retry on transient `lookup_host` failures, falls back to `hickory-resolver` and
/// DoH when system DNS fails (e.g. Windows `os error 11001` under TUN VPNs), caches verified
/// results with TTL + stale-on-error fallback, and always enforces [`check_entry_ip`].
pub async fn resolve_entry_checked(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
) -> io::Result<Vec<SocketAddr>> {
    resolve_entry_checked_with(
        entry,
        allow_local,
        gateway_port,
        &ProdEntryDnsBackend,
        global_entry_dns_cache(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_forbidden_ip_gaps_closed() {
        for s in [
            "0.0.0.0",
            "0.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
            "127.0.0.1",
            "10.1.2.3",
            "::127.0.0.1",
            "::10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b::c0a8:1",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "::",
            "::1",
            "100::1",
        ] {
            assert!(is_forbidden_ip(&ip(s)), "{s} must be forbidden");
        }
        for s in [
            "8.8.8.8",
            "185.10.10.2",
            "2606:4700:4700::1111",
            "64:ff9b::808:808",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_forbidden_ip(&ip(s)), "{s} must be allowed");
        }
    }

    #[test]
    fn test_local_policy_for_manual_keys() {
        // zastava:// keys: public only.
        assert!(check_entry_ip(&ip("127.0.0.1"), 10808, false, false, 8899).is_err());
        assert!(check_entry_ip(&ip("10.0.0.1"), 8080, false, false, 8899).is_err());
        assert!(check_entry_ip(&ip("185.1.1.1"), 1080, false, false, 8899).is_ok());
        // Manual URL keys: the user's own proxy is fine ...
        assert!(check_entry_ip(&ip("127.0.0.1"), 10808, false, true, 8899).is_ok());
        assert!(check_entry_ip(&ip("10.0.0.1"), 8080, false, true, 8899).is_ok());
        assert!(check_entry_ip(&ip("::1"), 10808, false, true, 8899).is_ok());
        assert!(check_entry_ip(&ip("::ffff:127.0.0.1"), 10808, false, true, 8899).is_ok());
        // ... but never the gateway itself, metadata or reserved ranges.
        assert!(check_entry_ip(&ip("127.0.0.1"), 8899, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("::1"), 8899, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("0.0.0.0"), 8899, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("::ffff:127.0.0.1"), 8899, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("169.254.169.254"), 80, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("0.0.0.0"), 1080, false, true, 8899).is_err());
        // Unknown gateway port: both defaults are protected.
        assert!(check_entry_ip(&ip("127.0.0.1"), 8900, false, true, 0).is_err());
        assert!(check_entry_ip(&ip("127.0.0.1"), 8901, false, true, 0).is_ok());
        // TUN FakeIP is acceptable only for names.
        assert!(check_entry_ip(&ip("198.18.0.5"), 443, true, false, 8899).is_ok());
        assert!(check_entry_ip(&ip("198.18.0.5"), 443, false, false, 8899).is_err());
    }

    fn entry(host: &str, port: u16) -> Entry {
        Entry {
            proto: super::super::EntryProto::Socks5,
            host: host.into(),
            port,
            username: None,
            password: None,
            sni: None,
        }
    }

    struct FakeEntryDnsBackend {
        system_results: Mutex<VecDeque<io::Result<Vec<SocketAddr>>>>,
        fallback_results: Mutex<VecDeque<io::Result<Vec<SocketAddr>>>>,
        system_calls: AtomicUsize,
        fallback_calls: AtomicUsize,
    }

    impl FakeEntryDnsBackend {
        fn new(
            system_results: Vec<io::Result<Vec<SocketAddr>>>,
            fallback_results: Vec<io::Result<Vec<SocketAddr>>>,
        ) -> Self {
            Self {
                system_results: Mutex::new(VecDeque::from(system_results)),
                fallback_results: Mutex::new(VecDeque::from(fallback_results)),
                system_calls: AtomicUsize::new(0),
                fallback_calls: AtomicUsize::new(0),
            }
        }
    }

    impl EntryDnsBackend for FakeEntryDnsBackend {
        fn system_lookup<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
            self.system_calls.fetch_add(1, Ordering::SeqCst);
            let next = self
                .system_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::from_raw_os_error(11001)));
            Box::pin(async move { next })
        }

        fn fallback_lookup<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
            self.fallback_calls.fetch_add(1, Ordering::SeqCst);
            let next = self
                .fallback_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::NotFound, "no fallback")));
            Box::pin(async move { next })
        }
    }

    #[tokio::test]
    async fn test_resolve_checks_every_address() {
        // Names that resolve to loopback are rejected for external keys even though the text
        // looks like a public domain ...
        let e = resolve_entry_checked(&entry("localhost", 1080), false, 8899).await;
        assert_eq!(e.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        // ... and accepted for the user's own keys.
        let ok = resolve_entry_checked(&entry("localhost", 1080), true, 8899)
            .await
            .unwrap();
        assert!(!ok.is_empty() && ok.iter().all(|a| a.ip().is_loopback()));
        // Odd numeric spellings go through the system resolver as IPv4 literals and are caught.
        if let Ok(res) = resolve_entry_checked(&entry("127.1", 1080), false, 8899).await {
            panic!("127.1 must not pass: {res:?}");
        }
        let loopback_gw = resolve_entry_checked(&entry("127.0.0.1", 8899), true, 8899).await;
        assert_eq!(
            loopback_gw.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn test_resolve_retries_transient_system_dns_failure() {
        let addr: SocketAddr = "185.10.20.30:443".parse().unwrap();
        let backend = FakeEntryDnsBackend::new(
            vec![
                Err(io::Error::from_raw_os_error(11001)),
                Ok(vec![addr]),
            ],
            vec![],
        );
        let cache = EntryDnsCache::default();
        let res = resolve_entry_checked_with(
            &entry("node.example.com", 443),
            false,
            8899,
            &backend,
            &cache,
        )
        .await
        .unwrap();
        assert_eq!(res, vec![addr]);
        assert_eq!(backend.system_calls.load(Ordering::SeqCst), 2);
        assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_resolve_falls_back_on_persistent_11001_and_enforces_check_entry_ip() {
        let public_addr: SocketAddr = "185.10.20.31:443".parse().unwrap();
        let backend = FakeEntryDnsBackend::new(
            vec![
                Err(io::Error::from_raw_os_error(11001)),
                Err(io::Error::from_raw_os_error(11001)),
            ],
            vec![Ok(vec![public_addr])],
        );
        let cache = EntryDnsCache::default();
        let res = resolve_entry_checked_with(
            &entry("node.example.com", 443),
            false,
            8899,
            &backend,
            &cache,
        )
        .await
        .unwrap();
        assert_eq!(res, vec![public_addr]);
        assert_eq!(backend.system_calls.load(Ordering::SeqCst), 2);
        assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 1);

        // Policy rejection on fallback result must NEVER pass or populate cache.
        let evil_cache = EntryDnsCache::default();
        let evil_backend = FakeEntryDnsBackend::new(
            vec![
                Err(io::Error::from_raw_os_error(11001)),
                Err(io::Error::from_raw_os_error(11001)),
            ],
            vec![Ok(vec!["169.254.169.254:443".parse().unwrap()])],
        );
        let err = resolve_entry_checked_with(
            &entry("metadata.example.com", 443),
            false,
            8899,
            &evil_backend,
            &evil_cache,
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            evil_cache
                .entries
                .read()
                .unwrap()
                .is_empty(),
            "rejected fallback IP must never be cached"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_resolve_uses_fresh_cache_and_stale_on_error_fallback() {
        let addr: SocketAddr = "185.10.20.32:443".parse().unwrap();
        let backend = FakeEntryDnsBackend::new(
            vec![Ok(vec![addr])],
            vec![],
        );
        let cache = EntryDnsCache::default();
        let node = entry("cached.example.com", 443);

        // 1. Initial lookup populates cache.
        let first = resolve_entry_checked_with(&node, false, 8899, &backend, &cache)
            .await
            .unwrap();
        assert_eq!(first, vec![addr]);
        assert_eq!(backend.system_calls.load(Ordering::SeqCst), 1);

        // 2. Within TTL -> served from cache without calling resolvers.
        tokio::time::advance(Duration::from_secs(30)).await;
        let second = resolve_entry_checked_with(&node, false, 8899, &backend, &cache)
            .await
            .unwrap();
        assert_eq!(second, vec![addr]);
        assert_eq!(backend.system_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 0);

        // 3. Past fresh TTL (60s) but within stale TTL (900s), and all resolvers fail -> stale fallback.
        tokio::time::advance(Duration::from_secs(40)).await;
        let stale = resolve_entry_checked_with(&node, false, 8899, &backend, &cache)
            .await
            .unwrap();
        assert_eq!(stale, vec![addr]);
        assert_eq!(backend.system_calls.load(Ordering::SeqCst), 3);
        assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 1);

        // 4. Past stale TTL (900s) and all resolvers fail -> returns error.
        tokio::time::advance(Duration::from_secs(900)).await;
        let expired = resolve_entry_checked_with(&node, false, 8899, &backend, &cache).await;
        assert!(expired.is_err());
    }

    #[tokio::test]
    async fn test_resolve_policy_rejection_on_system_dns_does_not_use_fallback_or_stale() {
        let good_addr: SocketAddr = "185.10.20.33:443".parse().unwrap();
        let evil_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let cache = EntryDnsCache::default();
        let key = EntryCacheKey {
            host: "rebind.example.com".to_string(),
            port: 443,
            allow_local: false,
            gateway_port: 8899,
        };
        cache.insert(key, vec![good_addr]);
        // Force stale by backdating resolved_at past fresh TTL.
        cache.entries.write().unwrap().values_mut().for_each(|v| {
            v.resolved_at -= Duration::from_secs(120);
        });

        let backend = FakeEntryDnsBackend::new(
            vec![Ok(vec![evil_addr])],
            vec![Ok(vec![good_addr])],
        );
        let err = resolve_entry_checked_with(
            &entry("rebind.example.com", 443),
            false,
            8899,
            &backend,
            &cache,
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 0);
    }
}
