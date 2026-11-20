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
        vec![Err(io::Error::from_raw_os_error(11001)), Ok(vec![addr])],
        vec![],
    );
    let cache = EntryDnsCache::default();
    let res = resolve_entry_checked_with(
        &entry("node.example.com", 443),
        false,
        8899,
        &backend,
        &cache,
        false,
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
        false,
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
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        evil_cache.entries.read().unwrap().is_empty(),
        "rejected fallback IP must never be cached"
    );
}

#[tokio::test(start_paused = true)]
async fn test_resolve_uses_fresh_cache_and_stale_on_error_fallback() {
    let addr: SocketAddr = "185.10.20.32:443".parse().unwrap();
    let backend = FakeEntryDnsBackend::new(vec![Ok(vec![addr])], vec![]);
    let cache = EntryDnsCache::default();
    let node = entry("cached.example.com", 443);

    // 1. Initial lookup populates cache.
    let first = resolve_entry_checked_with(&node, false, 8899, &backend, &cache, false)
        .await
        .unwrap();
    assert_eq!(first, vec![addr]);
    assert_eq!(backend.system_calls.load(Ordering::SeqCst), 1);

    // 2. Within TTL -> served from cache without calling resolvers.
    tokio::time::advance(Duration::from_secs(30)).await;
    let second = resolve_entry_checked_with(&node, false, 8899, &backend, &cache, false)
        .await
        .unwrap();
    assert_eq!(second, vec![addr]);
    assert_eq!(backend.system_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 0);

    // 3. Past fresh TTL (60s) but within stale TTL (900s), and all resolvers fail -> stale fallback.
    tokio::time::advance(Duration::from_secs(40)).await;
    let stale = resolve_entry_checked_with(&node, false, 8899, &backend, &cache, false)
        .await
        .unwrap();
    assert_eq!(stale, vec![addr]);
    assert_eq!(backend.system_calls.load(Ordering::SeqCst), 3);
    assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 1);

    // 4. Past normal stale TTL (900s) but within emergency stale TTL (7200s) -> emergency fallback + stale flag.
    tokio::time::advance(Duration::from_secs(900)).await;
    let emergency = resolve_entry_checked_with(&node, false, 8899, &backend, &cache, false)
        .await
        .unwrap();
    assert_eq!(emergency, vec![addr]);
    assert!(
        cache
            .entries
            .read()
            .unwrap()
            .values()
            .all(|v| v.stale && v.last_refresh_attempt.is_some())
    );

    // 5. Past emergency stale TTL (7200s) and all resolvers fail -> returns error & records proxy:route dns.
    tokio::time::advance(Duration::from_secs(6400)).await;
    let expired = resolve_entry_checked_with(&node, false, 8899, &backend, &cache, false).await;
    assert!(expired.is_err());
    assert!(
        crate::diagnostics::dump()
            .iter()
            .any(|l| l.contains("[proxy:route]") && l.contains("phase=dns")),
        "expected [proxy:route] phase=dns in diagnostics"
    );
}

#[tokio::test]
async fn test_resolve_timeout_on_system_dns_skips_second_system_attempt() {
    let public_addr: SocketAddr = "185.10.20.34:443".parse().unwrap();
    let backend = FakeEntryDnsBackend::new(
        vec![Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "hung system dns",
        ))],
        vec![Ok(vec![public_addr])],
    );
    let cache = EntryDnsCache::default();
    let res = resolve_entry_checked_with(
        &entry("timeout-skip.example.com", 443),
        false,
        8899,
        &backend,
        &cache,
        false,
    )
    .await
    .unwrap();
    assert_eq!(res, vec![public_addr]);
    assert_eq!(backend.system_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_resolve_policy_rejection_on_system_and_fallback_does_not_use_stale() {
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
        vec![Ok(vec!["169.254.169.254:443".parse().unwrap()])],
    );
    let err = resolve_entry_checked_with(
        &entry("rebind.example.com", 443),
        false,
        8899,
        &backend,
        &cache,
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("169.254.169.254"));
    assert!(err.to_string().contains("source=fallback"));
    assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_resolve_system_forbidden_ip_falls_back_to_public_dns_and_logs() {
    let public_addr: SocketAddr = "185.10.20.40:443".parse().unwrap();
    for evil in ["127.0.0.1:443", "[fd00::1]:443"] {
        let evil_addr: SocketAddr = evil.parse().unwrap();
        let backend =
            FakeEntryDnsBackend::new(vec![Ok(vec![evil_addr])], vec![Ok(vec![public_addr])]);
        let cache = EntryDnsCache::default();
        let res = resolve_entry_checked_with(
            &entry("override.example.com", 443),
            false,
            8899,
            &backend,
            &cache,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res, vec![public_addr]);
        assert_eq!(backend.fallback_calls.load(Ordering::SeqCst), 1);
    }
    let logs = crate::diagnostics::dump();
    assert!(
        logs.iter().any(|l| l.contains("[routing:dns]")
            && l.contains("127.0.0.1")
            && l.contains("source=system")),
        "expected rejected 127.0.0.1 source=system in diagnostics"
    );
    assert!(
        logs.iter().any(|l| l.contains("[routing:dns]")
            && l.contains("fd00::1")
            && l.contains("source=system")),
        "expected rejected fd00::1 source=system in diagnostics"
    );
}

#[tokio::test]
async fn test_resolve_fake_ipv6_and_ipv4_override_then_last_resort() {
    let public_v6: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
    let fake_v6: SocketAddr = "[fc00::1]:443".parse().unwrap();
    let fake_v4: SocketAddr = "198.18.0.1:443".parse().unwrap();

    // 1. System returns fc00::1 -> fallback public DNS overrides it.
    let backend_override =
        FakeEntryDnsBackend::new(vec![Ok(vec![fake_v6])], vec![Ok(vec![public_v6])]);
    let cache = EntryDnsCache::default();
    let res = resolve_entry_checked_with(
        &entry("tun-v6.example.com", 443),
        false,
        8899,
        &backend_override,
        &cache,
        false,
    )
    .await
    .unwrap();
    assert_eq!(res, vec![public_v6]);
    assert_eq!(backend_override.fallback_calls.load(Ordering::SeqCst), 1);

    // 2. Public DNS fails -> fc00::1 accepted as last resort under active TUN.
    let backend_last_resort = FakeEntryDnsBackend::new(
        vec![Ok(vec![fake_v6])],
        vec![Err(io::Error::new(io::ErrorKind::TimedOut, "doh blocked"))],
    );
    let res2 = resolve_entry_checked_with(
        &entry("tun-v6-offline.example.com", 443),
        false,
        8899,
        &backend_last_resort,
        &EntryDnsCache::default(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(res2, vec![fake_v6]);

    // 3. Same for IPv4 FakeIP 198.18.0.1 -> last resort when fallback fails.
    let backend_v4 = FakeEntryDnsBackend::new(
        vec![Ok(vec![fake_v4])],
        vec![Err(io::Error::new(io::ErrorKind::TimedOut, "doh blocked"))],
    );
    let res3 = resolve_entry_checked_with(
        &entry("tun-v4-offline.example.com", 443),
        false,
        8899,
        &backend_v4,
        &EntryDnsCache::default(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(res3, vec![fake_v4]);

    // 4. Local LAN IP (fd12:3456::1) is NEVER accepted even if public DNS fails.
    let lan_v6: SocketAddr = "[fd12:3456::1]:443".parse().unwrap();
    let backend_lan = FakeEntryDnsBackend::new(
        vec![Ok(vec![lan_v6])],
        vec![Err(io::Error::new(io::ErrorKind::TimedOut, "doh blocked"))],
    );
    let err = resolve_entry_checked_with(
        &entry("lan-v6.example.com", 443),
        false,
        8899,
        &backend_lan,
        &EntryDnsCache::default(),
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("fd12:3456::1"));
}

#[test]
fn test_is_gateway_loop_includes_registered_alias_ports() {
    struct Guard(u16);
    impl Drop for Guard {
        fn drop(&mut self) {
            crate::core::net_safety::unregister_alias_port(self.0);
        }
    }
    let port = 51423;
    assert!(!is_gateway_loop(&ip("127.0.0.1"), port, 8899));
    crate::core::net_safety::register_alias_port(port);
    let _guard = Guard(port);
    assert!(is_gateway_loop(&ip("127.0.0.1"), port, 8899));
    assert!(is_gateway_loop(&ip("::1"), port, 0));
    assert!(!is_gateway_loop(&ip("185.10.20.30"), port, 8899));
}

#[test]
fn test_parse_doh_json_addrs_supports_a_and_aaaa() {
    use crate::auditor::seams::LookupOutcome;
    let a_json = r#"{"Status":0,"Answer":[{"type":1,"data":"185.10.20.30"}]}"#;
    assert_eq!(
        dns::parse_doh_json_addrs(a_json),
        LookupOutcome::Addrs(vec![ip("185.10.20.30")])
    );

    let aaaa_json = r#"{"Status":0,"Answer":[{"type":28,"data":"2606:4700:4700::1111"}]}"#;
    assert_eq!(
        dns::parse_doh_json_addrs(aaaa_json),
        LookupOutcome::Addrs(vec![ip("2606:4700:4700::1111")])
    );

    let nx_json = r#"{"Status":3,"Answer":[]}"#;
    assert_eq!(dns::parse_doh_json_addrs(nx_json), LookupOutcome::NotFound);

    let err_json = r#"{"Status":2}"#;
    assert_eq!(dns::parse_doh_json_addrs(err_json), LookupOutcome::Failed);
}
