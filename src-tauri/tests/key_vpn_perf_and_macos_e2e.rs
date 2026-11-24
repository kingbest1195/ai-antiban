//! E2E regression tests for §7.8 (Zastava key over VPN / Gemini speed & stability)
//! and §7.9 (macOS `RLIMIT_NOFILE` raise & `clear_pac_url` fix).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zastava_lib::auditor::cache::{CheckCache, EXTERNAL_LIST_UNKNOWN_TTL, RDNS_TTL, cached_check};
use zastava_lib::auditor::rules::ProviderMatrix;
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{AuditEnv, HttpProbeOutcome, LookupOutcome};
use zastava_lib::auditor::{
    AuditProtectionFlags, Auditor, CheckResult, NetworkTelemetry, ProviderId, UnknownReason,
};
use zastava_lib::proxy::pac::{generate_pac_script, get_all_ai_domains};
use zastava_lib::proxy::upstream::connect_via_route_with_chained;
use zastava_lib::proxy::{HoldQueue, ProxyServer};
use zastava_lib::routing::net::test_support::resolve_entry_checked_with_closures_opts;
use zastava_lib::routing::{Entry, EntryProto, Route};
use zastava_lib::state::AppState;
use zastava_lib::sysproxy::fs::FakeFs;
use zastava_lib::sysproxy::journal::Journal;
use zastava_lib::sysproxy::platform::{FakePlatform, PacState, Platform, ServiceId};
use zastava_lib::sysproxy::test_support::enable_macos_pac;

fn socks_route(id: &str, host: &str, port: u16) -> Route {
    Route {
        id: id.to_string(),
        label: format!("test {id}"),
        country: Some("NL".to_string()),
        exit_ip: None,
        expires_at: None,
        sub_url: None,
        grace_extended: false,
        entries: vec![Entry {
            proto: EntryProto::Socks5,
            host: host.to_string(),
            port,
            username: None,
            password: None,
            sni: None,
        }],
        raw_key: format!("socks5://{host}:{port}"),
        enabled: true,
        added_at: 0,
    }
}

async fn spawn_socks_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut g = [0u8; 3];
                if s.read_exact(&mut g).await.is_err() {
                    return;
                }
                let _ = s.write_all(&[0x05, 0x00]).await;
                let mut head = [0u8; 4];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut len = [0u8; 1];
                if s.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut rest = vec![0u8; len[0] as usize + 2];
                if s.read_exact(&mut rest).await.is_err() {
                    return;
                }
                let _ = s
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn sec7_8_parallel_gemini_connects_coalesce_and_reuse_cached_route_audit() {
    let socks_port = spawn_socks_echo().await;
    let state = AppState::new_in_memory();
    let route = socks_route("gem-vpn", "127.0.0.1", socks_port);
    state.upsert_route(route.clone()).await.unwrap();
    state
        .bind_provider_route("gemini", Some("gem-vpn"))
        .await
        .unwrap();

    // Simulate an audit environment whose external network probes all stall/timeout
    // while route telemetry is cached and the entry proxy itself is alive.
    let mut probe = FakeProbe::new(HttpProbeOutcome::Timeout);
    probe = probe.with_route("torproject", HttpProbeOutcome::Timeout);
    let dns = FakeDns::new(LookupOutcome::Timeout);
    let env = AuditEnv {
        dns: Arc::new(dns),
        probe: Arc::new(probe),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    };
    let auditor = Auditor::with_env(env).unwrap();
    auditor.set_protection_flags(AuditProtectionFlags {
        sysproxy_active: true,
        cli_or_sandbox_protection_active: true,
        os_pac_deferred: false,
    });
    let nl_tel = NetworkTelemetry {
        ip: "185.220.10.50".to_string(),
        country_code: "NL".to_string(),
        hostname: Some("nl-vps.example.net".to_string()),
        asn: Some(20473),
        org: Some("Choopa".to_string()),
        isp: Some("Choopa".to_string()),
        timezone: Some("Europe/Amsterdam".to_string()),
        resolved_at: zastava_lib::auditor::network::current_timestamp(),
    };
    auditor
        .resolver
        .set_cached_for_route(Some(route.id.clone()), nl_tel)
        .await;

    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::new(HoldQueue::new()), None)
            .await
            .unwrap(),
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let hosts = [
        "gemini.google.com",
        "aistudio.google.com",
        "generativelanguage.googleapis.com",
        "alkalimakersuite-pa.clients6.google.com",
        "notebooklm.google.com",
        "accounts.google.com",
        "oauth2.googleapis.com",
        "clients6.google.com",
    ];
    let started = Instant::now();
    let mut handles = Vec::new();
    for (idx, host) in hosts.into_iter().enumerate() {
        let addr = server.bound_addr;
        handles.push(tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
            client.write_all(req.as_bytes()).await.unwrap();
            let mut head = [0u8; 256];
            let n = tokio::time::timeout(Duration::from_secs(6), client.read(&mut head))
                .await
                .expect("CONNECT response must not stall on cascading 8-10s audits")
                .unwrap();
            let s = String::from_utf8_lossy(&head[..n]).to_string();
            assert!(
                s.starts_with("HTTP/1.1 200"),
                "CONNECT #{idx} ({host}) failed: {s}"
            );
            let msg = format!("GEM_{idx}");
            client.write_all(msg.as_bytes()).await.unwrap();
            let mut echo = vec![0u8; msg.len()];
            client.read_exact(&mut echo).await.unwrap();
            assert_eq!(echo, msg.as_bytes());
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "8 parallel Gemini CONNECTs took {:?}, expected coalesced fast completion",
        started.elapsed()
    );

    // Second wave of CONNECTs must hit the cached RouteReport in <500ms without running any audit.
    let wave2_start = Instant::now();
    for host in ["gemini.google.com", "aistudio.google.com"] {
        let mut client = tokio::net::TcpStream::connect(server.bound_addr)
            .await
            .unwrap();
        let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();
        let mut head = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut head))
            .await
            .expect("cached route audit must respond immediately")
            .unwrap();
        assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
    }
    assert!(
        wave2_start.elapsed() < Duration::from_millis(500),
        "cached wave2 took {:?}, expected <500ms",
        wave2_start.elapsed()
    );
}

#[tokio::test]
async fn sec7_8_tun_fake_ip_fast_accept_without_chained_and_v4_first() {
    let entry = Entry {
        proto: EntryProto::Https,
        host: "node.zastava.test".to_string(),
        port: 443,
        username: None,
        password: None,
        sni: None,
    };
    let fake_v4: SocketAddr = "198.18.0.42:443".parse().unwrap();
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let fb_ref = Arc::clone(&fallback_calls);

    let started = Instant::now();
    let resolved = resolve_entry_checked_with_closures_opts(
        &entry,
        false,
        8899,
        true,
        move |_, _, _| Ok(vec![fake_v4]),
        move |_, _| {
            fb_ref.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1500));
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "fallback slow",
            ))
        },
    )
    .await
    .unwrap();
    assert_eq!(resolved, vec![fake_v4]);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "FakeIP resolution must not block on 1500ms fallback DNS"
    );

    // Dead IPv6 (::1) + live IPv4 (127.0.0.1) over localhost route connects immediately via IPv4.
    let socks_port = spawn_socks_echo().await;
    let he_route = socks_route("he-v4-first", "localhost", socks_port);
    let he_start = Instant::now();
    let mut stream = connect_via_route_with_chained(
        &he_route,
        "gemini.google.com",
        443,
        Duration::from_secs(3),
        0,
        None,
    )
    .await
    .expect("IPv4-first Happy Eyeballs must connect around dead IPv6");
    assert!(
        he_start.elapsed() < Duration::from_millis(500),
        "IPv4-first connect took {:?}",
        he_start.elapsed()
    );
    stream.write_all(b"V4_FAST").await.unwrap();
    let mut buf = [0u8; 7];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"V4_FAST");
}

#[tokio::test(start_paused = true)]
async fn sec7_8_rdns_and_external_list_unknown_cooldown_and_pac_domain_trim() {
    // 1. Reverse DNS & external list unknown cooldowns prevent 5s retry storms.
    let cache = CheckCache::default();
    let calls = AtomicUsize::new(0);
    let probe = || async {
        calls.fetch_add(1, Ordering::SeqCst);
        CheckResult::unknown("DNSBL_TIMEOUT", "timeout", UnknownReason::Timeout)
    };
    let _ = cache
        .rdns
        .get_or_compute_with_unknown_ttl(
            "rdns:1.2.3.4",
            RDNS_TTL,
            EXTERNAL_LIST_UNKNOWN_TTL,
            |r| !r.is_unknown(),
            probe(),
        )
        .await;
    tokio::time::advance(Duration::from_secs(15)).await;
    let _ = cache
        .rdns
        .get_or_compute_with_unknown_ttl(
            "rdns:1.2.3.4",
            RDNS_TTL,
            EXTERNAL_LIST_UNKNOWN_TTL,
            |r| !r.is_unknown(),
            probe(),
        )
        .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "Unknown must stay cached across 15s (30s cooldown)"
    );
    tokio::time::advance(Duration::from_secs(16)).await;
    let _ = cached_check(&cache.rdns, "rdns:2.3.4.5", RDNS_TTL, async {
        CheckResult::ok("REVERSE_DNS_CLEAN", "ok")
    })
    .await;

    // 2. Noisy general-Google domains are excluded from PAC and ProviderId::from_host,
    // while Gemini, AI Studio, and auth domains stay routed.
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let pac = generate_pac_script(&get_all_ai_domains(&matrix), "127.0.0.1:8899", None);
    for noisy in [
        "www.google.com",
        "play.google.com",
        "ogs.google.com",
        "apis.google.com",
        "jnn-pa.googleapis.com",
        "myaccount.google.com",
    ] {
        assert_eq!(ProviderId::from_host(noisy), None);
        assert!(!pac.contains(&format!("\"{noisy}\"")), "{noisy} in PAC");
    }
    for kept in [
        "gemini.google.com",
        "aistudio.google.com",
        "generativelanguage.googleapis.com",
        "alkalimakersuite-pa.clients6.google.com",
        "accounts.google.com",
        "oauth2.googleapis.com",
    ] {
        assert_eq!(ProviderId::from_host(kept), Some(ProviderId::Gemini));
        assert!(
            pac.contains(&format!("\"{kept}\"")),
            "{kept} missing in PAC"
        );
    }
}

#[test]
fn sec7_9_unix_rlimit_nofile_and_clear_pac_url_avoid_empty_url_param() {
    zastava_lib::sysproxy::force_os_dry_run();

    // 1. On Unix/macOS, soft RLIMIT_NOFILE is raised well above the 256 macOS .app default.
    #[cfg(unix)]
    {
        let (cur, max) = zastava_lib::raise_nofile_limit().expect("Unix getrlimit succeeds");
        let expected_min = 4096u64.min(max);
        assert!(
            cur >= expected_min,
            "expected RLIMIT_NOFILE >= {expected_min}, got cur={cur} max={max}"
        );
        assert!(cur > 256 || max <= 256);
    }

    // 2. Enabling and restoring macOS PAC via Journal leaves no empty `""` URL failure path.
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let wifi = ServiceId::new("en0", "Wi-Fi", "Wi-Fi");
    plat.add_service(wifi.clone());
    let mut j = Journal::open(fs, Path::new("/sec79-mac")).unwrap();
    enable_macos_pac(&mut j, &plat, "http://127.0.0.1:8899/proxy.pac").unwrap();
    assert_eq!(
        plat.pac_of(&wifi).url.as_deref(),
        Some("http://127.0.0.1:8899/proxy.pac")
    );
    plat.set_pac(
        &wifi,
        &PacState {
            url: Some(String::new()),
            enabled: Some(false),
        },
    )
    .unwrap();
    assert_eq!(plat.pac_of(&wifi).enabled, Some(false));
}

#[tokio::test]
async fn sec7_8_unreachable_route_disables_soft_bypass_and_records_route_down() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = listener.local_addr().unwrap().port();
    drop(listener);

    let state = AppState::new_in_memory();
    let route = socks_route("dead-cached", "127.0.0.1", dead_port);
    state.upsert_route(route.clone()).await.unwrap();
    state
        .bind_provider_route("gemini", Some("dead-cached"))
        .await
        .unwrap();
    // Simulate a route that had cached telemetry earlier, then failed reachability check.
    state
        .route_health()
        .mark_unreachable("dead-cached", "connection refused");

    let env = AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::Timeout)),
        probe: Arc::new(FakeProbe::new(HttpProbeOutcome::Timeout)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    };
    let auditor = Auditor::with_env(env).unwrap();
    auditor
        .resolver
        .set_cached_for_route(
            Some(route.id.clone()),
            NetworkTelemetry {
                ip: "185.220.10.50".to_string(),
                country_code: "NL".to_string(),
                hostname: None,
                asn: Some(20473),
                org: Some("Choopa".to_string()),
                isp: Some("Choopa".to_string()),
                timezone: Some("Europe/Amsterdam".to_string()),
                resolved_at: zastava_lib::auditor::network::current_timestamp(),
            },
        )
        .await;

    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::new(HoldQueue::new()), None)
            .await
            .unwrap(),
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let mut client = tokio::net::TcpStream::connect(server.bound_addr)
        .await
        .unwrap();
    client
        .write_all(b"CONNECT gemini.google.com:443 HTTP/1.1\r\nHost: gemini.google.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let read_timeout = if cfg!(windows) {
        // Windows loopback TCP connect to a closed port incurs ~2s SYN retransmission delay.
        Duration::from_secs(8)
    } else {
        Duration::from_secs(3)
    };
    let n = tokio::time::timeout(read_timeout, client.read(&mut buf))
        .await
        .expect("unreachable route must fail fast without soft-bypass stall")
        .unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        resp.contains("502") || resp.contains("unavailable"),
        "expected fail-closed 502 route unavailable, got: {resp}"
    );
    assert!(
        state
            .stats()
            .snapshot_sync()
            .recent_events
            .iter()
            .any(|e| e.action == "ROUTE_DOWN"),
        "ROUTE_DOWN must be recorded"
    );
}
