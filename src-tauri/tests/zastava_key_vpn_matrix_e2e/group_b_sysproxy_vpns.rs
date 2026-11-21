use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use zastava_lib::auditor::network::build_entry_client;
use zastava_lib::auditor::seams::fakes::FakeUdp;
use zastava_lib::auditor::{OverallStatus, ProviderId};
use zastava_lib::proxy::ProxyManager;
use zastava_lib::proxy::upstream::connect_via_route_with_chained;
use zastava_lib::routing::net::test_support::TestEntryDnsGuard;
use zastava_lib::routing::{DIRECT_ROUTE_ID, Entry, EntryProto, Route};
use zastava_lib::state::AppState;
use zastava_lib::sysproxy::fs::FakeFs;
use zastava_lib::sysproxy::journal::Journal;
use zastava_lib::sysproxy::platform::{
    ChainState, FakePlatform, ProxyEndpoint, RegValue, ServiceId,
};
use zastava_lib::sysproxy::test_support::{
    HEAL_WINDOW_SECS, TestHealGuard, enable_macos_pac, enable_windows_inet, refresh_macos_pac,
};
use zastava_lib::sysproxy::{get_chained_proxy, set_chained_proxy};

use crate::harness::{
    ChainedMode, EntryMode, MockChainedProxy, MockEchoTarget, MockZastavaEntry, OfflineDns,
    RuIspKeyProbe, acquire_global_state, build_offline_auditor, clean_de_telemetry,
    send_connect_and_echo, send_http_get, start_proxy_server,
};

fn wifi() -> ServiceId {
    ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
}

#[tokio::test]
async fn e2e_v2box_happ_http_sysproxy_macos_and_windows() {
    let _g = acquire_global_state().await;
    let target = MockEchoTarget::spawn().await;
    let cp = MockChainedProxy::spawn(ChainedMode::HttpConnect, Some(target.addr)).await;
    let cp_port = cp.addr.port();
    let pac_url = "http://127.0.0.1:8899/proxy.pac";

    // 1. macOS v2box/Happ HTTP system proxy detection via FakePlatform
    let fs_mac = Arc::new(FakeFs::new());
    let plat_mac = FakePlatform::new();
    plat_mac.add_service(wifi());
    plat_mac.seed_chain(
        &wifi(),
        ChainState {
            http: ProxyEndpoint {
                enabled: Some(true),
                server: Some("127.0.0.1".into()),
                port: Some(cp_port),
                authenticated: Some(false),
            },
            https: ProxyEndpoint {
                enabled: Some(true),
                server: Some("127.0.0.1".into()),
                port: Some(cp_port),
                authenticated: Some(false),
            },
            socks: ProxyEndpoint::default(),
        },
    );
    let mut j_mac = Journal::open(fs_mac, Path::new("/mac")).unwrap();
    enable_macos_pac(&mut j_mac, &plat_mac, pac_url).unwrap();
    let detected_mac = get_chained_proxy().expect("macOS upstream HTTP proxy must be captured");
    assert_eq!(detected_mac, format!("http://127.0.0.1:{cp_port}"));

    // 2. Windows v2box/Happ HTTP ProxyServer detection via FakePlatform
    set_chained_proxy(None);
    let fs_win = Arc::new(FakeFs::new());
    let plat_win = FakePlatform::new();
    plat_win.seed_inet("ProxyEnable", RegValue::dword(1));
    plat_win.seed_inet("ProxyServer", RegValue::sz(&format!("127.0.0.1:{cp_port}")));
    let mut j_win = Journal::open(fs_win, Path::new("/win")).unwrap();
    enable_windows_inet(&mut j_win, &plat_win, pac_url, None).unwrap();
    assert_eq!(
        get_chained_proxy().as_deref(),
        Some(format!("http://127.0.0.1:{cp_port}").as_str())
    );

    // 3. PAC, RouteSelection::Direct (AI + Clean Room alias), and cascade build_entry_client
    let state = AppState::new_in_memory();
    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "DE",
        block_doh_and_tor: false,
        stun_ip: "185.100.10.2",
        stun_cc: "DE",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    auditor.resolver.set_cached(clean_de_telemetry()).await;

    let (srv, srv_task) = start_proxy_server(auditor.clone(), state.clone(), None, None).await;
    let pac = srv.build_pac_script().await;
    assert!(
        pac.contains(&format!("PROXY 127.0.0.1:{cp_port}; DIRECT")),
        "PAC must emit PROXY fallback for HTTP upstream, got:\n{pac}"
    );

    // RouteSelection::Direct AI CONNECT must honor chained_proxy
    let echoed = send_connect_and_echo(srv.bound_addr, "claude.ai:443", b"via-http-cp")
        .await
        .expect("Direct AI CONNECT must chain via HTTP upstream");
    assert_eq!(echoed, b"via-http-cp");
    assert!(cp.counters.http_connect_count.load(Ordering::SeqCst) >= 1);

    // Clean Room Direct alias must honor chained_proxy
    let pm = ProxyManager::from_server(Arc::clone(&srv));
    let alias_port = pm
        .ensure_profile_alias("cr-direct", Some(DIRECT_ROUTE_ID.to_string()))
        .await
        .unwrap();
    let alias_addr = format!("127.0.0.1:{alias_port}").parse().unwrap();
    let echoed_alias = send_connect_and_echo(alias_addr, "example.org:443", b"alias-http-cp")
        .await
        .expect("Clean Room Direct alias must chain via HTTP upstream");
    assert_eq!(echoed_alias, b"alias-http-cp");

    // cascade::build_entry_client must route through MockChainedProxy -> MockZastavaEntry
    let entry_node = MockZastavaEntry::spawn(EntryMode::HttpHealthy, None).await;
    cp.counters
        .add_route("entry-via-cp.zastava.test", entry_node.addr);
    let _dns_guard = TestEntryDnsGuard::install(Arc::new(|host, _port| {
        if host == "entry-via-cp.zastava.test" {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "offline dns blocked",
            )));
        }
        None
    }));
    let entry = Entry {
        proto: EntryProto::Http,
        host: "entry-via-cp.zastava.test".to_string(),
        port: entry_node.addr.port(),
        username: None,
        password: None,
        sni: None,
    };
    let client = build_entry_client(&entry, true, srv.bound_addr.port())
        .await
        .unwrap();
    let resp = client
        .get("http://probe.zastava.test/ipwho")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert!(entry_node.counters.connections.load(Ordering::SeqCst) >= 1);

    pm.stop_profile_alias("cr-direct").await;
    srv_task.abort();
}

#[tokio::test]
async fn e2e_incy_v2rayn_shadowrocket_socks5_sysproxy_macos_and_windows() {
    let _g = acquire_global_state().await;
    let target = MockEchoTarget::spawn().await;
    let cp = MockChainedProxy::spawn(ChainedMode::Socks5, Some(target.addr)).await;
    let cp_port = cp.addr.port();
    let pac_url = "http://127.0.0.1:8899/proxy.pac";

    // 1. macOS -getsocksfirewallproxy (SOCKS-only) preserves socks5://
    let fs_mac = Arc::new(FakeFs::new());
    let plat_mac = FakePlatform::new();
    plat_mac.add_service(wifi());
    plat_mac.seed_chain(
        &wifi(),
        ChainState {
            http: ProxyEndpoint::default(),
            https: ProxyEndpoint::default(),
            socks: ProxyEndpoint {
                enabled: Some(true),
                server: Some("127.0.0.1".into()),
                port: Some(cp_port),
                authenticated: Some(false),
            },
        },
    );
    let mut j_mac = Journal::open(fs_mac, Path::new("/mac-socks")).unwrap();
    enable_macos_pac(&mut j_mac, &plat_mac, pac_url).unwrap();
    assert_eq!(
        get_chained_proxy().as_deref(),
        Some(format!("socks5://127.0.0.1:{cp_port}").as_str())
    );

    // 2. Windows ProxyServer="socks=127.0.0.1:<port>" preserves socks5://
    set_chained_proxy(None);
    let fs_win = Arc::new(FakeFs::new());
    let plat_win = FakePlatform::new();
    plat_win.seed_inet("ProxyEnable", RegValue::dword(1));
    plat_win.seed_inet(
        "ProxyServer",
        RegValue::sz(&format!("socks=127.0.0.1:{cp_port}")),
    );
    let mut j_win = Journal::open(fs_win, Path::new("/win-socks")).unwrap();
    enable_windows_inet(&mut j_win, &plat_win, pac_url, None).unwrap();
    assert_eq!(
        get_chained_proxy().as_deref(),
        Some(format!("socks5://127.0.0.1:{cp_port}").as_str())
    );

    // 3. PAC emits SOCKS5; http_handler, tunnel, and entry_connect relay via SOCKS5 ATYP=0x03
    let state = AppState::new_in_memory();
    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "DE",
        block_doh_and_tor: false,
        stun_ip: "185.100.10.2",
        stun_cc: "DE",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    auditor.resolver.set_cached(clean_de_telemetry()).await;

    let (srv, srv_task) = start_proxy_server(auditor, state, None, None).await;
    let pac = srv.build_pac_script().await;
    assert!(
        pac.contains(&format!("SOCKS5 127.0.0.1:{cp_port}; DIRECT")),
        "PAC must emit SOCKS5 fallback, got:\n{pac}"
    );

    // Plain HTTP request to non-AI host -> must open SOCKS5 tunnel, NOT raw HTTP GET to SOCKS5 port
    let http_resp = send_http_get(
        srv.bound_addr,
        "GET http://example.org/hello HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        http_resp.contains("200 OK"),
        "plain HTTP via SOCKS5 chained proxy failed: {http_resp}"
    );

    // AI CONNECT in Direct mode -> SOCKS5 ATYP=0x03
    let echoed = send_connect_and_echo(srv.bound_addr, "claude.ai:443", b"socks5-tunnel")
        .await
        .expect("CONNECT via SOCKS5 chained proxy must succeed");
    assert_eq!(echoed, b"socks5-tunnel");

    // entry_connect via SOCKS5 chained proxy
    let entry_node = MockZastavaEntry::spawn(EntryMode::Socks5Healthy, Some(target.addr)).await;
    cp.counters
        .add_route("socks-entry.zastava.test", entry_node.addr);
    let _dns_guard = TestEntryDnsGuard::install(Arc::new(|host, _port| {
        if host == "socks-entry.zastava.test" {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "blocked direct dns",
            )));
        }
        None
    }));
    let route = Route {
        id: "r-socks".into(),
        label: "Socks Entry".into(),
        raw_key: "socks5://socks-entry.zastava.test:1080".into(),
        entries: vec![Entry {
            proto: EntryProto::Socks5,
            host: "socks-entry.zastava.test".into(),
            port: entry_node.addr.port(),
            username: None,
            password: None,
            sni: None,
        }],
        exit_ip: None,
        country: Some("DE".into()),
        expires_at: None,
        enabled: true,
        added_at: 0,
    };
    let mut stream = connect_via_route_with_chained(
        &route,
        "claude.ai",
        443,
        Duration::from_secs(4),
        srv.bound_addr.port(),
        Some(&cp.socks5_url()),
    )
    .await
    .expect("connect_via_route_with_chained via SOCKS5 must succeed");
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"entry-ok")
        .await
        .unwrap();

    assert!(
        cp.counters
            .socks5_domain_connect_count
            .load(Ordering::SeqCst)
            >= 3
    );
    assert_eq!(
        cp.counters.raw_http_on_socks_port.load(Ordering::SeqCst),
        0,
        "must NEVER send raw HTTP GET/CONNECT to a SOCKS5 port"
    );
    srv_task.abort();
}

#[tokio::test]
async fn e2e_key_reachable_only_via_chained_proxy_fast_hedged_connect() {
    let _g = acquire_global_state().await;
    let target = MockEchoTarget::spawn().await;
    let entry_node = MockZastavaEntry::spawn(EntryMode::HttpHealthy, Some(target.addr)).await;
    let cp = MockChainedProxy::spawn(ChainedMode::Socks5, None).await;
    cp.counters
        .add_route("isp-blocked.zastava.test", entry_node.addr);
    set_chained_proxy(Some(cp.socks5_url()));

    // Simulate direct ISP blocking entry DNS/TCP so only chained proxy reaches it
    let _dns_guard = TestEntryDnsGuard::install(Arc::new(|host, _port| {
        if host == "isp-blocked.zastava.test" {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "ISP blocked direct",
            )));
        }
        None
    }));

    let route = entry_node.as_domain_route("blocked-direct", "Via VPN", "isp-blocked.zastava.test");
    let started = Instant::now();
    let stream = connect_via_route_with_chained(
        &route,
        "claude.ai",
        443,
        Duration::from_secs(8),
        8899,
        Some(&cp.socks5_url()),
    )
    .await
    .expect("hedged chained connect must recover");
    drop(stream);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(2500),
        "must NOT stall on 4.25s direct_budget; took {:?}",
        elapsed
    );
    assert!(
        cp.counters
            .socks5_domain_connect_count
            .load(Ordering::SeqCst)
            >= 1
    );

    // Auditor populates gateway_latency_ms even when non-essential probes timeout
    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "DE",
        block_doh_and_tor: true,
        stun_ip: "185.100.10.2",
        stun_cc: "DE",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: true,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    let state = AppState::new_in_memory();
    let rep = auditor
        .evaluate_all(ProviderId::Openai, &state, true)
        .await
        .unwrap();
    assert_eq!(rep.overall_status, OverallStatus::Green);
    assert!(
        rep.gateway_latency_ms.is_some(),
        "gateway_latency_ms must be populated"
    );
}

#[tokio::test]
async fn e2e_incy_v2rayn_proxy_override_heal_guard_windows_and_macos() {
    let _g = acquire_global_state().await;
    let pac_url = "http://127.0.0.1:8899/proxy.pac";

    // 1. Windows HealGuard breaks iNCY/v2rayN tug-of-war loop
    let fs_win = Arc::new(FakeFs::new());
    let plat_win = FakePlatform::new();
    let mut j_win = Journal::open(fs_win, Path::new("/win-heal")).unwrap();
    let guard_win = TestHealGuard::new();
    let t0 = Instant::now();
    enable_windows_inet(&mut j_win, &plat_win, pac_url, Some((&guard_win, t0))).unwrap();

    for step in 1..=3 {
        // Simulate external VPN overwriting AutoConfigURL and forcing ProxyEnable=1
        plat_win.seed_inet(
            "AutoConfigURL",
            RegValue::sz("http://127.0.0.1:9999/vpn.pac"),
        );
        plat_win.seed_inet("ProxyEnable", RegValue::dword(1));
        plat_win.seed_inet("ProxyServer", RegValue::sz("socks=127.0.0.1:10808"));
        enable_windows_inet(
            &mut j_win,
            &plat_win,
            pac_url,
            Some((&guard_win, t0 + Duration::from_secs(step * 5))),
        )
        .unwrap();
    }
    assert!(
        guard_win.is_suspended_at("wininet", t0 + Duration::from_secs(20)),
        "Windows HealGuard must suspend after 3 foreign overrides"
    );
    // While suspended, Zastava leaves VPN settings untouched (0 extra writes)
    plat_win.seed_inet(
        "AutoConfigURL",
        RegValue::sz("http://127.0.0.1:9999/vpn.pac"),
    );
    let rep_suspended = enable_windows_inet(
        &mut j_win,
        &plat_win,
        pac_url,
        Some((&guard_win, t0 + Duration::from_secs(25))),
    )
    .unwrap();
    assert!(!rep_suspended.changed);
    assert_eq!(
        plat_win.inet_of("AutoConfigURL"),
        Some(RegValue::sz("http://127.0.0.1:9999/vpn.pac"))
    );

    // 2. macOS HealGuard suspends after 3 overrides AND recovers after HEAL_WINDOW cooldown
    let fs_mac = Arc::new(FakeFs::new());
    let plat_mac = FakePlatform::new();
    plat_mac.add_service(wifi());
    let mut j_mac = Journal::open(fs_mac, Path::new("/mac-heal")).unwrap();
    let guard_mac = TestHealGuard::new();
    enable_macos_pac(&mut j_mac, &plat_mac, pac_url).unwrap();

    for step in 1..=3 {
        plat_mac.seed_pac(
            &wifi(),
            zastava_lib::sysproxy::platform::PacState {
                url: Some("http://127.0.0.1:9999/other.pac".into()),
                enabled: Some(true),
            },
        );
        refresh_macos_pac(
            &mut j_mac,
            &plat_mac,
            pac_url,
            &guard_mac,
            t0 + Duration::from_secs(step * 5),
        )
        .unwrap();
    }
    assert!(guard_mac.is_suspended_at(&wifi().key(), t0 + Duration::from_secs(20)));

    // After HEAL_WINDOW cooldown expires, macOS HealGuard recovers and re-applies Zastava PAC
    plat_mac.seed_pac(
        &wifi(),
        zastava_lib::sysproxy::platform::PacState {
            url: Some("http://127.0.0.1:9999/other.pac".into()),
            enabled: Some(true),
        },
    );
    let after_cooldown = t0 + Duration::from_secs(HEAL_WINDOW_SECS + 20);
    let rep_recovered =
        refresh_macos_pac(&mut j_mac, &plat_mac, pac_url, &guard_mac, after_cooldown).unwrap();
    assert!(rep_recovered.changed);
    assert_eq!(plat_mac.pac_of(&wifi()).url.as_deref(), Some(pac_url));
}

#[tokio::test]
async fn e2e_windows_proxy_override_star_bypasses_chained_proxy() {
    let _g = acquire_global_state().await;
    let fs_win = Arc::new(FakeFs::new());
    let plat_win = FakePlatform::new();
    plat_win.seed_inet("ProxyEnable", RegValue::dword(1));
    plat_win.seed_inet("ProxyServer", RegValue::sz("127.0.0.1:10809"));
    plat_win.seed_inet("ProxyOverride", RegValue::sz("<local>;*"));
    let mut j_win = Journal::open(fs_win, Path::new("/win-override")).unwrap();
    enable_windows_inet(
        &mut j_win,
        &plat_win,
        "http://127.0.0.1:8899/proxy.pac",
        None,
    )
    .unwrap();
    assert_eq!(
        get_chained_proxy(),
        None,
        "wildcard ProxyOverride=* must clear chained_proxy"
    );
}

#[tokio::test]
async fn e2e_macos_incompatible_http_https_upstreams_fails_closed() {
    let _g = acquire_global_state().await;
    let fs_mac = Arc::new(FakeFs::new());
    let plat_mac = FakePlatform::new();
    plat_mac.add_service(wifi());
    plat_mac.seed_chain(
        &wifi(),
        ChainState {
            http: ProxyEndpoint {
                enabled: Some(true),
                server: Some("127.0.0.1".into()),
                port: Some(10809),
                authenticated: Some(false),
            },
            https: ProxyEndpoint {
                enabled: Some(true),
                server: Some("127.0.0.1".into()),
                port: Some(10810),
                authenticated: Some(false),
            },
            socks: ProxyEndpoint::default(),
        },
    );
    let mut j_mac = Journal::open(fs_mac, Path::new("/mac-incompat")).unwrap();
    let err =
        enable_macos_pac(&mut j_mac, &plat_mac, "http://127.0.0.1:8899/proxy.pac").unwrap_err();
    assert!(!err.is_empty());
    assert_eq!(
        plat_mac.os_writes(),
        0,
        "incompatible split HTTP/HTTPS upstreams must fail closed with 0 OS writes"
    );
}
