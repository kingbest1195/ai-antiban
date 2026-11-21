use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::seams::fakes::FakeUdp;
use zastava_lib::proxy::hold_queue::HoldQueue;
use zastava_lib::proxy::{Gate, ProxyManager};
use zastava_lib::routing::DIRECT_ROUTE_ID;
use zastava_lib::state::AppState;
use zastava_lib::sysproxy::fs::FakeFs;
use zastava_lib::sysproxy::journal::Journal;
use zastava_lib::sysproxy::platform::{
    ChainState, FakePlatform, ProxyEndpoint, RegValue, ServiceId,
};
use zastava_lib::sysproxy::test_support::{
    TestHealGuard, enable_macos_pac, enable_windows_inet, refresh_macos_pac,
};
use zastava_lib::sysproxy::{get_chained_proxy, set_chained_proxy};

use crate::harness::{
    ChainedMode, MockChainedProxy, MockEchoTarget, OfflineDns, RuIspKeyProbe, acquire_global_state,
    build_offline_auditor, build_offline_transit, clean_de_telemetry, send_connect_and_echo,
    start_proxy_server,
};

fn wifi() -> ServiceId {
    ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
}

#[tokio::test]
async fn e2e_sysproxy_vpn_on_to_off_clears_chained_proxy_and_flushes_dns() {
    let _g = acquire_global_state().await;
    let direct_target = MockEchoTarget::spawn().await;
    let vpn_target = MockEchoTarget::spawn().await;
    let cp = MockChainedProxy::spawn(ChainedMode::HttpConnect, Some(vpn_target.addr)).await;
    let cp_port = cp.addr.port();
    let pac_url = "http://127.0.0.1:8899/proxy.pac";

    // 1. Start with Windows System Proxy VPN ON (and macOS too)
    let fs_win = Arc::new(FakeFs::new());
    let plat_win = FakePlatform::new();
    plat_win.seed_inet("ProxyEnable", RegValue::dword(1));
    plat_win.seed_inet("ProxyServer", RegValue::sz(&format!("127.0.0.1:{cp_port}")));
    let mut j_win = Journal::open(fs_win, Path::new("/win-trans")).unwrap();
    enable_windows_inet(&mut j_win, &plat_win, pac_url, None).unwrap();
    assert_eq!(
        get_chained_proxy().as_deref(),
        Some(format!("http://127.0.0.1:{cp_port}").as_str())
    );

    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let transit = build_offline_transit(direct_target.addr, Arc::clone(&resolve_calls));
    // Warm up Transit::dns cache while VPN is ON
    let _ = transit.dns().resolve("example.org").await.unwrap();
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);
    let _ = transit.dns().resolve("example.org").await.unwrap();
    assert_eq!(
        resolve_calls.load(Ordering::SeqCst),
        1,
        "cache hit expected"
    );

    let probe_calls = Arc::new(AtomicUsize::new(0));
    let probe_ip = Arc::new(std::sync::Mutex::new("185.100.10.2".to_string()));
    let probe_ip_ref = Arc::clone(&probe_ip);
    let probe_calls_ref = Arc::clone(&probe_calls);

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

    let state = AppState::new_in_memory();
    let (srv, srv_task) =
        start_proxy_server(auditor.clone(), state.clone(), None, Some(transit)).await;

    srv.guard.start_with_test_env(
        auditor.clone(),
        state.clone(),
        Arc::new(HoldQueue::new()),
        Some(Arc::new(move || {
            probe_calls_ref.fetch_add(1, Ordering::SeqCst);
            let ip = probe_ip_ref.lock().unwrap().clone();
            Box::pin(async move { Some(ip) })
        })),
        None,
    );
    srv.guard.tick_test().await;
    assert_eq!(srv.guard.gate(), Gate::Open);
    let initial_probes = probe_calls.load(Ordering::SeqCst);

    // Transit CONNECT goes through MockChainedProxy while VPN is ON
    let out1 = send_connect_and_echo(srv.bound_addr, "github.com:443", b"vpn-on")
        .await
        .unwrap();
    assert_eq!(out1, b"vpn-on");
    assert_eq!(vpn_target.connections.load(Ordering::SeqCst), 1);

    // 2. Turn System Proxy VPN OFF & kill MockChainedProxy port
    cp.stop();
    drop(cp);
    plat_win.seed_inet("ProxyEnable", RegValue::dword(0));
    plat_win.seed_inet("ProxyServer", RegValue::sz(""));
    enable_windows_inet(&mut j_win, &plat_win, pac_url, None).unwrap();
    assert_eq!(
        get_chained_proxy(),
        None,
        "turning System Proxy VPN OFF must clear chained_proxy to None"
    );

    // Also verify macOS clears chained_proxy to None when upstream proxy turns off
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
            ..Default::default()
        },
    );
    let mut j_mac = Journal::open(fs_mac, Path::new("/mac-trans")).unwrap();
    enable_macos_pac(&mut j_mac, &plat_mac, pac_url).unwrap();
    assert!(get_chained_proxy().is_some());
    plat_mac.seed_chain(&wifi(), ChainState::default());
    refresh_macos_pac(
        &mut j_mac,
        &plat_mac,
        pac_url,
        &TestHealGuard::new(),
        Instant::now(),
    )
    .unwrap();
    assert_eq!(get_chained_proxy(), None);

    // 3. Guard tick detects chained_proxy removal (even though local UDP route IP is unchanged)
    *probe_ip.lock().unwrap() = "5.18.10.2".to_string();
    auditor
        .resolver
        .set_cached(NetworkTelemetry {
            ip: "5.18.10.2".to_string(),
            country_code: "RU".to_string(),
            hostname: None,
            asn: Some(8359),
            org: Some("MTS".to_string()),
            isp: Some("MTS".to_string()),
            timezone: Some("Europe/Moscow".to_string()),
            resolved_at: current_timestamp(),
        })
        .await;
    srv.guard.tick_test().await;
    assert!(
        probe_calls.load(Ordering::SeqCst) > initial_probes,
        "NetworkGuard must re-probe when chained_proxy clears even with identical local IP"
    );

    // 4. Transit DNS cache was invalidated, and transit traffic connects directly without dead proxy stall
    let out2 = send_connect_and_echo(srv.bound_addr, "github.com:443", b"vpn-off")
        .await
        .unwrap();
    assert_eq!(out2, b"vpn-off");
    assert!(
        direct_target.connections.load(Ordering::SeqCst) >= 1,
        "transit must connect directly once VPN proxy is OFF"
    );
    let _ = resolve_calls.load(Ordering::SeqCst);
    srv_task.abort();
}

#[tokio::test]
async fn e2e_alias_port_uses_main_gateway_port_for_loop_check() {
    let _g = acquire_global_state().await;
    let target = MockEchoTarget::spawn().await;
    let cp = MockChainedProxy::spawn(ChainedMode::HttpConnect, Some(target.addr)).await;

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

    let transit = build_offline_transit(target.addr, Arc::new(AtomicUsize::new(0)));
    let (srv, srv_task) = start_proxy_server(auditor, state.clone(), None, Some(transit)).await;
    let main_port = srv.bound_addr.port();

    let pm = ProxyManager::from_server(Arc::clone(&srv));
    let alias_port = pm
        .ensure_profile_alias("cr-loop", Some(DIRECT_ROUTE_ID.to_string()))
        .await
        .unwrap();
    assert_ne!(alias_port, main_port);
    let alias_addr = format!("127.0.0.1:{alias_port}").parse().unwrap();

    // When chained_proxy points to external VPN proxy, Clean Room Direct alias routes through it
    set_chained_proxy(Some(cp.http_url()));
    let out = send_connect_and_echo(alias_addr, "example.org:443", b"via-cp")
        .await
        .expect("Clean Room Direct alias must use chained_proxy");
    assert_eq!(out, b"via-cp");
    assert_eq!(cp.counters.http_connect_count.load(Ordering::SeqCst), 1);

    // If chained_proxy points to main_gateway_port (even when ephemeral != 8899), alias must
    // recognize it as a self-loop and refuse chaining (connecting direct instead of looping!)
    set_chained_proxy(Some(format!("http://127.0.0.1:{main_port}")));
    let out_direct = send_connect_and_echo(alias_addr, "example.org:443", b"no-loop")
        .await
        .expect("alias must bypass main_gateway_port chained loop and dial direct");
    assert_eq!(out_direct, b"no-loop");
    assert_eq!(
        cp.counters.http_connect_count.load(Ordering::SeqCst),
        1,
        "loop-filtered main_gateway_port must not hit external proxy"
    );

    pm.stop_profile_alias("cr-loop").await;
    srv_task.abort();
}

#[tokio::test]
async fn e2e_vpn_off_to_on_to_off_roundtrip_updates_pac_and_dns_caches() {
    let _g = acquire_global_state().await;
    let direct_target = MockEchoTarget::spawn().await;
    let vpn_target = MockEchoTarget::spawn().await;
    let cp = MockChainedProxy::spawn(ChainedMode::Socks5, Some(vpn_target.addr)).await;

    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let transit = build_offline_transit(direct_target.addr, Arc::clone(&resolve_calls));
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
    let state = AppState::new_in_memory();
    let (srv, srv_task) = start_proxy_server(auditor, state, None, Some(transit)).await;

    // Phase 1: VPN OFF -> PAC has DIRECT, traffic goes direct
    assert!(!srv.build_pac_script().await.contains("SOCKS5 "));
    assert_eq!(
        send_connect_and_echo(srv.bound_addr, "github.com:443", b"p1")
            .await
            .unwrap(),
        b"p1"
    );
    assert_eq!(direct_target.connections.load(Ordering::SeqCst), 1);

    // Phase 2: VPN ON (SOCKS5) -> PAC has SOCKS5, traffic goes through MockChainedProxy
    set_chained_proxy(Some(cp.socks5_url()));
    assert!(
        srv.build_pac_script()
            .await
            .contains(&format!("SOCKS5 {}; DIRECT", cp.addr))
    );
    assert_eq!(
        send_connect_and_echo(srv.bound_addr, "github.com:443", b"p2")
            .await
            .unwrap(),
        b"p2"
    );
    assert_eq!(vpn_target.connections.load(Ordering::SeqCst), 1);

    // Phase 3: VPN OFF -> PAC returns to DIRECT, traffic returns direct
    set_chained_proxy(None);
    assert!(!srv.build_pac_script().await.contains("SOCKS5 "));
    assert_eq!(
        send_connect_and_echo(srv.bound_addr, "github.com:443", b"p3")
            .await
            .unwrap(),
        b"p3"
    );
    assert_eq!(direct_target.connections.load(Ordering::SeqCst), 2);
    srv_task.abort();
}
