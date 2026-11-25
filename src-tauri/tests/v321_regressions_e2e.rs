//! End-to-End regression suite for Zastava v3.2.1 (`spec-v3.2.1.md` §8.2 Scenarios 1–6).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::geo_matrix::ProviderId;
use zastava_lib::auditor::probes::stun;
use zastava_lib::auditor::rules::DangerousAsns;
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp, addr};
use zastava_lib::auditor::seams::{
    HttpProbeOutcome, IpProbe, LookupOutcome, TxtOutcome, nameserver_signature,
    should_record_dns_diag_in,
};
use zastava_lib::auditor::{AuditEnv, Auditor};
use zastava_lib::proxy::guard::{GuardTestObserver, ProbeFn, compute_local_route_fingerprint};
use zastava_lib::proxy::hold_queue::{HoldQueue, HoldResolution};
use zastava_lib::proxy::{Gate, ProxyServer};
use zastava_lib::routing::{Entry, EntryProto, Route};
use zastava_lib::state::AppState;
use zastava_lib::sysproxy::fs::FakeFs;
use zastava_lib::sysproxy::journal::Journal;
use zastava_lib::sysproxy::platform::{FakePlatform, RegValue};
use zastava_lib::sysproxy::test_support::{
    LEGACY_MIGRATION_MARK, enable_windows_inet, restore_and_migrate_for_test,
};
use zastava_lib::updater::test_support::{
    WINDOWS_NSIS_TARGET, WindowsInstallKind, configure_rollback_builder,
    validate_windows_rollback_compatibility, windows_rollback_target,
};
use zastava_lib::updater::{UPDATER_PUBKEY, UpdateFailure};

struct DynamicExitProbe(Arc<Mutex<Option<(String, String, u32)>>>);

impl IpProbe for DynamicExitProbe {
    fn get<'a>(
        &'a self,
        url: &'a str,
        _limit: Duration,
    ) -> zastava_lib::auditor::seams::BoxFuture<'a, HttpProbeOutcome> {
        let snap = self.0.lock().unwrap().clone();
        Box::pin(async move {
            let Some((ip, cc, asn)) = snap else {
                return HttpProbeOutcome::Timeout;
            };
            let body = if url.contains("ipwho.is") {
                format!(
                    r#"{{"success":true,"ip":"{ip}","country_code":"{cc}","connection":{{"asn":{asn},"org":"TestNet","isp":"TestNet","domain":"test.example"}},"timezone":{{"id":"Europe/Berlin"}}}}"#
                )
            } else {
                format!("fl=1\nip={ip}\nloc={cc}\ncolo=FRA\n")
            };
            HttpProbeOutcome::Response { status: 200, body }
        })
    }
}

async fn spawn_echo_upstream() -> Option<(SocketAddr, Arc<AtomicU64>)> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("bind echo upstream: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let hits_clone = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            hits_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Some((addr, hits))
}

async fn send_connect(addr: SocketAddr, host: &str) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect proxy");
    let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut buf))
        .await
        .expect("gateway response timeout")
        .unwrap();
    (stream, String::from_utf8_lossy(&buf[..n]).to_string())
}

async fn ping_tunnel(stream: &mut TcpStream, msg: &[u8]) {
    stream.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);
}

fn offline_auditor() -> Auditor {
    Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(FakeProbe::new(HttpProbeOutcome::Timeout)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap()
}

async fn start_guard_server(
    auditor: Auditor,
    upstream_addr: SocketAddr,
    probe: ProbeFn,
) -> (
    Arc<ProxyServer>,
    AppState,
    Arc<HoldQueue>,
    Arc<GuardTestObserver>,
) {
    let state = AppState::new_in_memory();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor.clone(),
            state.clone(),
            hold_queue.clone(),
            Some(upstream_addr),
        )
        .await
        .unwrap(),
    );
    let observer = Arc::new(GuardTestObserver::default());
    let fixed_fp = compute_local_route_fingerprint(None);
    server
        .guard
        .set_route_fingerprint_fn_for_test(Some(Arc::new(move |_| fixed_fp.clone())));
    server.guard.start_with_test_env_observed(
        auditor,
        state.clone(),
        hold_queue.clone(),
        Some(probe),
        None,
        Arc::clone(&observer),
    );
    server
        .guard
        .seed_baseline_for_test("185.10.20.30", "DE", None)
        .await;
    server.guard.ensure_fresh().await;
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });
    (server, state, hold_queue, observer)
}

#[tokio::test]
async fn scenario_1_slow_vpn_blip_and_fallback_keeps_ai_tunnel_open_with_zero_popup_and_leaks() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, _)) = spawn_echo_upstream().await else {
        return;
    };
    let exit = Arc::new(Mutex::new(Some((
        "185.10.20.30".into(),
        "DE".into(),
        24940,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(exit)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();

    let blip = Arc::new(AtomicBool::new(false));
    let slow_fallback = Arc::new(AtomicBool::new(false));
    let (blip_flag, slow_flag) = (Arc::clone(&blip), Arc::clone(&slow_fallback));
    let probe: ProbeFn = Arc::new(move || {
        let (do_blip, do_slow) = (
            blip_flag.load(Ordering::SeqCst),
            slow_flag.load(Ordering::SeqCst),
        );
        Box::pin(async move {
            if do_blip {
                return None;
            }
            if do_slow {
                tokio::time::sleep(Duration::from_millis(450)).await;
            }
            Some("185.10.20.30".to_string())
        })
    });
    let (server, state, _hq, observer) = start_guard_server(auditor, upstream_addr, probe).await;

    let (mut ai_tunnel, head) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping_tunnel(&mut ai_tunnel, b"before-blip").await;

    // Single transient 1.1.1.1 blip with stable local route -> stays Open.
    blip.store(true, Ordering::SeqCst);
    server.guard.tick_test().await;
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    ping_tunnel(&mut ai_tunnel, b"during-single-blip").await;

    // Slow fallback (450ms RTT, simulating api.ipify.org) resets counter and keeps tunnel open.
    blip.store(false, Ordering::SeqCst);
    slow_fallback.store(true, Ordering::SeqCst);
    server.guard.tick_test().await;
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    ping_tunnel(&mut ai_tunnel, b"after-slow-fallback").await;

    assert_eq!(observer.shows.load(Ordering::SeqCst), 0);
    assert_eq!(state.stats().snapshot().await.intercepted_leaks, 0);
}

#[tokio::test]
async fn scenario_2_real_vpn_drop_to_ru_aborts_tunnels_writes_diag_avoids_all_and_logs_manual_allow()
 {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };
    let exit = Arc::new(Mutex::new(Some((
        "185.10.20.30".into(),
        "DE".into(),
        24940,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let exit_probe = Arc::clone(&exit);
    let probe: ProbeFn = Arc::new(move || {
        let ip = exit_probe.lock().unwrap().as_ref().map(|x| x.0.clone());
        Box::pin(async move { ip })
    });
    let (server, state, hold_queue, _obs) =
        start_guard_server(auditor.clone(), upstream_addr, probe).await;

    let (mut active_tunnel, head) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping_tunnel(&mut active_tunnel, b"alive").await;
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Real VPN drop -> confirmed IP change to RU (`5.5.5.5`).
    *exit.lock().unwrap() = Some(("5.5.5.5".into(), "RU".into(), 9009));
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;

    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
    let mut abort_buf = [0u8; 8];
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), active_tunnel.read(&mut abort_buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));

    for _ in 0..100 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.phase == "ready")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let alert = hold_queue.current_alert().expect("RU ready alert");

    // New AI CONNECT is held behind Pending gate without dialing upstream.
    let addr = server.bound_addr;
    let blocked_req = tokio::spawn(async move { send_connect(addr, "api.openai.com").await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // [guard] diagnostic entry written; NO `"all"` pseudo-host in recent_events.
    assert!(
        zastava_lib::diagnostics::dump()
            .iter()
            .any(|l| l.contains("[guard]"))
    );
    let snap = state.stats().snapshot().await;
    assert!(!snap.recent_events.iter().any(|e| e.host == "all"));

    assert!(hold_queue.resolve(&alert.id, HoldResolution::Block).await);
    let (_s2, resp2) = blocked_req.await.unwrap();
    assert!(resp2.contains("403 Forbidden"), "{resp2}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Exercise provider hold `Allow` on RU -> emits `MANUAL_ALLOW` and never `PROTECTED`.
    server.guard.set_manual_killswitch(false, &state).await;
    *exit.lock().unwrap() = Some(("5.5.5.6".into(), "RU".into(), 9009));
    auditor.resolver.invalidate_direct_cache().await;
    server
        .guard
        .seed_baseline_for_test("5.5.5.6", "RU", None)
        .await;
    let hold_conn = tokio::spawn(async move { send_connect(addr, "claude.ai").await });
    for _ in 0..100 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.scope == "provider")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let prov_alert = hold_queue
        .current_alert()
        .expect("provider hold alert on RU");
    assert!(
        hold_queue
            .resolve(&prov_alert.id, HoldResolution::Allow)
            .await
    );
    let (_s4, resp4) = hold_conn.await.unwrap();
    assert!(resp4.contains("200 Connection Established"), "{resp4}");

    let final_events = state.stats().snapshot().await.recent_events;
    assert!(
        final_events
            .iter()
            .any(|e| e.action == "MANUAL_ALLOW" && e.country == "RU")
    );
    assert!(
        !final_events
            .iter()
            .any(|e| e.action == "PROTECTED" && e.country == "RU")
    );
}

#[tokio::test]
async fn scenario_3_manual_killswitch_isolates_non_ai_transit_from_ai_and_payment_blocks() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, _)) = spawn_echo_upstream().await else {
        return;
    };
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = http_listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        }
    });

    let state = AppState::new_in_memory();
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_auditor(),
            state.clone(),
            Arc::new(HoldQueue::new()),
            Some(upstream_addr),
        )
        .await
        .unwrap(),
    );
    server.guard.set_manual_killswitch(true, &state).await;
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let (_s_ai, ai_resp) = send_connect(server.bound_addr, "api.anthropic.com").await;
    assert!(ai_resp.contains("403 Forbidden"), "{ai_resp}");
    let (_s_pay, pay_resp) = send_connect(server.bound_addr, "checkout.stripe.com").await;
    assert!(pay_resp.contains("403 Forbidden"), "{pay_resp}");

    let mut pay_http = TcpStream::connect(server.bound_addr).await.unwrap();
    pay_http
        .write_all(
            b"GET http://checkout.stripe.com/pay HTTP/1.1\r\nHost: checkout.stripe.com\r\n\r\n",
        )
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = pay_http.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 503"));

    for host in ["discord.com", "prod-live-front.playbattlegrounds.com"] {
        let (mut s, head) = send_connect(server.bound_addr, host).await;
        assert!(
            head.starts_with("HTTP/1.1 200") && !head.contains("503"),
            "{head}"
        );
        ping_tunnel(&mut s, b"transit-ok").await;
    }

    let http_server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_auditor(),
            state.clone(),
            Arc::new(HoldQueue::new()),
            Some(http_addr),
        )
        .await
        .unwrap(),
    );
    http_server.guard.set_manual_killswitch(true, &state).await;
    let h_srv = Arc::clone(&http_server);
    tokio::spawn(async move { h_srv.run().await });

    let mut transit_http = TcpStream::connect(http_server.bound_addr).await.unwrap();
    transit_http
        .write_all(b"GET http://discord.com/api/updates HTTP/1.1\r\nHost: discord.com\r\n\r\n")
        .await
        .unwrap();
    let n = transit_http.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 200") && resp.ends_with("ok"),
        "{resp}"
    );
}

#[test]
fn scenario_4_windows_wininet_dead_loopback_and_continuous_pac_sweep() {
    let dead_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);

    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_inet("ProxyEnable", RegValue::dword(1));
    p.seed_inet(
        "ProxyServer",
        RegValue::sz(&format!("127.0.0.1:{dead_port}")),
    );
    let mut j = Journal::open(Arc::new(fs), Path::new("/data")).unwrap();
    enable_windows_inet(&mut j, &p, "http://127.0.0.1:8899/proxy.pac", None).unwrap();
    assert_eq!(p.inet_of("ProxyEnable"), Some(RegValue::dword(0)));
    p.clear_calls();

    let rep = j.restore_all(&p);
    assert!(!rep.has_failures());
    assert_eq!(p.inet_of("ProxyEnable"), Some(RegValue::dword(0)));
    assert!(p.calls().iter().any(|c| c == "notify_inet_refresh"));
    assert!(
        zastava_lib::diagnostics::dump()
            .iter()
            .any(|l| l.contains("[sysproxy:windows]") && l.contains("ProxyEnable=1"))
    );

    let (fs2, p2) = (FakeFs::new(), FakePlatform::new());
    let mut j2 = Journal::open(Arc::new(fs2), Path::new("/data")).unwrap();
    j2.set_mark(&p2, LEGACY_MIGRATION_MARK).unwrap();
    p2.seed_inet(
        "AutoConfigURL",
        RegValue::sz("http://127.0.0.1:9123/proxy.pac"),
    );
    p2.clear_calls();

    let sweep_rep = restore_and_migrate_for_test(&mut j2, &p2);
    assert!(!sweep_rep.has_failures());
    assert_eq!(p2.inet_of("AutoConfigURL"), None);
    assert!(p2.calls().iter().any(|c| c == "notify_inet_refresh"));
}

#[tokio::test(flavor = "multi_thread")]
async fn scenario_5_windows_rollback_safety_and_release_workflow_mapping() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let manifest = serde_json::json!({
        "version": "3.1.1",
        "notes": "legacy v3.1.1",
        "platforms": {
            "windows-x86_64": { "url": "http://127.0.0.1:1/Zastava_3.1.1_x64-setup.exe", "signature": "sig-exe" },
            "windows-x86_64-msi": { "url": "http://127.0.0.1:1/Zastava_3.1.1_x64_en-US.msi", "signature": "sig-msi" },
            "windows-x86_64-nsis": { "url": "http://127.0.0.1:1/Zastava_3.1.1_x64-setup.exe", "signature": "sig-nsis" }
        }
    })
    .to_string();

    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                manifest.len(),
                manifest
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });

    assert_eq!(
        windows_rollback_target(WindowsInstallKind::Nsis),
        WINDOWS_NSIS_TARGET
    );

    let mut ctx = tauri::test::mock_context(tauri::test::noop_assets());
    ctx.config_mut().plugins.0.insert(
        "updater".to_string(),
        serde_json::json!({ "pubkey": UPDATER_PUBKEY, "endpoints": [], "dangerousInsecureTransportProtocol": true }),
    );
    let app = tauri::test::mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(ctx)
        .unwrap();

    let url: url::Url = format!("http://{addr}/latest.json").parse().unwrap();
    let updater = configure_rollback_builder(
        app.handle(),
        url,
        "3.1.1".to_string(),
        Some(WindowsInstallKind::Nsis),
    )
    .unwrap()
    .build()
    .unwrap();
    let update = updater
        .check()
        .await
        .unwrap()
        .expect("v3.1.1 rollback resolved");
    assert_eq!(
        update.download_url.as_str(),
        "http://127.0.0.1:1/Zastava_3.1.1_x64-setup.exe"
    );

    let err = validate_windows_rollback_compatibility(WindowsInstallKind::Msi, &update.version)
        .expect_err("MSI rollback < 3.2.1 must fail before teardown");
    assert!(matches!(err, UpdateFailure::Install(ref m) if m.contains("Защита не отключалась")));

    let workflow = include_str!("../../.github/workflows/release.yml");
    assert!(workflow.contains("\"windows-x86_64\": exeEntry"));
    assert!(workflow.contains("\"windows-x86_64-nsis\": exeEntry"));
    assert!(workflow.contains("\"windows-x86_64-msi\": msiEntry"));
    assert!(include_str!("../src/updater/github.rs").contains(".no_proxy()"));
    assert!(include_str!("../src/updater/install.rs").contains(".no_proxy()"));
}

#[tokio::test]
async fn scenario_6_macos_dns_txt_dedup_single_source_and_payment_route_selection() {
    zastava_lib::sysproxy::force_os_dry_run();
    let cache = Mutex::new(HashMap::new());
    let sig = nameserver_signature(&["10.8.0.1".parse().unwrap()]);
    let t0 = Instant::now();
    let recorded: usize = [0u64, 15, 60, 120, 240, 299]
        .into_iter()
        .filter(|&secs| {
            should_record_dns_diag_in(
                &cache,
                "scutil",
                "o-o.myaddr.l.google.com",
                &TxtOutcome::Failed,
                &sig,
                t0 + Duration::from_secs(secs),
            )
        })
        .count();
    assert_eq!(
        recorded, 1,
        "repeated DNS TXT failure must record <= 1 per 300s"
    );

    let exit_ip = "185.10.20.30";
    let mut dns = FakeDns::new(LookupOutcome::NotFound)
        .with("whoami.akamai.net", addr(exit_ip))
        .with_txt("o-o.myaddr.l.google.com", TxtOutcome::Timeout)
        .with_ptr(exit_ip.parse().unwrap(), "de.example");
    for z in DangerousAsns::load_bundled().unwrap().dnsbl_zones {
        dns = dns
            .with(&format!("2.0.0.127.{}", z.zone), addr("127.0.0.2"))
            .with(&format!("30.20.10.185.{}", z.zone), LookupOutcome::NotFound);
    }
    let probe = FakeProbe::new(HttpProbeOutcome::Response {
        status: 200,
        body: r#"{"success":true,"ip":"185.10.20.30","country_code":"DE","connection":{"asn":24940,"org":"Hetzner","isp":"Hetzner","domain":"hetzner.com"},"timezone":{"id":"Europe/Berlin"}}"#.into(),
    })
    .with_route("torbulkexitlist", HttpProbeOutcome::Response { status: 200, body: "198.51.100.1\n".into() })
    .with_route("1.1.1.1/cdn-cgi/trace", HttpProbeOutcome::Response { status: 200, body: "fl=1\nip=185.10.20.30\nloc=DE\ncolo=FRA\n".into() });
    let ip4: Ipv4Addr = exit_ip.parse().unwrap();
    let udp = FakeUdp::new()
        .with_server(stun::SERVERS[0].addr, stun::testing::echoing(ip4))
        .with_server(stun::SERVERS[1].addr, stun::testing::echoing(ip4));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(dns),
        probe: Arc::new(probe),
        udp: Arc::new(udp),
        system: Arc::new(FakeSystem {
            timezone: Ok("Europe/Berlin".into()),
            local_offset: Some(3600),
            ..FakeSystem::healthy()
        }),
    })
    .unwrap();
    let report = auditor
        .evaluate_all(ProviderId::Anthropic, &AppState::new_in_memory(), false)
        .await
        .unwrap();
    assert_eq!(
        report
            .checks
            .iter()
            .filter(|c| c.code == "DNS_WHOAMI_SINGLE_SOURCE")
            .count(),
        1
    );
    assert!(report.checks[10].is_not_applicable());
    assert_eq!(report.checks[10].code, "DNS_COUNTRY_UNMEASURED");
    assert!(
        report.unknown_count <= 1,
        "unknown_count={}",
        report.unknown_count
    );

    let Some((direct_addr, direct_hits)) = spawn_echo_upstream().await else {
        return;
    };
    let route_entry = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route_port = route_entry.local_addr().unwrap().port();
    let route_hits = Arc::new(AtomicUsize::new(0));
    let route_hits_clone = Arc::clone(&route_hits);
    tokio::spawn(async move {
        if let Ok((mut s, _)) = route_entry.accept().await {
            route_hits_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await;
        }
    });
    let state = AppState::new_in_memory();
    let entry = Entry {
        proto: EntryProto::Http,
        host: "127.0.0.1".into(),
        port: route_port,
        username: None,
        password: None,
        sni: None,
    };
    let route = Route {
        id: "gemini-key".into(),
        label: "Gemini Route".into(),
        country: Some("NL".into()),
        exit_ip: None,
        expires_at: None,
        sub_url: None,
        grace_extended: false,
        entries: vec![entry],
        raw_key: format!("http://127.0.0.1:{route_port}"),
        enabled: true,
        added_at: 0,
    };
    state.upsert_route(route).await.unwrap();
    state
        .bind_provider_route("gemini", Some("gemini-key"))
        .await
        .unwrap();
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor,
            state,
            Arc::new(HoldQueue::new()),
            Some(direct_addr),
        )
        .await
        .unwrap(),
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });
    let (_s, pay_resp) = send_connect(server.bound_addr, "api.stripe.com").await;
    assert!(
        pay_resp.contains("200 Connection Established"),
        "{pay_resp}"
    );
    assert_eq!(route_hits.load(Ordering::SeqCst), 1);
    assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
}
