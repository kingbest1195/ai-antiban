//! End-to-End tests for Core Monolith v3.2.0 fixes:
//! 1) 5 rapid fingerprint flaps during VPN switch -> 1 Checking, 1 final decision, 0 tray oscillations.
//! 2) Pause until network change during `detecting` + concurrent CONNECT + audit/tray refresh -> stays " Пауза".
//! 3) Returning to `pinned_ip` after automatic "СТОП СЕТИ" with failed CONNECT + utun flaps -> all pinned unlock.
//! 4) Multi-provider isolation (`anthropic` + `gemini`): manual allow/verify of one never blocks/resets the other.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::geo_matrix::ProviderId;
use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{HttpProbeOutcome, IpProbe, LookupOutcome};
use zastava_lib::auditor::{AuditEnv, Auditor};
use zastava_lib::proxy::guard::{GuardTestObserver, PauseMode};
use zastava_lib::proxy::hold_queue::{HoldQueue, HoldResolution};
use zastava_lib::proxy::{Gate, ProxyServer};
use zastava_lib::state::{AppState, KNOWN_PROVIDERS};
use zastava_lib::tray::resolve_tray_transition_for_test;

struct DynamicExitProbe(Arc<std::sync::Mutex<Option<(String, String, u32)>>>);

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
                if cc.is_empty() {
                    return HttpProbeOutcome::Timeout;
                }
                format!(
                    r#"{{"success":true,"ip":"{ip}","country_code":"{cc}","connection":{{"asn":{asn},"org":"MyPersonalVPS","isp":"MyPersonalVPS","domain":"vps.example"}},"timezone":{{"id":"Europe/Berlin"}}}}"#
                )
            } else {
                let loc = if cc.is_empty() { "XX" } else { &cc };
                format!("fl=1\nip={ip}\nloc={loc}\ncolo=FRA\n")
            };
            HttpProbeOutcome::Response { status: 200, body }
        })
    }
}

async fn spawn_echo_upstream() -> Option<(std::net::SocketAddr, Arc<AtomicU64>)> {
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
                let mut buf = [0u8; 512];
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

async fn send_connect(addr: std::net::SocketAddr, host: &str) -> (TcpStream, String) {
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

async fn assert_connect_ok_echo(addr: std::net::SocketAddr, host: &str) {
    let (mut s, resp) = send_connect(addr, host).await;
    assert!(
        resp.contains("200 Connection Established"),
        "expected 200 for {host}, got: {resp}"
    );
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn e2e_five_rapid_fingerprint_flaps_single_checking_single_decision_zero_tray_oscillation() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, _upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "1.1.1.1".to_string(),
        "DE".to_string(),
        24940u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
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

    let fp = Arc::new(std::sync::Mutex::new("fp-base".to_string()));
    let fp_reader = Arc::clone(&fp);
    server
        .guard
        .set_route_fingerprint_fn_for_test(Some(Arc::new(move |_| {
            fp_reader.lock().unwrap().clone()
        })));

    let probe_calls = Arc::new(AtomicUsize::new(0));
    let probe_calls_cb = Arc::clone(&probe_calls);
    let exit_probe = Arc::clone(&exit);
    let observer = Arc::new(GuardTestObserver::default());
    server.guard.start_with_test_env_observed(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(move || {
            probe_calls_cb.fetch_add(1, Ordering::SeqCst);
            let snap = exit_probe.lock().unwrap().as_ref().map(|x| x.0.clone());
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(120)).await;
                snap
            })
        })),
        None,
        Arc::clone(&observer),
    );
    server
        .guard
        .seed_baseline_for_test("1.1.1.1", "DE", None)
        .await;
    server.guard.ensure_fresh().await;

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // Trigger VPN switch to RU with 5 rapid consecutive fingerprint flaps (`fp-1` .. `fp-5`).
    *exit.lock().unwrap() = Some(("5.5.5.5".to_string(), "RU".to_string(), 9009));
    auditor.resolver.invalidate_direct_cache().await;

    *fp.lock().unwrap() = "fp-1".to_string();
    server.guard.tick_test().await;

    // Wait: tick_test waits for probe settle, so drive flaps 2..5 concurrently with first `ensure_fresh`!
    // Reset baseline back cleanly? No — test burst flaps right from `ensure_fresh`:
    // Re-seed clean state and drive 5 flaps via `ensure_fresh` + `check_route_fingerprint_sync` while in-flight!
    for _ in 0..50 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.phase == "ready")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let alert1 = hold_queue.current_alert().expect("alert ready");
    assert!(hold_queue.resolve(&alert1.id, HoldResolution::Allow).await);
    for _ in 0..40 {
        if server.guard.gate() == Gate::Open {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Clear observer for the 5-flap burst measurement on switching back to DE -> new RU.
    observer.events.lock().unwrap().clear();
    observer.shows.store(0, Ordering::SeqCst);
    observer.tray_statuses.lock().unwrap().clear();
    observer.tray_guard_statuses.lock().unwrap().clear();
    observer.tray_reports.lock().unwrap().clear();

    *exit.lock().unwrap() = Some(("9.9.9.9".to_string(), "RU".to_string(), 9009));
    auditor.resolver.invalidate_direct_cache().await;

    // Flap 1 starts the single `ProbeChanged` transition immediately.
    *fp.lock().unwrap() = "fp-flap-1".to_string();
    server.guard.ensure_fresh().await;
    assert_eq!(server.guard.gate(), Gate::Pending);

    // Flaps 2..5 arrive rapidly while Pending + probe_in_flight (via both guard ticks and CONNECT).
    for i in 2..=5 {
        tokio::time::sleep(Duration::from_millis(45)).await;
        *fp.lock().unwrap() = format!("fp-flap-{i}");
        let _ = server.guard.check_route_fingerprint_sync(None);
        server.guard.ensure_fresh().await;
    }

    // Wait for settling + single audit completion.
    for _ in 0..160 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.phase == "ready")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    let alert_burst = hold_queue
        .current_alert()
        .expect("single ready alert after 5 flaps");
    assert_eq!(
        alert_burst
            .network_change
            .as_ref()
            .and_then(|n| n.new_ip.as_deref()),
        Some("9.9.9.9")
    );

    // Resolve once (deny -> Pause).
    assert!(
        hold_queue
            .resolve(&alert_burst.id, HoldResolution::Block)
            .await
    );
    for _ in 0..60 {
        if server.guard.pause_mode() == PauseMode::UntilNetworkChange
            && server.guard.gate() == Gate::Blocked
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Verify 0 raw `tray_status` overrides, 1 popup show, 1 `risk-detected`, 1 `enriched`, 0 oscillations!
    assert!(
        observer.tray_statuses.lock().unwrap().is_empty(),
        "guard must never emit raw tray_status during flaps: {:?}",
        observer.tray_statuses.lock().unwrap()
    );
    assert_eq!(observer.shows.load(Ordering::SeqCst), 1);
    let events = observer.events.lock().unwrap().clone();
    let detected_count = events
        .iter()
        .filter(|(e, _)| e == "interceptor://risk-detected")
        .count();
    let enriched_count = events
        .iter()
        .filter(|(e, _)| e == "interceptor://enriched")
        .count();
    assert_eq!(detected_count, 1, "expected exactly 1 risk-detected popup");
    assert_eq!(enriched_count, 1, "expected exactly 1 enriched decision");

    // Reconstruct every tray view emitted during the burst and assert monotonic Checking -> Paused (0 flips).
    let guard_trays = observer.tray_guard_statuses.lock().unwrap().clone();
    let mut titles: Vec<String> = Vec::new();
    for st in &guard_trays {
        let (_, title) = resolve_tray_transition_for_test(st, false, true, None, false);
        if titles.last() != Some(&title) {
            titles.push(title);
        }
    }
    assert_eq!(
        titles,
        vec![
            " Проверяем…".to_string(),
            " СТОП СЕТИ".to_string(),
            " Пауза".to_string()
        ],
        "tray must transition Checking -> СТОП СЕТИ -> Пауза with zero oscillations: {titles:?}"
    );
}

#[tokio::test]
async fn e2e_pause_during_detecting_with_concurrent_connect_and_tray_refresh_stays_paused() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "1.1.1.1".to_string(),
        "NL".to_string(),
        13335u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
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

    let fp = Arc::new(std::sync::Mutex::new("fp-nl".to_string()));
    let fp_reader = Arc::clone(&fp);
    server
        .guard
        .set_route_fingerprint_fn_for_test(Some(Arc::new(move |_| {
            fp_reader.lock().unwrap().clone()
        })));

    let observer = Arc::new(GuardTestObserver::default());
    let exit_probe = Arc::clone(&exit);
    server.guard.start_with_test_env_observed(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(move || {
            let snap = exit_probe.lock().unwrap().as_ref().map(|x| x.0.clone());
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(180)).await;
                snap
            })
        })),
        None,
        Arc::clone(&observer),
    );
    server
        .guard
        .seed_baseline_for_test("1.1.1.1", "NL", None)
        .await;
    server.guard.ensure_fresh().await;

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // 1. Trigger detecting phase via route change while probe takes 180ms.
    *exit.lock().unwrap() = Some(("9.9.9.9".to_string(), "RU".to_string(), 9009));
    *fp.lock().unwrap() = "fp-switch-1".to_string();
    server.guard.ensure_fresh().await;
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);

    // 2. User immediately presses "Пауза до смены сети" while still `detecting` (`pending_pause_ip_bind == true`).
    let pause_st = server
        .guard
        .pause_until_network_change(&state, Some("Пауза до смены сети".to_string()))
        .await;
    assert_eq!(pause_st.mode, PauseMode::UntilNetworkChange);

    // 3. Settling route flap + parallel CONNECTs arrive right after pause (`settling_pause` path!).
    *fp.lock().unwrap() = "fp-switch-2-settling".to_string();
    assert!(
        !server.guard.check_route_fingerprint_sync(None),
        "settling_pause must return false so connect.rs does not clear pause"
    );
    let (_s1, resp1) = send_connect(server.bound_addr, "claude.ai").await;
    let (_s2, resp2) = send_connect(server.bound_addr, "api.openai.com").await;
    assert!(resp1.contains("403"), "expected 403 while paused: {resp1}");
    assert!(resp2.contains("403"), "expected 403 while paused: {resp2}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    assert_eq!(server.guard.pause_mode(), PauseMode::UntilNetworkChange);

    // 4. Simulate `spawn_refresh_tray` + `audit_connection` tray sync with a Green/Red report -> MUST stay " Пауза"!
    let green_rep = auditor
        .evaluate_all(ProviderId::Anthropic, &state, false)
        .await
        .unwrap();
    server.guard.trigger_refresh_tray_for_test();
    server
        .guard
        .refresh_tray_with_report_for_test(&green_rep)
        .await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(server.guard.pause_mode(), PauseMode::UntilNetworkChange);
    assert!(server.guard.pause_status().paused);
    assert!(hold_queue.current_alert().is_none());
    let (color, title) = resolve_tray_transition_for_test(
        &server.guard.pause_status(),
        !state.get_data().await.blocked_providers.is_empty(),
        true,
        Some(&green_rep),
        true,
    );
    assert_eq!(color, "gray");
    assert_eq!(title, " Пауза");
    assert!(
        observer.tray_reports.lock().unwrap().is_empty(),
        "refresh_tray must never overwrite PauseMode::UntilNetworkChange with tray_report"
    );
}

#[tokio::test]
async fn e2e_return_to_pinned_ip_with_failed_connects_and_utun_flaps_auto_unlocks_all_pinned() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "1.1.1.1".to_string(),
        "DE".to_string(),
        24940u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let state = AppState::new_in_memory();
    state
        .set_pinned_ip(Some("1.1.1.1".to_string()))
        .await
        .unwrap();
    state
        .set_interception_behavior(zastava_lib::state::InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();

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
    let fp = Arc::new(std::sync::Mutex::new("fp-pinned".to_string()));
    let fp_reader = Arc::clone(&fp);
    server
        .guard
        .set_route_fingerprint_fn_for_test(Some(Arc::new(move |_| {
            fp_reader.lock().unwrap().clone()
        })));

    let exit_probe = Arc::clone(&exit);
    server.guard.start_with_test_env(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(move || {
            let snap = exit_probe.lock().unwrap().as_ref().map(|x| x.0.clone());
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(60)).await;
                snap
            })
        })),
        None,
    );
    server
        .guard
        .seed_baseline_for_test("1.1.1.1", "DE", None)
        .await;
    server.guard.ensure_fresh().await;

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // 1. Drop to RU -> automatic "СТОП СЕТИ" blocks all 3 pinned providers.
    *exit.lock().unwrap() = Some(("5.5.5.5".to_string(), "RU".to_string(), 9009));
    *fp.lock().unwrap() = "fp-ru".to_string();
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;
    for _ in 0..80 {
        if server.guard.pause_mode() == PauseMode::UntilNetworkChange
            && KNOWN_PROVIDERS.iter().all(|p| {
                ProviderId::from_id(p)
                    .is_some_and(|pid| server.guard.gate_for(pid) == Gate::Blocked)
            })
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert_eq!(server.guard.pause_mode(), PauseMode::UntilNetworkChange);

    // 2. Return to `pinned_ip` ("1.1.1.1") with utun flaps + parallel failed CONNECT / wake_immediate_probe storms!
    *exit.lock().unwrap() = Some(("1.1.1.1".to_string(), "DE".to_string(), 24940));
    *fp.lock().unwrap() = "fp-utun-1".to_string();
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.ensure_fresh().await;

    // Simulate concurrent utun flaps & failed CONNECT wake calls during recovery.
    for i in 2..=3 {
        tokio::time::sleep(Duration::from_millis(30)).await;
        *fp.lock().unwrap() = format!("fp-utun-{i}");
        let _ = server.guard.check_route_fingerprint_sync(None);
        server.guard.wake_immediate_probe().await;
    }
    server.guard.wait_probe_settled_for_test().await;
    for _ in 0..100 {
        if server.guard.pause_mode() == PauseMode::None
            && state.get_data().await.blocked_providers.is_empty()
            && !server.guard.any_provider_gate_closed()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(server.guard.pause_mode(), PauseMode::None);
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert!(!server.guard.any_provider_gate_closed());

    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
    assert_connect_ok_echo(server.bound_addr, "api.openai.com").await;
    assert_connect_ok_echo(server.bound_addr, "generativelanguage.googleapis.com").await;
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn e2e_multi_provider_isolation_manual_allow_anthropic_then_gemini_without_collateral_block()
{
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "5.5.5.5".to_string(),
        "RU".to_string(),
        9009u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let state = AppState::new_in_memory();
    state
        .set_provider_monitoring("openai", false)
        .await
        .unwrap();
    state.block_provider("anthropic").await.unwrap();
    state.block_provider("gemini").await.unwrap();

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
    let exit_probe = Arc::clone(&exit);
    server.guard.start_with_test_env(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(move || {
            let snap = exit_probe.lock().unwrap().as_ref().map(|x| x.0.clone());
            Box::pin(async move { snap })
        })),
        None,
    );
    server
        .guard
        .seed_baseline_for_test("5.5.5.5", "RU", None)
        .await;
    server
        .guard
        .mark_paused_until_network_change(Some("Оба заблокированы".to_string()))
        .await;
    server.guard.sync_gates_with_state(&state).await;

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert_eq!(server.guard.gate_for(ProviderId::Gemini), Gate::Blocked);

    // 1. Manually allow `anthropic` for session while `gemini` remains Blocked.
    let tel_ru = NetworkTelemetry {
        ip: "5.5.5.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(9009),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    state.allow_provider_for_session("anthropic").await.unwrap();
    state.unblock_provider("anthropic").await.unwrap();
    server
        .guard
        .confirm_provider_session("anthropic", Some(&tel_ru))
        .await;

    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_eq!(server.guard.gate_for(ProviderId::Gemini), Gate::Blocked);
    assert!(
        server
            .guard
            .can_use_session_allowance(ProviderId::Anthropic)
            .await
    );
    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let (_sg, resp_gem) =
        send_connect(server.bound_addr, "generativelanguage.googleapis.com").await;
    assert!(
        resp_gem.contains("403"),
        "gemini must stay 403 Blocked: {resp_gem}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Even if `ensure_open_for_verified` runs for `anthropic` while `gemini` is still blocked,
    // no global force_reaudit fires and `gemini` remains Blocked while `anthropic` stays Open.
    server.guard.ensure_open_for_verified(&tel_ru).await;
    server.guard.tick_test().await;
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_eq!(server.guard.gate_for(ProviderId::Gemini), Gate::Blocked);

    // 2. Now manually allow `gemini` as well -> BOTH stay Open and pass CONNECT cleanly.
    state.allow_provider_for_session("gemini").await.unwrap();
    state.unblock_provider("gemini").await.unwrap();
    server
        .guard
        .confirm_provider_session("gemini", Some(&tel_ru))
        .await;

    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_eq!(server.guard.gate_for(ProviderId::Gemini), Gate::Open);
    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
    assert_connect_ok_echo(server.bound_addr, "generativelanguage.googleapis.com").await;
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 3);

    // Subsequent guard ticks on the same IP must respect session allowances and keep both Open.
    let re_tick_ok = AtomicBool::new(true);
    let _ = &re_tick_ok;
    server.guard.tick_test().await;
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_eq!(server.guard.gate_for(ProviderId::Gemini), Gate::Open);
    assert!(state.get_data().await.blocked_providers.is_empty());
}

mod video_regressions;
