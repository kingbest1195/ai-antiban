use super::*;

#[tokio::test]
async fn e2e_video_1_disconnect_reconnect_pinned_auto_unlocks_claude() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, _upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "145.241.193.245".to_string(),
        "GB".to_string(),
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
        .set_pinned_ip_for("anthropic", Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    state.set_strict_pinning_enabled(true).await.unwrap();
    state
        .add_trusted_exception("openai", "95.165.1.10")
        .await
        .unwrap();
    state
        .add_trusted_exception("gemini", "95.165.1.10")
        .await
        .unwrap();
    state
        .add_trusted_exception("openai", "145.241.193.245")
        .await
        .unwrap();
    state
        .add_trusted_exception("gemini", "145.241.193.245")
        .await
        .unwrap();
    state
        .set_interception_behavior(zastava_lib::state::InterceptionBehavior::AskPopup)
        .await
        .unwrap();

    let hold_queue = Arc::new(HoldQueue::new());
    let exit_probe = Arc::clone(&exit);
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
        .seed_baseline_for_test("145.241.193.245", "GB", None)
        .await;
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // 1. Disconnect onto RU: `anthropic` is blocked, while `openai`+`gemini` stay open by exception.
    *exit.lock().unwrap() = Some(("95.165.1.10".to_string(), "RU".to_string(), 12389));
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;
    for _ in 0..50 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.phase == zastava_lib::proxy::hold_queue::PHASE_READY)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if let Some(alert) = hold_queue.current_alert() {
        hold_queue.resolve(&alert.id, HoldResolution::Block).await;
    }
    for _ in 0..50 {
        if server.guard.gate_for(ProviderId::Anthropic) == Gate::Blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);

    // 2. Reconnect onto pinned GB (`145.241.193.245`): fresh Green audit auto-unblocks `anthropic`
    // without manual "Снять блок" via `try_auto_unblock_pinned_providers`.
    *exit.lock().unwrap() = Some(("145.241.193.245".to_string(), "GB".to_string(), 24940));
    auditor.resolver.invalidate_direct_cache().await;
    let mut green_gb_report = auditor
        .evaluate_all(ProviderId::Anthropic, &state, true)
        .await
        .expect("fresh GB audit");
    assert_eq!(
        green_gb_report.overall_status,
        zastava_lib::auditor::OverallStatus::Green
    );
    // Incomplete report must NOT auto-unblock; complete (12/12) Green pinned report MUST auto-unblock.
    green_gb_report.incomplete = false;
    green_gb_report.unknown_count = 0;
    let unblocked = zastava_lib::proxy::try_auto_unblock_pinned_providers(
        &state,
        &server.guard,
        std::slice::from_ref(&green_gb_report),
    )
    .await;
    assert!(
        unblocked,
        "pinned GB Green audit must auto-unblock anthropic"
    );
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
}

#[tokio::test]
async fn e2e_video_2_switch_to_se_strict_pinning_tray_never_shows_yellow_attention() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, _upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "145.241.193.245".to_string(),
        "GB".to_string(),
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
        .set_pinned_ip_for("anthropic", Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    state.set_strict_pinning_enabled(true).await.unwrap();
    state
        .add_trusted_exception("openai", "185.200.1.50")
        .await
        .unwrap();
    state
        .add_trusted_exception("gemini", "185.200.1.50")
        .await
        .unwrap();
    state
        .set_interception_behavior(zastava_lib::state::InterceptionBehavior::AskPopup)
        .await
        .unwrap();

    let hold_queue = Arc::new(HoldQueue::new());
    let exit_probe = Arc::clone(&exit);
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
        .seed_baseline_for_test("145.241.193.245", "GB", None)
        .await;
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // Switch to SE (`185.200.1.50`): `anthropic` triggers strict pinning mismatch & risk alert,
    // while `openai` + `gemini` are open by trusted exception.
    *exit.lock().unwrap() = Some(("185.200.1.50".to_string(), "SE".to_string(), 24940));
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;
    for _ in 0..50 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.phase == zastava_lib::proxy::hold_queue::PHASE_READY)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let alert = hold_queue
        .current_alert()
        .expect("risk alert for SE strict pinning mismatch must be active");
    assert_eq!(alert.phase, zastava_lib::proxy::hold_queue::PHASE_READY);
    let status = server.guard.pause_status();
    assert!(
        status.has_active_risk_alert,
        "GuardPauseStatus must report active ready risk alert"
    );

    let se_report = auditor
        .evaluate_all(ProviderId::Openai, &state, true)
        .await
        .expect("SE audit report");
    let (tray_color, tray_title) =
        resolve_tray_transition_for_test(&status, false, true, Some(&se_report), false);
    assert_eq!(
        tray_color, "red",
        "tray must NEVER show yellow 'Внимание · SE' while risk alert is active; got {tray_color} ({tray_title})"
    );
    assert_eq!(tray_title, " СТОП СЕТИ");
    assert_eq!(server.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert_connect_ok_echo(server.bound_addr, "api.openai.com").await;
}

struct SlowFirstExitProbe {
    calls: Arc<AtomicUsize>,
    exit: Arc<std::sync::Mutex<Option<(String, String, u32)>>>,
}

impl IpProbe for SlowFirstExitProbe {
    fn get<'a>(
        &'a self,
        url: &'a str,
        _limit: Duration,
    ) -> zastava_lib::auditor::seams::BoxFuture<'a, HttpProbeOutcome> {
        let call_idx = self.calls.fetch_add(1, Ordering::SeqCst);
        let snap = self.exit.lock().unwrap().clone();
        Box::pin(async move {
            if call_idx < 3 {
                // Simulate slow 5s audit inside `verify_and_restore_baseline`.
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            let Some((ip, cc, asn)) = snap else {
                return HttpProbeOutcome::Timeout;
            };
            let body = if url.contains("ipwho.is") {
                format!(
                    r#"{{"success":true,"ip":"{ip}","country_code":"{cc}","connection":{{"asn":{asn},"org":"MyPersonalVPS","isp":"MyPersonalVPS","domain":"vps.example"}},"timezone":{{"id":"Europe/London"}}}}"#
                )
            } else {
                format!("fl=1\nip={ip}\nloc={cc}\ncolo=LHR\n")
            };
            HttpProbeOutcome::Response { status: 200, body }
        })
    }
}

#[tokio::test]
async fn e2e_video_3_verify_restore_does_not_block_probe_loop_for_25s() {
    zastava_lib::sysproxy::force_os_dry_run();
    let fp = Arc::new(std::sync::Mutex::new("fp-gb".to_string()));
    let ip = Arc::new(std::sync::Mutex::new("145.241.193.245".to_string()));
    let exit = Arc::new(std::sync::Mutex::new(Some((
        "145.241.193.245".to_string(),
        "GB".to_string(),
        24940u32,
    ))));
    let audit_calls = Arc::new(AtomicUsize::new(0));

    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(SlowFirstExitProbe {
            calls: Arc::clone(&audit_calls),
            exit: Arc::clone(&exit),
        }),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();

    let state = AppState::new_in_memory();
    state.block_provider("anthropic").await.unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard.set_route_fingerprint_fn_for_test(Some(Arc::new({
        let fp = Arc::clone(&fp);
        move |_| fp.lock().unwrap().clone()
    })));
    guard.start_with_test_env(
        auditor,
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new({
            let ip = Arc::clone(&ip);
            move || {
                let cur = ip.lock().unwrap().clone();
                Box::pin(async move { Some(cur) })
            }
        })),
        None,
    );
    guard
        .seed_baseline_for_test("145.241.193.245", "GB", None)
        .await;
    // Set `last_route_fp` to match `"fp-gb"` so initial tick runs `ProbeRegular` -> `verify_and_restore_baseline`.
    guard.start_loop_for_test();

    // Wait for slow `verify_and_restore_baseline` to start in the background.
    tokio::time::timeout(Duration::from_secs(2), async {
        while audit_calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("slow verify_and_restore_baseline must start");

    // Now switch VPN config / fingerprint while the 5s verify_and_restore_baseline is still running!
    *ip.lock().unwrap() = "185.100.1.2".to_string();
    *exit.lock().unwrap() = Some(("185.100.1.2".to_string(), "NL".to_string(), 24940));
    *fp.lock().unwrap() = "fp-nl".to_string();

    // Must detect and transition open gates to Pending within < 500ms (NOT blocked for 5s/25s!).
    tokio::time::timeout(Duration::from_millis(500), async {
        while !guard.any_provider_gate_pending() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("probe_loop must detect fp/IP change in < 500ms while verify_and_restore_baseline is running");
}

#[tokio::test]
async fn e2e_video_4_try_auto_unblock_rejects_tor_and_vpn_even_on_green_report() {
    let state = AppState::new_in_memory();
    state
        .set_pinned_ip_for("anthropic", Some("185.220.101.1".to_string()))
        .await
        .unwrap();
    state.block_provider("anthropic").await.unwrap();

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "185.220.101.1".to_string(),
        "NL".to_string(),
        24940u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(exit)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard.start_with_test_env(auditor.clone(), state.clone(), hold_queue, None, None);

    let mut tor_report = auditor
        .evaluate_all(ProviderId::Anthropic, &state, true)
        .await
        .unwrap();
    tor_report.overall_status = zastava_lib::auditor::OverallStatus::Green;
    tor_report.incomplete = false;
    tor_report.asn_result = tor_report
        .asn_result
        .with_ip_type(zastava_lib::auditor::IpType::Tor);

    assert!(
        !zastava_lib::proxy::try_auto_unblock_pinned_providers(&state, &guard, &[tor_report]).await,
        "Tor exit must never be auto-unblocked even if overall_status is Green"
    );
    assert!(
        state
            .get_data()
            .await
            .blocked_providers
            .contains("anthropic")
    );

    let mut vpn_report = auditor
        .evaluate_all(ProviderId::Anthropic, &state, true)
        .await
        .unwrap();
    vpn_report.overall_status = zastava_lib::auditor::OverallStatus::Green;
    vpn_report.incomplete = false;
    vpn_report.asn_result = vpn_report
        .asn_result
        .with_ip_type(zastava_lib::auditor::IpType::Vpn);

    assert!(
        !zastava_lib::proxy::try_auto_unblock_pinned_providers(&state, &guard, &[vpn_report]).await,
        "Mass VPN exit must never be auto-unblocked even if overall_status is Green"
    );
    assert!(
        state
            .get_data()
            .await
            .blocked_providers
            .contains("anthropic")
    );
}

#[tokio::test]
async fn e2e_video1942_dual_stack_ipv4_ipv6_pause_never_spams_popup() {
    zastava_lib::sysproxy::force_os_dry_run();
    let fp = Arc::new(std::sync::Mutex::new("fp-home".to_string()));
    let probe_ip = Arc::new(std::sync::Mutex::new("5.228.44.64".to_string()));
    // Simulate dual-stack ISP where geo telemetry returns IPv6 while probe_ip is IPv4.
    let exit = Arc::new(std::sync::Mutex::new(Some((
        "2a02:4540:1234::1".to_string(),
        "RU".to_string(),
        12345u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();

    let state = AppState::new_in_memory();
    state.block_provider("anthropic").await.unwrap();
    state.block_provider("openai").await.unwrap();
    state.block_provider("gemini").await.unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard.set_route_fingerprint_fn_for_test(Some(Arc::new({
        let fp = Arc::clone(&fp);
        move |_| fp.lock().unwrap().clone()
    })));
    guard.start_with_test_env(
        auditor,
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new({
            let ip = Arc::clone(&probe_ip);
            move || {
                let cur = ip.lock().unwrap().clone();
                Box::pin(async move { Some(cur) })
            }
        })),
        None,
    );
    guard
        .seed_baseline_for_test("5.228.44.64", "RU", None)
        .await;
    guard
        .mark_paused_until_network_change(Some("Санкционный регион".to_string()))
        .await;

    for _ in 0..3 {
        guard.tick_test().await;
        assert_eq!(guard.pause_status().mode, PauseMode::UntilNetworkChange);
        assert!(
            hold_queue.current_alert().is_none(),
            "dual-stack IPv4/IPv6 mismatch must never spam a popup while paused"
        );
        assert_eq!(guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    }
}

#[tokio::test]
async fn e2e_video1942_dynamic_ip_rotation_while_paused_silent_then_auto_unlocks_pinned() {
    zastava_lib::sysproxy::force_os_dry_run();
    let fp = Arc::new(std::sync::Mutex::new("fp-home-1".to_string()));
    let probe_ip = Arc::new(std::sync::Mutex::new("5.228.44.64".to_string()));
    let exit = Arc::new(std::sync::Mutex::new(Some((
        "5.228.44.64".to_string(),
        "RU".to_string(),
        12345u32,
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
        .set_pinned_ip_for("anthropic", Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    state
        .set_pinned_ip_for("openai", Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    state
        .set_pinned_ip_for("gemini", Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    state.block_provider("anthropic").await.unwrap();
    state.block_provider("openai").await.unwrap();
    state.block_provider("gemini").await.unwrap();

    let hold_queue = Arc::new(HoldQueue::new());
    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard.set_route_fingerprint_fn_for_test(Some(Arc::new({
        let fp = Arc::clone(&fp);
        move |_| fp.lock().unwrap().clone()
    })));
    guard.start_with_test_env(
        auditor,
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new({
            let ip = Arc::clone(&probe_ip);
            move || {
                let cur = ip.lock().unwrap().clone();
                Box::pin(async move { Some(cur) })
            }
        })),
        None,
    );
    guard
        .seed_baseline_for_test("5.228.44.64", "RU", None)
        .await;
    guard
        .mark_paused_until_network_change(Some("Пауза на домашнем IP".to_string()))
        .await;

    // Dynamic home IP rotates 5.228.44.64 -> 5.228.44.99 (still RU) + fp jitter.
    *probe_ip.lock().unwrap() = "5.228.44.99".to_string();
    *exit.lock().unwrap() = Some(("5.228.44.99".to_string(), "RU".to_string(), 12345));
    *fp.lock().unwrap() = "fp-home-2".to_string();
    guard.tick_test().await;

    assert_eq!(
        guard.pause_status().mode,
        PauseMode::UntilNetworkChange,
        "rotating to another risky IP must keep UntilNetworkChange active"
    );
    assert!(
        hold_queue.current_alert().is_none(),
        "rotating to another risky IP while paused must emit ZERO popups"
    );
    assert_eq!(guard.gate_for(ProviderId::Anthropic), Gate::Blocked);

    // Now switch back to pinned GB 145.241.193.245: must clear pause and auto-unlock.
    *probe_ip.lock().unwrap() = "145.241.193.245".to_string();
    *exit.lock().unwrap() = Some(("145.241.193.245".to_string(), "GB".to_string(), 24940));
    *fp.lock().unwrap() = "fp-gb-vpn".to_string();
    guard.tick_test().await;

    assert_eq!(guard.pause_status().mode, PauseMode::None);
    assert_eq!(guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert!(state.get_data().await.blocked_providers.is_empty());
}

#[tokio::test]
async fn e2e_video1942_single_provider_pause_sets_tray_pause_and_preserves_trusted_siblings() {
    zastava_lib::sysproxy::force_os_dry_run();
    let state = AppState::new_in_memory();
    state
        .add_trusted_exception("openai", "5.228.44.64")
        .await
        .unwrap();
    state.block_provider("anthropic").await.unwrap();
    state.block_provider("gemini").await.unwrap();

    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard
        .mark_paused_until_network_change(Some("Пауза до смены сети".to_string()))
        .await;
    guard.sync_gates_with_state(&state).await;

    let status = guard.pause_status();
    assert_eq!(status.mode, PauseMode::UntilNetworkChange);
    assert_eq!(guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert_eq!(guard.gate_for(ProviderId::Gemini), Gate::Blocked);
    assert_eq!(
        guard.gate_for(ProviderId::Openai),
        Gate::Open,
        "trusted-exception sibling must remain Gate::Open"
    );

    let (icon, title) = resolve_tray_transition_for_test(&status, true, true, None, true);
    assert_eq!(icon, "gray");
    assert_eq!(title.trim(), "Пауза");
}

#[tokio::test]
async fn e2e_video1942_global_sanctioned_pause_blocks_all_risky_prevents_chatgpt_second_popup() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, _)) = spawn_echo_upstream().await else {
        return;
    };
    let exit = Arc::new(std::sync::Mutex::new(Some((
        "5.228.44.64".to_string(),
        "RU".to_string(),
        12345u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();

    let state = AppState::new_in_memory();
    state.block_provider("anthropic").await.unwrap();
    state.block_provider("openai").await.unwrap();
    state.block_provider("gemini").await.unwrap();

    let hold_queue = Arc::new(HoldQueue::new());
    let server = match ProxyServer::bind_ephemeral(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(upstream_addr),
    )
    .await
    {
        Ok(s) => Arc::new(s),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("bind_ephemeral: {e}"),
    };
    let proxy_addr = server.bound_addr;
    server.guard.start_with_test_env(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(|| {
            Box::pin(async { Some("5.228.44.64".to_string()) })
        })),
        None,
    );
    server
        .guard
        .seed_baseline_for_test("5.228.44.64", "RU", None)
        .await;
    server
        .guard
        .mark_paused_until_network_change(Some("Санкционный регион".to_string()))
        .await;
    server.guard.sync_gates_with_state(&state).await;

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let (_s, resp) = send_connect(proxy_addr, "api.openai.com").await;
    assert!(
        resp.contains("403"),
        "paused ChatGPT CONNECT must fail closed with 403, got: {resp}"
    );
    assert!(
        hold_queue.current_alert().is_none(),
        "blocked sibling ChatGPT CONNECT while paused must not create a second popup"
    );
}

#[tokio::test]
async fn e2e_video1942_pinned_fast_path_cache_survives_vpn_switch_and_unlocks_fast() {
    zastava_lib::sysproxy::force_os_dry_run();
    let fp = Arc::new(std::sync::Mutex::new("fp-se".to_string()));
    let probe_ip = Arc::new(std::sync::Mutex::new("56.228.36.74".to_string()));
    let exit = Arc::new(std::sync::Mutex::new(Some((
        "56.228.36.74".to_string(),
        "SE".to_string(),
        24940u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();

    // Seed verified-pinned-IP cache for GB, then invalidate direct cache (simulating SE switch).
    auditor
        .resolver
        .record_verified_pinned_country("145.241.193.245", "GB")
        .await;
    auditor.resolver.invalidate_direct_cache().await;
    assert_eq!(
        auditor
            .resolver
            .cached_verified_pinned_country("145.241.193.245")
            .await
            .as_deref(),
        Some("GB")
    );

    let state = AppState::new_in_memory();
    state
        .set_pinned_ip_for("anthropic", Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    state
        .set_pinned_ip_for("openai", Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    state
        .set_pinned_ip_for("gemini", Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    state.block_provider("anthropic").await.unwrap();

    let hold_queue = Arc::new(HoldQueue::new());
    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard.set_route_fingerprint_fn_for_test(Some(Arc::new({
        let fp = Arc::clone(&fp);
        move |_| fp.lock().unwrap().clone()
    })));
    guard.start_with_test_env(
        auditor,
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new({
            let ip = Arc::clone(&probe_ip);
            move || {
                let cur = ip.lock().unwrap().clone();
                Box::pin(async move { Some(cur) })
            }
        })),
        None,
    );
    guard
        .seed_baseline_for_test("56.228.36.74", "SE", None)
        .await;
    guard.sync_gates_with_state(&state).await;

    // Switch back to pinned GB: Fast-path 2 must unlock immediately via verified-pinned cache.
    *probe_ip.lock().unwrap() = "145.241.193.245".to_string();
    *exit.lock().unwrap() = Some(("145.241.193.245".to_string(), "GB".to_string(), 24940));
    *fp.lock().unwrap() = "fp-gb".to_string();
    guard.tick_test().await;

    assert_eq!(guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert!(hold_queue.current_alert().is_none());
}

#[tokio::test]
async fn e2e_video1942_connect_fp_change_preserves_was_blocked_set() {
    zastava_lib::sysproxy::force_os_dry_run();
    let fp = Arc::new(std::sync::Mutex::new("fp-1".to_string()));
    let state = AppState::new_in_memory();
    state.block_provider("anthropic").await.unwrap();

    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard.set_route_fingerprint_fn_for_test(Some(Arc::new({
        let fp = Arc::clone(&fp);
        move |_| fp.lock().unwrap().clone()
    })));
    guard
        .seed_baseline_for_test("5.228.44.64", "RU", None)
        .await;
    guard
        .mark_paused_until_network_change(Some("Пауза".to_string()))
        .await;
    guard.sync_gates_with_state(&state).await;
    assert_eq!(guard.gate_for(ProviderId::Anthropic), Gate::Blocked);

    // Simulate CONNECT detecting an fp change: must NOT clear blocked_providers or drop Anthropic
    // from Gate::Blocked.
    *fp.lock().unwrap() = "fp-2".to_string();
    let changed = guard.check_route_fingerprint_sync(None);
    assert!(changed);
    assert_eq!(guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert!(
        state
            .get_data()
            .await
            .blocked_providers
            .contains("anthropic"),
        "blocked_providers must be preserved across check_route_fingerprint_sync"
    );
}
