use super::*;

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

#[tokio::test]
async fn e2e_pre_pause_tray_has_no_yellow_flash_on_ready_alert() {
    zastava_lib::sysproxy::force_os_dry_run();
    let fp = Arc::new(std::sync::Mutex::new("fp-de".to_string()));
    let probe_ip = Arc::new(std::sync::Mutex::new("1.1.1.1".to_string()));
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
    let observer = Arc::new(GuardTestObserver::default());
    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard.set_route_fingerprint_fn_for_test(Some(Arc::new({
        let fp = Arc::clone(&fp);
        move |_| fp.lock().unwrap().clone()
    })));
    guard.start_with_test_env_observed(
        auditor.clone(),
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
        Arc::clone(&observer),
    );
    guard.seed_baseline_for_test("1.1.1.1", "DE", None).await;
    guard.sync_gates_with_state(&state).await;
    observer.tray_guard_statuses.lock().unwrap().clear();
    observer.tray_reports.lock().unwrap().clear();

    // Switch to sanctioned RU IP under AskPopup: must emit ONE Yellow (Checking),
    // then transition atomically to Red (СТОП СЕТИ) with ZERO duplicate Yellow or post-ready Yellow flash.
    *probe_ip.lock().unwrap() = "5.5.5.5".to_string();
    *exit.lock().unwrap() = Some(("5.5.5.5".to_string(), "RU".to_string(), 9009));
    *fp.lock().unwrap() = "fp-ru".to_string();
    auditor.resolver.invalidate_direct_cache().await;
    guard.tick_test().await;

    for _ in 0..80 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.phase == "ready")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert_eq!(
        hold_queue
            .current_alert()
            .as_ref()
            .map(|a| a.phase.as_str()),
        Some("ready")
    );

    let statuses = observer.tray_guard_statuses.lock().unwrap().clone();
    assert!(!statuses.is_empty(), "expected guard tray status emissions");
    let checking_count = statuses
        .iter()
        .filter(|s| s.gate == "pending" && !s.has_active_risk_alert && !s.paused)
        .count();
    assert_eq!(
        checking_count, 1,
        "expected exactly ONE Checking (Yellow) emission before ready alert, got: {statuses:?}"
    );
    let last = statuses.last().unwrap();
    assert!(
        last.has_active_risk_alert,
        "final guard status after PHASE_READY must have has_active_risk_alert=true (Red), got: {last:?}"
    );
}

#[tokio::test]
async fn e2e_paused_returns_to_pinned_ip_auto_recovers_without_manual_check() {
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

    let state = AppState::new_in_memory();
    for p in KNOWN_PROVIDERS {
        state
            .set_pinned_ip_for(p, Some("145.241.193.245".to_string()))
            .await
            .unwrap();
        state.block_provider(p).await.unwrap();
    }

    let hold_queue = Arc::new(HoldQueue::new());
    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard.set_route_fingerprint_fn_for_test(Some(Arc::new({
        let fp = Arc::clone(&fp);
        move |_| fp.lock().unwrap().clone()
    })));
    guard.start_with_test_env(
        auditor.clone(),
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
        .seed_baseline_for_test("145.241.193.245", "GB", None)
        .await;
    // Simulate PauseMode::UntilNetworkChange where paused_ip already equals the pinned IP
    // (e.g. user clicked Pause right as VPN reconnected to pinned IP).
    guard
        .mark_paused_until_network_change(Some("Пауза".to_string()))
        .await;
    guard.sync_gates_with_state(&state).await;
    assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);

    // Live exit IP is the pinned GB IP: regular probe tick must auto-recover without manual audit!
    *probe_ip.lock().unwrap() = "145.241.193.245".to_string();
    *exit.lock().unwrap() = Some(("145.241.193.245".to_string(), "GB".to_string(), 24940));
    *fp.lock().unwrap() = "fp-gb".to_string();
    auditor.resolver.invalidate_direct_cache().await;
    guard.tick_test().await;

    for _ in 0..80 {
        if guard.pause_mode() == PauseMode::None && guard.gate() == Gate::Open {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert_eq!(guard.pause_mode(), PauseMode::None);
    assert_eq!(guard.gate(), Gate::Open);
    assert!(state.get_data().await.blocked_providers.is_empty());
}

#[tokio::test]
async fn e2e_paused_watcher_silent_recovery_on_pinned_ip_without_ui_storm() {
    zastava_lib::sysproxy::force_os_dry_run();
    use zastava_lib::auditor::seams::TxtOutcome;
    use zastava_lib::auditor::seams::fakes::addr;
    let exit = Arc::new(std::sync::Mutex::new(Some((
        "5.5.5.5".to_string(),
        "RU".to_string(),
        9009u32,
    ))));
    let dns = FakeDns::new(LookupOutcome::NotFound)
        .with("2.0.0.127.zen.spamhaus.org", addr("127.0.0.2"))
        .with("2.0.0.127.dnsbl.dronebl.org", addr("127.0.0.2"))
        .with("2.0.0.127.b.barracudacentral.org", addr("127.0.0.2"))
        .with("whoami.akamai.net", addr("145.241.193.245"))
        .with_txt(
            "o-o.myaddr.l.google.com",
            TxtOutcome::Records(vec!["145.241.193.245".to_string()]),
        );
    let stun_ip = std::net::Ipv4Addr::new(145, 241, 193, 245);
    let udp = FakeUdp::new().with_server("stun.cloudflare.com:3478", move |req| {
        if req.len() < 20 {
            return vec![];
        }
        let mut tx = [0u8; 12];
        tx.copy_from_slice(&req[8..20]);
        let magic: u32 = 0x2112_A442;
        let mut pkt = Vec::with_capacity(32);
        pkt.extend_from_slice(&0x0101u16.to_be_bytes());
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&magic.to_be_bytes());
        pkt.extend_from_slice(&tx);
        pkt.extend_from_slice(&0x0020u16.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.extend_from_slice(&(51820u16 ^ 0x2112).to_be_bytes());
        pkt.extend_from_slice(&(u32::from(stun_ip) ^ magic).to_be_bytes());
        vec![pkt]
    });
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(dns),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(udp),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let state = AppState::new_in_memory();
    for p in KNOWN_PROVIDERS {
        state
            .set_pinned_ip_for(p, Some("145.241.193.245".to_string()))
            .await
            .unwrap();
        state.block_provider(p).await.unwrap();
    }
    let guard = Arc::new(zastava_lib::proxy::NetworkGuard::new());
    guard
        .mark_paused_until_network_change(Some("Пауза".to_string()))
        .await;
    guard.sync_gates_with_state(&state).await;

    // Step 1: Still on risky RU IP -> silent watcher recovery returns None (zero UI events, stays paused).
    let res_risky = zastava_lib::try_silent_paused_recovery(
        &auditor,
        &state,
        &guard,
        zastava_lib::auditor::AuditProtectionFlags::default(),
    )
    .await;
    assert!(res_risky.is_none());
    assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);
    assert_eq!(
        state.get_data().await.blocked_providers.len(),
        KNOWN_PROVIDERS.len()
    );

    // Step 2: Exit IP switches back to pinned GB IP -> silent watcher recovery unblocks and clears pause!
    *exit.lock().unwrap() = Some(("145.241.193.245".to_string(), "GB".to_string(), 24940));
    auditor.resolver.invalidate_direct_cache().await;
    let res_pinned = zastava_lib::try_silent_paused_recovery(
        &auditor,
        &state,
        &guard,
        zastava_lib::auditor::AuditProtectionFlags::default(),
    )
    .await;
    assert!(res_pinned.is_some());
    assert_eq!(guard.pause_mode(), PauseMode::None);
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert_eq!(guard.gate(), Gate::Open);
}
