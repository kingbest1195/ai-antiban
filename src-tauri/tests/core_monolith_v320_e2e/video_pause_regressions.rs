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
