use super::super::*;
use super::*;
use crate::auditor::CheckResult;
use crate::state::InterceptionBehavior;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Real-ticker integration test (real wall-clock 250 ms ticker + 1000 ms `PROBE_MIN_GAP_MS`):
/// proves zero 1-second audit-abort starvation under slow (1.6 s) audits and automatic
/// silent recovery back to clean pinned VPN without manual intervention.
#[tokio::test]
async fn test_real_ticker_vpn_drop_no_1s_starvation_and_clean_return_auto_recovers() {
    let current_ip = Arc::new(std::sync::Mutex::new("185.10.10.10".to_string()));
    let probe_ip = Arc::clone(&current_ip);
    let ru_audit_calls = Arc::new(AtomicUsize::new(0));
    let ru_audit_calls2 = Arc::clone(&ru_audit_calls);
    let audit_ip = Arc::clone(&current_ip);
    let audit: AuditFn = Arc::new(move |provider, _force| {
        let ip = audit_ip.lock().unwrap().clone();
        let calls = Arc::clone(&ru_audit_calls2);
        Box::pin(async move {
            if ip == "5.5.5.5" {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1600)).await;
                let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                r.checks = vec![r.geo_result.clone()];
                Ok(r)
            } else {
                tokio::time::sleep(Duration::from_millis(30)).await;
                Ok(test_report(
                    provider,
                    OverallStatus::Green,
                    "185.10.10.10",
                    "DE",
                ))
            }
        })
    });

    let probe: ProbeFn = Arc::new(move || {
        let ip = probe_ip.lock().unwrap().clone();
        Box::pin(async move { Some(ip) })
    });
    let io = Arc::new(TestIo::default());
    let state = AppState::new_in_memory();
    state
        .set_pinned_ip(Some("185.10.10.10".to_string()))
        .await
        .unwrap();
    let tel_vpn =
        test_report(ProviderId::Anthropic, OverallStatus::Green, "185.10.10.10", "DE")
            .telemetry;
    let resolve_ip = Arc::clone(&current_ip);
    let env = Env {
        auditor: Auditor::new().expect("auditor"),
        state: state.clone(),
        hold_queue: Arc::new(HoldQueue::new()),
        io: io.clone(),
        audit,
        probe: Some(probe),
        resolve: Some(Arc::new(move || {
            let ip = resolve_ip.lock().unwrap().clone();
            let mut tel = tel_vpn.clone();
            if ip == "5.5.5.5" {
                tel.ip = "5.5.5.5".to_string();
                tel.country_code = "RU".to_string();
            }
            Box::pin(async move { Ok(tel) })
        })),
        audit_timeout: Duration::from_secs(10),
    };
    let guard = Arc::new(NetworkGuard::new());
    guard.start_with_env(env.clone());

    // 1. Wait for cold-start baseline initialization on pinned clean VPN.
    for _ in 0..80 {
        if guard
            .inner
            .lock()
            .await
            .baseline
            .as_ref()
            .is_some_and(|b| b.ip == "185.10.10.10")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        guard.inner.lock().await.baseline.as_ref().map(|b| b.ip.as_str()),
        Some("185.10.10.10")
    );
    assert_eq!(guard.gate(), Gate::Open);
    assert_eq!(io.count("interceptor://risk-detected"), 0);

    // 2. Sudden VPN drop to RU (`5.5.5.5`) with 1.6 s audit -> real ticker fires probes every
    //    1000 ms (`PROBE_MIN_GAP_MS`); audit must NOT be starved or aborted!
    *current_ip.lock().unwrap() = "5.5.5.5".to_string();
    guard.wake();

    let (detected, detected_at) = io
        .wait_for("interceptor://risk-detected", 1500)
        .await
        .expect("immediate alert_first under real ticker");
    assert_eq!(detected["phase"], PHASE_DETECTING);
    for p in [ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
        assert_eq!(
            guard.gate_for(p),
            Gate::Pending,
            "{p:?} must freeze Pending immediately on sudden IP drop"
        );
    }

    // Sleep past the 1000 ms `PROBE_MIN_GAP_MS` tick while 1.6 s audit is still running.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        ru_audit_calls.load(Ordering::SeqCst),
        3,
        "1s regular probe must NOT abort and restart in-flight audit (only 1 round of 3 providers)"
    );
    assert_eq!(io.count("interceptor://enriched"), 0);
    assert_eq!(guard.gate(), Gate::Pending);

    let (enriched, enriched_at) = io
        .wait_for("interceptor://enriched", 2500)
        .await
        .expect("ready enrichment after 1.6 s slow audit");
    assert_eq!(enriched["phase"], PHASE_READY);
    assert_eq!(enriched["network_change"]["new_country"], "RU");
    assert!(enriched_at.duration_since(detected_at) >= Duration::from_millis(1400));
    assert_eq!(
        ru_audit_calls.load(Ordering::SeqCst),
        3,
        "still only 1 audit round executed"
    );
    assert_eq!(io.shows.load(Ordering::SeqCst), 1);

    let id = enriched["id"].as_str().expect("alert id");
    assert!(env.hold_queue.resolve(id, HoldResolution::Block).await);
    for _ in 0..80 {
        if guard.pause_mode() == PauseMode::UntilNetworkChange
            && KNOWN_PROVIDERS
                .iter()
                .all(|p| ProviderId::from_id(p).is_some_and(|pid| guard.gate_for(pid) == Gate::Blocked))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);
    for p in KNOWN_PROVIDERS {
        assert!(state.is_provider_blocked(p).await, "{p} must be blocked");
        assert_eq!(
            guard.gate_for(ProviderId::from_id(p).unwrap()),
            Gate::Blocked
        );
    }

    // 3. Reconnect back to clean pinned VPN IP (`185.10.10.10`) -> auto-recovers silently!
    let shows_before = io.shows.load(Ordering::SeqCst);
    *current_ip.lock().unwrap() = "185.10.10.10".to_string();
    guard.wake();
    for _ in 0..120 {
        if guard.pause_mode() == PauseMode::None
            && state.get_data().await.blocked_providers.is_empty()
            && !guard.any_provider_gate_closed()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(guard.pause_mode(), PauseMode::None);
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert!(!guard.any_provider_gate_closed());
    for p in [ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
        assert_eq!(guard.gate_for(p), Gate::Open);
    }
    assert_eq!(
        io.shows.load(Ordering::SeqCst),
        shows_before,
        "returning to pinned VPN IP must auto-recover without showing a popup"
    );
}

#[tokio::test]
async fn test_real_ticker_auto_lock_silent_no_1s_starvation_and_recovery() {
    let current_ip = Arc::new(std::sync::Mutex::new("185.10.10.10".to_string()));
    let probe_ip = Arc::clone(&current_ip);
    let ru_audit_calls = Arc::new(AtomicUsize::new(0));
    let ru_audit_calls2 = Arc::clone(&ru_audit_calls);
    let audit_ip = Arc::clone(&current_ip);
    let audit: AuditFn = Arc::new(move |provider, _force| {
        let ip = audit_ip.lock().unwrap().clone();
        let calls = Arc::clone(&ru_audit_calls2);
        Box::pin(async move {
            if ip == "5.5.5.5" {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1600)).await;
                let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                r.checks = vec![r.geo_result.clone()];
                Ok(r)
            } else {
                tokio::time::sleep(Duration::from_millis(30)).await;
                Ok(test_report(
                    provider,
                    OverallStatus::Green,
                    "185.10.10.10",
                    "DE",
                ))
            }
        })
    });

    let probe: ProbeFn = Arc::new(move || {
        let ip = probe_ip.lock().unwrap().clone();
        Box::pin(async move { Some(ip) })
    });
    let io = Arc::new(TestIo::default());
    let state = AppState::new_in_memory();
    state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    let env = Env {
        auditor: Auditor::new().expect("auditor"),
        state: state.clone(),
        hold_queue: Arc::new(HoldQueue::new()),
        io: io.clone(),
        audit,
        probe: Some(probe),
        resolve: None,
        audit_timeout: Duration::from_secs(10),
    };
    let guard = Arc::new(NetworkGuard::new());
    guard.start_with_env(env);

    for _ in 0..80 {
        if guard
            .inner
            .lock()
            .await
            .baseline
            .as_ref()
            .is_some_and(|b| b.ip == "185.10.10.10" && b.trusted)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(guard.inner.lock().await.baseline.as_ref().unwrap().trusted);

    // Drop to RU under AutoLockSilent: Pending at t<400ms, zero popup, zero 1s starvation,
    // then all 3 blocked + PauseMode::UntilNetworkChange once 1.6 s audit completes.
    *current_ip.lock().unwrap() = "5.5.5.5".to_string();
    guard.wake();
    for _ in 0..40 {
        if guard.gate() == Gate::Pending {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(guard.gate(), Gate::Pending);
    assert_eq!(io.shows.load(Ordering::SeqCst), 0);

    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(ru_audit_calls.load(Ordering::SeqCst), 3);
    assert_eq!(guard.gate(), Gate::Pending);

    for _ in 0..80 {
        if guard.pause_mode() == PauseMode::UntilNetworkChange
            && guard.gate() == Gate::Blocked
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(ru_audit_calls.load(Ordering::SeqCst), 3);
    assert_eq!(io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);
    for p in KNOWN_PROVIDERS {
        assert!(state.is_provider_blocked(p).await);
    }

    // Return to verified clean baseline (`185.10.10.10`) -> auto-recovers without manual unlock.
    *current_ip.lock().unwrap() = "185.10.10.10".to_string();
    guard.wake();
    for _ in 0..80 {
        if guard.pause_mode() == PauseMode::None
            && state.get_data().await.blocked_providers.is_empty()
            && !guard.any_provider_gate_closed()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(guard.pause_mode(), PauseMode::None);
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert!(!guard.any_provider_gate_closed());
    assert_eq!(io.shows.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_real_ticker_pinned_a_to_vpn2_to_vpn3_to_pinned_a_within_4h_recovers_green_and_never_relapses()
{
    use crate::auditor::{evaluate_impossible_travel, evaluate_ip_pinning_for_route, score_checks};
    use crate::routing::RouteSelection;

    let pinned_ip = "145.241.193.245";
    let vpn2_ip = "185.10.10.10";
    let vpn3_ip = "195.20.20.20";

    let current_ip = Arc::new(std::sync::Mutex::new(pinned_ip.to_string()));
    let probe_ip = Arc::clone(&current_ip);
    let transient_failures_left = Arc::new(AtomicUsize::new(0));
    let transient_failures_audit = Arc::clone(&transient_failures_left);

    let state = AppState::new_in_memory();
    state
        .set_pinned_ip(Some(pinned_ip.to_string()))
        .await
        .unwrap();
    state.set_strict_pinning_enabled(true).await.unwrap();

    let auditor = Auditor::new().expect("auditor");
    let _ = auditor
        .resolver
        .check_cache()
        .os
        .get_or_compute("tz:init", Duration::from_secs(60), |_| true, async {
            CheckResult::ok("OK", "ok")
        })
        .await;

    let state_for_audit = state.clone();
    let audit_ip = Arc::clone(&current_ip);
    let audit_cache = auditor.resolver.check_cache().clone();
    let audit: AuditFn = Arc::new(move |provider, _force| {
        let ip = audit_ip.lock().unwrap().clone();
        let st_handle = state_for_audit.clone();
        let fail_ctr = Arc::clone(&transient_failures_audit);
        let cache = audit_cache.clone();
        Box::pin(async move {
            // Simulate transient `utun` stabilization failure on the first verification call(s).
            if ip == pinned_ip
                && fail_ctr
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                        v.checked_sub(1)
                    })
                    .is_ok()
            {
                return Err("transient utun stabilization timeout".to_string());
            }

            let cc = if ip == pinned_ip {
                "GB"
            } else if ip == vpn2_ip {
                "NL"
            } else {
                "DE"
            };
            let _ = cache
                .os
                .get_or_compute("dns:check", Duration::from_secs(60), |_| true, async {
                    CheckResult::ok("DNS_CLEAN", "ok")
                })
                .await;
            let st_data = st_handle.get_data().await;
            let history = st_data.ip_history_for_selection(provider.as_str(), &RouteSelection::Direct);
            let now = crate::auditor::network::current_timestamp();
            let geo_res = CheckResult::ok("GEO_ALLOWED", cc);
            let (pin_res, is_pinned) = evaluate_ip_pinning_for_route(
                st_data.pinned_ips.get(provider.as_str()).map(String::as_str),
                st_data.pinned_ip.as_deref(),
                st_data.strict_pinning_enabled,
                &ip,
                None,
            );
            let travel_res = evaluate_impossible_travel(&history, cc, now, provider);
            let checks = vec![geo_res.clone(), pin_res.clone(), travel_res.clone()];
            let verdict = score_checks(&checks, is_pinned);
            let mut rep = test_report(provider, verdict.overall_status, &ip, cc);
            rep.trust_score = verdict.trust_score;
            rep.geo_result = geo_res;
            rep.pinning_result = pin_res;
            rep.travel_result = travel_res;
            rep.checks = checks;
            Ok(rep)
        })
    });

    let probe: ProbeFn = Arc::new(move || {
        let ip = probe_ip.lock().unwrap().clone();
        Box::pin(async move { Some(ip) })
    });
    let io = Arc::new(TestIo::default());
    let env = Env {
        auditor: auditor.clone(),
        state: state.clone(),
        hold_queue: Arc::new(HoldQueue::new()),
        io: io.clone(),
        audit,
        probe: Some(probe),
        resolve: None,
        audit_timeout: Duration::from_secs(5),
    };
    let guard = Arc::new(NetworkGuard::new());
    guard.start_with_env(env.clone());

    // 1. Cold-start baseline on Pinned(A) (`GB`) within <4h.
    for _ in 0..80 {
        if guard
            .inner
            .lock()
            .await
            .baseline
            .as_ref()
            .is_some_and(|b| b.ip == pinned_ip && b.trusted)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(guard.gate(), Gate::Open);
    let t0 = crate::auditor::network::current_timestamp();
    for p in KNOWN_PROVIDERS {
        state
            .record_ip_history_for_selection(
                p,
                &RouteSelection::Direct,
                IpHistoryEntry::new(pinned_ip, "GB", Some(31898), t0 - 600),
            )
            .await
            .unwrap();
    }

    // 2. Jump to VPN2(B) (`NL`) -> blocks uniformly and records NL in history (<4h).
    *current_ip.lock().unwrap() = vpn2_ip.to_string();
    guard.wake();
    let enriched_b = io
        .wait_for("interceptor://enriched", 2500)
        .await
        .expect("VPN2 enriched");
    let id_b = enriched_b.0["id"].as_str().unwrap();
    assert!(env.hold_queue.resolve(id_b, HoldResolution::Block).await);
    for _ in 0..80 {
        let st_now = state.get_data().await;
        if guard.pause_mode() == PauseMode::UntilNetworkChange
            && KNOWN_PROVIDERS.iter().all(|p| st_now.blocked_providers.contains(*p))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);
    for p in [ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
        assert_eq!(guard.gate_for(p), Gate::Blocked);
        state
            .record_ip_history_for_selection(
                p.as_str(),
                &RouteSelection::Direct,
                IpHistoryEntry::new(vpn2_ip, "NL", Some(1234), t0 - 300),
            )
            .await
            .unwrap();
    }

    // 3. Jump to VPN3(C) (`DE`) -> stays uniformly blocked across all 3 unpinned providers,
    //    and simulate an orphaned per-provider 60s hold + recent DE history (<4h).
    *current_ip.lock().unwrap() = vpn3_ip.to_string();
    guard.wake();
    for _ in 0..80 {
        if guard.current_observed_ip().await.as_deref() == Some(vpn3_ip)
            && guard.pause_mode() == PauseMode::UntilNetworkChange
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for p in KNOWN_PROVIDERS {
        assert!(state.is_provider_blocked(p).await);
        state
            .record_ip_history_for_selection(
                p,
                &RouteSelection::Direct,
                IpHistoryEntry::new(vpn3_ip, "DE", Some(5678), t0 - 60),
            )
            .await
            .unwrap();
    }
    let (_orphan_id, orphan_rx, _) = env
        .hold_queue
        .register_or_coalesce_provider("orphan-hold-vpn3".to_string(), "anthropic")
        .await;

    // 4. Return to Pinned(A) (`GB`) within <4h, WITH transient `utun` stabilization failures
    //    on the first 2 verification calls -> must recover cleanly without popup or PauseMode!
    let shows_before = io.shows.load(Ordering::SeqCst);
    transient_failures_left.store(6, Ordering::SeqCst);
    *current_ip.lock().unwrap() = pinned_ip.to_string();
    guard.wake();

    // Orphaned hold must resolve immediately as Superseded.
    let orphan_res = tokio::time::timeout(Duration::from_secs(2), orphan_rx)
        .await
        .expect("orphan hold cancelled by restore_locked")
        .unwrap();
    assert_eq!(orphan_res, HoldResolution::Superseded);

    // Wait for recovery AND transient retry to complete and record GB back into ip_history.
    for _ in 0..160 {
        let st_now = state.get_data().await;
        let anthropic_last_ip = st_now
            .ip_history_for_selection("anthropic", &RouteSelection::Direct)
            .last()
            .map(|e| e.ip.clone());
        if guard.pause_mode() == PauseMode::None
            && st_now.blocked_providers.is_empty()
            && !guard.any_provider_gate_closed()
            && anthropic_last_ip.as_deref() == Some(pinned_ip)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(guard.pause_mode(), PauseMode::None);
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert!(!guard.any_provider_gate_closed());
    assert_eq!(io.shows.load(Ordering::SeqCst), shows_before);

    // Even while history still had DE -> GB (<4h), `effective_tray_report` MUST NOT brand
    // Pinned(A) as Red / "СТОП СЕТИ" (must be Green!).
    let st_check = state.get_data().await;
    let mut red_travel_report = test_report(ProviderId::Anthropic, OverallStatus::Red, pinned_ip, "GB");
    let travel_crit = CheckResult::critical("IMPOSSIBLE_TRAVEL_CRITICAL", "DE -> GB in 1m", None);
    red_travel_report.travel_result = travel_crit.clone();
    red_travel_report.checks = vec![
        CheckResult::ok("GEO_ALLOWED", "GB"),
        CheckResult::ok("PINNED_IP_MATCH", "ok"),
        travel_crit,
    ];
    assert_eq!(
        effective_tray_report(&red_travel_report, false, &st_check).overall_status,
        OverallStatus::Green
    );

    // 5. Simulate `CheckCache` expiry + multiple real ticker cycles (>1.3s) -> never relapses!
    env.auditor.resolver.check_cache().clear().await;
    tokio::time::sleep(Duration::from_millis(1350)).await;
    assert_eq!(guard.pause_mode(), PauseMode::None);
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert!(!guard.any_provider_gate_closed());
    assert_eq!(io.shows.load(Ordering::SeqCst), shows_before);
}

#[tokio::test(start_paused = true)]
async fn test_apply_regular_probe_never_traps_pinned_ip_in_pause_mode() {
    let pinned_ip = "145.241.193.245";
    let h = harness(
        slow_audit(Duration::from_millis(10), pinned_ip, OverallStatus::Green),
        pinned_ip,
    )
    .await;
    h.state
        .set_pinned_ip(Some(pinned_ip.to_string()))
        .await
        .unwrap();
    h.state.block_provider("anthropic").await.unwrap();
    h.guard.set_pause_mode_raw(PauseMode::UntilNetworkChange);
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: pinned_ip.to_string(),
            country: Some("GB".to_string()),
            trusted: true,
        });
        inner.paused_ip = Some(pinned_ip.to_string());
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }
    h.guard.sync_gates_with_state(&h.state).await;
    assert_eq!(h.guard.pause_mode(), PauseMode::UntilNetworkChange);
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);

    // Next regular probe on the exact same pinned IP must untrap `paused_ip` and recover!
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.pause_mode(), PauseMode::None);
    assert!(h.state.get_data().await.blocked_providers.is_empty());
    assert_eq!(h.guard.gate(), Gate::Open);
    assert!(h.guard.inner.lock().await.paused_ip.is_none());
}

#[tokio::test]
async fn superseded_hold_drain_emits_resolved_and_hides_popup_on_disable_and_all_routed() {
    let h = harness(
        slow_audit(Duration::from_millis(10), "1.2.3.4", OverallStatus::Green),
        "1.2.3.4",
    )
    .await;

    // 1. Provider-scoped hold drained by `sync_provider_disabled` hides popup and emits `interceptor://resolved`.
    let rx_prov = h
        .env
        .hold_queue
        .register("prov-hold-1".to_string(), "anthropic")
        .await;
    h.env.hold_queue.set_alert(RiskInterceptPayload {
        id: "prov-hold-1".to_string(),
        provider: ProviderId::Anthropic,
        host: "api.anthropic.com:443".to_string(),
        report: None,
        ttl_seconds: DEFAULT_HOLD_TTL_SECS,
        scope: "provider".to_string(),
        network_change: None,
        is_simulation: false,
        detected_at_ms: 1,
        phase: PHASE_READY.to_string(),
        gate_reason: None,
    });
    let hides_before = h.io.hides.load(Ordering::SeqCst);
    let resolved_before = h.io.count("interceptor://resolved");
    h.guard.sync_provider_disabled("anthropic", &h.state).await;
    assert_eq!(rx_prov.await.unwrap(), HoldResolution::Superseded);
    assert!(h.io.hides.load(Ordering::SeqCst) > hides_before);
    assert!(h.io.count("interceptor://resolved") > resolved_before);

    // 2. Active hold drained in `plan_tick` when `unrouted.is_empty()` hides popup and emits `interceptor://resolved`.
    for p in KNOWN_PROVIDERS {
        h.state.set_provider_monitoring(p, false).await.unwrap();
    }
    let rx_tick = h
        .env
        .hold_queue
        .register("prov-hold-2".to_string(), "openai")
        .await;
    let hides_before2 = h.io.hides.load(Ordering::SeqCst);
    let resolved_before2 = h.io.count("interceptor://resolved");
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(rx_tick.await.unwrap(), HoldResolution::Superseded);
    assert!(h.io.hides.load(Ordering::SeqCst) > hides_before2);
    assert!(h.io.count("interceptor://resolved") > resolved_before2);
}
