use super::*;
use crate::auditor::CheckResult;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::Instant as TInstant;

#[tokio::test]
async fn test_probe_changed_shows_window_under_150ms_before_2500ms_probe_completes() {
    let audit: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            let mut r = test_report(provider, OverallStatus::Red, "9.9.9.9", "RU");
            r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
            r.checks = vec![r.geo_result.clone()];
            Ok(r)
        })
    });
    let h = harness_env(audit, "9.9.9.9", |env| {
        env.probe = Some(Arc::new(|| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(2500)).await;
                Some("9.9.9.9".to_string())
            })
        }));
    })
    .await;
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(format!("{}-old", compute_local_route_fingerprint(None)));
    }

    let started = TInstant::now();
    h.guard.check_route_and_tick(&h.env).await;
    let tick_elapsed = started.elapsed();

    // Window-first: tick returns immediately (< 150ms), popup + risk-detected already fired with new_ip: None.
    assert!(
        tick_elapsed < Duration::from_millis(150),
        "check_route_and_tick must not wait for 2500ms probe: {tick_elapsed:?}"
    );
    let (det, det_at) =
        h.io.first("interceptor://risk-detected")
            .expect("risk-detected emitted before probe_ip finishes");
    assert!(det_at.duration_since(started) < Duration::from_millis(150));
    assert_eq!(det["phase"], PHASE_DETECTING);
    assert!(det["report"].is_null());
    assert_eq!(det["network_change"]["old_ip"], "1.1.1.1");
    assert!(det["network_change"]["new_ip"].is_null());
    assert!(det["network_change"]["new_country"].is_null());
    assert_eq!(
        h.io.shows.load(Ordering::SeqCst),
        0,
        "popup must be deferred during detecting until ready or held CONNECT > 1200ms"
    );
    assert_eq!(h.guard.gate(), Gate::Pending);
    assert_eq!(h.io.count("interceptor://enriched"), 0);

    // Neither `tick_lock` nor `inner` is blocked while the 2500ms probe runs.
    assert!(h.guard.tick_lock.try_lock().is_ok());
    assert!(h.guard.inner.try_lock().is_ok());

    // After 2500ms probe + audit complete, `interceptor://enriched` delivers phase: ready + new_ip/country
    // and surfaces the popup once.
    let (enr, enr_at) =
        h.io.wait_for("interceptor://enriched", 4000)
            .await
            .expect("enriched ready after slow probe");
    assert!(enr_at.duration_since(started) >= Duration::from_millis(2400));
    assert_eq!(enr["phase"], PHASE_READY);
    assert_eq!(enr["network_change"]["new_ip"], "9.9.9.9");
    assert_eq!(enr["network_change"]["new_country"], "RU");
    assert!(enr["report"].is_object());
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn test_probe_changed_offline_retries_and_transitions_to_failed_without_losing_state() {
    let online = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let online2 = Arc::clone(&online);
    let probe_calls = Arc::new(AtomicUsize::new(0));
    let probe_calls2 = Arc::clone(&probe_calls);
    let h = harness_env(
        slow_audit(Duration::from_millis(20), "1.1.1.1", OverallStatus::Green),
        "1.1.1.1",
        move |env| {
            env.probe = Some(Arc::new(move || {
                probe_calls2.fetch_add(1, Ordering::SeqCst);
                let is_on = online2.load(Ordering::SeqCst);
                Box::pin(async move {
                    if is_on {
                        Some("1.1.1.1".to_string())
                    } else {
                        None
                    }
                })
            }));
        },
    )
    .await;
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(format!("{}-old", compute_local_route_fingerprint(None)));
    }

    // Offline VPN drop: risk-detected fires immediately (`phase: detecting`), popup stays deferred.
    h.guard.check_route_and_tick(&h.env).await;
    let det =
        h.io.first("interceptor://risk-detected")
            .expect("immediate detecting on offline drop");
    assert_eq!(det.0["phase"], PHASE_DETECTING);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.guard.gate(), Gate::Pending);

    // Exhaust offline retries -> transitions cleanly to `phase: failed` and shows popup once.
    let enr =
        h.io.wait_for("interceptor://enriched", 10_000)
            .await
            .expect("offline failed enrichment");
    assert_eq!(enr.0["phase"], PHASE_FAILED);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 1);
    assert!(enr.0["network_change"]["new_ip"].is_null());
    assert!(enr.0["network_change"]["new_country"].is_null());
    assert!(enr.0["report"].is_null());
    assert_eq!(h.guard.gate(), Gate::Pending);
    assert!(
        probe_calls.load(Ordering::SeqCst) > 1,
        "should retry offline probes"
    );
    {
        let inner = h.guard.inner.lock().await;
        assert!(inner.handled_ip.is_none());
        assert!(inner.needs_reaudit);
        assert!(inner.pending.is_some());
    }

    // Network comes back online on baseline IP -> regular probe recovers Gate::Open and hides popup.
    online.store(true, Ordering::SeqCst);
    h.guard.inner.lock().await.last_probe = None;
    h.guard.check_route_and_tick(&h.env).await;
    h.guard.wait_probe_settled_for_test().await;
    assert_eq!(h.guard.gate(), Gate::Open);
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
    assert!(h.env.hold_queue.current_alert().is_none());
}

#[tokio::test(start_paused = true)]
async fn test_probe_changed_false_alarm_shows_detecting_then_hides_on_baseline_return() {
    let h = harness_env(
        slow_audit(Duration::from_millis(20), "1.1.1.1", OverallStatus::Green),
        "1.1.1.1",
        |env| {
            env.probe = Some(Arc::new(|| {
                Box::pin(async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Some("1.1.1.1".to_string())
                })
            }));
        },
    )
    .await;
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(format!("{}-old", compute_local_route_fingerprint(None)));
    }

    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.io.count("interceptor://risk-detected"), 1);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.guard.gate(), Gate::Pending);

    // Wait for background probe returning baseline IP -> quietly opens gate without ever flashing popup.
    h.guard.wait_probe_settled_for_test().await;
    assert_eq!(h.guard.gate(), Gate::Open);
    assert_eq!(
        h.io.shows.load(Ordering::SeqCst),
        0,
        "transient false alarm must never flash alert popup"
    );
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
    assert!(h.io.count("interceptor://resolved") >= 1);
    assert!(h.env.hold_queue.current_alert().is_none());
    assert_eq!(h.io.count("interceptor://enriched"), 0);
}

#[tokio::test(start_paused = true)]
async fn test_verify_and_restore_baseline_does_not_block_inner_try_lock_and_guards_toctou() {
    let audit_started = Arc::new(tokio::sync::Notify::new());
    let audit_release = Arc::new(tokio::sync::Notify::new());
    let started2 = Arc::clone(&audit_started);
    let release2 = Arc::clone(&audit_release);

    let audit: AuditFn = Arc::new(move |provider, _force| {
        let s = Arc::clone(&started2);
        let r = Arc::clone(&release2);
        Box::pin(async move {
            s.notify_one();
            r.notified().await;
            Ok(test_report(provider, OverallStatus::Green, "1.1.1.1", "DE"))
        })
    });
    let h = harness(audit, "1.1.1.1").await;
    h.state.block_provider("anthropic").await.unwrap();
    h.guard.sync_gates_with_state(&h.state).await;
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }

    let guard = Arc::clone(&h.guard);
    let env = h.env.clone();
    let verify_task = tokio::spawn(async move {
        guard
            .verify_and_restore_baseline(&env, "1.1.1.1", true)
            .await;
    });

    audit_started.notified().await;
    // `inner` MUST be unlocked during `audit_enabled()`, so `check_route_fingerprint_sync` succeeds!
    assert!(h.guard.inner.try_lock().is_ok());
    assert!(
        h.guard
            .check_route_fingerprint_sync(Some("moved-during-audit"))
    );
    assert_eq!(h.guard.gate(), Gate::Pending);

    audit_release.notify_waiters();
    verify_task.await.unwrap();
    // Because the route moved mid-audit, verify_and_restore_baseline must NOT open the gate.
    assert_ne!(h.guard.gate(), Gate::Open);
    let inner = h.guard.inner.lock().await;
    assert!(inner.route_dirty);
    assert!(inner.needs_reaudit);
}

#[tokio::test(start_paused = true)]
async fn test_pausing_or_closing_popup_in_detecting_phase_binds_new_probed_ip_without_relapse() {
    let current_ip = Arc::new(std::sync::Mutex::new("9.9.9.9".to_string()));
    let probe_ip = Arc::clone(&current_ip);
    let audit: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            let mut r = test_report(provider, OverallStatus::Red, "9.9.9.9", "RU");
            r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
            r.checks = vec![r.geo_result.clone()];
            Ok(r)
        })
    });
    let h = harness_env(audit, "9.9.9.9", move |env| {
        let p_ip = Arc::clone(&probe_ip);
        env.probe = Some(Arc::new(move || {
            let ip = p_ip.lock().unwrap().clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(250)).await;
                Some(ip)
            })
        }));
    })
    .await;
    {
        let mut inner = h.guard.inner.lock().await;
        // Simulate pre-change `observed_ip` still equal to old baseline ("1.1.1.1") when route moves.
        inner.observed_ip = Some("1.1.1.1".to_string());
        inner.last_route_fp = Some(format!("{}-old", compute_local_route_fingerprint(None)));
    }

    // 1. Route change emits `phase: "detecting"` immediately while 250ms probe is in flight;
    //    popup stays deferred until ready/failed or a held CONNECT exceeds 1200ms.
    h.guard.check_route_and_tick(&h.env).await;
    let det =
        h.io.first("interceptor://risk-detected")
            .expect("detecting alert");
    let alert_id = det.0["id"].as_str().unwrap().to_string();
    assert_eq!(det.0["phase"], PHASE_DETECTING);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);

    // 2. User clicks "Пауза до смены сети" / ✕ / Esc WHILE still in `phase: "detecting"`.
    h.guard
        .mark_paused_until_network_change(Some("Пауза в detecting".to_string()))
        .await;
    assert!(
        h.env
            .hold_queue
            .resolve(&alert_id, HoldResolution::Block)
            .await
    );
    for _ in 0..40 {
        if h.guard.gate() == Gate::Blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(h.guard.pause_mode(), PauseMode::UntilNetworkChange);
    assert_eq!(h.guard.gate(), Gate::Blocked);
    {
        let inner = h.guard.inner.lock().await;
        assert!(
            inner.paused_ip.is_none(),
            "must NOT bind paused_ip to stale old observed_ip (1.1.1.1)"
        );
        assert!(inner.pending_pause_ip_bind);
    }

    // 3. Background probe finishes (returns "9.9.9.9") -> binds `paused_ip = Some("9.9.9.9")`
    //    without clearing pause or popping an alert.
    h.guard.wait_probe_settled_for_test().await;
    assert_eq!(h.guard.pause_mode(), PauseMode::UntilNetworkChange);
    assert_eq!(h.guard.gate(), Gate::Blocked);
    assert_eq!(
        h.guard.inner.lock().await.paused_ip.as_deref(),
        Some("9.9.9.9")
    );
    assert!(!h.guard.inner.lock().await.pending_pause_ip_bind);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);

    // 4. Subsequent 1s `ProbeRegular` on "9.9.9.9" keeps pause intact and never re-shows popup!
    h.guard.inner.lock().await.last_probe = None;
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.pause_mode(), PauseMode::UntilNetworkChange);
    assert_eq!(h.guard.gate(), Gate::Blocked);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn test_held_connect_past_1200ms_surfaces_deferred_detecting_popup() {
    let h = harness_env(
        slow_audit(Duration::from_secs(3), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
        |env| {
            env.probe = Some(Arc::new(|| {
                Box::pin(async {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    Some("9.9.9.9".to_string())
                })
            }));
        },
    )
    .await;
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(format!("{}-old", compute_local_route_fingerprint(None)));
    }

    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.gate(), Gate::Pending);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);

    let guard = Arc::clone(&h.guard);
    let waiter = tokio::spawn(async move { guard.await_decision_for(ProviderId::Anthropic).await });
    tokio::time::sleep(Duration::from_millis(1250)).await;
    assert_eq!(
        h.io.shows.load(Ordering::SeqCst),
        1,
        "held CONNECT past 1200ms must surface deferred detecting popup"
    );

    h.guard.inner.lock().await.invalidate_alert();
    h.guard.set_gate(Gate::Blocked);
    let _ = waiter.await;
}

#[tokio::test]
async fn test_route_change_when_all_providers_disabled_or_routed_never_hides_checkout_popup() {
    let h = harness(
        slow_audit(Duration::from_millis(10), "1.2.3.4", OverallStatus::Green),
        "1.2.3.4",
    )
    .await;
    for p in KNOWN_PROVIDERS {
        h.state.set_provider_monitoring(p, false).await.unwrap();
    }

    // Active PayShield `checkout:*` hold and popup alert.
    let (chk_id, _rx_chk, _) = h
        .env
        .hold_queue
        .register_or_coalesce_provider(
            "checkout:checkout.stripe.com".to_string(),
            "checkout:checkout.stripe.com",
        )
        .await;
    h.env.hold_queue.set_alert(RiskInterceptPayload {
        id: chk_id.clone(),
        provider: ProviderId::Anthropic,
        host: "checkout.stripe.com:443".to_string(),
        report: None,
        ttl_seconds: DEFAULT_HOLD_TTL_SECS,
        scope: "checkout".to_string(),
        network_change: None,
        is_simulation: false,
        detected_at_ms: 1,
        phase: PHASE_READY.to_string(),
        gate_reason: Some("PayShield".to_string()),
        checkout_risk: None,
    });

    let hides_before = h.io.hides.load(Ordering::SeqCst);
    let resolved_before = h.io.count("interceptor://resolved");

    // Trigger both `plan_tick`, `begin_changed_probe`, and `handle_change_locked` with `unrouted.is_empty()`.
    h.guard.check_route_and_tick(&h.env).await;
    h.guard
        .begin_changed_probe(&h.env, Instant::now(), "fp-new".to_string(), false)
        .await;
    h.change("5.6.7.8").await;

    assert_eq!(
        h.io.hides.load(Ordering::SeqCst),
        hides_before,
        "PayShield checkout popup must NEVER be hidden by guard route ticks"
    );
    assert_eq!(h.io.count("interceptor://resolved"), resolved_before);
    assert!(h.env.hold_queue.is_active(&chk_id).await);
    assert_eq!(h.env.hold_queue.current_alert().map(|a| a.id), Some(chk_id));
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
        checkout_risk: None,
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
