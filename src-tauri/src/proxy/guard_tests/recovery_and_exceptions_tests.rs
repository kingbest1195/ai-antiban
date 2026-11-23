use super::*;
use crate::auditor::CheckResult;
use crate::state::InterceptionBehavior;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test(start_paused = true)]
async fn test_yellow_never_blocks_or_alerts_in_all_behaviors() {
    for behavior in [
        InterceptionBehavior::AskPopup,
        InterceptionBehavior::AutoLockSilent,
        InterceptionBehavior::AutoAllowTrusted,
    ] {
        let audit: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                let mut r = test_report(provider, OverallStatus::Yellow, "9.9.9.9", "KZ");
                r.checks = vec![
                    CheckResult::ok("GEO_LOCATION", "KZ"),
                    CheckResult::warning("TIMEZONE_MISMATCH", "TZ offset", None),
                ];
                Ok(r)
            })
        });
        let h = harness(audit, "9.9.9.9").await;
        h.state.set_interception_behavior(behavior).await.unwrap();
        h.change("9.9.9.9").await;
        h.io.wait_for("network://changed", 2000)
            .await
            .expect("yellow settled");
        if behavior == InterceptionBehavior::AskPopup {
            assert!(
                h.io.hides.load(Ordering::SeqCst) >= 1,
                "AskPopup quick detecting popup must auto-hide when audit settles Yellow"
            );
        } else {
            assert_eq!(
                h.io.count("interceptor://risk-detected"),
                0,
                "Yellow must never emit risk-detected under {behavior:?}"
            );
            assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
        }
        assert_eq!(
            h.io.count("interceptor://enriched"),
            0,
            "Yellow must never enrich/keep an active risk alert under {behavior:?}"
        );
        assert!(h.env.hold_queue.current_alert().is_none());
        assert_eq!(h.guard.gate(), Gate::Open);
        assert!(h.state.get_data().await.blocked_providers.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn test_trusted_exception_survives_restart_and_network_change_no_alert() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");
    let state1 = AppState::load_or_default(state_path.clone());
    let io1 = Arc::new(TestIo::default());
    let audit_red: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
            r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
            r.checks = vec![r.geo_result.clone()];
            Ok(r)
        })
    });
    let env1 = Env {
        auditor: Auditor::new().expect("auditor"),
        state: state1.clone(),
        hold_queue: Arc::new(HoldQueue::new()),
        io: io1.clone(),
        audit: audit_red.clone(),
        probe: Some(Arc::new(|| Box::pin(async { Some("5.5.5.5".to_string()) }))),
        resolve: None,
        audit_timeout: Duration::from_secs(2),
    };
    let guard1 = Arc::new(NetworkGuard::new());
    guard1.install_env(env1.clone());
    guard1.register_self_weak();
    guard1.inner.lock().await.baseline = Some(Baseline {
        ip: "1.1.1.1".to_string(),
        country: Some("DE".to_string()),
        trusted: true,
    });
    {
        let mut inner = guard1.inner.lock().await;
        guard1
            .handle_change_locked(&env1, &mut inner, "5.5.5.5".to_string(), Instant::now())
            .await;
    }
    let ev = io1
        .wait_for("interceptor://enriched", 2000)
        .await
        .expect("initial ready alert on Critical non-excepted IP");
    let id = ev.0["id"].as_str().unwrap().to_string();
    guard1
        .allow_network_alert(&id, &["anthropic".to_string()])
        .await
        .unwrap();
    assert!(
        state1
            .is_ip_trusted_for_provider("anthropic", "5.5.5.5")
            .await
    );

    // Simulate switching away and restarting app from disk (session_allowed cleared,
    // trusted_exceptions preserved). Force-allowing openai & gemini too for completeness.
    state1
        .add_trusted_exception("openai", "5.5.5.5")
        .await
        .unwrap();
    state1
        .add_trusted_exception("gemini", "5.5.5.5")
        .await
        .unwrap();
    drop(state1);

    let state2 = AppState::load_or_default(state_path);
    assert!(!state2.is_provider_session_allowed("anthropic").await);
    assert!(
        state2
            .is_ip_trusted_for_provider("anthropic", "5.5.5.5")
            .await
    );

    let io2 = Arc::new(TestIo::default());
    let env2 = Env {
        auditor: Auditor::new().expect("auditor"),
        state: state2.clone(),
        hold_queue: Arc::new(HoldQueue::new()),
        io: io2.clone(),
        audit: audit_red,
        probe: Some(Arc::new(|| Box::pin(async { Some("5.5.5.5".to_string()) }))),
        resolve: None,
        audit_timeout: Duration::from_secs(2),
    };
    let guard2 = Arc::new(NetworkGuard::new());
    guard2.install_env(env2.clone());
    guard2.register_self_weak();
    guard2.inner.lock().await.baseline = Some(Baseline {
        ip: "8.8.8.8".to_string(),
        country: Some("NL".to_string()),
        trusted: true,
    });
    {
        let mut inner = guard2.inner.lock().await;
        guard2
            .handle_change_locked(&env2, &mut inner, "5.5.5.5".to_string(), Instant::now())
            .await;
    }
    assert_eq!(io2.count("interceptor://risk-detected"), 0);
    assert_eq!(io2.shows.load(Ordering::SeqCst), 0);
    assert_eq!(guard2.gate(), Gate::Open);
    assert!(state2.get_data().await.blocked_providers.is_empty());
}

#[tokio::test(start_paused = true)]
async fn test_disabled_provider_skipped_in_audit_gates_and_alerts() {
    let audited_providers: Arc<std::sync::Mutex<Vec<ProviderId>>> = Arc::default();
    let audited2 = Arc::clone(&audited_providers);
    let audit: AuditFn = Arc::new(move |provider, _force| {
        audited2.lock().unwrap().push(provider);
        Box::pin(async move {
            if provider == ProviderId::Gemini {
                let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                r.checks = vec![r.geo_result.clone()];
                Ok(r)
            } else {
                Ok(test_report(provider, OverallStatus::Green, "5.5.5.5", "NL"))
            }
        })
    });
    let h = harness(audit, "5.5.5.5").await;
    h.state.block_provider("gemini").await.unwrap();
    h.state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();
    h.guard.sync_provider_disabled("gemini", &h.state).await;
    assert!(!h.state.is_provider_blocked("gemini").await);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);

    h.change("5.5.5.5").await;
    h.io.wait_for("network://changed", 2000)
        .await
        .expect("audit settled");
    assert_eq!(h.io.count("interceptor://enriched"), 0);
    assert!(h.env.hold_queue.current_alert().is_none());
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
    assert_eq!(h.guard.gate(), Gate::Open);
    assert!(
        !audited_providers
            .lock()
            .unwrap()
            .contains(&ProviderId::Gemini)
    );
}

#[tokio::test(start_paused = true)]
async fn test_already_blocked_alert_suppression_and_partial_newly_affected_alert() {
    let audit: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            match provider {
                ProviderId::Anthropic | ProviderId::Openai => {
                    let mut r = test_report(provider, OverallStatus::Red, "6.6.6.6", "RU");
                    r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                    r.checks = vec![r.geo_result.clone()];
                    Ok(r)
                }
                ProviderId::Gemini => {
                    Ok(test_report(provider, OverallStatus::Green, "6.6.6.6", "NL"))
                }
            }
        })
    });
    let h = harness(audit, "6.6.6.6").await;
    // Disable gemini; block BOTH anthropic and openai before network change.
    h.state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();
    h.state.block_provider("anthropic").await.unwrap();
    h.state.block_provider("openai").await.unwrap();
    h.guard.sync_gates_with_state(&h.state).await;

    // 1. All violated enabled providers are ALREADY blocked -> NO alert popup.
    h.change("6.6.6.6").await;
    h.io.wait_for("network://changed", 2000)
        .await
        .expect("network://changed after audit");
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Blocked);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);

    // 2. Now only anthropic is blocked while openai was allowed -> alert ONLY for openai,
    //    and allowing it keeps anthropic blocked while persisting exception only for openai.
    h.state.unblock_provider("openai").await.unwrap();
    h.guard.sync_gates_with_state(&h.state).await;
    h.change("7.7.7.7").await;
    let det =
        h.io.wait_for("interceptor://risk-detected", 2000)
            .await
            .expect("detecting alert for newly affected openai");
    assert_eq!(det.0["phase"], "detecting");
    assert_eq!(det.0["provider"], "openai");
    let enr =
        h.io.wait_for("interceptor://enriched", 2000)
            .await
            .expect("ready enrichment for newly affected openai");
    assert_eq!(enr.0["phase"], "ready");
    let id = enr.0["id"].as_str().unwrap().to_string();
    let affected = h
        .guard
        .affected_providers_for_alert(&id)
        .await
        .expect("pending affected");
    assert_eq!(affected, vec!["openai".to_string()]);
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Pending);

    h.guard.allow_network_alert(&id, &affected).await.unwrap();
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert!(h.state.is_provider_blocked("anthropic").await);
    assert!(!h.state.is_provider_blocked("openai").await);
}

#[tokio::test(start_paused = true)]
async fn test_silent_auto_recovery_when_checks_become_yellow_pinned_or_excepted() {
    let mode = Arc::new(AtomicUsize::new(0));
    let mode2 = Arc::clone(&mode);
    let audit: AuditFn = Arc::new(move |provider, _force| {
        let cur = mode2.load(Ordering::SeqCst);
        Box::pin(async move {
            if cur == 0 {
                let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                r.checks = vec![r.geo_result.clone()];
                Ok(r)
            } else {
                let mut r = test_report(provider, OverallStatus::Yellow, "9.9.9.9", "RS");
                r.checks = vec![
                    CheckResult::ok("GEO_LOCATION", "RS"),
                    CheckResult::warning("TIMEZONE_MISMATCH", "TZ", None),
                ];
                Ok(r)
            }
        })
    });
    let h = harness(audit, "9.9.9.9").await;
    h.state.block_provider("anthropic").await.unwrap();
    h.state.block_provider("openai").await.unwrap();
    h.guard.sync_gates_with_state(&h.state).await;
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);

    // Recovery via Yellow (`no_critical_and_geo_ok`) on new IP -> silent unblock & Open!
    mode.store(1, Ordering::SeqCst);
    h.change("9.9.9.9").await;
    h.io.wait_for("network://changed", 2000)
        .await
        .expect("silent recovery event");
    assert_eq!(h.io.count("interceptor://enriched"), 0);
    assert!(h.env.hold_queue.current_alert().is_none());
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
    assert_eq!(h.guard.gate(), Gate::Open);
    assert!(h.state.get_data().await.blocked_providers.is_empty());

    // Recovery on same baseline IP when per-provider pinned_ips matches and geo is OK!
    mode.store(0, Ordering::SeqCst);
    h.state.block_provider("anthropic").await.unwrap();
    h.state
        .set_pinned_ip_for("anthropic", Some("5.5.5.5".to_string()))
        .await
        .unwrap();
    h.state
        .add_trusted_exception("openai", "5.5.5.5")
        .await
        .unwrap();
    h.state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();
    h.guard.sync_gates_with_state(&h.state).await;
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "5.5.5.5".to_string(),
            country: Some("RU".to_string()),
            trusted: true,
        });
        // Keep trusted_exception for anthropic off to ensure trusted_exceptions OR Yellow recovers cleanly:
    }
    // Make geo DE with impossible-travel critical so pinned_ips["anthropic"] recovers anthropic & trusted_exception recovers openai.
    let travel_audit: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "DE");
            r.checks = vec![CheckResult::critical(
                "IMPOSSIBLE_TRAVEL_CRITICAL",
                "DE hop",
                None,
            )];
            Ok(r)
        })
    });
    let h2 = harness(travel_audit, "5.5.5.5").await;
    h2.state.block_provider("anthropic").await.unwrap();
    h2.state.block_provider("openai").await.unwrap();
    h2.state
        .set_pinned_ip_for("anthropic", Some("5.5.5.5".to_string()))
        .await
        .unwrap();
    h2.state
        .add_trusted_exception("openai", "5.5.5.5")
        .await
        .unwrap();
    h2.state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();
    h2.guard.sync_gates_with_state(&h2.state).await;
    h2.guard
        .verify_and_restore_baseline(&h2.env, "5.5.5.5", true)
        .await;
    assert_eq!(h2.io.count("interceptor://risk-detected"), 0);
    assert_eq!(h2.guard.gate(), Gate::Open);
    assert!(h2.state.get_data().await.blocked_providers.is_empty());
}

#[tokio::test(start_paused = true)]
async fn test_startup_pinned_ip_and_stale_block_silent_clear_no_alert() {
    let audit: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            let mut r = test_report(provider, OverallStatus::Yellow, "1.1.1.1", "DE");
            r.checks = vec![
                CheckResult::ok("GEO_LOCATION", "DE"),
                CheckResult::warning("TIMEZONE_MISMATCH", "TZ", None),
            ];
            Ok(r)
        })
    });
    let h = harness(audit, "1.1.1.1").await;
    h.state.block_provider("anthropic").await.unwrap();
    h.state
        .set_pinned_ip_for("anthropic", Some("1.1.1.1".to_string()))
        .await
        .unwrap();
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = None;
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.guard.gate(), Gate::Open);
    assert!(h.state.get_data().await.blocked_providers.is_empty());
}

#[tokio::test(start_paused = true)]
async fn test_sync_provider_route_change_unbind_triggers_reaudit() {
    let audit_calls = Arc::new(AtomicUsize::new(0));
    let audit_calls2 = Arc::clone(&audit_calls);
    let audit: AuditFn = Arc::new(move |provider, _force| {
        audit_calls2.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if provider == ProviderId::Anthropic {
                let mut r = test_report(provider, OverallStatus::Red, "1.1.1.1", "RU");
                r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                r.checks = vec![r.geo_result.clone()];
                Ok(r)
            } else {
                Ok(test_report(provider, OverallStatus::Green, "1.1.1.1", "NL"))
            }
        })
    });
    let h = harness(audit, "1.1.1.1").await;
    h.state
        .set_provider_monitoring("openai", false)
        .await
        .unwrap();
    h.state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "1.1.1.1".to_string(),
            country: Some("DE".to_string()),
            trusted: true,
        });
        inner.handled_ip = Some("1.1.1.1".to_string());
    }

    // Simulate unbinding Anthropic route on the SAME baseline IP -> must reset handled_ip,
    // arm needs_reaudit, and kick an immediate re-audit so Critical violation is caught!
    h.guard.sync_provider_route_change("anthropic", false);
    let ev =
        h.io.wait_for("interceptor://risk-detected", 2000)
            .await
            .expect("reaudit alert after route unbind");
    assert_eq!(ev.0["provider"], "anthropic");
    assert!(audit_calls.load(Ordering::SeqCst) >= 1);
}

#[tokio::test(start_paused = true)]
async fn test_first_provider_failure_preserves_siblings_and_blocks_failed_provider() {
    // 1. AutoLockSilent: Anthropic fails while OpenAI & Gemini succeed Green.
    //    OpenAI & Gemini stay Gate::Open; ONLY Anthropic is blocked.
    let partial_fail: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            if provider == ProviderId::Anthropic {
                Err("anthropic check failed".to_string())
            } else {
                Ok(test_report(provider, OverallStatus::Green, "9.9.9.9", "NL"))
            }
        })
    });
    let h = harness(partial_fail.clone(), "9.9.9.9").await;
    h.state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    h.change("9.9.9.9").await;
    h.io.wait_for("network://changed", 2000)
        .await
        .expect("partial fail settled");

    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert!(h.state.is_provider_blocked("anthropic").await);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert!(!h.state.is_provider_blocked("openai").await);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
    assert!(!h.state.is_provider_blocked("gemini").await);

    // 2. AskPopup: Anthropic fails while OpenAI & Gemini succeed Green.
    //    OpenAI & Gemini return to Gate::Open; enriched emits PHASE_FAILED for Anthropic (not Green OpenAI).
    let h2 = harness(partial_fail, "9.9.9.9").await;
    h2.change("9.9.9.9").await;
    let ev = h2
        .io
        .wait_for("interceptor://enriched", 2000)
        .await
        .expect("failed enrichment for anthropic");
    assert_eq!(ev.0["phase"], PHASE_FAILED);
    assert!(ev.0["report"].is_null());
    assert_eq!(
        h2.env
            .hold_queue
            .current_alert()
            .expect("held alert")
            .provider,
        ProviderId::Anthropic
    );
    assert_eq!(h2.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
    assert_eq!(h2.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert_eq!(h2.guard.gate_for(ProviderId::Gemini), Gate::Open);

    // 3. AutoLockSilent when ALL enabled unrouted providers fail -> gates MUST be Blocked, never Open!
    let all_fail: AuditFn = Arc::new(|_, _| Box::pin(async { Err("all down".to_string()) }));
    let h3 = harness(all_fail, "9.9.9.9").await;
    h3.state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    h3.change("9.9.9.9").await;
    h3.io
        .wait_for("network://changed", 2000)
        .await
        .expect("all fail settled");

    for p in KNOWN_PROVIDERS {
        assert!(
            h3.state.is_provider_blocked(p).await,
            "{p} must be blocked when all audits fail under AutoLockSilent"
        );
    }
    assert_eq!(h3.guard.gate(), Gate::Blocked);
    assert_eq!(h3.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert_eq!(h3.guard.gate_for(ProviderId::Openai), Gate::Blocked);
    assert_eq!(h3.guard.gate_for(ProviderId::Gemini), Gate::Blocked);
}

#[tokio::test(start_paused = true)]
async fn test_kick_reaudit_and_route_sync_never_drop_when_inner_is_locked() {
    let audit_calls = Arc::new(AtomicUsize::new(0));
    let audit_calls2 = Arc::clone(&audit_calls);
    let audit: AuditFn = Arc::new(move |provider, _force| {
        audit_calls2.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if provider == ProviderId::Anthropic {
                let mut r = test_report(provider, OverallStatus::Red, "1.1.1.1", "RU");
                r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                r.checks = vec![r.geo_result.clone()];
                Ok(r)
            } else {
                Ok(test_report(provider, OverallStatus::Green, "1.1.1.1", "NL"))
            }
        })
    });
    let h = harness(audit, "1.1.1.1").await;
    h.state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    h.state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();

    let route = crate::routing::parse_route_key("socks5://10.0.0.1:1080#nl", 1).unwrap();
    let route_id = h.state.upsert_route(route).await.unwrap();
    h.state
        .bind_provider_route("openai", Some(&route_id))
        .await
        .unwrap();

    // Hold `self.inner` so `try_lock()` inside `kick_reaudit` and `sync_provider_route_change`
    // fails, and verify the atomic/lock-free signals are NOT dropped!
    {
        let mut inner = h.guard.inner.lock().await;
        inner.handled_ip = Some("1.1.1.1".to_string());
        inner.last_probe = Some(Instant::now());
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        inner.pending = Some(Pending {
            id: "p-lock".to_string(),
            epoch: inner.epoch,
            target_ip: "1.1.1.1".to_string(),
            tel: None,
            clear_old_state: None,
            affected_providers: vec!["openai"],
            already_blocked_providers: Vec::new(),
            healthy_providers: Vec::new(),
            alert_emitted: true,
        });

        // `try_lock()` fails here because `inner` is locked.
        h.guard.sync_provider_route_change("openai", true);
        h.guard.kick_reaudit();
    }

    h.guard.check_route_and_tick(&h.env).await;

    assert!(
        audit_calls.load(Ordering::SeqCst) >= 1,
        "kick_reaudit signal must not be dropped when inner was locked"
    );
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert!(h.state.is_provider_blocked("anthropic").await);
    assert!(
        h.guard.inner.lock().await.pending.is_none(),
        "pending alert containing routed openai must have been pruned"
    );
}

#[tokio::test(start_paused = true)]
async fn test_confirm_provider_session_routed_does_not_mark_direct_baseline_trusted() {
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let resolve_calls2 = Arc::clone(&resolve_calls);
    let h = harness_env(
        slow_audit(Duration::from_millis(10), "5.5.5.5", OverallStatus::Red),
        "5.5.5.5",
        move |env| {
            env.resolve = Some(Arc::new(move || {
                resolve_calls2.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    Ok(
                        test_report(ProviderId::Anthropic, OverallStatus::Red, "5.5.5.5", "RU")
                            .telemetry,
                    )
                })
            }));
        },
    )
    .await;

    // Direct baseline is an untrusted RU IP.
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "5.5.5.5".to_string(),
            country: Some("RU".to_string()),
            trusted: false,
        });
    }

    // Bind Anthropic to a route (OpenAI remains direct/unrouted), then confirm Anthropic
    // with `tel = None` (as `resolve_exit_ip_for_provider` does for routed providers).
    let route = crate::routing::parse_route_key("socks5://10.0.0.1:1080#nl", 1).unwrap();
    let route_id = h.state.upsert_route(route).await.unwrap();
    h.state
        .bind_provider_route("anthropic", Some(&route_id))
        .await
        .unwrap();

    h.guard.confirm_provider_session("anthropic", None).await;
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    assert!(
        !h.guard
            .inner
            .lock()
            .await
            .baseline
            .as_ref()
            .unwrap()
            .trusted,
        "confirming a routed provider must NOT trust an untrusted direct baseline"
    );

    // Also when all providers are routed, confirm_provider_session must not resolve direct egress.
    h.state.set_default_route(Some(&route_id)).await.unwrap();
    h.guard.confirm_provider_session("openai", None).await;
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    assert!(
        !h.guard
            .inner
            .lock()
            .await
            .baseline
            .as_ref()
            .unwrap()
            .trusted
    );
}
