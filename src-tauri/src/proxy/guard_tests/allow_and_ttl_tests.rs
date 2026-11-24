use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::Instant as TInstant;

#[tokio::test(start_paused = true)]
async fn test_stale_probe_never_opens_gate() {
    // The route moves (a CONNECT sees it) while the tick's probe is in flight, and the probe
    // still answers with the old, trusted baseline IP.
    let slot: Arc<std::sync::OnceLock<Arc<NetworkGuard>>> = Arc::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let (slot2, calls2) = (Arc::clone(&slot), Arc::clone(&calls));
    let h = harness_env(
        slow_audit(Duration::from_millis(50), "9.9.9.9", OverallStatus::Red),
        "1.1.1.1",
        move |env| {
            env.probe = Some(Arc::new(move || {
                let first = calls2.fetch_add(1, Ordering::SeqCst) == 0;
                let guard = slot2.get().cloned();
                Box::pin(async move {
                    if first {
                        let g = guard.expect("guard");
                        assert!(g.check_route_fingerprint_sync(Some("moved")));
                        Some("1.1.1.1".to_string())
                    } else {
                        Some("9.9.9.9".to_string())
                    }
                })
            }));
        },
    )
    .await;
    slot.set(Arc::clone(&h.guard)).ok();
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }
    h.guard.set_gate(Gate::Pending);
    let env = h.env.clone();

    h.guard.check_route_and_tick(&env).await;
    assert_eq!(
        h.guard.gate(),
        Gate::Pending,
        "stale probe must not open the gate"
    );
    assert!(
        h.guard.inner.lock().await.route_dirty,
        "change stays flagged"
    );
    assert_eq!(h.io.count("network://changed"), 0);
    assert_eq!(h.io.hides.load(Ordering::SeqCst), 0);

    // The next tick handles the change and emits the window once the audit completes.
    h.guard.check_route_and_tick(&env).await;
    h.io.wait_for("interceptor://risk-detected", 1000)
        .await
        .expect("risk-detected");
    assert_eq!(h.guard.gate(), Gate::Pending);
}

#[tokio::test(start_paused = true)]
async fn test_allow_for_superseded_alert_changes_nothing() {
    let h = harness(
        slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    h.change("9.9.9.9").await;
    let ev =
        h.io.wait_for("interceptor://risk-detected", 2000)
            .await
            .expect("first risk-detected");
    let id1 = ev.0["id"].as_str().unwrap().to_string();

    // A new change C arrives; the user's allow for alert 1 reaches the guard afterwards.
    h.change("8.8.8.8").await;
    let err = h.guard.allow_network_alert(&id1, &all_providers()).await;
    assert_eq!(err.map_err(|e| e.code), Err(AllowErrorCode::AlertStale));
    assert_eq!(h.guard.gate(), Gate::Pending);
    let deadline = TInstant::now() + Duration::from_millis(2000);
    while TInstant::now() < deadline && h.io.count("interceptor://risk-detected") < 2 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(h.io.count("interceptor://risk-detected"), 2);
    let inner = h.guard.inner.lock().await;
    assert_eq!(
        inner.baseline.as_ref().map(|b| b.ip.as_str()),
        Some("1.1.1.1")
    );
    let id2 = inner.pending.as_ref().expect("alert 2 alive").id.clone();
    drop(inner);
    assert_ne!(id1, id2);
    assert_eq!(h.env.hold_queue.current_alert().map(|a| a.id), Some(id2));
    for p in KNOWN_PROVIDERS {
        assert!(!h.state.is_provider_blocked(p).await);
        assert!(!h.state.is_provider_session_allowed(p).await);
    }
    let mut rx = h.guard.subscribe();
    assert!(
        tokio::time::timeout(Duration::from_millis(80), wait_open(&mut rx))
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn test_network_allow_only_when_ready() {
    // Pending audit: immediate detecting alert emitted, allow refused with AuditPending.
    let h = harness(
        slow_audit(Duration::from_millis(300), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    h.change("9.9.9.9").await;
    let det =
        h.io.first("interceptor://risk-detected")
            .expect("immediate detecting");
    assert_eq!(det.0["phase"], "detecting");
    let internal_id = alert_id(&det);
    assert_eq!(
        h.guard
            .allow_network_alert(&internal_id, &all_providers())
            .await
            .map_err(|e| e.code),
        Err(AllowErrorCode::AuditPending)
    );
    assert_eq!(h.guard.gate(), Gate::Pending);
    assert!(!h.state.is_provider_session_allowed("anthropic").await);

    // Ready: enriched emitted, allow accepted, gate opens, trusted_exception written.
    let ev =
        h.io.wait_for("interceptor://enriched", 2000)
            .await
            .expect("ready enriched");
    assert_eq!(ev.0["phase"], "ready");
    let id = ev.0["id"].as_str().unwrap().to_string();
    h.guard
        .allow_network_alert_with(&id, &all_providers(), true)
        .await
        .expect("allowed");
    assert_eq!(h.guard.gate(), Gate::Open);
    assert!(h.state.is_provider_session_allowed("anthropic").await);
    assert!(
        h.state
            .is_ip_trusted_for_provider("anthropic", "9.9.9.9")
            .await
    );
    assert!(h.env.hold_queue.current_alert().is_none());
    assert_eq!(
        h.guard
            .inner
            .lock()
            .await
            .baseline
            .as_ref()
            .map(|b| b.ip.as_str()),
        Some("9.9.9.9")
    );
    // The same allow again (stale id) is refused.
    assert_eq!(
        h.guard
            .allow_network_alert(&id, &all_providers())
            .await
            .map_err(|e| e.code),
        Err(AllowErrorCode::AlertStale)
    );

    // Failed audit: refused as well, window and gate stay.
    let failing: AuditFn = Arc::new(|_, _| Box::pin(async { Err("geo down".to_string()) }));
    let h = harness(failing, "9.9.9.9").await;
    h.change("9.9.9.9").await;
    let ev =
        h.io.wait_for("interceptor://enriched", 3000)
            .await
            .expect("failed enrichment");
    assert_eq!(ev.0["phase"], "failed");
    let id = ev.0["id"].as_str().unwrap().to_string();
    assert_eq!(
        h.guard
            .allow_network_alert(&id, &all_providers())
            .await
            .map_err(|e| e.code),
        Err(AllowErrorCode::AuditPending)
    );
    assert_eq!(h.guard.gate(), Gate::Pending);
    assert!(h.env.hold_queue.current_alert().is_some());

    // The manual kill-switch outranks everything: refused with its own code.
    h.guard.set_manual_killswitch(true, &h.state).await;
    assert_eq!(
        h.guard
            .allow_network_alert(&id, &all_providers())
            .await
            .map_err(|e| e.code),
        Err(AllowErrorCode::BlockedByManualKillswitch)
    );
}

#[tokio::test(start_paused = true)]
async fn test_allow_without_audit_never_opens_gate() {
    // An allow sent to a failed (un-audited) alert is never honoured.
    let failing: AuditFn = Arc::new(|_, _| Box::pin(async { Err("geo down".to_string()) }));
    let h = harness(failing, "9.9.9.9").await;
    h.change("9.9.9.9").await;
    let ev =
        h.io.wait_for("interceptor://enriched", 2000)
            .await
            .expect("failed enriched");
    assert_eq!(ev.0["phase"], "failed");
    let id = ev.0["id"].as_str().unwrap().to_string();
    assert!(h.env.hold_queue.resolve(&id, HoldResolution::Allow).await);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.guard.gate(), Gate::Blocked);
    assert_ne!(h.guard.gate(), Gate::Open);
    assert!(h.state.is_provider_blocked("anthropic").await);
    assert_eq!(
        h.guard
            .inner
            .lock()
            .await
            .baseline
            .as_ref()
            .map(|b| b.ip.as_str()),
        Some("1.1.1.1")
    );
}

#[tokio::test(start_paused = true)]
async fn test_accept_current_error_does_not_open_gate() {
    let tel = test_report(ProviderId::Anthropic, OverallStatus::Green, "9.9.9.9", "NL").telemetry;
    let ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ok2 = Arc::clone(&ok);
    let h = harness_env(
        slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
        move |env| {
            env.resolve = Some(Arc::new(move || {
                let tel = tel.clone();
                let ok = ok2.load(Ordering::SeqCst);
                Box::pin(async move {
                    if ok {
                        Ok(tel)
                    } else {
                        Err("offline".to_string())
                    }
                })
            }));
        },
    )
    .await;
    h.change("9.9.9.9").await;
    h.io.wait_for("interceptor://enriched", 2000)
        .await
        .expect("ready enrichment");
    let hides = h.io.hides.load(Ordering::SeqCst);

    h.guard.accept_current().await;
    assert_eq!(
        h.guard.gate(),
        Gate::Pending,
        "unverifiable network stays closed"
    );
    assert!(
        h.env.hold_queue.current_alert().is_some(),
        "alert is untouched"
    );
    assert_eq!(h.io.hides.load(Ordering::SeqCst), hides);

    ok.store(true, Ordering::SeqCst);
    h.guard.accept_current().await;
    assert_eq!(h.guard.gate(), Gate::Open);
}

#[tokio::test(start_paused = true)]
async fn test_hold_ttl_blocks_a_ready_alert() {
    let h = harness(
        slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    h.change("9.9.9.9").await;
    h.io.wait_for("interceptor://enriched", 2000)
        .await
        .expect("ready enrichment");
    assert_eq!(h.guard.gate(), Gate::Pending);

    tokio::time::sleep(Duration::from_secs(DEFAULT_HOLD_TTL_SECS - 1)).await;
    assert_eq!(h.guard.gate(), Gate::Pending);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(h.guard.gate(), Gate::Blocked);
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
    for p in KNOWN_PROVIDERS {
        assert!(h.state.is_provider_blocked(p).await);
    }
    assert!(h.env.hold_queue.current_alert().is_none());
}

#[tokio::test(start_paused = true)]
async fn test_default_audit_timeout_then_ttl_blocks() {
    // A hanging audit: failed after AUDIT_TIMEOUT_SECS, the hold TTL then blocks.
    let hanging: AuditFn = Arc::new(|_, _| Box::pin(std::future::pending()));
    let h = harness_env(hanging, "9.9.9.9", |env| {
        env.audit_timeout = Duration::from_secs(AUDIT_TIMEOUT_SECS);
    })
    .await;
    h.change("9.9.9.9").await;

    tokio::time::sleep(Duration::from_secs(AUDIT_TIMEOUT_SECS - 1)).await;
    assert_eq!(h.io.count("interceptor://enriched"), 0);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let failed =
        h.io.first("interceptor://enriched")
            .expect("failed after the timeout");
    assert_eq!(failed.0["phase"], "failed");
    assert_eq!(h.guard.gate(), Gate::Pending);

    tokio::time::sleep(Duration::from_secs(DEFAULT_HOLD_TTL_SECS)).await;
    assert_eq!(h.guard.gate(), Gate::Blocked);
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
    assert!(h.state.is_provider_blocked("anthropic").await);
}

#[tokio::test(start_paused = true)]
async fn test_killswitch_mid_alert_really_cancels_the_audit() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let dropped2 = Arc::clone(&dropped);
    let audit: AuditFn = Arc::new(move |_, _| {
        let guard = DropCounter(Arc::clone(&dropped2));
        Box::pin(async move {
            let _guard = guard;
            std::future::pending().await
        })
    });
    let h = harness(audit, "9.9.9.9").await;
    h.change("9.9.9.9").await;
    tokio::time::sleep(Duration::from_millis(50)).await; // the three audits are running
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(h.env.hold_queue.current_alert().is_some());

    assert!(h.guard.set_manual_killswitch(true, &h.state).await);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        3,
        "the audit futures were dropped"
    );
    assert_eq!(h.guard.gate(), Gate::Blocked);
    assert!(h.env.hold_queue.current_alert().is_none());
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);

    tokio::time::sleep(Duration::from_secs(40)).await;
    assert_eq!(h.io.count("interceptor://enriched"), 0);
    assert_eq!(h.guard.gate(), Gate::Blocked);
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
