use super::super::*;
use super::*;
use crate::state::InterceptionBehavior;
use std::sync::atomic::Ordering;
use tokio::time::Instant as TInstant;

#[tokio::test(start_paused = true)]
async fn test_window_shown_before_slow_audit_and_events_are_ordered() {
    let h = harness(
        slow_audit(Duration::from_secs(2), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    let started = TInstant::now();
    h.change("9.9.9.9").await;

    // Window-first: risk-detected (phase = detecting) fires immediately at t0 so user
    // gets instant feedback while traffic stays safely frozen (Pending) during slow audit.
    let (detected, detected_at) =
        h.io.wait_for("interceptor://risk-detected", 300)
            .await
            .expect("immediate risk-detected");
    assert!(detected_at.duration_since(started) < Duration::from_millis(300));
    assert_eq!(detected["phase"], "detecting");
    assert!(detected["report"].is_null());
    assert_eq!(detected["scope"], "network");
    assert_eq!(detected["is_simulation"], false);
    assert!(detected["detected_at_ms"].as_u64().unwrap() > 0);
    assert_eq!(detected["network_change"]["old_ip"], "1.1.1.1");
    assert_eq!(detected["network_change"]["old_country"], "DE");
    assert_eq!(detected["network_change"]["new_ip"], "9.9.9.9");
    assert!(detected["network_change"]["new_country"].is_null());
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.env.hold_queue.current_alert().expect("snapshot").phase,
        "detecting"
    );
    assert_eq!(
        h.io.trays.lock().unwrap().first().map(String::as_str),
        Some("yellow")
    );
    assert_eq!(h.guard.gate(), Gate::Pending);
    assert_eq!(h.io.count("interceptor://enriched"), 0);
    assert_eq!(h.io.count("network://changed"), 0);

    // Once the 2 s audit lands with Critical risk, enriched (phase = ready) and
    // network://changed are emitted.
    let (enriched, enriched_at) =
        h.io.wait_for("interceptor://enriched", 4000)
            .await
            .expect("enriched");
    assert!(enriched_at.duration_since(started) >= Duration::from_secs(2));
    assert_eq!(enriched["phase"], "ready");
    assert_eq!(enriched["network_change"]["new_country"], "NL");
    assert!(enriched["report"].is_object());

    let changed =
        h.io.wait_for("network://changed", 1000)
            .await
            .expect("network://changed");
    assert!(detected_at <= enriched_at && enriched_at <= changed.1);
    assert_eq!(h.guard.gate(), Gate::Pending);
    let snapshot = h.env.hold_queue.current_alert().expect("snapshot");
    assert_eq!(snapshot.phase, "ready");
    assert!(snapshot.report.is_some());
}

#[tokio::test(start_paused = true)]
async fn test_stale_audit_result_is_ignored() {
    let h = harness(
        slow_audit(Duration::from_millis(100), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    h.change("9.9.9.9").await;
    let first =
        h.io.first("interceptor://risk-detected")
            .expect("first immediate risk-detected");
    assert_eq!(first.0["phase"], "detecting");
    let first_id = alert_id(&first);
    let first_epoch = h.guard.inner.lock().await.epoch;

    // A newer change supersedes it (new id, new epoch).
    h.change("8.8.8.8").await;
    let second_epoch = h.guard.inner.lock().await.epoch;
    assert!(second_epoch > first_epoch);

    // Late result of the first alert: id no longer pending.
    h.guard
        .finish_audit(
            &h.env,
            &first_id,
            first_epoch,
            "9.9.9.9".into(),
            &["anthropic"],
            None,
            Instant::now(),
        )
        .await;
    // Current id but an old epoch: also dropped.
    let second_id = {
        let inner = h.guard.inner.lock().await;
        inner.pending.as_ref().expect("pending").id.clone()
    };
    h.guard
        .finish_audit(
            &h.env,
            &second_id,
            first_epoch,
            "8.8.8.8".into(),
            &["anthropic"],
            None,
            Instant::now(),
        )
        .await;
    assert_eq!(h.io.count("interceptor://enriched"), 0);

    // Only the current alert emits enriched (phase = ready).
    let enriched =
        h.io.wait_for("interceptor://enriched", 3000)
            .await
            .expect("enriched");
    assert_eq!(enriched.0["id"], second_id.as_str());
    assert_eq!(enriched.0["phase"], "ready");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(h.io.count("interceptor://enriched"), 1);
    assert_eq!(h.guard.gate(), Gate::Pending);
}

#[tokio::test(start_paused = true)]
async fn test_accept_cancels_inflight_audit() {
    let h = harness(
        slow_audit(Duration::from_millis(300), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    h.change("9.9.9.9").await;
    {
        let mut inner = h.guard.inner.lock().await;
        let tel =
            test_report(ProviderId::Anthropic, OverallStatus::Green, "9.9.9.9", "NL").telemetry;
        h.guard
            .accept_locked(&h.env, &mut inner, "9.9.9.9", &tel)
            .await;
        assert!(inner.pending.is_none());
        assert!(inner.audit_abort.is_none());
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(h.io.count("interceptor://enriched"), 0);
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
    assert_eq!(h.guard.gate(), Gate::Open);
    assert!(h.env.hold_queue.current_alert().is_none());
}

#[tokio::test(start_paused = true)]
async fn test_pinned_ip_with_green_audit_shows_no_window() {
    let h = harness(
        slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Green),
        "9.9.9.9",
    )
    .await;
    h.state
        .set_pinned_ip(Some("9.9.9.9".to_string()))
        .await
        .unwrap();
    h.change("9.9.9.9").await;
    h.io.wait_for("network://changed", 2000)
        .await
        .expect("pinned audit completed");
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.guard.gate(), Gate::Open);
    let inner = h.guard.inner.lock().await;
    assert_eq!(
        inner.baseline.as_ref().map(|b| b.ip.as_str()),
        Some("9.9.9.9")
    );
    assert!(inner.pending.is_none());
}

#[tokio::test(start_paused = true)]
async fn test_silent_behavior_freezes_immediately_and_blocks_without_popup() {
    let h = harness(
        slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    h.state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    h.change("9.9.9.9").await;
    // Freezes immediately at t=0ms with Pending gate and zero popup while async audit runs.
    assert_eq!(h.guard.gate(), Gate::Pending);
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);

    h.io.wait_for("network://changed", 2000)
        .await
        .expect("network://changed");
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.guard.gate(), Gate::Blocked);
    assert_eq!(h.io.count("network://changed"), 1);
}

#[tokio::test(start_paused = true)]
async fn test_audit_failure_keeps_gate_closed_and_does_not_reopen_window() {
    let failing: AuditFn = Arc::new(|_, _| Box::pin(async { Err("geo down".to_string()) }));
    let h = harness(failing, "9.9.9.9").await;
    h.change("9.9.9.9").await;
    assert_eq!(h.io.count("interceptor://risk-detected"), 1);

    let enriched =
        h.io.wait_for("interceptor://enriched", 3000)
            .await
            .expect("failed enriched");
    assert_eq!(enriched.0["phase"], "failed");
    assert_eq!(
        h.io.trays.lock().unwrap().last().map(String::as_str),
        Some("red")
    );
    assert!(enriched.0["report"].is_null());
    assert!(enriched.0["new_country"].is_null());
    // Fail-closed: still pending, not allowed to pass, no network://changed.
    assert_eq!(h.guard.gate(), Gate::Pending);
    let mut rx = h.guard.subscribe();
    assert!(
        tokio::time::timeout(Duration::from_millis(80), wait_open(&mut rx))
            .await
            .is_err(),
        "traffic must keep waiting"
    );
    assert_eq!(h.io.count("network://changed"), 0);

    // The next tick sees the same network: no second window.
    let env = h.env.clone();
    h.guard.check_route_and_tick(&env).await;
    assert_eq!(h.io.count("interceptor://risk-detected"), 1);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 1);
    assert_eq!(h.guard.gate(), Gate::Pending);
    let snapshot = h.env.hold_queue.current_alert().expect("alert stays");
    assert_eq!(snapshot.phase, "failed");
}

#[tokio::test(start_paused = true)]
async fn test_audit_timeout_is_a_failure() {
    let mut h = harness(
        slow_audit(Duration::from_secs(10), "9.9.9.9", OverallStatus::Green),
        "9.9.9.9",
    )
    .await;
    h.env.audit_timeout = Duration::from_millis(100);
    // Rebuild the guard around the shortened timeout.
    let guard = Arc::new(NetworkGuard::new());
    guard.install_env(h.env.clone());
    guard.register_self_weak();
    guard.inner.lock().await.baseline = h.guard.inner.lock().await.baseline.clone();
    h.guard = guard;
    h.change("9.9.9.9").await;
    let enriched =
        h.io.wait_for("interceptor://enriched", 2000)
            .await
            .expect("failed enrichment");
    assert_eq!(enriched.0["phase"], "failed");
    assert_eq!(h.guard.gate(), Gate::Pending);
}

#[tokio::test(start_paused = true)]
async fn test_decision_block_and_allow_after_ready_audit() {
    // Deny after audit is ready: providers blocked, gate Blocked, popup hidden.
    let h = harness(
        slow_audit(Duration::from_millis(50), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    h.change("9.9.9.9").await;
    let ev =
        h.io.wait_for("interceptor://risk-detected", 2000)
            .await
            .expect("risk-detected");
    let id = alert_id(&ev);
    assert!(h.env.hold_queue.resolve(&id, HoldResolution::Block).await);
    for _ in 0..200 {
        if h.guard.gate() == Gate::Blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(h.guard.gate(), Gate::Blocked);
    for p in KNOWN_PROVIDERS {
        assert!(h.state.is_provider_blocked(p).await);
    }
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);

    // Allow after the audit is ready: baseline becomes the new network, gate opens.
    let h = harness(
        slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    h.change("9.9.9.9").await;
    let enriched =
        h.io.wait_for("interceptor://enriched", 2000)
            .await
            .expect("ready enrichment");
    let id = enriched.0["id"].as_str().unwrap().to_string();
    assert!(h.env.hold_queue.resolve(&id, HoldResolution::Allow).await);
    for _ in 0..200 {
        if h.guard.gate() == Gate::Open {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(h.guard.gate(), Gate::Open);
    let inner = h.guard.inner.lock().await;
    assert_eq!(
        inner.baseline.as_ref().map(|b| b.ip.as_str()),
        Some("9.9.9.9")
    );
}

#[tokio::test(start_paused = true)]
async fn test_route_dirty_bypasses_probe_min_gap() {
    let h = harness(
        slow_audit(Duration::from_millis(10), "1.1.1.1", OverallStatus::Green),
        "1.1.1.1",
    )
    .await;
    let fp = compute_local_route_fingerprint(None);
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(fp);
        inner.last_probe = Some(Instant::now()); // a probe just ran: the min gap applies
    }
    let env = h.env.clone();

    // Nothing dirty: the min gap suppresses the probe.
    h.guard.check_route_and_tick(&env).await;
    assert_eq!(h.probes.load(Ordering::SeqCst), 0);

    // A CONNECT flagged the change (gate already closed): probed at once, gap ignored.
    h.guard.inner.lock().await.route_dirty = true;
    h.guard.set_gate(Gate::Pending);
    h.guard.check_route_and_tick(&env).await;
    assert_eq!(h.probes.load(Ordering::SeqCst), 1);
    assert!(!h.guard.inner.lock().await.route_dirty, "flag is consumed");
    // Probed IP == trusted baseline: the network did not really change.
    assert_eq!(h.guard.gate(), Gate::Open);
}

#[tokio::test(start_paused = true)]
async fn test_route_dirty_with_new_ip_freezes_gate_until_audit_completes() {
    let h = harness(
        slow_audit(Duration::from_secs(1), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        inner.last_probe = Some(Instant::now());
        inner.route_dirty = true;
    }
    h.guard.set_gate(Gate::Pending);
    let started = TInstant::now();
    let env = h.env.clone();
    h.guard.check_route_and_tick(&env).await;
    assert!(started.elapsed() < Duration::from_millis(300));
    // Alert-first emits detecting immediately while slow audit runs; gate stays Pending.
    let ev =
        h.io.first("interceptor://risk-detected")
            .expect("immediate risk-detected");
    assert_eq!(ev.0["phase"], "detecting");
    assert_eq!(h.guard.gate(), Gate::Pending);

    let enr =
        h.io.wait_for("interceptor://enriched", 2000)
            .await
            .expect("enriched after audit");
    assert_eq!(enr.0["phase"], "ready");
    assert_eq!(h.guard.gate(), Gate::Pending);
}

#[tokio::test(start_paused = true)]
async fn test_audit_all_forces_only_first_and_isolates_failures() {
    let calls: Arc<std::sync::Mutex<Vec<(ProviderId, bool)>>> = Arc::default();
    let calls2 = Arc::clone(&calls);
    let audit: AuditFn = Arc::new(move |provider, force| {
        calls2.lock().unwrap().push((provider, force));
        Box::pin(async move {
            if provider == ProviderId::Openai {
                Err("openai down".to_string())
            } else {
                Ok(test_report(provider, OverallStatus::Green, "9.9.9.9", "NL"))
            }
        })
    });
    let results = audit_all(&audit).await;
    let providers: Vec<ProviderId> = results.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        providers,
        vec![
            ProviderId::Anthropic,
            ProviderId::Openai,
            ProviderId::Gemini
        ]
    );
    assert!(results[0].1.is_ok() && results[1].1.is_err() && results[2].1.is_ok());
    let calls = calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .all(|(p, force)| *force == (*p == ProviderId::Anthropic))
    );
    // Anthropic (1) + OpenAI (1 + 1 retry) + Gemini (1) = 4
    assert_eq!(calls.len(), 4);
}

#[tokio::test(start_paused = true)]
async fn test_audit_all_retries_transient_openai_and_gemini_failures() {
    let attempts: Arc<std::sync::Mutex<std::collections::HashMap<ProviderId, usize>>> =
        Arc::default();
    let attempts2 = Arc::clone(&attempts);
    let audit: AuditFn = Arc::new(move |provider, _force| {
        let mut map = attempts2.lock().unwrap();
        let count = map.entry(provider).or_insert(0);
        *count += 1;
        let n = *count;
        Box::pin(async move {
            if matches!(provider, ProviderId::Openai | ProviderId::Gemini) && n == 1 {
                Err("transient interface shake".to_string())
            } else {
                Ok(test_report(provider, OverallStatus::Green, "9.9.9.9", "NL"))
            }
        })
    });
    let results = audit_all(&audit).await;
    assert!(results.iter().all(|(_, r)| r.is_ok()));
    let map = attempts.lock().unwrap();
    assert_eq!(map.get(&ProviderId::Anthropic), Some(&1));
    assert_eq!(map.get(&ProviderId::Openai), Some(&2));
    assert_eq!(map.get(&ProviderId::Gemini), Some(&2));
}

#[test]
fn test_summarize_failure_rules() {
    let ok = |p| (p, Ok(test_report(p, OverallStatus::Green, "9.9.9.9", "NL")));
    let err = |p| (p, Err::<RiskReport, String>("x".to_string()));
    let all = ["anthropic", "openai", "gemini"];

    // First provider failed while siblings succeeded: preserve sibling results and track the
    // failed provider instead of returning None.
    let r = vec![
        err(ProviderId::Anthropic),
        ok(ProviderId::Openai),
        ok(ProviderId::Gemini),
    ];
    let s = summarize(&r, &all).expect("sibling reports must be preserved");
    assert!(!s.all_green);
    assert!(!s.no_critical_and_geo_ok);
    assert_eq!(s.healthy_providers, vec!["openai", "gemini"]);
    assert_eq!(s.affected_providers, vec!["anthropic"]);
    assert_eq!(s.critical_providers, vec!["anthropic"]);
    assert_eq!(s.failed_providers, vec!["anthropic"]);
    // ...and when that failed provider is routed, unrouted siblings are all green.
    let s = summarize(&r, &["openai", "gemini"]).expect("openai & gemini are healthy");
    assert!(s.all_green);
    assert!(s.failed_providers.is_empty());

    // Only when ALL unrouted providers fail does summarize return None.
    assert!(summarize(&r, &["anthropic"]).is_none());
    let all_err = vec![
        err(ProviderId::Anthropic),
        err(ProviderId::Openai),
        err(ProviderId::Gemini),
    ];
    assert!(summarize(&all_err, &all).is_none());

    // Another provider failed: the rest survives, but "all green" is no longer provable.
    let r = vec![
        ok(ProviderId::Anthropic),
        err(ProviderId::Openai),
        ok(ProviderId::Gemini),
    ];
    let s = summarize(&r, &all).expect("anthropic & gemini are healthy");
    assert!(!s.all_green);
    assert_eq!(s.healthy_providers, vec!["anthropic", "gemini"]);
    assert_eq!(s.affected_providers, vec!["openai"]);
    assert_eq!(s.failed_providers, vec!["openai"]);
    let s = summarize(&r, &["anthropic", "gemini"]).unwrap();
    assert!(s.all_green);
}
