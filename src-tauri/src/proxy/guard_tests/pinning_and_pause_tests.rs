use super::super::*;
use super::*;
use crate::auditor::CheckResult;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test(start_paused = true)]
async fn test_returning_to_pinned_ip_after_blocked_audits_and_clears_blocked_providers() {
    let current_ip = Arc::new(std::sync::Mutex::new("9.9.9.9".to_string()));
    let probe_ip = Arc::clone(&current_ip);
    let audit_calls: Arc<std::sync::Mutex<Vec<ProviderId>>> = Arc::default();
    let audit_calls2 = Arc::clone(&audit_calls);
    let current_ip_audit = Arc::clone(&current_ip);
    let audit: AuditFn = Arc::new(move |provider, _force| {
        audit_calls2.lock().unwrap().push(provider);
        let ip = current_ip_audit.lock().unwrap().clone();
        Box::pin(async move {
            if ip == "9.9.9.9" {
                Ok(test_report(provider, OverallStatus::Red, "9.9.9.9", "RU"))
            } else {
                // Non-critical Yellow warning on pinned IP must still auto-restore.
                let mut r = test_report(provider, OverallStatus::Yellow, "1.1.1.1", "DE");
                r.checks = vec![
                    CheckResult::ok("Geo", "ok"),
                    CheckResult::warning("Timezone", "mismatch", None),
                ];
                Ok(r)
            }
        })
    });

    let io = Arc::new(TestIo::default());
    let state = AppState::new_in_memory();
    state
        .set_pinned_ip(Some("1.1.1.1".to_string()))
        .await
        .unwrap();
    state
        .set_interception_behavior(crate::state::InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    let probe: ProbeFn = Arc::new(move || {
        let ip = probe_ip.lock().unwrap().clone();
        Box::pin(async move { Some(ip) })
    });
    let env = Env {
        auditor: Auditor::new().expect("auditor"),
        state: state.clone(),
        hold_queue: Arc::new(HoldQueue::new()),
        io: io.clone(),
        audit,
        probe: Some(probe),
        resolve: None,
        audit_timeout: Duration::from_secs(5),
    };
    let guard = Arc::new(NetworkGuard::new());
    assert!(guard.install_env(env.clone()));
    {
        let mut inner = guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "1.1.1.1".to_string(),
            country: Some("DE".to_string()),
            trusted: true,
        });
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }

    // 1. Drop to RU -> immediately freezes Pending, then async silent audit blocks all 3.
    guard.inner.lock().await.route_dirty = true;
    guard.check_route_and_tick(&env).await;
    assert_eq!(guard.gate(), Gate::Pending);
    io.wait_for("network://changed", 2000)
        .await
        .expect("silent block event");
    assert_eq!(guard.gate(), Gate::Blocked);
    assert!(guard.inner.lock().await.pending.is_none());
    for p in KNOWN_PROVIDERS {
        assert!(state.is_provider_blocked(p).await);
    }
    let changed_before = io.count("network://changed");
    audit_calls.lock().unwrap().clear();

    // 2. Return to previously pinned IP ("1.1.1.1") -> clears blocked_providers, opens gate
    // immediately, emits network://changed, and verifies all 3 providers asynchronously.
    *current_ip.lock().unwrap() = "1.1.1.1".to_string();
    guard.inner.lock().await.route_dirty = true;
    guard.check_route_and_tick(&env).await;
    io.wait_for_count("network://changed", changed_before + 1, 2000)
        .await
        .expect("restored network://changed");
    for _ in 0..40 {
        if audit_calls.lock().unwrap().len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert_eq!(guard.gate(), Gate::Open);
    assert!(guard.inner.lock().await.handled_ip.is_none());
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert_eq!(io.count("network://changed"), changed_before + 1);
    let audited = audit_calls.lock().unwrap();
    assert!(audited.contains(&ProviderId::Anthropic));
    assert!(audited.contains(&ProviderId::Openai));
    assert!(audited.contains(&ProviderId::Gemini));
}

#[tokio::test(start_paused = true)]
async fn test_returning_to_baseline_with_critical_audit_stays_blocked() {
    let audit: AuditFn = Arc::new(move |provider, _force| {
        Box::pin(async move { Ok(test_report(provider, OverallStatus::Red, "1.1.1.1", "RU")) })
    });
    let io = Arc::new(TestIo::default());
    let state = AppState::new_in_memory();
    state.block_provider("anthropic").await.unwrap();
    let probe: ProbeFn = Arc::new(|| Box::pin(async { Some("1.1.1.1".to_string()) }));
    let env = Env {
        auditor: Auditor::new().expect("auditor"),
        state: state.clone(),
        hold_queue: Arc::new(HoldQueue::new()),
        io,
        audit,
        probe: Some(probe),
        resolve: None,
        audit_timeout: Duration::from_secs(5),
    };
    let guard = Arc::new(NetworkGuard::new());
    assert!(guard.install_env(env.clone()));
    {
        let mut inner = guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "1.1.1.1".to_string(),
            country: Some("DE".to_string()),
            trusted: true,
        });
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }
    guard.set_gate(Gate::Blocked);
    guard.inner.lock().await.route_dirty = true;
    guard.check_route_and_tick(&env).await;

    assert_eq!(guard.gate(), Gate::Blocked);
    assert!(state.is_provider_blocked("anthropic").await);
}

#[tokio::test(start_paused = true)]
async fn test_transient_route_flicker_on_non_pinned_warning_network_recovers_and_keeps_allows()
{
    let probe_calls = Arc::new(AtomicUsize::new(0));
    let probe_calls2 = Arc::clone(&probe_calls);
    let probe: ProbeFn = Arc::new(move || {
        let n = probe_calls2.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if n == 0 {
                None // brief DNS/socket hiccup during local route flicker
            } else {
                Some("8.8.8.8".to_string())
            }
        })
    });
    let audit: AuditFn = Arc::new(move |provider, _force| {
        Box::pin(async move {
            let mut r = test_report(provider, OverallStatus::Yellow, "8.8.8.8", "NL");
            r.unknown_count = 1;
            r.checks = vec![
                CheckResult::ok("Geo", "ok"),
                CheckResult::warning("Timezone", "mismatch", None),
            ];
            Ok(r)
        })
    });

    let io = Arc::new(TestIo::default());
    let state = AppState::new_in_memory();
    // Not pinned, user has a session allowance on this warning network.
    state.allow_provider_for_session("anthropic").await.unwrap();
    let env = Env {
        auditor: Auditor::new().expect("auditor"),
        state: state.clone(),
        hold_queue: Arc::new(HoldQueue::new()),
        io: io.clone(),
        audit,
        probe: Some(probe),
        resolve: None,
        audit_timeout: Duration::from_secs(5),
    };
    let guard = Arc::new(NetworkGuard::new());
    assert!(guard.install_env(env.clone()));
    {
        let mut inner = guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "8.8.8.8".to_string(),
            country: Some("NL".to_string()),
            trusted: true,
        });
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }

    // 1. Transient route flicker where probe returns None: stays recoverable (not Blocked)
    //    and preserves session_allowed_providers.
    guard.inner.lock().await.route_dirty = true;
    guard.check_route_and_tick(&env).await;
    assert_eq!(guard.gate(), Gate::Pending);
    assert!(state.is_provider_session_allowed("anthropic").await);
    assert!(state.get_data().await.blocked_providers.is_empty());

    // 2. Next regular probe gets unchanged IP "8.8.8.8" on non-pinned warning network:
    //    restores Gate::Open and keeps session allowance.
    guard.inner.lock().await.last_probe =
        Instant::now().checked_sub(Duration::from_millis(PROBE_MIN_GAP_MS + 10));
    guard.check_route_and_tick(&env).await;
    assert_eq!(probe_calls.load(Ordering::SeqCst), 2);
    assert_eq!(guard.gate(), Gate::Open);
    assert!(state.is_provider_session_allowed("anthropic").await);
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert_eq!(io.count("interceptor://risk-detected"), 0);
}

#[tokio::test(start_paused = true)]
async fn test_confirm_current_session_marks_untrusted_baseline_trusted() {
    let h = harness(
        slow_audit(Duration::from_millis(10), "5.5.5.5", OverallStatus::Red),
        "5.5.5.5",
    )
    .await;
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "5.5.5.5".to_string(),
            country: Some("RU".to_string()),
            trusted: false,
        });
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }
    assert_eq!(h.guard.gate(), Gate::Open);

    let tel = test_report(ProviderId::Anthropic, OverallStatus::Red, "5.5.5.5", "RU").telemetry;
    h.guard.confirm_current_session(Some(&tel)).await;
    {
        let inner = h.guard.inner.lock().await;
        assert!(inner.baseline.as_ref().is_some_and(|b| b.trusted));
        assert!(inner.handled_ip.is_none());
    }

    // Subsequent regular probe on the same IP must not freeze or open an alert.
    let probes_before = h.probes.load(Ordering::SeqCst);
    h.guard.inner.lock().await.last_probe =
        Instant::now().checked_sub(Duration::from_millis(PROBE_MIN_GAP_MS + 10));
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.probes.load(Ordering::SeqCst), probes_before + 1);
    assert_eq!(h.guard.gate(), Gate::Open);
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    assert!(h.state.get_data().await.blocked_providers.is_empty());

    // Manual kill-switch must not be lifted by confirm_current_session.
    assert!(h.guard.set_manual_killswitch(true, &h.state).await);
    h.guard.confirm_current_session(Some(&tel)).await;
    assert_eq!(h.guard.gate(), Gate::Blocked);
    assert!(h.guard.is_manual_killswitch());
}

#[tokio::test(start_paused = true)]
async fn test_regular_probe_on_untrusted_baseline_respects_all_session_allowed() {
    let h = harness(
        slow_audit(Duration::from_millis(10), "5.5.5.5", OverallStatus::Red),
        "5.5.5.5",
    )
    .await;
    for p in KNOWN_PROVIDERS {
        h.state.allow_provider_for_session(p).await.unwrap();
    }
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "5.5.5.5".to_string(),
            country: Some("RU".to_string()),
            trusted: false,
        });
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }

    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.gate(), Gate::Open);
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    assert!(
        h.guard
            .inner
            .lock()
            .await
            .baseline
            .as_ref()
            .is_some_and(|b| b.trusted)
    );
    for p in KNOWN_PROVIDERS {
        assert!(h.state.is_provider_session_allowed(p).await);
    }
}

#[test]
fn test_effective_tray_report_downgrades_red_when_session_allowed_and_open() {
    let report = test_report(ProviderId::Anthropic, OverallStatus::Red, "5.5.5.5", "RU");
    let mut st = crate::state::AppStateData::default();
    assert_eq!(
        effective_tray_report(&report, false, &st).overall_status,
        OverallStatus::Red
    );

    st.session_allowed_providers.insert("anthropic".to_string());
    assert_eq!(
        effective_tray_report(&report, false, &st).overall_status,
        OverallStatus::Yellow
    );
    // When actually blocked/pending, keep Red.
    assert_eq!(
        effective_tray_report(&report, true, &st).overall_status,
        OverallStatus::Red
    );
}

#[tokio::test(start_paused = true)]
async fn test_split_tunnel_mode_ignores_1_1_1_1_exit_ip_jitter() {
    let h = harness(
        slow_audit(Duration::from_millis(10), "5.5.5.5", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;
    h.state.set_split_tunnel_mode(true).await.unwrap();
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        inner.route_dirty = true;
    }

    // Baseline is "1.1.1.1", fake probe returns "9.9.9.9" + route_dirty:
    // split_tunnel_mode must NOT trip, show alert popup, block providers, or freeze the gate.
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.gate(), Gate::Open);
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    assert!(h.state.get_data().await.blocked_providers.is_empty());
    assert_eq!(
        h.guard.inner.lock().await.observed_ip.as_deref(),
        Some("9.9.9.9")
    );
}

#[tokio::test(start_paused = true)]
async fn gate_reason_populated_on_ready_risk_detected_event() {
    let h = harness(
        slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
        "9.9.9.9",
    )
    .await;

    let fp = compute_local_route_fingerprint(None);
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_route_fp = Some(format!("{fp}-old"));
        inner.route_dirty = true;
    }
    h.guard.check_route_and_tick(&h.env).await;

    // Window-first: detecting alert emitted immediately before slow audit completes.
    let det = h
        .env
        .hold_queue
        .current_alert()
        .expect("detecting alert emitted immediately");
    assert_eq!(det.phase, PHASE_DETECTING);
    assert!(
        det.gate_reason
            .as_deref()
            .is_some_and(|r| !r.trim().is_empty()),
        "expected detecting gate_reason, got {:?}",
        det.gate_reason
    );

    h.io.wait_for("interceptor://enriched", 1000)
        .await
        .expect("enriched ready event emitted");

    let ready = h
        .env
        .hold_queue
        .current_alert()
        .expect("alert still held after audit");
    assert_eq!(ready.phase, PHASE_READY);
    assert!(
        ready
            .gate_reason
            .as_deref()
            .is_some_and(|r| !r.trim().is_empty()),
        "expected ready gate_reason, got {:?}",
        ready.gate_reason
    );
    assert_eq!(h.guard.gate_reason(), ready.gate_reason);
}

#[tokio::test(start_paused = true)]
async fn pause_until_network_change_stays_on_same_ip_and_clears_on_change_or_invalidate_cache()
{
    let probe_ip = Arc::new(std::sync::Mutex::new("1.1.1.1".to_string()));
    let probe_ip_env = Arc::clone(&probe_ip);
    let h = harness_env(
        slow_audit(Duration::from_millis(10), "1.1.1.1", OverallStatus::Green),
        "1.1.1.1",
        move |env| {
            env.probe = Some(Arc::new(move || {
                let ip = probe_ip_env.lock().unwrap().clone();
                Box::pin(async move { Some(ip) })
            }));
        },
    )
    .await;

    // 1. Engage PauseMode::UntilNetworkChange on baseline 1.1.1.1.
    let status = h
        .guard
        .pause_until_network_change(&h.state, Some("Пауза на время теста".to_string()))
        .await;
    assert!(status.paused);
    assert_eq!(status.mode, PauseMode::UntilNetworkChange);
    assert_eq!(status.gate, "blocked");
    assert_eq!(status.gate_reason.as_deref(), Some("Пауза на время теста"));
    assert_eq!(h.guard.gate(), Gate::Blocked);
    assert!(!h.state.get_data().await.blocked_providers.is_empty());

    // Same IP tick (after probe interval) MUST keep PauseMode::UntilNetworkChange.
    tokio::time::advance(Duration::from_secs(2)).await;
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.pause_mode(), PauseMode::UntilNetworkChange);
    assert_eq!(h.guard.gate(), Gate::Blocked);

    // 2. invalidate_cache_and_clear_pause automatically clears UntilNetworkChange pause.
    let dummy_tel = NetworkTelemetry {
        ip: "1.1.1.1".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: None,
        org: None,
        isp: None,
        timezone: None,
        resolved_at: crate::auditor::network::current_timestamp(),
    };
    h.env.auditor.resolver.set_cached(dummy_tel).await;
    let cleared = h
        .guard
        .invalidate_cache_and_clear_pause(&h.env.auditor.resolver, Some(&h.state))
        .await;
    assert!(cleared);
    assert_eq!(h.guard.pause_mode(), PauseMode::None);
    assert_eq!(h.guard.gate(), Gate::Open);
    assert!(h.guard.gate_reason().is_none());
    assert!(h.state.get_data().await.blocked_providers.is_empty());

    // 3. Re-engage UntilNetworkChange and trigger a real IP/network change on next tick -> cleared.
    h.guard
        .pause_until_network_change(&h.state, Some("Ждём новую сеть".to_string()))
        .await;
    assert_eq!(h.guard.pause_mode(), PauseMode::UntilNetworkChange);
    {
        let mut w = probe_ip.lock().unwrap();
        *w = "9.9.9.9".to_string();
    }
    {
        // `last_probe` uses `std::time::Instant`; clear it so the next tick runs the probe.
        let mut inner = h.guard.inner.lock().await;
        inner.last_probe = None;
    }
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.pause_mode(), PauseMode::None);

    // 4. Manual kill-switch must NEVER clear on invalidate_cache_and_clear_pause.
    h.guard.set_manual_killswitch(true, &h.state).await;
    assert_eq!(h.guard.pause_mode(), PauseMode::Manual);
    assert!(
        !h.guard
            .invalidate_cache_and_clear_pause(&h.env.auditor.resolver, Some(&h.state))
            .await
    );
    assert_eq!(h.guard.pause_mode(), PauseMode::Manual);
    assert_eq!(h.guard.gate(), Gate::Blocked);
}

