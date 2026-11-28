use super::*;
use crate::auditor::CheckResult;
use std::sync::atomic::{AtomicUsize, Ordering};

const BASELINE_IP: &str = "103.139.51.30";

fn partial_block_audit(calls: Arc<AtomicUsize>) -> AuditFn {
    Arc::new(move |provider, _force| {
        calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            match provider {
                ProviderId::Openai => Ok(test_report(
                    provider,
                    OverallStatus::Green,
                    BASELINE_IP,
                    "SE",
                )),
                ProviderId::Anthropic | ProviderId::Gemini => {
                    let mut r = test_report(provider, OverallStatus::Red, BASELINE_IP, "SE");
                    r.travel_result =
                        CheckResult::critical("IMPOSSIBLE_TRAVEL_CRITICAL", "RU -> SE", None);
                    r.checks = vec![r.travel_result.clone()];
                    Ok(r)
                }
            }
        })
    })
}

async fn setup_partial_block_harness(calls: Arc<AtomicUsize>) -> Harness {
    let h = harness(partial_block_audit(calls), BASELINE_IP).await;
    h.state
        .add_trusted_exception("anthropic", BASELINE_IP)
        .await
        .unwrap();
    h.state.block_provider("gemini").await.unwrap();
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: BASELINE_IP.to_string(),
            country: Some("SE".to_string()),
            trusted: true,
        });
        inner.observed_ip = Some(BASELINE_IP.to_string());
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }
    h.guard.sync_gates_with_state(&h.state).await;
    h
}

#[tokio::test(start_paused = true)]
async fn test_partial_block_steady_state_no_verify_storm_and_recovers_on_exception_or_pin() {
    let audit_calls = Arc::new(AtomicUsize::new(0));
    let h = setup_partial_block_harness(Arc::clone(&audit_calls)).await;

    // Initial tick latches `handled_ip` for the partial-blocked baseline without emitting popup/UI storms.
    h.guard.check_route_and_tick(&h.env).await;
    h.guard.wait_probe_settled_for_test().await;
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Blocked);
    assert_eq!(
        h.guard.inner.lock().await.handled_ip.as_deref(),
        Some(BASELINE_IP)
    );
    assert_eq!(h.io.count("interceptor://resolved"), 0);
    assert_eq!(h.io.count("network://changed"), 0);

    let calls_after_settle = audit_calls.load(Ordering::SeqCst);
    assert!(calls_after_settle >= 3);

    // 5 consecutive regular ticks on the same baseline must NOT re-spawn baseline verification or emit UI events.
    for _ in 0..5 {
        h.guard.inner.lock().await.last_probe = None;
        h.guard.check_route_and_tick(&h.env).await;
        h.guard.wait_probe_settled_for_test().await;
        assert!(!h.guard.is_verify_in_flight());
    }
    assert_eq!(audit_calls.load(Ordering::SeqCst), calls_after_settle);
    assert_eq!(h.io.count("interceptor://resolved"), 0);
    assert_eq!(h.io.count("network://changed"), 0);
    assert!(h.state.is_provider_blocked("gemini").await);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Blocked);

    // Zero-Regression: adding `trusted_exceptions` for `gemini` auto-unblocks on next tick.
    h.state
        .add_trusted_exception("gemini", BASELINE_IP)
        .await
        .unwrap();
    h.guard.inner.lock().await.last_probe = None;
    h.guard.check_route_and_tick(&h.env).await;
    h.guard.wait_probe_settled_for_test().await;

    assert!(!h.state.is_provider_blocked("gemini").await);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
    assert!(h.io.count("interceptor://resolved") >= 1);
    assert!(h.io.count("network://changed") >= 1);

    // Zero-Regression: `pinned_ip` for a blocked provider also auto-unblocks on next tick.
    let audit_calls_pin = Arc::new(AtomicUsize::new(0));
    let h_pin = setup_partial_block_harness(Arc::clone(&audit_calls_pin)).await;
    h_pin.guard.check_route_and_tick(&h_pin.env).await;
    h_pin.guard.wait_probe_settled_for_test().await;
    assert_eq!(h_pin.io.count("interceptor://resolved"), 0);
    assert_eq!(h_pin.io.count("network://changed"), 0);

    h_pin
        .state
        .set_pinned_ip_for("gemini", Some(BASELINE_IP.to_string()))
        .await
        .unwrap();
    h_pin.guard.inner.lock().await.last_probe = None;
    h_pin.guard.check_route_and_tick(&h_pin.env).await;
    h_pin.guard.wait_probe_settled_for_test().await;

    assert!(!h_pin.state.is_provider_blocked("gemini").await);
    assert_eq!(h_pin.guard.gate_for(ProviderId::Gemini), Gate::Open);
    assert!(h_pin.io.count("interceptor://resolved") >= 1);
    assert!(h_pin.io.count("network://changed") >= 1);
}

#[tokio::test(start_paused = true)]
async fn test_probe_changed_ask_popup_to_silent_or_paused_hides_popup_without_spurious_hides() {
    // 1. No prior popup under AutoLockSilent: `begin_changed_probe` must NOT emit spurious `hide_popup`.
    let h = harness(
        slow_audit(Duration::from_millis(50), "2.2.2.2", OverallStatus::Yellow),
        "2.2.2.2",
    )
    .await;
    h.state
        .set_interception_behavior(crate::state::InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    h.guard
        .begin_changed_probe(&h.env, Instant::now(), "fp-silent-0".to_string(), false)
        .await;
    assert_eq!(h.io.hides.load(Ordering::SeqCst), 0);
    assert_eq!(h.io.count("interceptor://resolved"), 0);
    h.guard.wait_probe_settled_for_test().await;

    // 2. AskPopup alert active (`alert_emitted` + shown popup) -> switch to AutoLockSilent -> route change
    //    must immediately hide the old popup and emit `interceptor://resolved`.
    h.state
        .set_interception_behavior(crate::state::InterceptionBehavior::AskPopup)
        .await
        .unwrap();
    h.guard
        .begin_changed_probe(&h.env, Instant::now(), "fp-ask-1".to_string(), false)
        .await;
    {
        let mut inner = h.guard.inner.lock().await;
        let alert_id = inner
            .pending
            .as_ref()
            .expect("pending AskPopup alert")
            .id
            .clone();
        assert!(inner.pending.as_ref().unwrap().alert_emitted);
        inner.popup_shown_alert_id = Some(alert_id);
    }

    h.state
        .set_interception_behavior(crate::state::InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    let hides_before = h.io.hides.load(Ordering::SeqCst);
    let resolved_before = h.io.count("interceptor://resolved");
    h.guard
        .begin_changed_probe(&h.env, Instant::now(), "fp-silent-2".to_string(), false)
        .await;
    assert!(h.io.hides.load(Ordering::SeqCst) > hides_before);
    assert!(h.io.count("interceptor://resolved") > resolved_before);
    h.guard.wait_probe_settled_for_test().await;

    // 3. AskPopup alert active -> PauseMode::UntilNetworkChange -> route change also hides the old popup.
    h.state
        .set_interception_behavior(crate::state::InterceptionBehavior::AskPopup)
        .await
        .unwrap();
    h.guard
        .begin_changed_probe(&h.env, Instant::now(), "fp-ask-3".to_string(), false)
        .await;
    assert!(
        h.guard
            .inner
            .lock()
            .await
            .pending
            .as_ref()
            .is_some_and(|p| p.alert_emitted)
    );
    h.guard.set_pause_mode_raw(PauseMode::UntilNetworkChange);
    let hides_before_pause = h.io.hides.load(Ordering::SeqCst);
    let resolved_before_pause = h.io.count("interceptor://resolved");
    h.guard
        .begin_changed_probe(&h.env, Instant::now(), "fp-paused-4".to_string(), false)
        .await;
    assert!(h.io.hides.load(Ordering::SeqCst) > hides_before_pause);
    assert!(h.io.count("interceptor://resolved") > resolved_before_pause);
    h.guard.wait_probe_settled_for_test().await;
}
