use super::super::*;
use super::*;
use crate::state::InterceptionBehavior;
use std::sync::atomic::Ordering;

fn asn_jump_audit(ip: &'static str, cc: &'static str) -> AuditFn {
    Arc::new(move |provider, _force| {
        Box::pin(async move {
            let mut r = test_report(provider, OverallStatus::Yellow, ip, cc);
            let jump = CheckResult::warning(
                "TRAVEL_ASN_JUMP_SAME_COUNTRY",
                "Резкая смена дата-центра/ASN внутри NL (AS20473 -> AS24940) за 10м без 4-часовой паузы.",
                None,
            );
            r.travel_result = jump.clone();
            r.checks = vec![
                CheckResult::ok("GEO_ALLOWED", cc),
                CheckResult::ok("STRICT_PINNING_DISABLED", "ok"),
                jump,
            ];
            Ok(r)
        })
    })
}

#[tokio::test(start_paused = true)]
async fn guard_holds_and_requires_confirmation_on_same_country_asn_jump() {
    let h = harness(asn_jump_audit("95.217.1.1", "NL"), "95.217.1.1").await;
    h.change("95.217.1.1").await;

    let ev = h
        .io
        .wait_for("interceptor://enriched", 2000)
        .await
        .expect("enriched alert on TRAVEL_ASN_JUMP_SAME_COUNTRY");
    assert_eq!(ev.0["phase"], "ready");
    let gate_reason = ev.0["gate_reason"].as_str().unwrap_or("");
    assert!(
        gate_reason.contains("TRAVEL_ASN_JUMP_SAME_COUNTRY"),
        "unexpected gate_reason: {gate_reason}"
    );
    assert_eq!(h.guard.gate(), Gate::Pending);
    assert!(h.env.hold_queue.current_alert().is_some());

    // Explicit user Allow opens the gate and persists trusted_exception.
    let id = ev.0["id"].as_str().unwrap().to_string();
    h.guard
        .allow_network_alert(&id, &all_providers())
        .await
        .expect("explicit allow");
    assert_eq!(h.guard.gate(), Gate::Open);
    assert!(
        h.state
            .is_ip_trusted_for_provider("anthropic", "95.217.1.1")
            .await
    );
}

#[tokio::test(start_paused = true)]
async fn guard_blocks_under_auto_lock_silent_on_same_country_asn_jump() {
    let h = harness(asn_jump_audit("95.217.1.1", "NL"), "95.217.1.1").await;
    h.state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    h.change("95.217.1.1").await;

    h.io
        .wait_for("network://changed", 2000)
        .await
        .expect("network://changed");
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.guard.gate(), Gate::Blocked);
    for p in KNOWN_PROVIDERS {
        assert!(h.state.is_provider_blocked(p).await);
    }
    assert!(
        h.guard
            .gate_reason()
            .as_deref()
            .is_some_and(|r| r.contains("TRAVEL_ASN_JUMP_SAME_COUNTRY"))
    );
}

#[tokio::test(start_paused = true)]
async fn guard_still_allows_pinned_ip_return_without_popup() {
    let h = harness(asn_jump_audit("95.217.1.1", "NL"), "95.217.1.1").await;
    h.state
        .set_pinned_ip(Some("95.217.1.1".to_string()))
        .await
        .unwrap();
    h.change("95.217.1.1").await;

    h.io
        .wait_for("network://changed", 2000)
        .await
        .expect("pinned IP accepted");
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.guard.gate(), Gate::Open);
}

#[tokio::test(start_paused = true)]
async fn guard_enforces_ip_change_cooldown_under_ask_popup_and_auto_lock_silent() {
    // 1. AskPopup with active 4h cooldown holds even on a Green audit with Russian reason text.
    let h = harness(
        slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Green),
        "9.9.9.9",
    )
    .await;
    h.state.start_ip_change_cooldown(14_400).await.unwrap();
    h.change("9.9.9.9").await;

    let ev = h
        .io
        .wait_for("interceptor://enriched", 2000)
        .await
        .expect("enriched cooldown alert");
    assert_eq!(ev.0["phase"], "ready");
    let reason = ev.0["gate_reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("охлаждения"),
        "expected Russian cooldown reason, got: {reason}"
    );
    assert_eq!(h.guard.gate(), Gate::Pending);

    // Explicit allow opens gate.
    let id = ev.0["id"].as_str().unwrap().to_string();
    h.guard
        .allow_network_alert(&id, &all_providers())
        .await
        .expect("allow during cooldown");
    assert_eq!(h.guard.gate(), Gate::Open);

    // 2. AutoLockSilent with active 4h cooldown blocks instead of silent accept_locked.
    let h2 = harness(
        slow_audit(Duration::from_millis(20), "8.8.8.8", OverallStatus::Green),
        "8.8.8.8",
    )
    .await;
    h2.state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    h2.state.start_ip_change_cooldown(14_400).await.unwrap();
    h2.change("8.8.8.8").await;

    h2.io
        .wait_for("network://changed", 2000)
        .await
        .expect("network://changed");
    assert_eq!(h2.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h2.guard.gate(), Gate::Blocked);
    assert!(
        h2.guard
            .gate_reason()
            .as_deref()
            .is_some_and(|r| r.contains("охлаждения"))
    );

    // 3. Clearing cooldown allows subsequent Green IP change silently.
    h2.state.clear_ip_change_cooldown().await.unwrap();
    h2.change("7.7.7.7").await;
    h2.io
        .wait_for_count("network://changed", 2, 2000)
        .await
        .expect("network://changed after cooldown cleared");
    assert_eq!(h2.guard.gate(), Gate::Open);
    assert!(h2.state.get_data().await.blocked_providers.is_empty());
}

#[tokio::test(start_paused = true)]
async fn guard_allows_pinned_ip_even_during_active_cooldown() {
    let h = harness(
        slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Green),
        "9.9.9.9",
    )
    .await;
    h.state
        .set_pinned_ip(Some("9.9.9.9".to_string()))
        .await
        .unwrap();
    h.state.start_ip_change_cooldown(14_400).await.unwrap();
    h.change("9.9.9.9").await;

    h.io
        .wait_for("network://changed", 2000)
        .await
        .expect("pinned IP allowed during cooldown");
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
    assert_eq!(h.guard.gate(), Gate::Open);
}
