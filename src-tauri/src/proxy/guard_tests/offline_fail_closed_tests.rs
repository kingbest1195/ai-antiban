use super::*;
use crate::auditor::network::{NetworkTelemetry, current_timestamp};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::Instant as TInstant;

#[tokio::test]
async fn test_regular_probe_offline_freezes_gate_clears_session_invalidates_cache_under_150ms() {
    let online = Arc::new(AtomicBool::new(true));
    let online_flag = Arc::clone(&online);
    let h = harness_env(
        slow_audit(Duration::from_millis(10), "1.1.1.1", OverallStatus::Green),
        "1.1.1.1",
        move |env| {
            env.probe = Some(Arc::new(move || {
                let is_on = online_flag.load(Ordering::SeqCst);
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

    h.state
        .allow_provider_for_session("anthropic")
        .await
        .expect("session allow");
    h.env
        .auditor
        .resolver
        .set_cached(NetworkTelemetry {
            ip: "1.1.1.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(13335),
            org: Some("Cloudflare".to_string()),
            isp: Some("Cloudflare".to_string()),
            timezone: Some("Europe/Amsterdam".to_string()),
            resolved_at: current_timestamp(),
        })
        .await;
    let abort_rx = h.guard.subscribe_tunnel_abort();
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert!(
        h.env
            .auditor
            .resolver
            .cached_direct_country("1.1.1.1")
            .await
            .is_some()
    );

    // Simulate VPN switch / brief drop with identical local route fingerprint (`probe() == None`).
    online.store(false, Ordering::SeqCst);
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_probe = None;
        inner.last_route_fp = Some(h.guard.current_local_route_fingerprint());
    }

    let t0 = TInstant::now();
    h.guard.check_route_and_tick(&h.env).await;
    let elapsed = t0.elapsed();

    assert!(
        elapsed < Duration::from_millis(150),
        "offline regular probe must freeze fail-closed immediately (<150ms), took {elapsed:?}"
    );
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
    assert!(
        abort_rx.has_changed().unwrap_or(false),
        "active unrouted tunnels must be aborted immediately"
    );
    assert!(
        !h.state.is_provider_session_allowed("anthropic").await,
        "stale session_allowed_providers must be revoked on offline probe"
    );
    assert!(
        h.env
            .auditor
            .resolver
            .cached_direct_country("1.1.1.1")
            .await
            .is_none(),
        "stale direct telemetry cache must be invalidated on offline probe"
    );
    assert!(
        !h.guard
            .can_use_session_allowance(ProviderId::Anthropic)
            .await,
        "can_use_session_allowance must block Step 2 bypass during pending check"
    );

    let (det, _) =
        h.io.first("interceptor://risk-detected")
            .expect("alert risk-detected event emitted");
    assert_eq!(det["phase"], PHASE_DETECTING);
    assert_eq!(det["scope"], "network");
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 1);

    let pause_ev =
        h.io.first("guard://pause-status-changed")
            .expect("guard://pause-status-changed emitted");
    assert_eq!(pause_ev.0["gate"], "pending");
    let pending_list = pause_ev.0["pending_providers"]
        .as_array()
        .expect("pending_providers array");
    assert!(
        pending_list.iter().any(|v| v == "anthropic"),
        "pending_providers should include anthropic: {pause_ev:?}"
    );

    // Subsequent tick while detecting offline alert is active must not spawn duplicate popups.
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_probe = None;
    }
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.io.shows.load(Ordering::SeqCst), 1);

    // Cleanly invalidate background retry task so test exits immediately.
    h.guard.inner.lock().await.invalidate_alert();
}

#[tokio::test]
async fn test_regular_probe_offline_recovers_cleanly_when_same_baseline_returns() {
    let online = Arc::new(AtomicBool::new(false));
    let online_flag = Arc::clone(&online);
    let h = harness_env(
        slow_audit(Duration::from_millis(10), "1.1.1.1", OverallStatus::Green),
        "1.1.1.1",
        move |env| {
            env.probe = Some(Arc::new(move || {
                let is_on = online_flag.load(Ordering::SeqCst);
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
        inner.last_probe = None;
        inner.last_route_fp = Some(h.guard.current_local_route_fingerprint());
    }
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Pending);

    // Network comes back on same trusted baseline IP.
    tokio::time::sleep(Duration::from_millis(80)).await;
    online.store(true, Ordering::SeqCst);
    h.guard.wait_probe_settled_for_test().await;

    // Next regular tick sees restored baseline and re-opens the gate cleanly.
    {
        let mut inner = h.guard.inner.lock().await;
        inner.last_probe = None;
    }
    h.guard.check_route_and_tick(&h.env).await;
    h.guard.wait_probe_settled_for_test().await;
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn test_can_use_session_allowance_blocks_stale_session_and_unverified_states() {
    let h = harness(
        slow_audit(Duration::from_millis(5), "1.1.1.1", OverallStatus::Green),
        "1.1.1.1",
    )
    .await;

    // 1) No observed mismatch & Gate::Open & baseline present -> allowed.
    assert!(
        h.guard
            .can_use_session_allowance(ProviderId::Anthropic)
            .await
    );

    // 2) Mismatched observed_ip -> blocked.
    {
        let mut inner = h.guard.inner.lock().await;
        inner.observed_ip = Some("2.2.2.2".to_string());
    }
    assert!(
        !h.guard
            .can_use_session_allowance(ProviderId::Anthropic)
            .await
    );

    // 3) needs_reaudit -> blocked.
    {
        let mut inner = h.guard.inner.lock().await;
        inner.observed_ip = Some("1.1.1.1".to_string());
        inner.needs_reaudit = true;
    }
    assert!(
        !h.guard
            .can_use_session_allowance(ProviderId::Anthropic)
            .await
    );

    // 4) No baseline (cold startup offline) -> blocked.
    {
        let mut inner = h.guard.inner.lock().await;
        inner.needs_reaudit = false;
        inner.baseline = None;
    }
    assert!(
        !h.guard
            .can_use_session_allowance(ProviderId::Anthropic)
            .await
    );
}

#[tokio::test(start_paused = true)]
async fn test_switch_from_blocked_ru_to_clean_unpinned_de_prompts_under_ask_popup() {
    let current_ip = Arc::new(std::sync::Mutex::new("2.2.2.2".to_string()));
    let audit_ip = Arc::clone(&current_ip);
    let h = harness_env(
        Arc::new(move |provider, _force| {
            let ip = audit_ip.lock().unwrap().clone();
            Box::pin(async move {
                if ip == "5.5.5.5" {
                    let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                    r.geo_result = crate::auditor::CheckResult::critical("GEO_BLOCKED", "RU", None);
                    r.checks = vec![r.geo_result.clone()];
                    Ok(r)
                } else {
                    Ok(test_report(provider, OverallStatus::Green, &ip, "DE"))
                }
            })
        }),
        "2.2.2.2",
        |_| {},
    )
    .await;
    h.state.block_provider("anthropic").await.unwrap();
    h.guard.sync_gates_with_state(&h.state).await;
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "5.5.5.5".to_string(),
            country: Some("RU".to_string()),
            trusted: false,
        });
    }

    h.change("2.2.2.2").await;
    let enr =
        h.io.wait_for("interceptor://enriched", 2000)
            .await
            .expect("AskPopup must prompt on clean unpinned DE after RU block");
    assert_eq!(enr.0["phase"], PHASE_READY);
    assert_eq!(enr.0["network_change"]["new_ip"], "2.2.2.2");
    assert_eq!(enr.0["network_change"]["new_country"], "DE");
    let id = enr.0["id"].as_str().unwrap().to_string();
    h.guard
        .allow_network_alert(&id, &all_providers())
        .await
        .unwrap();
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert!(!h.state.is_provider_blocked("anthropic").await);
}
