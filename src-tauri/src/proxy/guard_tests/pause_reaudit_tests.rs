use super::*;

#[tokio::test(start_paused = true)]
async fn test_per_provider_pinned_ips_untraps_pause_and_recovers_after_transient_unknown_geo() {
    let phase = Arc::new(AtomicUsize::new(0));
    let phase_audit = Arc::clone(&phase);
    let audit: AuditFn = Arc::new(move |provider, _| {
        let cur = phase_audit.load(Ordering::SeqCst);
        Box::pin(async move {
            if provider == ProviderId::Anthropic && cur == 0 {
                let mut r = test_report(provider, OverallStatus::Yellow, "1.1.1.1", "");
                r.geo_result = CheckResult::unknown(
                    "GEO_UNKNOWN",
                    "timeout",
                    crate::auditor::UnknownReason::Timeout,
                );
                r.checks = vec![r.geo_result.clone()];
                return Ok(r);
            }
            Ok(test_report(provider, OverallStatus::Green, "1.1.1.1", "DE"))
        })
    });
    let h = harness(audit, "1.1.1.1").await;
    h.state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();
    h.state
        .set_pinned_ip_for("anthropic", Some("1.1.1.1".into()))
        .await
        .unwrap();
    h.state
        .set_pinned_ip_for("openai", Some("2.2.2.2".into()))
        .await
        .unwrap();
    h.state.set_strict_pinning_enabled(true).await.unwrap();
    h.state.block_provider("anthropic").await.unwrap();
    h.state.block_provider("openai").await.unwrap();
    h.guard.set_pause_mode_raw(PauseMode::UntilNetworkChange);
    {
        let mut inner = h.guard.inner.lock().await;
        inner.paused_ip = Some("1.1.1.1".to_string());
        inner.handled_ip = Some("1.1.1.1".to_string());
        inner.baseline = Some(Baseline {
            ip: "9.9.9.9".into(),
            country: Some("RU".into()),
            trusted: false,
        });
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }
    h.guard.sync_gates_with_state(&h.state).await;

    h.guard.check_route_and_tick(&h.env).await;
    for _ in 0..40 {
        let inner = h.guard.inner.lock().await;
        if inner.pending.is_none() && inner.needs_reaudit {
            break;
        }
        drop(inner);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(h.guard.inner.lock().await.handled_ip.is_none());
    assert!(h.guard.inner.lock().await.needs_reaudit);

    phase.store(1, Ordering::SeqCst);
    h.guard.inner.lock().await.last_probe = None;
    h.guard.check_route_and_tick(&h.env).await;
    for _ in 0..40 {
        if !h.state.is_provider_blocked("anthropic").await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert!(!h.state.is_provider_blocked("anthropic").await);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Blocked);
    assert!(h.state.is_provider_blocked("openai").await);
    assert_eq!(h.guard.pause_mode(), PauseMode::None);
    assert!(h.io.count("interceptor://resolved") >= 1);
    assert!(h.io.count("guard://pause-status-changed") >= 1);
}
