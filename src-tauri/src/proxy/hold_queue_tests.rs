use super::*;

#[tokio::test]
async fn test_connect_hold_and_allow_session() {
    let queue = HoldQueue::new();
    let id = "test-req-1".to_string();

    let rx = queue.register(id.clone(), "anthropic").await;

    let resolved = queue.resolve(&id, HoldResolution::Allow).await;
    assert!(resolved);

    let res = rx.await.expect("channel should resolve");
    assert_eq!(res, HoldResolution::Allow);
}

#[tokio::test]
async fn test_connect_hold_and_block() {
    let queue = HoldQueue::new();
    let id = "test-req-2".to_string();

    let rx = queue.register(id.clone(), "gemini").await;

    let resolved = queue.resolve(&id, HoldResolution::Block).await;
    assert!(resolved);

    let res = rx.await.expect("channel should resolve");
    assert_eq!(res, HoldResolution::Block);
}

#[tokio::test]
async fn test_resolve_all_for_provider() {
    let queue = HoldQueue::new();
    let rx1 = queue.register("req-1".into(), "openai").await;
    let rx2 = queue.register("req-2".into(), "openai").await;
    let rx3 = queue.register("req-3".into(), "anthropic").await;

    let count = queue
        .resolve_all_for_provider("openai", HoldResolution::Allow)
        .await;
    assert_eq!(count, 2);

    assert_eq!(rx1.await.unwrap(), HoldResolution::Allow);
    assert_eq!(rx2.await.unwrap(), HoldResolution::Allow);

    // Anthropic still in queue
    let res3 = queue.resolve("req-3", HoldResolution::Block).await;
    assert!(res3);
    assert_eq!(rx3.await.unwrap(), HoldResolution::Block);
}

#[tokio::test]
async fn test_coalesces_concurrent_provider_holds_and_skips_simulations() {
    let queue = HoldQueue::new();
    let _sim_rx = queue
        .register("sim-123".to_string(), "anthropic")
        .await;

    let (id1, rx1, leader1) = queue
        .register_or_coalesce_provider("hold-1".to_string(), "anthropic")
        .await;
    assert!(leader1);
    assert_eq!(id1, "hold-1");

    let (id2, rx2, leader2) = queue
        .register_or_coalesce_provider("hold-2".to_string(), "anthropic")
        .await;
    assert!(!leader2);
    assert_eq!(id2, "hold-1");
    assert_eq!(queue.active_entry_count().await, 2); // sim-123 + hold-1

    assert!(queue.resolve(&id1, HoldResolution::Allow).await);
    assert_eq!(rx1.await.unwrap(), HoldResolution::Allow);
    assert_eq!(rx2.await.unwrap(), HoldResolution::Allow);
}

#[tokio::test]
async fn test_cancel_all_superseded_drains_all_holds_and_clears_alert() {
    let queue = HoldQueue::new();
    let (id1, rx1, leader1) = queue
        .register_or_coalesce_provider("hold-1".to_string(), "anthropic")
        .await;
    assert!(leader1);
    let (_id2, rx2, leader2) = queue
        .register_or_coalesce_provider("hold-2".to_string(), "anthropic")
        .await;
    assert!(!leader2);
    let rx3 = queue.register("hold-3".to_string(), "openai").await;

    queue.set_alert(RiskInterceptPayload {
        id: id1,
        provider: ProviderId::Anthropic,
        host: "api.anthropic.com".to_string(),
        report: None,
        ttl_seconds: DEFAULT_HOLD_TTL_SECS,
        scope: "provider".to_string(),
        network_change: None,
        is_simulation: false,
        detected_at_ms: 0,
        phase: PHASE_READY.to_string(),
        gate_reason: None,
    });
    assert!(queue.current_alert().is_some());
    assert_eq!(queue.active_entry_count().await, 2);

    let cancelled = queue.cancel_all_superseded().await;
    assert_eq!(cancelled, 3);
    assert_eq!(queue.active_entry_count().await, 0);
    assert!(queue.current_alert().is_none());
    assert_eq!(rx1.await.unwrap(), HoldResolution::Superseded);
    assert_eq!(rx2.await.unwrap(), HoldResolution::Superseded);
    assert_eq!(rx3.await.unwrap(), HoldResolution::Superseded);
}

#[tokio::test]
async fn test_is_active_and_has_active_non_sim_holds() {
    let queue = HoldQueue::new();
    assert!(!queue.is_active("hold-1").await);
    assert!(!queue.has_active_non_sim_holds().await);

    let _sim_rx = queue.register("sim-1".to_string(), "anthropic").await;
    assert!(queue.is_active("sim-1").await);
    assert!(!queue.has_active_non_sim_holds().await);

    let _real_rx = queue.register("hold-1".to_string(), "anthropic").await;
    assert!(queue.is_active("hold-1").await);
    assert!(queue.has_active_non_sim_holds().await);

    queue.cancel_all_superseded().await;
    assert!(!queue.is_active("hold-1").await);
    assert!(!queue.has_active_non_sim_holds().await);
}
