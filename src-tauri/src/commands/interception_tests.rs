use super::*;
use std::sync::Arc;

#[test]
fn simulation_network_change_uses_pinned_history_or_defaults() {
    let mut data = state::AppStateData::default();
    let nc = build_simulation_network_change(&data, "anthropic");
    assert_eq!(nc.old_ip.as_deref(), Some("185.212.102.40"));
    assert_eq!(nc.old_country.as_deref(), Some("NL"));
    assert_eq!(nc.new_ip.as_deref(), Some("185.220.101.5"));
    assert_eq!(nc.new_country.as_deref(), Some("TR"));

    data.ip_history.insert(
        "anthropic".to_string(),
        vec![state::IpHistoryEntry::new(
            "45.83.220.10".to_string(),
            "DE".to_string(),
            Some(24940),
            1,
        )],
    );
    let nc_hist = build_simulation_network_change(&data, "anthropic");
    assert_eq!(nc_hist.old_ip.as_deref(), Some("45.83.220.10"));
    assert_eq!(nc_hist.old_country.as_deref(), Some("DE"));

    data.pinned_ip = Some("91.199.10.20".to_string());
    let nc_pinned = build_simulation_network_change(&data, "anthropic");
    assert_eq!(nc_pinned.old_ip.as_deref(), Some("91.199.10.20"));
    assert_eq!(nc_pinned.old_country.as_deref(), Some("DE"));
}

#[test]
fn simulation_gate_reason_and_pause_mode_serde_work() {
    let data = state::AppStateData::default();
    let nc = build_simulation_network_change(&data, "anthropic");
    let sim_reason = proxy::hold_queue::build_gate_reason(None, Some(&nc), true);
    assert!(!sim_reason.trim().is_empty());
    assert!(sim_reason.contains("185.212.102.40"));
    assert!(sim_reason.contains("185.220.101.5"));

    let parsed: proxy::guard::PauseMode =
        serde_json::from_str("\"until_network_change\"").expect("parse PauseMode");
    assert_eq!(parsed, proxy::guard::PauseMode::UntilNetworkChange);
}

#[tokio::test]
async fn resolve_interception_single_provider_allow_persists_exception_and_keeps_unrelated_block()
{
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let state = state::AppState::load_or_default(path.clone());
    state.block_provider("anthropic").await.unwrap();
    state.block_provider("openai").await.unwrap();

    let auditor = auditor::Auditor::new().unwrap();
    let tel = auditor::NetworkTelemetry {
        ip: "5.5.5.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(1),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: crate::auditor::network::current_timestamp(),
    };
    auditor.resolver.set_cached(tel).await;

    let hq = Arc::new(proxy::HoldQueue::new());
    let server = Arc::new(
        proxy::ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), hq, None)
            .await
            .unwrap(),
    );
    let pm = proxy::ProxyManager {
        hold_queue: Arc::clone(&server.hold_queue),
        guard: Arc::clone(&server.guard),
        coverage: Arc::clone(&server.coverage),
        server,
    };
    pm.guard.sync_gates_with_state(&state).await;
    let rx = pm.hold_queue.register("hold-1".to_string(), "anthropic").await;

    resolve_interception_core(
        "hold-1",
        proxy::InterceptionAction::AllowSession,
        "anthropic",
        Some("provider"),
        &pm,
        &state,
        &auditor,
    )
    .await
    .unwrap();

    assert_eq!(rx.await.unwrap(), proxy::HoldResolution::Allow);
    assert!(!state.is_provider_blocked("anthropic").await);
    assert!(state.is_ip_trusted_for_provider("anthropic", "5.5.5.5").await);
    assert_eq!(pm.guard.gate_for(auditor::ProviderId::Anthropic), proxy::Gate::Open);
    // Unrelated openai remains blocked and un-excepted.
    assert!(state.is_provider_blocked("openai").await);
    assert!(!state.is_ip_trusted_for_provider("openai", "5.5.5.5").await);
    assert_eq!(pm.guard.gate_for(auditor::ProviderId::Openai), proxy::Gate::Blocked);

    // Reloading clears session_allowed but keeps trusted_exceptions.
    drop(state);
    let reloaded = state::AppState::load_or_default(path);
    assert!(!reloaded.is_provider_session_allowed("anthropic").await);
    assert!(reloaded.is_ip_trusted_for_provider("anthropic", "5.5.5.5").await);
}

#[tokio::test]
async fn resolve_interception_network_block_skips_disabled_and_routed_providers() {
    let state = state::AppState::new_in_memory();
    state.set_provider_monitoring("gemini", false).await.unwrap();
    let route =
        crate::routing::parse_route_key("socks5://1.2.3.4:1080#nl", 1).unwrap();
    let route_id = state.upsert_route(route).await.unwrap();
    state
        .bind_provider_route("openai", Some(&route_id))
        .await
        .unwrap();

    let auditor = auditor::Auditor::new().unwrap();
    let hq = std::sync::Arc::new(proxy::HoldQueue::new());
    let server = std::sync::Arc::new(
        proxy::ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), hq, None)
            .await
            .unwrap(),
    );
    let pm = proxy::ProxyManager {
        hold_queue: std::sync::Arc::clone(&server.hold_queue),
        guard: std::sync::Arc::clone(&server.guard),
        coverage: std::sync::Arc::clone(&server.coverage),
        server,
    };
    let _rx = pm.hold_queue.register("net-1".to_string(), proxy::ALL_PROVIDERS).await;

    resolve_interception_core(
        "net-1",
        proxy::InterceptionAction::BlockUntilNetworkChange,
        proxy::ALL_PROVIDERS,
        Some("network"),
        &pm,
        &state,
        &auditor,
    )
    .await
    .unwrap();

    // Only enabled unrouted provider `anthropic` was blocked; disabled `gemini` & routed `openai` stay open.
    assert!(state.is_provider_blocked("anthropic").await);
    assert!(!state.is_provider_blocked("openai").await);
    assert!(!state.is_provider_blocked("gemini").await);
    assert_eq!(pm.guard.gate_for(auditor::ProviderId::Anthropic), proxy::Gate::Blocked);
    assert_eq!(pm.guard.gate_for(auditor::ProviderId::Openai), proxy::Gate::Open);
    assert_eq!(pm.guard.gate_for(auditor::ProviderId::Gemini), proxy::Gate::Open);
}

#[tokio::test]
async fn toggle_or_clear_stop_unblocks_automatic_pause_without_engaging_manual_killswitch() {
    let state = state::AppState::new_in_memory();
    state.block_provider("anthropic").await.unwrap();
    let auditor = auditor::Auditor::new().unwrap();
    let hq = std::sync::Arc::new(proxy::HoldQueue::new());
    let server = std::sync::Arc::new(
        proxy::ProxyServer::bind_ephemeral(auditor, state.clone(), hq, None)
            .await
            .unwrap(),
    );
    server.guard.sync_gates_with_state(&state).await;
    assert!(!server.guard.is_manual_killswitch());
    assert!(server.guard.any_provider_gate_closed());
    assert_eq!(
        server.guard.gate_for(auditor::ProviderId::Anthropic),
        proxy::Gate::Blocked
    );

    let (now_manual, should_emit_changed) =
        toggle_or_clear_stop_core(None, &server.guard, &state).await;
    assert!(
        !now_manual,
        "clearing automatic provider blocks must NOT engage manual_killswitch"
    );
    assert!(should_emit_changed);
    assert!(!server.guard.is_manual_killswitch());
    assert!(!server.guard.any_provider_gate_closed());
    assert!(state.get_data().await.blocked_providers.is_empty());
}

#[tokio::test]
async fn resolve_interception_superseded_block_and_open_guide_are_noops_and_never_reblock() {
    let state = state::AppState::new_in_memory();
    let auditor = auditor::Auditor::new().unwrap();
    let hq = Arc::new(proxy::HoldQueue::new());
    let server = Arc::new(
        proxy::ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), hq, None)
            .await
            .unwrap(),
    );
    let pm = proxy::ProxyManager {
        hold_queue: Arc::clone(&server.hold_queue),
        guard: Arc::clone(&server.guard),
        coverage: Arc::clone(&server.coverage),
        server,
    };

    // Provider hold superseded by network recovery must NOT re-block on BlockUntilNetworkChange or OpenGuideAndBlock.
    let _rx_prov = pm
        .hold_queue
        .register("hold-prov-1".to_string(), "anthropic")
        .await;
    pm.hold_queue.cancel_all_superseded().await;

    let out_block = resolve_interception_core(
        "hold-prov-1",
        proxy::InterceptionAction::BlockUntilNetworkChange,
        "anthropic",
        Some("provider"),
        &pm,
        &state,
        &auditor,
    )
    .await
    .unwrap();
    assert!(!out_block.applied);
    assert!(out_block.pause_status.is_none());
    assert!(!state.is_provider_blocked("anthropic").await);
    assert_eq!(pm.guard.gate_for(auditor::ProviderId::Anthropic), proxy::Gate::Open);

    let out_guide = resolve_interception_core(
        "hold-prov-1",
        proxy::InterceptionAction::OpenGuideAndBlock,
        "anthropic",
        Some("provider"),
        &pm,
        &state,
        &auditor,
    )
    .await
    .unwrap();
    assert!(!out_guide.applied);
    assert!(!out_guide.open_guide);
    assert!(!state.is_provider_blocked("anthropic").await);
    assert_eq!(pm.guard.gate_for(auditor::ProviderId::Anthropic), proxy::Gate::Open);

    // Network-scoped alert superseded before UI click must NOT block or enter PauseMode.
    let _rx_net = pm
        .hold_queue
        .register("net-stale-1".to_string(), proxy::ALL_PROVIDERS)
        .await;
    pm.hold_queue.cancel_all_superseded().await;
    let out_net = resolve_interception_core(
        "net-stale-1",
        proxy::InterceptionAction::BlockUntilNetworkChange,
        proxy::ALL_PROVIDERS,
        Some("network"),
        &pm,
        &state,
        &auditor,
    )
    .await
    .unwrap();
    assert!(!out_net.applied);
    assert!(!pm.guard.pause_status().paused);
    assert!(state.get_data().await.blocked_providers.is_empty());

    // Active provider hold still blocks as expected.
    let rx_active = pm
        .hold_queue
        .register("hold-active-1".to_string(), "anthropic")
        .await;
    let out_active = resolve_interception_core(
        "hold-active-1",
        proxy::InterceptionAction::BlockUntilNetworkChange,
        "anthropic",
        Some("provider"),
        &pm,
        &state,
        &auditor,
    )
    .await
    .unwrap();
    assert!(out_active.applied);
    assert_eq!(rx_active.await.unwrap(), proxy::HoldResolution::Block);
    assert!(state.is_provider_blocked("anthropic").await);
    assert_eq!(
        pm.guard.gate_for(auditor::ProviderId::Anthropic),
        proxy::Gate::Blocked
    );
}
