use super::super::*;
use super::V131_STATE_JSON;
use tempfile::tempdir;

#[test]
fn test_state_serialization_deserialization() {
    let mut original = AppStateData {
        pinned_ip: Some("185.220.101.5".to_string()),
        strict_pinning_enabled: true,
        ..Default::default()
    };
    original
        .session_allowed_providers
        .insert("anthropic".to_string());
    original.blocked_providers.insert("gemini".to_string());

    let entry = IpHistoryEntry::new("185.220.101.5", "nl", Some(20473), 1730745600);
    original
        .ip_history
        .get_mut("anthropic")
        .unwrap()
        .push(entry.clone());

    let json = serde_json::to_string_pretty(&original).expect("serialize failed");
    let deserialized: AppStateData = serde_json::from_str(&json).expect("deserialize failed");

    assert_eq!(original, deserialized);
    assert_eq!(deserialized.pinned_ip.as_deref(), Some("185.220.101.5"));
    assert!(deserialized.strict_pinning_enabled);
    assert!(deserialized.session_allowed_providers.contains("anthropic"));
    assert!(deserialized.blocked_providers.contains("gemini"));

    let history = deserialized.ip_history.get("anthropic").unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].country_code, "NL");
    assert_eq!(history[0].asn, Some(20473));
}

#[test]
fn test_asn_deserializer_variants() {
    let json_num = r#"{"ip":"1.1.1.1","country_code":"US","asn":13335,"timestamp":100}"#;
    let entry1: IpHistoryEntry = serde_json::from_str(json_num).unwrap();
    assert_eq!(entry1.asn, Some(13335));

    let json_str = r#"{"ip":"1.1.1.1","country_code":"US","asn":"AS13335","timestamp":100}"#;
    let entry2: IpHistoryEntry = serde_json::from_str(json_str).unwrap();
    assert_eq!(entry2.asn, Some(13335));

    let json_null = r#"{"ip":"1.1.1.1","country_code":"US","asn":null,"timestamp":100}"#;
    let entry3: IpHistoryEntry = serde_json::from_str(json_null).unwrap();
    assert_eq!(entry3.asn, None);

    let json_missing = r#"{"ip":"1.1.1.1","country_code":"US","timestamp":100}"#;
    let entry4: IpHistoryEntry = serde_json::from_str(json_missing).unwrap();
    assert_eq!(entry4.asn, None);
}

#[tokio::test]
async fn test_persistence_save_load() {
    let dir = tempdir().expect("create temp dir");
    let file_path = dir.path().join("state.json");

    let state = AppState::load_or_default(file_path.clone());
    assert_eq!(state.get_pinned_ip().await, None);
    assert!(!state.is_strict_pinning_enabled().await);

    // Mutate and verify auto-save
    state
        .set_pinned_ip(Some("95.217.1.1".to_string()))
        .await
        .expect("set pinned ip");
    state
        .set_strict_pinning_enabled(true)
        .await
        .expect("set strict pinning");

    // Reload fresh instance from disk
    let reloaded = AppState::load_or_default(file_path);
    assert_eq!(
        reloaded.get_pinned_ip().await,
        Some("95.217.1.1".to_string())
    );
    assert!(reloaded.is_strict_pinning_enabled().await);
}

#[tokio::test]
async fn test_ip_history_max_10_entries() {
    let state = AppState::new_in_memory();

    // Push 15 entries
    for i in 1..=15 {
        let entry = IpHistoryEntry::new(
            format!("185.10.10.{}", i),
            "NL",
            Some(12345),
            1000 + i as u64,
        );
        state
            .record_ip_history("anthropic", entry)
            .await
            .expect("record history");
    }

    let history = state.get_ip_history("anthropic").await;
    assert_eq!(history.len(), 10);
    // Oldest entry kept should be i = 6
    assert_eq!(history[0].ip, "185.10.10.6");
    // Latest entry kept should be i = 15
    assert_eq!(history[9].ip, "185.10.10.15");

    let last = state.get_last_ip_history("anthropic").await.unwrap();
    assert_eq!(last.ip, "185.10.10.15");
}

#[tokio::test]
async fn test_session_allowance_logic() {
    let state = AppState::new_in_memory();

    assert!(!state.is_provider_session_allowed("anthropic").await);

    state
        .allow_provider_for_session("anthropic")
        .await
        .expect("allow session");
    assert!(state.is_provider_session_allowed("anthropic").await);
    assert!(!state.is_provider_session_allowed("openai").await);

    state
        .revoke_session_allowed_provider("anthropic")
        .await
        .expect("revoke session");
    assert!(!state.is_provider_session_allowed("anthropic").await);

    state
        .allow_provider_for_session("anthropic")
        .await
        .expect("allow session");
    state
        .allow_provider_for_session("openai")
        .await
        .expect("allow session");
    state
        .clear_session_allowed_providers()
        .await
        .expect("clear all");
    assert!(!state.is_provider_session_allowed("anthropic").await);
    assert!(!state.is_provider_session_allowed("openai").await);
}

#[tokio::test]
async fn test_provider_blocking_logic() {
    let state = AppState::new_in_memory();

    assert!(!state.is_provider_blocked("gemini").await);

    state
        .block_provider("gemini")
        .await
        .expect("block provider");
    assert!(state.is_provider_blocked("gemini").await);

    // Blocking should revoke session allowed status if present
    state
        .allow_provider_for_session("openai")
        .await
        .expect("allow openai");
    assert!(state.is_provider_session_allowed("openai").await);
    state.block_provider("openai").await.expect("block openai");
    assert!(state.is_provider_blocked("openai").await);
    assert!(!state.is_provider_session_allowed("openai").await);

    // Allowing session should unblock provider
    state
        .allow_provider_for_session("openai")
        .await
        .expect("allow openai again");
    assert!(!state.is_provider_blocked("openai").await);
    assert!(state.is_provider_session_allowed("openai").await);

    state
        .unblock_provider("gemini")
        .await
        .expect("unblock gemini");
    assert!(!state.is_provider_blocked("gemini").await);

    state.block_provider("anthropic").await.unwrap();
    state.clear_blocked_providers().await.unwrap();
    assert!(!state.is_provider_blocked("anthropic").await);
}

#[tokio::test]
async fn test_upstream_proxy_and_warmup_timer_state() {
    let state = AppState::new_in_memory();

    assert_eq!(state.get_upstream_proxy().await, None);
    assert_eq!(state.get_warmup_started_at().await, None);

    let cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: "socks5://user:pass@127.0.0.1:1080#Custom".to_string(),
        protocol: "socks5".to_string(),
        host: "127.0.0.1".to_string(),
        port: 1080,
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        label: Some("Custom".to_string()),
    };

    state
        .set_upstream_proxy(Some(cfg.clone()))
        .await
        .expect("set upstream proxy");
    assert_eq!(state.get_upstream_proxy().await, Some(cfg));

    state
        .set_warmup_started_at(Some(1730000000))
        .await
        .expect("set warmup timer");
    assert_eq!(state.get_warmup_started_at().await, Some(1730000000));

    state
        .set_upstream_proxy(None)
        .await
        .expect("clear upstream proxy");
    assert_eq!(state.get_upstream_proxy().await, None);

    state
        .set_warmup_started_at(None)
        .await
        .expect("clear warmup timer");
    assert_eq!(state.get_warmup_started_at().await, None);

    // Synced AI timezone
    assert_eq!(state.get_synced_ai_timezone().await, None);
    state
        .set_synced_ai_timezone(Some("Europe/Amsterdam".to_string()))
        .await
        .expect("set synced ai tz");
    assert_eq!(
        state.get_synced_ai_timezone().await,
        Some("Europe/Amsterdam".to_string())
    );
    state
        .set_synced_ai_timezone(None)
        .await
        .expect("clear synced ai tz");
    assert_eq!(state.get_synced_ai_timezone().await, None);
}

#[tokio::test]
async fn test_gateway_stats_tracker() {
    let state = AppState::new_in_memory();
    let tracker = state.stats();

    let initial = state.get_gateway_stats().await;
    assert_eq!(initial.protected_ai_requests, 0);
    assert_eq!(initial.intercepted_leaks, 0);
    assert_eq!(initial.direct_bypassed_requests, 0);
    assert_eq!(initial.active_ai_tunnels, 0);
    assert!(initial.recent_events.is_empty());

    // Increment direct bypass
    tracker.record_direct_bypassed();
    assert_eq!(state.get_gateway_stats().await.direct_bypassed_requests, 1);

    // Record protected events
    tracker.record_protected("api.anthropic.com", "anthropic", "GB");
    let snap1 = state.get_gateway_stats().await;
    assert_eq!(snap1.protected_ai_requests, 1);
    assert_eq!(
        snap1.last_protected_host.as_deref(),
        Some("api.anthropic.com")
    );
    assert_eq!(snap1.recent_events.len(), 1);
    assert_eq!(snap1.recent_events[0].action, "PROTECTED");
    assert_eq!(snap1.recent_events[0].host, "api.anthropic.com");

    // Record intercepted leak
    tracker.record_intercepted("api.openai.com", "openai", "HELD", "TR");
    let snap2 = state.get_gateway_stats().await;
    assert_eq!(snap2.intercepted_leaks, 1);
    assert_eq!(snap2.recent_events.len(), 2);
    assert_eq!(snap2.recent_events[1].action, "HELD");

    // Test active tunnel RAII guard
    {
        let guard = tracker.enter_tunnel();
        assert_eq!(state.get_gateway_stats().await.active_ai_tunnels, 1);
        drop(guard);
    }
    assert_eq!(state.get_gateway_stats().await.active_ai_tunnels, 0);

    // Test ring buffer caps at 20 events
    for i in 0..25 {
        tracker.record_protected(&format!("host-{i}.ai"), "gemini", "US");
    }
    let snap3 = state.get_gateway_stats().await;
    assert_eq!(snap3.recent_events.len(), 20);
    assert_eq!(snap3.recent_events.last().unwrap().host, "host-24.ai");

    // Test direct bypass recording and deduplication
    let prev_direct = snap3.direct_bypassed_requests;
    tracker.record_direct_bypassed_host("api.github.com");
    let snap4 = state.get_gateway_stats().await;
    assert_eq!(snap4.direct_bypassed_requests, prev_direct + 1);
    let last_ev = snap4.recent_events.last().unwrap();
    assert_eq!(last_ev.host, "api.github.com");
    assert_eq!(last_ev.provider, "Non-AI");
    assert_eq!(last_ev.action, "DIRECT");
    assert_eq!(last_ev.country, "DIRECT");
    assert_eq!(last_ev.kind.as_deref(), Some("direct"));
    let count_events = snap4.recent_events.len();

    // Same host called again -> deduplication updates timestamp without increasing queue length
    tracker.record_direct_bypassed_host("api.github.com");
    let snap5 = state.get_gateway_stats().await;
    assert_eq!(snap5.direct_bypassed_requests, prev_direct + 2);
    assert_eq!(snap5.recent_events.len(), count_events);
    assert_eq!(snap5.recent_events.last().unwrap().host, "api.github.com");

    // Different non-AI host -> appends new event
    tracker.record_direct_bypassed_host("registry.npmjs.org");
    let snap6 = state.get_gateway_stats().await;
    assert_eq!(snap6.direct_bypassed_requests, prev_direct + 3);
    assert_eq!(
        snap6.recent_events.last().unwrap().host,
        "registry.npmjs.org"
    );
}

#[tokio::test]
async fn test_interception_behavior_popup_position_and_custom_domains() {
    let state = AppState::new_in_memory();

    // Defaults
    assert_eq!(
        state.get_interception_behavior().await,
        InterceptionBehavior::AskPopup
    );
    assert_eq!(state.get_popup_position().await, PopupPosition::TopRight);
    assert!(state.get_custom_ai_domains().await.is_empty());

    // Update interception behavior
    state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    assert_eq!(
        state.get_interception_behavior().await,
        InterceptionBehavior::AutoLockSilent
    );

    state
        .set_interception_behavior(InterceptionBehavior::AutoAllowTrusted)
        .await
        .unwrap();
    assert_eq!(
        state.get_interception_behavior().await,
        InterceptionBehavior::AutoAllowTrusted
    );

    // Update popup position
    state
        .set_popup_position(PopupPosition::TopCenter)
        .await
        .unwrap();
    assert_eq!(state.get_popup_position().await, PopupPosition::TopCenter);

    // Custom AI domains management
    let domains = state
        .add_custom_ai_domain("my-local-llm.internal".to_string())
        .await
        .unwrap();
    assert_eq!(domains, vec!["my-local-llm.internal".to_string()]);
    assert_eq!(
        state.get_custom_ai_domains().await,
        vec!["my-local-llm.internal".to_string()]
    );

    // Trimming, leading wildcard normalization, and deduplication
    let domains = state
        .add_custom_ai_domain(" *.Custom-Model.ai ".to_string())
        .await
        .unwrap();
    assert_eq!(domains.len(), 2);
    assert_eq!(domains[1], "custom-model.ai");

    // Duplicate addition is idempotent
    let domains = state
        .add_custom_ai_domain("custom-model.ai".to_string())
        .await
        .unwrap();
    assert_eq!(domains.len(), 2);

    // Removal
    let domains = state
        .remove_custom_ai_domain("my-local-llm.internal")
        .await
        .unwrap();
    assert_eq!(domains, vec!["custom-model.ai".to_string()]);
    assert_eq!(
        state.get_custom_ai_domains().await,
        vec!["custom-model.ai".to_string()]
    );
}

#[tokio::test]
async fn test_migration_from_v131_state_json() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, V131_STATE_JSON).unwrap();

    let state = AppState::load_or_default(path.clone());
    let data = state.get_data().await;
    let expected_id =
        crate::routing::route_id_for_raw_key("socks5://alice:s3cret@185.10.10.2:1080#NL Gate");

    assert_eq!(data.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(data.routes.len(), 1);
    let r = &data.routes[0];
    assert_eq!(r.id, expected_id);
    assert_eq!(r.label, "NL Gate");
    assert!(r.enabled);
    assert_eq!(r.entries[0].proto, crate::routing::EntryProto::Socks5);
    assert_eq!(r.entries[0].host, "185.10.10.2");
    assert_eq!(r.entries[0].password.as_deref(), Some("s3cret"));
    assert_eq!(data.default_route_id.as_deref(), Some(expected_id.as_str()));
    assert_eq!(data.legacy_route_id.as_deref(), Some(expected_id.as_str()));
    // Untouched v1.3.1 fields survive.
    assert_eq!(data.pinned_ip.as_deref(), Some("185.10.10.1"));
    assert_eq!(data.synced_ai_timezone.as_deref(), Some("Europe/Amsterdam"));
    assert_eq!(data.ip_history["anthropic"].len(), 1);

    // Legacy mirror keeps the v1.3.1 shape for the current frontend.
    let mirror = state.get_upstream_proxy().await.expect("mirror");
    assert!(mirror.enabled);
    assert_eq!(
        mirror.raw_key,
        "socks5://alice:s3cret@185.10.10.2:1080#NL Gate"
    );
    assert_eq!(mirror.protocol, "socks5");
    assert_eq!(mirror.port, 1080);
    assert_eq!(mirror.label.as_deref(), Some("NL Gate"));

    // Every AI provider without a binding now uses the migrated route.
    for p in KNOWN_PROVIDERS {
        assert!(
            matches!(state.route_selection(p).await, RouteSelection::Route(ref r) if r.id == expected_id)
        );
    }

    // Migrated file was rewritten; a second load is stable (id does not change).
    let on_disk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(on_disk["schema_version"], 2);
    let again = AppState::load_or_default(path).get_data().await;
    assert_eq!(again.routes, data.routes);
    assert_eq!(again.default_route_id, data.default_route_id);
}

#[test]
fn test_migration_of_disabled_upstream_goes_direct() {
    let json = V131_STATE_JSON.replace("\"enabled\": true", "\"enabled\": false");
    let mut data: AppStateData = serde_json::from_str(&json).unwrap();
    assert_eq!(data.schema_version, 0);
    assert!(data.migrate(1));
    assert_eq!(data.routes.len(), 1);
    assert!(!data.routes[0].enabled);
    assert_eq!(data.default_route_id, None);
    assert_eq!(select_route(&data, "openai"), RouteSelection::Direct);
    assert_eq!(data.upstream_proxy.as_ref().map(|c| c.enabled), Some(false));
    // Idempotent.
    assert!(!data.migrate(2));
}

#[test]
fn test_state_without_upstream_and_new_fields_loads() {
    let json = r#"{"pinned_ip": null, "auto_update_enabled": false}"#;
    let mut data: AppStateData = serde_json::from_str(json).unwrap();
    data.migrate(1);
    assert!(data.routes.is_empty());
    assert_eq!(data.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(data.upstream_proxy, None);
    assert_eq!(data.ip_change_cooldown_until, None);
    assert_eq!(data.last_safe_logout_at, None);
}

#[tokio::test]
async fn test_ip_change_cooldown_helpers_and_ui_redaction() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    let state = AppState::load_or_default(path.clone());

    let until = state.record_safe_logout(1_000_000, 14_400).await.unwrap();
    assert_eq!(until, 1_014_400);
    assert_eq!(
        state.ip_change_cooldown_remaining_secs(1_000_100).await,
        Some(14_300)
    );
    assert_eq!(state.ip_change_cooldown_remaining_secs(1_014_400).await, None);

    let ui = state.get_data().await.redacted_for_ui();
    assert_eq!(ui.ip_change_cooldown_until, Some(1_014_400));
    assert_eq!(ui.last_safe_logout_at, Some(1_000_000));

    let reloaded = AppState::load_or_default(path);
    assert_eq!(
        reloaded.ip_change_cooldown_remaining_secs(1_000_000).await,
        Some(14_400)
    );
    assert_eq!(reloaded.get_data().await.last_safe_logout_at, Some(1_000_000));

    reloaded.clear_ip_change_cooldown().await.unwrap();
    assert_eq!(
        reloaded.ip_change_cooldown_remaining_secs(1_000_000).await,
        None
    );
    let mut d = reloaded.get_data().await;
    assert_eq!(d.start_ip_change_cooldown(2_000_000, 0), 2_014_400);
    assert_eq!(d.ip_change_cooldown_remaining_secs(2_000_400), Some(14_000));
    d.clear_ip_change_cooldown();
    assert_eq!(d.ip_change_cooldown_remaining_secs(2_000_400), None);
}

