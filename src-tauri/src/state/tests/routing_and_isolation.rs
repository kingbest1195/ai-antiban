use super::super::*;
use super::V131_STATE_JSON;
use tempfile::tempdir;

#[tokio::test]
async fn test_legacy_commands_on_top_of_routes() {
    let state = AppState::new_in_memory();
    let cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: "socks5://185.1.1.1:1080".into(),
        protocol: "socks5".into(),
        host: "185.1.1.1".into(),
        port: 1080,
        username: None,
        password: None,
        label: Some("A".into()),
    };
    state.set_upstream_proxy(Some(cfg.clone())).await.unwrap();
    let id = state.get_data().await.default_route_id.clone().unwrap();

    // Toggle off: route kept, default detached -> unbound providers go direct (v1.3.x semantics).
    let off = state.toggle_legacy_upstream(false).await.unwrap().unwrap();
    assert!(!off.enabled);
    assert_eq!(
        state.route_selection("openai").await,
        RouteSelection::Direct
    );
    assert_eq!(state.get_routes().await.len(), 1);

    let on = state.toggle_legacy_upstream(true).await.unwrap().unwrap();
    assert!(on.enabled);
    assert!(matches!(
        state.route_selection("openai").await,
        RouteSelection::Route(_)
    ));

    // Explicit binding survives replacing the legacy key, and is fail-closed when disabled.
    state
        .bind_provider_route("gemini", Some(&id))
        .await
        .unwrap();
    let mut cfg2 = cfg.clone();
    cfg2.raw_key = "socks5://185.2.2.2:1080".into();
    cfg2.host = "185.2.2.2".into();
    state.set_upstream_proxy(Some(cfg2)).await.unwrap();
    let data = state.get_data().await;
    assert_eq!(data.routes.len(), 2, "bound old route is kept");
    assert_ne!(data.default_route_id.as_deref(), Some(id.as_str()));
    state.set_route_enabled(&id, false).await.unwrap();
    match state.route_selection("gemini").await {
        RouteSelection::Route(r) => assert!(r.check_usable(0).is_err()),
        other => panic!("gemini must stay on its (disabled) route, got {other:?}"),
    }

    // Removing a route preserves provider bindings (fail-closed dangling route -> RouteSelection::Missing).
    state.remove_route(&id).await.unwrap();
    assert_eq!(
        state.get_data().await.provider_routes.get("gemini"),
        Some(&id)
    );
    assert_eq!(
        state.route_selection("gemini").await,
        RouteSelection::Missing(id.clone())
    );

    // clear_upstream_proxy removes the legacy route.
    state.set_upstream_proxy(None).await.unwrap();
    assert!(state.get_routes().await.is_empty());
    assert_eq!(state.get_upstream_proxy().await, None);
}

#[test]
fn test_redacted_for_ui_hides_route_secrets() {
    let mut data: AppStateData = serde_json::from_str(V131_STATE_JSON).unwrap();
    data.migrate(1);
    let ui = serde_json::to_string(&data.redacted_for_ui().routes).unwrap();
    assert!(!ui.contains("s3cret"));
    assert!(!ui.contains("alice"));
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
#[tokio::test]
async fn state_json_and_copies_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");

    // A fresh state.json is created 0600.
    let state = AppState::load_or_default(path.clone());
    state
        .set_pinned_ip(Some("95.217.1.1".to_string()))
        .await
        .unwrap();
    assert_eq!(mode_of(&path), 0o600, "new state.json");

    // An existing world-readable v1 file is tightened on load, and its backup is 0600 too.
    std::fs::write(&path, V131_STATE_JSON).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = AppState::load_or_default(path.clone());
    assert_eq!(mode_of(&path), 0o600, "loaded state.json");
    assert_eq!(
        mode_of(&dir.path().join(STATE_V1_BACKUP_NAME)),
        0o600,
        "backup_v1"
    );

    // An unreadable file leaves a 0600 corrupt copy.
    std::fs::write(&path, "{ not json").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = AppState::load_or_default(path.clone());
    let corrupt: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("state.corrupt-")
        })
        .collect();
    assert_eq!(corrupt.len(), 1);
    assert_eq!(mode_of(&corrupt[0].path()), 0o600, "state.corrupt copy");
    assert_eq!(mode_of(&path), 0o600, "rewritten state.json");
}

// --- time zone switch and CLI mode (2.1) ---

#[test]
fn state_json_of_2_0_0_without_the_new_fields_reads_with_the_defaults() {
    let data: AppStateData = serde_json::from_str(
        r#"{"schema_version": 2, "synced_ai_timezone": "Europe/Amsterdam", "auto_update_enabled": true}"#,
    )
    .unwrap();
    assert!(
        data.sync_ai_tz_enabled,
        "the switch is on unless the user turned it off"
    );
    assert!(!data.autostart_enabled);
    assert!(!data.cowork_guard_enabled);
    assert_eq!(data.cli_mode, CliMode::AiOnly);
    assert_eq!(data.synced_ai_timezone.as_deref(), Some("Europe/Amsterdam"));
    // The v1.3.1 file has neither field either.
    let old: AppStateData = serde_json::from_str(V131_STATE_JSON).unwrap();
    assert!(old.sync_ai_tz_enabled);
    assert_eq!(old.cli_mode, CliMode::AiOnly);
    assert_eq!(AppStateData::default().cli_mode, CliMode::AiOnly);
    assert!(AppStateData::default().sync_ai_tz_enabled);
}

#[test]
fn cli_mode_is_snake_case_in_state_json() {
    assert_eq!(
        serde_json::to_string(&CliMode::AiOnly).unwrap(),
        "\"ai_only\""
    );
    assert_eq!(
        serde_json::to_string(&CliMode::GlobalTerminal).unwrap(),
        "\"global_terminal\""
    );
    let data: AppStateData =
        serde_json::from_str(r#"{"cli_mode": "global_terminal", "sync_ai_tz_enabled": false}"#)
            .unwrap();
    assert_eq!(data.cli_mode, CliMode::GlobalTerminal);
    assert!(!data.sync_ai_tz_enabled);
    let json = serde_json::to_value(&data).unwrap();
    assert_eq!(json["cli_mode"], "global_terminal");
    assert_eq!(json["sync_ai_tz_enabled"], false);
}

#[tokio::test]
async fn the_switch_and_the_mode_are_saved_and_reloaded() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    let state = AppState::load_or_default(path.clone());
    assert_eq!(state.get_cli_mode().await, CliMode::AiOnly);
    assert!(state.get_sync_ai_tz_enabled().await);
    state.set_cli_mode(CliMode::GlobalTerminal).await.unwrap();
    state.set_sync_ai_tz_enabled(false).await.unwrap();
    let reloaded = AppState::load_or_default(path.clone());
    assert_eq!(reloaded.get_cli_mode().await, CliMode::GlobalTerminal);
    assert!(!reloaded.get_sync_ai_tz_enabled().await);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state.json stays private");
    }
}

#[tokio::test]
async fn the_zone_to_apply_needs_the_switch_and_a_well_formed_name() {
    let state = AppState::new_in_memory();
    assert_eq!(state.effective_sync_tz().await, None, "no zone known");
    state
        .set_synced_ai_timezone(Some("Europe/Amsterdam".into()))
        .await
        .unwrap();
    assert_eq!(
        state.effective_sync_tz().await.as_deref(),
        Some("Europe/Amsterdam")
    );
    state.set_sync_ai_tz_enabled(false).await.unwrap();
    assert_eq!(
        state.effective_sync_tz().await,
        None,
        "switch off: nothing to apply"
    );
    // The zone stays remembered while the switch is off.
    assert_eq!(
        state.get_synced_ai_timezone().await.as_deref(),
        Some("Europe/Amsterdam")
    );
    state.set_sync_ai_tz_enabled(true).await.unwrap();
    state
        .set_synced_ai_timezone(Some("Europe/Berlin; rm -rf /".into()))
        .await
        .unwrap();
    assert_eq!(
        state.effective_sync_tz().await,
        None,
        "malformed name is never applied"
    );
}

#[tokio::test]
async fn direct_route_sentinel_persists_and_overrides_default_route() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    let state = AppState::load_or_default(path.clone());
    let route = crate::routing::parse_route_key("socks5://1.2.3.4:1080#nl", 1).unwrap();
    let rid = state.upsert_route(route).await.unwrap();
    state.set_default_route(Some(&rid)).await.unwrap();

    // Explicit direct overrides default_route_id without failing unknown route check.
    state
        .bind_provider_route("gemini", Some(DIRECT_ROUTE_ID))
        .await
        .unwrap();
    let reloaded = AppState::load_or_default(path);
    let data = reloaded.get_data().await;
    assert_eq!(
        select_route_id(&data, "gemini"),
        None,
        "gemini must stay direct when bound to DIRECT_ROUTE_ID"
    );
    assert_eq!(
        select_route_id(&data, "openai").as_deref(),
        Some(rid.as_str()),
        "openai still inherits default_route_id"
    );

    // set_default_route still rejects DIRECT_ROUTE_ID.
    assert!(
        reloaded
            .set_default_route(Some(DIRECT_ROUTE_ID))
            .await
            .is_err()
    );

    // Passing None clears the explicit override so gemini falls back to default_route_id.
    reloaded.bind_provider_route("gemini", None).await.unwrap();
    let data = reloaded.get_data().await;
    assert_eq!(
        select_route_id(&data, "gemini").as_deref(),
        Some(rid.as_str())
    );
}

#[tokio::test]
async fn state_migration_defaults_missing_split_tunnel_mode_to_false_and_persists_updates() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    // Legacy state.json without `split_tunnel_mode`.
    std::fs::write(
        &path,
        r#"{"schema_version":1,"strict_pinning_enabled":true,"auto_update_enabled":true}"#,
    )
    .unwrap();

    let state = AppState::load_or_default(path.clone());
    assert!(!state.is_split_tunnel_mode().await);
    assert!(!state.get_data().await.split_tunnel_mode);

    state.set_split_tunnel_mode(true).await.unwrap();
    let reloaded = AppState::load_or_default(path);
    assert!(reloaded.is_split_tunnel_mode().await);
    assert!(reloaded.get_data().await.split_tunnel_mode);
}

#[tokio::test]
async fn per_provider_pinned_ips_and_v22_flags_persist_and_isolate_routes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(
        &path,
        r#"{"schema_version":2,"pinned_ip":"145.241.193.245","strict_pinning_enabled":true}"#,
    )
    .unwrap();

    let state = AppState::load_or_default(path.clone());
    let data = state.get_data().await;
    // Legacy pinned_ip migrates into pinned_ips["default"].
    assert_eq!(
        data.pinned_ips.get("default").map(String::as_str),
        Some("145.241.193.245")
    );
    assert!(!data.onboarding_v2_2_done);
    assert!(!data.hide_ip_mode);
    // Direct providers see the default VPN pinned IP; routed providers do NOT fall back to it.
    assert_eq!(
        data.pinned_ip_for_provider("anthropic", false),
        Some("145.241.193.245")
    );
    assert_eq!(data.pinned_ip_for_provider("gemini", true), None);

    // Pinning a specific routed provider does not overwrite default/pinned_ip.
    state
        .set_pinned_ip_for("gemini", Some("136.244.114.42".to_string()))
        .await
        .unwrap();
    state.set_onboarding_v2_2_done(true).await.unwrap();
    state.set_hide_ip_mode(true).await.unwrap();

    let reloaded = AppState::load_or_default(path);
    let d2 = reloaded.get_data().await;
    assert_eq!(d2.pinned_ip.as_deref(), Some("145.241.193.245"));
    assert_eq!(
        d2.pinned_ip_for_provider("anthropic", false),
        Some("145.241.193.245")
    );
    assert_eq!(
        d2.pinned_ip_for_provider("gemini", true),
        Some("136.244.114.42")
    );
    assert!(reloaded.is_onboarding_v2_2_done().await);
    assert!(reloaded.is_hide_ip_mode().await);
}

#[tokio::test]
async fn scoped_ip_history_isolates_routes_and_preserves_legacy_state_json() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    // Legacy state.json with unscoped FR entry on "anthropic".
    std::fs::write(
        &path,
        r#"{
          "schema_version": 2,
          "ip_history": {
            "anthropic": [{"ip":"136.244.114.42","country_code":"FR","asn":16276,"timestamp":1730745600}],
            "openai": [],
            "gemini": []
          }
        }"#,
    )
    .unwrap();

    let state = AppState::load_or_default(path.clone());
    let fr_route =
        crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
    let fr_sel = RouteSelection::Route(fr_route.clone());
    let fr_id = state.upsert_route(fr_route).await.unwrap();
    state
        .bind_provider_route("gemini", Some(&fr_id))
        .await
        .unwrap();

    let now = 1_730_746_000;
    // Record FR on Gemini's route and on an Anthropic route, plus GB on Direct for Claude & ChatGPT.
    state
        .record_ip_history_for_selection(
            "gemini",
            &fr_sel,
            IpHistoryEntry::new("136.244.114.42", "FR", Some(16276), now),
        )
        .await
        .unwrap();
    state
        .record_ip_history_for_selection(
            "anthropic",
            &fr_sel,
            IpHistoryEntry::new("136.244.114.42", "FR", Some(16276), now),
        )
        .await
        .unwrap();
    state
        .record_ip_history_for_selection(
            "anthropic",
            &RouteSelection::Direct,
            IpHistoryEntry::new("203.0.113.10", "GB", Some(5089), now + 60),
        )
        .await
        .unwrap();
    state
        .record_ip_history_for_selection(
            "openai",
            &RouteSelection::Direct,
            IpHistoryEntry::new("203.0.113.10", "GB", Some(5089), now + 60),
        )
        .await
        .unwrap();

    let data = state.get_data().await;
    // Direct history never picks up FR from a route scope OR from legacy unscoped "anthropic".
    let anthropic_direct = data.ip_history_for_selection("anthropic", &RouteSelection::Direct);
    assert_eq!(anthropic_direct.len(), 1);
    assert_eq!(anthropic_direct[0].country_code, "GB");

    let openai_direct = data.ip_history_for_selection("openai", &RouteSelection::Direct);
    assert_eq!(openai_direct.len(), 1);
    assert_eq!(openai_direct[0].country_code, "GB");

    let gemini_routed = data.ip_history_for_provider("gemini");
    assert_eq!(gemini_routed.len(), 1);
    assert_eq!(gemini_routed[0].country_code, "FR");
    assert!(
        data.ip_history_for_selection("gemini", &RouteSelection::Direct)
            .is_empty()
    );

    // Clearing anthropic wipes both legacy and scoped keys for anthropic, leaving openai/gemini intact.
    state
        .clear_ip_history_for_provider("anthropic")
        .await
        .unwrap();
    let data = state.get_data().await;
    assert!(
        data.ip_history_for_selection("anthropic", &RouteSelection::Direct)
            .is_empty()
    );
    assert!(
        data.ip_history_for_selection("anthropic", &fr_sel)
            .is_empty()
    );
    assert!(data.ip_history["anthropic"].is_empty());
    assert_eq!(data.ip_history_for_provider("gemini").len(), 1);
    assert_eq!(
        data.ip_history_for_selection("openai", &RouteSelection::Direct)
            .len(),
        1
    );

    let reloaded = AppState::load_or_default(path);
    assert_eq!(
        reloaded.get_data().await.ip_history_for_provider("gemini")[0].country_code,
        "FR"
    );
}

#[tokio::test]
async fn trusted_exceptions_persist_across_restarts_and_canonicalize() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    let state = AppState::load_or_default(path.clone());

    state
        .add_trusted_exception("claude", " 185.220.101.5 ")
        .await
        .unwrap();
    state
        .add_trusted_exception("anthropic", "185.220.101.5")
        .await
        .unwrap();
    state
        .add_trusted_exception("openai", "2001:0db8::1")
        .await
        .unwrap();
    state
        .allow_provider_for_session("anthropic")
        .await
        .unwrap();

    assert!(
        state
            .is_ip_trusted_for_provider("anthropic", "185.220.101.5")
            .await
    );
    assert!(
        !state
            .is_ip_trusted_for_provider("openai", "185.220.101.5")
            .await
    );
    assert!(
        state
            .is_ip_trusted_for_provider("openai", "2001:db8::1")
            .await
    );
    assert_eq!(state.get_data().await.trusted_exceptions["anthropic"].len(), 1);

    // Simulate app restart: session allowances clear, trusted exceptions survive.
    let reloaded = AppState::load_or_default(path.clone());
    assert!(!reloaded.is_provider_session_allowed("anthropic").await);
    assert!(
        reloaded
            .is_ip_trusted_for_provider("anthropic", "185.220.101.5")
            .await
    );
    assert!(
        reloaded
            .is_ip_trusted_for_provider("openai", "2001:0db8::1")
            .await
    );

    reloaded
        .remove_trusted_exception("anthropic", "185.220.101.5")
        .await
        .unwrap();
    assert!(
        !reloaded
            .is_ip_trusted_for_provider("anthropic", "185.220.101.5")
            .await
    );
    assert!(
        !reloaded
            .get_data()
            .await
            .trusted_exceptions
            .contains_key("anthropic")
    );

    reloaded.clear_trusted_exceptions(None).await.unwrap();
    assert!(reloaded.get_data().await.trusted_exceptions.is_empty());
}

#[tokio::test]
async fn disabled_providers_persist_clear_blocks_and_filter_unrouted() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("state.json");
    let state = AppState::load_or_default(path.clone());
    state.block_provider("gemini").await.unwrap();
    assert!(state.is_provider_blocked("gemini").await);

    state.set_provider_monitoring("gemini", false).await.unwrap();
    assert!(state.is_provider_disabled("gemini").await);
    assert!(!state.is_provider_blocked("gemini").await);
    assert_eq!(
        state.enabled_unrouted_providers().await,
        vec!["anthropic", "openai"]
    );

    let reloaded = AppState::load_or_default(path);
    assert!(reloaded.is_provider_disabled("gemini").await);
    assert!(reloaded.disabled_providers().await.contains("gemini"));

    reloaded
        .set_provider_monitoring("gemini", true)
        .await
        .unwrap();
    assert!(!reloaded.is_provider_disabled("gemini").await);
    assert_eq!(
        reloaded.enabled_unrouted_providers().await,
        vec!["anthropic", "openai", "gemini"]
    );
}

#[tokio::test]
async fn clear_provider_blocks_and_session_isolates_provider_and_preserves_exceptions() {
    let state = AppState::new_in_memory();
    state.block_provider("anthropic").await.unwrap();
    state.block_provider("openai").await.unwrap();
    state
        .allow_provider_for_session("anthropic")
        .await
        .unwrap();
    state
        .add_trusted_exception("anthropic", "1.2.3.4")
        .await
        .unwrap();

    state
        .clear_provider_blocks_and_session("anthropic")
        .await
        .unwrap();

    assert!(!state.is_provider_blocked("anthropic").await);
    assert!(!state.is_provider_session_allowed("anthropic").await);
    assert!(state.is_provider_blocked("openai").await);
    assert!(
        state
            .is_ip_trusted_for_provider("anthropic", "1.2.3.4")
            .await
    );
}

#[tokio::test]
async fn apply_profile_route_reenables_existing_disabled_route() {
    let state = AppState::new_in_memory();
    let mut route = crate::routing::parse_route_key("socks5://1.2.3.4:1080#nl", 1).unwrap();
    let id = route.id.clone();
    route.enabled = false;
    state.upsert_route(route.clone()).await.unwrap();
    assert!(!state.get_route(&id).await.unwrap().enabled);

    state.apply_profile_route(route).await.unwrap();
    assert!(state.get_route(&id).await.unwrap().enabled);
    assert_eq!(
        state.get_data().await.profile_route_id.as_deref(),
        Some(id.as_str())
    );
    assert!(matches!(
        state.route_selection("anthropic").await,
        RouteSelection::Route(r) if r.id == id && r.enabled
    ));
}

#[tokio::test]
async fn has_explicit_pinned_ip_distinguishes_provider_pin_from_default() {
    let state = AppState::new_in_memory();
    state
        .set_pinned_ip_for("default", Some("2.2.2.2".to_string()))
        .await
        .unwrap();
    assert!(!state.has_explicit_pinned_ip("anthropic").await);

    state
        .set_pinned_ip_for("anthropic", Some("1.1.1.1".to_string()))
        .await
        .unwrap();
    assert!(state.has_explicit_pinned_ip("anthropic").await);
    assert_eq!(
        state.get_data().await.pinned_ip_for_provider("anthropic", false),
        Some("1.1.1.1")
    );

    state.set_pinned_ip_for("anthropic", None).await.unwrap();
    assert!(!state.has_explicit_pinned_ip("anthropic").await);
    assert_eq!(
        state.get_data().await.pinned_ip_for_provider("anthropic", false),
        Some("2.2.2.2")
    );
}
