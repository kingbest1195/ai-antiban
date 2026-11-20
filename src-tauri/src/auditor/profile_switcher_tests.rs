use super::*;

#[test]
fn test_profile_creation_and_default_initialization() {
    let temp = tempfile::tempdir().unwrap();
    let storage_dir = temp.path().join(".zastava").join("claude_profiles");
    let claude_dir = temp.path().join("Claude");
    fs::create_dir_all(&claude_dir).unwrap();

    // 1. Initial list auto-creates default profile
    let resp = list_claude_profiles_in(&storage_dir, &claude_dir, Some("145.241.10.5")).unwrap();
    assert_eq!(resp.profiles.len(), 1);
    assert_eq!(resp.profiles[0].id, "default");
    assert_eq!(resp.profiles[0].name, "Основной аккаунт");
    assert_eq!(resp.profiles[0].bound_ip.as_deref(), Some("145.241.10.5"));
    assert!(resp.profiles[0].is_active);

    // 2. Create second profile
    let resp2 = create_claude_profile_in(
        &storage_dir,
        &claude_dir,
        "Рабочий Claude Pro",
        Some("195.12.34.56".to_string()),
        Some("NL".to_string()),
        Some("socks5://proxy.example.com:1080".to_string()),
    )
    .unwrap();
    assert_eq!(resp2.profiles.len(), 2);
    assert_eq!(resp2.profiles[1].name, "Рабочий Claude Pro");
    assert_eq!(
        resp2.profiles[1].bound_upstream_key.as_deref(),
        Some("socks5://proxy.example.com:1080")
    );
    assert_ne!(
        resp2.profiles[0].isolated_device_id,
        resp2.profiles[1].isolated_device_id
    );
}

#[test]
fn test_profile_switching_and_snapshot_restoration() {
    let temp = tempfile::tempdir().unwrap();
    let storage_dir = temp.path().join(".zastava").join("claude_profiles");
    let claude_dir = temp.path().join("Claude");
    fs::create_dir_all(&claude_dir).unwrap();

    // Put initial session file in claude_dir for default profile
    fs::write(claude_dir.join("Cookies"), "session_default_cookie_data").unwrap();
    fs::create_dir_all(claude_dir.join("Cache")).unwrap();
    fs::write(
        claude_dir.join("Cache").join("cache_file.bin"),
        "cached_telemetry",
    )
    .unwrap();

    // Preserve claude_desktop_config.json
    fs::write(
        claude_dir.join("claude_desktop_config.json"),
        r#"{"mcpServers":{}}"#,
    )
    .unwrap();

    // Create second profile
    let resp = create_claude_profile_in(
        &storage_dir,
        &claude_dir,
        "Резервный аккаунт",
        None,
        None,
        Some("http://10.0.0.1:8080".to_string()),
    )
    .unwrap();
    let p2_id = resp.profiles[1].id.clone();

    // Switch to profile 2
    let switch_res = switch_claude_profile_in(&storage_dir, &claude_dir, &p2_id).unwrap();
    assert_eq!(switch_res.previous_profile_id, "default");
    assert_eq!(switch_res.active_profile.id, p2_id);
    assert_eq!(
        switch_res.bound_upstream_key_updated.as_deref(),
        Some("http://10.0.0.1:8080")
    );

    // Caches were cleaned
    assert!(!claude_dir.join("Cache").exists());
    // claude_desktop_config.json strictly preserved
    assert!(claude_dir.join("claude_desktop_config.json").exists());

    // Default profile's snapshot contains old Cookies
    let default_snapshot = storage_dir.join("default").join("snapshot").join("Cookies");
    assert!(default_snapshot.exists());
    assert_eq!(
        fs::read_to_string(&default_snapshot).unwrap(),
        "session_default_cookie_data"
    );

    // Claude dir now has profile 2's fresh isolated device registry
    assert!(claude_dir.join("ant-device-registry.json").exists());
    let registry_content = fs::read_to_string(claude_dir.join("ant-device-registry.json")).unwrap();
    assert!(registry_content.contains(&resp.profiles[1].isolated_device_id));

    // Switch back to default profile
    let switch_back = switch_claude_profile_in(&storage_dir, &claude_dir, "default").unwrap();
    assert_eq!(switch_back.active_profile.id, "default");
    assert_eq!(switch_back.bound_upstream_key_updated, None);
    assert!(claude_dir.join("Cookies").exists());
    assert_eq!(
        fs::read_to_string(claude_dir.join("Cookies")).unwrap(),
        "session_default_cookie_data"
    );
}

#[test]
fn test_delete_profile_and_prevent_last_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let storage_dir = temp.path().join(".zastava").join("claude_profiles");
    let claude_dir = temp.path().join("Claude");

    // Single profile cannot be deleted
    let _ = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
    let del_err = delete_claude_profile_in(&storage_dir, &claude_dir, "default");
    assert!(del_err.is_err());

    // Add second profile and delete it
    let resp =
        create_claude_profile_in(&storage_dir, &claude_dir, "Temporary", None, None, None).unwrap();
    let p2_id = resp.profiles[1].id.clone();
    let after_del = delete_claude_profile_in(&storage_dir, &claude_dir, &p2_id).unwrap();
    assert_eq!(after_del.profiles.len(), 1);
}

#[test]
fn test_ip_binding_update() {
    let temp = tempfile::tempdir().unwrap();
    let storage_dir = temp.path().join(".zastava").join("claude_profiles");
    let claude_dir = temp.path().join("Claude");

    let _ = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
    let updated = update_profile_bound_ip_in(
        &storage_dir,
        &claude_dir,
        "default",
        Some("104.28.19.2".to_string()),
        Some("US".to_string()),
    )
    .unwrap();

    assert_eq!(updated.profiles[0].bound_ip.as_deref(), Some("104.28.19.2"));
    assert_eq!(updated.profiles[0].bound_country.as_deref(), Some("US"));

    let updated_upstream = update_profile_bound_upstream_in(
        &storage_dir,
        &claude_dir,
        "default",
        Some("socks5://127.0.0.1:1080".to_string()),
    )
    .unwrap();
    assert_eq!(
        updated_upstream.profiles[0].bound_upstream_key.as_deref(),
        Some("socks5://127.0.0.1:1080")
    );
    assert!(updated_upstream.profiles[0].bound_route_id.is_some());
}

#[test]
fn test_sync_profiles_for_route_update_in() {
    let temp = tempfile::tempdir().unwrap();
    let storage_dir = temp.path().join(".zastava").join("claude_profiles");
    let claude_dir = temp.path().join("Claude");

    let _ = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
    let initial_key = "socks5://127.0.0.1:1080#NL";
    let bound = update_profile_bound_upstream_in(
        &storage_dir,
        &claude_dir,
        "default",
        Some(initial_key.to_string()),
    )
    .unwrap();
    let route_id = bound.profiles[0].bound_route_id.clone().unwrap();

    // Update raw key for the same route ID
    let updated_key = "socks5://127.0.0.1:1080#NL-Updated";
    let res =
        sync_profiles_for_route_update_in(&storage_dir, &claude_dir, &route_id, Some(updated_key))
            .unwrap();
    assert_eq!(res, Some(Some(updated_key.to_string())));

    // Remove route -> clears profile binding and reports active profile cleared
    let removed =
        sync_profiles_for_route_update_in(&storage_dir, &claude_dir, &route_id, None).unwrap();
    assert_eq!(removed, Some(None));
    let after = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
    assert_eq!(after.profiles[0].bound_upstream_key, None);
    assert_eq!(after.profiles[0].bound_route_id, None);
}

#[test]
fn test_delete_active_profile_switches_and_persists_cleanly() {
    let temp = tempfile::tempdir().unwrap();
    let storage_dir = temp.path().join(".zastava").join("claude_profiles");
    let claude_dir = temp.path().join("Claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(claude_dir.join("Cookies"), "default_cookies").unwrap();

    let _ = list_claude_profiles_in(&storage_dir, &claude_dir, Some("1.1.1.1")).unwrap();
    update_profile_bound_upstream_in(
        &storage_dir,
        &claude_dir,
        "default",
        Some("socks5://127.0.0.1:1080#DefaultNL".to_string()),
    )
    .unwrap();

    let created = create_claude_profile_in(
        &storage_dir,
        &claude_dir,
        "TempActive",
        Some("2.2.2.2".to_string()),
        Some("DE".to_string()),
        Some("socks5://127.0.0.1:1081#TempDE".to_string()),
    )
    .unwrap();
    let temp_id = created.profiles[1].id.clone();

    switch_claude_profile_in(&storage_dir, &claude_dir, &temp_id).unwrap();
    fs::write(claude_dir.join("Cookies"), "temp_active_cookies").unwrap();

    let after_del = delete_claude_profile_in(&storage_dir, &claude_dir, &temp_id).unwrap();
    assert_eq!(after_del.profiles.len(), 1);
    assert_eq!(after_del.active_profile_id, "default");
    assert!(after_del.profiles[0].is_active);
    assert_eq!(after_del.profiles[0].bound_ip.as_deref(), Some("1.1.1.1"));
    assert_eq!(
        after_del.profiles[0].bound_upstream_key.as_deref(),
        Some("socks5://127.0.0.1:1080#DefaultNL")
    );
    assert!(!storage_dir.join(&temp_id).exists());
    assert_eq!(
        fs::read_to_string(claude_dir.join("Cookies")).unwrap(),
        "default_cookies"
    );

    let reloaded = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
    assert_eq!(reloaded.profiles.len(), 1);
    assert_eq!(reloaded.active_profile_id, "default");
}

#[test]
fn test_concurrent_profile_operations_do_not_corrupt_storage() {
    let temp = tempfile::tempdir().unwrap();
    let storage_dir = temp.path().join(".zastava").join("claude_profiles");
    let claude_dir = temp.path().join("Claude");
    fs::create_dir_all(&claude_dir).unwrap();
    let _ = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();

    std::thread::scope(|s| {
        for i in 0..8 {
            let sd = &storage_dir;
            let cd = &claude_dir;
            s.spawn(move || {
                create_claude_profile_in(
                    sd,
                    cd,
                    &format!("Worker-{i}"),
                    Some(format!("10.0.0.{}", i + 10)),
                    Some("NL".to_string()),
                    None,
                )
                .unwrap();
            });
        }
    });

    let listed = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
    assert_eq!(listed.profiles.len(), 9);
}

#[test]
fn test_active_profile_binding_state_in() {
    let temp = tempfile::tempdir().unwrap();
    let storage_dir = temp.path().join(".zastava").join("claude_profiles");
    let claude_dir = temp.path().join("Claude");
    fs::create_dir_all(&claude_dir).unwrap();

    assert_eq!(active_profile_binding_state_in(&storage_dir).unwrap(), None);

    let created = create_claude_profile_in(
        &storage_dir,
        &claude_dir,
        "Work",
        Some("185.10.20.30".to_string()),
        Some("FR".to_string()),
        Some("socks5://127.0.0.1:1080#FR".to_string()),
    )
    .unwrap();
    let work_id = created.profiles[1].id.clone();
    switch_claude_profile_in(&storage_dir, &claude_dir, &work_id).unwrap();

    let state = active_profile_binding_state_in(&storage_dir)
        .unwrap()
        .expect("binding state must exist");
    assert_eq!(state.profile_id, work_id);
    assert_eq!(state.bound_ip.as_deref(), Some("185.10.20.30"));
    assert_eq!(
        state.bound_upstream_key.as_deref(),
        Some("socks5://127.0.0.1:1080#FR")
    );
    assert!(state.bound_route_id.is_some());
}

#[tokio::test]
async fn test_safe_logout_clears_auth_preserves_device_id_and_starts_cooldown() {
    crate::sysproxy::force_os_dry_run();
    assert!(!crate::sysproxy::os_effects_enabled());

    let temp = tempfile::tempdir().unwrap();
    let claude_dir = temp.path().join("Claude");
    let home_dir = temp.path().join("home");
    let state_path = temp.path().join("state.json");
    fs::create_dir_all(claude_dir.join("Network")).unwrap();
    fs::create_dir_all(claude_dir.join("Local Storage/leveldb")).unwrap();
    fs::create_dir_all(claude_dir.join("Session Storage")).unwrap();
    fs::create_dir_all(claude_dir.join("IndexedDB")).unwrap();
    fs::create_dir_all(claude_dir.join("WebStorage")).unwrap();
    fs::create_dir_all(claude_dir.join("SharedStorage")).unwrap();
    fs::create_dir_all(home_dir.join(".claude")).unwrap();

    // Auth/session files that MUST be deleted
    fs::write(claude_dir.join("Cookies"), "cookie-bytes").unwrap();
    fs::write(claude_dir.join("Cookies-journal"), "journal").unwrap();
    fs::write(claude_dir.join("Network/Cookies"), "net-cookie").unwrap();
    fs::write(claude_dir.join("Network/Cookies-journal"), "net-journal").unwrap();
    fs::write(claude_dir.join("Network/Network Persistent State"), "{}").unwrap();
    fs::write(claude_dir.join("Network/Trust Tokens"), "tok").unwrap();
    fs::write(claude_dir.join("Local Storage/leveldb/000001.ldb"), "ls").unwrap();
    fs::write(claude_dir.join("Session Storage/000001.log"), "ss").unwrap();
    fs::write(claude_dir.join("IndexedDB/db.bin"), "idb").unwrap();
    fs::write(claude_dir.join("WebStorage/ws.bin"), "ws").unwrap();
    fs::write(claude_dir.join("SharedStorage/ss.db"), "shared").unwrap();
    fs::write(claude_dir.join("DIPS"), "dips").unwrap();
    fs::write(claude_dir.join("DIPS-wal"), "dips-wal").unwrap();
    fs::write(
        home_dir.join(".claude/.credentials.json"),
        r#"{"token":"secret"}"#,
    )
    .unwrap();
    fs::write(
        home_dir.join(".claude.json"),
        r#"{"oauthAccount":{"email":"a@b.c"},"userID":"u1","mcpServers":{"s1":{}}}"#,
    )
    .unwrap();

    // Device identity & configs that MUST BE STRICTLY PRESERVED
    let reg_json = r#"{"deviceId":"dev-preserve-123","version":1}"#;
    let ccd_json = r#"{"device_id":"dev-preserve-123","client_id":"client_dev"}"#;
    let desktop_cfg = r#"{"mcpServers":{"local":{}}}"#;
    let cli_settings = r#"{"env":{"HTTPS_PROXY":"http://127.0.0.1:8899"}}"#;
    fs::write(claude_dir.join("ant-device-registry.json"), reg_json).unwrap();
    fs::write(claude_dir.join("ccd-ids.json"), ccd_json).unwrap();
    fs::write(claude_dir.join("claude_desktop_config.json"), desktop_cfg).unwrap();
    fs::write(home_dir.join(".claude/settings.json"), cli_settings).unwrap();

    let state = crate::state::AppState::load_or_default(state_path.clone());
    let res = safe_logout_claude_with_dirs(&state, claude_dir.clone(), Some(home_dir.clone()))
        .await
        .expect("safe_logout succeeds");

    assert_eq!(res.closed_processes, 0);
    assert!(res.preserved_device_id);
    assert_eq!(res.cooldown_secs, 14_400);
    assert!(res.cooldown_until > 0);
    assert!(!res.cleared_items.is_empty());

    // Auth/session files deleted
    assert!(!claude_dir.join("Cookies").exists());
    assert!(!claude_dir.join("Cookies-journal").exists());
    assert!(!claude_dir.join("Network/Cookies").exists());
    assert!(!claude_dir.join("Network/Cookies-journal").exists());
    assert!(!claude_dir.join("Network/Network Persistent State").exists());
    assert!(!claude_dir.join("Network/Trust Tokens").exists());
    assert!(!claude_dir.join("Local Storage").exists());
    assert!(!claude_dir.join("Session Storage").exists());
    assert!(!claude_dir.join("IndexedDB").exists());
    assert!(!claude_dir.join("WebStorage").exists());
    assert!(!claude_dir.join("SharedStorage").exists());
    assert!(!claude_dir.join("DIPS").exists());
    assert!(!claude_dir.join("DIPS-wal").exists());
    assert!(!home_dir.join(".claude/.credentials.json").exists());

    let claude_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home_dir.join(".claude.json")).unwrap()).unwrap();
    assert!(claude_json.get("oauthAccount").is_none());
    assert!(claude_json.get("userID").is_none());
    assert!(claude_json.get("mcpServers").is_some());

    // Preserved files untouched
    assert_eq!(
        fs::read_to_string(claude_dir.join("ant-device-registry.json")).unwrap(),
        reg_json
    );
    assert_eq!(
        fs::read_to_string(claude_dir.join("ccd-ids.json")).unwrap(),
        ccd_json
    );
    assert_eq!(
        fs::read_to_string(claude_dir.join("claude_desktop_config.json")).unwrap(),
        desktop_cfg
    );
    assert_eq!(
        fs::read_to_string(home_dir.join(".claude/settings.json")).unwrap(),
        cli_settings
    );

    // 4h cooldown persisted in state.json
    let reloaded = crate::state::AppState::load_or_default(state_path);
    let data = reloaded.get_data().await;
    assert_eq!(data.ip_change_cooldown_until, Some(res.cooldown_until));
    assert!(data.last_safe_logout_at.is_some());
}
