use std::fs;
use std::path::Path;

use serde_json::json;
use tempfile::TempDir;

use zastava_lib::auditor::profile_switcher::{
    create_claude_profile_in, delete_claude_profile_in_with_home, list_claude_profiles_in,
    resolve_claude_desktop_dir_for_platform, switch_claude_profile_in_with_home,
};

#[test]
fn e2e_scenario_1_browser_login_and_desktop_cli_isolation() {
    let tmp = TempDir::new().unwrap();
    let storage_dir = tmp.path().join("profiles");
    let claude_dir = tmp.path().join("Claude");
    let home_dir = tmp.path().join("home");
    fs::create_dir_all(claude_dir.join("Local Storage/leveldb")).unwrap();
    fs::create_dir_all(claude_dir.join("Network")).unwrap();
    fs::create_dir_all(claude_dir.join("DawnWebGPUCache")).unwrap();
    fs::create_dir_all(home_dir.join(".claude")).unwrap();

    // Seed Profile A (default) Desktop + CLI credentials + non-auth MCP settings
    fs::write(claude_dir.join("Network/Cookies"), b"SESSION_COOKIE_ACCOUNT_A").unwrap();
    fs::write(claude_dir.join("Local Storage/leveldb/0001.ldb"), b"STORAGE_A").unwrap();
    fs::write(claude_dir.join("DawnWebGPUCache/blob.bin"), b"CACHE_A").unwrap();
    fs::write(claude_dir.join("Preferences"), r#"{"account":"A"}"#).unwrap();
    fs::write(claude_dir.join("claude_desktop_config.json"), r#"{"mcpServers":{"local":{}}}"#).unwrap();
    fs::write(home_dir.join(".claude/.credentials.json"), r#"{"claudeAiOauth":{"accessToken":"tok-A"}}"#).unwrap();
    fs::write(
        home_dir.join(".claude.json"),
        json!({
            "userID": "user-A",
            "oauthAccount": { "emailAddress": "alice@example.com" },
            "mcpServers": { "github": { "command": "npx" } },
            "theme": "dark"
        })
        .to_string(),
    )
    .unwrap();

    // Create Profile B (for browser login) and Profile C (empty check)
    let list_b = create_claude_profile_in(&storage_dir, &claude_dir, "Account B", None, None, None).unwrap();
    let prof_b = list_b.profiles.iter().find(|p| p.name == "Account B").unwrap().clone();
    let list_c = create_claude_profile_in(&storage_dir, &claude_dir, "Profile C", None, None, None).unwrap();
    let prof_c = list_c.profiles.iter().find(|p| p.name == "Profile C").unwrap().clone();

    // Switch A -> B: B must start clean for fresh browser login while A's backup stays intact
    let sw_b = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_b.id).unwrap();
    assert_eq!(sw_b.active_profile.id, prof_b.id);
    assert!(!claude_dir.join("Network/Cookies").exists(), "A Cookies must not leak to B");
    assert!(!claude_dir.join("Preferences").exists(), "A Preferences must not leak to B");
    assert!(claude_dir.join("claude_desktop_config.json").exists(), "Desktop MCP config must be preserved");
    assert!(!claude_dir.join("DawnWebGPUCache/blob.bin").exists(), "Electron cache must be purged");
    assert!(!home_dir.join(".claude/.credentials.json").exists(), "A CLI credentials must not leak to B");
    let cli_b_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home_dir.join(".claude.json")).unwrap()).unwrap();
    assert!(cli_b_json.get("oauthAccount").is_none());
    assert!(cli_b_json.get("userID").is_none());
    assert!(cli_b_json.get("mcpServers").is_some(), "non-auth mcpServers must survive");
    assert_eq!(
        fs::read_to_string(storage_dir.join("default/snapshot/Network/Cookies")).unwrap(),
        "SESSION_COOKIE_ACCOUNT_A"
    );
    assert!(storage_dir.join("default/snapshot/cli_credentials.json").exists());

    // Switch unlogged B -> C: B still never had real auth, so has_saved_session must remain false
    let _ = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_c.id).unwrap();
    let list_after_c = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
    let b_meta = list_after_c.profiles.iter().find(|p| p.id == prof_b.id).unwrap();
    assert!(!b_meta.has_saved_session, "device-id files alone must not mark has_saved_session=true");
    assert!(list_after_c.profiles.iter().find(|p| p.id == "default").unwrap().has_saved_session);

    // Switch to B, perform browser/CLI login for B, then switch B -> A -> B
    let _ = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_b.id).unwrap();
    fs::create_dir_all(claude_dir.join("Network")).unwrap();
    fs::write(claude_dir.join("Network/Cookies"), b"SESSION_COOKIE_ACCOUNT_B").unwrap();
    fs::write(home_dir.join(".claude/.credentials.json"), r#"{"claudeAiOauth":{"accessToken":"tok-B"}}"#).unwrap();
    fs::write(
        home_dir.join(".claude.json"),
        json!({ "userID": "user-B", "oauthAccount": { "emailAddress": "bob@example.com" }, "mcpServers": { "github": { "command": "npx" } } }).to_string(),
    )
    .unwrap();

    // Back to A: restores A verbatim without touching B's backup
    let _ = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), "default").unwrap();
    assert_eq!(fs::read_to_string(claude_dir.join("Network/Cookies")).unwrap(), "SESSION_COOKIE_ACCOUNT_A");
    assert!(fs::read_to_string(home_dir.join(".claude/.credentials.json")).unwrap().contains("tok-A"));
    assert_eq!(
        fs::read_to_string(storage_dir.join(format!("{}/snapshot/Network/Cookies", prof_b.id))).unwrap(),
        "SESSION_COOKIE_ACCOUNT_B"
    );

    // Switch back to B: restores B verbatim
    let _ = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_b.id).unwrap();
    assert_eq!(fs::read_to_string(claude_dir.join("Network/Cookies")).unwrap(), "SESSION_COOKIE_ACCOUNT_B");
    assert!(fs::read_to_string(home_dir.join(".claude/.credentials.json")).unwrap().contains("tok-B"));

    // Deleting unused Profile C deletes only C without touching active B or backup A
    let after_del = delete_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_c.id).unwrap();
    assert_eq!(after_del.profiles.len(), 2);
    assert!(!storage_dir.join(&prof_c.id).exists());
    assert_eq!(fs::read_to_string(claude_dir.join("Network/Cookies")).unwrap(), "SESSION_COOKIE_ACCOUNT_B");
    assert_eq!(
        fs::read_to_string(storage_dir.join("default/snapshot/Network/Cookies")).unwrap(),
        "SESSION_COOKIE_ACCOUNT_A"
    );
}

#[test]
fn e2e_scenario_6_windows_macos_path_bom_crlf_symlink_parity() {
    let tmp = TempDir::new().unwrap();

    // Windows standard %APPDATA%\Claude vs MSIX Microsoft Store vs macOS
    let win_home = tmp.path().join("win_user");
    let win_roaming = win_home.join("AppData/Roaming");
    let win_local = win_home.join("AppData/Local");
    let msix_claude = win_local.join("Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude");
    fs::create_dir_all(&msix_claude).unwrap();
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("windows", None, Some(&win_roaming), Some(&win_local)),
        Some(msix_claude.clone())
    );
    let direct_win_claude = win_roaming.join("Claude");
    fs::create_dir_all(&direct_win_claude).unwrap();
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("windows", None, Some(&win_roaming), Some(&win_local)),
        Some(direct_win_claude)
    );

    let mac_home = tmp.path().join("mac_user");
    let mac_claude = mac_home.join("Library/Application Support/Claude");
    fs::create_dir_all(&mac_claude).unwrap();
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("macos", Some(&mac_home), None, None),
        Some(mac_claude)
    );

    // UTF-8 BOM + CRLF profiles.json & .claude.json safety
    let storage = tmp.path().join("profiles_bom");
    let claude = tmp.path().join("Claude_bom");
    let home = tmp.path().join("home_bom");
    fs::create_dir_all(&storage).unwrap();
    fs::create_dir_all(claude.join("Network")).unwrap();
    fs::create_dir_all(home.join(".claude")).unwrap();

    let bom_profiles = "\u{FEFF}{\r\n  \"version\": 1,\r\n  \"profiles\": [\r\n    {\r\n      \"id\": \"default\",\r\n      \"name\": \"Основной\",\r\n      \"isolated_device_id\": \"dev-1\",\r\n      \"created_at\": 1,\r\n      \"last_used_at\": 1,\r\n      \"is_active\": true,\r\n      \"has_saved_session\": false\r\n    }\r\n  ]\r\n}\r\n";
    fs::write(storage.join("profiles.json"), bom_profiles.as_bytes()).unwrap();

    let bom_claude_json = "\u{FEFF}{\r\n  \"userID\": \"u1\",\r\n  \"oauthAccount\": {\"emailAddress\": \"bom@example.com\"},\r\n  \"mcpServers\": {\"fs\": {\"command\": \"npx\"}}\r\n}\r\n";
    fs::write(home.join(".claude.json"), bom_claude_json.as_bytes()).unwrap();
    let list = create_claude_profile_in(&storage, &claude, "Second", None, None, None).unwrap();
    let second_id = list.profiles.iter().find(|p| p.name == "Second").unwrap().id.clone();

    #[cfg(unix)]
    {
        // Planted symlink inside .credentials.json pointing outside must never leak secret target
        let decoy = tmp.path().join("outside_secret.txt");
        fs::write(&decoy, "DO_NOT_COPY_THIS_SECRET").unwrap();
        std::os::unix::fs::symlink(&decoy, home.join(".claude/.credentials.json")).unwrap();
    }

    let _ = switch_claude_profile_in_with_home(&storage, &claude, Some(&home), &second_id).unwrap();
    assert!(!storage.join("default/snapshot/cli_credentials.json").exists(), "symlink credentials must not be snapshotted");
    assert!(!home.join(".claude/.credentials.json").exists(), "symlink credentials must be removed on switch");
    assert!(fs::read_to_string(storage.join("default/snapshot/cli_oauth.json")).unwrap().contains("bom@example.com"));
}

#[test]
fn e2e_scenario_6b_claude_desktop_dir_missing_returns_none_cleanly() {
    let tmp = TempDir::new().unwrap();
    let empty_home = tmp.path().join("no_claude");
    fs::create_dir_all(&empty_home).unwrap();
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("macos", None, None, None),
        None
    );
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("windows", None, None, None),
        None
    );
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("macos", Some(&empty_home), None, None),
        Some(empty_home.join("Library/Application Support/Claude"))
    );
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("windows", None, Some(&empty_home), Some(&empty_home)),
        Some(empty_home.join("Claude"))
    );
    let _ = Path::new(".");
}
