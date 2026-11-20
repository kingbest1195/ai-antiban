use std::fs;
use std::io::Write;
use std::path::Path;

use zip::write::SimpleFileOptions;

use super::*;
use crate::state::BunkerSettings;

fn make_mock_claude_and_cursor(home: &Path, project_dir: &Path) {
    let claude_dir = home.join(".claude");
    let proj_slug = "-Users-test-app";
    let proj_dir = claude_dir.join("projects").join(proj_slug);
    fs::create_dir_all(proj_dir.join("memory")).unwrap();
    fs::write(proj_dir.join("memory").join("MEMORY.md"), "# Memory\nRust").unwrap();
    fs::write(
        proj_dir.join("session-1.jsonl"),
        r#"{"type":"last-prompt","lastPrompt":"Implement Bunker backup"}"#,
    )
    .unwrap();

    fs::create_dir_all(claude_dir.join("plans")).unwrap();
    fs::write(claude_dir.join("plans").join("p1.md"), "# Plan 1").unwrap();
    fs::write(claude_dir.join("CLAUDE.md"), "# Global Rules").unwrap();
    fs::write(claude_dir.join("history.jsonl"), "{}\n").unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{"theme":"dark","apiKey":"sk-ant-secret-12345678901234567890"}"#,
    )
    .unwrap();
    // Credentials file that MUST NEVER be exported
    fs::write(
        claude_dir.join(".credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"secret-oauth-token"}}"#,
    )
    .unwrap();

    // ~/.claude.json with OAuth secret
    fs::write(
        home.join(".claude.json"),
        r#"{"numStartups":5,"oauthAccount":{"emailAddress":"u@example.com","accountUuid":"abc"},"primaryApiKey":"sk-ant-api-secret"}"#,
    )
    .unwrap();

    // Cursor IDE User directory + state.vscdb (MUST NEVER be copied)
    #[cfg(target_os = "macos")]
    let cursor_user = home.join("Library/Application Support/Cursor/User");
    #[cfg(target_os = "windows")]
    let cursor_user = home.join("AppData/Roaming/Cursor/User");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let cursor_user = home.join(".config/Cursor/User");

    fs::create_dir_all(cursor_user.join("snippets")).unwrap();
    fs::create_dir_all(cursor_user.join("globalStorage")).unwrap();
    fs::write(
        cursor_user.join("settings.json"),
        r#"{"editor.fontSize":14,"cursorToken":"secret-cursor-tok"}"#,
    )
    .unwrap();
    fs::write(cursor_user.join("keybindings.json"), "[]").unwrap();
    fs::write(cursor_user.join("snippets").join("rust.json"), "{}").unwrap();
    fs::write(cursor_user.join("state.vscdb"), "SECRET_SQLITE_DB").unwrap();
    fs::write(
        cursor_user.join("globalStorage").join("state.vscdb"),
        "SECRET_GLOBAL_DB",
    )
    .unwrap();

    fs::create_dir_all(home.join(".cursor")).unwrap();
    fs::write(
        home.join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"filesystem":{"command":"npx","env":{"API_KEY":"secret-mcp-key"}}}}"#,
    )
    .unwrap();

    fs::create_dir_all(project_dir).unwrap();
    fs::write(home.join(".cursorrules"), "Always write tests.").unwrap();
}

#[test]
fn backup_omits_credentials_and_state_vscdb_and_sanitizes_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let app_data = tmp.path().join("app_data");
    let home = tmp.path().join("home");
    let project = tmp.path().join("proj");
    let export_dest = tmp.path().join("desktop_copy");
    make_mock_claude_and_cursor(&home, &project);

    let settings = BunkerSettings::default();
    let res = run_bunker_backup_in(&app_data, &home, &settings, "manual", Some(&export_dest))
        .expect("backup succeeds");

    let snap_dir = Path::new(&res.snapshot.snapshot_dir);
    assert!(
        snap_dir
            .join("projects/-Users-test-app/memory/MEMORY.md")
            .is_file()
    );
    assert!(snap_dir.join("plans/p1.md").is_file());
    assert!(snap_dir.join("CLAUDE.md").is_file());
    assert!(snap_dir.join("cursor/User/settings.json").is_file());
    assert!(snap_dir.join("cursor/User/keybindings.json").is_file());
    assert!(snap_dir.join("cursor/User/snippets/rust.json").is_file());
    assert!(snap_dir.join("cursor/mcp.json").is_file());
    assert!(snap_dir.join("cursor/rules/global.cursorrules").is_file());
    assert!(res.exported_copy_dir.is_some());

    // Secrets & state.vscdb MUST be absent
    assert!(!snap_dir.join(".credentials.json").exists());
    assert!(!snap_dir.join("cursor/User/state.vscdb").exists());
    assert!(
        !snap_dir
            .join("cursor/User/globalStorage/state.vscdb")
            .exists()
    );

    // JSON secret values MUST be redacted
    let cli_cfg = fs::read_to_string(snap_dir.join("configs/claude_cli_config.json")).unwrap();
    assert!(!cli_cfg.contains("sk-ant-api-secret"));
    assert!(!cli_cfg.contains("u@example.com"));
    assert!(cli_cfg.contains("[REDACTED]"));

    let mcp_cfg = fs::read_to_string(snap_dir.join("cursor/mcp.json")).unwrap();
    assert!(!mcp_cfg.contains("secret-mcp-key"));
    assert!(mcp_cfg.contains("filesystem"));

    let cur_settings = fs::read_to_string(snap_dir.join("cursor/User/settings.json")).unwrap();
    assert!(!cur_settings.contains("secret-cursor-tok"));
    assert!(cur_settings.contains("editor.fontSize"));

    // RESTORE_PROMPT.md includes Claude Code context + Cursor + MCP
    let prompt = fs::read_to_string(&res.restore_prompt_path).unwrap();
    assert!(prompt.contains("Implement Bunker backup"));
    assert!(prompt.contains("Cursor IDE"));
    assert!(prompt.contains("filesystem"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = fs::metadata(snap_dir).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(&res.restore_prompt_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }
}

#[test]
fn fifo_retention_keeps_seven_newest_snapshots() {
    let tmp = tempfile::tempdir().unwrap();
    let app_data = tmp.path().join("app_data");
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::write(home.join(".claude/CLAUDE.md"), "# Test").unwrap();

    let settings = BunkerSettings {
        retention_count: 7,
        ..BunkerSettings::default()
    };

    let mut total_pruned = 0usize;
    let mut created_ids = Vec::new();
    for i in 0..9 {
        let res = run_bunker_backup_in(&app_data, &home, &settings, "auto", None).unwrap();
        // Give distinct created_at timestamps so FIFO order is deterministic
        let snap_dir = Path::new(&res.snapshot.snapshot_dir);
        let mut meta = res.snapshot.clone();
        meta.created_at = 1_700_000_000 + i as u64;
        retention::write_snapshot_meta(snap_dir, &meta).unwrap();
        // Re-prune with updated timestamps
        let pruned = retention::prune_old_snapshots(&bunker_snapshots_dir(&app_data), 7).unwrap();
        total_pruned += pruned + res.pruned_snapshots;
        created_ids.push(meta.id);
    }

    assert!(total_pruned >= 2);
    let listed = retention::list_snapshots(&bunker_snapshots_dir(&app_data));
    assert_eq!(listed.len(), 7);
    assert_eq!(listed[0].created_at, 1_700_000_008);
    assert_eq!(listed[6].created_at, 1_700_000_002);
}

#[test]
fn web_helper_converts_claude_json_and_chatgpt_zip() {
    let tmp = tempfile::tempdir().unwrap();

    // 1. Claude conversations.json
    let claude_json = tmp.path().join("conversations.json");
    fs::write(
        &claude_json,
        r#"[
          {
            "uuid": "c1",
            "name": "Rust Architecture",
            "created_at": "2026-10-01T12:00:00Z",
            "chat_messages": [
              {"sender": "human", "text": "Explain hexagonal layers"},
              {"sender": "assistant", "text": "Keep domain pure."}
            ]
          }
        ]"#,
    )
    .unwrap();
    let out1 = tmp.path().join("out_claude");
    let res1 = web_helper::convert_web_export_to(&claude_json, &out1).unwrap();
    assert_eq!(res1.detected_provider, "claude");
    assert_eq!(res1.conversations_count, 1);
    assert_eq!(res1.markdown_files.len(), 1);
    let md1 = fs::read_to_string(&res1.markdown_files[0]).unwrap();
    assert!(md1.contains("Explain hexagonal layers"));
    assert!(Path::new(&res1.restore_prompt_path).is_file());

    // 2. ChatGPT export.zip
    let zip_path = tmp.path().join("export.zip");
    {
        let file = fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("conversations.json", SimpleFileOptions::default())
            .unwrap();
        let chatgpt_json = r#"[
          {
            "title": "VPN Troubleshooting",
            "create_time": 1700000000.0,
            "current_node": "n2",
            "mapping": {
              "n1": {
                "id": "n1",
                "parent": null,
                "message": {"author": {"role": "user"}, "content": {"parts": ["Check IPv6"]}}
              },
              "n2": {
                "id": "n2",
                "parent": "n1",
                "message": {"author": {"role": "assistant"}, "content": {"parts": ["IPv6 is encapsulated."]}}
              }
            }
          }
        ]"#;
        writer.write_all(chatgpt_json.as_bytes()).unwrap();
        writer.finish().unwrap();
    }
    let out2 = tmp.path().join("out_chatgpt");
    let res2 = web_helper::convert_web_export_to(&zip_path, &out2).unwrap();
    assert_eq!(res2.detected_provider, "chatgpt");
    assert_eq!(res2.conversations_count, 1);
    let md2 = fs::read_to_string(&res2.markdown_files[0]).unwrap();
    assert!(md2.contains("Check IPv6"));
    assert!(md2.contains("IPv6 is encapsulated."));
}

#[test]
fn web_helper_rejects_zip_traversal_and_entry_bomb() {
    let tmp = tempfile::tempdir().unwrap();

    // 1. Path traversal archive
    let bad_zip = tmp.path().join("traversal.zip");
    {
        let file = fs::File::create(&bad_zip).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("../escape.json", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"[]").unwrap();
        writer.finish().unwrap();
    }
    let err = web_helper::convert_web_export_to(&bad_zip, &tmp.path().join("out_bad")).unwrap_err();
    assert!(err.contains("traversal") || err.contains("Небезопасный"));

    // 2. Entry-count bomb (> MAX_ZIP_ENTRIES)
    let bomb_zip = tmp.path().join("many_entries.zip");
    {
        let file = fs::File::create(&bomb_zip).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        for i in 0..=web_helper::MAX_ZIP_ENTRIES {
            writer
                .start_file(format!("e_{i}.txt"), SimpleFileOptions::default())
                .unwrap();
        }
        writer.finish().unwrap();
    }
    let err2 =
        web_helper::convert_web_export_to(&bomb_zip, &tmp.path().join("out_bomb")).unwrap_err();
    assert!(err2.contains("слишком много записей"));
}

#[test]
fn scheduler_respects_enabled_data_and_interval() {
    let mut s = BunkerSettings::default();
    assert!(!scheduler::should_run_scheduled_backup(&s, 10_000, false));
    assert!(scheduler::should_run_scheduled_backup(&s, 10_000, true));

    s.last_backup_at = Some(10_000);
    assert!(!scheduler::should_run_scheduled_backup(
        &s,
        10_000 + 3600,
        true
    ));
    assert!(scheduler::should_run_scheduled_backup(
        &s,
        10_000 + 24 * 3600,
        true
    ));

    s.auto_backup_enabled = false;
    assert!(!scheduler::should_run_scheduled_backup(
        &s,
        10_000 + 48 * 3600,
        true
    ));
}

#[test]
fn concurrent_snapshot_dir_allocation_never_collides() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("snapshots");
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let r = root.clone();
            std::thread::spawn(move || allocate_snapshot_dir(&r).unwrap())
        })
        .collect();
    let mut created = std::collections::HashSet::new();
    for h in handles {
        let (id, path) = h.join().unwrap();
        assert!(path.is_dir());
        assert!(created.insert(id), "duplicate snapshot dir allocated");
    }
    assert_eq!(created.len(), 8);
}

#[test]
fn web_exports_enforce_bounded_fifo_retention() {
    let tmp = tempfile::tempdir().unwrap();
    let web_root = bunker_web_exports_dir(tmp.path());
    for idx in 1..=5 {
        let (_id, dir) = allocate_timestamped_dir(&web_root).unwrap();
        fs::write(dir.join("RESTORE_PROMPT.md"), format!("export {idx}")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    let pruned = retention::prune_old_web_exports(&web_root, 3).unwrap();
    assert_eq!(pruned, 2);
    let remaining: Vec<_> = fs::read_dir(&web_root)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .collect();
    assert_eq!(remaining.len(), 3);
}
