//! End-to-end integration tests for Zastava v3.0.0:
//! - Free Local Bunker full backup (Claude Code + Claude Desktop MSIX + Cursor IDE)
//! - Secret & OAuth/API key sanitization + `state.vscdb` exclusion + Unix 0o600/0o700 perms
//! - 7-snapshot FIFO retention
//! - Web export conversion (`conversations.json` + `export.zip` + zip-bomb/traversal guard)
//! - `RESTORE_PROMPT.md` generation (Claude Code + Cursor + MCP)
//! - Persona Risk Index evaluation (auto technical signals + self-check toggles + score clamping)
//! - 4-State Tray (`TrayColor::Gray` transitions)

use std::fs;
use std::io::Write;
use std::path::Path;

use zip::write::SimpleFileOptions;

use zastava_lib::auditor::geo_matrix::{CheckResult, ProviderId};
use zastava_lib::auditor::ip_type::IpType;
use zastava_lib::auditor::network::NetworkTelemetry;
use zastava_lib::auditor::persona_risk::{
    PersonaRiskInput, PersonaRiskLevel, PersonaSelfCheckPatch, evaluate_persona_risk,
};
use zastava_lib::auditor::{OverallStatus, RiskReport};
use zastava_lib::bunker::retention::{list_snapshots, prune_old_snapshots, write_snapshot_meta};
use zastava_lib::bunker::web_helper::convert_web_export_to;
use zastava_lib::bunker::{
    bunker_snapshots_dir, generate_bunker_restore_prompt_in, get_bunker_status_in,
    run_bunker_backup_in,
};
use zastava_lib::state::{AppStateData, BunkerSettings};
use zastava_lib::sysproxy;
use zastava_lib::tray::inspect_tray_state_transition;

fn build_rich_home(home: &Path) {
    let claude_dir = home.join(".claude");
    let proj_dir = claude_dir.join("projects").join("-Users-dev-zastava");
    fs::create_dir_all(proj_dir.join("memory")).unwrap();
    fs::write(proj_dir.join("memory/MEMORY.md"), "# Zastava\nLayered Rust").unwrap();
    fs::write(
        proj_dir.join("latest.jsonl"),
        r#"{"type":"last-prompt","lastPrompt":"Verify Bunker E2E and Persona Risk Index"}"#,
    )
    .unwrap();
    fs::create_dir_all(claude_dir.join("plans")).unwrap();
    fs::write(claude_dir.join("plans/v3.md"), "# v3.0.0 Plan").unwrap();
    fs::write(claude_dir.join("CLAUDE.md"), "# Rules").unwrap();
    fs::write(claude_dir.join("history.jsonl"), "{}\n").unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{"model":"claude-sonnet","env":{"ANTHROPIC_API_KEY":"sk-ant-real-secret-1234567890"}}"#,
    )
    .unwrap();
    // Must never be copied:
    fs::write(
        claude_dir.join(".credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"oauth-secret-xyz"}}"#,
    )
    .unwrap();
    fs::write(
        home.join(".claude.json"),
        r#"{"theme":"dark","oauthAccount":{"emailAddress":"dev@example.com"},"primaryApiKey":"sk-ant-key-999"}"#,
    )
    .unwrap();

    // Cursor IDE
    #[cfg(target_os = "macos")]
    let cursor_user = home.join("Library/Application Support/Cursor/User");
    #[cfg(target_os = "windows")]
    let cursor_user = home.join("AppData/Roaming/Cursor/User");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let cursor_user = home.join(".config/Cursor/User");

    fs::create_dir_all(cursor_user.join("snippets")).unwrap();
    fs::write(
        cursor_user.join("settings.json"),
        r#"{"editor.tabSize":4,"refreshToken":"cursor-refresh-secret"}"#,
    )
    .unwrap();
    fs::write(cursor_user.join("keybindings.json"), "[]").unwrap();
    fs::write(cursor_user.join("snippets/ts.json"), "{}").unwrap();
    fs::write(cursor_user.join("state.vscdb"), "SENSITIVE_SQLITE_DB").unwrap();
    fs::write(
        cursor_user.join("state.vscdb.backup"),
        "SENSITIVE_SQLITE_BAK",
    )
    .unwrap();

    fs::create_dir_all(home.join(".cursor")).unwrap();
    fs::write(
        home.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"ghp_secret_123"}}}}"#,
    )
    .unwrap();
    fs::write(
        home.join(".cursorrules"),
        "Follow Clean Hexagonal architecture.",
    )
    .unwrap();
}

#[test]
fn e2e_bunker_backup_sanitization_and_7_snapshot_fifo_rotation() {
    assert!(!sysproxy::os_effects_enabled());

    let tmp = tempfile::tempdir().unwrap();
    let app_data = tmp.path().join("app_data");
    let home = tmp.path().join("home");
    let dest = tmp.path().join("user_export");
    build_rich_home(&home);

    let settings = BunkerSettings::default();
    assert_eq!(settings.retention_count, 7);

    let status_before = get_bunker_status_in(&app_data, &home, &settings);
    assert!(status_before.has_any_local_data);
    assert!(
        status_before
            .sources
            .iter()
            .any(|s| s.kind == "claude_code" && s.available)
    );
    assert!(
        status_before
            .sources
            .iter()
            .any(|s| s.kind == "cursor" && s.available)
    );

    // Run 9 backups with monotonic created_at -> verify FIFO keeps 7 newest
    for i in 0..9u64 {
        let copy_dest = if i == 8 { Some(dest.as_path()) } else { None };
        let res = run_bunker_backup_in(&app_data, &home, &settings, "manual", copy_dest).unwrap();
        let snap_dir = Path::new(&res.snapshot.snapshot_dir);
        let mut meta = res.snapshot.clone();
        meta.created_at = 1_750_000_000 + i;
        write_snapshot_meta(snap_dir, &meta).unwrap();
        let _ = prune_old_snapshots(
            &bunker_snapshots_dir(&app_data),
            settings.retention_count,
            settings.max_total_mb.saturating_mul(1024 * 1024),
        );

        if i == 8 {
            assert!(res.exported_copy_dir.is_some());
            assert!(!snap_dir.join(".credentials.json").exists());
            assert!(!snap_dir.join("cursor/User/state.vscdb").exists());
            assert!(!snap_dir.join("cursor/User/state.vscdb.backup").exists());

            let cli_cfg =
                fs::read_to_string(snap_dir.join("configs/claude_cli_config.json")).unwrap();
            assert!(!cli_cfg.contains("sk-ant-key-999"));
            assert!(!cli_cfg.contains("dev@example.com"));
            assert!(cli_cfg.contains("[REDACTED]"));

            let mcp = fs::read_to_string(snap_dir.join("cursor/mcp.json")).unwrap();
            assert!(!mcp.contains("ghp_secret_123"));
            assert!(mcp.contains("github"));

            let prompt = fs::read_to_string(&res.restore_prompt_path).unwrap();
            assert!(prompt.contains("Verify Bunker E2E and Persona Risk Index"));
            assert!(prompt.contains("github"));
            assert!(prompt.contains("Cursor IDE"));

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(snap_dir).unwrap().permissions().mode() & 0o777,
                    0o700
                );
                assert_eq!(
                    fs::metadata(&res.restore_prompt_path)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }

    let snapshots = list_snapshots(&bunker_snapshots_dir(&app_data));
    assert_eq!(snapshots.len(), 7);
    assert_eq!(snapshots[0].created_at, 1_750_000_008);
    assert_eq!(snapshots[6].created_at, 1_750_000_002);

    let live_prompt = generate_bunker_restore_prompt_in(&app_data, &home);
    assert!(live_prompt.contains("Verify Bunker E2E and Persona Risk Index"));
    assert!(live_prompt.contains("github"));
}

#[test]
fn e2e_web_export_zip_and_json_conversion_with_security_guards() {
    let tmp = tempfile::tempdir().unwrap();

    // Claude export.zip
    let claude_zip = tmp.path().join("claude_export.zip");
    {
        let f = fs::File::create(&claude_zip).unwrap();
        let mut w = zip::ZipWriter::new(f);
        w.start_file("nested/conversations.json", SimpleFileOptions::default())
            .unwrap();
        let payload = r#"[
          {
            "name": "Payment Setup",
            "created_at": "2026-11-10T10:00:00Z",
            "chat_messages": [
              {"sender": "human", "text": "Which US state has 0% sales tax?"},
              {"sender": "assistant", "text": "Delaware, Oregon, New Hampshire, Montana, Alaska."}
            ]
          }
        ]"#;
        w.write_all(payload.as_bytes()).unwrap();
        w.finish().unwrap();
    }
    let out_dir = tmp.path().join("converted_claude");
    let res = convert_web_export_to(&claude_zip, &out_dir).unwrap();
    assert_eq!(res.detected_provider, "claude");
    assert_eq!(res.conversations_count, 1);
    assert!(Path::new(&res.restore_prompt_path).is_file());
    let md = fs::read_to_string(&res.markdown_files[0]).unwrap();
    assert!(md.contains("Delaware, Oregon"));

    // ChatGPT conversations.json
    let chatgpt_json = tmp.path().join("conversations.json");
    fs::write(
        &chatgpt_json,
        r#"[
          {
            "title": "Clean Room Guide",
            "create_time": 1730000000.0,
            "current_node": "m2",
            "mapping": {
              "m1": {"id": "m1", "parent": null, "message": {"author": {"role": "user"}, "content": {"parts": ["Use isolated profile"]}}},
              "m2": {"id": "m2", "parent": "m1", "message": {"author": {"role": "assistant"}, "content": {"parts": ["Always isolate cookies and timezone."]}}}
            }
          }
        ]"#,
    )
    .unwrap();
    let res_gpt = convert_web_export_to(&chatgpt_json, &tmp.path().join("converted_gpt")).unwrap();
    assert_eq!(res_gpt.detected_provider, "chatgpt");
    assert_eq!(res_gpt.conversations_count, 1);

    // Path traversal rejection
    let bad_zip = tmp.path().join("bad.zip");
    {
        let f = fs::File::create(&bad_zip).unwrap();
        let mut w = zip::ZipWriter::new(f);
        w.start_file("../../etc/passwd", SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"x").unwrap();
        w.finish().unwrap();
    }
    assert!(convert_web_export_to(&bad_zip, &tmp.path().join("out_bad")).is_err());
}

#[test]
fn e2e_persona_risk_index_and_tray_gray_state_transitions() {
    let mut state = AppStateData::default();
    let ok = CheckResult::ok("OK", "ok");
    let mut report = RiskReport {
        provider: ProviderId::Anthropic,
        overall_status: OverallStatus::Green,
        trust_score: 100,
        telemetry: NetworkTelemetry {
            ip: "198.51.100.77".to_string(),
            country_code: "US".to_string(),
            hostname: None,
            isp: Some("Hetzner".to_string()),
            org: None,
            asn: Some(24940),
            timezone: Some("America/New_York".to_string()),
            resolved_at: 1_700_000_000,
        },
        geo_result: ok.clone(),
        pinning_result: CheckResult::ok("STRICT_PINNING_DISABLED", "off"),
        travel_result: CheckResult::ok("TRAVEL_NORMAL", "ok"),
        dnsbl_result: ok.clone(),
        dnsbl_clean_count: "0/5".to_string(),
        asn_result: CheckResult::ok("IP_TYPE_HOSTING", "hosting").with_ip_type(IpType::Hosting),
        ipv6_result: CheckResult::ok("IPV6_ENCAPSULATED", "ok"),
        timezone_result: CheckResult::ok("TIMEZONE_MATCH", "ok"),
        ipv6_exit: false,
        checks: vec![ok],
        unknown_count: 0,
        applicable_count: 14,
        incomplete: false,
        gateway_latency_ms: None,
    };

    // Unpinned Hosting (+15) + sysproxy off (+15) = 30 (medium)
    let r1 = evaluate_persona_risk(&PersonaRiskInput {
        state_data: &state,
        risk_report: Some(&report),
        sysproxy_active: false,
        os_tz: Some("America/New_York"),
        has_personal_browser_traces: false,
        has_desktop_traces: false,
        now_secs: 1_700_000_100,
    });
    assert_eq!(r1.score, 30);
    assert_eq!(r1.level, PersonaRiskLevel::Medium);

    // Self-check patch (+45) + RU TZ (+20) + sysproxy on -> 15 + 20 + 45 = 80 (high)
    let patch = PersonaSelfCheckPatch {
        bought_or_grey_account: Some(true),
        ..Default::default()
    };
    patch.apply_to(&mut state.persona_self_check);
    report.timezone_result = CheckResult::warning("TIMEZONE_LEAK_RU", "ru tz", None);
    let r2 = evaluate_persona_risk(&PersonaRiskInput {
        state_data: &state,
        risk_report: Some(&report),
        sysproxy_active: true,
        os_tz: Some("Europe/Moscow"),
        has_personal_browser_traces: false,
        has_desktop_traces: false,
        now_secs: 1_700_000_100,
    });
    assert_eq!(r2.score, 80);
    assert_eq!(r2.level, PersonaRiskLevel::High);

    // 4-State Tray transitions:
    // 1. Protection off (!sysproxy_active, !has_blocked) -> Gray (with non-empty tray-gray.png bytes)
    let (color_off, title_off, bytes_off) =
        inspect_tray_state_transition(false, false, OverallStatus::Green);
    assert_eq!(color_off, "gray");
    assert_eq!(title_off, " Защита выключена");
    assert!(!bytes_off.is_empty());

    // 2. Kill-switch / blocked overrides Gray -> Red
    let (color_blk, _, _) = inspect_tray_state_transition(true, false, OverallStatus::Green);
    assert_eq!(color_blk, "red");

    // 3. Protection on + Green -> Green
    let (color_on, _, _) = inspect_tray_state_transition(false, true, OverallStatus::Green);
    assert_eq!(color_on, "green");
}

#[test]
fn e2e_bunker_web_exports_bounded_fifo_and_atomic_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let app_data = tmp.path().join("app_data");
    let src_json = tmp.path().join("conversations.json");
    fs::write(
        &src_json,
        r#"[{"uuid":"c1","name":"FIFO Test","created_at":"2026-11-10T10:00:00Z","chat_messages":[{"sender":"human","text":"hi"},{"sender":"assistant","text":"hello"}]}]"#,
    )
    .unwrap();

    for _ in 0..5 {
        let res =
            zastava_lib::commands::bunker::convert_web_export_in(&app_data, &src_json, None, 3)
                .unwrap();
        assert!(Path::new(&res.restore_prompt_path).is_file());
    }

    let web_root = zastava_lib::bunker::bunker_web_exports_dir(&app_data);
    let remaining: Vec<_> = fs::read_dir(&web_root)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .collect();
    assert_eq!(
        remaining.len(),
        3,
        "web-exports must be bounded to retention_count=3"
    );

    // Failed conversion must not leave an empty allocated directory in web-exports/
    let missing_src = tmp.path().join("does_not_exist.json");
    assert!(
        zastava_lib::commands::bunker::convert_web_export_in(&app_data, &missing_src, None, 3)
            .is_err()
    );
    let after_err: Vec<_> = fs::read_dir(&web_root)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .collect();
    assert_eq!(after_err.len(), 3);
}
