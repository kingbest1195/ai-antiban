//! E2E tests for Spec v3.2.0 §8.3 items 5-6 (Block 4 Context Teleport & Block 5 Unified Clean Room,
//! state.json v3 compatibility, session_ip_stability_for_studio, and 403 Antigravity auth cache reset).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use zastava_lib::auditor::cache_cleaner::clean_antigravity_auth_cache_in_home;
use zastava_lib::auditor::geo_matrix::{
    CheckStatus, ProviderId, evaluate_studio_session_ip_stability, is_ai_studio_host,
};
use zastava_lib::auditor::history::evaluate_impossible_travel_with_pin_exit_and_studio;
use zastava_lib::auditor::rules::ProviderMatrix;
use zastava_lib::bunker::teleport::run_context_teleport_in;
use zastava_lib::clean_room::browser_sandbox::build_hardened_chromium_args;
use zastava_lib::clean_room::detector::{DetectorEnv, DetectorInput, run_clean_room_audit_with};
use zastava_lib::clean_room::{CreateCleanProfileInput, TraceSeverity};
use zastava_lib::commands::clean_room::create_clean_profile_in;
use zastava_lib::core::context_teleport::{CHATGPT_BLOCK_CHAR_LIMIT, TeleportTarget};
use zastava_lib::state::{
    AppState, AppStateData, CURRENT_SCHEMA_VERSION, IpHistoryEntry, KNOWN_PROVIDERS,
};

struct MockIdeAndBrowserEnv {
    existing: HashSet<PathBuf>,
    browsers: Vec<(&'static str, PathBuf)>,
    cursor_dirs: Vec<PathBuf>,
    windsurf_dirs: Vec<PathBuf>,
}

impl DetectorEnv for MockIdeAndBrowserEnv {
    fn path_exists(&self, path: &Path) -> bool {
        self.existing.contains(path)
    }
    fn running_ai_processes(&self) -> Vec<String> {
        Vec::new()
    }
    fn browser_profile_dirs(&self) -> Vec<(&'static str, PathBuf)> {
        self.browsers.clone()
    }
    fn claude_data_dirs(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    fn chatgpt_data_dirs(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    fn cursor_data_dirs(&self) -> Vec<PathBuf> {
        self.cursor_dirs.clone()
    }
    fn windsurf_data_dirs(&self) -> Vec<PathBuf> {
        self.windsurf_dirs.clone()
    }
    fn read_text_limited(&self, path: &Path) -> Option<String> {
        fs::read_to_string(path).ok()
    }
    fn is_windows(&self) -> bool {
        false
    }
}

#[test]
fn e2e_teleport_zero_secret_all_targets_and_copy_only() {
    let tmp = tempfile::tempdir().unwrap();
    let app_data = tmp.path().join("app_data");
    let home = tmp.path().join("home");
    let claude_dir = home.join(".claude");
    let proj_dir = claude_dir.join("projects").join("-Users-alice-demo");
    fs::create_dir_all(proj_dir.join("memory")).unwrap();
    fs::create_dir_all(claude_dir.join("plans")).unwrap();

    fs::write(
        claude_dir.join("CLAUDE.md"),
        "Rule: keep clean. Never leak sk-ant-api03-SECRET123 or AIzaSySecretGoogleKey1234567890.",
    )
    .unwrap();
    fs::write(
        proj_dir.join("memory").join("MEMORY.md"),
        "Token ghp_1234567890abcdef1234 and xoxb-1234567890-abcdef and Bearer secretBearer999.",
    )
    .unwrap();
    fs::write(
        proj_dir.join("session.jsonl"),
        r#"{"type":"last-prompt","lastPrompt":"Deploy with oauth_token=myOauthSecret42"}"#,
    )
    .unwrap();
    fs::write(
        claude_dir.join("plans").join("migration.md"),
        "password=\"superSecretPass123\"",
    )
    .unwrap();
    // Forbidden credential files that MUST NEVER be read or leaked
    fs::write(
        claude_dir.join(".credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"FORBIDDEN_CREDENTIALS_TOKEN"}}"#,
    )
    .unwrap();
    fs::create_dir_all(home.join(".cursor")).unwrap();
    fs::write(
        home.join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"filesystem":{"command":"npx","env":{"API_KEY":"FORBIDDEN_MCP_ENV"}}}}"#,
    )
    .unwrap();
    fs::write(home.join(".cursorrules"), "Always write tests.").unwrap();

    // copy_only == Some(true) writes NOTHING to disk
    let mem_only = run_context_teleport_in(
        &app_data,
        &home,
        TeleportTarget::Universal,
        None,
        Some(true),
    )
    .expect("copy_only works");
    assert!(mem_only.files_written.is_empty());
    assert!(mem_only.output_dir.is_empty());
    assert!(!app_data.join("bunker").join("teleports").exists());
    assert!(!mem_only.primary_paste_text.contains("SECRET123"));
    assert!(
        !mem_only
            .primary_paste_text
            .contains("FORBIDDEN_CREDENTIALS_TOKEN")
    );

    for target in [
        TeleportTarget::GeminiAntigravity,
        TeleportTarget::Cursor,
        TeleportTarget::Chatgpt,
        TeleportTarget::Universal,
    ] {
        let res = run_context_teleport_in(&app_data, &home, target, None, Some(false))
            .expect("teleport succeeds");
        assert!(res.secrets_redacted_count >= 6);
        assert!(!res.files_written.is_empty());
        assert!(Path::new(&res.output_dir).is_dir());

        for secret in [
            "SECRET123",
            "AIzaSySecretGoogleKey",
            "ghp_1234567890abcdef1234",
            "xoxb-1234567890-abcdef",
            "secretBearer999",
            "myOauthSecret42",
            "superSecretPass123",
            "FORBIDDEN_CREDENTIALS_TOKEN",
            "FORBIDDEN_MCP_ENV",
        ] {
            assert!(
                !res.primary_paste_text.contains(secret),
                "leaked {secret} in primary_paste_text for {target:?}"
            );
            for f in &res.files_written {
                let body = fs::read_to_string(f).unwrap();
                assert!(
                    !body.contains(secret),
                    "leaked {secret} in file {f} for {target:?}"
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(f).unwrap().permissions().mode() & 0o777;
                    assert_eq!(mode, 0o600, "file {f} must be 0o600");
                }
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(&res.output_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
        }

        match target {
            TeleportTarget::GeminiAntigravity => {
                assert!(res.files_written.iter().any(|p| p.ends_with("GEMINI.md")));
                assert!(
                    res.files_written
                        .iter()
                        .any(|p| p.ends_with("SYSTEM_INSTRUCTIONS_GEMINI.txt"))
                );
            }
            TeleportTarget::Cursor => {
                let mdc_path = res
                    .files_written
                    .iter()
                    .find(|p| p.ends_with(".cursor/rules/migrated-context.mdc"))
                    .expect("cursor mdc");
                let mdc = fs::read_to_string(mdc_path).unwrap();
                assert!(mdc.contains("alwaysApply: true"));
                assert!(mdc.contains("filesystem"));
            }
            TeleportTarget::Chatgpt => {
                let instr_path = res
                    .files_written
                    .iter()
                    .find(|p| p.ends_with("CHATGPT_CUSTOM_INSTRUCTIONS.txt"))
                    .expect("chatgpt instructions");
                assert!(
                    res.files_written
                        .iter()
                        .any(|p| p.ends_with("MEMORY_SEED.md"))
                );
                let instr = fs::read_to_string(instr_path).unwrap();
                let blocks: Vec<&str> = instr.split("\n\n=== Block ").collect();
                assert_eq!(blocks.len(), 2);
                for b in blocks {
                    assert!(b.chars().count() <= CHATGPT_BLOCK_CHAR_LIMIT);
                }
            }
            TeleportTarget::Universal => {
                assert!(
                    res.files_written
                        .iter()
                        .any(|p| p.ends_with("RESTORE_PROMPT.md"))
                );
            }
        }
    }
}

#[tokio::test]
async fn e2e_unified_clean_room_gemini_quota_profiles_and_v3_state_compat() {
    let tmp = tempfile::tempdir().unwrap();
    let v3_1_1_state_json = serde_json::json!({
        "schema_version": 3,
        "pinned_ip": "185.212.102.40",
        "strict_pinning_enabled": true,
        "routes": [{
            "id": "route-nl-1",
            "label": "NL Key",
            "country": "NL",
            "exit_ip": "185.212.102.40",
            "entries": [{
                "proto": "http",
                "host": "185.212.102.40",
                "port": 8443
            }],
            "raw_key": "http://185.212.102.40:8443",
            "enabled": true,
            "added_at": 1760000000u64
        }],
        "pinned_ips": { "anthropic": "185.212.102.40" },
        "ip_history": {
            "gemini": [{ "ip": "185.212.102.40", "country_code": "NL", "asn": 20473, "timestamp": 1760000000u64 }]
        }
    });
    let state_path = tmp.path().join("state.json");
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&v3_1_1_state_json).unwrap(),
    )
    .unwrap();

    // Compatibility check: state.json v3 loads cleanly and preserves KNOWN_PROVIDERS
    let parsed: AppStateData = serde_json::from_str(&fs::read_to_string(&state_path).unwrap())
        .expect("v3.1.1 state loads");
    assert_eq!(parsed.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(KNOWN_PROVIDERS, ["anthropic", "openai", "gemini"]);
    assert_eq!(parsed.routes.len(), 1);
    assert_eq!(
        parsed.pinned_ips.get("anthropic").map(String::as_str),
        Some("185.212.102.40")
    );
    assert_eq!(parsed.ip_history.get("gemini").map(Vec::len), Some(1));

    let state = AppState::load_or_default(state_path);
    assert_eq!(state.get_data().await.routes.len(), 1);
    let p1 = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "Gemini — Основной".into(),
            provider: "gemini".into(),
            browser_engine: "chrome".into(),
            bound_route_id: None,
        },
        &state,
    )
    .await
    .unwrap();
    let p2 = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "Gemini — Резерв".into(),
            provider: "gemini".into(),
            browser_engine: "chrome".into(),
            bound_route_id: None,
        },
        &state,
    )
    .await
    .unwrap();

    let dir1 = tmp.path().join("sandboxes").join(&p1.id);
    let dir2 = tmp.path().join("sandboxes").join(&p2.id);
    assert_ne!(dir1, dir2);

    let args1 = build_hardened_chromium_args(&dir1, 41001, Some("https://aistudio.google.com"));
    let args2 = build_hardened_chromium_args(&dir2, 41002, Some("https://aistudio.google.com"));
    assert!(
        args1.contains(&"--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string())
    );
    assert!(
        args2.contains(&"--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string())
    );
    assert!(
        args1.contains(&"--proxy-server=http://127.0.0.1:41001".to_string())
            && args1.contains(&format!("--user-data-dir={}", dir1.display()))
    );
    assert!(
        args2.contains(&"--proxy-server=http://127.0.0.1:41002".to_string())
            && args2.contains(&format!("--user-data-dir={}", dir2.display()))
    );
}

#[test]
fn e2e_detector_gemini_warning_readonly_ide_machine_id_and_studio_stability() {
    let tmp = tempfile::tempdir().unwrap();
    let chrome_dir = tmp.path().join("Chrome");
    let windsurf_dir = tmp.path().join("Windsurf");
    let gs_dir = windsurf_dir.join("User").join("globalStorage");
    fs::create_dir_all(&chrome_dir).unwrap();
    fs::create_dir_all(&gs_dir).unwrap();
    let storage_file = gs_dir.join("storage.json");
    let original_storage = r#"{"telemetry.machineId":"abc-123","devDeviceId":"dev-456"}"#;
    fs::write(&storage_file, original_storage).unwrap();

    let mut existing = HashSet::new();
    existing.insert(chrome_dir.clone());
    existing.insert(storage_file.clone());

    let env = MockIdeAndBrowserEnv {
        existing,
        browsers: vec![("Chrome", chrome_dir)],
        cursor_dirs: Vec::new(),
        windsurf_dirs: vec![windsurf_dir],
    };
    let state = AppStateData::default();
    let report = run_clean_room_audit_with(
        &env,
        &DetectorInput {
            target_provider: ProviderId::Gemini,
            target_profile_id: None,
            risk_report: None,
            audit_error: None,
            state_data: &state,
            claude_profiles: &[],
            os_tz: Some("Europe/Berlin"),
            now_secs: 1_760_000_000,
        },
    );

    let browser_finding = report
        .findings
        .iter()
        .find(|f| f.id == "personal_browsers_present")
        .expect("personal_browsers_present");
    assert!(browser_finding.detail.contains("OR-CCSEH-21"));
    assert!(browser_finding.detail.contains("PREF"));

    let ide_finding = report
        .findings
        .iter()
        .find(|f| f.id == "ide_machine_id_note")
        .expect("ide_machine_id_note");
    assert_eq!(ide_finding.severity, TraceSeverity::Warning);
    assert!(ide_finding.fix_action.is_none());
    // Strictly read-only: storage.json MUST NOT be modified!
    assert_eq!(fs::read_to_string(&storage_file).unwrap(), original_storage);

    // session_ip_stability_for_studio in provider_matrix.json + history + geo_matrix
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let gemini_rules = matrix.get_provider_rules("gemini").unwrap();
    assert!(gemini_rules.session_ip_stability_for_studio);
    assert!(is_ai_studio_host("aistudio.google.com"));
    assert!(is_ai_studio_host("generativelanguage.googleapis.com"));
    assert!(is_ai_studio_host("aiplatform.googleapis.com"));

    let stab = evaluate_studio_session_ip_stability(
        &matrix,
        ProviderId::Gemini,
        Some("aistudio.google.com"),
        Some("185.10.10.1"),
        "185.10.10.2",
        Some(20473),
        Some(24940),
    );
    assert_eq!(stab.status, CheckStatus::Warning);
    assert_eq!(stab.code, "AI_STUDIO_IP_UNSTABLE");

    let now = 1_760_000_000;
    let hist = vec![IpHistoryEntry::new(
        "185.10.10.1",
        "NL",
        Some(20473),
        now - 300,
    )];
    let travel_warn = evaluate_impossible_travel_with_pin_exit_and_studio(
        &hist,
        "NL",
        Some("185.10.10.2"),
        Some(20473),
        now,
        ProviderId::Gemini,
        false,
        true,
    );
    assert_eq!(travel_warn.status, CheckStatus::Warning);
    assert_eq!(travel_warn.code, "AI_STUDIO_IP_UNSTABLE");
}

#[test]
fn e2e_clean_antigravity_auth_cache_preserves_gemini_md_and_mcp() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let gem = home.join(".gemini");
    let anti = home.join(".antigravity");
    fs::create_dir_all(gem.join("rules")).unwrap();
    fs::create_dir_all(anti.join("auth_cache")).unwrap();

    // Auth cache files to remove
    fs::write(gem.join("oauth_creds.json"), r#"{"token":"x"}"#).unwrap();
    fs::write(gem.join("google_accounts.json"), r#"{"active":"a@b"}"#).unwrap();
    fs::write(anti.join("oauth_creds.json"), r#"{"token":"y"}"#).unwrap();
    fs::write(anti.join("auth_cache").join("sess.bin"), "cache").unwrap();

    // Preserved user artifacts (MUST NOT be touched!)
    fs::write(gem.join("GEMINI.md"), "# Keep my rules").unwrap();
    fs::write(gem.join("settings.json"), r#"{"theme":"dark"}"#).unwrap();
    fs::write(gem.join("rules").join("rust.md"), "Keep rules").unwrap();
    fs::write(anti.join("mcp.json"), r#"{"mcpServers":{"fs":{}}}"#).unwrap();

    let res = clean_antigravity_auth_cache_in_home(home);
    assert!(res.success);
    assert!(res.found_dir);
    assert_eq!(res.files_removed, 4);

    assert!(!gem.join("oauth_creds.json").exists());
    assert!(!gem.join("google_accounts.json").exists());
    assert!(!anti.join("oauth_creds.json").exists());
    assert!(!anti.join("auth_cache").exists());

    assert!(gem.join("GEMINI.md").is_file());
    assert!(gem.join("settings.json").is_file());
    assert!(gem.join("rules").join("rust.md").is_file());
    assert!(anti.join("mcp.json").is_file());
}
