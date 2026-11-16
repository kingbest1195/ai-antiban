use std::fs;
use zastava_lib::auditor::profile_switcher::{
    active_profile_binding_state_in, list_claude_profiles_in, resolve_route_id_for_key,
    switch_claude_profile_in, sync_profiles_for_route_update_in,
};
use zastava_lib::autostart::windows_run_value;
use zastava_lib::cowork_guard::{
    COWORK_ERROR_FILE_ARG, COWORK_TASK_FULL_NAME, INSTALL_COWORK_GUARD_ARG,
    build_elevated_cli_params, build_schtasks_create_args, build_windows_summary,
    build_windows_task_xml_with_system_root, cowork_guard_inline_ps, decode_windows_cmd_text,
    encode_utf16_le_with_bom, is_task_xml_healthy, parse_install_cli_args, parse_reg_start_dword,
    parse_sc_running, parse_tasklist_has_claude, validate_windows_task_xml,
};
use zastava_lib::routing::RouteSelection;
use zastava_lib::state::{AppState, AppStateData, CURRENT_SCHEMA_VERSION};
use zastava_lib::sysproxy::{build_powershell_guard_block_with_tz, force_os_dry_run};
use zastava_lib::win_reg::{
    decode_dword, decode_multi_sz, decode_utf16_le_string, encode_utf16_le_bytes, encode_utf16_nul,
};

#[test]
fn windows_artifacts_avoid_defender_and_bropass_av_heuristics() {
    let xml = build_windows_task_xml_with_system_root(r"C:\Windows");
    let inline_ps = cowork_guard_inline_ps();
    let elevated_params = build_elevated_cli_params(Some(std::path::Path::new(
        r"C:\Users\Ivan\AppData\Local\Temp\zastava-cowork-err.txt",
    )));
    let ps_profile_block =
        build_powershell_guard_block_with_tz("http://127.0.0.1:8899", Some("Europe/Amsterdam"));

    let forbidden_av_patterns = [
        "-encodedcommand",
        "-enc ",
        "-executionpolicy bypass",
        "-ep bypass",
        "start-process",
        "-verb runas",
        "wscript",
        "cscript",
        "vbscript",
        ".vbs",
        "frombase64string",
        "mshta",
        "certutil",
        "bitsadmin",
    ];

    for (label, text) in [
        ("task_xml", xml.as_str()),
        ("inline_ps", inline_ps),
        ("elevated_params", elevated_params.as_str()),
        ("ps_profile_block", ps_profile_block.as_str()),
    ] {
        let lower = text.to_ascii_lowercase();
        for pattern in forbidden_av_patterns {
            assert!(
                !lower.contains(pattern),
                "{label} must not contain AV-sensitive pattern `{pattern}`"
            );
        }
    }

    // Task XML must never launch user-writable binaries (LPE / BroPass heuristic guard)
    let xml_lower = xml.to_ascii_lowercase();
    assert!(!xml_lower.contains("%localappdata%"));
    assert!(!xml_lower.contains(r"appdata\local"));
    assert!(!xml_lower.contains("zastava.exe"));
    assert!(!xml_lower.contains("logontype"));
    assert!(xml.contains("Manual"));
    assert!(!xml.contains("Disabled"));

    // Elevated CLI params roundtrip preserves paths with spaces cleanly
    let parsed = parse_install_cli_args(&[
        INSTALL_COWORK_GUARD_ARG.to_string(),
        COWORK_ERROR_FILE_ARG.to_string(),
        r"C:\Users\Ivan Petrov\AppData\Local\Temp\err.txt".to_string(),
    ]);
    assert_eq!(
        parsed,
        Some(Some(std::path::PathBuf::from(
            r"C:\Users\Ivan Petrov\AppData\Local\Temp\err.txt"
        )))
    );

    // Win32 Registry UTF-16 helpers & Run key value preserve Cyrillic Windows paths cleanly
    let cyr_path = r"C:\Users\Иван Петров\AppData\Local\Zastava\zastava.exe";
    let nul_units = encode_utf16_nul(cyr_path);
    assert_eq!(nul_units.last(), Some(&0));
    let bytes = encode_utf16_le_bytes(cyr_path);
    assert_eq!(decode_utf16_le_string(&bytes).unwrap(), cyr_path);
    assert_eq!(decode_dword(&3u32.to_le_bytes()).unwrap(), 3);
    let mut multi = encode_utf16_le_bytes("ru-RU");
    multi.extend(encode_utf16_le_bytes("en-US"));
    multi.extend([0, 0]);
    assert_eq!(
        decode_multi_sz(&multi).unwrap(),
        vec!["ru-RU".to_string(), "en-US".to_string()]
    );
    assert_eq!(
        windows_run_value(std::path::Path::new(cyr_path)),
        format!("\"{cyr_path}\" --minimized")
    );
}

#[tokio::test]
async fn upgrade_from_v2_2_0_state_json_migrates_cleanly_without_data_loss() {
    force_os_dry_run();
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");

    // Representative v2.2.0 state.json:
    // - missing `disabled_providers`, `trusted_exceptions`, `pinned_ips`, `split_tunnel_mode`
    // - has `pinned_ip`, stale `session_allowed_providers`, persisted `blocked_providers`
    // - has `routes`, `provider_routes`, `ip_history` (with both string "AS..." and numeric ASN)
    let legacy_v220_json = r#"{
      "schema_version": 2,
      "pinned_ip": "185.10.20.30",
      "strict_pinning_enabled": true,
      "onboarding_v2_2_done": true,
      "hide_ip_mode": false,
      "ip_history": {
        "anthropic": [
          { "ip": "185.10.20.30", "country_code": "nl", "asn": "AS20473", "timestamp": 1700000000 }
        ],
        "openai": [
          { "ip": "198.51.100.7", "country_code": "DE", "asn": 24940, "timestamp": 1700000100 }
        ]
      },
      "session_allowed_providers": ["anthropic", "openai"],
      "blocked_providers": ["gemini"],
      "synced_ai_timezone": "Europe/Amsterdam",
      "sync_ai_tz_enabled": true,
      "cli_mode": "ai_only",
      "auto_update_enabled": true,
      "autostart_enabled": true,
      "cowork_guard_enabled": true,
      "interception_behavior": "ask_popup",
      "popup_position": "top_right",
      "custom_ai_domains": ["my-ai.example.com"],
      "routes": [
        {
          "id": "route-eu-1",
          "label": "Amsterdam VPS",
          "raw_key": "socks5://alice:s3cret@185.10.20.30:1080#NL",
          "enabled": true,
          "entries": [
            {
              "proto": "socks5",
              "host": "185.10.20.30",
              "port": 1080,
              "username": "alice",
              "password": "s3cret",
              "sni": null
            }
          ],
          "added_at": 1700000000
        }
      ],
      "provider_routes": {
        "anthropic": "route-eu-1"
      },
      "default_route_id": null,
      "profile_route_id": null,
      "legacy_route_id": null,
      "profile_route_invalid": null,
      "manual_killswitch": true
    }"#;

    fs::write(&state_path, legacy_v220_json).unwrap();

    let state = AppState::load_or_default(state_path.clone());
    let data = state.get_data().await;

    assert_eq!(data.schema_version, CURRENT_SCHEMA_VERSION);
    assert!(data.disabled_providers.is_empty());
    assert!(data.trusted_exceptions.is_empty());
    assert!(!data.split_tunnel_mode);

    // Ephemeral session allowances from v2.2.0 must NEVER survive an upgrade/restart
    assert!(data.session_allowed_providers.is_empty());
    // Persisted blocks, routes, pin, and flags must survive cleanly
    assert!(data.blocked_providers.contains("gemini"));
    assert_eq!(data.blocked_providers.len(), 1);
    assert_eq!(data.pinned_ip.as_deref(), Some("185.10.20.30"));
    assert_eq!(
        data.pinned_ips.get("default").map(String::as_str),
        Some("185.10.20.30")
    );
    assert!(data.strict_pinning_enabled);
    assert!(data.manual_killswitch);
    assert!(data.cowork_guard_enabled);
    assert!(data.autostart_enabled);
    assert_eq!(data.custom_ai_domains, vec!["my-ai.example.com"]);
    assert_eq!(data.routes.len(), 1);
    assert_eq!(data.routes[0].id, "route-eu-1");
    assert_eq!(
        data.provider_routes.get("anthropic").map(String::as_str),
        Some("route-eu-1")
    );
    assert!(matches!(
        state.route_selection("anthropic").await,
        RouteSelection::Route(ref r) if r.id == "route-eu-1"
    ));
    assert_eq!(
        data.ip_history.get("anthropic").unwrap()[0].asn,
        Some(20473)
    );
    assert_eq!(data.ip_history.get("openai").unwrap()[0].asn, Some(24940));

    // Re-loading the migrated file on disk must remain idempotent
    let reloaded = AppState::load_or_default(state_path);
    assert_eq!(reloaded.get_data().await, data);
}

#[tokio::test]
async fn upgrade_from_v2_2_1_state_json_handles_pinned_ips_stale_blocks_and_unknown_routes() {
    force_os_dry_run();
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");

    // Representative v2.2.1 state.json:
    // - has `pinned_ips` per provider, missing `disabled_providers` & `trusted_exceptions`
    // - has stale `session_allowed_providers` and `blocked_providers`
    // - includes one valid route and one future/unrecognized route entry
    let legacy_v221_json = r#"{
      "schema_version": 2,
      "pinned_ip": "1.1.1.1",
      "pinned_ips": {
        "default": "1.1.1.1",
        "anthropic": "5.6.7.8"
      },
      "session_allowed_providers": ["gemini"],
      "blocked_providers": ["openai"],
      "routes": [
        {
          "id": "route-valid",
          "label": "DE",
          "raw_key": "http://198.51.100.10:8080#DE",
          "enabled": true,
          "entries": [
            {
              "proto": "http",
              "host": "198.51.100.10",
              "port": 8080,
              "username": null,
              "password": null,
              "sni": null
            }
          ],
          "added_at": 1700000200
        },
        {
          "id": "route-future",
          "entries": "not-an-array-in-future-schema"
        }
      ],
      "provider_routes": {
        "openai": "route-valid"
      }
    }"#;

    fs::write(&state_path, legacy_v221_json).unwrap();

    let state = AppState::load_or_default(state_path.clone());
    let data = state.get_data().await;

    assert!(data.session_allowed_providers.is_empty());
    assert!(data.blocked_providers.contains("openai"));
    assert!(data.disabled_providers.is_empty());
    assert!(data.trusted_exceptions.is_empty());
    assert_eq!(
        data.pinned_ips.get("default").map(String::as_str),
        Some("1.1.1.1")
    );
    assert_eq!(
        data.pinned_ips.get("anthropic").map(String::as_str),
        Some("5.6.7.8")
    );
    assert_eq!(data.routes.len(), 1);
    assert_eq!(data.routes[0].id, "route-valid");
    assert_eq!(data.skipped_routes.len(), 1);

    // New v2.2.2 features work on top of migrated v2.2.1 state and persist across restart
    state.set_provider_monitoring("openai", false).await.unwrap();
    state
        .add_trusted_exception("anthropic", "5.6.7.8")
        .await
        .unwrap();

    let reloaded = AppState::load_or_default(state_path);
    assert!(reloaded.is_provider_disabled("openai").await);
    assert!(!reloaded.is_provider_blocked("openai").await);
    assert!(
        reloaded
            .is_ip_trusted_for_provider("anthropic", "5.6.7.8")
            .await
    );
    assert_eq!(reloaded.get_data().await.skipped_routes.len(), 1);

    let ui = serde_json::to_string(&reloaded.get_data().await.redacted_for_ui()).unwrap();
    assert!(!ui.contains("route-future"));
    let _: AppStateData = serde_json::from_str(&ui).unwrap();
}

#[test]
fn upgrade_from_legacy_profiles_json_without_bound_route_id_migrates_cleanly() {
    let temp = tempfile::tempdir().unwrap();
    let storage_dir = temp.path().join(".zastava").join("claude_profiles");
    let claude_dir = temp.path().join("Claude");
    fs::create_dir_all(&storage_dir).unwrap();
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(claude_dir.join("Cookies"), "work-cookie-v220").unwrap();
    fs::write(
        claude_dir.join("ant-device-registry.json"),
        r#"{"deviceId":"dev-work-111"}"#,
    )
    .unwrap();

    let work_key = "socks5://alice:pass@198.51.100.2:1080#WorkEU";
    let expected_route_id = resolve_route_id_for_key(Some(work_key)).unwrap();

    // Legacy v2.2.0 / v2.2.1 profiles.json without `bound_route_id` field
    let legacy_profiles_json = format!(
        r#"{{
          "profiles": [
            {{
              "id": "default",
              "name": "Основной аккаунт",
              "bound_ip": "198.51.100.2",
              "bound_country": "NL",
              "bound_upstream_key": "{work_key}",
              "isolated_device_id": "dev-work-111",
              "created_at": 1700000000,
              "last_used_at": 1700000500,
              "is_active": true,
              "has_saved_session": true
            }},
            {{
              "id": "profile-personal",
              "name": "Личный",
              "bound_ip": null,
              "bound_country": null,
              "isolated_device_id": "dev-pers-222",
              "created_at": 1700000100,
              "last_used_at": 1700000200,
              "is_active": false,
              "has_saved_session": false
            }}
          ]
        }}"#
    );
    fs::write(storage_dir.join("profiles.json"), legacy_profiles_json).unwrap();

    let list = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
    assert_eq!(list.profiles.len(), 2);
    assert_eq!(list.active_profile_id, "default");
    assert_eq!(
        list.profiles[0].bound_route_id.as_deref(),
        Some(expected_route_id.as_str())
    );
    assert_eq!(
        list.profiles[0].bound_upstream_key.as_deref(),
        Some(work_key)
    );
    assert_eq!(list.profiles[1].bound_route_id, None);
    assert_eq!(list.profiles[1].bound_upstream_key, None);

    let binding = active_profile_binding_state_in(&storage_dir)
        .unwrap()
        .expect("active binding state must resolve");
    assert_eq!(binding.profile_id, "default");
    assert_eq!(binding.bound_ip.as_deref(), Some("198.51.100.2"));
    assert_eq!(binding.bound_upstream_key.as_deref(), Some(work_key));
    assert_eq!(
        binding.bound_route_id.as_deref(),
        Some(expected_route_id.as_str())
    );

    // Switching away and back preserves the legacy session data and isolated device ID
    let switched = switch_claude_profile_in(&storage_dir, &claude_dir, "profile-personal").unwrap();
    assert_eq!(switched.active_profile.id, "profile-personal");
    let switched_back = switch_claude_profile_in(&storage_dir, &claude_dir, "default").unwrap();
    assert_eq!(switched_back.active_profile.id, "default");
    assert_eq!(
        fs::read_to_string(claude_dir.join("Cookies")).unwrap(),
        "work-cookie-v220"
    );

    // Updating the route key syncs even profiles loaded without persisted `bound_route_id`
    let new_key = "socks5://alice:pass@198.51.100.2:1080#WorkEU-Renamed";
    let synced = sync_profiles_for_route_update_in(
        &storage_dir,
        &claude_dir,
        &expected_route_id,
        Some(new_key),
    )
    .unwrap();
    assert_eq!(synced, Some(Some(new_key.to_string())));
}

#[test]
fn cowork_guard_handles_v2_2_0_and_v2_2_1_upgrade_repair_and_windows_encodings() {
    // 1. Overwrite/repair uses `/Create ... /F` for idempotent replacement of v2.2.0/v2.2.1 tasks
    let args = build_schtasks_create_args(r"C:\Temp\zastava-cowork-task-123.xml");
    assert_eq!(
        args,
        [
            "/Create",
            "/TN",
            COWORK_TASK_FULL_NAME,
            "/XML",
            r"C:\Temp\zastava-cowork-task-123.xml",
            "/F"
        ]
    );

    // 2. Newly generated v2.2.2 Task XML passes schema & health checks and encodes to UTF-16LE BOM
    let v222_xml = build_windows_task_xml_with_system_root(r"C:\Windows");
    assert!(validate_windows_task_xml(&v222_xml).is_ok());
    assert!(is_task_xml_healthy(&v222_xml));
    let utf16_bom = encode_utf16_le_with_bom(&v222_xml);
    assert_eq!(&utf16_bom[..2], &[0xFF, 0xFE]);
    assert_eq!(decode_windows_cmd_text(&utf16_bom), v222_xml.trim());

    // 3. v2.2.1 XML had encoding="UTF-8", which validate_windows_task_xml rejects for new installs
    let v221_utf8_xml = v222_xml.replace("encoding=\"UTF-16\"", "encoding=\"UTF-8\"");
    assert!(validate_windows_task_xml(&v221_utf8_xml).is_err());

    // 4. v2.2.0 Task Scheduler exported XML (SYSTEM + BootTrigger + System32 powershell.exe)
    //    decoded from Windows UTF-16LE BOM stdout is recognized cleanly, while legacy/LPE tasks
    //    targeting AppData\Local\Zastava\zastava.exe are flagged for repair.
    let v220_exported_xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoProfile -NonInteractive -WindowStyle Hidden -Command 'Set-Service CoworkVMService -StartupType Manual'</Arguments></Exec></Actions>
</Task>"#;
    let mut exported_utf16 = encode_utf16_le_with_bom(v220_exported_xml);
    exported_utf16.extend([0, 0]); // Simulate trailing NUL from console tool output
    let decoded = decode_windows_cmd_text(&exported_utf16);
    assert!(is_task_xml_healthy(&decoded));
    assert!(validate_windows_task_xml(&decoded).is_err());

    let legacy_localappdata_xml = v220_exported_xml.replace(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"%LOCALAPPDATA%\Zastava\zastava.exe",
    );
    assert!(!is_task_xml_healthy(&legacy_localappdata_xml));

    // 5. Status & repair detection matrix across Windows states
    let (repair_auto, _) = build_windows_summary(true, Some(2), true, true, true);
    assert!(repair_auto);
    let (repair_disabled, _) = build_windows_summary(true, Some(4), false, true, true);
    assert!(repair_disabled);
    let (repair_unhealthy_task, _) = build_windows_summary(true, Some(3), false, true, false);
    assert!(repair_unhealthy_task);
    let (repair_ok, _) = build_windows_summary(true, Some(3), false, true, true);
    assert!(!repair_ok);

    // 6. Console output parsers handle Windows CRLF / UTF-16LE output
    let sc_utf16 = encode_utf16_le_with_bom(
        "SERVICE_NAME: CoworkVMService\r\n        STATE              : 4  RUNNING\r\n",
    );
    assert!(parse_sc_running(&decode_windows_cmd_text(&sc_utf16)));
    assert_eq!(
        parse_reg_start_dword("    Start    REG_DWORD    0x3\r\n"),
        Some(3)
    );
    assert!(parse_tasklist_has_claude("\"claude.exe\",\"4242\",\"Console\",\"1\",\"90,000 K\""));
}
