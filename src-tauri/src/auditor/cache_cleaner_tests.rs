use super::*;
use crate::auditor::claude_exporter::get_claude_desktop_config_path;
use crate::auditor::profile_switcher::resolve_ai_app_data_dirs_for_platform;

#[test]
fn test_app_cache_cleaner_execution_respects_dry_run() {
    crate::sysproxy::force_os_dry_run();
    assert!(!crate::sysproxy::os_effects_enabled());
    assert_eq!(soft_close_ai_client(ProviderId::Anthropic), 0);
    assert_eq!(soft_close_ai_client(ProviderId::Openai), 0);
    assert_eq!(soft_close_ai_client(ProviderId::Gemini), 0);
}

#[test]
fn test_absent_dir_sets_found_dir_false() {
    let temp = tempfile::tempdir().expect("tempdir");
    let absent = temp.path().join("does-not-exist");
    let result = clean_ai_app_cache_in_dir(ProviderId::Anthropic, &absent);
    assert!(result.success);
    assert!(!result.found_dir);
    assert_eq!(result.files_removed, 0);
    assert_eq!(result.bytes_freed, 0);
    assert!(result.locked_targets.is_empty());
}

#[test]
fn test_deep_cache_cleaning_and_whitelist_protection() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let app_dir = temp_dir.path();

    let cookies = app_dir.join("Cookies");
    std::fs::write(&cookies, "cookie_data").unwrap();

    let net_dir = app_dir.join("Network");
    std::fs::create_dir_all(&net_dir).unwrap();
    let net_cookies = net_dir.join("Cookies");
    std::fs::write(&net_cookies, "net_cookie_data").unwrap();

    let ant_device = app_dir.join("ant-device-registry.json");
    std::fs::write(&ant_device, "{}").unwrap();

    let local_state = app_dir.join("Local State");
    std::fs::write(&local_state, "{}").unwrap();

    // Whitelisted files: MUST NEVER BE REMOVED!
    let mcp_config = app_dir.join("claude_desktop_config.json");
    std::fs::write(&mcp_config, r#"{"mcpServers":{}}"#).unwrap();

    let dot_claude_dir = app_dir.join(".claude");
    std::fs::create_dir_all(&dot_claude_dir).unwrap();
    let claude_settings = dot_claude_dir.join("settings.json");
    std::fs::write(&claude_settings, r#"{"permissions":{}}"#).unwrap();

    let result = clean_ai_app_cache_in_dir(ProviderId::Anthropic, app_dir);
    assert!(result.success);
    assert!(result.found_dir);
    assert!(result.locked_targets.is_empty());
    assert_eq!(result.files_removed, 4);
    assert!(!cookies.exists());
    assert!(!net_cookies.exists());
    assert!(!ant_device.exists());
    assert!(!local_state.exists());

    assert!(mcp_config.exists());
    assert_eq!(
        std::fs::read_to_string(&mcp_config).unwrap(),
        r#"{"mcpServers":{}}"#
    );
    assert!(claude_settings.exists());
    assert_eq!(
        std::fs::read_to_string(&claude_settings).unwrap(),
        r#"{"permissions":{}}"#
    );
}

#[test]
fn test_msix_claude_and_chatgpt_directories_resolved_and_cleaned() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let roaming = home.join("AppData").join("Roaming");
    let local = home.join("AppData").join("Local");

    // Mock Windows MSIX Claude Store directory + Classic Claude directory
    let claude_msix = local
        .join("Packages")
        .join("Claude_test123")
        .join("LocalCache")
        .join("Roaming")
        .join("Claude");
    std::fs::create_dir_all(claude_msix.join("Local Storage")).unwrap();
    std::fs::write(claude_msix.join("Cookies"), "msix_cookie").unwrap();
    std::fs::write(
        claude_msix.join("Local Storage").join("000003.log"),
        "msix_ls",
    )
    .unwrap();
    std::fs::write(
        claude_msix.join("claude_desktop_config.json"),
        r#"{"mcpServers":{"demo":{}}}"#,
    )
    .unwrap();

    let claude_classic = roaming.join("Claude");
    std::fs::create_dir_all(&claude_classic).unwrap();
    std::fs::write(claude_classic.join("Cookies"), "classic_cookie").unwrap();

    // Mock Windows MSIX ChatGPT Store directory
    let gpt_msix = local
        .join("Packages")
        .join("OpenAI.ChatGPT-Desktop_test456")
        .join("LocalCache")
        .join("Roaming")
        .join("ChatGPT");
    std::fs::create_dir_all(gpt_msix.join("Cache")).unwrap();
    std::fs::write(gpt_msix.join("Cookies"), "gpt_cookie").unwrap();
    std::fs::write(gpt_msix.join("Cache").join("data_0"), "gpt_cache").unwrap();

    let claude_dirs = resolve_ai_app_data_dirs_for_platform(
        ProviderId::Anthropic,
        "windows",
        Some(home),
        Some(&roaming),
        Some(&local),
    );
    assert_eq!(
        claude_dirs,
        vec![claude_classic.clone(), claude_msix.clone()]
    );

    let gpt_dirs = resolve_ai_app_data_dirs_for_platform(
        ProviderId::Openai,
        "windows",
        Some(home),
        Some(&roaming),
        Some(&local),
    );
    assert_eq!(gpt_dirs, vec![gpt_msix.clone()]);
    assert!(
        resolve_ai_app_data_dirs_for_platform(
            ProviderId::Gemini,
            "windows",
            Some(home),
            Some(&roaming),
            Some(&local),
        )
        .is_empty()
    );

    // Exporter config discovery finds MSIX claude_desktop_config.json
    let cfg_path = get_claude_desktop_config_path(home);
    if cfg!(target_os = "windows") {
        assert_eq!(
            cfg_path,
            Some(claude_msix.join("claude_desktop_config.json"))
        );
    }

    // Clean both Classic + MSIX Claude dirs, preserving claude_desktop_config.json
    let claude_res = clean_ai_app_cache_in_dirs(ProviderId::Anthropic, &claude_dirs);
    assert!(claude_res.success);
    assert!(claude_res.found_dir);
    assert_eq!(claude_res.files_removed, 3);
    assert!(!claude_msix.join("Cookies").exists());
    assert!(!claude_classic.join("Cookies").exists());
    assert!(claude_msix.join("claude_desktop_config.json").exists());

    // Clean ChatGPT MSIX dir
    let gpt_res = clean_ai_app_cache_in_dirs(ProviderId::Openai, &gpt_dirs);
    assert!(gpt_res.success);
    assert!(gpt_res.found_dir);
    assert_eq!(gpt_res.files_removed, 2);
    assert!(!gpt_msix.join("Cookies").exists());
    assert!(!gpt_msix.join("Cache").exists());
}

#[test]
fn test_locked_file_not_counted_and_recorded_in_locked_targets() {
    let temp = tempfile::tempdir().expect("tempdir");
    let app_dir = temp.path();

    let ls_dir = app_dir.join("Local Storage");
    std::fs::create_dir_all(&ls_dir).unwrap();
    let unlocked = ls_dir.join("unlocked.ldb");
    let locked_in_dir = ls_dir.join("LOCK");
    std::fs::write(&unlocked, "12345").unwrap();
    std::fs::write(&locked_in_dir, "locked_bytes").unwrap();

    let locked_top = app_dir.join("Cookies");
    std::fs::write(&locked_top, "locked_cookie").unwrap();

    let unlocked_top = app_dir.join("Local State");
    std::fs::write(&unlocked_top, "{}").unwrap();

    let remover = |p: &Path| -> std::io::Result<()> {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "LOCK" || name == "Cookies" {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "file in use",
            ))
        } else {
            std::fs::remove_file(p)
        }
    };

    let result =
        clean_ai_app_cache_in_dirs_with(ProviderId::Anthropic, &[app_dir.to_path_buf()], &remover);

    assert!(!result.success);
    assert!(result.found_dir);
    // Only the 2 actually deleted files (unlocked.ldb + Local State) may be counted
    assert_eq!(result.files_removed, 2);
    assert_eq!(result.bytes_freed, 5 + 2);
    assert_eq!(
        result.locked_targets,
        vec!["Cookies".to_string(), "Local Storage/LOCK".to_string()]
    );
    assert!(locked_in_dir.exists());
    assert!(locked_top.exists());
    assert!(!unlocked.exists());
    assert!(!unlocked_top.exists());
}

#[test]
fn test_windows_process_filter_rejects_claude_code_cli() {
    // Desktop paths MUST match
    assert!(is_windows_claude_desktop_exe(
        r"C:\Program Files\WindowsApps\Claude_0.9.3.0_x64__pzs8sxrjxfjjc\app\Claude.exe"
    ));
    assert!(is_windows_claude_desktop_exe(
        r"C:\Users\alice\AppData\Local\AnthropicClaude\app-0.9.0\claude.exe"
    ));
    assert!(is_windows_claude_desktop_exe(
        r"C:\Users\alice\AppData\Local\Programs\Claude\Claude.exe"
    ));

    // Native Claude Code CLI & unqualified names MUST be rejected
    assert!(!is_windows_claude_desktop_exe(
        r"C:\Users\alice\.local\bin\claude.exe"
    ));
    assert!(!is_windows_claude_desktop_exe(
        r"C:\Users\alice\.claude\local\claude.exe"
    ));
    assert!(!is_windows_claude_desktop_exe(
        r"C:\Users\alice\AppData\Roaming\npm\claude.exe"
    ));
    assert!(!is_windows_claude_desktop_exe(
        r"C:\Users\alice\AppData\Local\Programs\claude-code\claude.exe"
    ));
    assert!(!is_windows_claude_desktop_exe(
        r"C:\Users\alice\scoop\shims\claude.exe"
    ));
    assert!(!is_windows_claude_desktop_exe("claude.exe"));
    assert!(!is_windows_claude_desktop_exe(""));

    let mixed_ps_output = "\
101|C:\\Users\\alice\\.local\\bin\\claude.exe\n\
202|C:\\Program Files\\WindowsApps\\Claude_0.9.3.0_x64__pzs8sxrjxfjjc\\app\\Claude.exe\n\
303|C:\\Users\\alice\\AppData\\Roaming\\npm\\claude.exe\n\
404|C:\\Users\\alice\\AppData\\Local\\AnthropicClaude\\app-0.9.1\\claude.exe\n";
    assert_eq!(
        filter_windows_claude_desktop_pids(mixed_ps_output),
        vec![202, 404]
    );

    // macOS predicate also distinguishes Desktop bundle from terminal CLI
    assert!(is_macos_claude_desktop_cmd(
        "/Applications/Claude.app/Contents/MacOS/Claude"
    ));
    assert!(!is_macos_claude_desktop_cmd(
        "/Users/alice/.local/bin/claude"
    ));
    assert!(!is_macos_claude_desktop_cmd("claude --resume"));
}
