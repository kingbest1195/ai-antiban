use super::browser_discovery::{
    DiscoveryPlatform, discover_browsers_with, resolve_browser_executable_from,
};
use super::browser_sandbox::{
    RunningSandboxProcess, SandboxMeta, SandboxProcessRegistry, accept_languages_for_country,
    build_hardened_chromium_args, build_hardened_chromium_args_for_engine, launch_hardened_sandbox,
    read_sandbox_meta, write_fail_closed_preferences, write_fail_closed_preferences_with_country,
    write_sandbox_meta,
};
use super::detector::{DetectorEnv, DetectorInput, run_clean_room_audit_with};
use super::detector_env::parse_windows_running_ai_processes;
use super::tz_guard::{evaluate_tz_guard, resolve_target_tz_for_spawn};
use super::{CleanProfileId, CleanRoomFixAction, TraceSeverity};
use crate::auditor::geo_matrix::{CheckResult, CheckStatus, ProviderId};
use crate::auditor::network::NetworkTelemetry;
use crate::auditor::{OverallStatus, RiskReport};
use crate::state::{AppStateData, CleanProfileStatus, CleanRoomProfile, IpHistoryEntry};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

struct FakeDetectorEnv {
    existing: HashSet<PathBuf>,
    running: Vec<String>,
    browsers: Vec<(&'static str, PathBuf)>,
    claude_dirs: Vec<PathBuf>,
    chatgpt_dirs: Vec<PathBuf>,
    cursor_dirs: Vec<PathBuf>,
    windows: bool,
}

impl DetectorEnv for FakeDetectorEnv {
    fn path_exists(&self, path: &Path) -> bool {
        self.existing.contains(path)
    }
    fn running_ai_processes(&self) -> Vec<String> {
        self.running.clone()
    }
    fn browser_profile_dirs(&self) -> Vec<(&'static str, PathBuf)> {
        self.browsers.clone()
    }
    fn claude_data_dirs(&self) -> Vec<PathBuf> {
        self.claude_dirs.clone()
    }
    fn chatgpt_data_dirs(&self) -> Vec<PathBuf> {
        self.chatgpt_dirs.clone()
    }
    fn cursor_data_dirs(&self) -> Vec<PathBuf> {
        self.cursor_dirs.clone()
    }
    fn is_windows(&self) -> bool {
        self.windows
    }
}

fn ok_check(code: &str) -> CheckResult {
    CheckResult {
        status: CheckStatus::Ok,
        code: code.to_string(),
        message: "ok".to_string(),
        guide_ref: None,
        reason: None,
        checked_at: None,
        measured_via: None,
        detail: None,
    }
}

fn sample_report(ip: &str, country: &str, tz: Option<&str>) -> RiskReport {
    RiskReport {
        provider: ProviderId::Anthropic,
        overall_status: OverallStatus::Green,
        trust_score: 100,
        telemetry: NetworkTelemetry {
            ip: ip.to_string(),
            country_code: country.to_string(),
            hostname: None,
            asn: Some(13335),
            org: None,
            isp: Some("Cloudflare".to_string()),
            timezone: tz.map(str::to_string),
            resolved_at: 1_700_000_000,
        },
        geo_result: ok_check("geo"),
        pinning_result: ok_check("pinning"),
        travel_result: ok_check("travel"),
        dnsbl_result: ok_check("dnsbl"),
        dnsbl_clean_count: "5/5".to_string(),
        asn_result: ok_check("asn"),
        ipv6_result: ok_check("ipv6"),
        timezone_result: ok_check("timezone"),
        ipv6_exit: false,
        checks: vec![ok_check("dns")],
        unknown_count: 0,
        applicable_count: 1,
        incomplete: false,
        gateway_latency_ms: None,
    }
}

#[test]
fn profile_id_rejects_path_traversal_and_accepts_safe_ids() {
    assert!(CleanProfileId::parse("us-claude-1").is_ok());
    assert!(CleanProfileId::parse("work_acc_2").is_ok());

    for bad in [
        "", "   ", ".", "..", "../etc", "a/b", "a\\b", "a:b", "a..b", "bad id", "a\0b",
    ] {
        assert!(CleanProfileId::parse(bad).is_err(), "must reject {bad:?}");
    }
}

#[test]
fn browser_discovery_priority_windows_and_macos() {
    let env_win = |k: &str| match k {
        "ProgramFiles(x86)" => Some("C:\\Program Files (x86)".to_string()),
        _ => None,
    };
    let reg_win = |exe: &str| match exe {
        "chrome.exe" => {
            Some("\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"".to_string())
        }
        _ => None,
    };
    let exists_win = |p: &Path| {
        let s = p.to_string_lossy().replace('\\', "/");
        s == "C:/Program Files/Google/Chrome/Application/chrome.exe"
            || s.ends_with("/Microsoft/Edge/Application/msedge.exe")
    };
    let win_list =
        discover_browsers_with(DiscoveryPlatform::Windows, &env_win, &reg_win, &exists_win);
    assert_eq!(win_list[0].engine, "chrome");
    assert!(win_list[0].available);
    assert_eq!(win_list[1].engine, "edge");
    assert!(win_list[1].available);
    assert_eq!(win_list[2].engine, "brave");
    assert!(!win_list[2].available);

    let (chosen_engine, _) = resolve_browser_executable_from(&win_list, "").unwrap();
    assert_eq!(chosen_engine, "chrome");

    let env_mac = |k: &str| (k == "HOME").then(|| "/Users/tester".to_string());
    let no_reg = |_: &str| None;
    let exists_mac = |p: &Path| {
        p == Path::new("/Users/tester/Applications/Brave Browser.app/Contents/MacOS/Brave Browser")
    };
    let mac_list = discover_browsers_with(DiscoveryPlatform::Macos, &env_mac, &no_reg, &exists_mac);
    assert!(!mac_list[0].available);
    assert!(!mac_list[1].available);
    assert!(mac_list[2].available);
    let (chosen_mac, _) = resolve_browser_executable_from(&mac_list, "").unwrap();
    assert_eq!(chosen_mac, "brave");
}

#[test]
fn hardened_args_and_fail_closed_preferences() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_id = CleanProfileId::parse("clean-1").unwrap();
    let profile_dir = tmp.path().join("clean-profiles").join(profile_id.as_str());

    let prefs_path =
        write_fail_closed_preferences_with_country(&profile_dir, 45123, Some("DE")).unwrap();
    let prefs_raw = std::fs::read_to_string(&prefs_path).unwrap();
    let prefs: serde_json::Value = serde_json::from_str(&prefs_raw).unwrap();
    assert_eq!(prefs["proxy"]["mode"], "fixed_servers");
    assert_eq!(prefs["proxy"]["server"], "http://127.0.0.1:45123");
    assert_eq!(prefs["dns_over_https"]["mode"], "off");
    assert_eq!(prefs["intl"]["accept_languages"], "de-DE,de,en");
    assert_eq!(
        prefs["webrtc"]["ip_handling_policy"],
        "disable_non_proxied_udp"
    );
    assert_eq!(prefs["webrtc"]["multiple_routes_enabled"], false);
    assert_eq!(prefs["signin"]["allowed"], false);
    assert_eq!(prefs["sync"]["requested"], false);
    assert_eq!(prefs["browser"]["has_seen_welcome_page"], true);
    assert_eq!(prefs["browser"]["edge_first_run_complete"], true);
    assert!(
        profile_dir.join("First Run").is_file(),
        "First Run sentinel must be created"
    );
    assert_eq!(accept_languages_for_country(Some("GB")), "en-GB,en");
    assert_eq!(accept_languages_for_country(None), "en-US,en");
    assert!(write_fail_closed_preferences(&profile_dir, 45123).is_ok());

    let args = build_hardened_chromium_args(&profile_dir, 45123, Some("https://claude.ai"));
    assert!(
        !args.iter().any(|a| a.starts_with("--lang=")),
        "must NOT force English UI via --lang=en-US"
    );
    assert!(
        args.iter()
            .any(|a| a == "--proxy-server=http://127.0.0.1:45123")
    );
    assert!(
        args.iter()
            .any(|a| a == "--proxy-bypass-list=127.0.0.1;[::1]")
    );
    assert!(
        args.iter()
            .any(|a| a == "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1")
    );
    assert!(args.iter().any(|a| a == "--disable-quic"));
    assert!(args.iter().any(|a| a == "--disable-features=DnsOverHttps"));
    assert!(
        args.iter()
            .any(|a| a == "--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
    );
    assert!(args.iter().any(|a| a == "https://claude.ai"));
    assert!(
        !args
            .iter()
            .any(|a| a.contains("WebRtcHideLocalIpsWithMdns")),
        "must NEVER disable WebRtcHideLocalIpsWithMdns"
    );

    let edge_args = build_hardened_chromium_args_for_engine(&profile_dir, 45123, None, "edge");
    assert!(
        edge_args
            .iter()
            .any(|a| a == "--disable-features=DnsOverHttps,msEdgeFRE")
    );
}

#[test]
fn stale_port_replaces_old_sandbox_record_without_spawning() {
    assert!(!crate::sysproxy::os_effects_enabled());
    let tmp = tempfile::tempdir().unwrap();
    let registry = SandboxProcessRegistry::new();
    let pid_id = CleanProfileId::parse("p-stale").unwrap();
    registry.record(
        "p-stale",
        RunningSandboxProcess {
            pid: 999_999,
            alias_port: 40001,
            browser_engine: "chrome".to_string(),
        },
    );

    let res = launch_hardened_sandbox(
        &registry,
        tmp.path(),
        &pid_id,
        "chrome",
        "/nonexistent/chrome",
        40002,
        Some("https://claude.ai"),
        Some("America/New_York"),
    )
    .unwrap();

    assert_eq!(res.alias_port, 40002);
    assert_eq!(res.pid, None);
    assert!(
        registry.get("p-stale").is_none(),
        "stale port entry must be evicted"
    );
}

#[test]
fn tz_guard_enforces_windows_sync_and_allows_macos_env() {
    let win_ru = evaluate_tz_guard(true, Some("Europe/Moscow"), Some("America/New_York"));
    assert!(!win_ru.os_tz_matches_exit);
    assert!(win_ru.is_ru_by_os_tz);
    assert!(win_ru.requires_os_sync);

    let win_ok = evaluate_tz_guard(true, Some("America/New_York"), Some("America/New_York"));
    assert!(win_ok.os_tz_matches_exit);
    assert!(!win_ok.requires_os_sync);

    let mac_ru_host = evaluate_tz_guard(false, Some("Europe/Moscow"), Some("America/New_York"));
    assert!(!mac_ru_host.requires_os_sync);
    assert_eq!(
        resolve_target_tz_for_spawn(true, Some("America/New_York")).as_deref(),
        Some("America/New_York")
    );
    assert_eq!(
        resolve_target_tz_for_spawn(true, Some("Europe/Moscow")),
        None
    );
}

#[test]
fn detector_blocks_on_claude_traces_tainted_ip_and_killswitch() {
    let msix_dir = PathBuf::from("/fake/Packages/Claude_123/LocalCache/Roaming/Claude");
    let mut existing = HashSet::new();
    existing.insert(msix_dir.join("ant-device-registry.json"));

    let env = FakeDetectorEnv {
        existing,
        running: vec!["Claude".to_string()],
        browsers: vec![],
        claude_dirs: vec![msix_dir],
        chatgpt_dirs: vec![],
        cursor_dirs: vec![],
        windows: false,
    };

    let mut state = AppStateData::default();
    state
        .clean_room
        .tainted_ips
        .insert("198.51.100.44".to_string(), 1_700_000_000);
    state.clean_room.profiles.push(CleanRoomProfile {
        id: "other-p".to_string(),
        label: "Other".to_string(),
        provider: "anthropic".to_string(),
        browser_engine: "chrome".to_string(),
        bound_route_id: None,
        last_exit_ip: Some("198.51.100.44".to_string()),
        last_exit_country: Some("US".to_string()),
        status: CleanProfileStatus::Tainted,
        created_at: 1_699_999_000,
        last_opened_at: Some(1_700_000_000),
        warmup_started_at: None,
        launchpad_step: 1,
        completed_checklist: vec![],
        post_payment_quarantine: None,
    });
    state.ip_history.insert(
        "anthropic".to_string(),
        vec![IpHistoryEntry::new(
            "198.51.100.44".to_string(),
            "US".to_string(),
            Some(13335),
            1_700_000_000,
        )],
    );
    state.manual_killswitch = true;

    let report = sample_report("198.51.100.44", "US", Some("America/New_York"));
    let audit = run_clean_room_audit_with(
        &env,
        &DetectorInput {
            target_provider: ProviderId::Anthropic,
            target_profile_id: Some("new-p"),
            risk_report: Some(&report),
            audit_error: None,
            state_data: &state,
            claude_profiles: &[],
            os_tz: Some("America/New_York"),
            now_secs: 1_700_000_100,
        },
    );

    assert!(!audit.ready_to_launch);
    assert!(audit.ip_is_tainted);
    assert!(audit.critical_count >= 4);
    assert!(audit.findings.iter().any(|f| matches!(
        f.fix_action,
        Some(CleanRoomFixAction::CleanAppCache { ref provider }) if provider == "anthropic"
    )));
}

#[test]
fn detector_fails_closed_when_risk_report_is_none() {
    let env = FakeDetectorEnv {
        existing: HashSet::new(),
        running: vec![],
        browsers: vec![],
        claude_dirs: vec![],
        chatgpt_dirs: vec![],
        cursor_dirs: vec![],
        windows: false,
    };
    let state = AppStateData::default();

    let with_err = run_clean_room_audit_with(
        &env,
        &DetectorInput {
            target_provider: ProviderId::Anthropic,
            target_profile_id: Some("p-err"),
            risk_report: None,
            audit_error: Some("route r-dead is disabled"),
            state_data: &state,
            claude_profiles: &[],
            os_tz: None,
            now_secs: 1_700_000_200,
        },
    );
    assert!(!with_err.ready_to_launch);
    assert_eq!(with_err.critical_count, 1);
    let f = with_err
        .findings
        .iter()
        .find(|f| f.id == "network_audit_failed")
        .expect("network_audit_failed finding");
    assert!(f.detail.contains("route r-dead is disabled"));
    assert_eq!(f.fix_action, Some(CleanRoomFixAction::SwitchRouteOrVpn));

    let without_err = run_clean_room_audit_with(
        &env,
        &DetectorInput {
            target_provider: ProviderId::Anthropic,
            target_profile_id: Some("p-none"),
            risk_report: None,
            audit_error: None,
            state_data: &state,
            claude_profiles: &[],
            os_tz: None,
            now_secs: 1_700_000_200,
        },
    );
    assert!(!without_err.ready_to_launch);
    assert_eq!(without_err.critical_count, 1);
}

#[test]
fn windows_detector_ignores_claude_code_cli_and_flags_desktop() {
    let cli_only = "\
101|claude.exe|C:\\Users\\dev\\.local\\bin\\claude.exe
102|claude.exe|C:\\Users\\dev\\AppData\\Roaming\\npm\\claude.exe
103|claude.exe|
";
    assert!(parse_windows_running_ai_processes(cli_only).is_empty());

    let mixed = "\
101|claude.exe|C:\\Users\\dev\\.local\\bin\\claude.exe
202|claude.exe|C:\\Program Files\\WindowsApps\\Claude_1.0.0_x64__pzs8sxrjxfjjc\\app\\Claude.exe
303|ChatGPT.exe|C:\\Program Files\\WindowsApps\\OpenAI.ChatGPT-Desktop\\ChatGPT.exe
404|Cursor.exe|C:\\Users\\dev\\AppData\\Local\\Programs\\cursor\\Cursor.exe
";
    assert_eq!(
        parse_windows_running_ai_processes(mixed),
        vec![
            "ChatGPT.exe".to_string(),
            "Cursor.exe".to_string(),
            "claude.exe".to_string(),
        ]
    );

    let win_entries = vec![
        crate::win_native::process::ProcessEntry {
            pid: 101,
            parent_pid: 1,
            exe_name: "claude.exe".into(),
        },
        crate::win_native::process::ProcessEntry {
            pid: 202,
            parent_pid: 1,
            exe_name: "claude.exe".into(),
        },
        crate::win_native::process::ProcessEntry {
            pid: 303,
            parent_pid: 1,
            exe_name: "ChatGPT.exe".into(),
        },
    ];
    let classified =
        super::detector_env::classify_windows_process_entries(&win_entries, |pid| match pid {
            101 => Some(r"C:\Users\dev\.local\bin\claude.exe".into()),
            202 => Some(
                r"C:\Program Files\WindowsApps\Claude_1.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe"
                    .into(),
            ),
            _ => None,
        });
    assert_eq!(
        classified,
        vec!["ChatGPT.exe".to_string(), "claude.exe".to_string()]
    );
}

#[test]
fn windows_tz_mismatch_is_warning_and_persisted_meta_recovers_stale_singleton() {
    let env = FakeDetectorEnv {
        existing: HashSet::new(),
        running: vec![],
        browsers: vec![],
        claude_dirs: vec![],
        chatgpt_dirs: vec![],
        cursor_dirs: vec![],
        windows: true,
    };
    let state = AppStateData::default();
    let report = sample_report("198.51.100.44", "US", Some("America/New_York"));
    let audit = run_clean_room_audit_with(
        &env,
        &DetectorInput {
            target_provider: ProviderId::Anthropic,
            target_profile_id: None,
            risk_report: Some(&report),
            audit_error: None,
            state_data: &state,
            claude_profiles: &[],
            os_tz: Some("Europe/Moscow"),
            now_secs: 1_700_000_100,
        },
    );
    assert!(
        audit.ready_to_launch,
        "A1: Windows TZ mismatch must not hard-block sandbox launch"
    );
    let tz_finding = audit
        .findings
        .iter()
        .find(|f| f.id == "windows_os_tz_mismatch")
        .expect("windows_os_tz_mismatch finding");
    assert_eq!(tz_finding.severity, TraceSeverity::Warning);
    assert!(!tz_finding.title.is_ascii());

    // Persisted .zastava-sandbox.json recovery cleans stale SingletonLock when port changed
    let tmp = tempfile::tempdir().unwrap();
    let pid_id = CleanProfileId::parse("p-restart").unwrap();
    let profile_dir = tmp.path().join("clean-profiles").join(pid_id.as_str());
    write_sandbox_meta(
        &profile_dir,
        SandboxMeta {
            pid: 4242,
            alias_port: 40001,
        },
    )
    .unwrap();
    std::fs::write(profile_dir.join("SingletonLock"), b"stale").unwrap();

    let registry = SandboxProcessRegistry::new();
    let res = launch_hardened_sandbox(
        &registry,
        tmp.path(),
        &pid_id,
        "chrome",
        "/nonexistent/chrome",
        40009,
        None,
        None,
    )
    .unwrap();
    assert_eq!(res.alias_port, 40009);
    assert!(!profile_dir.join("SingletonLock").exists());
    assert_eq!(
        read_sandbox_meta(&profile_dir).map(|m| m.alias_port),
        Some(40009)
    );
}

#[test]
fn parse_ps_pids_for_profile_finds_only_matching_sandbox_browser_pids() {
    use super::browser_sandbox::parse_ps_pids_for_profile;

    let profile_dir = Path::new("/tmp/zastava-test/clean-profiles/cr-gemini3");
    let ps_out = format!(
        "  101 /sbin/launchd\n\
         {} /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/tmp/zastava-test/clean-profiles/cr-gemini3\n\
         42001 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/tmp/zastava-test/clean-profiles/cr-gemini3 --proxy-server=http://127.0.0.1:41000\n\
         42002 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/Users/alice/Library/Application Support/Google/Chrome\n\
         42003 /bin/cat /tmp/zastava-test/clean-profiles/cr-gemini3/Default/Preferences\n\
         42004 /Applications/Brave Browser.app/Contents/MacOS/Brave Browser --user-data-dir=/tmp/zastava-test/clean-profiles/cr-gemini3\n",
        std::process::id()
    );
    let pids = parse_ps_pids_for_profile(&ps_out, profile_dir);
    assert_eq!(pids, vec![42001, 42004]);
}

#[test]
fn sandbox_args_suppress_chromium_self_updater_and_keychain_prompts() {
    let profile_dir = Path::new("/tmp/zastava-test/clean-profiles/cr-updater");
    let args = build_hardened_chromium_args(profile_dir, 43210, Some("https://claude.ai"));
    assert!(args.iter().any(|a| a == "--disable-component-update"));
    assert!(args.iter().any(|a| a == "--disable-background-networking"));
    assert!(
        args.iter()
            .any(|a| a.starts_with("--simulate-outdated-no-au="))
    );
    assert!(args.iter().any(|a| a == "--no-service-autorun"));
    #[cfg(target_os = "macos")]
    assert!(args.iter().any(|a| a == "--use-mock-keychain"));
    #[cfg(target_os = "linux")]
    assert!(args.iter().any(|a| a == "--password-store=basic"));
}

#[test]
fn is_sandbox_browser_cmdline_enforces_exact_user_data_dir_boundary() {
    use super::sandbox_proc::is_sandbox_browser_cmdline;
    let profile_abc = Path::new("/tmp/zastava-clean/clean-profiles/cr-abc");

    assert!(is_sandbox_browser_cmdline(
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/tmp/zastava-clean/clean-profiles/cr-abc --disable-quic",
        profile_abc
    ));
    assert!(is_sandbox_browser_cmdline(
        "\"/usr/bin/chromium\" --user-data-dir=\"/tmp/zastava-clean/clean-profiles/cr-abc\" --no-first-run",
        profile_abc
    ));
    assert!(is_sandbox_browser_cmdline(
        "chromium --user-data-dir=/tmp/zastava-clean/clean-profiles/cr-abc/",
        profile_abc
    ));

    // Prefix collision (`.../cr-abc` vs `.../cr-abcdef`) MUST NOT match!
    assert!(!is_sandbox_browser_cmdline(
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/tmp/zastava-clean/clean-profiles/cr-abcdef --disable-quic",
        profile_abc
    ));
    assert!(!is_sandbox_browser_cmdline(
        "\"/usr/bin/chromium\" --user-data-dir=\"/tmp/zastava-clean/clean-profiles/cr-abcdef\"",
        profile_abc
    ));

    // Unrelated command containing path without `--user-data-dir=` MUST NOT match.
    assert!(!is_sandbox_browser_cmdline(
        "chromium /tmp/zastava-clean/clean-profiles/cr-abc",
        profile_abc
    ));
}

#[test]
fn launch_cleans_all_singleton_artifacts_and_writes_new_port_preferences() {
    let tmp = tempfile::tempdir().unwrap();
    let pid_id = CleanProfileId::parse("cr-singleton-v300").unwrap();
    let profile_dir = super::browser_sandbox::clean_profile_dir(tmp.path(), &pid_id);
    std::fs::create_dir_all(profile_dir.join("Default")).unwrap();
    // Simulate legacy v3.0.0 profile: NO .zastava-sandbox.json, stale Singleton* + old Preferences
    std::fs::write(profile_dir.join("SingletonLock"), b"old-lock").unwrap();
    std::fs::write(profile_dir.join("SingletonSocket"), b"old-sock").unwrap();
    std::fs::write(profile_dir.join("SingletonCookie"), b"old-cookie").unwrap();
    std::fs::write(
        profile_dir.join("Default").join("Preferences"),
        br#"{"proxy":{"mode":"fixed_servers","server":"127.0.0.1:11111"}}"#,
    )
    .unwrap();

    let registry = SandboxProcessRegistry::new();
    launch_hardened_sandbox(
        &registry,
        tmp.path(),
        &pid_id,
        "chrome",
        "/nonexistent/chrome",
        44444,
        None,
        None,
    )
    .unwrap();

    assert!(!profile_dir.join("SingletonLock").exists());
    assert!(!profile_dir.join("SingletonSocket").exists());
    assert!(!profile_dir.join("SingletonCookie").exists());
    let prefs = std::fs::read_to_string(profile_dir.join("Default").join("Preferences")).unwrap();
    assert!(prefs.contains("127.0.0.1:44444"));
    assert!(!prefs.contains("11111"));
}
