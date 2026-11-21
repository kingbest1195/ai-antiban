use super::*;

#[test]
fn no_proxy_covers_loopback_bonjour_and_every_private_range() {
    assert_eq!(
        NO_PROXY_VALUE,
        "localhost,127.0.0.1,::1,.local,*.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
    );
    let items: Vec<&str> = NO_PROXY_VALUE.split(',').collect();
    for must in [
        "localhost",
        "127.0.0.1",
        "::1",
        ".local",
        "*.local",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    ] {
        assert!(items.contains(&must), "{must}");
    }
}

#[test]
fn both_generations_of_no_proxy_are_known_and_nothing_else() {
    assert!(is_known_no_proxy_value(NO_PROXY_VALUE));
    assert!(is_known_no_proxy_value(NO_PROXY_VALUE_2_0));
    assert!(is_known_no_proxy_value(
        "  localhost,127.0.0.1,::1,.local \n"
    ));
    assert_eq!(NO_PROXY_VALUE_2_0, "localhost,127.0.0.1,::1,.local");
    assert!(!is_known_no_proxy_value("localhost,corp.example"));
    assert!(!is_known_no_proxy_value(""));
}

#[test]
fn app_identifier_matches_tauri_conf() {
    let conf = include_str!("../../tauri.conf.json");
    assert!(conf.contains(&format!("\"identifier\": \"{APP_IDENTIFIER}\"")));
}

#[test]
fn recovery_entry_point_is_a_no_op_in_dry_run() {
    let before = dry_run_blocked_calls();
    let dir = std::env::temp_dir().join("zastava-never-created-by-dry-run");
    let r = recover_ownership_on_start(&dir).unwrap();
    assert!(r.skipped_dry_run && r.items.is_empty());
    assert!(
        !dir.exists(),
        "dry-run recovery must not even create the directory"
    );
    assert!(dry_run_blocked_calls() > before);
}

#[test]
fn enable_in_dry_run_changes_no_system_setting_and_reports_no_service() {
    let before = dry_run_blocked_calls();
    let st = enable_sysproxy("http://127.0.0.1:8899/proxy.pac").unwrap();
    assert!(st.enabled && st.services_configured.is_empty());
    assert!(is_sysproxy_active());
    assert!(!refresh_if_services_changed(), "nothing to heal in dry-run");
    assert!(dry_run_blocked_calls() > before);
    let _ = cleanup_all_persistent_settings();
    assert!(!is_sysproxy_active());
}

#[test]
fn journal_failure_texts_are_russian_and_carry_no_values() {
    use journal::JournalError as E;
    for e in [
        E::Locked,
        E::Corrupt,
        E::UnknownSchema(7),
        E::Io("write", std::io::ErrorKind::PermissionDenied),
        E::KindMismatch,
    ] {
        let t = journal_failure_text(&e);
        assert!(t.starts_with("Защита не включена"), "{t}");
        assert!(t.contains("Системные настройки не менялись"));
    }
}

#[test]
fn dry_run_is_always_on_in_unit_tests() {
    assert!(!os_effects_enabled());
}

#[test]
fn dry_run_silent_command_never_starts_the_requested_program() {
    let before = dry_run_blocked_calls();
    let marker = "zastava-definitely-not-a-real-program";
    // A real spawn of this name would fail with NotFound; the no-op replacement succeeds.
    let status = silent_command(marker)
        .arg("--whatever")
        .status()
        .expect("no-op spawn");
    assert!(status.success());
    assert!(dry_run_blocked_calls() > before);
    assert!(dry_run_blocked_programs().iter().any(|p| p == marker));
}

#[test]
fn dry_run_home_is_a_scratch_dir_not_the_real_home() {
    let home = user_home_dir().expect("dry-run home");
    assert!(home.is_dir());
    assert!(home.starts_with(std::env::temp_dir()));
    assert_eq!(
        user_home_dir(),
        Some(home),
        "the dry-run home is stable per process"
    );
}

#[test]
fn dry_run_cli_protection_changes_no_file_and_reports_no_target() {
    let before = dry_run_blocked_calls();
    let before_programs = dry_run_blocked_programs().len();
    let report = enable_cli_and_ide_protection("127.0.0.1:8899");
    assert!(report.enabled);
    assert!(
        report.configured_targets.is_empty(),
        "nothing is written in dry-run, so nothing is configured"
    );
    // The journal gate blocked the file layer: the scratch home stays empty.
    let home = user_home_dir().unwrap();
    assert!(!home.join(".zshrc").exists());
    assert!(!home.join(".claude").exists());
    assert!(dry_run_blocked_calls() > before);
    // No `launchctl setenv` / registry write for the GUI session, with or without a timezone sync.
    let with_tz = enable_cli_and_ide_protection_with(
        "127.0.0.1:8899",
        crate::state::CliMode::AiOnly,
        Some("Europe/Berlin"),
    );
    assert!(with_tz.enabled);
    let new_programs = dry_run_blocked_programs();
    let recent = new_programs.get(before_programs..).unwrap_or(&[]);
    assert!(
        !recent
            .iter()
            .any(|w| w.contains("launchctl") || w == "user_env:set" || w == "user_env:unset"),
        "the GUI session stays clean: {:?}",
        recent
    );
    let report = disable_cli_protection();
    assert!(report.skipped_dry_run || !report.has_failures());
    assert!(!state().cli_protection_active());
    state().set_cli_tz(None);
}

#[test]
fn test_parse_networksetup_webproxy_output() {
    let active_output =
        "Enabled: Yes\nServer: 127.0.0.1\nPort: 10808\nAuthenticated Proxy Enabled: 0\n";
    let parsed = parse_networksetup_webproxy_output(active_output);
    assert_eq!(parsed, Some(("127.0.0.1".to_string(), 10808)));

    // Test loop prevention on Zastava's gateway
    assert!(!is_gateway_target("127.0.0.1", 10808, Some(8899)));
    assert!(is_gateway_target("127.0.0.1", 8899, Some(8899)));
    assert!(is_gateway_target("localhost", 8899, None));
    assert!(is_gateway_target("127.0.0.1", 8900, None));
    assert!(is_gateway_target("127.0.0.1", 0, None));

    let disabled_output = "Enabled: No\nServer: amrika-panel.nomadnocode.com\nPort: 11443\nAuthenticated Proxy Enabled: 0\n";
    assert_eq!(parse_networksetup_webproxy_output(disabled_output), None);

    let empty_output = "";
    assert_eq!(parse_networksetup_webproxy_output(empty_output), None);
}

#[test]
fn test_parse_windows_proxy_server_and_loop_prevention() {
    // Plain format -> http://
    assert_eq!(
        parse_windows_proxy_server("127.0.0.1:10808", Some(8899)),
        Some("http://127.0.0.1:10808".to_string())
    );

    // Protocol formats
    assert_eq!(
        parse_windows_proxy_server("http=127.0.0.1:10808;https=127.0.0.1:10808", Some(8899)),
        Some("http://127.0.0.1:10808".to_string())
    );
    assert_eq!(
        parse_windows_proxy_server("http=127.0.0.1:10808;https=127.0.0.1:2080", Some(8899)),
        Some("http://127.0.0.1:2080".to_string())
    );
    assert_eq!(
        parse_windows_proxy_server("socks=127.0.0.1:10808", Some(8899)),
        Some("socks5://127.0.0.1:10808".to_string())
    );

    // Loop prevention: Zastava's active gateway port or default ports
    assert_eq!(
        parse_windows_proxy_server("127.0.0.1:8899", Some(8899)),
        None
    );
    assert_eq!(
        parse_windows_proxy_server("http=127.0.0.1:8899;https=127.0.0.1:8899", Some(8899)),
        None
    );
    assert_eq!(parse_windows_proxy_server("localhost:8900", None), None);
    assert_eq!(parse_windows_proxy_server("", Some(8899)), None);
}

#[test]
fn test_parse_reg_dword_and_sz() {
    let dword_sample = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\n    ProxyEnable    REG_DWORD    0x1\n";
    assert_eq!(parse_reg_dword(dword_sample, "ProxyEnable"), Some(1));

    let sz_sample = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\n    ProxyServer    REG_SZ    http=127.0.0.1:10808;https=127.0.0.1:10808\n";
    assert_eq!(
        parse_reg_sz(sz_sample, "ProxyServer"),
        Some("http=127.0.0.1:10808;https=127.0.0.1:10808".to_string())
    );
}

#[test]
fn test_get_set_chained_proxy_loop_guard() {
    // A context of its own: no other test can change it.
    let st = SysState::new();
    st.set_chained_proxy(Some("127.0.0.1:10808".to_string()));
    assert_eq!(st.chained_proxy(), Some("127.0.0.1:10808".to_string()));

    // Setting Zastava default port should be rejected by loop guard
    st.set_chained_proxy(Some("127.0.0.1:8899".to_string()));
    assert_eq!(st.chained_proxy(), Some("127.0.0.1:10808".to_string()));

    // The gateway port of the PAC last enabled is refused too.
    st.set_last_pac_url(Some("http://127.0.0.1:9123/proxy.pac".to_string()));
    assert_eq!(st.gateway_port(), Some(9123));
    st.set_chained_proxy(Some("127.0.0.1:9123".to_string()));
    assert_eq!(st.chained_proxy(), Some("127.0.0.1:10808".to_string()));

    st.set_chained_proxy(None);
    assert_eq!(st.chained_proxy(), None);
}

#[test]
fn sys_state_instances_are_independent_and_reset_clears_everything() {
    let a = SysState::new();
    let b = SysState::new();
    a.set_sys_proxy_active(true);
    a.set_cli_protection_active(true);
    a.set_last_pac_url(Some("http://127.0.0.1:8899/proxy.pac".into()));
    a.set_chained_proxy(Some("127.0.0.1:10808".into()));
    assert!(!b.sys_proxy_active() && !b.cli_protection_active());
    assert_eq!(b.last_pac_url(), None);
    a.reset();
    assert!(!a.sys_proxy_active() && !a.cli_protection_active());
    assert_eq!((a.last_pac_url(), a.chained_proxy()), (None, None));
}

#[test]
fn file_context_is_built_from_what_it_is_given_not_from_the_environment() {
    let fs = fs::FakeFs::new();
    let ctx = FileCtx::new(
        Arc::new(fs),
        PathBuf::from("/h"),
        vec![PathBuf::from("/h/root")],
    );
    assert_eq!(
        ctx.claude_settings(),
        PathBuf::from("/h/.claude/settings.json")
    );
    assert_eq!(
        ctx.gemini_settings(),
        PathBuf::from("/h/.gemini/settings.json")
    );
    assert!(
        ctx.powershell_profiles()
            .iter()
            .all(|p| p.starts_with("/h/Documents"))
    );
}

#[test]
fn test_parse_gateway_port_from_pac_url() {
    assert_eq!(
        parse_gateway_port_from_pac_url("http://127.0.0.1:8899/proxy.pac"),
        Some(8899)
    );
    assert_eq!(
        parse_gateway_port_from_pac_url("http://127.0.0.1:8900/pac.js"),
        Some(8900)
    );
    assert_eq!(
        parse_gateway_port_from_pac_url("127.0.0.1:8899"),
        Some(8899)
    );
}

// --- WP-26 ---------------------------------------------------------------------------------

use super::fs::{FakeFs, FsOp};
use super::journal::Journal;
use super::platform::{FakePlatform, PacState, ServiceId};
use std::path::Path;

const PAC: &str = "http://127.0.0.1:8899/proxy.pac";

fn wifi() -> ServiceId {
    ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
}

/// A service that had no PAC before Zastava: URL absent, switched off.
fn restored_pac() -> PacState {
    PacState {
        url: None,
        enabled: Some(false),
    }
}

fn fixture() -> (SysState, FakeFs, FakePlatform) {
    let p = FakePlatform::new();
    p.add_service(wifi());
    (SysState::new(), FakeFs::new(), p)
}

fn journal(fs: &FakeFs) -> Journal {
    Journal::open(Arc::new(fs.clone()), Path::new("/d")).unwrap()
}

#[test]
fn the_pac_flag_is_down_before_the_restore_starts() {
    let (st, fs, p) = fixture();
    let mut j = journal(&fs);
    enable_with(&st, &mut j, &p, PAC).unwrap();
    assert!(st.sys_proxy_active());
    let mut seen_active_during_restore = None;
    restore_pass(&st, &mut j, &p, |j, p| {
        seen_active_during_restore = Some(st.sys_proxy_active());
        cleanup::restore_with(j, p, cleanup::Scope::All)
    });
    assert_eq!(
        seen_active_during_restore,
        Some(false),
        "a refresh waiting for the lock must already see `off`"
    );
}

#[test]
fn a_refresh_that_runs_after_the_switch_off_leaves_the_pac_off() {
    let (st, fs, p) = fixture();
    let mut j = journal(&fs);
    enable_with(&st, &mut j, &p, PAC).unwrap();
    restore_pass(&st, &mut j, &p, |j, p| {
        cleanup::restore_with(j, p, cleanup::Scope::All)
    });
    let writes = p.os_writes();
    // The refresh tick that was queued behind the switch-off now gets the lock.
    let r = refresh_with(&st, &mut j, &p).unwrap();
    assert!(!r.changed && r.configured.is_empty());
    assert_eq!(p.os_writes(), writes, "nothing is written back");
    // The per-service PAC exists only on macOS; Windows keeps it in a WinINet value.
    if cfg!(target_os = "macos") {
        assert_eq!(p.pac_of(&wifi()), restored_pac());
    }
}

#[test]
fn control_a_refresh_that_still_sees_the_flag_up_does_put_the_pac_back() {
    // The race itself, forced: restore WITHOUT lowering the flag first (the old order).
    // Only where the PAC is actually written (macOS service, WinINet value).
    if !cfg!(any(target_os = "macos", target_os = "windows")) {
        return;
    }
    let (st, fs, p) = fixture();
    let mut j = journal(&fs);
    enable_with(&st, &mut j, &p, PAC).unwrap();
    cleanup::restore_with(&mut j, &p, cleanup::Scope::All);
    assert!(
        st.sys_proxy_active(),
        "old order: still up after the restore"
    );
    let writes = p.os_writes();
    let r = refresh_with(&st, &mut j, &p).unwrap();
    assert!(
        r.changed && p.os_writes() > writes,
        "the PAC is back: the bug"
    );
}

#[test]
fn refresh_without_a_remembered_pac_url_does_nothing() {
    let (st, fs, p) = fixture();
    st.set_sys_proxy_active(true);
    let mut j = journal(&fs);
    let r = refresh_with(&st, &mut j, &p).unwrap();
    assert!(!r.changed);
    assert_eq!(p.os_writes(), 0);
}

#[test]
fn enable_with_temporary_vpn_dns_defers_os_pac_applies_browser_policies_and_recovers_later() {
    if !cfg!(target_os = "macos") {
        return; // the temporary-DNS deferral is a macOS rule
    }
    use browser_policies::{FakePolicyStore, KEY_PROXY_MODE, KEY_PROXY_PAC_URL, PolicyValue};
    let (st, fs, p) = fixture();
    let happ = p.add_vpn_service("Happ Plus", true);
    p.set_temp_dns(true);
    let store = FakePolicyStore::new();
    let mut j = journal(&fs).with_policy_store(store.clone());

    // Enable succeeds cleanly: OS networksetup writes are deferred, browser policies & flag are on.
    let rep = enable_with(&st, &mut j, &p, PAC).unwrap();
    assert!(rep.os_pac_deferred);
    assert!(!rep.changed);
    assert_eq!(rep.skipped_vpn, vec!["Happ Plus".to_string()]);
    assert_eq!(
        p.os_writes(),
        0,
        "no networksetup writes while temp_dns is set"
    );
    assert!(st.sys_proxy_active());
    assert_eq!(st.last_pac_url().as_deref(), Some(PAC));
    assert_eq!(
        store.get("com.google.Chrome", KEY_PROXY_MODE),
        Some(PolicyValue::Sz("pac_script".to_string()))
    );
    assert_eq!(
        store.get("com.google.Chrome", KEY_PROXY_PAC_URL),
        Some(PolicyValue::Sz(PAC.to_string()))
    );

    // While VPN still holds temporary DNS, self-heal stays a clean no-op.
    let still_vpn = refresh_with(&st, &mut j, &p).unwrap();
    assert!(still_vpn.os_pac_deferred);
    assert!(!still_vpn.changed);
    assert_eq!(p.os_writes(), 0);

    // Once the VPN disconnects and releases temporary DNS, refresh_with applies OS PAC.
    p.set_vpn_connection(&happ.name, false);
    p.set_temp_dns(false);
    let healed = refresh_with(&st, &mut j, &p).unwrap();
    assert!(!healed.os_pac_deferred);
    assert!(healed.changed);
    assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some(PAC));
    assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
}

#[test]
fn disabling_after_temp_dns_deferred_enable_restores_browser_policies_without_deferral_error() {
    if !cfg!(target_os = "macos") {
        return;
    }
    use browser_policies::{FakePolicyStore, KEY_PROXY_PAC_URL};
    let (st, fs, p) = fixture();
    p.set_temp_dns(true);
    let store = FakePolicyStore::new();
    let mut j = journal(&fs).with_policy_store(store.clone());

    let rep = enable_with(&st, &mut j, &p, PAC).unwrap();
    assert!(rep.os_pac_deferred);

    // Disabling even while temp_dns is still true has no OS PAC entries to defer: clean restore.
    let restore_rep = restore_pass(&st, &mut j, &p, |j, p| {
        cleanup::restore_with(j, p, cleanup::Scope::All)
    });
    assert!(!restore_rep.has_failures());
    assert!(!restore_rep.restore_deferred_by_vpn_dns());
    assert_eq!(store.get("com.google.Chrome", KEY_PROXY_PAC_URL), None);
}

#[test]
fn the_restore_is_reported_as_deferred_only_while_a_vpn_holds_temporary_dns() {
    if !cfg!(target_os = "macos") {
        return; // PAC / chain journal records exist on macOS
    }
    let (st, fs, p) = fixture();
    let mut j = journal(&fs);
    enable_with(&st, &mut j, &p, PAC).unwrap();
    p.set_temp_dns(true);
    let report = cleanup::restore_with(&mut j, &p, cleanup::Scope::All);
    assert!(report.restore_deferred_by_vpn_dns());
    assert_ne!(
        p.pac_of(&wifi()),
        PacState::default(),
        "PAC stays, as designed"
    );
    p.set_temp_dns(false);
    let report = cleanup::restore_with(&mut j, &p, cleanup::Scope::All);
    assert!(!report.restore_deferred_by_vpn_dns());
    assert_eq!(p.pac_of(&wifi()), restored_pac());
}

#[test]
fn the_deferred_restore_text_is_plain_russian_and_carries_no_values() {
    let t = RESTORE_DEFERRED_TEXT;
    assert!(t.starts_with("Застава закрыта"));
    assert!(t.contains("при следующем запуске") && t.contains("VPN"));
    assert!(
        !t.contains(['"', '\\', '\n']) && !t.chars().any(|c| c.is_ascii_digit()),
        "it goes into an AppleScript string and must not hold an address"
    );
}

#[test]
fn telling_the_user_goes_through_the_dry_run_gate() {
    let before = dry_run_blocked_calls();
    notify_restore_deferred();
    if cfg!(target_os = "macos") {
        assert!(
            dry_run_blocked_calls() > before,
            "osascript was not started"
        );
        assert!(dry_run_blocked_programs().iter().any(|p| p == "osascript"));
    }
}

#[test]
fn a_running_app_makes_cleanup_stand_down_and_a_stopped_one_does_not() {
    let fs = FakeFs::new();
    let dir = Path::new("/d");
    let app = take_app_lock(&fs, dir).expect("the app takes its lock");
    assert!(
        cleanup_cli_gate(&fs, dir).unwrap().is_none(),
        "app alive -> --cleanup writes nothing"
    );
    drop(app);
    let gate = cleanup_cli_gate(&fs, dir).unwrap();
    assert!(gate.is_some(), "app gone -> --cleanup may go on");
    // While --cleanup holds the lock, a second one (or an app start) is told.
    assert!(cleanup_cli_gate(&fs, dir).unwrap().is_none());
    assert_eq!(
        take_app_lock(&fs, dir).err(),
        Some(journal::JournalError::Locked)
    );
}

#[test]
fn an_unusable_lock_file_is_an_error_not_a_green_light() {
    let fs = FakeFs::new();
    fs.fail_next(FsOp::Lock);
    assert!(matches!(
        cleanup_cli_gate(&fs, Path::new("/d")),
        Err(journal::JournalError::Io("app_lock", _))
    ));
    fs.fail_next(FsOp::CreateDir);
    assert!(matches!(
        cleanup_cli_gate(&fs, Path::new("/d")),
        Err(journal::JournalError::Io("create_dir", _))
    ));
}

#[test]
fn the_app_lock_is_not_the_journal_lock() {
    let fs = FakeFs::new();
    let dir = Path::new("/d");
    let _app = take_app_lock(&fs, dir).unwrap();
    // The app lock does not stop journal operations of the same or another process.
    assert!(Journal::open(Arc::new(fs.clone()), dir).is_ok());
    assert_ne!(
        journal::app_lock_path(dir),
        dir.join("ownership").join("journal.lock")
    );
}

#[test]
fn windows_keeps_the_journal_in_the_local_profile_and_falls_back_to_app_data() {
    let roaming = Path::new("/roaming/io.zastava.desktop");
    assert_eq!(
        local_journal_base(Some(PathBuf::from("/local")), roaming),
        PathBuf::from("/local").join(APP_IDENTIFIER)
    );
    assert_eq!(local_journal_base(None, roaming), roaming);
    assert_eq!(local_journal_base(Some(PathBuf::new()), roaming), roaming);
    #[cfg(not(target_os = "windows"))]
    assert_eq!(journal_base_dir(roaming), roaming);
}

#[test]
fn enable_with_applies_browser_pac_policies_and_restore_cleans_them() {
    use browser_policies::{FakePolicyStore, KEY_PROXY_MODE, KEY_PROXY_PAC_URL, PolicyValue};
    let (st, fs, p) = fixture();
    let store = FakePolicyStore::new();
    let mut j = journal(&fs).with_policy_store(store.clone());

    enable_with(&st, &mut j, &p, PAC).unwrap();
    if cfg!(target_os = "macos") {
        assert_eq!(
            store.get("com.google.Chrome", KEY_PROXY_MODE),
            Some(PolicyValue::Sz("pac_script".to_string()))
        );
        assert_eq!(
            store.get("com.google.Chrome", KEY_PROXY_PAC_URL),
            Some(PolicyValue::Sz(PAC.to_string()))
        );
        assert_eq!(
            store.get("company.thebrowser.Browser", KEY_PROXY_PAC_URL),
            Some(PolicyValue::Sz(PAC.to_string()))
        );
    } else if cfg!(target_os = "windows") {
        assert_eq!(
            store.get(r"Software\Policies\Google\Chrome", KEY_PROXY_PAC_URL),
            Some(PolicyValue::Sz(PAC.to_string()))
        );
    }

    let rep = restore_pass(&st, &mut j, &p, |j, p| {
        cleanup::restore_with(j, p, cleanup::Scope::All)
    });
    assert!(!rep.has_failures());
    assert_eq!(store.get("com.google.Chrome", KEY_PROXY_MODE), None);
    assert_eq!(store.get("com.google.Chrome", KEY_PROXY_PAC_URL), None);
    assert_eq!(
        store.get(r"Software\Policies\Google\Chrome", KEY_PROXY_PAC_URL),
        None
    );
}

#[test]
fn enable_with_error_leaves_sys_proxy_inactive_and_journal_empty() {
    use super::platform::PlatOp;
    if !cfg!(any(target_os = "macos", target_os = "windows")) {
        return;
    }
    let (st, fs, p) = fixture();
    let mut j = journal(&fs);

    #[cfg(target_os = "macos")]
    {
        let usb_svc = ServiceId::new("en5", "USB 10/100 LAN", "USB LAN");
        p.add_service(usb_svc.clone());
        p.seed_pac(
            &usb_svc,
            PacState {
                url: Some(PAC.to_string()),
                enabled: Some(true),
            },
        );
        p.seed_pac(&wifi(), restored_pac());
        p.fail_next_auth(PlatOp::SetPac);
        let err = enable_with(&st, &mut j, &p, PAC).unwrap_err();
        assert!(
            err.starts_with("ADMIN_AUTH_REQUIRED:"),
            "expected ADMIN_AUTH_REQUIRED: prefix, got {err}"
        );
    }

    #[cfg(target_os = "windows")]
    {
        p.fail_next(PlatOp::SetInet);
        assert!(enable_with(&st, &mut j, &p, PAC).is_err());
    }

    assert!(
        !st.sys_proxy_active(),
        "sys_proxy_active must remain false when enable_with fails"
    );
    assert!(
        j.is_empty(),
        "journal entries must be rolled back on enable_with failure: {:?}",
        j.entries()
    );
}
