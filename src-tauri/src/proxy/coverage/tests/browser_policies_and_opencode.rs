use super::super::*;
use super::*;
use crate::state::CliMode;
use crate::sysproxy::browser_policies::{
    KEY_PROXY_MODE, KEY_PROXY_PAC_URL, MACOS_CHROMIUM_DOMAIN_NAMES, PROXY_MODE_PAC_SCRIPT,
    PolicyValue, WINDOWS_CHROMIUM_DOMAIN_NAMES,
};
use crate::sysproxy::fs::Fs;
use crate::sysproxy::platform::RegValue;

fn put_browser_prefs(rig: &Rig, rel: &str, json: &str) {
    let p = rig
        .ctx
        .home
        .join("Library")
        .join("Application Support")
        .join(rel)
        .join("Preferences");
    rig.fs.put(&p, json.as_bytes(), 0o600);
}

#[test]
fn browser_pac_policy_active_ignores_plist_only_and_detects_preferences_and_flags() {
    let rig = Rig::new();
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let env = rig.env(PacSource::Services, false);

    let snap = t.snapshot(&env, true);
    assert!(!snap.browser_pac_policy_active);
    assert!(snap.browsers_pac_active.is_empty());
    assert!(snap.browsers_needing_restart.is_empty());

    // Managed plist policy alone (POLICY_LEVEL_RECOMMENDED) MUST NOT mark PAC active.
    let domain = MACOS_CHROMIUM_DOMAIN_NAMES[0];
    rig.policy_store.set_domain_applicable(domain, true);
    rig.policy_store.preset(
        domain,
        KEY_PROXY_MODE,
        PolicyValue::Sz(PROXY_MODE_PAC_SCRIPT.into()),
    );
    rig.policy_store
        .preset(domain, KEY_PROXY_PAC_URL, PolicyValue::Sz(OUR_PAC.into()));
    assert!(!t.snapshot(&env, true).browser_pac_policy_active);

    // Chrome profile Preferences JSON with our PAC -> active.
    put_browser_prefs(
        &rig,
        "Google/Chrome/Default",
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac","pac_mandatory":false}}"#,
    );

    // Without invalidation or force=true cached facts stay until invalidated.
    let cached = t.snapshot(&env, false);
    assert!(!cached.browser_pac_policy_active);

    t.invalidate_facts();
    let refreshed = t.snapshot(&env, false);
    assert!(refreshed.browser_pac_policy_active);
    assert_eq!(
        refreshed.browsers_pac_active,
        vec!["Google Chrome".to_string()]
    );

    // Windows ignores `User Data/.../Preferences` and reads HKCU policy keys + WinINet instead.
    let win_prefs = rig
        .ctx
        .local_appdata
        .join("Microsoft/Edge/User Data/Default/Preferences");
    rig.fs.put(
        &win_prefs,
        br#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac","pac_mandatory":false}}"#,
        0o600,
    );
    let (_, win_tracker) = {
        let (t_clock, clock) = clock_at(10_000_000);
        (
            t_clock,
            CoverageTracker::with_parts(clock, FakeProbe::failing(), Os::Windows),
        )
    };
    win_tracker.set_gateway_addr(gw(8899));
    let win_no_policy = win_tracker.snapshot(&rig.env(PacSource::Inet, false), true);
    assert!(!win_no_policy.browser_pac_policy_active);
    assert!(win_no_policy.browsers_pac_active.is_empty());

    // WinINet AutoConfigURL alone marks Windows PAC active.
    rig.platform
        .seed_inet("AutoConfigURL", RegValue::sz(OUR_PAC));
    let win_inet = win_tracker.snapshot(&rig.env(PacSource::Inet, false), true);
    assert!(win_inet.browser_pac_policy_active);
    assert_eq!(
        win_inet.browsers_pac_active,
        vec!["Windows Internet Settings (WinINet)".to_string()]
    );

    // HKCU\Software\Policies\Microsoft\Edge keeps browser protection active even if WinINet is overridden.
    let win_domain = WINDOWS_CHROMIUM_DOMAIN_NAMES[1];
    rig.policy_store.set_domain_applicable(win_domain, true);
    rig.policy_store.preset(
        win_domain,
        KEY_PROXY_MODE,
        PolicyValue::Sz(PROXY_MODE_PAC_SCRIPT.into()),
    );
    rig.policy_store
        .preset(win_domain, KEY_PROXY_PAC_URL, PolicyValue::Sz(OUR_PAC.into()));
    rig.platform.seed_inet("AutoConfigURL", RegValue::sz(""));
    let win_snap = win_tracker.snapshot(&rig.env(PacSource::Inet, false), true);
    assert!(win_snap.browser_pac_policy_active);
    assert_eq!(
        win_snap.browsers_pac_active,
        vec!["Microsoft Edge".to_string()]
    );
    assert_eq!(
        app(&win_snap, "browsers").status,
        CoverageStatus::Configured
    );
}

#[test]
fn browser_pac_running_flag_vs_needing_restart_is_reported_accurately() {
    let rig = Rig::new();
    rig.seed_wifi_pac(OUR_PAC, true);
    let _vpn = rig.platform.add_vpn_service("V2Box Pro", true);
    rig.platform.set_effective_pac(None, false);

    // Chrome is running without `--proxy-pac-url` and without PAC in Preferences -> needs restart.
    // Comet is running WITH `--proxy-pac-url` -> active.
    put_browser_prefs(&rig, "Google/Chrome/Default", "{}");
    put_browser_prefs(&rig, "Comet/Default", "{}");
    let ps = format!(
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n\
         /Applications/Comet.app/Contents/MacOS/Comet --proxy-pac-url={OUR_PAC}\n"
    );
    let (_, t) = tracker(FakeProbe::answering(&ps));
    t.set_gateway_addr(gw(8899));

    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert!(snap.browser_pac_policy_active);
    assert_eq!(snap.browsers_pac_active, vec!["Comet".to_string()]);
    assert_eq!(
        snap.browsers_needing_restart,
        vec!["Google Chrome".to_string()]
    );
    let browsers = app(&snap, "browsers");
    assert_eq!(browsers.status, CoverageStatus::Configured);
    assert!(browsers.detail.contains("Google Chrome"));

    // If ONLY Chrome is running without PAC and no browser has PAC active -> false + Off.
    let rig_only = Rig::new();
    rig_only.seed_wifi_pac(OUR_PAC, true);
    let _vpn2 = rig_only.platform.add_vpn_service("V2Box Pro", true);
    rig_only.platform.set_effective_pac(None, false);
    put_browser_prefs(&rig_only, "Google/Chrome/Default", "{}");
    let (_, t2) = tracker(FakeProbe::answering(
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n",
    ));
    t2.set_gateway_addr(gw(8899));
    let snap2 = t2.snapshot(&rig_only.env(PacSource::Services, false), true);
    assert!(!snap2.browser_pac_policy_active);
    assert!(snap2.browsers_pac_active.is_empty());
    assert_eq!(
        snap2.browsers_needing_restart,
        vec!["Google Chrome".to_string()]
    );
    assert_eq!(app(&snap2, "browsers").status, CoverageStatus::Off);
}

#[test]
fn browser_pac_policy_active_marks_browsers_configured_even_when_vpn_overrides_system_proxy() {
    let rig = Rig::new();
    rig.seed_wifi_pac(OUR_PAC, true);
    let _vpn = rig.platform.add_vpn_service("V2Box Pro", true);
    // Simulate a TUN VPN overriding effective `scutil --proxy` so OS proxy reads inactive.
    rig.platform.set_effective_pac(None, false);

    put_browser_prefs(
        &rig,
        "Google/Chrome/Default",
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac","pac_mandatory":false}}"#,
    );

    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);

    assert_eq!(snap.vpn_connected, vec!["V2Box Pro".to_string()]);
    assert_eq!(snap.system_proxy_effective, Some(false));
    assert!(snap.browser_pac_policy_active);
    assert_eq!(snap.browsers_pac_active, vec!["Google Chrome".to_string()]);

    let browsers = app(&snap, "browsers");
    assert_eq!(browsers.status, CoverageStatus::Configured);
    assert!(browsers.manual_steps.is_empty());
    assert!(browsers.detail.contains("VPN"));
}

#[test]
fn browser_pac_policy_active_serializes_in_json_and_defaults_to_false() {
    let rig = Rig::new();
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    put_browser_prefs(
        &rig,
        "Google/Chrome/Default",
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac","pac_mandatory":false}}"#,
    );

    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    let mut v = serde_json::to_value(&snap).unwrap();
    assert_eq!(v["browser_pac_policy_active"], true);
    assert_eq!(
        v["browsers_pac_active"],
        serde_json::json!(["Google Chrome"])
    );
    assert_eq!(v["browsers_needing_restart"], serde_json::json!([]));

    let obj = v.as_object_mut().unwrap();
    obj.remove("browser_pac_policy_active");
    obj.remove("browsers_pac_active");
    obj.remove("browsers_needing_restart");
    let old: CoverageSnapshot = serde_json::from_value(v).unwrap();
    assert!(!old.browser_pac_policy_active);
    assert!(old.browsers_pac_active.is_empty());
    assert!(old.browsers_needing_restart.is_empty());
}

#[test]
fn utun_vpn_with_temp_dns_and_deferred_os_pac_surfaces_tunnel_notice_and_configured_browsers() {
    let rig = Rig::new();
    // Simulate AmneziaVPN (utun daemon not in scutil --nc list) holding temporary DNS so OS PAC
    // on Wi-Fi stayed off, while browser Preferences PAC is active.
    rig.seed_wifi_pac("", false);
    rig.platform.set_temp_dns(true);
    rig.platform.set_effective_pac(None, false);
    rig.fs
        .create_private_dir_all(Path::new("/Applications/Claude.app"))
        .unwrap();

    put_browser_prefs(
        &rig,
        "Google/Chrome/Default",
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac","pac_mandatory":false}}"#,
    );

    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let mut env = rig.env(PacSource::Services, false);
    env.sysproxy_enabled = true;
    let snap = t.snapshot(&env, true);

    assert_eq!(
        snap.vpn_connected,
        vec!["активный туннель (временные DNS)".to_string()]
    );
    assert_eq!(snap.system_proxy_effective, Some(false));
    assert!(snap.browser_pac_policy_active);

    let browsers = app(&snap, "browsers");
    assert_eq!(browsers.status, CoverageStatus::Configured);
    assert!(browsers.detail.contains("VPN"));

    let claude = app(&snap, "claude-desktop");
    assert_eq!(claude.status, CoverageStatus::Off);
    assert!(claude.detail.contains("временные DNS"), "{}", claude.detail);
    assert!(
        !claude
            .manual_steps
            .contains(&steps::ENABLE_PROTECTION.to_string())
    );
}

#[test]
fn opencode_in_ai_only_is_off_with_bypass_suspected_even_with_service_json() {
    let rig = Rig::new();
    let cfg_dir = home().join(".config").join("opencode");
    rig.fs.create_private_dir_all(&cfg_dir).unwrap();
    rig.fs.put(
        &cfg_dir.join("service.json"),
        br#"{"env":{"HTTPS_PROXY":"http://127.0.0.1:8899","HTTP_PROXY":"http://127.0.0.1:8899"}}"#,
        0o600,
    );

    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    t.set_cli_mode(CliMode::AiOnly);
    let snap = t.snapshot(&rig.env(PacSource::Services, true), true);

    let oc = app(&snap, "opencode");
    assert!(oc.installed);
    assert_eq!(oc.status, CoverageStatus::Off);
    assert!(oc.bypass_suspected);
    assert_eq!(oc.manual_steps, vec![steps::SET_ENV_PROXY.to_string()]);
    assert!(oc.detail.contains("Весь терминал"), "{}", oc.detail);
}

#[test]
fn opencode_in_global_terminal_is_configured_and_traffic_confirms() {
    let rig = Rig::new();
    let bin = home().join(".opencode").join("bin").join("opencode");
    rig.fs.create_private_dir_all(bin.parent().unwrap()).unwrap();
    rig.fs.put(&bin, b"#!/bin/sh\n", 0o755);

    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    t.set_cli_mode(CliMode::GlobalTerminal);
    let snap = t.snapshot(&rig.env(PacSource::Services, true), true);

    let oc = app(&snap, "opencode");
    assert!(oc.installed);
    assert_eq!(oc.status, CoverageStatus::Configured);
    assert!(!oc.bypass_suspected);

    t.set_cli_mode(CliMode::AiOnly);
    t.record_hit("opencode", None);
    let snap2 = t.snapshot(&rig.env(PacSource::Services, true), true);
    let oc2 = app(&snap2, "opencode");
    assert_eq!(oc2.status, CoverageStatus::Confirmed);
    assert!(!oc2.bypass_suspected);
}
