use super::super::*;
use super::*;
use crate::sysproxy::fs::Fs;
use crate::sysproxy::platform::{PacState, PlatOp};
use std::sync::atomic::Ordering;

fn snapshot_with_vpn(rig: &Rig) -> CoverageSnapshot {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    t.snapshot(&rig.env(PacSource::Services, false), true)
}

#[test]
fn the_system_proxy_is_effective_when_scutil_shows_our_pac() {
    let rig = Rig::new();
    rig.seed_wifi_pac(OUR_PAC, true);
    rig.platform.set_effective_pac(Some(OUR_PAC), true);
    let snap = snapshot_with_vpn(&rig);
    assert_eq!(snap.system_proxy_effective, Some(true));
    assert!(snap.vpn_connected.is_empty());
}

#[test]
fn a_vpn_that_takes_over_makes_the_pac_on_wifi_ineffective_and_is_named() {
    let rig = Rig::new();
    rig.seed_wifi_pac(OUR_PAC, true);
    let vpn = rig.platform.add_vpn_service("Delta Pro", true);
    rig.platform.add_vpn_service("Alpha VPN", false);
    // The global dictionary follows the VPN, whose service has no PAC of ours.
    rig.platform.set_effective_pac(None, false);
    let snap = snapshot_with_vpn(&rig);
    assert_eq!(snap.system_proxy_effective, Some(false));
    assert_eq!(snap.vpn_connected, vec!["Delta Pro".to_string()]);
    // Wi-Fi still carries our PAC, so the apps are "configured": the honest part is the notice.
    assert_eq!(app(&snap, "browsers").status, CoverageStatus::Configured);
    assert_eq!(rig.platform.pac_of(&vpn), PacState::default());
    assert_eq!(rig.platform.os_writes(), 0, "coverage only reads");
    // Another PAC or a disabled flag is "not ours" too.
    rig.platform
        .set_effective_pac(Some("http://vpn.example/p.pac"), true);
    assert_eq!(snapshot_with_vpn(&rig).system_proxy_effective, Some(false));
    rig.platform.set_effective_pac(Some(OUR_PAC), false);
    assert_eq!(snapshot_with_vpn(&rig).system_proxy_effective, Some(false));
}

#[test]
fn an_unreadable_effective_proxy_is_unknown_not_a_verdict() {
    let rig = Rig::new();
    rig.seed_wifi_pac(OUR_PAC, true);
    // The fake has no `scutil --proxy` answer until it is given one.
    assert_eq!(snapshot_with_vpn(&rig).system_proxy_effective, None);
    rig.platform.set_effective_pac(Some(OUR_PAC), true);
    rig.platform.fail_next(PlatOp::EffectiveProxy);
    assert_eq!(snapshot_with_vpn(&rig).system_proxy_effective, None);
}

#[test]
fn with_the_protection_off_there_is_nothing_to_call_ineffective() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    rig.seed_wifi_pac("http://other/p.pac", true);
    rig.platform.set_effective_pac(None, false);
    let mut env = rig.env(PacSource::Services, false);
    env.sysproxy_enabled = false;
    assert_eq!(t.snapshot(&env, true).system_proxy_effective, None);
}

#[test]
fn windows_has_no_service_list_and_no_scutil() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    rig.platform.add_vpn_service("Alpha VPN", true);
    rig.platform.set_effective_pac(None, false);
    let snap = t.snapshot(&rig.env(PacSource::Inet, false), true);
    assert_eq!(snap.system_proxy_effective, None);
    assert!(snap.vpn_connected.is_empty());
}

#[test]
fn a_pac_in_a_vpn_service_is_not_a_verdict_for_the_apps() {
    let rig = Rig::new();
    // Only a VPN service carries our PAC (a leftover of 2.0.0); Wi-Fi has somebody else's.
    rig.seed_wifi_pac("http://other/p.pac", true);
    let vpn = rig.platform.add_vpn_service("Alpha VPN", false);
    rig.platform.seed_pac(
        &vpn,
        PacState {
            url: Some(OUR_PAC.to_string()),
            enabled: Some(true),
        },
    );
    let snap = snapshot_with_vpn(&rig);
    assert_eq!(app(&snap, "browsers").status, CoverageStatus::Off);
}

#[test]
fn the_snapshot_json_carries_the_new_fields() {
    let rig = Rig::new();
    rig.seed_wifi_pac(OUR_PAC, true);
    rig.platform.add_vpn_service("Delta Pro", true);
    rig.platform.set_effective_pac(None, false);
    let json = serde_json::to_value(snapshot_with_vpn(&rig)).unwrap();
    assert_eq!(json["system_proxy_effective"], serde_json::json!(false));
    assert_eq!(json["vpn_connected"], serde_json::json!(["Delta Pro"]));
}

// ----- WP-29: Antigravity 2.x ------------------------------------------------------------------

const PS_ANTIGRAVITY: &str = "/sbin/launchd\n/Applications/Antigravity.app/Contents/MacOS/Antigravity\n/Applications/Antigravity.app/Contents/Resources/bin/language_server_macos_arm\n";
const PS_OTHER: &str = "/sbin/launchd\n/Applications/Safari.app/Contents/MacOS/Safari\n";

fn desktop_app(rig: &Rig) {
    rig.fs
        .create_private_dir_all(Path::new("/Applications/Antigravity.app"))
        .unwrap();
}

fn desktop_data_folder(rig: &Rig) {
    rig.fs
        .create_private_dir_all(&editor_root().join("Antigravity"))
        .unwrap();
}

fn antigravity_snapshot(rig: &Rig, probe: Arc<FakeProbe>) -> CoverageSnapshot {
    let (_, t) = tracker(probe);
    t.set_gateway_addr(gw(8899));
    t.snapshot(&rig.env(PacSource::Services, false), true)
}

#[test]
fn antigravity_kind_is_told_by_the_user_folder_and_the_bundle() {
    let rig = Rig::new();
    assert_eq!(antigravity_kind(&rig.ctx), None);
    assert!(!check_app_installed_in("antigravity", &rig.ctx));

    // Data folder of the Electron app without `User/`: version 2.x.
    desktop_data_folder(&rig);
    assert_eq!(antigravity_kind(&rig.ctx), Some(AntigravityKind::Desktop));
    assert!(check_app_installed_in("antigravity", &rig.ctx));

    // `User/` makes it the editor again, even with the bundle next to it.
    desktop_app(&rig);
    make_editor(&rig.fs, "Antigravity", None);
    assert_eq!(antigravity_kind(&rig.ctx), Some(AntigravityKind::Editor));

    let bundle_only = Rig::new();
    desktop_app(&bundle_only);
    assert_eq!(
        antigravity_kind(&bundle_only.ctx),
        Some(AntigravityKind::Desktop)
    );

    let cli_only = Rig::new();
    cli_only
        .fs
        .create_private_dir_all(&home().join(".gemini").join("antigravity-cli"))
        .unwrap();
    assert_eq!(
        antigravity_kind(&cli_only.ctx),
        Some(AntigravityKind::CliOnly)
    );
    assert!(check_app_installed_in("antigravity", &cli_only.ctx));
}

#[test]
fn the_editor_antigravity_keeps_the_settings_model() {
    let rig = Rig::new();
    make_editor(&rig.fs, "Antigravity", Some("{}"));
    let snap = antigravity_snapshot(&rig, FakeProbe::failing());
    let a = app(&snap, "antigravity");
    assert_eq!(a.status, CoverageStatus::Off);
    assert!(a.detail.contains("settings.json"), "{}", a.detail);
    assert!(a.manual_steps.contains(&steps::SET_HTTP_PROXY.to_string()));
    assert!(!a.bypass_suspected);
}

#[test]
fn desktop_antigravity_is_not_judged_by_a_settings_file() {
    let rig = Rig::new();
    desktop_data_folder(&rig);
    rig.seed_wifi_pac("http://203.0.113.9/other.pac", true);
    let snap = antigravity_snapshot(&rig, FakeProbe::answering(PS_OTHER));
    let a = app(&snap, "antigravity");
    assert!(a.installed);
    assert_eq!(a.status, CoverageStatus::Off);
    assert!(!a.detail.contains("settings.json"), "{}", a.detail);
    assert!(
        a.detail.contains("мимо") || a.detail.contains("напрямую"),
        "{}",
        a.detail
    );
    assert_eq!(
        a.manual_steps,
        vec![
            steps::ENABLE_SYSTEM_PROXY.to_string(),
            steps::LAUNCH_WITH_ENV.to_string()
        ]
    );
    assert!(
        !a.manual_steps
            .contains(&steps::ENABLE_PROTECTION.to_string()),
        "no automatic button for this app"
    );
    assert!(!a.bypass_suspected, "not running: no alarm");
}

#[test]
fn desktop_antigravity_with_an_effective_pac_is_off_and_asks_for_the_env() {
    let rig = Rig::new();
    desktop_app(&rig);
    rig.seed_wifi_pac(OUR_PAC, true);
    rig.platform.set_effective_pac(Some(OUR_PAC), true);
    let snap = antigravity_snapshot(&rig, FakeProbe::answering(PS_OTHER));
    let a = app(&snap, "antigravity");
    assert_eq!(a.status, CoverageStatus::Off);
    assert_eq!(a.manual_steps, vec![steps::LAUNCH_WITH_ENV.to_string()]);
    assert!(a.detail.contains("агент"), "{}", a.detail);

    // A VPN that overrides the PAC: it is still off and asks for system proxy + env.
    rig.platform.set_effective_pac(None, false);
    let snap = antigravity_snapshot(&rig, FakeProbe::answering(PS_OTHER));
    assert_eq!(app(&snap, "antigravity").status, CoverageStatus::Off);
}

#[test]
fn running_antigravity_without_traffic_is_reported_as_going_around_the_gateway() {
    let rig = Rig::new();
    desktop_app(&rig);
    let probe = FakeProbe::answering(PS_ANTIGRAVITY);
    let snap = antigravity_snapshot(&rig, Arc::clone(&probe));
    let a = app(&snap, "antigravity");
    assert!(a.bypass_suspected);
    assert_eq!(a.detail, ANTIGRAVITY_BYPASS_DETAIL);
    assert_eq!(a.status, CoverageStatus::Off, "never green without traffic");
    assert_eq!(probe.count(), 1);
    assert!(probe.calls.lock().unwrap()[0].starts_with("ps -axo comm="));
}

#[test]
fn a_running_antigravity_is_off_even_when_the_pac_is_ours() {
    let rig = Rig::new();
    desktop_app(&rig);
    rig.seed_wifi_pac(OUR_PAC, true);
    rig.platform.set_effective_pac(Some(OUR_PAC), true);
    let snap = antigravity_snapshot(&rig, FakeProbe::answering(PS_ANTIGRAVITY));
    let a = app(&snap, "antigravity");
    assert!(a.bypass_suspected);
    assert_eq!(a.status, CoverageStatus::Off);
    assert_eq!(a.manual_steps, vec![steps::LAUNCH_WITH_ENV.to_string()]);
}

#[test]
fn a_failed_process_listing_is_no_alarm_and_the_listing_is_throttled() {
    let rig = Rig::new();
    desktop_app(&rig);
    let snap = antigravity_snapshot(&rig, FakeProbe::failing());
    assert!(!app(&snap, "antigravity").bypass_suspected);

    let probe = FakeProbe::answering(PS_ANTIGRAVITY);
    let (clock, t) = tracker(Arc::clone(&probe));
    t.set_gateway_addr(gw(8899));
    let env = rig.env(PacSource::Services, false);
    for _ in 0..5 {
        t.snapshot(&env, true);
    }
    assert_eq!(probe.count(), 1, "one listing per window, not per poll");
    clock.fetch_add(PROCESS_CHECK_TTL_MS + 1, Ordering::SeqCst);
    t.snapshot(&env, true);
    assert_eq!(probe.count(), 2);
}

#[test]
fn the_editor_antigravity_and_other_apps_never_cost_a_process_listing() {
    let rig = Rig::new();
    make_editor(&rig.fs, "Antigravity", Some("{}"));
    let probe = FakeProbe::answering(PS_ANTIGRAVITY);
    let snap = antigravity_snapshot(&rig, Arc::clone(&probe));
    assert!(!app(&snap, "antigravity").bypass_suspected);
    assert_eq!(probe.count(), 0);
}

#[test]
fn desktop_antigravity_is_confirmed_by_traffic_of_its_ui_or_its_agent() {
    let rig = Rig::new();
    desktop_app(&rig);
    let env = rig.env(PacSource::Services, false);

    let (_, t) = tracker(FakeProbe::answering(PS_ANTIGRAVITY));
    t.set_gateway_addr(gw(8899));
    t.record_hit("Antigravity Helper", None);
    let snap = t.snapshot(&env, true);
    let a = app(&snap, "antigravity");
    assert_eq!(a.status, CoverageStatus::Confirmed);
    assert!(!a.bypass_suspected);

    // The agent runs as a separate binary: its traffic belongs to Antigravity, not to a stray row.
    let (_, t) = tracker(FakeProbe::answering(PS_ANTIGRAVITY));
    t.set_gateway_addr(gw(8899));
    t.record_hit("language_server_macos_arm", None);
    t.record_hit("language_server_macos_arm", None);
    let snap = t.snapshot(&env, true);
    let a = app(&snap, "antigravity");
    assert_eq!(a.status, CoverageStatus::Confirmed);
    assert_eq!(a.ai_requests, 2);
    assert!(a.last_seen_ms.is_some());
    assert!(
        snap.apps
            .iter()
            .all(|x| !x.id.starts_with("language-server")),
        "no duplicate row"
    );
}

#[test]
fn the_language_server_is_not_claimed_when_windsurf_shares_the_binary() {
    let rig = Rig::new();
    desktop_app(&rig);
    make_editor(&rig.fs, "Windsurf", Some("{}"));
    let (_, t) = tracker(FakeProbe::answering(PS_OTHER));
    t.set_gateway_addr(gw(8899));
    t.record_hit("language_server_macos_arm", None);
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_ne!(app(&snap, "antigravity").status, CoverageStatus::Confirmed);
    assert!(
        snap.apps
            .iter()
            .any(|x| x.id == "language-server-macos-arm")
    );
}

#[test]
fn the_new_item_field_is_in_the_json() {
    let rig = Rig::new();
    desktop_app(&rig);
    let snap = antigravity_snapshot(&rig, FakeProbe::answering(PS_ANTIGRAVITY));
    let v = serde_json::to_value(&snap).unwrap();
    let a = v["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "antigravity")
        .unwrap();
    assert_eq!(a["bypass_suspected"], true);
    // An old front end / old snapshot without the field still reads as "no alarm".
    let mut old = a.clone();
    old.as_object_mut().unwrap().remove("bypass_suspected");
    let item: AppCoverageItem = serde_json::from_value(old).unwrap();
    assert!(!item.bypass_suspected);
}

#[test]
fn listing_and_agent_id_helpers() {
    assert!(listing_has_antigravity(PS_ANTIGRAVITY));
    assert!(listing_has_antigravity(
        "\"Antigravity.exe\",\"4312\",\"Console\"\n"
    ));
    assert!(!listing_has_antigravity(PS_OTHER));
    assert!(is_antigravity_agent_id("language-server-macos-arm"));
    assert!(!is_antigravity_agent_id("antigravity"));
}
