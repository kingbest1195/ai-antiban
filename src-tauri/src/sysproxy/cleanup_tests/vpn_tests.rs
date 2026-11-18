use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::journal::{Journal, Value};
use crate::sysproxy::platform::{FakePlatform, PacState, PlatOp, ServiceId};
use std::path::Path;

// --- WP-28: VPN services ------------------------------------------------------------------

fn ours() -> PacState {
    PacState {
        url: Some("http://127.0.0.1:8899/proxy.pac".into()),
        enabled: Some(true),
    }
}
fn calls_on(p: &FakePlatform, svc: &ServiceId) -> bool {
    let key = svc.key();
    p.calls().iter().any(|c| c.contains(&key))
}

#[test]
fn the_vpn_leftover_cleanup_clears_only_a_disconnected_service_and_marks_once() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let vpn = p.add_vpn_service("Alpha VPN", false);
    p.seed_pac(&vpn, ours());
    let mut j = open(&fs);
    let items = migrate_legacy(&mut j, &p, None);
    assert_eq!(
        p.pac_of(&vpn),
        PacState {
            url: None,
            enabled: Some(false)
        }
    );
    assert!(
        items
            .iter()
            .any(|i| i.resource.starts_with("legacy:vpn-pac:"))
    );
    assert!(j.has_mark(VPN_PAC_MIGRATION_MARK));
    assert_eq!(
        VPN_PAC_MIGRATION_MARK,
        "legacy-2.0-vpn-services-pac-cleanup"
    );
    // Done once: a second run neither reads nor writes.
    p.seed_pac(&vpn, ours());
    p.clear_calls();
    assert!(migrate_legacy(&mut j, &p, None).is_empty());
    assert_eq!(p.pac_of(&vpn), ours());
    assert!(!calls_on(&p, &vpn));
}

#[test]
fn a_connected_vpn_is_not_even_read_and_the_cleanup_waits_for_it_to_disconnect() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let vpn = p.add_vpn_service("Alpha VPN", true);
    p.seed_pac(&vpn, ours());
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert!(!calls_on(&p, &vpn), "calls: {:?}", p.calls());
    assert_eq!(p.os_writes(), 0);
    assert_eq!(p.pac_of(&vpn), ours());
    assert!(!j.has_mark(VPN_PAC_MIGRATION_MARK));
    // Later it is disconnected: now the leftover goes, once.
    p.set_vpn_connection("Alpha VPN", false);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.pac_of(&vpn).enabled, Some(false));
    assert!(j.has_mark(VPN_PAC_MIGRATION_MARK));
}

#[test]
fn a_foreign_pac_on_a_disconnected_vpn_is_never_cleared() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let vpn = p.add_vpn_service("Alpha VPN", false);
    let theirs = PacState {
        url: Some("http://corp.example/p.pac".into()),
        enabled: Some(true),
    };
    p.seed_pac(&vpn, theirs.clone());
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.pac_of(&vpn), theirs);
    assert_eq!(p.os_writes(), 0);
    assert!(j.has_mark(VPN_PAC_MIGRATION_MARK));
}

#[test]
fn a_vpn_leftover_waits_for_temporary_dns_like_every_other_write() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let vpn = p.add_vpn_service("Alpha VPN", false);
    p.seed_pac(&vpn, ours());
    p.set_temp_dns(true);
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.pac_of(&vpn), ours());
    assert!(!j.has_mark(VPN_PAC_MIGRATION_MARK));
}

#[test]
fn the_physical_pass_does_not_touch_a_vpn_service() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    let vpn = p.add_vpn_service("Alpha VPN", true);
    p.seed_pac(&wifi(), ours());
    p.seed_pac(&vpn, ours());
    let mut j = open(&fs);
    migrate_legacy_pac(&mut j, &p, None, false);
    assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
    assert!(!calls_on(&p, &vpn));
}

fn own_pac_on(j: &mut Journal, p: &FakePlatform, svc: &ServiceId) {
    j.apply(
        p,
        &Resource::Pac {
            service: svc.clone(),
        },
        Value::Pac(ours()),
    )
    .unwrap();
}

#[test]
fn a_restore_leaves_a_record_on_a_connected_vpn_and_finishes_it_after_the_disconnect() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    let vpn = p.add_vpn_service("Alpha VPN", true);
    // A record from an earlier build that wrote into the VPN service.
    let mut j = open(&fs);
    own_pac_on(&mut j, &p, &vpn);
    own_pac_on(&mut j, &p, &wifi());
    p.clear_calls();
    let writes = p.os_writes();
    let rep = restore_with(&mut j, &p, Scope::All);
    assert_eq!(
        p.pac_of(&vpn),
        ours(),
        "the connected VPN keeps what it has"
    );
    assert_eq!(p.pac_of(&wifi()).enabled, Some(false), "Wi-Fi is restored");
    assert_eq!(p.os_writes(), writes + 1);
    assert!(
        rep.items
            .iter()
            .any(|i| i.outcome == Outcome::Skipped("vpn"))
    );
    assert!(!rep.has_failures(), "a skipped VPN is not an error");
    assert!(
        j.entry(&Resource::Pac {
            service: vpn.clone()
        })
        .is_some()
    );
    assert!(
        !p.calls()
            .iter()
            .any(|c| c.starts_with("set_") && c.contains(&vpn.key()))
    );
    // Disconnected: the record is put back like any other.
    p.set_vpn_connection("Alpha VPN", false);
    let rep = restore_with(&mut j, &p, Scope::All);
    assert_eq!(rep.restored(), 1);
    assert_eq!(p.pac_of(&vpn).enabled, Some(false));
    assert!(j.is_empty());
}

#[test]
fn a_restore_of_a_physical_service_does_not_depend_on_the_connection_list() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    let mut j = open(&fs);
    own_pac_on(&mut j, &p, &wifi());
    p.fail_next(PlatOp::VpnList);
    let rep = restore_with(&mut j, &p, Scope::All);
    assert_eq!(rep.restored(), 1, "quit must not leave our PAC behind");
}

#[test]
fn cleanup_scope_all_restores_journaled_browser_policies_while_scope_user_env_leaves_them() {
    use crate::sysproxy::browser_policies::{
        FakePolicyStore, PolicySpec, PolicyValue, apply_policy_specs,
    };
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let store = FakePolicyStore::new();
    store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));

    let mut j = open(&fs).with_policy_store(store.clone());
    let specs = vec![
        PolicySpec::new("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(false)),
        PolicySpec::new(
            "com.google.Chrome",
            "DnsOverHttpsMode",
            PolicyValue::Sz("off".to_string()),
        ),
    ];
    apply_policy_specs(&mut j, &p, &specs);
    assert_eq!(
        store.get("com.google.Chrome", "QuicAllowed"),
        Some(PolicyValue::Bool(false))
    );

    // Scope::UserEnv (disabling CLI protection) must not remove browser policies.
    let env_rep = restore_with(&mut j, &p, Scope::UserEnv);
    assert!(env_rep.items.is_empty());
    assert_eq!(
        store.get("com.google.Chrome", "QuicAllowed"),
        Some(PolicyValue::Bool(false))
    );

    // Scope::All (disable sysproxy / quit / crash recovery) restores baseline.
    let all_rep = restore_with(&mut j, &p, Scope::All);
    assert_eq!(all_rep.restored(), 2);
    assert_eq!(
        store.get("com.google.Chrome", "QuicAllowed"),
        Some(PolicyValue::Bool(true))
    );
    assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
    assert!(j.is_empty());
}

#[test]
fn shutdown_cleanup_guard_runs_once_emits_steps_and_resets_for_retry() {
    use std::sync::atomic::AtomicUsize;

    let guard = ShutdownCleanupGuard::new();
    let events = std::sync::Mutex::new(Vec::<ShutdownProgressPayload>::new());
    let calls = AtomicUsize::new(0);

    assert!(guard.try_claim_async_start());
    // Duplicate async quit claim while in-progress is rejected.
    assert!(!guard.try_claim_async_start());

    let res1 = guard.run_once_with(
        "quit",
        false,
        |p| events.lock().unwrap().push(p),
        || {
            calls.fetch_add(1, Ordering::SeqCst);
        },
        || {
            calls.fetch_add(1, Ordering::SeqCst);
            RecoveryReport::default()
        },
        || {
            calls.fetch_add(1, Ordering::SeqCst);
            RecoveryReport::default()
        },
        || {
            calls.fetch_add(1, Ordering::SeqCst);
        },
    );
    assert!(res1.is_some());
    assert!(guard.is_completed());
    assert_eq!(calls.load(Ordering::SeqCst), 4);

    // Subsequent RunEvent::ExitRequested / RunEvent::Exit calls must be no-ops.
    let res2 = guard.run_once_with(
        "quit",
        true,
        |p| events.lock().unwrap().push(p),
        || {
            calls.fetch_add(1, Ordering::SeqCst);
        },
        RecoveryReport::default,
        RecoveryReport::default,
        || {},
    );
    assert!(res2.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 4);

    let recorded = events.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![
            ShutdownProgressPayload::step("quit", 2),
            ShutdownProgressPayload::step("quit", 3),
            ShutdownProgressPayload::step("quit", 4),
            ShutdownProgressPayload::done("quit"),
        ]
    );
    assert_eq!(
        recorded.last().unwrap().label,
        "Готово, закрываем приложение..."
    );
    assert!(recorded.last().unwrap().done);

    // Resetting (e.g. failed update install) allows cleanup to run again later with step 1.
    guard.reset();
    assert!(!guard.is_completed());
    let mut update_events = Vec::new();
    let res3 = guard.run_once_with(
        "update",
        true,
        |p| update_events.push(p),
        || {},
        RecoveryReport::default,
        RecoveryReport::default,
        || {},
    );
    assert!(res3.is_some());
    assert_eq!(update_events.len(), 5);
    assert_eq!(update_events[0].step, 1);
    assert_eq!(
        update_events[0].label,
        "Остановка защиты и локального шлюза..."
    );
    assert_eq!(
        update_events[1].label,
        "Восстановление системного прокси и политик браузеров..."
    );
    assert_eq!(
        update_events[2].label,
        "Очистка настроек терминала и IDE..."
    );
    assert_eq!(
        update_events[3].label,
        "Восстановление системного часового пояса..."
    );
    assert!(update_events[4].done);
    assert_eq!(update_events[4].label, "Перезапуск после обновления...");
}

#[test]
fn restore_with_probe_skips_running_browser_pac_pref_and_restores_closed() {
    use crate::sysproxy::fs::FakeFs;
    use crate::sysproxy::journal::Value;
    use crate::sysproxy::platform::FakePlatform;
    use std::path::PathBuf;
    use std::sync::Arc;

    struct RunningChromeProbe;
    impl SystemProbe for RunningChromeProbe {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<String> {
            Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n".to_string())
        }
    }

    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let chrome_prefs = PathBuf::from("/Users/t/Chrome/Default/Preferences");
    let comet_prefs = PathBuf::from("/Users/t/Comet/Default/Preferences");
    fs.put(&chrome_prefs, br#"{"keep":1}"#, 0o600);
    fs.put(&comet_prefs, br#"{"keep":2}"#, 0o600);

    let mut j = Journal::open(fs.clone(), Path::new("/j")).unwrap();
    let desired =
        browser_policies::build_browser_proxy_json_string("http://127.0.0.1:8899/proxy.pac");
    j.apply(
        &plat,
        &Resource::BrowserPacPref {
            domain: "com.google.Chrome".into(),
            file: chrome_prefs.to_string_lossy().into_owned(),
        },
        Value::Json(Some(desired.clone())),
    )
    .unwrap();
    j.apply(
        &plat,
        &Resource::BrowserPacPref {
            domain: "ai.perplexity.comet".into(),
            file: comet_prefs.to_string_lossy().into_owned(),
        },
        Value::Json(Some(desired)),
    )
    .unwrap();

    let probe = RunningChromeProbe;
    let rep = restore_with_probe(&mut j, &plat, Scope::All, Some((Os::Macos, &probe)));
    assert!(!rep.has_failures());
    assert!(
        rep.items
            .iter()
            .any(|i| matches!(i.outcome, Outcome::Skipped("browser_running")))
    );
    // Running Chrome keeps its injected proxy; closed Comet had its proxy removed.
    assert!(
        browser_policies::read_browser_proxy_pref(&*fs, &chrome_prefs)
            .unwrap()
            .is_some()
    );
    assert!(
        browser_policies::read_browser_proxy_pref(&*fs, &comet_prefs)
            .unwrap()
            .is_none()
    );
}
