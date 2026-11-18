use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::journal::{Value, recover_with};
use crate::sysproxy::platform::{FakePlatform, PacState, PlatOp, ServiceId};
use crate::sysproxy::{NO_PROXY_VALUE, SysProxy, dry_run_blocked_calls, is_sysproxy_active, os_effects_enabled};
use std::path::Path;
use std::sync::Arc;

// --- entry points never touch the OS in unit tests -------------------------------------

#[test]
fn cleanup_entry_points_run_in_dry_run_without_touching_the_os() {
    assert!(
        !os_effects_enabled(),
        "unit tests must run in OS dry-run mode"
    );
    let before = dry_run_blocked_calls();
    register_clean_exit_guard();
    SysProxy::disable();
    assert!(!SysProxy::is_active());
    let report = cleanup_all_persistent_settings();
    assert!(report.skipped_dry_run);
    assert!(!is_sysproxy_active());
    assert_eq!(force_clean_all_os_proxy_traces().len(), 3);
    assert!(cleaned_components().iter().any(|c| c.contains("PAC")));
    assert!(
        dry_run_blocked_calls() > before,
        "the journal gate must have counted the calls"
    );
}

#[test]
fn panic_hook_only_raises_the_flag() {
    register_clean_exit_guard();
    let before = dry_run_blocked_calls();
    let _ = std::panic::catch_unwind(|| panic!("probe"));
    assert!(journal::panic_flagged());
    assert_eq!(
        dry_run_blocked_calls(),
        before,
        "no system call from the hook"
    );
}

// --- restore / DNS guard ---------------------------------------------------------------

fn own_pac(j: &mut Journal, p: &FakePlatform) {
    j.apply(
        p,
        &Resource::Pac { service: wifi() },
        Value::Pac(PacState {
            url: Some("http://127.0.0.1:8899/proxy.pac".into()),
            enabled: Some(true),
        }),
    )
    .unwrap();
}

#[test]
fn cleanup_of_our_pac_under_temporary_dns_keeps_the_record_and_reports_an_error() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    p.seed_pac(
        &wifi(),
        PacState {
            url: None,
            enabled: Some(false),
        },
    );
    let mut j = open(&fs);
    own_pac(&mut j, &p);
    j.apply(&p, &env_res("HTTPS_PROXY"), Value::Env(Some("x".into())))
        .unwrap();
    p.set_temp_dns(true);
    let writes = p.os_writes();
    let rep = restore_with(&mut j, &p, Scope::All);
    assert!(rep.has_failures());
    assert_eq!(rep.failed(), 1);
    assert!(
        j.entry(&Resource::Pac { service: wifi() }).is_some(),
        "record kept"
    );
    assert_eq!(p.pac_of(&wifi()).enabled, Some(true), "PAC not written");
    assert_eq!(
        p.os_writes(),
        writes + 1,
        "only the environment variable was restored"
    );
    assert_eq!(p.env_of("HTTPS_PROXY"), None);
    // The VPN goes away: the next pass finishes the job.
    p.set_temp_dns(false);
    let rep = restore_with(&mut j, &p, Scope::All);
    assert_eq!(rep.restored(), 1);
    assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
    assert!(j.is_empty());
}

#[test]
fn unknown_dns_state_also_defers_network_restores() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    let mut j = open(&fs);
    own_pac(&mut j, &p);
    p.fail_next(PlatOp::TempDns);
    let rep = restore_with(&mut j, &p, Scope::All);
    assert_eq!(rep.failed(), 1);
    assert!(!j.is_empty());
}

#[test]
fn env_only_restore_does_not_touch_pac_nor_ask_about_dns() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    let mut j = open(&fs);
    own_pac(&mut j, &p);
    j.apply(&p, &env_res("HTTP_PROXY"), Value::Env(Some("x".into())))
        .unwrap();
    p.clear_calls();
    let rep = restore_with(&mut j, &p, Scope::UserEnv);
    assert_eq!(rep.restored(), 1);
    assert!(!p.calls().iter().any(|c| c.starts_with("temp_dns")));
    assert!(j.entry(&Resource::Pac { service: wifi() }).is_some());
    assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
}

#[test]
fn restore_after_a_hard_kill_returns_everything_in_one_pass() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    p.seed_env("TZ", "Europe/Berlin");
    {
        let mut j = open(&fs);
        own_pac(&mut j, &p);
        j.apply(
            &p,
            &env_res("HTTPS_PROXY"),
            Value::Env(Some("http://127.0.0.1:8899".into())),
        )
        .unwrap();
        // kill -9: no cleanup runs, only the file remains.
    }
    let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
    assert_eq!(r.restored(), 2);
    assert_eq!(p.env_of("HTTPS_PROXY"), None);
    assert_eq!(
        p.env_of("TZ"),
        Some("Europe/Berlin".into()),
        "a foreign TZ is never touched"
    );
    // Running it twice changes nothing.
    let writes = p.os_writes();
    let mut j = open(&fs);
    assert_eq!(restore_with(&mut j, &p, Scope::All).items.len(), 0);
    assert_eq!(p.os_writes(), writes);
}

// --- legacy_env_plan (pure) -------------------------------------------------------------

#[test]
fn legacy_env_plan_keeps_foreign_proxy_and_timezone() {
    let env = env_of(&[("HTTPS_PROXY", "http://corp:3128"), ("TZ", "Europe/Berlin")]);
    assert!(legacy_env_plan_with_gateway(&env, None).is_empty());
}

#[test]
fn legacy_env_plan_removes_whole_signed_set() {
    let env = env_of(&[
        ("HTTP_PROXY", "http://127.0.0.1:8899"),
        ("HTTPS_PROXY", "http://127.0.0.1:8899"),
        ("ALL_PROXY", "http://127.0.0.1:8899"),
        ("NO_PROXY", NO_PROXY_VALUE),
        ("TZ", "Europe/Amsterdam"),
        ("LANG", "en_US.UTF-8"),
        ("LC_TIME", "en_US.UTF-8"),
        ("LC_ALL", "en_US.UTF-8"),
    ]);
    let mut plan = legacy_env_plan_with_gateway(&env, None);
    plan.sort();
    let mut expected: Vec<String> = env.keys().cloned().collect();
    expected.sort();
    assert_eq!(plan, expected);
}

#[test]
fn legacy_env_plan_empty_environment() {
    assert!(legacy_env_plan_with_gateway(&BTreeMap::new(), Some(8899)).is_empty());
}

#[test]
fn legacy_env_plan_timezone_only_is_not_ours() {
    let env = env_of(&[("TZ", "Europe/Moscow"), ("LANG", "ru_RU.UTF-8")]);
    assert!(legacy_env_plan_with_gateway(&env, None).is_empty());
}

#[test]
fn legacy_env_plan_mixed_set_removes_only_signed_proxy_vars() {
    let env = env_of(&[
        ("HTTP_PROXY", "http://127.0.0.1:8899"),
        ("HTTPS_PROXY", "http://corp:3128"),
        ("NO_PROXY", "internal.example"),
        ("TZ", "Europe/Helsinki"),
        ("Path", r"C:\Windows"),
    ]);
    let mut plan = legacy_env_plan_with_gateway(&env, None);
    plan.sort();
    assert_eq!(plan, vec!["HTTP_PROXY".to_string(), "TZ".to_string()]);
}

#[test]
fn legacy_env_plan_recognises_8900_and_custom_gateway_port() {
    let env_8900 = env_of(&[
        ("ALL_PROXY", "http://127.0.0.1:8900/"),
        ("LC_ALL", "en_US.UTF-8"),
    ]);
    assert_eq!(legacy_env_plan_with_gateway(&env_8900, None).len(), 2);

    let env_custom = env_of(&[
        ("https_proxy", "http://localhost:9123"),
        ("TZ", "Asia/Tokyo"),
    ]);
    assert!(legacy_env_plan_with_gateway(&env_custom, None).is_empty());
    assert_eq!(
        legacy_env_plan_with_gateway(&env_custom, Some(9123)).len(),
        2
    );

    // Look-alikes are not signatures.
    let lookalike = env_of(&[("HTTP_PROXY", "http://127.0.0.1:88990"), ("TZ", "UTC")]);
    assert!(legacy_env_plan_with_gateway(&lookalike, Some(9123)).is_empty());
    let foreign_host = env_of(&[("HTTP_PROXY", "http://10.0.0.1:8899"), ("TZ", "UTC")]);
    assert!(legacy_env_plan_with_gateway(&foreign_host, None).is_empty());
}

// --- one-time migration of 1.3.x leftovers -----------------------------------------------

#[test]
fn migration_removes_the_signed_set_through_the_platform_and_sets_the_mark() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_env("HTTPS_PROXY", "http://127.0.0.1:8899");
    p.seed_env("HTTP_PROXY", "http://127.0.0.1:8900");
    p.seed_env("NO_PROXY", NO_PROXY_VALUE);
    p.seed_env("TZ", "Europe/Amsterdam");
    let mut j = open(&fs);
    let items = migrate_legacy(&mut j, &p, None);
    assert_eq!(items.len(), 4);
    for n in ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "TZ"] {
        assert_eq!(p.env_of(n), None, "{n}");
    }
    assert!(j.has_mark(LAUNCHD_MIGRATION_MARK));
    assert!(j.has_mark(LEGACY_MIGRATION_MARK));
    assert!(
        p.calls()
            .iter()
            .any(|c| c.starts_with("broadcast_env_change"))
    );
}

#[test]
fn migration_without_the_signature_touches_nothing() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_env("HTTPS_PROXY", "http://corp:3128");
    p.seed_env("TZ", "Europe/Berlin");
    p.seed_env("LANG", "de_DE.UTF-8");
    p.seed_env("HTTP_PROXY", "http://localhost:3128");
    let mut j = open(&fs);
    assert!(migrate_legacy(&mut j, &p, None).is_empty());
    assert_eq!(p.os_writes(), 0);
    assert_eq!(p.env_of("HTTPS_PROXY"), Some("http://corp:3128".into()));
    assert_eq!(p.env_of("TZ"), Some("Europe/Berlin".into()));
    assert!(
        !p.calls()
            .iter()
            .any(|c| c.starts_with("broadcast_env_change")),
        "no change, no broadcast"
    );
    assert!(
        j.has_mark(LAUNCHD_MIGRATION_MARK) && j.has_mark(LEGACY_MIGRATION_MARK),
        "examined completely, so done"
    );
}

#[test]
fn migration_runs_once_and_the_mark_survives_a_restart() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    {
        let mut j = open(&fs);
        migrate_legacy(&mut j, &p, None);
    }
    // Leftovers that appear later are no longer "legacy": the migration does not run again.
    p.seed_env("HTTPS_PROXY", "http://127.0.0.1:8899");
    let mut j = open(&fs);
    assert!(j.has_mark(LAUNCHD_MIGRATION_MARK));
    assert!(migrate_legacy(&mut j, &p, None).is_empty());
    assert_eq!(
        p.env_of("HTTPS_PROXY"),
        Some("http://127.0.0.1:8899".into())
    );
}

#[test]
fn migration_failure_keeps_the_values_and_is_retried() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_env("HTTPS_PROXY", "http://127.0.0.1:8899");
    let mut j = open(&fs);
    p.fail_next(PlatOp::UnsetEnv);
    let items = migrate_legacy(&mut j, &p, None);
    assert!(
        items
            .iter()
            .any(|i| matches!(i.outcome, Outcome::Failed(_)))
    );
    assert!(!j.has_mark(LAUNCHD_MIGRATION_MARK));
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.env_of("HTTPS_PROXY"), None);
    assert!(j.has_mark(LAUNCHD_MIGRATION_MARK));
}

#[test]
fn migration_skips_variables_the_journal_manages() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let mut j = open(&fs);
    j.apply(
        &p,
        &env_res("HTTPS_PROXY"),
        Value::Env(Some("http://127.0.0.1:8899".into())),
    )
    .unwrap();
    migrate_legacy(&mut j, &p, None);
    assert_eq!(
        p.env_of("HTTPS_PROXY"),
        Some("http://127.0.0.1:8899".into()),
        "the journal restores it, the migration does not guess"
    );
}

#[test]
fn migration_switches_off_a_dead_signed_pac_but_never_a_foreign_one() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let usb = ServiceId::new("en5", "USB LAN", "USB LAN");
    p.add_service(wifi());
    p.add_service(usb.clone());
    p.seed_pac(
        &wifi(),
        PacState {
            url: Some("http://127.0.0.1:8899/proxy.pac".into()),
            enabled: Some(true),
        },
    );
    p.seed_pac(
        &usb,
        PacState {
            url: Some("http://corp/p.pac".into()),
            enabled: Some(true),
        },
    );
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
    assert_eq!(p.pac_of(&wifi()).url, None, "our own URL is cleared too");
    assert_eq!(p.pac_of(&usb).enabled, Some(true));
    assert_eq!(p.pac_of(&usb).url.as_deref(), Some("http://corp/p.pac"));
}

#[test]
fn migration_of_pac_waits_for_temporary_dns_and_keeps_the_mark_unset() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    p.seed_pac(
        &wifi(),
        PacState {
            url: Some("http://127.0.0.1:8899/proxy.pac".into()),
            enabled: Some(true),
        },
    );
    p.set_temp_dns(true);
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
    assert!(!j.has_mark(LEGACY_MIGRATION_MARK));
    p.set_temp_dns(false);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
    assert!(j.has_mark(LEGACY_MIGRATION_MARK));
}

#[test]
fn migration_deletes_a_signed_wininet_pac_only() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_inet(
        "AutoConfigURL",
        RegValue::sz("http://127.0.0.1:8899/proxy.pac"),
    );
    p.seed_inet("ProxyEnable", RegValue::dword(1));
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.inet_of("AutoConfigURL"), None);
    assert_eq!(p.inet_of("ProxyEnable"), Some(RegValue::dword(1)));

    let (fs2, p2) = (FakeFs::new(), FakePlatform::new());
    p2.seed_inet("AutoConfigURL", RegValue::sz("http://corp/p.pac"));
    let mut j2 = open(&fs2);
    migrate_legacy(&mut j2, &p2, None);
    assert_eq!(
        p2.inet_of("AutoConfigURL"),
        Some(RegValue::sz("http://corp/p.pac"))
    );
    assert_eq!(p2.os_writes(), 0);
}

#[test]
fn migration_also_finds_locale_variables_the_registry_lists() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_env("HTTPS_PROXY", "http://127.0.0.1:8899");
    p.seed_env("LC_IDENTIFICATION", "en_US.UTF-8");
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.env_of("LC_IDENTIFICATION"), None);
}

