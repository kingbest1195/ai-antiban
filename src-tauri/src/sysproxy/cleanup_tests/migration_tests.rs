use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::journal::Value;
use crate::sysproxy::platform::{ChainState, FakePlatform, PacState, ProxyEndpoint};
use crate::sysproxy::{NO_PROXY_VALUE, NO_PROXY_VALUE_2_0};

// --- WP-23: 2.0.0 leftovers in the GUI session, by signature ------------------------------

fn signed_proxy_env(p: &FakePlatform) {
    p.seed_env("HTTP_PROXY", "http://127.0.0.1:8899");
    p.seed_env("HTTPS_PROXY", "http://127.0.0.1:8899");
    p.seed_env("ALL_PROXY", "http://127.0.0.1:8899");
}

#[test]
fn no_proxy_of_2_0_0_is_still_ours_and_the_new_one_too() {
    for v in [NO_PROXY_VALUE_2_0, NO_PROXY_VALUE] {
        let env = env_of(&[("HTTP_PROXY", "http://127.0.0.1:8899"), ("NO_PROXY", v)]);
        let plan = legacy_env_plan_with_gateway(&env, None);
        assert!(plan.contains(&"NO_PROXY".to_string()), "{v}");
    }
    let foreign = env_of(&[
        ("HTTP_PROXY", "http://127.0.0.1:8899"),
        ("NO_PROXY", "localhost,corp.example"),
    ]);
    assert_eq!(
        legacy_env_plan_with_gateway(&foreign, None),
        vec!["HTTP_PROXY".to_string()]
    );
}

#[test]
fn a_users_locale_next_to_a_signed_proxy_stays() {
    let env = env_of(&[
        ("HTTP_PROXY", "http://127.0.0.1:8899"),
        ("LANG", "ru_RU.UTF-8"),
        ("LC_TIME", "ru_RU.UTF-8"),
        ("LC_ALL", "en_US.UTF-8"),
    ]);
    let mut plan = legacy_env_plan_with_gateway(&env, None);
    plan.sort();
    assert_eq!(plan, vec!["HTTP_PROXY".to_string(), "LC_ALL".to_string()]);
}

#[test]
fn migration_removes_2_0_0_leftovers_with_the_loopback_signature() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    signed_proxy_env(&p);
    p.seed_env("NO_PROXY", NO_PROXY_VALUE_2_0);
    p.seed_env("TZ", "Europe/Amsterdam");
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    for n in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "TZ"] {
        assert_eq!(p.env_of(n), None, "{n}");
    }
}

#[test]
fn migration_keeps_a_foreign_corporate_proxy_next_to_our_leftovers() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_env("HTTPS_PROXY", "http://corp:3128");
    p.seed_env("HTTP_PROXY", "http://localhost:8900");
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.env_of("HTTPS_PROXY"), Some("http://corp:3128".into()));
    assert_eq!(p.env_of("HTTP_PROXY"), None);
}

#[test]
fn migration_removes_tz_and_locale_only_with_the_co_signature() {
    // With a signed proxy in the same session: TZ and our locale go, the user's locale stays.
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_env("HTTP_PROXY", "http://127.0.0.1:8899");
    p.seed_env("TZ", "Europe/Berlin");
    p.seed_env("LC_ALL", "en_US.UTF-8");
    p.seed_env("LANG", "ru_RU.UTF-8");
    migrate_legacy(&mut open(&fs), &p, None);
    assert_eq!(p.env_of("TZ"), None);
    assert_eq!(p.env_of("LC_ALL"), None);
    assert_eq!(p.env_of("LANG"), Some("ru_RU.UTF-8".into()));

    // Without it nothing is touched, even a value that looks like ours.
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_env("TZ", "Europe/Berlin");
    p.seed_env("LC_ALL", "en_US.UTF-8");
    p.seed_env("LANG", "en_US.UTF-8");
    p.seed_env("HTTPS_PROXY", "http://corp:3128");
    migrate_legacy(&mut open(&fs), &p, None);
    assert_eq!(p.os_writes(), 0);
    assert_eq!(p.env_of("LC_ALL"), Some("en_US.UTF-8".into()));
}

#[test]
fn the_second_migration_run_makes_no_calls_at_all() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    signed_proxy_env(&p);
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert!(j.has_mark(LAUNCHD_MIGRATION_MARK));
    p.clear_calls();
    assert!(migrate_legacy(&mut j, &p, None).is_empty());
    assert!(p.calls().is_empty(), "{:?}", p.calls());
    // And after a restart (the mark is durable).
    drop(j);
    let mut j2 = open(&fs);
    assert!(migrate_legacy(&mut j2, &p, None).is_empty());
    assert!(p.calls().is_empty());
}

#[test]
fn the_old_1_3_mark_does_not_hide_2_0_0_leftovers() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let mut j = open(&fs);
    j.set_mark(&p, LEGACY_MIGRATION_MARK).unwrap();
    signed_proxy_env(&p);
    p.seed_env("TZ", "Asia/Tokyo");
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.env_of("HTTPS_PROXY"), None);
    assert_eq!(p.env_of("TZ"), None);
    assert!(j.has_mark(LAUNCHD_MIGRATION_MARK));
}

#[test]
fn migration_leaves_variables_the_journal_owns_to_the_journal_rule() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let mut j = open(&fs);
    j.apply(&p, &env_res("TZ"), Value::Env(Some("Europe/Oslo".into())))
        .unwrap();
    signed_proxy_env(&p);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(p.env_of("TZ"), Some("Europe/Oslo".into()));
    // The general rule: restored only while the value still is the one we wrote.
    let rep = restore_with(&mut j, &p, Scope::UserEnv);
    assert_eq!(rep.restored(), 1);
    assert_eq!(p.env_of("TZ"), None);
    p.seed_env("TZ", "Europe/Oslo");
    drop(j);
    let mut j = open(&fs);
    j.apply(&p, &env_res("TZ"), Value::Env(Some("Europe/Oslo".into())))
        .unwrap();
    p.seed_env("TZ", "mine");
    assert_eq!(restore_with(&mut j, &p, Scope::UserEnv).external(), 1);
    assert_eq!(p.env_of("TZ"), Some("mine".into()));
}

#[test]
fn only_the_exact_pac_address_of_our_gateway_is_a_signature() {
    assert!(is_zastava_pac_signature(
        "http://127.0.0.1:8899/proxy.pac",
        None
    ));
    assert!(is_zastava_pac_signature(
        "http://localhost:9123/proxy.pac",
        Some(9123)
    ));
    for bad in [
        "https://127.0.0.1:8899/proxy.pac",
        "http://127.0.0.1:8899/other.pac",
        "http://127.0.0.1:8899/proxy.pac?x=1",
        "http://127.0.0.1:8899",
        "http://10.0.0.1:8899/proxy.pac",
        "http://127.0.0.1:9123/proxy.pac",
        "http://corp/p.pac",
    ] {
        assert!(!is_zastava_pac_signature(bad, None), "{bad}");
    }
}

#[test]
fn a_pac_with_a_look_alike_address_is_left_alone() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    let st = PacState {
        url: Some("http://127.0.0.1:8899/other.pac".into()),
        enabled: Some(true),
    };
    p.seed_pac(&wifi(), st.clone());
    migrate_legacy(&mut open(&fs), &p, None);
    assert_eq!(p.pac_of(&wifi()), st);
    assert_eq!(p.os_writes(), 0);
}

#[test]
fn chain_endpoints_are_untouched_by_the_migration() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.add_service(wifi());
    let chain = ChainState {
        http: ProxyEndpoint {
            enabled: Some(true),
            server: Some("127.0.0.1".into()),
            port: Some(8899),
            authenticated: None,
        },
        https: ProxyEndpoint::default(),
    };
    p.seed_chain(&wifi(), chain.clone());
    let mut j = open(&fs);
    migrate_legacy(&mut j, &p, None);
    assert_eq!(
        p.chain_of(&wifi()),
        chain,
        "no signature-based guessing for explicit proxies"
    );
}

// --- strict signature of a JSON value; ~/.zshenv at start ------------------------------------

#[test]
fn the_json_signature_is_strict() {
    for (raw, gw, yes) in [
        ("\"http://127.0.0.1:8899\"", None, true),
        ("\"http://localhost:8900/\"", None, true),
        ("\"http://127.0.0.1:9123\"", Some(9123), true),
        ("\"http://127.0.0.1:9123\"", None, false),
        ("\"http://user@127.0.0.1:8899\"", None, false),
        ("\"http://my-localhost:8900\"", None, false),
        ("\"http://127.0.0.1:88990\"", None, false),
        ("http://127.0.0.1:8899", None, false), // not a JSON string
        ("8899", None, false),
    ] {
        assert_eq!(is_zastava_proxy_json(raw, gw), yes, "{raw}");
    }
}

#[test]
fn the_start_pass_cuts_an_old_block_out_of_zshenv_and_leaves_a_half_marker_alone() {
    use crate::sysproxy::shell_rc::{build_shell_rc_guard_block_with_tz, upsert_block};
    let fs = FakeFs::new();
    let p = FakePlatform::new();
    let home = crate::sysproxy::user_home_dir().expect("dry-run home");
    let zshenv = home.join(".zshenv");
    let block = build_shell_rc_guard_block_with_tz("http://127.0.0.1:8899", 8899, None);
    let text = upsert_block("export A=1\n", &block).unwrap();
    fs.put(&zshenv, text.as_bytes(), 0o600);
    let mut j = open(&fs);
    let report = restore_and_migrate(&mut j, &p);
    assert!(!report.has_failures(), "{}", report.summary());
    assert_eq!(fs.get(&zshenv).unwrap(), b"export A=1\n");
    // Run again: nothing to do, nothing written.
    let writes = fs.write_count();
    restore_and_migrate(&mut j, &p);
    assert_eq!(fs.write_count(), writes);
    // A half marker is left alone and is not a failure.
    let broken = format!("export A=1\n{}\n", crate::sysproxy::ZASTAVA_RC_START);
    fs.put(&zshenv, broken.as_bytes(), 0o600);
    let report = restore_and_migrate(&mut j, &p);
    assert!(!report.has_failures());
    assert!(report.external() >= 1, "{}", report.summary());
    assert_eq!(fs.get(&zshenv).unwrap(), broken.as_bytes());
}
