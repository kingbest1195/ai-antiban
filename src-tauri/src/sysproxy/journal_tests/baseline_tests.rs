use super::*;
use crate::sysproxy::fs::FsOp;
use crate::sysproxy::platform::{PlatOp, ProxyEndpoint};

// --- types / absence / empty -----------------------------------------------------------

#[test]
fn absent_baseline_is_deleted_on_restore() {
    let (fs, p) = setup();
    let mut j = open(&fs).unwrap();
    assert_eq!(
        j.apply(&p, &env("HTTPS_PROXY"), ev("x")).unwrap(),
        ApplyOutcome::Applied
    );
    assert_eq!(p.env_of("HTTPS_PROXY"), Some("x".into()));
    let r = j.restore_all(&p);
    assert_eq!(r.restored(), 1);
    assert_eq!(
        p.env_of("HTTPS_PROXY"),
        None,
        "absent baseline -> variable deleted"
    );
}

#[test]
fn empty_string_baseline_differs_from_absent() {
    let (fs, p) = setup();
    p.seed_env("A", "");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("x")).unwrap();
    assert_eq!(
        j.entry(&env("A")).unwrap().baseline,
        Value::Env(Some(String::new()))
    );
    j.restore_all(&p);
    assert_eq!(
        p.env_of("A"),
        Some(String::new()),
        "empty string comes back as empty, not removed"
    );
}

#[test]
fn registry_type_is_preserved_through_restore() {
    let (fs, p) = setup();
    p.seed_inet("ProxyEnable", RegValue::dword(1));
    p.seed_inet("AutoConfigURL", RegValue::expand_sz("%X%"));
    let mut j = open(&fs).unwrap();
    let en = Resource::Inet {
        name: "ProxyEnable".into(),
    };
    let url = Resource::Inet {
        name: "AutoConfigURL".into(),
    };
    j.apply(&p, &en, Value::Reg(Some(RegValue::dword(0))))
        .unwrap();
    j.apply(
        &p,
        &url,
        Value::Reg(Some(RegValue::sz("http://127.0.0.1:8899/proxy.pac"))),
    )
    .unwrap();
    j.restore_all(&p);
    assert_eq!(p.inet_of("ProxyEnable"), Some(RegValue::dword(1)));
    assert_eq!(p.inet_of("AutoConfigURL"), Some(RegValue::expand_sz("%X%")));
}

#[test]
fn absent_registry_value_is_deleted_not_blanked() {
    let (fs, p) = setup();
    let mut j = open(&fs).unwrap();
    let url = Resource::Inet {
        name: "AutoConfigURL".into(),
    };
    j.apply(&p, &url, Value::Reg(Some(RegValue::sz("u"))))
        .unwrap();
    j.restore_all(&p);
    assert_eq!(p.inet_of("AutoConfigURL"), None);
}

#[test]
fn pac_baseline_with_third_party_pac_returns_exactly() {
    let (fs, p) = setup();
    p.add_service(wifi());
    p.seed_pac(
        &wifi(),
        PacState {
            url: Some("http://corp/p.pac".into()),
            enabled: Some(false),
        },
    );
    let mut j = open(&fs).unwrap();
    let res = Resource::Pac { service: wifi() };
    j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
        .unwrap();
    j.restore_all(&p);
    assert_eq!(
        p.pac_of(&wifi()),
        PacState {
            url: Some("http://corp/p.pac".into()),
            enabled: Some(false)
        }
    );
}

#[test]
fn pac_absent_baseline_clears_url() {
    let (fs, p) = setup();
    p.add_service(wifi());
    let mut j = open(&fs).unwrap();
    let res = Resource::Pac { service: wifi() };
    j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
        .unwrap();
    j.restore_all(&p);
    assert_eq!(p.pac_of(&wifi()).url, None);
}

#[test]
fn http_and_https_upstreams_are_kept_apart() {
    let (fs, p) = setup();
    p.add_service(wifi());
    let http = ProxyEndpoint {
        enabled: Some(true),
        server: Some("h1".into()),
        port: Some(1080),
        ..Default::default()
    };
    let https = ProxyEndpoint {
        enabled: Some(true),
        server: Some("h2".into()),
        port: Some(2080),
        ..Default::default()
    };
    p.seed_chain(
        &wifi(),
        ChainState {
            http: http.clone(),
            https: https.clone(),
        },
    );
    let mut j = open(&fs).unwrap();
    let res = Resource::Chain { service: wifi() };
    // `apply` takes the complete value as the OS will report it back.
    let off = ChainState {
        http: ProxyEndpoint {
            enabled: Some(false),
            ..http.clone()
        },
        https: ProxyEndpoint {
            enabled: Some(false),
            ..https.clone()
        },
    };
    j.apply(&p, &res, Value::Chain(off)).unwrap();
    j.restore_all(&p);
    assert_eq!(p.chain_of(&wifi()), ChainState { http, https });
}

// --- repeated enable -------------------------------------------------------------------

#[test]
fn repeated_enable_keeps_the_original_baseline() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    assert_eq!(
        j.apply(&p, &env("A"), ev("ours")).unwrap(),
        ApplyOutcome::Unchanged
    );
    j.apply(&p, &env("A"), ev("ours2")).unwrap();
    assert_eq!(j.entry(&env("A")).unwrap().baseline, ev("orig"));
    j.restore_all(&p);
    assert_eq!(p.env_of("A"), Some("orig".into()));
}

#[test]
fn new_pac_url_update_keeps_original_flag_baseline() {
    let (fs, p) = setup();
    p.add_service(wifi());
    p.seed_pac(
        &wifi(),
        PacState {
            url: Some("http://corp/p.pac".into()),
            enabled: Some(false),
        },
    );
    let mut j = open(&fs).unwrap();
    let res = Resource::Pac { service: wifi() };
    j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
        .unwrap();
    j.apply(&p, &res, pac_value("http://127.0.0.1:9000/proxy.pac", true))
        .unwrap();
    j.restore_all(&p);
    assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
    assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some("http://corp/p.pac"));
}

// --- external change -------------------------------------------------------------------

#[test]
fn external_change_is_preserved_and_record_released() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    p.seed_env("A", "users-own-value");
    let writes = p.os_writes();
    let r = j.restore_all(&p);
    assert_eq!(r.external(), 1);
    assert_eq!(p.env_of("A"), Some("users-own-value".into()));
    assert_eq!(
        p.os_writes(),
        writes,
        "an external value is never written over"
    );
    assert!(j.is_empty());
}

#[test]
fn external_deletion_is_not_resurrected() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    p.remove_env_externally("A");
    let r = j.restore_all(&p);
    assert_eq!(r.external(), 1);
    assert_eq!(p.env_of("A"), None);
}

#[test]
fn external_pac_change_is_not_rolled_back_and_foreign_flag_stays() {
    let (fs, p) = setup();
    p.add_service(wifi());
    let mut j = open(&fs).unwrap();
    let res = Resource::Pac { service: wifi() };
    j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
        .unwrap();
    p.seed_pac(
        &wifi(),
        PacState {
            url: Some("http://vpn/p.pac".into()),
            enabled: Some(true),
        },
    );
    j.restore_all(&p);
    assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some("http://vpn/p.pac"));
    assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
}

#[test]
fn apply_over_external_change_rebases_the_baseline() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    p.seed_env("A", "other");
    assert_eq!(
        j.apply(&p, &env("A"), ev("ours")).unwrap(),
        ApplyOutcome::Rebased
    );
    // Protection is back on, and the foreign value is what will be restored.
    assert_eq!(p.env_of("A"), Some("ours".into()));
    assert_eq!(j.entry(&env("A")).unwrap().baseline, ev("other"));
    j.restore_all(&p);
    assert_eq!(p.env_of("A"), Some("other".into()));
}

#[test]
fn external_change_after_a_rebase_is_still_not_rolled_back() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    p.seed_env("A", "other");
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    p.seed_env("A", "latest-foreign");
    let writes = p.os_writes();
    let r = j.restore_all(&p);
    assert_eq!(r.external(), 1);
    assert_eq!(p.env_of("A"), Some("latest-foreign".into()));
    assert_eq!(p.os_writes(), writes);
}

#[test]
fn crash_between_intent_and_write_after_a_rebase_keeps_the_foreign_value() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    {
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("ours")).unwrap();
        p.seed_env("A", "other");
        // The rebase intent is durable, the OS write never lands.
        p.fail_next(PlatOp::SetEnv);
        assert!(j.apply(&p, &env("A"), ev("ours")).is_err());
    }
    let writes = p.os_writes();
    let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
    assert_eq!(
        p.env_of("A"),
        Some("other".into()),
        "foreign value untouched"
    );
    assert_eq!(p.os_writes(), writes);
    assert_eq!(r.failed(), 0);
}

#[test]
fn crash_after_a_rebase_write_before_the_applied_mark_restores_the_foreign_value() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    {
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("ours")).unwrap();
        p.seed_env("A", "other");
        fs.fail_after(FsOp::WriteAtomic, 1); // intent lands, the "applied" mark is lost
        assert!(j.apply(&p, &env("A"), ev("ours")).is_err());
    }
    assert_eq!(p.env_of("A"), Some("ours".into()));
    recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
    assert_eq!(p.env_of("A"), Some("other".into()));
}

#[test]
fn a_foreign_value_equal_to_ours_does_not_replace_the_baseline() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    p.seed_env("A", "other");
    j.apply(&p, &env("A"), ev("v2")).unwrap(); // rebase onto "other"
    p.seed_env("A", "v3"); // somebody writes exactly the value we are about to apply
    assert_eq!(
        j.apply(&p, &env("A"), ev("v3")).unwrap(),
        ApplyOutcome::Applied
    );
    assert_eq!(j.entry(&env("A")).unwrap().baseline, ev("other"));
}

#[test]
fn rebase_is_logged_without_values_and_writes_the_journal_before_the_os() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    p.seed_env("A", "secret-foreign-value");
    let writes_before = fs.write_count();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    assert!(fs.write_count() >= writes_before + 2, "intent and applied");
    let calls = p.calls().join(" ");
    assert!(!calls.contains("secret-foreign-value"));
}
