use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::journal::{Journal, Outcome, recover_with};
use crate::sysproxy::macos::{HEAL_MAX_REWRITES, HEAL_WINDOW, HealGuard};
use crate::sysproxy::platform::{FakePlatform, PlatOp};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const DIR: &str = "/data";
const PAC: &str = "http://127.0.0.1:8899/proxy.pac";

fn open(fs: &FakeFs) -> Journal {
    Journal::open(Arc::new(fs.clone()), Path::new(DIR)).unwrap()
}

#[test]
fn enable_and_restore_return_exact_types_and_absence() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
    p.seed_inet(PROXY_SERVER, RegValue::sz("corp.example:3128"));
    let mut j = open(&fs);
    enable_inet(&mut j, &p, PAC).unwrap();
    assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz(PAC)));
    assert_eq!(p.inet_of(PROXY_ENABLE), Some(RegValue::dword(0)));
    j.restore_all(&p);
    assert_eq!(
        p.inet_of(AUTO_CONFIG_URL),
        None,
        "absent is deleted, not blanked"
    );
    assert_eq!(p.inet_of(PROXY_ENABLE), Some(RegValue::dword(1)));
    assert_eq!(
        p.inet_of(PROXY_SERVER),
        Some(RegValue::sz("corp.example:3128")),
        "ProxyServer is never rewritten"
    );
}

#[test]
fn third_party_pac_url_with_expand_type_comes_back_exactly() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_inet(AUTO_CONFIG_URL, RegValue::expand_sz("%CORP%/p.pac"));
    let mut j = open(&fs);
    enable_inet(&mut j, &p, PAC).unwrap();
    j.restore_all(&p);
    assert_eq!(
        p.inet_of(AUTO_CONFIG_URL),
        Some(RegValue::expand_sz("%CORP%/p.pac"))
    );
}

#[test]
fn proxy_enable_that_is_already_off_gets_no_record() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let mut j = open(&fs);
    enable_inet(&mut j, &p, PAC).unwrap();
    assert!(j.entry(&inet(PROXY_ENABLE)).is_none());
    assert_eq!(
        p.inet_of(PROXY_ENABLE),
        None,
        "no value is not turned into 0"
    );
    p.seed_inet(PROXY_ENABLE, RegValue::dword(0));
    enable_inet(&mut j, &p, PAC).unwrap();
    assert!(j.entry(&inet(PROXY_ENABLE)).is_none());
}

#[test]
fn external_pac_change_does_not_switch_off_a_foreign_proxy_enable() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
    let mut j = open(&fs);
    enable_inet(&mut j, &p, PAC).unwrap();
    p.seed_inet(AUTO_CONFIG_URL, RegValue::sz("http://mine/p.pac"));
    p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
    let rep = j.restore_all(&p);
    let pac_item = rep
        .items
        .iter()
        .find(|i| i.resource == "inet:AutoConfigURL")
        .unwrap();
    assert_eq!(pac_item.outcome, Outcome::ExternalChange);
    assert_eq!(
        p.inet_of(AUTO_CONFIG_URL),
        Some(RegValue::sz("http://mine/p.pac"))
    );
    assert_eq!(
        p.inet_of(PROXY_ENABLE),
        Some(RegValue::dword(1)),
        "only our own 0 is ever reverted, the foreign 1 stays"
    );
}

#[test]
fn the_two_values_are_independent() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
    let mut j = open(&fs);
    enable_inet(&mut j, &p, PAC).unwrap();
    p.seed_inet(PROXY_ENABLE, RegValue::dword(2));
    let rep = j.restore_all(&p);
    assert_eq!(rep.restored(), 1);
    assert_eq!(rep.external(), 1);
    assert_eq!(p.inet_of(AUTO_CONFIG_URL), None);
}

#[test]
fn notification_failure_keeps_the_record_and_the_restore_retries_it() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let mut j = open(&fs);
    enable_inet(&mut j, &p, PAC).unwrap();
    p.fail_next(PlatOp::NotifyInet);
    let rep = j.restore_all(&p);
    assert_eq!(rep.failed(), 1);
    assert_eq!(p.inet_of(AUTO_CONFIG_URL), None);
    assert!(!j.is_empty());
    p.clear_calls();
    let rep = j.restore_all(&p);
    assert_eq!(rep.failed(), 0);
    assert!(j.is_empty());
    assert!(
        p.calls()
            .iter()
            .any(|c| c.starts_with("notify_inet_refresh"))
    );
}

#[test]
fn notification_failure_while_enabling_keeps_the_record_and_is_repeated() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let mut j = open(&fs);
    p.fail_next(PlatOp::NotifyInet);
    enable_inet(&mut j, &p, PAC).unwrap();
    assert!(j.entry(&inet(AUTO_CONFIG_URL)).unwrap().notify_pending);
    p.clear_calls();
    let r = enable_inet(&mut j, &p, PAC).unwrap();
    assert!(!r.changed);
    assert!(!j.entry(&inet(AUTO_CONFIG_URL)).unwrap().notify_pending);
    assert!(
        p.calls()
            .iter()
            .any(|c| c.starts_with("notify_inet_refresh"))
    );
}

#[test]
fn crash_between_intent_and_write_loses_nothing() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    p.seed_inet(AUTO_CONFIG_URL, RegValue::sz("http://corp/p.pac"));
    {
        let mut j = open(&fs);
        p.fail_next(PlatOp::SetInet);
        assert!(enable_inet(&mut j, &p, PAC).is_err());
    }
    recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
    assert_eq!(
        p.inet_of(AUTO_CONFIG_URL),
        Some(RegValue::sz("http://corp/p.pac"))
    );
}

#[test]
fn explicit_proxy_is_detected_for_the_chain_but_never_rewritten() {
    let p = FakePlatform::new();
    p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
    p.seed_inet(
        PROXY_SERVER,
        RegValue::sz("http=127.0.0.1:2080;https=127.0.0.1:2080"),
    );
    assert_eq!(
        detect_chained(&p, Some(8899)).unwrap().as_deref(),
        Some("http://127.0.0.1:2080")
    );
    p.seed_inet(PROXY_SERVER, RegValue::sz("socks=127.0.0.1:10808"));
    assert_eq!(
        detect_chained(&p, Some(8899)).unwrap().as_deref(),
        Some("socks5://127.0.0.1:10808")
    );
    p.seed_inet(PROXY_OVERRIDE, RegValue::sz("localhost;*;<local>"));
    assert_eq!(
        detect_chained(&p, Some(8899)).unwrap(),
        None,
        "catch-all ProxyOverride=* disables chaining"
    );
    p.seed_inet(PROXY_OVERRIDE, RegValue::sz("localhost;127.*;<local>"));
    p.seed_inet(PROXY_SERVER, RegValue::sz("127.0.0.1:8899"));
    assert_eq!(
        detect_chained(&p, Some(8899)).unwrap(),
        None,
        "our own gateway is no upstream"
    );
    p.seed_inet(PROXY_ENABLE, RegValue::dword(0));
    assert_eq!(detect_chained(&p, None).unwrap(), None);

    p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
    p.seed_inet(PROXY_SERVER, RegValue::expand_sz("127.0.0.1:10808"));
    assert_eq!(
        detect_chained(&p, Some(8899)).unwrap().as_deref(),
        Some("http://127.0.0.1:10808")
    );
}

#[test]
fn vpn_override_on_windows_rechains_and_heals_pac_and_proxy_enable() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let expected_chained = format!("http://{proxy_addr}");

    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let mut j = open(&fs);
    enable_inet(&mut j, &p, PAC).unwrap();
    assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz(PAC)));
    p.clear_calls();

    p.seed_inet(AUTO_CONFIG_URL, RegValue::sz(""));
    p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
    p.seed_inet(PROXY_SERVER, RegValue::sz(&proxy_addr));
    assert_eq!(
        detect_chained(&p, Some(8899)).unwrap().as_deref(),
        Some(expected_chained.as_str())
    );

    let rep = enable_inet(&mut j, &p, PAC).unwrap();
    assert!(rep.changed);
    assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz(PAC)));
    assert_eq!(p.inet_of(PROXY_ENABLE), Some(RegValue::dword(0)));
    assert!(
        p.calls()
            .iter()
            .any(|c| c.starts_with("notify_inet_refresh"))
    );

    j.restore_all(&p);
    assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz("")));
    assert_eq!(p.inet_of(PROXY_ENABLE), Some(RegValue::dword(1)));
    assert_eq!(p.inet_of(PROXY_SERVER), Some(RegValue::sz(&proxy_addr)));
}

#[test]
fn windows_heal_guard_breaks_ping_pong_and_auto_resets_after_cooldown() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let mut j = open(&fs);
    let guard = HealGuard::new();
    let t0 = Instant::now();
    enable_inet_with_heal(&mut j, &p, PAC, Some((&guard, t0))).unwrap();

    // iNCY/v2rayN keeps overwriting AutoConfigURL and setting ProxyEnable=1.
    let mut healed = 0;
    for i in 1..=6u64 {
        p.seed_inet(AUTO_CONFIG_URL, RegValue::sz(""));
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        p.seed_inet(PROXY_SERVER, RegValue::sz("socks=127.0.0.1:10808"));
        let rep = enable_inet_with_heal(
            &mut j,
            &p,
            PAC,
            Some((&guard, t0 + Duration::from_secs(5 * i))),
        )
        .unwrap();
        if rep.changed {
            healed += 1;
        }
    }
    assert_eq!(healed, HEAL_MAX_REWRITES);
    assert!(guard.is_suspended_at("wininet", t0 + Duration::from_secs(35)));
    assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz("")));

    // After cooldown expires, self-heal resumes cleanly.
    let after = t0 + Duration::from_secs(35) + HEAL_WINDOW + Duration::from_secs(1);
    let rep = enable_inet_with_heal(&mut j, &p, PAC, Some((&guard, after))).unwrap();
    assert!(rep.changed);
    assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz(PAC)));
}

#[test]
fn resolve_chained_target_clears_stale_when_no_upstream_exists() {
    let (fs, p) = (FakeFs::new(), FakePlatform::new());
    let mut j = open(&fs);
    assert_eq!(resolve_chained_target(&j, &p, Some(8899)).unwrap(), None);

    p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
    p.seed_inet(PROXY_SERVER, RegValue::sz("socks=127.0.0.1:10808"));
    enable_inet(&mut j, &p, PAC).unwrap();
    assert_eq!(
        resolve_chained_target(&j, &p, Some(8899))
            .unwrap()
            .as_deref(),
        Some("socks5://127.0.0.1:10808")
    );

    // VPN exits and blanks ProxyServer -> chained target clears to None.
    p.seed_inet(PROXY_SERVER, RegValue::sz(""));
    assert_eq!(resolve_chained_target(&j, &p, Some(8899)).unwrap(), None);
}

fn unused_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[test]
fn dead_loopback_proxy_server_baseline_restores_proxy_enable_zero_and_records_diag() {
    let dead_port = unused_loopback_port();
    let formats = [
        format!("127.0.0.1:{dead_port}"),
        format!("localhost:{dead_port}"),
        format!("[::1]:{dead_port}"),
        format!("http://127.0.0.1:{dead_port}"),
        format!("https://127.0.0.1:{dead_port}"),
        format!("socks=127.0.0.1:{dead_port}"),
        format!("http=127.0.0.1:{dead_port};https=localhost:{dead_port}"),
    ];
    for proxy_server in formats {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        p.seed_inet(PROXY_SERVER, RegValue::sz(&proxy_server));
        let mut j = open(&fs);
        enable_inet(&mut j, &p, PAC).unwrap();
        assert_eq!(p.inet_of(PROXY_ENABLE), Some(RegValue::dword(0)));
        p.clear_calls();

        let rep = j.restore_all(&p);
        assert!(!rep.has_failures(), "{proxy_server}: {:?}", rep.items);
        assert!(j.is_empty(), "{proxy_server}");
        assert_eq!(
            p.inet_of(PROXY_ENABLE),
            Some(RegValue::dword(0)),
            "dead loopback {proxy_server} must not strand WinINet on ProxyEnable=1"
        );
        assert!(
            p.calls().iter().any(|c| c == "notify_inet_refresh"),
            "WinINet refresh must be called for {proxy_server}"
        );
    }
    assert!(
        crate::diagnostics::dump()
            .iter()
            .any(|line| line.contains("[sysproxy:windows]") && line.contains("ProxyEnable=1")),
        "diagnostic record must be emitted when suppressing dead loopback ProxyEnable=1"
    );
}

#[test]
fn reachable_loopback_and_non_loopback_proxy_server_preserves_proxy_enable_one() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let live_port = listener.local_addr().unwrap().port();
    let dead_port = unused_loopback_port();

    let preserved_cases = [
        format!("127.0.0.1:{live_port}"),
        format!("socks=localhost:{live_port}"),
        format!("http=127.0.0.1:{live_port};https=127.0.0.1:{live_port}"),
        "10.20.30.40:3128".to_string(),
        "corp.example:3128".to_string(),
        format!("http=127.0.0.1:{dead_port};https=corp.example:3128"),
    ];

    for proxy_server in preserved_cases {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        p.seed_inet(PROXY_SERVER, RegValue::sz(&proxy_server));
        let mut j = open(&fs);
        enable_inet(&mut j, &p, PAC).unwrap();
        p.clear_calls();

        let rep = j.restore_all(&p);
        assert!(!rep.has_failures(), "{proxy_server}: {:?}", rep.items);
        assert_eq!(
            p.inet_of(PROXY_ENABLE),
            Some(RegValue::dword(1)),
            "reachable or non-loopback {proxy_server} must preserve ProxyEnable=1"
        );
        assert!(p.calls().iter().any(|c| c == "notify_inet_refresh"));
    }
}
