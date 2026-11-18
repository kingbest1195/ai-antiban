use super::*;
use crate::auditor::geo_matrix::CheckStatus;
use crate::auditor::seams::fakes::{FakeProbe, FakeSystem};

const URL: &str = "https://probe.invalid/cdn-cgi/trace";
const LIMIT: Duration = Duration::from_millis(50);

fn v6_host() -> FakeSystem {
    FakeSystem {
        global_ipv6: Some(true),
        ..FakeSystem::healthy()
    }
}

async fn ipv6(
    probe: &FakeProbe,
    sys: &FakeSystem,
    country: &str,
    blocked: &[&str],
) -> CheckResult {
    let blocked: Vec<String> = blocked.iter().map(|s| s.to_string()).collect();
    check_ipv6_leak_with(probe, sys, URL, LIMIT, country, &blocked).await
}

#[test]
fn test_russian_timezone_detection() {
    use crate::auditor::os_env::is_russian_or_belarusian_timezone;
    assert!(is_russian_or_belarusian_timezone("Europe/Moscow"));
    assert!(is_russian_or_belarusian_timezone("Asia/Vladivostok"));
    assert!(is_russian_or_belarusian_timezone("Europe/Minsk"));
    assert!(!is_russian_or_belarusian_timezone("Europe/Amsterdam"));
    assert!(!is_russian_or_belarusian_timezone("America/New_York"));
}

// (1) a host with IPv6 whose IPv6 probe times out (e.g. blocked by VPN kill-switch)
#[tokio::test]
async fn ipv6_timeout_on_a_host_with_ipv6_is_ok_when_blocked_by_vpn() {
    let probe = FakeProbe::new(HttpProbeOutcome::Timeout);
    let r = ipv6(&probe, &v6_host(), "NL", &[]).await;
    assert_eq!(r.status, CheckStatus::Ok);
    assert_eq!(r.code, "IPV6_BLOCKED_OR_TIMEOUT");
    assert_eq!(probe.calls(), 1);
}

// (2) a host without global IPv6: nothing to leak, the probe is not even needed
#[tokio::test]
async fn ipv6_not_configured_is_ok_even_if_the_probe_would_time_out() {
    let probe = FakeProbe::new(HttpProbeOutcome::Timeout);
    let sys = FakeSystem {
        global_ipv6: Some(false),
        ..FakeSystem::healthy()
    };
    let r = ipv6(&probe, &sys, "NL", &[]).await;
    assert_eq!(r.status, CheckStatus::Ok);
    assert_eq!(r.code, "IPV6_NOT_CONFIGURED");
    assert!(r.message.contains("IPv6 не настроен"));
    assert_eq!(probe.calls(), 0);
}

// (3) HTTP 500 / 403 / HTML without loc=
#[tokio::test]
async fn ipv6_bad_status_or_no_loc_is_unknown_empty_response() {
    for (status, body) in [
        (500, "oops"),
        (403, "<html>blocked</html>"),
        (200, "<html>portal</html>"),
        (200, "ip=1.2.3.4"),
    ] {
        let r = ipv6(&FakeProbe::body(status, body), &v6_host(), "NL", &[]).await;
        assert_eq!(r.status, CheckStatus::Unknown, "{status} {body}");
        assert_eq!(
            r.reason,
            Some(UnknownReason::EmptyResponse),
            "{status} {body}"
        );
    }
}

// (4) the answer is the blocked country
#[tokio::test]
async fn ipv6_from_a_blocked_country_is_critical() {
    let r = ipv6(
        &FakeProbe::body(200, "ip=2a00::1\nloc=RU\n"),
        &v6_host(),
        "NL",
        &["RU"],
    )
    .await;
    assert_eq!(r.status, CheckStatus::Critical);
    assert_eq!(r.code, "IPV6_LEAK_SANCTIONED_CRITICAL");
}

// (5) a different country than IPv4 is a warning, the same one is ok
#[tokio::test]
async fn ipv6_country_is_compared_with_ipv4() {
    let probe = FakeProbe::body(200, "loc=DE\n");
    let r = ipv6(&probe, &v6_host(), "NL", &[]).await;
    assert_eq!(r.status, CheckStatus::Warning);
    let r = ipv6(&probe, &v6_host(), "de", &[]).await;
    assert_eq!(r.status, CheckStatus::Ok);
    assert!(r.message.contains("DE"));
    // Nothing to compare with: not a match.
    let r = ipv6(&probe, &v6_host(), "", &[]).await;
    assert_eq!(r.status, CheckStatus::Unknown);
    let r = ipv6(&FakeProbe::body(200, "loc=XX\n"), &v6_host(), "NL", &[]).await;
    assert_eq!(r.status, CheckStatus::Unknown);
}

// (6) client/read errors remain unknown; ConnectFailed means IPv6 cannot connect (safe)
#[tokio::test]
async fn ipv6_probe_errors_are_unknown() {
    let r = ipv6(
        &FakeProbe::new(HttpProbeOutcome::ClientError),
        &v6_host(),
        "NL",
        &[],
    )
    .await;
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::InternalError))
    );
    let r = ipv6(
        &FakeProbe::new(HttpProbeOutcome::ReadFailed),
        &v6_host(),
        "NL",
        &[],
    )
    .await;
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::NetworkError))
    );
    let r = ipv6(
        &FakeProbe::new(HttpProbeOutcome::ConnectFailed),
        &v6_host(),
        "NL",
        &[],
    )
    .await;
    assert_eq!(r.status, CheckStatus::Ok);
    assert_eq!(r.code, "IPV6_UNREACHABLE_SAFE");
}

// The host could not tell whether it has IPv6: the probe decides (leak warns, timeout/blocked is Ok).
#[tokio::test]
async fn ipv6_undetermined_host_falls_back_to_the_probe() {
    let sys = FakeSystem {
        global_ipv6: None,
        ..FakeSystem::healthy()
    };
    let timeout_probe = FakeProbe::new(HttpProbeOutcome::Timeout);
    assert_eq!(
        ipv6(&timeout_probe, &sys, "NL", &[]).await.status,
        CheckStatus::Ok
    );
    assert_eq!(timeout_probe.calls(), 1);

    let leak_probe = FakeProbe::body(200, "loc=DE\n");
    assert_eq!(
        ipv6(&leak_probe, &sys, "NL", &[]).await.status,
        CheckStatus::Warning
    );
    assert_eq!(leak_probe.calls(), 1);
}

#[tokio::test]
async fn ipv6_split_tunnel_mode_returns_informational_ok() {
    let probe = FakeProbe::body(200, "ip=2a00::1\nloc=RU\n");
    let r = check_ipv6_leak_with_split(
        &probe,
        &v6_host(),
        "http://v6.test",
        Duration::from_millis(10),
        "NL",
        &["RU".to_string()],
        true,
    )
    .await;
    assert_eq!(r.status, CheckStatus::Ok);
    assert_eq!(r.code, "IPV6_SPLIT_TUNNEL_INFO");
    assert_eq!(probe.calls(), 0);
}

fn kws() -> Vec<String> {
    ["Rostelecom", "MTS", "VK", "Yandex"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[test]
fn dns_unreadable_or_empty_is_unknown() {
    let offline = FakeSystem::offline();
    let r = check_dns_leak_with(&offline, "NL", &kws());
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::InternalError))
    );
    let unsupported = FakeSystem {
        dns_listing: Err(SystemReadError::Unsupported),
        ..FakeSystem::healthy()
    };
    let r = check_dns_leak_with(&unsupported, "NL", &kws());
    assert_eq!(r.reason, Some(UnknownReason::UnsupportedOs));
    // A command that ran but printed no resolver address (also what a dry-run stub gives).
    let empty = FakeSystem {
        dns_listing: Ok("DNS configuration\n".into()),
        ..FakeSystem::healthy()
    };
    let r = check_dns_leak_with(&empty, "NL", &kws());
    assert_eq!(r.reason, Some(UnknownReason::EmptyResponse));
}

#[test]
fn dns_listing_is_matched_on_dns_lines_only() {
    // Windows `ipconfig /all`: the provider shows in the DNS suffix line.
    let win = "Ethernet adapter Ethernet:\n   Description . . . : Realtek PCIe\n   Connection-specific DNS Suffix  . : mts.ru\n   DNS Servers . . . . . . . . . . . : 192.168.1.1\n";
    let r = evaluate_dns_listing(win, "NL", &kws());
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );
    // The same keyword outside of DNS lines (an adapter description) is not a finding.
    let desc = "Description . . . : Gigabit MTS Adapter\n   DNS Servers . . . : 1.1.1.1\n";
    assert_eq!(
        evaluate_dns_listing(desc, "NL", &kws()).status,
        CheckStatus::Ok
    );
    // macOS `scutil --dns`.
    let mac = "resolver #1\n  search domain[0] : beeline.local\n  nameserver[0] : 8.8.8.8\n";
    assert_eq!(
        evaluate_dns_listing(mac, "NL", &["Beeline".to_string()]).status,
        CheckStatus::Warning
    );
}

#[test]
fn yandex_dns_is_an_address_match_not_a_substring() {
    let yandex = "resolver #1\n  nameserver[0] : 77.88.8.8\n";
    assert_eq!(
        evaluate_dns_listing(yandex, "NL", &[]).code,
        "DNS_YANDEX_LEAK"
    );
    // Exit in Russia: not a leak of this kind.
    assert_eq!(
        evaluate_dns_listing(yandex, "RU", &[]).status,
        CheckStatus::Ok
    );
    // 177.88.8.8 only contains the digits.
    let other = "resolver #1\n  nameserver[0] : 177.88.8.8\n";
    assert_eq!(
        evaluate_dns_listing(other, "NL", &[]).status,
        CheckStatus::Ok
    );
}

#[test]
fn dns_ok_text_states_what_was_checked() {
    let r = evaluate_dns_listing("resolver #1\n  nameserver[0] : 1.1.1.1\n", "NL", &kws());
    assert_eq!(r.status, CheckStatus::Ok);
    assert!(
        r.message.contains("список настроенных резолверов"),
        "{}",
        r.message
    );
}

// ---- the resolver that really sees the requests ----

use crate::auditor::probes::whoami::Unmeasured;

fn located(ip: &str, cc: &str) -> ResolverView {
    ResolverView::Located {
        ip: ip.parse().unwrap(),
        country: cc.into(),
        public_service: None,
        sources: vec![],
    }
}

fn unmeasured(reason: UnknownReason) -> ResolverView {
    ResolverView::Unmeasured(Unmeasured {
        code: "DNS_WHOAMI_TIMEOUT",
        reason,
        detail: "источники молчат".into(),
        sources: vec![],
    })
}

fn config_ok() -> CheckResult {
    evaluate_dns_listing("resolver #1\n  nameserver[0] : 1.1.1.1\n", "NL", &kws())
}

fn config_domestic() -> CheckResult {
    evaluate_dns_listing(
        "resolver #1\n  search domain[0] : mts.ru\n  nameserver[0] : 192.168.1.1\n",
        "NL",
        &kws(),
    )
}

#[test]
fn resolver_in_the_exit_country_is_ok_with_source_and_caveat() {
    let r = evaluate_dns_resolver(config_ok(), &located("9.9.9.9", "NL"), "NL");
    assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "DNS_CLEAN"));
    assert_eq!(r.measured_via.as_deref(), Some("whoami:akamai+google"));
    assert!(
        r.message.contains("9.9.9.9") && r.message.contains("ECS"),
        "{}",
        r.message
    );
    assert!(
        r.message.contains("справочно"),
        "the OS list is reference: {}",
        r.message
    );
}

#[test]
fn resolver_in_russia_is_a_warning_like_the_other_domestic_findings() {
    let r = evaluate_dns_resolver(config_ok(), &located("77.88.8.8", "RU"), "NL");
    // The same severity and code as the configuration finding (never harsher).
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );
    assert!(
        r.message.contains("РФ") && r.message.contains("NL"),
        "{}",
        r.message
    );
    // The real resolver speaks even when the OS list looks clean; an unknown exit does too.
    assert_eq!(
        evaluate_dns_resolver(config_ok(), &located("77.88.8.8", "RU"), "").status,
        CheckStatus::Warning
    );
    // A Russian exit with a Russian resolver is consistent.
    assert_eq!(
        evaluate_dns_resolver(config_ok(), &located("77.88.8.8", "RU"), "RU").status,
        CheckStatus::Ok
    );
}

#[test]
fn resolver_in_another_country_than_the_exit_is_a_warning() {
    let r = evaluate_dns_resolver(config_ok(), &located("8.8.8.8", "US"), "NL");
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "DNS_RESOLVER_MISMATCH")
    );
    assert!(r.message.contains("US") && r.message.contains("NL"));
}

#[test]
fn a_finding_of_the_os_list_is_not_loosened_by_a_good_real_resolver() {
    let r = evaluate_dns_resolver(config_domestic(), &located("9.9.9.9", "NL"), "NL");
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );
    assert!(r.message.contains("9.9.9.9"));
    // ... and stays when the resolver could not be measured at all.
    let r = evaluate_dns_resolver(config_domestic(), &unmeasured(UnknownReason::Timeout), "NL");
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );
    assert!(r.message.contains("не удалось"));
}

#[test]
fn unmeasured_resolver_is_unknown_not_ok_even_with_a_clean_os_list() {
    for reason in [
        UnknownReason::Timeout,
        UnknownReason::SourceRefused,
        UnknownReason::NoData,
    ] {
        let r = evaluate_dns_resolver(config_ok(), &unmeasured(reason), "NL");
        assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(reason)));
        assert_eq!(r.code, "DNS_WHOAMI_TIMEOUT");
        assert!(
            r.message.contains("Справочно")
                && r.message.contains("нет резолверов провайдеров РФ")
        );
    }
    // An unreadable OS list does not matter when the real resolver is known.
    let unreadable = check_dns_leak_with(&FakeSystem::offline(), "NL", &kws());
    assert_eq!(
        evaluate_dns_resolver(unreadable, &located("9.9.9.9", "NL"), "NL").status,
        CheckStatus::Ok
    );
}

fn public(ip: &str, cc: &str, service: &'static str) -> ResolverView {
    ResolverView::Located {
        ip: ip.parse().unwrap(),
        country: cc.into(),
        public_service: Some(service),
        sources: vec![],
    }
}

#[test]
fn public_resolver_is_ok_without_comparing_its_country() {
    for (ip, cc, svc) in [
        ("74.125.40.10", "US", "Google Public DNS"),
        ("162.158.1.1", "AU", "Cloudflare"),
    ] {
        let r = evaluate_dns_resolver(config_ok(), &public(ip, cc, svc), "NL");
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Ok, "DNS_PUBLIC_RESOLVER"),
            "{svc}"
        );
        assert!(
            r.message.contains(svc) && r.message.contains("anycast"),
            "{}",
            r.message
        );
        assert!(r.message.contains("ECS") && r.message.contains("DNS-over-HTTPS"));
        assert_eq!(r.measured_via.as_deref(), Some("whoami:akamai+google"));
    }
    // An ordinary provider resolver in another country still warns, a Russian one too.
    assert_eq!(
        evaluate_dns_resolver(config_ok(), &located("203.0.113.53", "DE"), "NL").code,
        "DNS_RESOLVER_MISMATCH"
    );
    assert_eq!(
        evaluate_dns_resolver(config_ok(), &located("77.88.8.8", "RU"), "NL").code,
        "DNS_DOMESTIC_WARNING"
    );
}

#[test]
fn findings_stay_with_a_public_resolver() {
    // A domestic provider in the OS list is still a Warning.
    let r = evaluate_dns_resolver(
        config_domestic(),
        &public("74.125.40.10", "US", "Google Public DNS"),
        "NL",
    );
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );
    // A public service seen in Russia is still reported as a resolver in Russia.
    let r = evaluate_dns_resolver(config_ok(), &public("1.1.1.1", "RU", "Cloudflare"), "NL");
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );
}

#[tokio::test]
async fn fake_ip_tun_dns_and_zastava_key_route_isolation_are_ok() {
    use crate::auditor::probes::whoami::{SourceReading, combine_sources};
    use crate::auditor::seams::fakes::FakeProbe;

    let fake_ip_view = ResolverView::Unmeasured(
        combine_sources(
            &SourceReading::Special("198.18.0.10".parse().unwrap()),
            &SourceReading::Special("198.18.0.11".parse().unwrap()),
        )
        .unwrap_err(),
    );

    let fake_ok = evaluate_dns_resolver_for_route(config_ok(), &fake_ip_view, "FR", false);
    assert_eq!(
        (fake_ok.status, fake_ok.code.as_str()),
        (CheckStatus::Ok, "DNS_TUN_FAKE_IP_SAFE")
    );

    // Domestic ISP resolver finding overrides Fake-IP Ok.
    let fake_ru =
        evaluate_dns_resolver_for_route(config_domestic(), &fake_ip_view, "FR", false);
    assert_eq!(
        (fake_ru.status, fake_ru.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );

    // Unknown OS DNS list keeps Fake-IP Unknown rather than assuming safe.
    let unknown_cfg = check_dns_leak_with(&FakeSystem::offline(), "FR", &kws());
    let fake_unknown = evaluate_dns_resolver_for_route(unknown_cfg, &fake_ip_view, "FR", false);
    assert_eq!(fake_unknown.status, CheckStatus::Unknown);

    // Routed Zastava key in FR with foreign VPN resolver in GB -> Ok("DNS_KEY_REMOTE_RESOLVE").
    let r_routed =
        evaluate_dns_resolver_for_route(config_ok(), &located("81.2.69.142", "GB"), "FR", true);
    assert_eq!(
        (r_routed.status, r_routed.code.as_str()),
        (CheckStatus::Ok, "DNS_KEY_REMOTE_RESOLVE")
    );

    // IPv6 exit in GB while Zastava key is in FR -> Ok("IPV6_KEY_TCP_ISOLATED"),
    // whereas RU IPv6 remains Critical even with Zastava key.
    let gb_probe = FakeProbe::body(200, "fl=1\nloc=GB\n");
    let sys_v6 = FakeSystem {
        global_ipv6: Some(true),
        ..FakeSystem::healthy()
    };
    let v6_routed = check_ipv6_leak_with_route(
        &gb_probe,
        &sys_v6,
        "https://example.invalid/cdn-cgi/trace",
        Duration::from_secs(1),
        "FR",
        &["RU".into(), "BY".into()],
        false,
        true,
    )
    .await;
    assert_eq!(
        (v6_routed.status, v6_routed.code.as_str()),
        (CheckStatus::Ok, "IPV6_KEY_TCP_ISOLATED")
    );

    let ru_probe = FakeProbe::body(200, "fl=1\nloc=RU\n");
    let v6_ru = check_ipv6_leak_with_route(
        &ru_probe,
        &sys_v6,
        "https://example.invalid/cdn-cgi/trace",
        Duration::from_secs(1),
        "FR",
        &["RU".into(), "BY".into()],
        false,
        true,
    )
    .await;
    assert_eq!(
        (v6_ru.status, v6_ru.code.as_str()),
        (CheckStatus::Critical, "IPV6_LEAK_SANCTIONED_CRITICAL")
    );
}
