use super::*;
use crate::auditor::geo_matrix::CheckStatus;

#[test]
fn test_strict_ip_pinning() {
    // Strict enabled and matches
    let res = evaluate_ip_pinning(Some("185.10.10.10"), true, "185.10.10.10");
    assert_eq!(res.status, CheckStatus::Ok);
    assert_eq!(res.code, "PINNED_IP_MATCH");

    // Strict enabled and mismatches -> Critical
    let res = evaluate_ip_pinning(Some("185.10.10.10"), true, "185.20.20.20");
    assert_eq!(res.status, CheckStatus::Critical);
    assert_eq!(res.code, "PINNED_IP_MISMATCH");

    // Strict disabled and the IP does not match / is not pinned: nothing was checked.
    for pinned in [Some("185.10.10.10"), None] {
        let res = evaluate_ip_pinning(pinned, false, "185.20.20.20");
        assert_eq!(res.status, CheckStatus::Unknown);
        assert!(res.is_not_applicable());
        assert_eq!(res.code, "STRICT_PINNING_DISABLED");
    }

    // Strict disabled, but the IP is the pinned one: a real match.
    let res = evaluate_ip_pinning(Some("185.10.10.10"), false, "185.10.10.10");
    assert_eq!(
        (res.status, res.code.as_str()),
        (CheckStatus::Ok, "PINNED_IP_MATCH")
    );

    // Strict enabled without a pinned IP is a warning, not "not applicable".
    let res = evaluate_ip_pinning(None, true, "185.10.10.10");
    assert_eq!(res.status, CheckStatus::Warning);
}

#[test]
fn first_session_is_not_applicable_and_not_a_pass() {
    let res = evaluate_impossible_travel(&[], "NL", 100_000, ProviderId::Anthropic);
    assert_eq!(res.status, CheckStatus::Unknown);
    assert!(res.is_not_applicable());
    assert_eq!(res.code, "HISTORY_FIRST_SESSION");
}

#[test]
fn travel_ok_text_states_the_compared_fact() {
    let now = 100_000;
    let same = vec![IpHistoryEntry::new("1.1.1.1", "DE", Some(1), now - 600)];
    let r = evaluate_impossible_travel(&same, "DE", now, ProviderId::Openai);
    assert!(r.message.contains("совпадает"), "{}", r.message);
    let old = vec![IpHistoryEntry::new(
        "1.1.1.1",
        "DE",
        Some(1),
        now - 5 * 3600,
    )];
    let r = evaluate_impossible_travel(&old, "US", now, ProviderId::Openai);
    assert!(
        r.message.contains("DE -> US") && r.message.contains("4 ч"),
        "{}",
        r.message
    );
}

#[test]
fn test_impossible_travel_detection() {
    let now = 100000;
    let one_hour_ago = now - 3600;

    let history = vec![IpHistoryEntry::new(
        "1.1.1.1",
        "DE",
        Some(1234),
        one_hour_ago,
    )];

    // Anthropic: DE to US in 1 hour -> Critical
    let res_anthropic = evaluate_impossible_travel(&history, "US", now, ProviderId::Anthropic);
    assert_eq!(res_anthropic.status, CheckStatus::Critical);
    assert!(res_anthropic.message.contains("DE to US"));

    // OpenAI: DE to US in 1 hour -> Warning
    let res_openai = evaluate_impossible_travel(&history, "US", now, ProviderId::Openai);
    assert_eq!(res_openai.status, CheckStatus::Warning);

    // Same country (DE to DE) in 1 hour -> Ok
    let res_same = evaluate_impossible_travel(&history, "DE", now, ProviderId::Anthropic);
    assert_eq!(res_same.status, CheckStatus::Ok);

    // DE to US after 5 hours (>4h) -> Ok
    let five_hours_ago = now - (5 * 3600);
    let history_old = vec![IpHistoryEntry::new(
        "1.1.1.1",
        "DE",
        Some(1234),
        five_hours_ago,
    )];
    let res_old = evaluate_impossible_travel(&history_old, "US", now, ProviderId::Anthropic);
    assert_eq!(res_old.status, CheckStatus::Ok);
}

#[test]
fn route_bound_to_zastava_key_never_mismatches_global_vpn_pin() {
    // Global VPN IP is pinned (145.241.193.245) with strict pinning ON,
    // while Gemini is routed through a France Zastava key (136.244.114.42).
    let (res, is_pinned) = evaluate_ip_pinning_for_route(
        None,
        Some("145.241.193.245"),
        true,
        "136.244.114.42",
        Some("Zastava · Франция"),
    );
    assert_eq!(res.status, CheckStatus::Ok);
    assert_eq!(res.code, "PINNED_BY_ZASTAVA_KEY");
    assert!(res.message.contains("IP закреплён ключом Заставы"));
    assert!(is_pinned);

    // Meanwhile Direct VPN provider (Claude) still validates against global VPN pin.
    let (direct_ok, direct_pinned) = evaluate_ip_pinning_for_route(
        None,
        Some("145.241.193.245"),
        true,
        "145.241.193.245",
        None,
    );
    assert_eq!(
        (direct_ok.status, direct_ok.code.as_str()),
        (CheckStatus::Ok, "PINNED_IP_MATCH")
    );
    assert!(direct_pinned);

    // Explicit per-provider pin on routed key works when matching and warns/criticals on mismatch.
    let (explicit_ok, pinned_ok) = evaluate_ip_pinning_for_route(
        Some("136.244.114.42"),
        Some("145.241.193.245"),
        true,
        "136.244.114.42",
        Some("Zastava · Франция"),
    );
    assert_eq!(
        (explicit_ok.status, explicit_ok.code.as_str()),
        (CheckStatus::Ok, "PINNED_IP_MATCH")
    );
    assert!(pinned_ok);

    let (explicit_bad, pinned_bad) = evaluate_ip_pinning_for_route(
        Some("136.244.114.42"),
        Some("145.241.193.245"),
        true,
        "198.51.100.1",
        Some("Zastava · Франция"),
    );
    assert_eq!(
        (explicit_bad.status, explicit_bad.code.as_str()),
        (CheckStatus::Critical, "PINNED_IP_MISMATCH")
    );
    assert!(!pinned_bad);
}

#[test]
fn impossible_travel_with_pin_allows_pinned_return_and_blocks_unpinned_or_sanctioned() {
    let now = 100_000;
    let history = vec![
        IpHistoryEntry::new("145.241.193.245", "GB", Some(31898), now - 1800),
        IpHistoryEntry::new("185.10.10.10", "NL", Some(1234), now - 900),
        IpHistoryEntry::new("195.20.20.20", "DE", Some(5678), now - 300),
    ];

    // Unpinned return to GB within <4h still triggers IMPOSSIBLE_TRAVEL_CRITICAL / WARNING.
    let unpinned_claude =
        evaluate_impossible_travel_with_pin(&history, "GB", now, ProviderId::Anthropic, false);
    assert_eq!(unpinned_claude.status, CheckStatus::Critical);
    assert_eq!(unpinned_claude.code, "IMPOSSIBLE_TRAVEL_CRITICAL");

    let unpinned_openai =
        evaluate_impossible_travel_with_pin(&history, "GB", now, ProviderId::Openai, false);
    assert_eq!(unpinned_openai.status, CheckStatus::Warning);
    assert_eq!(unpinned_openai.code, "IMPOSSIBLE_TRAVEL_WARNING");

    // Pinned return to non-sanctioned GB within <4h is allowed cleanly.
    for pid in [ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
        let pinned_ok = evaluate_impossible_travel_with_pin(&history, "GB", now, pid, true);
        assert_eq!(pinned_ok.status, CheckStatus::Ok);
        assert_eq!(pinned_ok.code, "TRAVEL_PINNED_RETURN");
    }

    // Sanctioned country (RU) must NEVER be downgraded even if is_pinned == true.
    let pinned_ru =
        evaluate_impossible_travel_with_pin(&history, "RU", now, ProviderId::Anthropic, true);
    assert_eq!(pinned_ru.status, CheckStatus::Critical);
    assert_eq!(pinned_ru.code, "IMPOSSIBLE_TRAVEL_CRITICAL");
}

#[test]
fn apply_pinned_travel_grace_turns_pinned_travel_red_green_without_hiding_real_risks() {
    use crate::auditor::{NetworkTelemetry, OverallStatus, RiskReport};

    let ok = CheckResult::ok("OK", "ok");
    let travel_crit = CheckResult::critical("IMPOSSIBLE_TRAVEL_CRITICAL", "DE -> GB in 5m", None);
    let base = RiskReport {
        provider: ProviderId::Anthropic,
        overall_status: OverallStatus::Red,
        trust_score: 35,
        telemetry: NetworkTelemetry {
            ip: "145.241.193.245".to_string(),
            country_code: "GB".to_string(),
            hostname: None,
            asn: Some(31898),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: 100_000,
        },
        geo_result: ok.clone(),
        pinning_result: ok.clone(),
        travel_result: travel_crit.clone(),
        dnsbl_result: ok.clone(),
        dnsbl_clean_count: "0/0".to_string(),
        asn_result: ok.clone(),
        ipv6_result: ok.clone(),
        timezone_result: ok.clone(),
        ipv6_exit: false,
        checks: vec![ok.clone(), ok.clone(), travel_crit.clone(), ok.clone()],
        unknown_count: 0,
        applicable_count: 4,
        incomplete: false,
    };

    // Unpinned stays Red.
    let mut unpinned = base.clone();
    assert!(!apply_pinned_travel_grace(&mut unpinned, false));
    assert_eq!(unpinned.overall_status, OverallStatus::Red);

    // Pinned on allowed GB with only travel anomaly becomes Green.
    let mut pinned = base.clone();
    assert!(apply_pinned_travel_grace(&mut pinned, true));
    assert_eq!(pinned.overall_status, OverallStatus::Green);
    assert_eq!(pinned.travel_result.code, "TRAVEL_PINNED_RETURN");
    assert_eq!(pinned.checks[2].code, "TRAVEL_PINNED_RETURN");

    // Pinned with another Warning (e.g. timezone) becomes Yellow, not Red.
    let mut with_warn = base.clone();
    with_warn
        .checks
        .push(CheckResult::warning("TIMEZONE_MISMATCH", "tz", None));
    assert!(apply_pinned_travel_grace(&mut with_warn, true));
    assert_eq!(with_warn.overall_status, OverallStatus::Yellow);

    // Pinned with DNSBL critical stays Red.
    let mut with_dnsbl = base;
    with_dnsbl.dnsbl_result = CheckResult::critical("DNSBL_LISTED_CRITICAL", "listed", None);
    assert!(!apply_pinned_travel_grace(&mut with_dnsbl, true));
    assert_eq!(with_dnsbl.overall_status, OverallStatus::Red);
}

#[test]
fn same_country_asn_jump_within_4h_warns_while_same_asn_and_pinned_stay_ok() {
    let now = 200_000;
    let history = vec![IpHistoryEntry::new(
        "185.10.10.10",
        "NL",
        Some(20473),
        now - 1800,
    )];

    // Same country, different ASN + different IP within <4h -> TRAVEL_ASN_JUMP_SAME_COUNTRY (Warning).
    let asn_jump = evaluate_impossible_travel_with_exit(
        &history,
        "NL",
        Some("95.217.1.1"),
        Some(24940),
        now,
        ProviderId::Anthropic,
    );
    assert_eq!(asn_jump.status, CheckStatus::Warning);
    assert_eq!(asn_jump.code, "TRAVEL_ASN_JUMP_SAME_COUNTRY");
    assert!(asn_jump.message.contains("AS20473 -> AS24940"));

    // Same country, SAME ASN DHCP IP change within <4h -> TRAVEL_NORMAL (Ok).
    let same_asn = evaluate_impossible_travel_with_exit(
        &history,
        "NL",
        Some("185.10.10.99"),
        Some(20473),
        now,
        ProviderId::Anthropic,
    );
    assert_eq!(same_asn.status, CheckStatus::Ok);
    assert_eq!(same_asn.code, "TRAVEL_NORMAL");

    // Same country, different ASN after >= 4h -> TRAVEL_NORMAL (Ok).
    let old_history = vec![IpHistoryEntry::new(
        "185.10.10.10",
        "NL",
        Some(20473),
        now - IMPOSSIBLE_TRAVEL_WINDOW_SECS,
    )];
    let after_4h = evaluate_impossible_travel_with_exit(
        &old_history,
        "NL",
        Some("95.217.1.1"),
        Some(24940),
        now,
        ProviderId::Anthropic,
    );
    assert_eq!(after_4h.status, CheckStatus::Ok);
    assert_eq!(after_4h.code, "TRAVEL_NORMAL");

    // Pinned return within <4h across ASNs in same non-sanctioned country -> TRAVEL_PINNED_RETURN (Ok).
    let pinned_return = evaluate_impossible_travel_with_pin_and_exit(
        &history,
        "NL",
        Some("95.217.1.1"),
        Some(24940),
        now,
        ProviderId::Anthropic,
        true,
    );
    assert_eq!(pinned_return.status, CheckStatus::Ok);
    assert_eq!(pinned_return.code, "TRAVEL_PINNED_RETURN");
}
