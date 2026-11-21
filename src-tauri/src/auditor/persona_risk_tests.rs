use super::*;
use crate::auditor::geo_matrix::{CheckResult, ProviderId};
use crate::auditor::network::NetworkTelemetry;

fn clean_report(ip: &str, ip_type: IpType, asn_code: &str, pinned_code: &str) -> RiskReport {
    let ok = CheckResult::ok("OK", "ok");
    RiskReport {
        provider: ProviderId::Anthropic,
        overall_status: crate::auditor::OverallStatus::Green,
        trust_score: 100,
        telemetry: NetworkTelemetry {
            ip: ip.to_string(),
            country_code: "US".to_string(),
            hostname: None,
            isp: Some("Example".to_string()),
            org: Some("Example".to_string()),
            asn: Some(15169),
            timezone: Some("America/New_York".to_string()),
            resolved_at: 1_700_000_000,
        },
        geo_result: ok.clone(),
        pinning_result: CheckResult::ok(pinned_code, "pinned"),
        travel_result: CheckResult::ok("TRAVEL_NORMAL", "ok"),
        dnsbl_result: ok.clone(),
        dnsbl_clean_count: "0/5".to_string(),
        asn_result: CheckResult::ok(asn_code, "asn").with_ip_type(ip_type),
        ipv6_result: CheckResult::ok("IPV6_ENCAPSULATED", "ok"),
        timezone_result: CheckResult::ok("TIMEZONE_MATCH", "ok"),
        ipv6_exit: false,
        checks: vec![ok],
        unknown_count: 0,
        applicable_count: 14,
        incomplete: false,
        gateway_latency_ms: None,
    }
}

#[test]
fn clean_setup_yields_low_risk_zero() {
    let state = AppStateData::default();
    let report = clean_report(
        "198.51.100.1",
        IpType::Residential,
        "IP_TYPE_RESIDENTIAL",
        "PINNED_IP_MATCH",
    );
    let res = evaluate_persona_risk(&PersonaRiskInput {
        state_data: &state,
        risk_report: Some(&report),
        sysproxy_active: true,
        os_tz: Some("America/New_York"),
        has_personal_browser_traces: false,
        has_desktop_traces: false,
        now_secs: 1_700_000_100,
    });
    assert_eq!(res.score, 0);
    assert_eq!(res.level, PersonaRiskLevel::Low);
}

#[test]
fn hosting_unpinned_plus_unprotected_browser_is_medium() {
    let state = AppStateData::default();
    let report = clean_report(
        "203.0.113.5",
        IpType::Hosting,
        "IP_TYPE_HOSTING",
        "STRICT_PINNING_DISABLED",
    );
    let res = evaluate_persona_risk(&PersonaRiskInput {
        state_data: &state,
        risk_report: Some(&report),
        sysproxy_active: false,
        os_tz: Some("America/New_York"),
        has_personal_browser_traces: true,
        has_desktop_traces: false,
        now_secs: 1_700_000_100,
    });
    // Hosting unpinned (+15) + unprotected/traces (+15) = 30 -> Medium
    assert_eq!(res.score, 30);
    assert_eq!(res.level, PersonaRiskLevel::Medium);
}

#[test]
fn tor_or_leaks_and_cooldown_accumulate_and_clamp_at_100() {
    let mut state = AppStateData {
        ip_change_cooldown_until: Some(1_700_010_000),
        ..AppStateData::default()
    };
    state.persona_self_check.bought_or_grey_account = true;
    state.persona_self_check.reseller_payment_used = true;

    let mut report = clean_report(
        "198.51.100.9",
        IpType::Tor,
        "IP_TYPE_TOR",
        "STRICT_PINNING_DISABLED",
    );
    report.ipv6_result = CheckResult::warning("IPV6_LEAK_MISMATCH", "leak", None);
    report.timezone_result = CheckResult::warning("TIMEZONE_LEAK_RU", "ru tz", None);

    let res = evaluate_persona_risk(&PersonaRiskInput {
        state_data: &state,
        risk_report: Some(&report),
        sysproxy_active: true,
        os_tz: Some("Europe/Moscow"),
        has_personal_browser_traces: false,
        has_desktop_traces: false,
        now_secs: 1_700_000_100,
    });
    // 60 + 40 + 25 + 20 + 45 + 45 = 235 -> clamped to 100
    assert_eq!(res.score, 100);
    assert_eq!(res.level, PersonaRiskLevel::High);
    assert!(!res.recommended_actions.is_empty());
}

#[test]
fn self_check_patch_updates_and_scores_exact_weights() {
    let mut state = AppStateData::default();
    let patch = PersonaSelfCheckPatch {
        bought_or_grey_account: Some(true),
        virtual_sms_used: Some(true),
        reseller_payment_used: None,
        multi_account_same_browser: Some(true),
    };
    patch.apply_to(&mut state.persona_self_check);

    let report = clean_report(
        "198.51.100.1",
        IpType::Residential,
        "IP_TYPE_RESIDENTIAL",
        "PINNED_IP_MATCH",
    );
    let res = evaluate_persona_risk(&PersonaRiskInput {
        state_data: &state,
        risk_report: Some(&report),
        sysproxy_active: true,
        os_tz: Some("America/New_York"),
        has_personal_browser_traces: false,
        has_desktop_traces: false,
        now_secs: 1_700_000_100,
    });
    // 45 + 30 + 35 = 110 -> clamped to 100
    assert_eq!(res.score, 100);
    assert_eq!(res.level, PersonaRiskLevel::High);
}

#[test]
fn mass_vpn_plus_ru_tz_is_high_risk() {
    let state = AppStateData::default();
    let mut report = clean_report(
        "198.51.100.2",
        IpType::Vpn,
        "HIGH_RISK_MASS_VPN_ASN",
        "STRICT_PINNING_DISABLED",
    );
    report.timezone_result = CheckResult::warning("TIMEZONE_LEAK_RU", "ru tz", None);

    let res = evaluate_persona_risk(&PersonaRiskInput {
        state_data: &state,
        risk_report: Some(&report),
        sysproxy_active: true,
        os_tz: Some("Europe/Moscow"),
        has_personal_browser_traces: false,
        has_desktop_traces: false,
        now_secs: 1_700_000_100,
    });
    // 35 + 20 = 55 -> High
    assert_eq!(res.score, 55);
    assert_eq!(res.level, PersonaRiskLevel::High);
}
