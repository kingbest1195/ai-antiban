use super::*;

#[test]
fn test_overall_status_allowed() {
    assert!(OverallStatus::Green.is_allowed_by_default());
    assert!(!OverallStatus::Yellow.is_allowed_by_default());
    assert!(!OverallStatus::Red.is_allowed_by_default());
}

#[tokio::test]
async fn test_auditor_initialization() {
    let auditor = Auditor::new().expect("Auditor initialization should succeed");
    let matrix = auditor.rules.provider_matrix.read().await;
    assert_eq!(matrix.version, "1.1.0");
}

#[test]
fn score_twelve_ok_and_one_unknown_is_below_100_and_green() {
    let v = score_checks(&all_checks(&[(3, unk())]), false);
    assert_eq!(v.overall_status, OverallStatus::Green);
    assert!(v.trust_score < 100);
    assert_eq!(v.trust_score, 94);
    assert!(v.incomplete);
}

#[test]
fn score_fourteen_ok_is_100() {
    let v = score_checks(&all_checks(&[]), false);
    assert_eq!(
        (v.trust_score, v.overall_status),
        (100, OverallStatus::Green)
    );
    assert!(!v.incomplete && v.unknown_count == 0 && v.applicable_count == 14);
}

#[test]
fn score_never_exceeds_94_with_unknown_even_when_pinned() {
    for pinned in [false, true] {
        let v = score_checks(&all_checks(&[(5, unk())]), pinned);
        assert!(v.trust_score <= 94, "pinned={pinned}");
    }
    // Unknown penalty is capped at -15: many Unknown still leave a Green 86+ (aux checks).
    let many = all_checks(&[
        (1, unk()),
        (3, unk()),
        (4, unk()),
        (5, unk()),
        (7, unk()),
        (9, unk()),
    ]);
    let v = score_checks(&many, false);
    assert_eq!(v.overall_status, OverallStatus::Green);
    assert_eq!(v.trust_score, 86);
    assert_eq!(v.unknown_count, 6);
}

#[test]
fn score_not_applicable_is_not_penalised_nor_counted() {
    let v = score_checks(&all_checks(&[(8, na())]), false);
    assert_eq!(v.trust_score, 100);
    assert!(!v.incomplete);
    assert_eq!((v.unknown_count, v.applicable_count), (0, 13));
}

#[test]
fn score_critical_plus_unknown_is_red_and_at_most_35() {
    let v = score_checks(
        &all_checks(&[(0, CheckResult::critical("C", "c", None)), (3, unk())]),
        false,
    );
    assert_eq!(v.overall_status, OverallStatus::Red);
    assert!(v.trust_score <= 35);
    assert!(v.incomplete);
}

#[test]
fn score_counters() {
    let v = score_checks(
        &all_checks(&[(1, unk()), (3, unk()), (8, na()), (10, na())]),
        false,
    );
    assert_eq!(v.unknown_count, 2);
    assert_eq!(v.applicable_count, 12);
    assert_eq!(count_checks(&all_checks(&[(2, unk())])), (1, 14));
}

#[test]
fn unknown_core_check_is_never_green() {
    // Geo (0) and Impossible Travel (2) are the core: fail-closed.
    for core in CORE_CHECKS {
        let v = score_checks(&all_checks(&[(core, unk())]), false);
        assert_eq!(v.overall_status, OverallStatus::Yellow, "core check {core}");
        assert!(!v.overall_status.is_allowed_by_default());
    }
    // The auxiliary ones keep the automatic admit (fail-open), but are reported.
    for aux in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] {
        let v = score_checks(&all_checks(&[(aux, unk())]), false);
        assert_eq!(v.overall_status, OverallStatus::Green, "aux check {aux}");
        assert!(v.incomplete);
    }
}

#[test]
fn risk_report_without_new_fields_reads() {
    let mut report = report_fixture();
    let mut json = serde_json::to_value(&report).unwrap();
    let obj = json.as_object_mut().unwrap();
    obj.remove("unknown_count");
    obj.remove("applicable_count");
    obj.remove("incomplete");
    let old: RiskReport = serde_json::from_value(json).unwrap();
    assert_eq!(
        (old.unknown_count, old.applicable_count, old.incomplete),
        (0, 0, false)
    );
    report.unknown_count = 2;
    report.incomplete = true;
    let v = serde_json::to_value(&report).unwrap();
    assert_eq!(v["unknown_count"], 2);
    assert_eq!(v["incomplete"], true);
}

fn report_fixture() -> RiskReport {
    RiskReport {
        provider: ProviderId::Anthropic,
        overall_status: OverallStatus::Green,
        trust_score: 100,
        telemetry: NetworkTelemetry {
            ip: "9.9.9.9".into(),
            country_code: "NL".into(),
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            resolved_at: 0,
        },
        geo_result: ok(),
        pinning_result: ok(),
        travel_result: ok(),
        dnsbl_result: ok(),
        dnsbl_clean_count: String::new(),
        asn_result: ok(),
        ipv6_result: ok(),
        timezone_result: ok(),
        ipv6_exit: false,
        checks: vec![ok()],
        unknown_count: 0,
        applicable_count: 14,
        incomplete: false,
        gateway_latency_ms: None,
    }
}

#[test]
fn bug3_via_zastava_key_dns_scoring_respects_all_preconditions() {
    use crate::auditor::leaks::{
        AuditProtectionContext, evaluate_dns_resolver_for_route_with_protection,
    };
    use crate::auditor::probes::whoami::{
        ResolverView, evaluate_dns_country_for_route_with_protection,
    };

    let ru_view = ResolverView::Located {
        ip: "77.88.8.8".parse().unwrap(),
        country: "RU".to_string(),
        public_service: None,
        sources: vec![],
    };
    let os_ru_cfg = CheckResult::warning(
        "DNS_DOMESTIC_WARNING",
        "В системном DNS обнаружен провайдер РФ",
        Some(crate::auditor::geo_matrix::GUIDE_OS_NETWORK.to_string()),
    );

    let healthy = AuditProtectionContext {
        route_usable: true,
        sysproxy_active: true,
        cli_or_sandbox_protection_active: false,
        os_pac_deferred: false,
    };
    let dns_ok = evaluate_dns_resolver_for_route_with_protection(
        os_ru_cfg.clone(),
        &ru_view,
        "NL",
        true,
        healthy,
    );
    let country_ok = evaluate_dns_country_for_route_with_protection(&ru_view, "NL", true, healthy);
    assert_eq!(dns_ok.code, "DNS_KEY_REMOTE_RESOLVE");
    assert_eq!(country_ok.code, "DNS_KEY_REMOTE_RESOLVE");

    let verdict_ok = score_checks(&all_checks(&[(6, dns_ok), (10, country_ok)]), false);
    assert_eq!(verdict_ok.overall_status, OverallStatus::Green);
    assert!(
        verdict_ok.trust_score >= 95,
        "got {}",
        verdict_ok.trust_score
    );

    // Any failed precondition or Direct mode preserves Warning (-15 penalty per check).
    let failure_modes = [
        (
            true,
            AuditProtectionContext {
                route_usable: false,
                ..healthy
            },
        ),
        (
            true,
            AuditProtectionContext {
                sysproxy_active: false,
                cli_or_sandbox_protection_active: false,
                os_pac_deferred: false,
                route_usable: true,
            },
        ),
        (
            true,
            AuditProtectionContext {
                os_pac_deferred: true,
                ..healthy
            },
        ),
        (false, healthy),
    ];

    for (via_key, ctx) in failure_modes {
        let dns_warn = evaluate_dns_resolver_for_route_with_protection(
            os_ru_cfg.clone(),
            &ru_view,
            "NL",
            via_key,
            ctx,
        );
        let country_warn =
            evaluate_dns_country_for_route_with_protection(&ru_view, "NL", via_key, ctx);
        assert_eq!(dns_warn.status, CheckStatus::Warning);
        assert_eq!(country_warn.status, CheckStatus::Warning);

        let verdict_warn = score_checks(&all_checks(&[(6, dns_warn), (10, country_warn)]), false);
        assert_eq!(verdict_warn.overall_status, OverallStatus::Yellow);
        assert_eq!(verdict_warn.trust_score, 70);
    }
}
