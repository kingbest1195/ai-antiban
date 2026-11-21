use super::*;
use crate::auditor::geo_matrix::CheckStatus;

fn config_ok() -> CheckResult {
    CheckResult::ok("DNS_CLEAN", "ok")
}

fn config_domestic() -> CheckResult {
    CheckResult::warning(
        "DNS_DOMESTIC_WARNING",
        "domestic dns",
        Some(GUIDE_OS_NETWORK.to_string()),
    )
}

fn located(ip: &str, cc: &str) -> ResolverView {
    ResolverView::Located {
        ip: ip.parse().unwrap(),
        country: cc.into(),
        public_service: None,
        sources: vec![],
    }
}

#[test]
fn bug3_via_zastava_key_dns_preconditions_enforced() {
    let ru_view = located("77.88.8.8", "RU");
    let healthy_sysproxy = AuditProtectionContext {
        route_usable: true,
        sysproxy_active: true,
        cli_or_sandbox_protection_active: false,
        os_pac_deferred: false,
    };
    let healthy_cli_only = AuditProtectionContext {
        route_usable: true,
        sysproxy_active: false,
        cli_or_sandbox_protection_active: true,
        os_pac_deferred: false,
    };

    // Pass when all 3 preconditions hold (both via sysproxy and via CLI/sandbox protection).
    for ctx in [healthy_sysproxy, healthy_cli_only] {
        let ok_res = evaluate_dns_resolver_for_route_with_protection(
            config_domestic(),
            &ru_view,
            "NL",
            true,
            ctx,
        );
        assert_eq!(
            (ok_res.status, ok_res.code.as_str()),
            (CheckStatus::Ok, "DNS_KEY_REMOTE_RESOLVE")
        );
        assert!(
            ok_res.message.contains("non-AI") && ok_res.message.contains("DNS ОС"),
            "Precondition 3 non-AI OS DNS note missing: {}",
            ok_res.message
        );
    }

    // Fail Precondition 1: bound route is NOT usable.
    let unusable = AuditProtectionContext {
        route_usable: false,
        ..healthy_sysproxy
    };
    let r1 = evaluate_dns_resolver_for_route_with_protection(
        config_ok(),
        &ru_view,
        "NL",
        true,
        unusable,
    );
    assert_eq!(
        (r1.status, r1.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );

    // Fail Precondition 2a: neither sysproxy nor CLI/sandbox protection is active.
    let no_protection = AuditProtectionContext {
        route_usable: true,
        sysproxy_active: false,
        cli_or_sandbox_protection_active: false,
        os_pac_deferred: false,
    };
    let r2 = evaluate_dns_resolver_for_route_with_protection(
        config_ok(),
        &ru_view,
        "NL",
        true,
        no_protection,
    );
    assert_eq!(
        (r2.status, r2.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );

    let deferred_cli = AuditProtectionContext {
        os_pac_deferred: true,
        cli_or_sandbox_protection_active: true,
        ..healthy_sysproxy
    };
    let r3 = evaluate_dns_resolver_for_route_with_protection(
        config_domestic(),
        &ru_view,
        "NL",
        true,
        deferred_cli,
    );
    assert_eq!(
        (r3.status, r3.code.as_str()),
        (CheckStatus::Ok, "DNS_KEY_REMOTE_RESOLVE")
    );
    let deferred_plain = AuditProtectionContext {
        os_pac_deferred: true,
        ..healthy_sysproxy
    };
    let r3b = evaluate_dns_resolver_for_route_with_protection(
        config_domestic(),
        &ru_view,
        "NL",
        true,
        deferred_plain,
    );
    assert_eq!(
        (r3b.status, r3b.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );

    // Direct mode (via_zastava_key == false) MUST preserve full strictness even with all flags true.
    let direct_ru = evaluate_dns_resolver_for_route_with_protection(
        config_ok(),
        &ru_view,
        "NL",
        false,
        healthy_sysproxy,
    );
    assert_eq!(
        (direct_ru.status, direct_ru.code.as_str()),
        (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
    );

    let yandex_cfg = evaluate_dns_listing("resolver #1\n  nameserver[0] : 77.88.8.8\n", "NL", &[]);
    let direct_yandex = evaluate_dns_resolver_for_route_with_protection(
        yandex_cfg,
        &located("9.9.9.9", "NL"),
        "NL",
        false,
        healthy_sysproxy,
    );
    assert_eq!(
        (direct_yandex.status, direct_yandex.code.as_str()),
        (CheckStatus::Warning, "DNS_YANDEX_LEAK")
    );
}
