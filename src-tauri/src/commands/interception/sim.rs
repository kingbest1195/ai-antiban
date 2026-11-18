//! Demo risk-interception simulation payload builder.

use crate::{auditor, proxy, state};

/// `measured_via` of the canned results in the demo simulation.
const SIMULATED_VIA: &str = "simulation";

pub(crate) fn build_simulation_network_change(
    data: &state::AppStateData,
    provider_key: &str,
) -> proxy::hold_queue::NetworkChange {
    let scoped_key = data.ip_history_key_for_provider(provider_key);
    let last_entry = data
        .ip_history
        .get(&scoped_key)
        .and_then(|v| v.last())
        .or_else(|| data.ip_history.get(provider_key).and_then(|v| v.last()))
        .or_else(|| data.ip_history.values().filter_map(|v| v.last()).next());

    let old_ip = data
        .pinned_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| last_entry.map(|e| e.ip.clone()))
        .unwrap_or_else(|| "185.212.102.40".to_string());

    let old_country = last_entry
        .and_then(|e| {
            if e.ip.trim() == old_ip.trim() {
                Some(e.country_code.clone())
            } else {
                None
            }
        })
        .or_else(|| last_entry.map(|e| e.country_code.clone()))
        .filter(|c| !c.trim().is_empty())
        .unwrap_or_else(|| "NL".to_string());

    proxy::hold_queue::NetworkChange {
        old_ip: Some(old_ip),
        old_country: Some(old_country),
        new_ip: Some("185.220.101.5".to_string()),
        new_country: Some("TR".to_string()),
    }
}

pub(super) async fn build_simulated_risk_report(
    provider_id: auditor::ProviderId,
    auditor: &auditor::Auditor,
) -> auditor::RiskReport {
    let matrix = auditor.rules.provider_matrix.read().await;
    let dangerous_asns = auditor.rules.dangerous_asns.read().await;

    let telemetry = auditor::NetworkTelemetry {
        ip: "185.220.101.5".to_string(),
        country_code: "TR".to_string(),
        hostname: Some("tor-exit-01.relays.net".to_string()),
        asn: Some(9009),
        org: Some("M247 Europe SRL".to_string()),
        isp: Some("M247 Europe SRL".to_string()),
        timezone: Some("Europe/Istanbul".to_string()),
        resolved_at: auditor::network::current_timestamp(),
    };

    let geo_result = auditor::evaluate_provider_geo(&matrix, provider_id, &telemetry.country_code);
    let pinning_result = auditor::CheckResult::warning(
        "PINNED_IP_NOT_CONFIGURED",
        "Строгая привязка IP отключена. Трафик идет через публичный коммерческий VPN-пул.",
        Some(auditor::geo_matrix::GUIDE_PERSONAL_VPN.to_string()),
    );
    let travel_result =
        auditor::CheckResult::ok("TRAVEL_NORMAL", "Конфликтов перемещения за 12ч нет.");
    let dnsbl_report = auditor::check_all_dnsbl(&telemetry.ip, &dangerous_asns).await;
    let dnsbl_result = auditor::evaluate_dnsbl_report(&dnsbl_report);
    // SIMULATION ONLY: the Tor list is not downloaded here; the demo address is a mass-VPN pool.
    let asn_result = auditor::evaluate_ip_reputation(
        &auditor::ExitIdentity {
            ip: &telemetry.ip,
            country_code: &telemetry.country_code,
            asn: telemetry.asn,
            isp: telemetry.isp.as_deref(),
            org: telemetry.org.as_deref(),
        },
        &dangerous_asns,
        auditor::TorLookup::NotListed,
        false,
    )
    .with_measured_via(SIMULATED_VIA);
    // SIMULATION ONLY: these two verdicts are canned demo values, not the outcome of a probe.
    // They are marked (`measured_via = "simulation"`) so that they never pass for a real check.
    let ipv6_result =
        auditor::CheckResult::ok("IPV6_SAFE", "Утечек по протоколу IPv6 не обнаружено.")
            .with_measured_via(SIMULATED_VIA);
    let dns_result = auditor::CheckResult::ok(
        "DNS_CLEAN",
        "Утечек через локальные DNS-резолверы РФ не обнаружено.",
    )
    .with_measured_via(SIMULATED_VIA);
    let timezone_result = auditor::evaluate_system_timezone(telemetry.timezone.as_deref(), None);
    let location_result = auditor::check_os_location_services();
    let reverse_dns_result = auditor::evaluate_reverse_dns_ptr(&telemetry);
    let dns_country_result = auditor::evaluate_dns_country_consistency(&telemetry, None);
    let locale_result = auditor::evaluate_locale_env_hygiene(None);
    // SIMULATION ONLY: the 13th check (UDP/STUN) is a canned demo value as well.
    let udp_stun_result = auditor::CheckResult::ok(
        "UDP_STUN_MATCH",
        "Внешний адрес по UDP совпадает с адресом HTTP-выхода.",
    )
    .with_measured_via(SIMULATED_VIA);

    let checks = vec![
        geo_result.clone(),
        pinning_result.clone(),
        travel_result.clone(),
        dnsbl_result.clone(),
        asn_result.clone(),
        ipv6_result.clone(),
        dns_result,
        timezone_result.clone(),
        location_result,
        reverse_dns_result,
        dns_country_result,
        locale_result,
        udp_stun_result,
    ];

    let (unknown_count, applicable_count) = auditor::count_checks(&checks);
    auditor::RiskReport {
        provider: provider_id,
        overall_status: auditor::OverallStatus::Red,
        trust_score: 28,
        telemetry,
        geo_result,
        pinning_result,
        travel_result,
        dnsbl_result,
        dnsbl_clean_count: dnsbl_report.summary_label,
        asn_result,
        ipv6_result,
        timezone_result,
        ipv6_exit: false,
        checks,
        unknown_count,
        applicable_count,
        incomplete: unknown_count > 0,
    }
}
