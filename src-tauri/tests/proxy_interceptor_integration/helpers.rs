use std::sync::Arc;

use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{HttpProbeOutcome, LookupOutcome};
use zastava_lib::auditor::{AuditEnv, Auditor, CheckResult, OverallStatus, ProviderId, RiskReport};
use zastava_lib::proxy::RiskInterceptPayload;
use zastava_lib::proxy::hold_queue::{NetworkChange, PHASE_DETECTING};

pub(crate) fn offline_test_auditor_with(dns: FakeDns, probe: FakeProbe) -> Auditor {
    let env = AuditEnv {
        dns: Arc::new(dns),
        probe: Arc::new(probe),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    };
    Auditor::with_env(env).expect("offline test auditor")
}

pub(crate) fn offline_test_auditor() -> Auditor {
    offline_test_auditor_with(
        FakeDns::new(LookupOutcome::NotFound),
        FakeProbe::new(HttpProbeOutcome::Timeout),
    )
}

pub(crate) fn sample_report(provider: ProviderId) -> RiskReport {
    let ok = CheckResult::ok("T", "t");
    RiskReport {
        provider,
        overall_status: OverallStatus::Yellow,
        trust_score: 70,
        telemetry: NetworkTelemetry {
            ip: "9.9.9.9".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(1),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        },
        geo_result: ok.clone(),
        pinning_result: ok.clone(),
        travel_result: ok.clone(),
        dnsbl_result: ok.clone(),
        dnsbl_clean_count: "0/0".to_string(),
        asn_result: ok.clone(),
        ipv6_result: ok.clone(),
        timezone_result: ok.clone(),
        ipv6_exit: false,
        checks: vec![ok],
        unknown_count: 0,
        applicable_count: 13,
        incomplete: false,
    }
}

pub(crate) fn detecting_payload(id: &str) -> RiskInterceptPayload {
    RiskInterceptPayload {
        id: id.to_string(),
        provider: ProviderId::Anthropic,
        host: "Смена сети · все ИИ-сервисы".to_string(),
        report: None,
        ttl_seconds: 60,
        scope: "network".to_string(),
        network_change: Some(NetworkChange {
            old_ip: Some("1.1.1.1".to_string()),
            old_country: Some("DE".to_string()),
            new_ip: Some("9.9.9.9".to_string()),
            new_country: None,
        }),
        is_simulation: false,
        detected_at_ms: 1_700_000_000_000,
        phase: PHASE_DETECTING.to_string(),
        gate_reason: None,
    }
}
