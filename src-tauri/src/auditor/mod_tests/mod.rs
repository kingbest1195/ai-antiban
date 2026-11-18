use super::*;

use probes::stun::testing::echoing;
use seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp, addr};
use seams::{HttpProbeOutcome, LookupOutcome, TxtOutcome};

pub(super) fn ok() -> CheckResult {
    CheckResult::ok("OK", "ok")
}
pub(super) fn unk() -> CheckResult {
    CheckResult::unknown("U", "u", UnknownReason::Timeout)
}
pub(super) fn na() -> CheckResult {
    CheckResult::unknown("NA", "na", UnknownReason::NotApplicable)
}
/// The 14 results of a report in order, `ok()` everywhere except the given positions.
pub(super) fn all_checks(over: &[(usize, CheckResult)]) -> Vec<CheckResult> {
    let mut v: Vec<CheckResult> = (0..CHECK_COUNT).map(|_| ok()).collect();
    for (i, r) in over {
        v[*i] = r.clone();
    }
    v
}

/// Number of checks in a report (`claude_exit` is the 14th, index 13).
pub(super) const CHECK_COUNT: usize = 14;


pub(super) fn rich_telemetry() -> NetworkTelemetry {
    NetworkTelemetry {
        ip: "203.0.113.9".into(),
        country_code: "NL".into(),
        hostname: Some("host.example".into()),
        asn: Some(64500),
        org: Some("Example Net".into()),
        isp: Some("Example Net".into()),
        timezone: Some("Europe/Amsterdam".into()),
        resolved_at: network::current_timestamp(),
    }
}

/// What `1.1.1.1/cdn-cgi/trace` gives: an IP and a country, nothing else.
pub(super) fn trace_only_telemetry() -> NetworkTelemetry {
    NetworkTelemetry {
        hostname: None,
        asn: None,
        org: None,
        isp: None,
        timezone: None,
        ..rich_telemetry()
    }
}

pub(super) fn zones_answering(dns: FakeDns) -> FakeDns {
    let asns = rules::DangerousAsns::load_bundled().unwrap();
    asns.dnsbl_zones.iter().fold(dns, |d, z| {
        d.with(&format!("2.0.0.127.{}", z.zone), addr("127.0.0.2"))
            .with(&format!("9.113.0.203.{}", z.zone), LookupOutcome::NotFound)
    })
}

pub(super) async fn audit(env: AuditEnv, tel: NetworkTelemetry) -> RiskReport {
    let auditor = Auditor::with_env(env).unwrap();
    auditor.resolver.set_cached(tel).await;
    auditor
        .evaluate_all(ProviderId::Anthropic, &AppState::new_in_memory(), false)
        .await
        .unwrap()
}

/// UDP stays silent (every STUN server times out).
pub(super) fn env_of(dns: FakeDns, probe: FakeProbe, system: FakeSystem) -> AuditEnv {
    env_with_udp(dns, probe, system, FakeUdp::new())
}

pub(super) fn env_with_udp(dns: FakeDns, probe: FakeProbe, system: FakeSystem, udp: FakeUdp) -> AuditEnv {
    AuditEnv {
        dns: Arc::new(dns),
        probe: Arc::new(probe),
        udp: Arc::new(udp),
        system: Arc::new(system),
    }
}

/// Both whoami sources name `resolver` as the resolver that asks them.
pub(super) fn with_whoami(dns: FakeDns, resolver: &str) -> FakeDns {
    dns.with(whoami::AKAMAI_HOST, addr(resolver)).with_txt(
        whoami::GOOGLE_TXT_HOST,
        TxtOutcome::Records(vec![format!("\"{resolver}\"")]),
    )
}

/// Attaches healthy direct neutral trace responses matching `rich_telemetry()` (never claude.ai / chatgpt.com).
pub(super) fn with_ai_traces(probe: FakeProbe) -> FakeProbe {
    probe.with_route(
        "1.1.1.1/cdn-cgi/trace",
        HttpProbeOutcome::Response {
            status: 200,
            body: "fl=1\nip=203.0.113.9\nloc=NL\ncolo=AMS\n".into(),
        },
    )
}

/// The geo services place the resolver in `country`; IPv6 and provider-exit probes report NL.
pub(super) fn probe_locating(country: &str) -> FakeProbe {
    with_ai_traces(with_tor_list(FakeProbe::body(200, "loc=NL\n"))).with_route(
        "ipwho.is",
        HttpProbeOutcome::Response {
            status: 200,
            body: format!("{{\"success\":true,\"country_code\":\"{country}\"}}"),
        },
    )
}

/// The Tor exit list answers (the audited address 203.0.113.9 is not in it).
pub(super) fn with_tor_list(probe: FakeProbe) -> FakeProbe {
    probe.with_route(
        "torbulkexitlist",
        HttpProbeOutcome::Response {
            status: 200,
            body: "198.51.100.1\n198.51.100.2\n".into(),
        },
    )
}

/// Both STUN servers report `ip` as the public UDP address.
pub(super) fn udp_exiting_as(ip: &str) -> FakeUdp {
    let ip: std::net::Ipv4Addr = ip.parse().unwrap();
    FakeUdp::new()
        .with_server(stun::SERVERS[0].addr, echoing(ip))
        .with_server(stun::SERVERS[1].addr, echoing(ip))
}

/// Every real source answers and everything is consistent (resolver and UDP exit in NL).
pub(super) fn healthy_env() -> AuditEnv {
    env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        ),
        probe_locating("NL"),
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
        udp_exiting_as("203.0.113.9"),
    )
}

mod scoring_tests;
mod evaluate_core_tests;
mod evaluate_scenarios_tests;
