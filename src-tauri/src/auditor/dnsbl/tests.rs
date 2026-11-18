use super::*;
use crate::auditor::geo_matrix::CheckStatus;
use crate::auditor::seams::HttpProbeOutcome;
use crate::auditor::seams::fakes::{FakeDns, addr};
use std::sync::atomic::Ordering;

const TEST_IP: &str = "203.0.113.9"; // TEST-NET-3, never a real address
const REVERSED: &str = "9.113.0.203";

fn zone(name: &str, severity: &str) -> DnsblZoneConfig {
    DnsblZoneConfig {
        zone: name.to_string(),
        name: name.to_uppercase(),
        severity: severity.to_string(),
        reason: "r".to_string(),
    }
}

/// The bundled rules with the zone list replaced by `z1.test` .. `zN.test`.
fn asns_with_zones(n: usize, severity: &str) -> DangerousAsns {
    let mut asns = DangerousAsns::load_bundled().unwrap();
    asns.dnsbl_zones = (1..=n)
        .map(|i| zone(&format!("z{i}.test"), severity))
        .collect();
    asns
}

/// A zone that works: the control address is listed, the IP is not.
fn healthy(dns: FakeDns, z: &str) -> FakeDns {
    dns.with(&format!("2.0.0.127.{z}"), addr("127.0.0.2"))
        .with(&format!("{REVERSED}.{z}"), LookupOutcome::NotFound)
}

async fn run(dns: FakeDns, asns: &DangerousAsns) -> (DnsblReport, CheckResult) {
    let rep = check_all_dnsbl_with(Arc::new(dns), TEST_IP, asns).await;
    let res = evaluate_dnsbl_report(&rep);
    (rep, res)
}

#[test]
fn test_dnsbl_reverse_ip_query_formatting() {
    assert_eq!(reverse_ipv4("185.220.101.1").unwrap(), "1.101.220.185");
    assert_eq!(
        format_dnsbl_query("185.220.101.1", "zen.spamhaus.org").unwrap(),
        "1.101.220.185.zen.spamhaus.org"
    );
    assert_eq!(reverse_ipv4("185.220.101.5").unwrap(), "5.101.220.185");
    assert!(reverse_ipv4("invalid.ip").is_err());
}

#[test]
fn bundled_zone_list_has_no_dead_zones() {
    let asns = DangerousAsns::load_bundled().unwrap();
    let zones: Vec<&str> = asns.dnsbl_zones.iter().map(|z| z.zone.as_str()).collect();
    assert!(
        !zones.iter().any(|z| z.contains("sorbs")),
        "SORBS is shut down"
    );
    assert!(zones.contains(&"zen.spamhaus.org"));
    assert!(asns.dnsbl_zones.len() >= MIN_ANSWERING_ZONES);
}

// (1) every zone times out
#[tokio::test]
async fn all_zones_timing_out_is_unknown_timeout() {
    let (rep, res) = run(
        FakeDns::new(LookupOutcome::Timeout),
        &asns_with_zones(4, "warning"),
    )
    .await;
    assert_eq!(rep.total_checked, 4);
    assert_eq!(res.status, CheckStatus::Unknown);
    assert_eq!(res.reason, Some(UnknownReason::Timeout));
}

// (2) every zone answers 127.255.255.254: the resolver is turned away
#[tokio::test]
async fn all_zones_refusing_is_unknown_source_refused() {
    let (_, res) = run(
        FakeDns::new(addr("127.255.255.254")),
        &asns_with_zones(4, "warning"),
    )
    .await;
    assert_eq!(res.status, CheckStatus::Unknown);
    assert_eq!(res.reason, Some(UnknownReason::SourceRefused));
    assert_eq!(res.code, "DNSBL_RESOLVER_REFUSED");
}

// (3) the threshold of two answering zones
#[tokio::test]
async fn two_answering_zones_are_enough_one_is_not() {
    let asns = asns_with_zones(4, "warning");
    let two = healthy(
        healthy(FakeDns::new(LookupOutcome::Timeout), "z1.test"),
        "z2.test",
    );
    let (rep, res) = run(two, &asns).await;
    assert_eq!(res.status, CheckStatus::Ok);
    assert_eq!(res.code, "DNSBL_CLEAN");
    assert!(res.message.contains("Ответили 2 из 4"), "{}", res.message);
    assert_eq!(rep.summary_label, "Ответили 2 из 4 баз");

    let one = healthy(FakeDns::new(LookupOutcome::Timeout), "z1.test");
    let (_, res) = run(one, &asns).await;
    assert_eq!(res.status, CheckStatus::Unknown);
}

#[tokio::test]
async fn the_denominator_is_the_real_number_of_zones() {
    let asns = asns_with_zones(3, "warning");
    let all = ["z1.test", "z2.test", "z3.test"]
        .iter()
        .fold(FakeDns::new(LookupOutcome::Timeout), |d, z| healthy(d, z));
    let (_, res) = run(all, &asns).await;
    assert!(res.message.contains("Ответили 3 из 3"), "{}", res.message);
}

// (4) a listing wins over zones that did not answer
#[tokio::test]
async fn a_listing_wins_over_timeouts() {
    let dns = FakeDns::new(LookupOutcome::Timeout)
        .with("2.0.0.127.z1.test", addr("127.0.0.2"))
        .with(&format!("{REVERSED}.z1.test"), addr("127.0.0.2"));
    let (_, res) = run(dns, &asns_with_zones(4, "warning")).await;
    assert_eq!(res.status, CheckStatus::Warning);
    let dns = FakeDns::new(LookupOutcome::Timeout)
        .with("2.0.0.127.z1.test", addr("127.0.0.2"))
        .with(&format!("{REVERSED}.z1.test"), addr("127.0.0.4"));
    let (_, res) = run(dns, &asns_with_zones(4, "critical")).await;
    assert_eq!(res.status, CheckStatus::Critical);
}

// (5) a zone whose control query does not come back listed is not counted
#[tokio::test]
async fn control_query_without_listing_discards_the_zone() {
    let cfg = zone("z1.test", "warning");
    // Dead zone / zone that turns the resolver away: NXDOMAIN for the control address.
    let dead = FakeDns::new(LookupOutcome::NotFound);
    assert_eq!(
        query_zone(&dead, REVERSED, &cfg, Duration::from_millis(10)).await,
        ZoneAnswer::Refused
    );
    // A fake-IP DNS interceptor answers everything with an address outside 127.0.0.0/8.
    let fake_ip = FakeDns::new(addr("198.18.0.7"));
    assert_eq!(
        query_zone(&fake_ip, REVERSED, &cfg, Duration::from_millis(10)).await,
        ZoneAnswer::Error
    );
    // Two such zones plus one healthy one: only one zone vouches, not enough.
    let asns = asns_with_zones(3, "warning");
    let dns = healthy(FakeDns::new(LookupOutcome::NotFound), "z3.test");
    let (rep, res) = run(dns, &asns).await;
    assert_eq!(rep.answered(), 1);
    assert_eq!(res.status, CheckStatus::Unknown);
    // The same fake-IP answers on every zone: never "clean".
    let (_, res) = run(FakeDns::new(addr("198.18.0.7")), &asns).await;
    assert_eq!(res.status, CheckStatus::Unknown);
}

// (6) an IPv6 exit address
#[tokio::test]
async fn ipv6_exit_ip_is_unknown_and_not_queried() {
    let asns = asns_with_zones(4, "warning");
    let dns = Arc::new(FakeDns::new(LookupOutcome::NotFound));
    let rep = check_all_dnsbl_with(dns.clone(), "2606:4700::1111", &asns).await;
    let res = evaluate_dnsbl_report(&rep);
    assert_eq!(res.status, CheckStatus::Unknown);
    assert_eq!(res.reason, Some(UnknownReason::NotApplicable));
    assert!(res.is_not_applicable());
    assert_eq!(res.code, "DNSBL_IPV6_UNSUPPORTED");
    assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
}

// (7) a zone task that panics is an error of that zone, never "clean"
#[tokio::test]
async fn a_panicking_zone_task_is_counted_as_an_error() {
    let asns = asns_with_zones(4, "warning");
    let all_ok = ["z1.test", "z2.test", "z3.test", "z4.test"]
        .iter()
        .fold(FakeDns::new(LookupOutcome::Timeout), |d, z| healthy(d, z));
    let (rep, res) = run(all_ok.panicking_on("z1.test"), &asns).await;
    assert_eq!(rep.failures, vec![UnknownReason::InternalError]);
    assert_eq!(rep.answered(), 3);
    assert!(res.message.contains("Ответили 3 из 4"), "{}", res.message);

    let (rep, res) = run(
        FakeDns::new(LookupOutcome::Timeout).panicking_on(".test"),
        &asns,
    )
    .await;
    assert_eq!(rep.failures, vec![UnknownReason::InternalError; 4]);
    assert_eq!(res.status, CheckStatus::Unknown);
    assert_eq!(res.reason, Some(UnknownReason::InternalError));
}

// (8) Spamhaus PBL is not a listing (default decision), SBL/XBL are
#[tokio::test]
async fn spamhaus_pbl_answers_are_not_a_listing() {
    let cfg = zone("zen.spamhaus.org", "critical");
    let base = |ans: LookupOutcome| {
        FakeDns::new(LookupOutcome::NotFound)
            .with("2.0.0.127.zen.spamhaus.org", addr("127.0.0.2"))
            .with(&format!("{REVERSED}.zen.spamhaus.org"), ans)
    };
    let lim = Duration::from_millis(10);
    for pbl in ["127.0.0.10", "127.0.0.11"] {
        assert_eq!(
            query_zone(&base(addr(pbl)), REVERSED, &cfg, lim).await,
            ZoneAnswer::NotListed,
            "{pbl}"
        );
    }
    for listed in ["127.0.0.2", "127.0.0.3", "127.0.0.4"] {
        assert!(matches!(
            query_zone(&base(addr(listed)), REVERSED, &cfg, lim).await,
            ZoneAnswer::Listed(_)
        ));
    }
    // PBL together with SBL is still a listing.
    let both = LookupOutcome::Addrs(vec![
        "127.0.0.10".parse().unwrap(),
        "127.0.0.2".parse().unwrap(),
    ]);
    match query_zone(&base(both), REVERSED, &cfg, lim).await {
        ZoneAnswer::Listed(hit) => assert_eq!(hit.return_ip, "127.0.0.2"),
        other => panic!("{other:?}"),
    }
    // The exclusion belongs to Spamhaus only: 127.0.0.10 of another zone is a listing.
    let other = zone("z1.test", "warning");
    let dns = FakeDns::new(LookupOutcome::NotFound)
        .with("2.0.0.127.z1.test", addr("127.0.0.2"))
        .with(&format!("{REVERSED}.z1.test"), addr("127.0.0.10"));
    assert!(matches!(
        query_zone(&dns, REVERSED, &other, lim).await,
        ZoneAnswer::Listed(_)
    ));
}

#[tokio::test]
async fn a_resolver_error_on_the_ip_query_is_not_a_clean_answer() {
    let cfg = zone("z1.test", "warning");
    let dns = FakeDns::new(LookupOutcome::Failed).with("2.0.0.127.z1.test", addr("127.0.0.2"));
    assert_eq!(
        query_zone(&dns, REVERSED, &cfg, Duration::from_millis(10)).await,
        ZoneAnswer::Error
    );
    let dns = FakeDns::new(LookupOutcome::Timeout).with("2.0.0.127.z1.test", addr("127.0.0.2"));
    assert_eq!(
        query_zone(&dns, REVERSED, &cfg, Duration::from_millis(10)).await,
        ZoneAnswer::Timeout
    );
}

fn report(total: usize, failures: Vec<UnknownReason>) -> DnsblReport {
    DnsblReport {
        total_checked: total,
        hits: Vec::new(),
        summary_label: String::new(),
        failures,
        unsupported_ip: false,
    }
}

#[test]
fn report_classification() {
    use UnknownReason::*;
    assert_eq!(
        evaluate_dnsbl_report(&report(4, vec![])).status,
        CheckStatus::Ok
    );
    assert_eq!(
        evaluate_dnsbl_report(&report(4, vec![Timeout; 2])).status,
        CheckStatus::Ok
    );
    assert_eq!(
        evaluate_dnsbl_report(&report(4, vec![Timeout; 3])).status,
        CheckStatus::Unknown
    );
    assert_eq!(
        evaluate_dnsbl_report(&report(0, vec![])).status,
        CheckStatus::Unknown
    );
    let mixed = evaluate_dnsbl_report(&report(
        4,
        vec![Timeout, SourceRefused, NetworkError, SourceRefused],
    ));
    assert_eq!(mixed.reason, Some(Timeout));
    let hit = DnsblZoneHit {
        zone: "z".into(),
        name: "Spamhaus ZEN".into(),
        return_ip: "127.0.0.2".into(),
        severity: "critical".into(),
        reason: "r".into(),
    };
    let mut listed = report(4, vec![Timeout; 3]);
    listed.hits.push(hit);
    let r = evaluate_dnsbl_report(&listed);
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Critical, "DNSBL_LISTED_CRITICAL")
    );
    assert!(r.message.contains("Spamhaus ZEN"));
}

#[test]
fn parse_doh_json_a_response_handles_listed_nxdomain_empty_and_refused() {
    let listed = r#"{"Status":0,"Answer":[{"name":"2.0.0.127.z1.test.","type":1,"TTL":300,"data":"127.0.0.2"}]}"#;
    assert_eq!(
        parse_doh_json_a_response(listed),
        LookupOutcome::Addrs(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))])
    );

    let nx = r#"{"Status":3,"Question":[{"name":"5.101.220.185.z1.test.","type":1}]}"#;
    assert_eq!(parse_doh_json_a_response(nx), LookupOutcome::NotFound);

    let empty_ok = r#"{"Status":0,"Answer":[]}"#;
    assert_eq!(parse_doh_json_a_response(empty_ok), LookupOutcome::NotFound);

    let servfail = r#"{"Status":2}"#;
    assert_eq!(parse_doh_json_a_response(servfail), LookupOutcome::Failed);
}

#[tokio::test]
async fn fake_dns_and_open_resolver_refusal_fall_back_to_doh_json() {
    use crate::auditor::seams::fakes::FakeProbe;

    let zones = vec![
        zone("zen.spamhaus.org", "critical"),
        zone("dnsbl.dronebl.org", "critical"),
        zone("b.barracudacentral.org", "warning"),
    ];
    let rules = DangerousAsns {
        dnsbl_zones: zones,
        ..DangerousAsns::load_bundled().unwrap()
    };

    // Simulate V2Box FakeDNS returning 198.18.0.x for all zones plus 1.1.1.1-style
    // 127.255.255.254 refusal on Spamhaus; DoH rescues DroneBL and Barracuda (>= 2 zones).
    let primary = Arc::new(
        FakeDns::new(LookupOutcome::Addrs(vec![IpAddr::V4(Ipv4Addr::new(
            198, 18, 0, 44,
        ))]))
        .with("2.0.0.127.zen.spamhaus.org", addr("127.255.255.254"))
        .with("42.114.244.136.zen.spamhaus.org", addr("127.255.255.254")),
    );

    let doh_probe = Arc::new(
        FakeProbe::body(200, r#"{"Status":3}"#)
            .with_route(
                "name=2.0.0.127.zen.spamhaus.org",
                HttpProbeOutcome::Response {
                    status: 200,
                    body: r#"{"Status":0,"Answer":[{"type":1,"data":"127.255.255.254"}]}"#
                        .into(),
                },
            )
            .with_route(
                "name=2.0.0.127.dnsbl.dronebl.org",
                HttpProbeOutcome::Response {
                    status: 200,
                    body: r#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.2"}]}"#.into(),
                },
            )
            .with_route(
                "name=2.0.0.127.b.barracudacentral.org",
                HttpProbeOutcome::Response {
                    status: 200,
                    body: r#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.2"}]}"#.into(),
                },
            ),
    );
    let doh = Arc::new(DohDns::with_probe(doh_probe)) as Arc<dyn DnsLookup>;

    let report = check_all_dnsbl_with_doh(primary, Some(doh), "136.244.114.42", &rules).await;
    assert_eq!(report.answered(), 2);
    assert!(report.hits.is_empty());
    let res = evaluate_dnsbl_report(&report);
    assert_eq!(
        (res.status, res.code.as_str()),
        (CheckStatus::Ok, "DNSBL_CLEAN")
    );
}
