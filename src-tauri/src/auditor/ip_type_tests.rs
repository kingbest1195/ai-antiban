use super::*;
use crate::auditor::geo_matrix::CheckStatus;
use crate::auditor::seams::fakes::FakeProbe;

const TOR_IP: &str = "203.0.113.50"; // TEST-NET-3, never a real address
const OTHER_IP: &str = "203.0.113.9";
const LIST: &str = "# exit list\n203.0.113.50\r\n\n203.0.113.51\nnot an ip\n";

fn asns() -> DangerousAsns {
    DangerousAsns::load_bundled().unwrap()
}

fn id<'a>(ip: &'a str, asn: Option<u32>, isp: Option<&'a str>) -> ExitIdentity<'a> {
    ExitIdentity {
        ip,
        country_code: "NL",
        asn,
        isp,
        org: None,
    }
}

fn list_probe() -> FakeProbe {
    FakeProbe::body(200, LIST)
}

async fn verdict(
    probe: &FakeProbe,
    ip: &str,
    asn: Option<u32>,
    isp: Option<&str>,
    pinned: bool,
) -> CheckResult {
    let cache = TorListCache::default();
    let tor = lookup_tor(&cache, probe, ip).await;
    evaluate_ip_reputation(&id(ip, asn, isp), &asns(), tor, pinned)
}

fn type_of(r: &CheckResult) -> Option<IpType> {
    r.detail.as_ref().and_then(|d| d.ip_type)
}

#[test]
fn tor_list_parsing_skips_noise() {
    let set = parse_tor_list(LIST);
    assert_eq!(set.len(), 2);
    assert!(set.contains(&TOR_IP.parse().unwrap()));
    assert!(parse_tor_list("<html>blocked</html>\n").is_empty());
}

#[tokio::test]
async fn tor_exit_is_a_warning_even_on_a_hosting_asn_and_even_pinned() {
    let probe = list_probe();
    for pinned in [false, true] {
        let r = verdict(
            &probe,
            TOR_IP,
            Some(24940),
            Some("Hetzner Online GmbH"),
            pinned,
        )
        .await;
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Warning, "IP_TYPE_TOR"),
            "pinned={pinned}"
        );
        assert_eq!(type_of(&r), Some(IpType::Tor));
    }
}

#[tokio::test]
async fn cloudflare_t1_country_is_tor_too() {
    let tor = TorLookup::NotListed;
    let ident = ExitIdentity {
        ip: OTHER_IP,
        country_code: "t1",
        asn: Some(64500),
        isp: Some("Example Net"),
        org: None,
    };
    assert_eq!(classify(&asns(), &ident, tor), IpType::Tor);
}

#[tokio::test]
async fn hosting_is_ok_and_costs_nothing() {
    let probe = list_probe();
    let r = verdict(
        &probe,
        OTHER_IP,
        Some(24940),
        Some("Hetzner Online GmbH"),
        false,
    )
    .await;
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Ok, "IP_TYPE_HOSTING")
    );
    assert!(
        r.message.starts_with("Datacenter / VPS IP (не резидентский)"),
        "{}",
        r.message
    );
    assert_eq!(type_of(&r), Some(IpType::Hosting));
    let v = crate::auditor::score_checks(&[r], false);
    assert_eq!(v.trust_score, 100, "a hosting address is not penalised");
}

#[tokio::test]
async fn hosting_is_recognised_by_the_name_when_the_asn_is_not_listed() {
    let probe = list_probe();
    let r = verdict(
        &probe,
        OTHER_IP,
        Some(64500),
        Some("Example Cloud Hosting Ltd"),
        false,
    )
    .await;
    assert_eq!(
        (r.status, type_of(&r)),
        (CheckStatus::Ok, Some(IpType::Hosting))
    );
}

#[tokio::test]
async fn residential_is_ok() {
    let probe = list_probe();
    let r = verdict(
        &probe,
        OTHER_IP,
        Some(64500),
        Some("Example Broadband Ltd"),
        false,
    )
    .await;
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Ok, "IP_TYPE_RESIDENTIAL")
    );
    assert_eq!(type_of(&r), Some(IpType::Residential));
}

#[tokio::test]
async fn a_known_name_of_no_known_kind_is_ok_with_unknown_type() {
    let probe = list_probe();
    let r = verdict(&probe, OTHER_IP, Some(64500), Some("Example Net"), false).await;
    assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "ASN_CLEAN"));
    assert_eq!(type_of(&r), Some(IpType::Unknown));
    assert!(r.message.contains("AS64500"), "{}", r.message);
}

#[tokio::test]
async fn mass_vpn_pool_is_a_warning_and_pinning_excuses_it() {
    let probe = list_probe();
    let r = verdict(&probe, OTHER_IP, Some(9009), Some("M247"), false).await;
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "HIGH_RISK_MASS_VPN_ASN")
    );
    assert_eq!(type_of(&r), Some(IpType::Vpn));
    assert!(r.message.contains("AS9009"), "{}", r.message);
    let r = verdict(&probe, OTHER_IP, Some(9009), Some("M247"), true).await;
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Ok, "ASN_VERIFIED_PINNED")
    );
}

#[tokio::test]
async fn a_russian_isp_stays_critical() {
    let probe = list_probe();
    let r = verdict(
        &probe,
        OTHER_IP,
        Some(12389),
        Some("PJSC Rostelecom"),
        false,
    )
    .await;
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Critical, "RUSSIAN_ISP_DETECTED")
    );
}

#[tokio::test]
async fn without_any_data_the_check_is_unknown_no_data() {
    let probe = list_probe();
    let r = verdict(&probe, OTHER_IP, None, None, false).await;
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::NoData))
    );
    assert_eq!(type_of(&r), Some(IpType::Unknown));
    // Blank names are no data either.
    let r = verdict(&probe, OTHER_IP, None, Some("  "), false).await;
    assert_eq!(r.status, CheckStatus::Unknown);
}

#[tokio::test]
async fn an_unavailable_list_is_unknown_never_ok_and_never_a_block() {
    for (probe, reason) in [
        (
            FakeProbe::new(HttpProbeOutcome::Timeout),
            UnknownReason::Timeout,
        ),
        (
            FakeProbe::new(HttpProbeOutcome::ConnectFailed),
            UnknownReason::NetworkError,
        ),
        (FakeProbe::body(403, "denied"), UnknownReason::SourceRefused),
        (
            FakeProbe::body(200, "<html>portal</html>"),
            UnknownReason::EmptyResponse,
        ),
        (FakeProbe::body(500, ""), UnknownReason::NetworkError),
    ] {
        let r = verdict(
            &probe,
            OTHER_IP,
            Some(24940),
            Some("Hetzner Online GmbH"),
            false,
        )
        .await;
        assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(reason)));
        assert_eq!(r.code, "TOR_LIST_UNAVAILABLE");
        // The type is still shown from the provider data.
        assert_eq!(type_of(&r), Some(IpType::Hosting));
    }
    // A finding wins over a missing list.
    let probe = FakeProbe::new(HttpProbeOutcome::Timeout);
    let r = verdict(&probe, OTHER_IP, Some(9009), Some("M247"), false).await;
    assert_eq!(r.status, CheckStatus::Warning);
}

#[tokio::test]
async fn an_ipv6_exit_is_not_applicable_and_the_list_is_not_downloaded() {
    let probe = list_probe();
    let r = verdict(
        &probe,
        "2001:db8::9",
        Some(24940),
        Some("Hetzner Online GmbH"),
        false,
    )
    .await;
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::NotApplicable))
    );
    assert!(r.is_not_applicable());
    assert!(
        r.message.starts_with("Не применимо к IPv6"),
        "{}",
        r.message
    );
    assert_eq!(type_of(&r), Some(IpType::Hosting));
    assert_eq!(probe.calls(), 0);
    // Not applicable costs nothing.
    assert_eq!(crate::auditor::score_checks(&[r], false).trust_score, 100);
}

#[tokio::test]
async fn the_list_is_downloaded_once_per_ttl_and_a_failure_is_not_remembered_long() {
    let cache = TorListCache::default();
    let probe = list_probe();
    assert_eq!(lookup_tor(&cache, &probe, TOR_IP).await, TorLookup::Listed);
    assert_eq!(
        lookup_tor(&cache, &probe, OTHER_IP).await,
        TorLookup::NotListed
    );
    assert_eq!(probe.calls(), 1);

    let cache = TorListCache::default();
    let failing = FakeProbe::new(HttpProbeOutcome::Timeout);
    assert_eq!(
        lookup_tor(&cache, &failing, TOR_IP).await,
        TorLookup::Unavailable(UnknownReason::Timeout)
    );
    assert!(failing.calls() >= 1);
}

#[test]
fn ip_type_wire_names_are_what_the_interface_reads() {
    let r = CheckResult::ok("A", "a").with_ip_type(IpType::Hosting);
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["detail"]["ip_type"], "hosting");
    for (t, s) in [
        (IpType::Hosting, "hosting"),
        (IpType::Residential, "residential"),
        (IpType::Tor, "tor"),
        (IpType::Vpn, "vpn"),
        (IpType::Unknown, "unknown"),
    ] {
        assert_eq!(serde_json::to_value(t).unwrap(), s);
    }
    // A result without a type carries no `detail` at all.
    assert!(
        serde_json::to_value(CheckResult::ok("A", "a"))
            .unwrap()
            .get("detail")
            .is_none()
    );
}
