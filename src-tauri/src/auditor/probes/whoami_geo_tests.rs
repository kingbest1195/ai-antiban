use super::*;
use crate::auditor::geo_matrix::CheckStatus;
use crate::auditor::seams::fakes::{FakeDns, FakeProbe, addr};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn txt(s: &str) -> TxtOutcome {
    TxtOutcome::Records(vec![s.to_string()])
}

fn geo_probe(country: &str) -> FakeProbe {
    FakeProbe::body(
        200,
        &format!("{{\"success\":true,\"country_code\":\"{country}\"}}"),
    )
}

async fn measure(dns: FakeDns, probe: &FakeProbe) -> ResolverView {
    measure_resolver(&dns, probe, &TtlCache::default()).await
}

fn agreeing(resolver: &str) -> FakeDns {
    FakeDns::new(LookupOutcome::Failed)
        .with(AKAMAI_HOST, addr(resolver))
        .with_txt(GOOGLE_TXT_HOST, txt(&format!("\"{resolver}\"")))
}

fn parts(view: &ResolverView) -> (IpAddr, &str, Option<&'static str>) {
    match view {
        ResolverView::Located {
            ip,
            country,
            public_service,
            ..
        } => (*ip, country.as_str(), *public_service),
        other => panic!("not located: {other:?}"),
    }
}

#[tokio::test]
async fn geo_cascade_falls_through_and_reports_why_it_failed() {
    let dns = || agreeing("77.88.8.8");
    // The first service fails, the second answers.
    let probe = FakeProbe::new(HttpProbeOutcome::Timeout).with_route(
        "ipinfo.io",
        HttpProbeOutcome::Response {
            status: 200,
            body: "{\"ip\":\"77.88.8.8\",\"country\":\"ru\"}".into(),
        },
    );
    assert_eq!(
        parts(&measure(dns(), &probe).await),
        (ip("77.88.8.8"), "RU", None)
    );
    // No service answers in time.
    let ResolverView::Unmeasured(u) =
        measure(dns(), &FakeProbe::new(HttpProbeOutcome::Timeout)).await
    else {
        panic!()
    };
    assert_eq!(
        (u.code, u.reason),
        ("DNS_RESOLVER_GEO_UNAVAILABLE", UnknownReason::Timeout)
    );
    // Services answer without a country (error body, bogon, rate limit).
    for body in [
        "{\"success\":false}",
        "{\"ip\":\"1.2.3.4\",\"bogon\":true}",
        "<html>",
        "{\"country_code\":\"XX\"}",
    ] {
        let ResolverView::Unmeasured(u) = measure(dns(), &FakeProbe::body(200, body)).await else {
            panic!()
        };
        assert_eq!(u.reason, UnknownReason::EmptyResponse, "{body}");
    }
    let ResolverView::Unmeasured(u) =
        measure(dns(), &FakeProbe::new(HttpProbeOutcome::ConnectFailed)).await
    else {
        panic!()
    };
    assert_eq!(u.reason, UnknownReason::NetworkError);
}

#[tokio::test]
async fn geo_of_one_resolver_is_asked_once() {
    let cache = TtlCache::default();
    let probe = geo_probe("NL");
    let dns = agreeing("203.0.113.9");
    measure_resolver(&dns, &probe, &cache).await;
    measure_resolver(&dns, &probe, &cache).await;
    assert_eq!(probe.calls(), 1);
}

// ---- №11 verdicts ----

fn located(ip_s: &str, cc: &str) -> ResolverView {
    ResolverView::Located {
        ip: ip(ip_s),
        country: cc.into(),
        public_service: None,
        sources: vec![],
    }
}

#[test]
fn same_country_is_ok_with_the_ecs_caveat_and_the_source() {
    let r = evaluate_dns_country(&located("9.9.9.9", "NL"), "nl");
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Ok, "DNS_COUNTRY_CONSISTENT")
    );
    assert!(
        r.message.contains("ECS") && r.message.contains("DNS-over-HTTPS"),
        "{}",
        r.message
    );
    assert_eq!(r.measured_via.as_deref(), Some(MEASURED_VIA));
}

#[test]
fn another_country_is_a_warning() {
    let r = evaluate_dns_country(&located("77.88.8.8", "RU"), "NL");
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "DNS_COUNTRY_SPLIT")
    );
    assert!(r.message.contains("RU") && r.message.contains("NL") && r.message.contains("ECS"));
    assert_eq!(r.measured_via.as_deref(), Some("whoami:akamai+google"));
}

#[test]
fn unmeasured_resolver_or_exit_is_unknown_never_ok() {
    let u = ResolverView::Unmeasured(Unmeasured {
        code: "DNS_WHOAMI_TIMEOUT",
        reason: UnknownReason::Timeout,
        detail: "x".into(),
        sources: vec![],
    });
    let r = evaluate_dns_country(&u, "NL");
    assert_eq!(
        (r.status, r.reason, r.code.as_str()),
        (
            CheckStatus::Unknown,
            Some(UnknownReason::NotApplicable),
            "DNS_COUNTRY_UNMEASURED"
        )
    );
    assert!(r.is_not_applicable());
    let single = ResolverView::Unmeasured(Unmeasured {
        code: "DNS_WHOAMI_SINGLE_SOURCE",
        reason: UnknownReason::NoData,
        detail: "ответил только один источник (Akamai)".into(),
        sources: vec![],
    });
    let r_single = evaluate_dns_country(&single, "NL");
    assert_eq!(
        (r_single.status, r_single.reason, r_single.code.as_str()),
        (
            CheckStatus::Unknown,
            Some(UnknownReason::NotApplicable),
            "DNS_COUNTRY_UNMEASURED"
        )
    );
    for exit in ["", "  ", "T1", "XXX"] {
        let r = evaluate_dns_country(&located("9.9.9.9", "NL"), exit);
        assert_eq!(
            (r.status, r.reason),
            (CheckStatus::Unknown, Some(UnknownReason::NoData)),
            "{exit:?}"
        );
    }
}

// ---- public DNS services ----

#[test]
fn public_dns_services_are_told_by_asn_or_organisation() {
    let cases = [
        (Some(15169), None, Some("Google Public DNS")),
        (None, Some("Google LLC"), Some("Google Public DNS")),
        (Some(13335), Some("Cloudflare, Inc."), Some("Cloudflare")),
        (None, Some("CLOUDFLARENET"), Some("Cloudflare")),
        (Some(19281), None, Some("Quad9")),
        (None, Some("Quad9 Foundation"), Some("Quad9")),
        (Some(36692), None, Some("Cisco OpenDNS")),
        (None, Some("Cisco OpenDNS, LLC"), Some("Cisco OpenDNS")),
        // An ordinary provider, a missing answer, a plain "Cisco" are not public DNS.
        (Some(8359), Some("MTS PJSC"), None),
        (Some(3320), Some("Deutsche Telekom AG"), None),
        (None, Some("Cisco Systems"), None),
        (None, None, None),
    ];
    for (asn, org, want) in cases {
        assert_eq!(public_dns_service(asn, org), want, "{asn:?} {org:?}");
    }
}

#[test]
fn geo_answers_of_all_three_services_give_asn_and_organisation() {
    let w = parse_ipwhois(
        "{\"success\":true,\"country_code\":\"US\",\"connection\":{\"asn\":15169,\"org\":\"Google LLC\",\"isp\":\"Google\"}}",
    )
    .unwrap();
    assert_eq!(
        (w.country.as_str(), w.asn, w.org.as_deref()),
        ("US", Some(15169), Some("Google LLC"))
    );
    let i = parse_ipinfo(
        "{\"ip\":\"1.1.1.1\",\"country\":\"AU\",\"org\":\"AS13335 Cloudflare, Inc.\"}",
    )
    .unwrap();
    assert_eq!((i.country.as_str(), i.asn), ("AU", Some(13335)));
    assert!(i.org.as_deref().unwrap().contains("Cloudflare"));
    let f = parse_freeipapi(
        "{\"countryCode\":\"US\",\"asn\":\"AS36692\",\"asnOrganization\":\"Cisco OpenDNS, LLC\"}",
    )
    .unwrap();
    assert_eq!(
        (f.asn, f.org.as_deref()),
        (Some(36692), Some("Cisco OpenDNS, LLC"))
    );
    // A country without ASN data is still a geo answer.
    let bare = parse_ipwhois("{\"success\":true,\"country_code\":\"NL\"}").unwrap();
    assert_eq!((bare.asn, bare.org), (None, None));
}

fn probe_with_org(cc: &str, asn: u32, org: &str) -> FakeProbe {
    FakeProbe::body(
        200,
        &format!(
            "{{\"success\":true,\"country_code\":\"{cc}\",\"connection\":{{\"asn\":{asn},\"org\":\"{org}\"}}}}"
        ),
    )
}

#[tokio::test]
async fn the_resolver_is_marked_as_a_public_service_from_the_same_geo_answer() {
    // An address outside of the built-in ranges: only the geo answer tells the operator.
    let probe = probe_with_org("US", 15169, "Google LLC");
    let view = measure(agreeing("35.199.1.1"), &probe).await;
    assert_eq!(
        parts(&view),
        (ip("35.199.1.1"), "US", Some("Google Public DNS"))
    );
    assert_eq!(probe.calls(), 1, "no extra request for the ASN");
    let plain = measure(
        agreeing("203.0.113.53"),
        &probe_with_org("DE", 3320, "Deutsche Telekom AG"),
    )
    .await;
    let ResolverView::Located { public_service, .. } = plain else {
        panic!()
    };
    assert_eq!(public_service, None);
}

#[test]
fn country_of_a_public_resolver_is_not_applicable_not_a_warning() {
    let view = ResolverView::Located {
        ip: ip("1.1.1.1"),
        country: "AU".into(),
        public_service: Some("Cloudflare"),
        sources: vec![],
    };
    let r = evaluate_dns_country(&view, "NL");
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::NotApplicable))
    );
    assert!(r.is_not_applicable());
    assert_eq!(r.code, "DNS_COUNTRY_PUBLIC_RESOLVER");
    assert!(
        r.message.contains("Cloudflare")
            && r.message.contains("anycast")
            && r.message.contains("ECS")
    );
}

#[test]
fn bug2_and_bug3_dns_country_guide_ref_and_zastava_key_preconditions() {
    use crate::auditor::geo_matrix::GUIDE_OS_NETWORK;
    use crate::auditor::leaks::AuditProtectionContext;

    let ru_view = located("77.88.8.8", "RU");
    let gb_view = located("81.2.69.142", "GB");

    // Bug #2: DNS_COUNTRY_SPLIT must point to GUIDE_OS_NETWORK.
    let split = evaluate_dns_country(&ru_view, "NL");
    assert_eq!(split.code, "DNS_COUNTRY_SPLIT");
    assert_eq!(split.guide_ref.as_deref(), Some(GUIDE_OS_NETWORK));

    let healthy = AuditProtectionContext {
        route_usable: true,
        sysproxy_active: true,
        cli_or_sandbox_protection_active: false,
        os_pac_deferred: false,
    };
    let cli_only = AuditProtectionContext {
        route_usable: true,
        sysproxy_active: false,
        cli_or_sandbox_protection_active: true,
        os_pac_deferred: false,
    };

    // Bug #3: via_zastava_key + all 3 preconditions pass -> Ok with non-AI OS DNS explanation.
    for ctx in [healthy, cli_only] {
        let ru_ok = evaluate_dns_country_for_route_with_protection(&ru_view, "NL", true, ctx);
        assert_eq!(
            (ru_ok.status, ru_ok.code.as_str()),
            (CheckStatus::Ok, "DNS_COUNTRY_KEY_ISOLATED")
        );
        assert!(ru_ok.message.contains("non-AI") && ru_ok.message.contains("DNS ОС"));

        let gb_ok = evaluate_dns_country_for_route_with_protection(&gb_view, "FR", true, ctx);
        assert_eq!(
            (gb_ok.status, gb_ok.code.as_str()),
            (CheckStatus::Ok, "DNS_KEY_COUNTRY_ISOLATED")
        );
        assert!(gb_ok.message.contains("non-AI") && gb_ok.message.contains("DNS ОС"));
    }

    // Failing any precondition -> Warning("DNS_COUNTRY_SPLIT").
    let failing_cases = [
        AuditProtectionContext {
            route_usable: false,
            ..healthy
        },
        AuditProtectionContext {
            route_usable: true,
            sysproxy_active: false,
            cli_or_sandbox_protection_active: false,
            os_pac_deferred: false,
        },
        AuditProtectionContext {
            os_pac_deferred: true,
            ..healthy
        },
    ];
    for bad in failing_cases {
        let res = evaluate_dns_country_for_route_with_protection(&ru_view, "NL", true, bad);
        assert_eq!(
            (res.status, res.code.as_str()),
            (CheckStatus::Warning, "DNS_COUNTRY_SPLIT")
        );
    }

    // Direct mode (via_zastava_key == false) preserves strictness even with healthy flags.
    let direct_ru = evaluate_dns_country_for_route_with_protection(&ru_view, "NL", false, healthy);
    assert_eq!(
        (direct_ru.status, direct_ru.code.as_str()),
        (CheckStatus::Warning, "DNS_COUNTRY_SPLIT")
    );
}
