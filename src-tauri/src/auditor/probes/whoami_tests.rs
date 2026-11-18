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

#[test]
fn special_addresses_are_recognised() {
    for s in [
        "198.18.0.7",
        "198.19.255.1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.9.9",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fd00::53",
        "::ffff:10.0.0.1",
    ] {
        assert!(is_special_addr(&ip(s)), "{s}");
    }
    for s in [
        "8.8.8.8",
        "77.88.8.8",
        "172.32.0.1",
        "100.128.0.1",
        "198.17.0.1",
        "198.20.0.1",
        "203.0.113.5",
        "2001:4860:4860::8888",
    ] {
        assert!(!is_special_addr(&ip(s)), "{s}");
    }
}

#[test]
fn google_txt_answer_is_parsed_and_the_subnet_record_skipped() {
    assert_eq!(
        google_reading(&txt("\"74.125.40.1\"")),
        SourceReading::Addr(ip("74.125.40.1"))
    );
    let with_ecs = TxtOutcome::Records(vec![
        "edns0-client-subnet 203.0.113.0/24".into(),
        "\"2a00:1450:4001::1\"".into(),
    ]);
    assert_eq!(
        google_reading(&with_ecs),
        SourceReading::Addr(ip("2a00:1450:4001::1"))
    );
    assert_eq!(google_reading(&txt("not an address")), SourceReading::Empty);
    assert_eq!(
        google_reading(&txt("\"10.0.0.2\"")),
        SourceReading::Special(ip("10.0.0.2"))
    );
    assert_eq!(google_reading(&TxtOutcome::NotFound), SourceReading::Empty);
}

/// `(ip, country, public_service)` of a located resolver.
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
async fn agreeing_sources_give_a_located_resolver() {
    let view = measure(agreeing("77.88.8.8"), &geo_probe("RU")).await;
    assert_eq!(parts(&view), (ip("77.88.8.8"), "RU", None));
    let ResolverView::Located { sources, .. } = &view else {
        panic!()
    };
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].source, "Akamai");
    assert_eq!(sources[1].addr.as_deref(), Some("77.88.8.8"));
}

#[tokio::test]
async fn two_addresses_of_one_resolver_pool_still_agree() {
    // The same /24 outside of any public DNS range: the geo answer places it.
    let dns = FakeDns::new(LookupOutcome::Failed)
        .with(AKAMAI_HOST, addr("203.0.113.10"))
        .with_txt(GOOGLE_TXT_HOST, txt("203.0.113.77"));
    let view = measure(dns, &geo_probe("US")).await;
    assert_eq!(parts(&view), (ip("203.0.113.10"), "US", None));
}

fn two(akamai: &str, google: &str) -> FakeDns {
    FakeDns::new(LookupOutcome::Failed)
        .with(AKAMAI_HOST, addr(akamai))
        .with_txt(GOOGLE_TXT_HOST, txt(&format!("\"{google}\"")))
}

#[tokio::test]
async fn owner_case_two_cloudflare_addresses_agree_without_a_geo_request() {
    // Akamai and Google reached the same resolver from different addresses of its fleet.
    let probe = geo_probe("US");
    let view = measure(two("172.70.161.26", "172.71.240.11"), &probe).await;
    assert_eq!(parts(&view), (ip("172.70.161.26"), "", Some("Cloudflare")));
    assert_eq!(probe.calls(), 0);
    let ResolverView::Located { sources, .. } = &view else {
        panic!()
    };
    assert_eq!(sources[0].operator.as_deref(), Some("Cloudflare"));
    assert_eq!(sources[1].addr.as_deref(), Some("172.71.240.11"));
    assert!(same_operator_note(sources, "Cloudflare").contains("172.71.240.11"));
}

#[tokio::test]
async fn owner_case_ends_as_ok_public_dns_with_both_sources_in_the_detail() {
    let view = measure(two("172.70.161.26", "172.71.240.11"), &geo_probe("US")).await;
    let config = CheckResult::ok("DNS_CONFIG_OK", "в настройках ОС всё чисто");
    let r = crate::auditor::leaks::evaluate_dns_resolver(config, &view, "NL");
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Ok, "DNS_PUBLIC_RESOLVER")
    );
    assert!(
        r.message
            .starts_with("Резолвер: Cloudflare (публичный DNS)"),
        "{}",
        r.message
    );
    assert!(r.message.contains("172.70.161.26") && r.message.contains("172.71.240.11"));
    let sources = r.detail.expect("detail").sources;
    assert_eq!(sources.len(), 2);
    assert!(
        sources
            .iter()
            .all(|s| s.operator.as_deref() == Some("Cloudflare"))
    );
    // The country check does not penalise it: not applicable.
    let c = evaluate_dns_country(&view, "NL");
    assert!(c.is_not_applicable());
    // The detail survives the JSON the interface reads.
    let json = serde_json::to_value(&c).unwrap();
    assert_eq!(json["detail"]["sources"][0]["source"], "Akamai");
    assert_eq!(json["detail"]["sources"][0]["state"], "answered");
}

#[tokio::test]
async fn one_operator_in_one_range_of_google_or_in_ipv6_agrees() {
    let probe = geo_probe("US");
    let google = measure(two("74.125.40.10", "74.125.99.1"), &probe).await;
    assert_eq!(parts(&google).2, Some("Google Public DNS"));
    let v6 = measure(two("2606:4700:4700::1111", "2606:4700:4700::1001"), &probe).await;
    assert_eq!(parts(&v6).2, Some("Cloudflare"));
    let mixed_family = measure(two("1.1.1.1", "2606:4700:4700::1111"), &probe).await;
    assert_eq!(parts(&mixed_family).2, Some("Cloudflare"));
    assert_eq!(probe.calls(), 0);
}

#[tokio::test]
async fn different_operators_stay_unknown_and_explain_both_sources() {
    let probe = geo_probe("US");
    let view = measure(two("172.70.161.26", "8.8.8.8"), &probe).await;
    let ResolverView::Unmeasured(u) = view else {
        panic!("{view:?}")
    };
    assert_eq!(u.code, "DNS_WHOAMI_DISAGREE");
    assert!(u.detail.contains("Cloudflare") && u.detail.contains("Google Public DNS"));
    assert_eq!(u.sources.len(), 2);
    assert_eq!(u.sources[0].operator.as_deref(), Some("Cloudflare"));
    assert_eq!(u.sources[1].operator.as_deref(), Some("Google Public DNS"));
    assert_eq!(probe.calls(), 0);
    // An unknown operator on one side is not an agreement either.
    let view = measure(two("172.70.161.26", "203.0.113.5"), &probe).await;
    assert!(matches!(view, ResolverView::Unmeasured(ref u) if u.code == "DNS_WHOAMI_DISAGREE"));
}

#[tokio::test]
async fn fake_ip_paired_with_public_txt_resolves_public_dns_while_single_source_is_unknown() {
    let probe = geo_probe("US");
    // Akamai Fake-IP + Google TXT Cloudflare -> resolves Cloudflare (not DNS_WHOAMI_FAKE_IP).
    let mixed = measure(two("198.18.0.98", "172.71.240.11"), &probe).await;
    let ResolverView::Located {
        ip: res_ip,
        public_service,
        sources,
        ..
    } = mixed
    else {
        panic!("expected Located when TXT returns public resolver, got {mixed:?}");
    };
    assert_eq!(res_ip.to_string(), "172.71.240.11");
    assert_eq!(public_service, Some("Cloudflare"));
    assert_eq!(sources[0].state, SourceState::Special);
    assert_eq!(sources[1].state, SourceState::Answered);

    // One silent source without another public/special answer is still Unknown.
    let dns = FakeDns::new(LookupOutcome::Failed)
        .with(AKAMAI_HOST, addr("172.70.161.26"))
        .with_txt(GOOGLE_TXT_HOST, TxtOutcome::Timeout);
    let ResolverView::Unmeasured(u) = measure(dns, &probe).await else {
        panic!()
    };
    assert_eq!(u.code, "DNS_WHOAMI_SINGLE_SOURCE");
    assert_eq!(u.sources[1].state, SourceState::Timeout);
    assert_eq!(u.sources[0].addr.as_deref(), Some("172.70.161.26"));
}

#[test]
fn dns_country_of_an_unmeasured_resolver_carries_the_sources() {
    let u = combine_sources(
        &SourceReading::Addr(ip("172.70.161.26")),
        &SourceReading::Addr(ip("8.8.8.8")),
    )
    .unwrap_err();
    let r = evaluate_dns_country(&ResolverView::Unmeasured(u), "NL");
    assert_eq!(r.status, CheckStatus::Unknown);
    assert_eq!(r.detail.as_ref().map(|d| d.sources.len()), Some(2));
}

#[tokio::test]
async fn disagreeing_sources_are_unknown() {
    let dns = FakeDns::new(LookupOutcome::Failed)
        .with(AKAMAI_HOST, addr("8.8.8.8"))
        .with_txt(GOOGLE_TXT_HOST, txt("77.88.8.8"));
    let probe = geo_probe("US");
    let view = measure(dns, &probe).await;
    let ResolverView::Unmeasured(u) = view else {
        panic!("{view:?}")
    };
    assert_eq!(
        (u.code, u.reason),
        ("DNS_WHOAMI_DISAGREE", UnknownReason::NoData)
    );
    assert_eq!(
        probe.calls(),
        0,
        "no geo request for an unconfirmed address"
    );
}

#[tokio::test]
async fn silent_sources_are_unknown_with_a_reason() {
    let cases = [
        (
            LookupOutcome::Timeout,
            TxtOutcome::Timeout,
            UnknownReason::Timeout,
        ),
        (
            LookupOutcome::Failed,
            TxtOutcome::Failed,
            UnknownReason::NetworkError,
        ),
        (
            LookupOutcome::NotFound,
            TxtOutcome::NotFound,
            UnknownReason::EmptyResponse,
        ),
        (
            LookupOutcome::Failed,
            TxtOutcome::Unsupported,
            UnknownReason::NetworkError,
        ),
        (
            LookupOutcome::NotFound,
            TxtOutcome::Unsupported,
            UnknownReason::UnsupportedOs,
        ),
    ];
    for (a, g, want) in cases {
        let dns = FakeDns::new(LookupOutcome::Failed)
            .with(AKAMAI_HOST, a.clone())
            .with_txt(GOOGLE_TXT_HOST, g.clone());
        let view = measure(dns, &geo_probe("NL")).await;
        let ResolverView::Unmeasured(u) = view else {
            panic!("{a:?} {g:?}")
        };
        assert_eq!(u.reason, want, "{a:?} {g:?}");
    }
}

#[tokio::test]
async fn one_silent_source_is_not_a_confirmation() {
    let dns = FakeDns::new(LookupOutcome::Failed)
        .with(AKAMAI_HOST, addr("8.8.8.8"))
        .with_txt(GOOGLE_TXT_HOST, TxtOutcome::Timeout);
    let view = measure(dns, &geo_probe("US")).await;
    let ResolverView::Unmeasured(u) = view else {
        panic!()
    };
    assert_eq!(
        (u.code, u.reason),
        ("DNS_WHOAMI_SINGLE_SOURCE", UnknownReason::NoData)
    );
}

#[tokio::test]
async fn fake_ip_and_private_answers_are_source_refused() {
    for fake in [
        "198.18.0.9",
        "10.0.0.2",
        "192.168.1.1",
        "100.64.3.3",
        "127.0.0.1",
        "169.254.2.2",
    ] {
        let view = measure(agreeing(fake), &geo_probe("NL")).await;
        let ResolverView::Unmeasured(u) = view else {
            panic!("{fake}")
        };
        assert_eq!(
            (u.code, u.reason),
            ("DNS_WHOAMI_FAKE_IP", UnknownReason::SourceRefused),
            "{fake}"
        );
    }
    // One Fake-IP + one public resolver uses the valid public resolver reading.
    let dns = FakeDns::new(LookupOutcome::Failed)
        .with(AKAMAI_HOST, addr("198.18.0.9"))
        .with_txt(GOOGLE_TXT_HOST, txt("8.8.8.8"));
    let view = measure(dns, &geo_probe("NL")).await;
    assert!(matches!(
        view,
        ResolverView::Located {
            public_service: Some("Google Public DNS"),
            ..
        }
    ));

    // Fake-IP + IPv6 Cloudflare TXT also locates the resolver.
    let dns_v6 = FakeDns::new(LookupOutcome::Failed)
        .with(AKAMAI_HOST, addr("198.18.0.98"))
        .with_txt(GOOGLE_TXT_HOST, txt("2400:cb00:989:1024::a29e:d50e"));
    let view_v6 = measure(dns_v6, &geo_probe("NL")).await;
    assert!(matches!(view_v6, ResolverView::Located { .. }));

    // Both TUN Fake-IP -> DNS_COUNTRY_FAKE_IP (NotApplicable) & DNS country route isolation.
    let both_fake = measure(two("198.18.0.12", "198.18.0.13"), &geo_probe("NL")).await;
    let fake_country = evaluate_dns_country_for_route(&both_fake, "FR", false);
    assert_eq!(fake_country.code, "DNS_COUNTRY_FAKE_IP");
    assert_eq!(fake_country.reason, Some(UnknownReason::NotApplicable));

    let gb_resolver = ResolverView::Located {
        ip: ip("81.2.69.142"),
        country: "GB".to_string(),
        public_service: None,
        sources: vec![],
    };
    assert_eq!(
        evaluate_dns_country_for_route(&gb_resolver, "FR", false).status,
        CheckStatus::Warning
    );
    let routed_country = evaluate_dns_country_for_route(&gb_resolver, "FR", true);
    assert_eq!(
        (routed_country.status, routed_country.code.as_str()),
        (CheckStatus::Ok, "DNS_KEY_COUNTRY_ISOLATED")
    );
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
        let ResolverView::Unmeasured(u) = measure(dns(), &FakeProbe::body(200, body)).await
        else {
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
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::Timeout))
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
    let f = parse_freeipapi("{\"countryCode\":\"US\",\"asn\":\"AS36692\",\"asnOrganization\":\"Cisco OpenDNS, LLC\"}").unwrap();
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
