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

fn probe_with_org(cc: &str, asn: u32, org: &str) -> FakeProbe {
    FakeProbe::body(
        200,
        &format!(
            "{{\"success\":true,\"country_code\":\"{cc}\",\"connection\":{{\"asn\":{asn},\"org\":\"{org}\"}}}}"
        ),
    )
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
        .with(AKAMAI_HOST, addr("203.0.113.5"))
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

    // Even when one source is Google Public DNS, a non-Google/RU resolver must stay Fail-Closed.
    let ru_split = FakeDns::new(LookupOutcome::Failed)
        .with(AKAMAI_HOST, addr("8.8.8.8"))
        .with_txt(GOOGLE_TXT_HOST, txt("77.88.8.8"));
    let yandex_probe = probe_with_org("RU", 13238, "Yandex LLC");
    let view = measure(ru_split, &yandex_probe).await;
    let ResolverView::Unmeasured(u) = view else {
        panic!("{view:?}")
    };
    assert_eq!(
        (u.code, u.reason),
        ("DNS_WHOAMI_DISAGREE", UnknownReason::NoData)
    );
}

#[tokio::test]
async fn google_public_dns_and_google_asn_egress_agree_while_non_google_stays_disagree() {
    // 8.8.8.8 (Google Public DNS CIDR) + 35.199.1.1 (outside static CIDRs, but AS15169 Google LLC).
    let dns = two("8.8.8.8", "35.199.1.1");
    let probe = probe_with_org("US", 15169, "Google LLC");
    let view = measure(dns, &probe).await;
    assert_eq!(parts(&view), (ip("8.8.8.8"), "", Some("Google Public DNS")));
    assert_eq!(probe.calls(), 1);
    let ResolverView::Located { sources, .. } = &view else {
        panic!()
    };
    assert_eq!(sources[0].operator.as_deref(), Some("Google Public DNS"));
    assert_eq!(sources[1].operator.as_deref(), Some("Google Public DNS"));

    // Reverse order (Akamai unlisted Google ASN 396982, Google TXT in Google Public DNS CIDR).
    let dns_rev = two("35.199.2.2", "74.125.99.1");
    let probe_rev = probe_with_org("NL", 396982, "Google Cloud");
    let view_rev = measure(dns_rev, &probe_rev).await;
    assert_eq!(
        parts(&view_rev),
        (ip("74.125.99.1"), "", Some("Google Public DNS"))
    );

    // Org name keyword alone without Google ASN must NOT bypass Fail-Closed.
    let spoof_org = two("8.8.8.8", "203.0.113.99");
    let fake_google_org = probe_with_org("RU", 8359, "Fake Google Tunnel");
    let view_bad = measure(spoof_org, &fake_google_org).await;
    assert!(matches!(
        view_bad,
        ResolverView::Unmeasured(ref u) if u.code == "DNS_WHOAMI_DISAGREE"
    ));
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
