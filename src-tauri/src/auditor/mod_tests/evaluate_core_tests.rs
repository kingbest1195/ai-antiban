use super::*;

#[tokio::test]
async fn evaluate_all_with_substituted_probes_all_timing_out_is_incomplete() {
    let report = audit(
        env_of(
            FakeDns::new(LookupOutcome::Timeout),
            FakeProbe::new(HttpProbeOutcome::Timeout),
            FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::healthy()
            },
        ),
        rich_telemetry(),
    )
    .await;
    assert_eq!(report.checks.len(), 14);
    assert!(report.dnsbl_result.is_unknown());
    assert_eq!(report.dnsbl_result.reason, Some(UnknownReason::Timeout));
    assert!(report.ipv6_result.status.is_ok());
    assert_eq!(report.ipv6_result.code, "IPV6_BLOCKED_OR_TIMEOUT");
    // The real DNS resolver, its country and the UDP probe could not be measured either.
    for i in [6, 10, 12] {
        assert!(
            report.checks[i].is_unknown(),
            "check {i}: {:?}",
            report.checks[i]
        );
        assert_eq!(
            report.checks[i].reason,
            Some(UnknownReason::Timeout),
            "check {i}"
        );
    }
    assert!(report.checks.iter().all(|c| c.checked_at.is_some()));
    assert!(report.incomplete);
    assert!(report.unknown_count >= 4, "{}", report.unknown_count);
    assert!(report.trust_score <= 94);
    assert!(!(report.overall_status == OverallStatus::Green && report.trust_score == 100));
}

/// Nothing reachable: network checks are Unknown except IPv6 ConnectFailed (no IPv6 leak).
#[tokio::test]
async fn evaluate_all_internet_off_every_network_check_is_unknown() {
    let report = audit(
        env_of(
            FakeDns::new(LookupOutcome::Failed),
            FakeProbe::new(HttpProbeOutcome::ConnectFailed),
            FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::offline()
            },
        ),
        // Only the cached egress is left; its metadata is missing as in the 1.1.1.1 fallback.
        trace_only_telemetry(),
    )
    .await;
    let names = [
        (13, "claude exit"),
        (12, "udp stun"),
        (3, "dnsbl"),
        (4, "asn"),
        (6, "dns"),
        (7, "timezone"),
        (9, "reverse dns"),
        (10, "dns country"),
        (11, "locale"),
    ];
    for (i, name) in names {
        assert!(
            report.checks[i].is_unknown(),
            "{name}: {:?}",
            report.checks[i]
        );
        assert!(
            !report.checks[i].is_not_applicable(),
            "{name} must be a real Unknown"
        );
    }
    assert!(report.checks[5].status.is_ok());
    assert_eq!(report.checks[5].code, "IPV6_UNREACHABLE_SAFE");
    // Not applicable here: pinning off, first session, no location setting on this host.
    for i in [1, 2, 8] {
        assert!(
            report.checks[i].is_not_applicable(),
            "check {i}: {:?}",
            report.checks[i]
        );
    }
    assert_eq!(report.checks.len(), 14);
    assert_eq!(report.unknown_count, 9);
    assert_eq!(report.applicable_count, 11);
    assert!(report.incomplete && report.trust_score <= 94);
}

/// A fallback geolocation answer without metadata must not leave a cascade of green checks.
#[tokio::test]
async fn evaluate_all_trace_fallback_has_no_cascade_of_false_greens() {
    let report = audit(
        env_of(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            FakeProbe::body(200, "loc=NL\n"),
            FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::healthy()
            },
        ),
        trace_only_telemetry(),
    )
    .await;
    // The checks that need ASN / ISP / time zone of the exit IP.
    for i in [4, 7, 9] {
        assert!(
            report.checks[i].is_unknown(),
            "check {i}: {:?}",
            report.checks[i]
        );
        assert_eq!(
            report.checks[i].reason,
            Some(UnknownReason::NoData),
            "check {i}"
        );
    }
    // The checks with their own sources still give an answer.
    assert!(
        report.dnsbl_result.status.is_ok(),
        "{:?}",
        report.dnsbl_result
    );
    assert!(
        report.ipv6_result.status.is_ok(),
        "{:?}",
        report.ipv6_result
    );
    assert!(report.incomplete);
}

/// The progress sink gets the exit address first and every one of the 14 checks exactly once,
/// with the very result that ends up in the final report.
#[tokio::test]
async fn evaluate_all_progress_reports_telemetry_and_each_check_once() {
    let auditor = Auditor::with_env(healthy_env()).unwrap();
    auditor.resolver.set_cached(rich_telemetry()).await;
    let seen: Arc<Mutex<Vec<AuditProgress>>> = Arc::default();
    let sink: ProgressSink = {
        let seen = seen.clone();
        Arc::new(move |p| seen.lock().unwrap().push(p))
    };
    let report = auditor
        .evaluate_all_progress(
            ProviderId::Anthropic,
            &AppState::new_in_memory(),
            false,
            Some(sink),
        )
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert!(matches!(
        seen.first(),
        Some(AuditProgress::Telemetry { .. })
    ));
    let mut indexes: Vec<usize> = Vec::new();
    for p in seen.iter() {
        if let AuditProgress::Check { index, result } = p {
            assert_eq!(result, &report.checks[*index], "check {index}");
            indexes.push(*index);
        }
    }
    indexes.sort_unstable();
    assert_eq!(indexes, (0..CHECK_COUNT).collect::<Vec<_>>());
    // The wire shape the interface reads.
    let json = serde_json::to_value(&seen[1]).unwrap();
    assert_eq!(json["kind"], "check");
}

/// With every source answering, the Ok texts claim only what was verified.
#[tokio::test]
async fn evaluate_all_healthy_sources_state_verified_facts() {
    let report = audit(healthy_env(), rich_telemetry()).await;
    assert_eq!(report.checks.len(), 14);
    assert!(report.dnsbl_result.status.is_ok());
    assert!(
        report.dnsbl_result.message.contains("Ответили 5 из 5"),
        "{}",
        report.dnsbl_result.message
    );
    assert_eq!(report.dnsbl_clean_count, "Ответили 5 из 5 баз");
    assert_eq!(report.ipv6_result.code, "IPV6_ENCAPSULATED");
    assert_eq!(report.timezone_result.code, "TIMEZONE_MATCH");
    // The checks of the real DNS resolver, UDP and provider exit rest on measurements now.
    let (dns, dns_country, udp, exit) = (
        &report.checks[6],
        &report.checks[10],
        &report.checks[12],
        &report.checks[13],
    );
    assert_eq!(dns.code, "DNS_CLEAN");
    assert_eq!(dns_country.code, "DNS_COUNTRY_CONSISTENT");
    assert_eq!(udp.code, "UDP_STUN_MATCH");
    assert_eq!(exit.code, "PROVIDER_EXIT_VERIFIED");
    assert_eq!(dns.measured_via.as_deref(), Some("whoami:akamai+google"));
    assert_eq!(
        dns_country.measured_via.as_deref(),
        Some("whoami:akamai+google")
    );
    assert_eq!(udp.measured_via.as_deref(), Some("stun:cloudflare+google"));
    assert_eq!(exit.measured_via.as_deref(), Some("1.1.1.1"));
    // Only pinning, first session and location do not apply: everything else was verified.
    assert_eq!(report.unknown_count, 0);
    assert_eq!(report.applicable_count, 11);
    assert!(!report.incomplete);
    assert_eq!(
        (report.trust_score, report.overall_status),
        (100, OverallStatus::Green)
    );
}

/// TUN with fake-IP DNS (`198.18.0.0/15`): safe when OS DNS has no Russian ISP / Yandex
/// resolvers (`DNS_TUN_FAKE_IP_SAFE`), while `DNS_COUNTRY_FAKE_IP` stays `NotApplicable`.
/// A loopback stub (`127.0.0.1`) still makes both resolver checks Unknown (`SourceRefused`).
#[tokio::test]
async fn evaluate_all_fake_ip_dns_recognizes_safe_tun_mode_when_os_dns_is_clean() {
    let tun_env = env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "198.18.0.12",
        ),
        probe_locating("NL"),
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
        udp_exiting_as("203.0.113.9"),
    );
    let tun_report = audit(tun_env, rich_telemetry()).await;
    assert_eq!(
        (
            tun_report.checks[6].status,
            tun_report.checks[6].code.as_str()
        ),
        (CheckStatus::Ok, "DNS_TUN_FAKE_IP_SAFE")
    );
    assert_eq!(tun_report.checks[10].code, "DNS_COUNTRY_FAKE_IP");
    assert!(tun_report.checks[10].is_not_applicable());
    assert_eq!(tun_report.unknown_count, 0);
    assert!(!tun_report.incomplete);

    // Localhost stub (127.0.0.1) is NOT a TUN Fake-IP and stays Unknown(SourceRefused).
    let stub_env = env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "127.0.0.1",
        ),
        probe_locating("NL"),
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
        udp_exiting_as("203.0.113.9"),
    );
    let stub_report = audit(stub_env, rich_telemetry()).await;
    for i in [6, 10] {
        let c = &stub_report.checks[i];
        assert_eq!(
            (c.status, c.reason),
            (CheckStatus::Unknown, Some(UnknownReason::SourceRefused)),
            "check {i}: {c:?}"
        );
    }
    assert_eq!(stub_report.unknown_count, 2);
    assert!(stub_report.incomplete && stub_report.trust_score <= 94);
}

/// The resolver is in Russia while the exit is in NL: both DNS checks warn.
#[tokio::test]
async fn evaluate_all_resolver_in_russia_warns_in_both_dns_checks() {
    let env = env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "77.88.8.8",
        ),
        probe_locating("RU"),
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
        udp_exiting_as("203.0.113.9"),
    );
    let report = audit(env, rich_telemetry()).await;
    assert_eq!(report.checks[6].status, CheckStatus::Warning);
    assert_eq!(report.checks[6].code, "DNS_DOMESTIC_WARNING");
    assert_eq!(report.checks[10].status, CheckStatus::Warning);
    assert_eq!(report.checks[10].code, "DNS_COUNTRY_SPLIT");
    assert_eq!(report.overall_status, OverallStatus::Yellow);
}

/// UDP exits through another address than HTTP: a Warning in the 13th check.
#[tokio::test]
async fn evaluate_all_udp_through_another_address_is_a_warning() {
    let env = env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        ),
        probe_locating("NL"),
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
        udp_exiting_as("198.51.100.77"),
    );
    let report = audit(env, rich_telemetry()).await;
    let udp = &report.checks[12];
    assert_eq!(
        (udp.status, udp.code.as_str()),
        (CheckStatus::Warning, "UDP_STUN_MISMATCH")
    );
    assert_eq!(report.overall_status, OverallStatus::Yellow);
    assert!(report.trust_score <= 85);
}

/// A closed UDP is not a leak and, as an auxiliary check, does not stop the automatic admit.
#[tokio::test]
async fn evaluate_all_silent_udp_is_unknown_and_keeps_the_admit() {
    let env = env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        ),
        probe_locating("NL"),
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
        FakeUdp::new(),
    );
    let report = audit(env, rich_telemetry()).await;
    let udp = &report.checks[12];
    assert_eq!(
        (udp.status, udp.reason),
        (CheckStatus::Unknown, Some(UnknownReason::Timeout))
    );
    assert_eq!((report.unknown_count, report.incomplete), (1, true));
    assert_eq!(report.overall_status, OverallStatus::Green);
    assert_eq!(report.trust_score, 94);
}

/// The same exit address is probed over UDP once per minute (and the DNS resolver once per
/// audit round): repeated audits do not repeat the network work.
#[tokio::test]
async fn evaluate_all_repeated_audits_reuse_the_probes() {
    let udp = Arc::new(udp_exiting_as("203.0.113.9"));
    let dns = Arc::new(with_whoami(
        zones_answering(FakeDns::new(LookupOutcome::Timeout)),
        "203.0.113.9",
    ));
    let env = AuditEnv {
        dns: dns.clone(),
        probe: Arc::new(probe_locating("NL")),
        udp: udp.clone(),
        system: Arc::new(FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        }),
    };
    let auditor = Auditor::with_env(env).unwrap();
    auditor.resolver.set_cached(rich_telemetry()).await;
    let state = AppState::new_in_memory();
    for provider in [ProviderId::Anthropic, ProviderId::Anthropic] {
        auditor.evaluate_all(provider, &state, false).await.unwrap();
    }
    assert_eq!(udp.calls(), 2, "two STUN servers, asked once");
}

/// Google Public DNS: the resolver check is Ok, the country check is not applicable (not
/// counted, not penalised), so the report is complete and Green-100.
#[tokio::test]
async fn evaluate_all_public_resolver_is_ok_and_its_country_not_applicable() {
    let probe = with_ai_traces(with_tor_list(FakeProbe::body(200, "loc=NL\n"))).with_route(
        "ipwho.is",
        HttpProbeOutcome::Response {
            status: 200,
            body: "{\"success\":true,\"country_code\":\"US\",\"connection\":{\"asn\":15169,\"org\":\"Google LLC\"}}".into(),
        },
    );
    let env = env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "74.125.40.10",
        ),
        probe,
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
        udp_exiting_as("203.0.113.9"),
    );
    let report = audit(env, rich_telemetry()).await;
    assert_eq!(report.checks[6].code, "DNS_PUBLIC_RESOLVER");
    assert!(report.checks[6].status.is_ok());
    assert!(
        report.checks[10].is_not_applicable(),
        "{:?}",
        report.checks[10]
    );
    assert_eq!((report.unknown_count, report.applicable_count), (0, 10));
    assert!(!report.incomplete);
    assert_eq!(
        (report.trust_score, report.overall_status),
        (100, OverallStatus::Green)
    );
}
/// The Tor list is downloaded once, not once per audit (three services share the cache).
#[tokio::test]
async fn evaluate_all_downloads_the_tor_list_once() {
    let probe = Arc::new(probe_locating("NL"));
    let env = AuditEnv {
        dns: Arc::new(with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        )),
        probe: probe.clone(),
        udp: Arc::new(udp_exiting_as("203.0.113.9")),
        system: Arc::new(FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        }),
    };
    let auditor = Auditor::with_env(env).unwrap();
    auditor.resolver.set_cached(rich_telemetry()).await;
    let state = AppState::new_in_memory();
    let first = auditor
        .evaluate_all(ProviderId::Anthropic, &state, false)
        .await
        .unwrap();
    assert!(!first.asn_result.is_unknown(), "{:?}", first.asn_result);
    let calls_after_first = probe.calls();
    for provider in [ProviderId::Openai, ProviderId::Gemini] {
        let r = auditor.evaluate_all(provider, &state, false).await.unwrap();
        assert_eq!(r.asn_result, first.asn_result);
    }
    assert_eq!(
        probe.calls(),
        calls_after_first + 1,
        "only OpenAI probes 1.1.1.1/cdn-cgi/trace; Tor list, IPv6 and ipwho.is reuse cache"
    );
}

/// An exit over IPv6: the report says so, the spam-list and Tor checks are "not applicable"
/// (neither a pass nor a failure) and the Tor list is not downloaded for them.
#[tokio::test]
async fn evaluate_all_ipv6_exit_marks_the_report_and_the_two_checks_not_applicable() {
    let probe = Arc::new(FakeProbe::new(HttpProbeOutcome::Timeout));
    let env = AuditEnv {
        dns: Arc::new(with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        )),
        probe: probe.clone(),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        }),
    };
    let auditor = Auditor::with_env(env).unwrap();
    let tel = NetworkTelemetry {
        ip: "2001:db8::9".into(),
        ..rich_telemetry()
    };
    auditor.resolver.set_cached(tel).await;
    let report = auditor
        .evaluate_all(ProviderId::Anthropic, &AppState::new_in_memory(), false)
        .await
        .unwrap();
    assert!(report.ipv6_exit);
    assert_eq!(report.checks.len(), 14);
    assert!(
        report.dnsbl_result.is_not_applicable(),
        "{:?}",
        report.dnsbl_result
    );
    assert_eq!(report.dnsbl_result.code, "DNSBL_IPV6_UNSUPPORTED");
    // IPv6 exit continues classification without downloading the IPv4-only Tor list.
    assert_eq!(report.asn_result.status, CheckStatus::Ok);
    assert_eq!(report.asn_result.code, "ASN_CLEAN");
    // The probe times out for everything: had the Tor list been asked for, the check would
    // be a real Unknown (TOR_LIST_UNAVAILABLE), not classified.
    assert_ne!(report.asn_result.code, "TOR_LIST_UNAVAILABLE");
}

/// The exit is a Tor exit: a Warning in the address check, nothing blocks on its own.
#[tokio::test]
async fn evaluate_all_tor_exit_is_a_warning() {
    let probe = FakeProbe::body(200, "loc=NL\n").with_route(
        "torbulkexitlist",
        HttpProbeOutcome::Response {
            status: 200,
            body: "203.0.113.9\n".into(),
        },
    );
    let env = env_of(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        ),
        probe,
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
    );
    let report = audit(env, rich_telemetry()).await;
    assert_eq!(
        (report.asn_result.status, report.asn_result.code.as_str()),
        (CheckStatus::Warning, "IP_TYPE_TOR")
    );
    assert_eq!(report.overall_status, OverallStatus::Yellow);
}

/// The Tor list is unreachable: the address check is a real Unknown (not "Ok", not a block):
/// only the core checks (0 and 2) stop the gateway.
#[tokio::test]
async fn evaluate_all_tor_list_unreachable_is_unknown_and_not_a_core_check() {
    let probe =
        FakeProbe::body(200, "loc=NL\n").with_route("torbulkexitlist", HttpProbeOutcome::Timeout);
    let env = env_of(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        ),
        probe,
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
    );
    let report = audit(env, rich_telemetry()).await;
    let c = &report.asn_result;
    assert_eq!(
        (c.status, c.reason),
        (CheckStatus::Unknown, Some(UnknownReason::Timeout))
    );
    assert_eq!(c.code, "TOR_LIST_UNAVAILABLE");
    assert!(!CORE_CHECKS.contains(&4));
    assert!(report.incomplete);
}

#[tokio::test]
async fn evaluate_all_ipv4_exit_is_not_marked_ipv6() {
    let report = audit(healthy_env(), rich_telemetry()).await;
    assert!(!report.ipv6_exit);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["ipv6_exit"], false);
    assert_eq!(json["asn_result"]["detail"]["ip_type"], "unknown");
}
