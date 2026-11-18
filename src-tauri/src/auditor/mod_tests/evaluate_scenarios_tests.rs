use super::*;

#[test]
fn dns_resolver_transient_unknown_keeps_score_100_and_green() {
    let dns_timeout = CheckResult::unknown("DNS_WHOAMI_TIMEOUT", "t", UnknownReason::Timeout);
    let dns_disagree = CheckResult::unknown("DNS_WHOAMI_DISAGREE", "d", UnknownReason::NoData);
    let v = score_checks(&all_checks(&[(6, dns_timeout), (10, dns_disagree)]), false);
    assert_eq!(v.overall_status, OverallStatus::Green);
    assert_eq!(v.trust_score, 100);
    assert!(!v.incomplete);
    assert_eq!(v.unknown_count, 2);

    // Another unknown check (e.g. udp_stun at 12) still caps at 94 and marks incomplete.
    let v_other = score_checks(
        &all_checks(&[
            (
                6,
                CheckResult::unknown("DNS_WHOAMI_TIMEOUT", "t", UnknownReason::Timeout),
            ),
            (12, unk()),
        ]),
        false,
    );
    assert_eq!(v_other.overall_status, OverallStatus::Green);
    assert_eq!(v_other.trust_score, 94);
    assert!(v_other.incomplete);
    assert_eq!(v_other.unknown_count, 2);
}

#[tokio::test]
async fn evaluate_all_whoami_timeout_keeps_report_green_100() {
    let env = env_with_udp(
        zones_answering(FakeDns::new(LookupOutcome::Timeout)),
        probe_locating("NL"),
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
        udp_exiting_as("203.0.113.9"),
    );
    let report = audit(env, rich_telemetry()).await;
    assert!(report.checks[6].is_unknown());
    assert!(report.checks[10].is_unknown());
    assert_eq!(report.overall_status, OverallStatus::Green);
    assert_eq!(report.trust_score, 100);
    assert!(!report.incomplete);
}

#[tokio::test]
async fn evaluate_all_ipv6_timeout_under_vpn_keeps_report_green_100_not_incomplete() {
    let probe =
        probe_locating("NL").with_route("2606:4700:4700::1111", HttpProbeOutcome::Timeout);
    let env = env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        ),
        probe,
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        },
        udp_exiting_as("203.0.113.9"),
    );
    let report = audit(env, rich_telemetry()).await;
    assert!(report.ipv6_result.status.is_ok());
    assert_eq!(report.ipv6_result.code, "IPV6_BLOCKED_OR_TIMEOUT");
    assert_eq!(report.overall_status, OverallStatus::Green);
    assert_eq!(report.trust_score, 100);
    assert!(!report.incomplete);
    assert_eq!(report.unknown_count, 0);
}

#[tokio::test]
async fn evaluate_all_zastava_key_coexists_with_foreign_vpn_fake_ip_and_doh_dnsbl() {
    use crate::routing::{Entry, EntryProto, Route};

    let route = Route {
        id: "fr-key".into(),
        label: "France Key".into(),
        country: Some("FR".into()),
        exit_ip: Some("136.244.114.42".into()),
        expires_at: None,
        entries: vec![Entry {
            proto: EntryProto::Http,
            host: "127.0.0.1".into(),
            port: 1, // loopback ECONNREFUSED in <1ms so check 13 never waits
            username: None,
            password: None,
            sni: None,
        }],
        raw_key: String::new(),
        enabled: true,
        added_at: 0,
    };

    let state = AppState::new_in_memory();
    state.upsert_route(route.clone()).await.unwrap();
    state
        .bind_provider_route("gemini", Some("fr-key"))
        .await
        .unwrap();
    // Global VPN pin is UK (145.241.193.245), completely distinct from FR key (136.244.114.42).
    state
        .set_pinned_ip_for("default", Some("145.241.193.245".into()))
        .await
        .unwrap();
    state.set_sync_ai_tz_enabled(true).await.unwrap();
    state
        .set_synced_ai_timezone(Some("Europe/London".into()))
        .await
        .unwrap();

    // Simulate Akamai returning Fake-IP 198.18.0.98 while Google TXT sees Cloudflare,
    // AND primary DNSBL zones returning 198.18.0.55 (FakeDNS) rescued by DoH JSON.
    let dns = FakeDns::new(LookupOutcome::Addrs(vec!["198.18.0.55".parse().unwrap()]))
        .with(whoami::AKAMAI_HOST, addr("198.18.0.98"))
        .with_txt(
            whoami::GOOGLE_TXT_HOST,
            TxtOutcome::Records(vec!["\"172.71.240.11\"".into()]),
        );

    let probe = with_tor_list(FakeProbe::body(200, "loc=GB\n"))
        .with_route(
            "ipwho.is",
            HttpProbeOutcome::Response {
                status: 200,
                body: r#"{"success":true,"country_code":"GB"}"#.into(),
            },
        )
        .with_route(
            "name=2.0.0.127.",
            HttpProbeOutcome::Response {
                status: 200,
                body: r#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.2"}]}"#.into(),
            },
        )
        .with_route(
            "dns.google/resolve",
            HttpProbeOutcome::Response {
                status: 200,
                body: r#"{"Status":3}"#.into(),
            },
        );

    let system = FakeSystem {
        timezone: Ok("Europe/Moscow".into()),
        local_offset: Some(3 * 3600),
        sync_ai_tz: true,
        global_ipv6: Some(true),
        ..FakeSystem::healthy()
    };

    let auditor = Auditor::with_env(env_with_udp(
        dns,
        probe,
        system,
        udp_exiting_as("145.241.193.245"),
    ))
    .unwrap();

    let fr_tel = NetworkTelemetry {
        ip: "136.244.114.42".into(),
        country_code: "FR".into(),
        timezone: Some("Europe/Paris".into()),
        ..rich_telemetry()
    };
    auditor
        .resolver
        .set_cached_for_route(Some("fr-key".into()), fr_tel)
        .await;

    let report = auditor
        .evaluate_all_with(
            ProviderId::Gemini,
            &state,
            &RouteSelection::Route(route),
            false,
        )
        .await
        .unwrap();

    assert_eq!(
        (report.checks[1].status, report.checks[1].code.as_str()),
        (CheckStatus::Ok, "PINNED_BY_ZASTAVA_KEY")
    );
    assert_eq!(
        (report.checks[3].status, report.checks[3].code.as_str()),
        (CheckStatus::Ok, "DNSBL_CLEAN")
    );
    assert_eq!(
        (report.checks[5].status, report.checks[5].code.as_str()),
        (CheckStatus::Ok, "IPV6_KEY_TCP_ISOLATED")
    );
    assert_eq!(
        (report.checks[6].status, report.checks[6].code.as_str()),
        (CheckStatus::Ok, "DNS_PUBLIC_RESOLVER")
    );
    assert_eq!(
        (report.checks[7].status, report.checks[7].code.as_str()),
        (CheckStatus::Ok, "TIMEZONE_SYNCED_AI")
    );
    assert_eq!(
        (report.checks[12].status, report.checks[12].code.as_str()),
        (CheckStatus::Ok, "UDP_KEY_TCP_PROTECTED")
    );
}

#[tokio::test]
async fn evaluate_all_force_refresh_clears_os_check_cache() {
    let state = AppState::new_in_memory();
    let env = healthy_env();
    let auditor = Auditor::with_env(env).unwrap();
    auditor.resolver.set_cached(rich_telemetry()).await;

    let _ = auditor
        .evaluate_all(ProviderId::Anthropic, &state, false)
        .await
        .unwrap();
    assert!(!auditor.resolver.check_cache().os.is_empty().await);

    // Pre-seed a stale OS entry; force_refresh=true must clear cache.os before resolving
    // telemetry or evaluating checks.
    let _ = auditor
        .resolver
        .check_cache()
        .os
        .get_or_compute("stale:tz", OS_TTL, |_| true, async {
            CheckResult::warning("STALE", "stale", None)
        })
        .await;
    assert!(
        auditor
            .resolver
            .check_cache()
            .os
            .contains_key("stale:tz")
            .await
    );

    let unreachable_route = crate::routing::Route {
        id: "dead-route".into(),
        label: "Dead".into(),
        country: None,
        exit_ip: None,
        expires_at: None,
        entries: vec![crate::routing::Entry {
            proto: crate::routing::EntryProto::Http,
            host: "127.0.0.1".into(),
            port: 1,
            username: None,
            password: None,
            sni: None,
        }],
        raw_key: String::new(),
        enabled: true,
        added_at: 0,
    };
    let _ = auditor
        .evaluate_all_with(
            ProviderId::Gemini,
            &state,
            &RouteSelection::Route(unreachable_route),
            true,
        )
        .await;
    assert!(
        !auditor
            .resolver
            .check_cache()
            .os
            .contains_key("stale:tz")
            .await
    );
    assert!(auditor.resolver.check_cache().os.is_empty().await);
}

#[tokio::test]
async fn gemini_fr_route_does_not_contaminate_direct_gb_providers() {
    let state = AppState::new_in_memory();
    let fr_route =
        crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
    let fr_sel = RouteSelection::Route(fr_route.clone());
    let fr_id = state.upsert_route(fr_route.clone()).await.unwrap();
    state
        .bind_provider_route("gemini", Some(&fr_id))
        .await
        .unwrap();

    let now = crate::auditor::network::current_timestamp();
    // Prior FR history under Gemini's route, Anthropic's route scope, AND legacy unscoped
    // "anthropic" key — none of these may poison Anthropic/OpenAI on Direct GB VPN.
    state
        .record_ip_history_for_selection(
            "gemini",
            &fr_sel,
            crate::state::IpHistoryEntry::new("136.244.114.42", "FR", Some(16276), now - 120),
        )
        .await
        .unwrap();
    state
        .record_ip_history_for_selection(
            "anthropic",
            &fr_sel,
            crate::state::IpHistoryEntry::new("136.244.114.42", "FR", Some(16276), now - 120),
        )
        .await
        .unwrap();
    state
        .record_ip_history(
            "anthropic",
            crate::state::IpHistoryEntry::new("136.244.114.42", "FR", Some(16276), now - 120),
        )
        .await
        .unwrap();

    let probe = with_tor_list(FakeProbe::body(200, "loc=GB\n"))
        .with_route(
            "1.1.1.1/cdn-cgi/trace",
            HttpProbeOutcome::Response {
                status: 200,
                body: "fl=1\nip=203.0.113.9\nloc=GB\ncolo=LHR\n".into(),
            },
        )
        .with_route(
            "ipwho.is",
            HttpProbeOutcome::Response {
                status: 200,
                body: r#"{"success":true,"country_code":"GB"}"#.into(),
            },
        );
    let system = FakeSystem {
        timezone: Ok("Europe/London".into()),
        local_offset: Some(0),
        global_ipv6: Some(true),
        ..FakeSystem::healthy()
    };
    let env = env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        ),
        probe,
        system,
        udp_exiting_as("203.0.113.9"),
    );
    let auditor = Auditor::with_env(env).unwrap();

    let gb_tel = NetworkTelemetry {
        ip: "203.0.113.9".into(),
        country_code: "GB".into(),
        timezone: Some("Europe/London".into()),
        resolved_at: now,
        ..rich_telemetry()
    };
    let fr_tel = NetworkTelemetry {
        ip: "136.244.114.42".into(),
        country_code: "FR".into(),
        timezone: Some("Europe/Paris".into()),
        resolved_at: now,
        ..rich_telemetry()
    };
    auditor.resolver.set_cached_for_route(None, gb_tel).await;
    auditor
        .resolver
        .set_cached_for_route(Some(fr_id.clone()), fr_tel)
        .await;

    let claude = auditor
        .evaluate_all(ProviderId::Anthropic, &state, false)
        .await
        .unwrap();
    let chatgpt = auditor
        .evaluate_all(ProviderId::Openai, &state, false)
        .await
        .unwrap();
    let gemini = auditor
        .evaluate_all(ProviderId::Gemini, &state, false)
        .await
        .unwrap();

    assert_eq!(claude.telemetry.country_code, "GB");
    assert_ne!(claude.checks[2].status, CheckStatus::Critical);
    assert_ne!(claude.checks[2].code, "IMPOSSIBLE_TRAVEL_CRITICAL");
    assert_eq!(claude.overall_status, OverallStatus::Green);

    assert_eq!(chatgpt.telemetry.country_code, "GB");
    assert_ne!(chatgpt.checks[2].status, CheckStatus::Warning);
    assert_eq!(chatgpt.overall_status, OverallStatus::Green);

    // Gemini resolves on its FR route without seeing GB VPN as an impossible jump.
    assert_eq!(gemini.telemetry.country_code, "FR");
    assert_eq!(gemini.checks[2].code, "TRAVEL_NORMAL");
    assert_eq!(gemini.checks[2].status, CheckStatus::Ok);
}

#[tokio::test]
async fn evaluate_all_applies_pinned_travel_grace_without_hiding_unpinned_or_sanctioned() {
    let state = AppState::new_in_memory();
    let now = crate::auditor::network::current_timestamp();
    for p in ["anthropic", "openai"] {
        state
            .record_ip_history_for_selection(
                p,
                &RouteSelection::Direct,
                crate::state::IpHistoryEntry::new("198.51.100.1", "DE", Some(1234), now - 300),
            )
            .await
            .unwrap();
    }
    state
        .set_pinned_ip(Some("203.0.113.9".to_string()))
        .await
        .unwrap();

    let probe = with_tor_list(FakeProbe::body(200, "loc=GB\n"))
        .with_route(
            "1.1.1.1/cdn-cgi/trace",
            HttpProbeOutcome::Response {
                status: 200,
                body: "fl=1\nip=203.0.113.9\nloc=GB\ncolo=LHR\n".into(),
            },
        )
        .with_route(
            "ipwho.is",
            HttpProbeOutcome::Response {
                status: 200,
                body: r#"{"success":true,"country_code":"GB"}"#.into(),
            },
        );
    let system = FakeSystem {
        timezone: Ok("Europe/London".into()),
        local_offset: Some(0),
        global_ipv6: Some(true),
        ..FakeSystem::healthy()
    };
    let env = env_with_udp(
        with_whoami(
            zones_answering(FakeDns::new(LookupOutcome::Timeout)),
            "203.0.113.9",
        ),
        probe,
        system,
        udp_exiting_as("203.0.113.9"),
    );
    let auditor = Auditor::with_env(env).unwrap();
    auditor
        .resolver
        .set_cached_for_route(
            None,
            NetworkTelemetry {
                ip: "203.0.113.9".into(),
                country_code: "GB".into(),
                timezone: Some("Europe/London".into()),
                resolved_at: now,
                ..rich_telemetry()
            },
        )
        .await;

    let claude_pinned = auditor
        .evaluate_all(ProviderId::Anthropic, &state, false)
        .await
        .unwrap();
    let openai_pinned = auditor
        .evaluate_all(ProviderId::Openai, &state, false)
        .await
        .unwrap();
    assert_eq!(claude_pinned.travel_result.code, "TRAVEL_PINNED_RETURN");
    assert_eq!(claude_pinned.checks[2].code, "TRAVEL_PINNED_RETURN");
    assert_eq!(claude_pinned.overall_status, OverallStatus::Green);
    assert_eq!(openai_pinned.travel_result.code, "TRAVEL_PINNED_RETURN");
    assert_eq!(openai_pinned.checks[2].code, "TRAVEL_PINNED_RETURN");
    assert_eq!(openai_pinned.overall_status, OverallStatus::Green);

    // Unpinning restores IMPOSSIBLE_TRAVEL_CRITICAL / IMPOSSIBLE_TRAVEL_WARNING.
    state.clear_all_pinned_ips().await.unwrap();
    let claude_unpinned = auditor
        .evaluate_all(ProviderId::Anthropic, &state, false)
        .await
        .unwrap();
    let openai_unpinned = auditor
        .evaluate_all(ProviderId::Openai, &state, false)
        .await
        .unwrap();
    assert_eq!(claude_unpinned.travel_result.code, "IMPOSSIBLE_TRAVEL_CRITICAL");
    assert_eq!(claude_unpinned.overall_status, OverallStatus::Red);
    assert_eq!(openai_unpinned.travel_result.code, "IMPOSSIBLE_TRAVEL_WARNING");
    assert_eq!(openai_unpinned.overall_status, OverallStatus::Yellow);
}
