use super::*;

#[test]
fn progress_event_is_one_flat_object_the_interface_reads() {
    let event = AuditProgressEvent {
        run_id: "r1",
        provider: "anthropic",
        progress: auditor::AuditProgress::Check {
            index: 6,
            result: auditor::CheckResult::ok("DNS_PUBLIC_RESOLVER", "ok"),
        },
    };
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["run_id"], "r1");
    assert_eq!(json["provider"], "anthropic");
    assert_eq!(json["kind"], "check");
    assert_eq!(json["index"], 6);
    assert_eq!(json["result"]["code"], "DNS_PUBLIC_RESOLVER");
}

#[test]
fn verify_unblock_decision_respects_killswitch_geo_and_critical_checks() {
    let ok = auditor::CheckResult::ok("T", "t");
    let base_report = |status: auditor::OverallStatus, cc: &str| auditor::RiskReport {
        provider: auditor::ProviderId::Openai,
        overall_status: status,
        trust_score: 90,
        telemetry: auditor::NetworkTelemetry {
            ip: "1.1.1.1".into(),
            country_code: cc.into(),
            hostname: None,
            asn: Some(1),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: 0,
        },
        geo_result: ok.clone(),
        pinning_result: ok.clone(),
        travel_result: ok.clone(),
        dnsbl_result: ok.clone(),
        dnsbl_clean_count: "0/0".into(),
        asn_result: ok.clone(),
        ipv6_result: ok.clone(),
        timezone_result: ok.clone(),
        ipv6_exit: false,
        checks: vec![ok.clone()],
        unknown_count: 0,
        applicable_count: 14,
        incomplete: false,
    };

    let base_state = state::AppStateData::default();
    let green = base_report(auditor::OverallStatus::Green, "NL");
    assert!(should_verify_unblock(false, &green, &base_state, false));
    assert!(!should_verify_unblock(true, &green, &base_state, false));

    // Non-critical Yellow warning on allowed geo / pinned IP succeeds.
    let mut yellow = base_report(auditor::OverallStatus::Yellow, "NL");
    yellow.checks = vec![
        ok.clone(),
        auditor::CheckResult::warning("TZ", "diff", None),
    ];
    let pinned_state = state::AppStateData {
        pinned_ip: Some("1.1.1.1".to_string()),
        ..Default::default()
    };
    assert!(should_verify_unblock(false, &yellow, &pinned_state, false));

    // Strict pinning mismatch rejects even Green until IP matches or strict pinning is off.
    let mut strict_mismatch = pinned_state.clone();
    strict_mismatch.strict_pinning_enabled = true;
    strict_mismatch.pinned_ip = Some("9.9.9.9".to_string());
    assert!(!should_verify_unblock(
        false,
        &green,
        &strict_mismatch,
        false
    ));

    let mut strict_match = strict_mismatch.clone();
    strict_match
        .pinned_ips
        .insert("openai".to_string(), "1.1.1.1".to_string());
    assert!(should_verify_unblock(false, &green, &strict_match, false));

    // Sanctioned country stays blocked unless in trusted_exceptions.
    let ru = base_report(auditor::OverallStatus::Green, "RU");
    assert!(!should_verify_unblock(false, &ru, &base_state, false));

    // Red status with non-travel critical check stays blocked even if IP is pinned,
    // unless (provider, ip) is explicitly in trusted_exceptions.
    let mut red = base_report(auditor::OverallStatus::Red, "NL");
    red.checks = vec![auditor::CheckResult::critical(
        "DNSBL_LISTED_CRITICAL",
        "listed",
        None,
    )];
    assert!(!should_verify_unblock(false, &red, &base_state, false));
    assert!(!should_verify_unblock(false, &red, &pinned_state, false));

    // Pinned IP overrides IMPOSSIBLE_TRAVEL_CRITICAL on an allowed country.
    let mut red_travel = base_report(auditor::OverallStatus::Red, "NL");
    red_travel.checks = vec![auditor::CheckResult::critical(
        "IMPOSSIBLE_TRAVEL_CRITICAL",
        "hop",
        None,
    )];
    assert!(!should_verify_unblock(false, &red_travel, &base_state, false));
    assert!(should_verify_unblock(
        false,
        &red_travel,
        &pinned_state,
        false
    ));

    let mut excepted_state = state::AppStateData::default();
    excepted_state
        .trusted_exceptions
        .insert("openai".to_string(), vec!["1.1.1.1".to_string()]);
    assert!(should_verify_unblock(false, &ru, &excepted_state, false));
    assert!(should_verify_unblock(false, &red, &excepted_state, false));
}

#[tokio::test]
async fn allow_provider_session_persists_exception_without_leaking_unrelated_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let state = state::AppState::load_or_default(path.clone());
    state.block_provider("anthropic").await.unwrap();
    state.block_provider("openai").await.unwrap();

    let auditor = auditor::Auditor::new().unwrap();
    let tel = auditor::NetworkTelemetry {
        ip: "5.5.5.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(1),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: crate::auditor::network::current_timestamp(),
    };
    auditor.resolver.set_cached(tel).await;

    let hq = Arc::new(proxy::HoldQueue::new());
    let server = Arc::new(
        proxy::ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), hq, None)
            .await
            .unwrap(),
    );
    let pm = proxy::ProxyManager {
        hold_queue: Arc::clone(&server.hold_queue),
        guard: Arc::clone(&server.guard),
        coverage: Arc::clone(&server.coverage),
        server,
    };
    pm.guard.sync_gates_with_state(&state).await;

    allow_provider_session_inner("anthropic", &state, &auditor, &pm)
        .await
        .unwrap();

    assert!(!state.is_provider_blocked("anthropic").await);
    assert!(state.is_provider_session_allowed("anthropic").await);
    assert!(state.is_ip_trusted_for_provider("anthropic", "5.5.5.5").await);
    assert_eq!(pm.guard.gate_for(auditor::ProviderId::Anthropic), proxy::Gate::Open);
    // Unrelated blocked provider remains blocked.
    assert!(state.is_provider_blocked("openai").await);
    assert_eq!(pm.guard.gate_for(auditor::ProviderId::Openai), proxy::Gate::Blocked);

    // Reload from disk: session allowance clears, persistent trusted exception survives.
    drop(state);
    let reloaded = state::AppState::load_or_default(path);
    assert!(!reloaded.is_provider_session_allowed("anthropic").await);
    assert!(reloaded.is_ip_trusted_for_provider("anthropic", "5.5.5.5").await);

    let guard2 = Arc::new(proxy::NetworkGuard::new());
    let st2 = remove_trusted_exception_inner(&reloaded, &guard2, "anthropic", "5.5.5.5")
        .await
        .unwrap();
    assert!(!st2.is_ip_trusted_for_provider("anthropic", "5.5.5.5"));

    reloaded
        .add_trusted_exception("openai", "6.6.6.6")
        .await
        .unwrap();
    reloaded
        .add_trusted_exception("gemini", "7.7.7.7")
        .await
        .unwrap();
    let st3 = clear_trusted_exceptions_inner(&reloaded, &guard2, Some("openai"))
        .await
        .unwrap();
    assert!(!st3.is_ip_trusted_for_provider("openai", "6.6.6.6"));
    assert!(st3.is_ip_trusted_for_provider("gemini", "7.7.7.7"));

    let st4 = clear_trusted_exceptions_inner(&reloaded, &guard2, None)
        .await
        .unwrap();
    assert!(st4.trusted_exceptions.is_empty());
}

#[tokio::test]
async fn set_provider_monitoring_toggles_state_and_guard_cleanly() {
    let state = state::AppState::new_in_memory();
    let guard = Arc::new(proxy::NetworkGuard::new());
    state.block_provider("gemini").await.unwrap();
    guard.sync_gates_with_state(&state).await;
    assert_eq!(guard.gate_for(auditor::ProviderId::Gemini), proxy::Gate::Blocked);

    let st_off = set_provider_monitoring_inner(&state, &guard, "gemini", false)
        .await
        .unwrap();
    assert!(st_off.disabled_providers.contains("gemini"));
    assert!(!st_off.blocked_providers.contains("gemini"));
    assert_eq!(guard.gate_for(auditor::ProviderId::Gemini), proxy::Gate::Open);

    let st_on = set_provider_monitoring_inner(&state, &guard, "gemini", true)
        .await
        .unwrap();
    assert!(!st_on.disabled_providers.contains("gemini"));
}

#[test]
fn finalize_audit_report_applies_pinned_travel_grace_to_critical_and_warning() {
    let ok = auditor::CheckResult::ok("GEO_ALLOWED", "ok");
    let make_report = |provider: auditor::ProviderId, cc: &str, travel: auditor::CheckResult| {
        let status = if travel.status.is_critical() {
            auditor::OverallStatus::Red
        } else {
            auditor::OverallStatus::Yellow
        };
        auditor::RiskReport {
            provider,
            overall_status: status,
            trust_score: 60,
            telemetry: auditor::NetworkTelemetry {
                ip: "203.0.113.9".into(),
                country_code: cc.into(),
                hostname: None,
                asn: Some(1),
                org: None,
                isp: None,
                timezone: None,
                resolved_at: 0,
            },
            geo_result: ok.clone(),
            pinning_result: auditor::CheckResult::ok("PINNED_IP_MATCH", "ok"),
            travel_result: travel.clone(),
            dnsbl_result: ok.clone(),
            dnsbl_clean_count: "0/0".into(),
            asn_result: ok.clone(),
            ipv6_result: ok.clone(),
            timezone_result: ok.clone(),
            ipv6_exit: false,
            checks: vec![ok.clone(), ok.clone(), travel],
            unknown_count: 0,
            applicable_count: 3,
            incomplete: false,
        }
    };

    let st = state::AppStateData {
        pinned_ip: Some("203.0.113.9".to_string()),
        ..Default::default()
    };

    let mut claude = make_report(
        auditor::ProviderId::Anthropic,
        "GB",
        auditor::CheckResult::critical("IMPOSSIBLE_TRAVEL_CRITICAL", "DE -> GB", None),
    );
    assert!(finalize_audit_report_for_state(&st, auditor::ProviderId::Anthropic, &mut claude));
    assert_eq!(claude.overall_status, auditor::OverallStatus::Green);
    assert_eq!(claude.travel_result.code, "TRAVEL_PINNED_RETURN");

    let mut openai = make_report(
        auditor::ProviderId::Openai,
        "GB",
        auditor::CheckResult::warning("IMPOSSIBLE_TRAVEL_WARNING", "DE -> GB", None),
    );
    assert!(finalize_audit_report_for_state(&st, auditor::ProviderId::Openai, &mut openai));
    assert_eq!(openai.overall_status, auditor::OverallStatus::Green);
    assert_eq!(openai.travel_result.code, "TRAVEL_PINNED_RETURN");

    // Sanctioned country must NEVER receive travel grace even if pinned.
    let mut sanctioned = make_report(
        auditor::ProviderId::Anthropic,
        "RU",
        auditor::CheckResult::critical("IMPOSSIBLE_TRAVEL_CRITICAL", "DE -> RU", None),
    );
    finalize_audit_report_for_state(&st, auditor::ProviderId::Anthropic, &mut sanctioned);
    assert_eq!(sanctioned.overall_status, auditor::OverallStatus::Red);
    assert_eq!(sanctioned.travel_result.code, "IMPOSSIBLE_TRAVEL_CRITICAL");
}

mod pin_tests {
    use super::super::*;
    use crate::routing::{Entry, EntryProto, Route};

    #[tokio::test]
    async fn pin_ip_isolates_routed_provider_from_default_vpn_and_preserves_route_lock() {
        let state = state::AppState::new_in_memory();
        let route = Route {
            id: "fr-1".to_string(),
            label: "France".to_string(),
            country: Some("FR".to_string()),
            exit_ip: Some("136.244.114.42".to_string()),
            expires_at: None,
            entries: vec![Entry {
                proto: EntryProto::Http,
                host: "136.244.114.42".to_string(),
                port: 8443,
                username: None,
                password: None,
                sni: None,
            }],
            raw_key: String::new(),
            enabled: true,
            added_at: 0,
        };
        state.upsert_route(route).await.unwrap();
        state
            .bind_provider_route("gemini", Some("fr-1"))
            .await
            .unwrap();

        // Direct provider (anthropic) pins under "default".
        pin_ip_inner(
            &state,
            "145.241.193.245".to_string(),
            Some("anthropic".to_string()),
        )
        .await
        .unwrap();

        let st = state.get_data().await;
        assert_eq!(st.pinned_ip.as_deref(), Some("145.241.193.245"));
        assert_eq!(
            st.pinned_ips.get("default").map(String::as_str),
            Some("145.241.193.245")
        );
        assert!(!st.pinned_ips.contains_key("gemini"));

        // Routed Gemini is pinned by its Zastava key even when its exit differs from global VPN.
        assert!(is_ip_pinned_for_state(
            &st,
            auditor::ProviderId::Gemini,
            "136.244.114.42"
        ));
        assert!(is_ip_pinned_for_state(
            &st,
            auditor::ProviderId::Anthropic,
            "145.241.193.245"
        ));
        assert!(!is_ip_pinned_for_state(
            &st,
            auditor::ProviderId::Anthropic,
            "1.2.3.4"
        ));

        // Explicit pin on routed Gemini goes into pinned_ips["gemini"] without touching "default".
        pin_ip_inner(
            &state,
            "136.244.114.42".to_string(),
            Some("gemini".to_string()),
        )
        .await
        .unwrap();
        let st2 = state.get_data().await;
        assert_eq!(
            st2.pinned_ips.get("gemini").map(String::as_str),
            Some("136.244.114.42")
        );
        assert_eq!(
            st2.pinned_ips.get("default").map(String::as_str),
            Some("145.241.193.245")
        );
        assert!(!is_ip_pinned_for_state(
            &st2,
            auditor::ProviderId::Gemini,
            "99.99.99.99"
        ));

        // Unpinning Gemini only removes Gemini's explicit pin, keeping "default" intact.
        unpin_ip_inner(&state, Some("gemini".to_string()))
            .await
            .unwrap();
        let st3 = state.get_data().await;
        assert!(!st3.pinned_ips.contains_key("gemini"));
        assert_eq!(
            st3.pinned_ips.get("default").map(String::as_str),
            Some("145.241.193.245")
        );

        // Unpinning with None clears all pinned IPs.
        unpin_ip_inner(&state, None).await.unwrap();
        let st4 = state.get_data().await;
        assert!(st4.pinned_ip.is_none());
        assert!(st4.pinned_ips.is_empty());
    }

    #[tokio::test]
    async fn unrouted_explicit_anthropic_pin_can_be_updated_and_unpinned_without_stranding() {
        let state = state::AppState::new_in_memory();
        // Global default VPN pin + explicit unrouted Anthropic profile pin.
        state
            .set_pinned_ip_for("default", Some("2.2.2.2".to_string()))
            .await
            .unwrap();
        state
            .set_pinned_ip_for("anthropic", Some("1.1.1.1".to_string()))
            .await
            .unwrap();

        // Updating anthropic updates pinned_ips["anthropic"], not just "default".
        pin_ip_inner(&state, "3.3.3.3".to_string(), Some("anthropic".to_string()))
            .await
            .unwrap();
        let st1 = state.get_data().await;
        assert_eq!(
            st1.pinned_ips.get("anthropic").map(String::as_str),
            Some("3.3.3.3")
        );
        assert_eq!(
            st1.pinned_ips.get("default").map(String::as_str),
            Some("2.2.2.2")
        );
        assert_eq!(st1.pinned_ip_for_provider("anthropic", false), Some("3.3.3.3"));

        // Unpinning anthropic clears pinned_ips["anthropic"], preserving "default" for OpenAI/Gemini.
        unpin_ip_inner(&state, Some("anthropic".to_string()))
            .await
            .unwrap();
        let st2 = state.get_data().await;
        assert!(!st2.pinned_ips.contains_key("anthropic"));
        assert_eq!(
            st2.pinned_ips.get("default").map(String::as_str),
            Some("2.2.2.2")
        );
        assert_eq!(st2.pinned_ip_for_provider("anthropic", false), Some("2.2.2.2"));

        // Without "default", unpinning explicit unrouted anthropic leaves it completely unpinned.
        state.clear_all_pinned_ips().await.unwrap();
        state
            .set_pinned_ip_for("anthropic", Some("4.4.4.4".to_string()))
            .await
            .unwrap();
        unpin_ip_inner(&state, Some("anthropic".to_string()))
            .await
            .unwrap();
        let st3 = state.get_data().await;
        assert!(st3.pinned_ips.is_empty());
        assert_eq!(st3.pinned_ip_for_provider("anthropic", false), None);
    }
}
