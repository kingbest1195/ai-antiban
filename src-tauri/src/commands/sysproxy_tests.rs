use super::*;

#[test]
fn cli_settings_has_the_four_fields_the_interface_reads_in_snake_case() {
    let settings = CliSettings {
        cli_mode: state::CliMode::GlobalTerminal,
        sync_ai_tz_enabled: false,
        cli_protection_enabled: true,
        synced_ai_timezone: Some("Europe/Berlin".to_string()),
    };
    let json = serde_json::to_value(&settings).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "cli_mode": "global_terminal",
            "sync_ai_tz_enabled": false,
            "cli_protection_enabled": true,
            "synced_ai_timezone": "Europe/Berlin",
        })
    );
    let none = serde_json::to_value(CliSettings {
        cli_mode: state::CliMode::AiOnly,
        sync_ai_tz_enabled: true,
        cli_protection_enabled: false,
        synced_ai_timezone: None,
    })
    .unwrap();
    assert_eq!(none["cli_mode"], "ai_only");
    assert!(none["synced_ai_timezone"].is_null());
}

#[test]
fn diagnostic_report_includes_error_os_snapshot_and_logs() {
    let report = build_error_diagnostics_report(
        Some("Не удалось переключить защиту"),
        Some("Command failed"),
        8899,
        &["services: Wi-Fi(dev=en0, enabled=true)".to_string()],
        &["[+1s] [sysproxy] set_pac failed".to_string()],
    );
    assert!(report.contains("Zastava v"));
    assert!(report.contains("Error title: Не удалось переключить защиту"));
    assert!(report.contains("gateway_port=8899"));
    assert!(report.contains("services: Wi-Fi(dev=en0, enabled=true)"));
    assert!(report.contains("[+1s] [sysproxy] set_pac failed"));
}

#[test]
fn windows_ipconfig_snapshot_extracts_active_tun_vpn_adapters_and_dns_without_host_ips() {
    let sample = "\
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-TEST

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Description . . . . . . . . . . . : Realtek PCIe GbE Family Controller

Unknown adapter Happ:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Wintun Userspace Tunnel
   IPv4 Address. . . . . . . . . . . : 172.19.0.1(Preferred)
   DNS Servers . . . . . . . . . . . : 198.18.0.2
                                   1.1.1.1

Wireless LAN adapter Wi-Fi:

   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   IPv4 Address. . . . . . . . . . . : 192.168.1.42(Preferred)
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
";
    let lines = parse_windows_ipconfig_snapshot(sample);
    let joined = lines.join("\n");
    assert!(joined.contains("Unknown adapter Happ"), "{joined}");
    assert!(joined.contains("TUN/VPN"), "{joined}");
    assert!(joined.contains("Wireless LAN adapter Wi-Fi"), "{joined}");
    assert!(!joined.contains("Ethernet adapter Ethernet"), "{joined}");
    assert!(joined.contains("198.18.0.2"), "{joined}");
    assert!(joined.contains("1.1.1.1"), "{joined}");
    assert!(!joined.contains("172.19.0.1"), "must not leak host IP: {joined}");
    assert!(!joined.contains("192.168.1.42"), "must not leak host IP: {joined}");

    // Localized Russian Windows output
    let ru_sample = "\
Настройка протокола IP для Windows

Неизвестный адаптер Happ:

   Описание. . . . . . . . . . . . . : Wintun Userspace Tunnel
   IPv4-адрес. . . . . . . . . . . . : 10.0.0.2(Основной)
   DNS-серверы. . . . . . . . . . .  : 198.18.0.2
";
    let ru_lines = parse_windows_ipconfig_snapshot(ru_sample);
    let ru_joined = ru_lines.join("\n");
    assert!(ru_joined.contains("Неизвестный адаптер Happ"), "{ru_joined}");
    assert!(ru_joined.contains("TUN/VPN"), "{ru_joined}");
    assert!(ru_joined.contains("198.18.0.2"), "{ru_joined}");
    assert!(!ru_joined.contains("10.0.0.2"), "{ru_joined}");
}

#[tokio::test]
async fn resolve_os_tz_and_sync_tz_fall_back_across_providers_when_anthropic_lacks_tz() {
    use crate::routing::{Entry, EntryProto, Route};

    let state = state::AppState::new_in_memory();
    let fr_route = Route {
        id: "fr-fallback".into(),
        label: "France".into(),
        country: Some("FR".into()),
        exit_ip: Some("136.244.114.42".into()),
        expires_at: None,
        entries: vec![Entry {
            proto: EntryProto::Http,
            host: "136.244.114.42".into(),
            port: 8443,
            username: None,
            password: None,
            sni: None,
        }],
        raw_key: String::new(),
        enabled: true,
        added_at: 0,
    };
    state.upsert_route(fr_route).await.unwrap();
    state
        .bind_provider_route("gemini", Some("fr-fallback"))
        .await
        .unwrap();

    let auditor = auditor::Auditor::new().unwrap();
    let now = auditor::network::current_timestamp();
    // Anthropic is Direct and has trace-only telemetry without timezone.
    auditor
        .resolver
        .set_cached(auditor::NetworkTelemetry {
            ip: "145.241.193.245".into(),
            country_code: "GB".into(),
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            resolved_at: now,
        })
        .await;
    // Gemini is routed and has a valid French timezone.
    auditor
        .resolver
        .set_cached_for_route(
            Some("fr-fallback".into()),
            auditor::NetworkTelemetry {
                ip: "136.244.114.42".into(),
                country_code: "FR".into(),
                hostname: None,
                asn: None,
                org: None,
                isp: None,
                timezone: Some("Europe/Paris".into()),
                resolved_at: now,
            },
        )
        .await;

    let resolved = resolve_os_tz_target(&state, &auditor, None).await.unwrap();
    assert_eq!(resolved, "Europe/Paris");

    let synced = sync_tz_for(true, &state, &auditor).await;
    assert_eq!(synced.as_deref(), Some("Europe/Paris"));
}

#[test]
fn sanitize_diagnostic_text_masks_ipv4_ipv6_urls_and_secrets() {
    assert_eq!(mask_ip_address("185.220.101.5"), "xxx.xxx.xxx.xxx");
    assert_eq!(mask_ip_address("2001:db8::1"), "xxxx:xxxx::xxxx");

    let msg = "Нарушение Strict Pinning: текущий IP (185.220.101.5) не совпадает с 136.244.114.42; \
               v6 [2001:db8:85a3::8a2e:370:7334]:443 и ключ zastava://secret-key@node.example:443?token=abc, \
               proxy socks5://alice:supersecret@198.51.100.7:1080 password=topsecret Bearer tok_live_123 v2.1.2.";
    let clean = sanitize_diagnostic_text(msg);

    assert!(!clean.contains("185.220.101.5"), "{clean}");
    assert!(!clean.contains("136.244.114.42"), "{clean}");
    assert!(!clean.contains("198.51.100.7"), "{clean}");
    assert!(!clean.contains("2001:db8"), "{clean}");
    assert!(!clean.contains("secret-key"), "{clean}");
    assert!(!clean.contains("supersecret"), "{clean}");
    assert!(!clean.contains("alice"), "{clean}");
    assert!(!clean.contains("topsecret"), "{clean}");
    assert!(!clean.contains("tok_live_123"), "{clean}");
    assert!(clean.contains("xxx.xxx.xxx.xxx"), "{clean}");
    assert!(clean.contains("xxxx:xxxx::xxxx"), "{clean}");
    assert!(clean.contains("zastava://[REDACTED]"), "{clean}");
    assert!(clean.contains("socks5://[REDACTED]"), "{clean}");
    assert!(clean.contains("v2.1.2"), "versions must survive: {clean}");
}

#[test]
fn diagnostic_bundle_serializes_routes_and_checks_without_secrets_or_ips() {
    let mut data = state::AppStateData {
        cli_mode: state::CliMode::GlobalTerminal,
        split_tunnel_mode: true,
        sync_ai_tz_enabled: true,
        synced_ai_timezone: Some("Europe/Amsterdam".to_string()),
        ..Default::default()
    };
    data.routes.push(routing::Route {
        id: "route-nl".to_string(),
        label: "NL Fast socks5://u:pw123@198.51.100.9:1080".to_string(),
        country: Some("NL".to_string()),
        exit_ip: Some("185.10.20.30".to_string()),
        expires_at: None,
        entries: vec![routing::Entry {
            proto: routing::EntryProto::Socks5,
            host: "198.51.100.9".to_string(),
            port: 1080,
            username: Some("secretuser".to_string()),
            password: Some("verysecretpassword".to_string()),
            sni: None,
        }],
        raw_key: "zastava://top-secret-raw-key".to_string(),
        enabled: true,
        added_at: 1_700_000_000,
    });
    data.provider_routes
        .insert("gemini".to_string(), "route-nl".to_string());
    data.ip_history.insert(
        "anthropic".to_string(),
        vec![state::IpHistoryEntry::new(
            "203.0.113.55".to_string(),
            "DE".to_string(),
            Some(24940),
            1_700_000_000,
        )],
    );

    let check = auditor::CheckResult::critical(
        "PINNED_IP_MISMATCH",
        "Текущий IP (203.0.113.55) не совпадает с 198.51.100.44",
        None,
    );
    let tel = auditor::NetworkTelemetry {
        ip: "203.0.113.55".to_string(),
        country_code: "DE".to_string(),
        hostname: Some("secret-host.internal".to_string()),
        asn: Some(24940),
        org: Some("Hetzner".to_string()),
        isp: Some("Hetzner".to_string()),
        timezone: Some("Europe/Berlin".to_string()),
        resolved_at: 1_700_000_000,
    };
    let report = auditor::RiskReport {
        provider: auditor::ProviderId::Anthropic,
        overall_status: auditor::OverallStatus::Red,
        trust_score: 40,
        telemetry: tel,
        geo_result: auditor::CheckResult::ok("GEO_OK", "OK"),
        pinning_result: check.clone(),
        travel_result: auditor::CheckResult::ok("TRAVEL_OK", "OK"),
        dnsbl_result: auditor::CheckResult::ok("DNSBL_CLEAN", "4/4"),
        dnsbl_clean_count: "4/4".to_string(),
        asn_result: auditor::CheckResult::ok("ASN_CLEAN", "OK"),
        ipv6_result: auditor::CheckResult::ok("IPV6_SAFE", "OK"),
        timezone_result: auditor::CheckResult::ok("TZ_OK", "OK"),
        ipv6_exit: false,
        checks: vec![check],
        unknown_count: 0,
        applicable_count: 1,
        incomplete: false,
    };

    let mut reports = HashMap::new();
    reports.insert("anthropic".to_string(), Ok(report));
    let stats = state::GatewayStatsSnapshot {
        protected_ai_requests: 5,
        intercepted_leaks: 1,
        direct_bypassed_requests: 2,
        active_ai_tunnels: 0,
        uptime_seconds: 120,
        last_protected_host: Some("api.anthropic.com".to_string()),
        recent_events: Vec::new(),
    };

    let bundle = build_sanitized_diagnostic_bundle(
        &data,
        &stats,
        &reports,
        true,
        true,
        8899,
        Some("15.2 (24C101)".to_string()),
        &["proxy connect socks5://user:pass@198.51.100.9:1080 failed".to_string()],
    );
    let json = serde_json::to_string_pretty(&bundle).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["app_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(parsed["os"], std::env::consts::OS);
    assert_eq!(parsed["arch"], std::env::consts::ARCH);
    assert_eq!(parsed["sysproxy_enabled"], true);
    assert_eq!(parsed["cli_protection_enabled"], true);
    assert_eq!(parsed["cli_mode"], "global_terminal");
    assert_eq!(parsed["split_tunnel_mode"], true);
    assert_eq!(parsed["sync_ai_tz_enabled"], true);

    assert_eq!(parsed["provider_routes"]["gemini"]["route_id"], "route-nl");
    assert_eq!(parsed["provider_routes"]["gemini"]["country"], "NL");
    assert_eq!(parsed["provider_routes"]["anthropic"]["mode"], "direct");
    assert_eq!(
        parsed["audit_reports"]["anthropic"]["exit_ip_masked"],
        "xxx.xxx.xxx.xxx"
    );
    assert_eq!(
        parsed["audit_reports"]["anthropic"]["checks"][0]["code"],
        "PINNED_IP_MISMATCH"
    );

    for secret in [
        "185.10.20.30",
        "198.51.100.9",
        "198.51.100.44",
        "203.0.113.55",
        "secretuser",
        "verysecretpassword",
        "top-secret-raw-key",
        "pw123",
        "secret-host.internal",
    ] {
        assert!(!json.contains(secret), "leaked `{secret}` in {json}");
    }
}

#[test]
fn preview_protection_changes_covers_all_layers_and_marks_all_reversible() {
    let items = build_protection_changes_preview(
        8899,
        state::CliMode::GlobalTerminal,
        true,
        &[(
            "VS Code",
            std::path::PathBuf::from("/tmp/Code/User/settings.json"),
        )],
    );
    assert!(!items.is_empty());
    for item in &items {
        assert!(!item.category.is_empty());
        assert!(!item.target.is_empty());
        assert!(!item.action.is_empty());
        assert!(!item.description.is_empty());
        assert!(item.reversible, "expected reversible=true for {item:?}");
    }
    assert!(items.iter().any(|i| i.category == "system_proxy"));
    assert!(items.iter().any(|i| {
        i.category == "browser_policies"
            && i.target.contains("ProxyMode")
            && i.target.contains("ProxyPacUrl")
            && i.target.contains("QuicAllowed")
            && i.target.contains("DnsOverHttpsMode")
    }));
    assert!(items.iter().any(|i| i.category == "shell_rc"));
    assert!(items.iter().any(|i| {
        i.category == "ide_settings"
            && i.target.contains("VS Code")
            && i.target.contains("Cursor")
            && i.target.contains("Antigravity")
    }));
    assert!(
        items
            .iter()
            .any(|i| i.category == "ide_settings" && i.target.contains("JetBrains"))
    );
}
