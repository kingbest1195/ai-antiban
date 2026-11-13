use zastava_lib::auditor::dnsbl::{format_dnsbl_query, reverse_ipv4};
use zastava_lib::auditor::ip_type::{evaluate_ip_reputation, ExitIdentity, TorLookup};
use zastava_lib::auditor::geo_matrix::{evaluate_provider_geo, CheckStatus, ProviderId};
use zastava_lib::auditor::history::{evaluate_impossible_travel, evaluate_ip_pinning};
use zastava_lib::auditor::leaks::{is_russian_or_belarusian_timezone, RUSSIAN_TIMEZONES};
use zastava_lib::auditor::rules::{DangerousAsns, ProviderMatrix};
use std::net::IpAddr;
use zastava_lib::bin_checker::BinChecker;
use zastava_lib::proxy::server::{is_forbidden_ip, is_tun_fake_ip, parse_host_port, validate_tunnel_target};
use zastava_lib::state::{AppState, AppStateData, IpHistoryEntry};

#[test]
fn test_edge_case_turkey_gemini_special_rules() {
    let matrix = ProviderMatrix::load_bundled().expect("Failed to load bundled provider matrix");

    // Gemini in Turkey is officially supported (web & API)
    let gemini_tr = evaluate_provider_geo(&matrix, ProviderId::Gemini, "TR");
    assert_eq!(gemini_tr.status, CheckStatus::Ok);
    assert_eq!(gemini_tr.code, "GEO_ALLOWED");

    // Claude (Anthropic) in Turkey is Warning
    let anthropic_tr = evaluate_provider_geo(&matrix, ProviderId::Anthropic, "TR");
    assert_eq!(anthropic_tr.status, CheckStatus::Warning);

    // ChatGPT (OpenAI) in Turkey is Ok
    let openai_tr = evaluate_provider_geo(&matrix, ProviderId::Openai, "TR");
    assert_eq!(openai_tr.status, CheckStatus::Ok);
}

#[test]
fn test_edge_case_impossible_travel_exact_window() {
    let now = 1_000_000;
    // Window is 4 hours = 14400 seconds
    let inside_window = now - (3 * 3600 + 59 * 60); // 3h 59m ago
    let outside_window = now - (4 * 3600 + 60); // 4h 1m ago

    let history_inside = vec![IpHistoryEntry::new("1.1.1.1", "DE", Some(1234), inside_window)];
    let res_inside = evaluate_impossible_travel(&history_inside, "US", now, ProviderId::Anthropic);
    assert_eq!(res_inside.status, CheckStatus::Critical);
    assert_eq!(res_inside.code, "IMPOSSIBLE_TRAVEL_CRITICAL");

    let history_outside = vec![IpHistoryEntry::new("1.1.1.1", "DE", Some(1234), outside_window)];
    let res_outside = evaluate_impossible_travel(&history_outside, "US", now, ProviderId::Anthropic);
    assert_eq!(res_outside.status, CheckStatus::Ok);
    assert_eq!(res_outside.code, "TRAVEL_NORMAL");
}

#[test]
fn test_edge_case_dnsbl_all_configured_zones_formatting() {
    let dangerous_asns = DangerousAsns::load_bundled().expect("Failed to load dangerous asns");
    let test_ip = "185.220.101.5";
    let reversed = reverse_ipv4(test_ip).expect("Valid IP");

    for zone_cfg in &dangerous_asns.dnsbl_zones {
        let fqdn = format_dnsbl_query(test_ip, &zone_cfg.zone).expect("Format query");
        assert_eq!(fqdn, format!("{reversed}.{}", zone_cfg.zone.trim_matches('.')));
        assert!(!fqdn.ends_with('.'));
    }
}

#[test]
fn test_edge_case_russian_timezones_exhaustiveness() {
    // Check known high-risk timezones
    assert!(is_russian_or_belarusian_timezone("Europe/Moscow"));
    assert!(is_russian_or_belarusian_timezone("Europe/Minsk"));
    assert!(is_russian_or_belarusian_timezone("Asia/Vladivostok"));
    assert!(is_russian_or_belarusian_timezone("Asia/Novosibirsk"));
    assert!(is_russian_or_belarusian_timezone("europe/moscow")); // case-insensitivity

    // Clean international timezones
    assert!(!is_russian_or_belarusian_timezone("Europe/Berlin"));
    assert!(!is_russian_or_belarusian_timezone("Europe/Amsterdam"));
    assert!(!is_russian_or_belarusian_timezone("America/New_York"));
    assert!(!is_russian_or_belarusian_timezone("UTC"));

    assert!(RUSSIAN_TIMEZONES.len() >= 25);
}

#[test]
fn test_edge_case_bin_checker_strict_privacy_and_lengths() {
    // 6-digit BIN is valid
    assert_eq!(BinChecker::sanitize_bin("4111 11").unwrap(), "411111");

    // 7-digit BIN is valid
    assert_eq!(BinChecker::sanitize_bin("4111-112").unwrap(), "4111112");

    // 8-digit BIN is valid
    assert_eq!(BinChecker::sanitize_bin("4111 1122").unwrap(), "41111122");

    // < 6 digits is rejected
    assert!(BinChecker::sanitize_bin("41111").is_err());

    // > 8 digits (e.g. 16-digit card number) is strictly rejected to prevent card leaks
    let card_leak = BinChecker::sanitize_bin("4111 2222 3333 4444");
    assert!(card_leak.is_err());
    assert!(card_leak.unwrap_err().contains("For your privacy"));

    // Letters only is rejected
    assert!(BinChecker::sanitize_bin("abcdef").is_err());
}

#[test]
fn test_edge_case_vps_pinning_and_russian_telecom() {
    let asns = DangerousAsns::load_bundled().expect("Failed to load bundled ASNs");

    let rep = |asn: u32, isp: &str, pinned: bool| {
        let id = ExitIdentity { ip: "203.0.113.9", country_code: "NL", asn: Some(asn), isp: Some(isp), org: None };
        evaluate_ip_reputation(&id, &asns, TorLookup::NotListed, pinned)
    };

    // Datacenter (DigitalOcean: AS14061): a personal VPS is a normal setup, not penalised.
    let res_hosting = rep(14061, "DigitalOcean, LLC", false);
    assert_eq!(res_hosting.status, CheckStatus::Ok);
    assert_eq!(res_hosting.code, "IP_TYPE_HOSTING");

    // Mass VPN pool (M247: AS9009): 1. Unpinned -> Warning
    let res_unpinned = rep(9009, "M247 Europe SRL", false);
    assert_eq!(res_unpinned.status, CheckStatus::Warning);

    // 2. User pinned this IP as their personal dedicated VPS -> suppressed (Ok)
    let res_pinned = rep(9009, "M247 Europe SRL", true);
    assert_eq!(res_pinned.status, CheckStatus::Ok);
    assert_eq!(res_pinned.code, "ASN_VERIFIED_PINNED");

    // 3. BUT Russian domestic telecom (Rostelecom, MTS, MegaFon) is NEVER suppressed by pinning!
    let res_pinned_ru = rep(12389, "PJSC Rostelecom", true);
    assert_eq!(res_pinned_ru.status, CheckStatus::Critical);
    assert_eq!(res_pinned_ru.code, "RUSSIAN_ISP_DETECTED");

    // 4. Strict IP Pinning test with country match
    let res_strict_mismatch = evaluate_ip_pinning(Some("1.2.3.4"), true, "5.6.7.8");
    assert_eq!(res_strict_mismatch.status, CheckStatus::Critical);
    assert_eq!(res_strict_mismatch.code, "PINNED_IP_MISMATCH");
}

#[test]
fn test_security_fqdn_trailing_dot_bypass_prevention() {
    // Trailing dot FQDN must still match AI providers so CONNECT cannot bypass the proxy guard
    assert_eq!(
        ProviderId::from_host("api.anthropic.com.:443"),
        Some(ProviderId::Anthropic)
    );
    assert_eq!(
        ProviderId::from_host("claude.ai."),
        Some(ProviderId::Anthropic)
    );
    assert_eq!(
        ProviderId::from_host("chatgpt.com.:443"),
        Some(ProviderId::Openai)
    );
    assert_eq!(
        ProviderId::from_host("generativelanguage.googleapis.com..:443"),
        Some(ProviderId::Gemini)
    );
}

#[test]
fn test_security_ssrf_and_proxy_loop_prevention() {
    let proxy_port = 8899;

    // Allowed standard HTTPS external host
    assert!(validate_tunnel_target("example.com", 443, proxy_port).is_ok());
    assert!(validate_tunnel_target("example.com", 8443, proxy_port).is_ok());

    // Disallowed non-HTTP/HTTPS ports (e.g., SSH, Redis, PostgreSQL, proxy loop)
    assert!(validate_tunnel_target("example.com", 22, proxy_port).is_err());
    assert!(validate_tunnel_target("example.com", 6379, proxy_port).is_err());
    assert!(validate_tunnel_target("example.com", 8899, proxy_port).is_err());
    assert!(validate_tunnel_target("example.com", 8900, proxy_port).is_err());

    // Disallowed localhost / internal hostnames
    assert!(validate_tunnel_target("localhost", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("internal.localhost", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("printer.local", 443, proxy_port).is_err());

    // Disallowed literal private/loopback/metadata IPs
    assert!(validate_tunnel_target("127.0.0.1", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("10.0.0.1", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("192.168.1.1", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("172.16.0.1", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("169.254.169.254", 80, proxy_port).is_err());
    assert!(validate_tunnel_target("100.64.0.1", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("::1", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("fe80::1", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("fd00::1", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("198.18.0.1", 443, proxy_port).is_err());
    assert!(validate_tunnel_target("198.19.255.1", 443, proxy_port).is_err());

    // Verify is_forbidden_ip directly
    assert!(is_forbidden_ip(&"127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_forbidden_ip(&"169.254.169.254".parse::<IpAddr>().unwrap()));
    assert!(!is_forbidden_ip(&"1.1.1.1".parse::<IpAddr>().unwrap()));
    assert!(!is_forbidden_ip(&"2606:4700:4700::1111".parse::<IpAddr>().unwrap()));

    // Verify is_tun_fake_ip identifies FakeIP pool (198.18.0.0/15)
    assert!(is_tun_fake_ip(&"198.18.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_tun_fake_ip(&"198.19.254.254".parse::<IpAddr>().unwrap()));
    assert!(!is_tun_fake_ip(&"198.20.0.1".parse::<IpAddr>().unwrap()));
    assert!(!is_tun_fake_ip(&"1.1.1.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_security_parse_host_port_ipv6_and_fqdn() {
    assert_eq!(
        parse_host_port("api.anthropic.com.:443"),
        ("api.anthropic.com".to_string(), 443)
    );
    assert_eq!(
        parse_host_port("[2606:4700:4700::1111]:443"),
        ("2606:4700:4700::1111".to_string(), 443)
    );
    assert_eq!(
        parse_host_port("[::1]:8899"),
        ("::1".to_string(), 8899)
    );
}

#[test]
fn test_self_healing_corrupt_state_file() {
    let temp_dir = std::env::temp_dir().join(format!("zastava_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let state_file = temp_dir.join("state.json");

    // Write corrupted JSON
    std::fs::write(&state_file, "{corrupt_json: true, ").expect("write corrupt state");

    // load_or_default must self-heal and overwrite with valid default JSON
    let _recovered = AppState::load_or_default(state_file.clone());

    let healed_contents = std::fs::read_to_string(&state_file).expect("read healed state");
    let parsed: AppStateData = serde_json::from_str(&healed_contents).expect("valid healed json");
    assert_eq!(parsed, AppStateData::default());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

