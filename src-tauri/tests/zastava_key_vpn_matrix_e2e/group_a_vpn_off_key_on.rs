use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tempfile::tempdir;
use zastava_lib::auditor::seams::fakes::{FakeSystem, FakeUdp};
use zastava_lib::auditor::{
    AuditProtectionFlags, CheckStatus, OverallStatus, ProviderId, check_ipv6_leak_with_route,
};
use zastava_lib::clean_room::detector::DetectorEnv;
use zastava_lib::commands::clean_room::run_clean_room_audit_with_route_env;
use zastava_lib::proxy::pac::{generate_pac_script, get_all_ai_domains_filtered};
use zastava_lib::routing::net::test_support::TestEntryDnsGuard;
use zastava_lib::routing::{Entry, EntryProto, Route, RouteSelection};
use zastava_lib::state::AppState;

use crate::harness::{
    EntryMode, MockEchoTarget, MockZastavaEntry, OfflineDns, RuIspKeyProbe, acquire_global_state,
    build_offline_auditor, clean_de_telemetry, dead_local_port, send_connect_and_echo,
    start_proxy_server, stun_binding_success_packet,
};

struct EmptyDetector;
impl DetectorEnv for EmptyDetector {
    fn path_exists(&self, _: &Path) -> bool {
        false
    }
    fn running_ai_processes(&self) -> Vec<String> {
        vec![]
    }
    fn browser_profile_dirs(&self) -> Vec<(&'static str, PathBuf)> {
        vec![]
    }
    fn claude_data_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
    fn chatgpt_data_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
    fn cursor_data_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
    fn is_windows(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn e2e_vpn_off_key_on_dual_stack_ru_ipv6_ok() {
    let _g = acquire_global_state().await;
    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "RU",
        block_doh_and_tor: false,
        stun_ip: "5.18.10.2",
        stun_cc: "RU",
    });
    let sys = FakeSystem {
        global_ipv6: Some(true),
        timezone: Ok("Europe/Berlin".to_string()),
        ..FakeSystem::healthy()
    };
    let v6 = check_ipv6_leak_with_route(
        &*probe,
        &sys,
        "https://[2606:4700:4700::1111]/cdn-cgi/trace",
        Duration::from_millis(500),
        "DE",
        &["RU".to_string(), "BY".to_string()],
        false,
        true,
    )
    .await;
    assert_eq!(v6.status, CheckStatus::Ok);
    assert_eq!(v6.code, "IPV6_KEY_TCP_ISOLATED");

    let target = MockEchoTarget::spawn().await;
    let entry = MockZastavaEntry::spawn(EntryMode::HttpHealthy, Some(target.addr)).await;
    let route = entry.as_route("key-de", "DE Key");

    let state = AppState::new_in_memory();
    state.upsert_route(route.clone()).await.unwrap();
    state
        .bind_provider_route("anthropic", Some(&route.id))
        .await
        .unwrap();

    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    auditor
        .resolver
        .set_cached_for_route(Some(route.id.clone()), clean_de_telemetry())
        .await;

    let report = auditor
        .evaluate_all_with_protection(
            ProviderId::Anthropic,
            &state,
            false,
            AuditProtectionFlags {
                sysproxy_active: true,
                cli_or_sandbox_protection_active: true,
                os_pac_deferred: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(report.ipv6_result.code, "IPV6_KEY_TCP_ISOLATED");
    assert_eq!(report.ipv6_result.status, CheckStatus::Ok);
    assert_eq!(report.overall_status, OverallStatus::Green);

    let (srv, srv_task) = start_proxy_server(auditor.clone(), state.clone(), None, None).await;
    let echoed = send_connect_and_echo(srv.bound_addr, "claude.ai:443", b"ping-key")
        .await
        .expect("CONNECT via Zastava Key must succeed on dual-stack RU IPv6");
    assert_eq!(echoed, b"ping-key");
    assert!(entry.counters.connect_requests.load(Ordering::SeqCst) >= 1);

    let tmp = tempdir().unwrap();
    let cr = run_clean_room_audit_with_route_env(
        &EmptyDetector,
        tmp.path(),
        &state,
        &auditor,
        None,
        Some(route.id.as_str()),
    )
    .await
    .unwrap();
    assert!(
        cr.ready_to_launch,
        "Clean Room must be ready on dual-stack RU IPv6 with Zastava Key: {:?}",
        cr.findings
    );
    srv_task.abort();
}

#[tokio::test]
async fn e2e_vpn_off_key_on_ru_stun_and_blocked_doh_tor_stays_green() {
    let _g = acquire_global_state().await;
    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "RU",
        block_doh_and_tor: true,
        stun_ip: "5.18.10.2",
        stun_cc: "RU",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: true,
        resolver_ip: "5.18.10.1",
    });
    let ru_ip = Ipv4Addr::new(5, 18, 10, 2);
    let udp = FakeUdp::new().with_server("stun.cloudflare.com:3478", move |req| {
        if req.len() < 20 {
            return vec![];
        }
        let mut tx = [0u8; 12];
        tx.copy_from_slice(&req[8..20]);
        vec![stun_binding_success_packet(ru_ip, 51820, &tx)]
    });
    let auditor = build_offline_auditor(probe, dns, udp);

    let entry = MockZastavaEntry::spawn(EntryMode::HttpHealthy, None).await;
    let route = entry.as_route("key-de-2", "DE Key 2");
    let state = AppState::new_in_memory();
    state.upsert_route(route.clone()).await.unwrap();
    state
        .bind_provider_route("anthropic", Some(&route.id))
        .await
        .unwrap();
    auditor
        .resolver
        .set_cached_for_route(Some(route.id.clone()), clean_de_telemetry())
        .await;

    let report = auditor
        .evaluate_all_with_protection(
            ProviderId::Anthropic,
            &state,
            false,
            AuditProtectionFlags {
                sysproxy_active: true,
                cli_or_sandbox_protection_active: true,
                os_pac_deferred: false,
            },
        )
        .await
        .unwrap();

    let stun_check = &report.checks[12];
    assert_eq!(stun_check.code, "UDP_STUN_KEY_ISOLATED");
    assert_eq!(stun_check.status, CheckStatus::Ok);
    assert_eq!(report.ipv6_result.code, "IPV6_KEY_TCP_ISOLATED");
    assert_eq!(report.overall_status, OverallStatus::Green);

    // Verify reconcile_key_exit_external_lists clears blocked DoH/DNSBL & Tor on verified key exit
    // (including when travel is HISTORY_FIRST_SESSION / NotApplicable!)
    let mut dnsbl_check = report.dnsbl_result.clone();
    let mut tor_check = zastava_lib::auditor::CheckResult::unknown(
        "TOR_LIST_UNAVAILABLE",
        "tor unavailable",
        zastava_lib::auditor::UnknownReason::Timeout,
    );
    let verified_exit = zastava_lib::auditor::CheckResult::ok("PROVIDER_EXIT_VERIFIED", "DE");
    zastava_lib::auditor::reconcile_key_exit_external_lists(
        true,
        true,
        &report.geo_result,
        &report.travel_result,
        &report.ipv6_result,
        &verified_exit,
        &mut dnsbl_check,
        &mut tor_check,
    );
    assert_eq!(dnsbl_check.code, "DNSBL_UNREACHABLE_KEY_OK");
    assert!(dnsbl_check.is_not_applicable());
    assert!(tor_check.is_not_applicable());
    let mut checks = report.checks.clone();
    checks[3] = dnsbl_check;
    checks[4] = tor_check;
    checks[13] = verified_exit;
    let verdict = zastava_lib::auditor::score_checks(&checks, true);
    assert!(!verdict.incomplete);
    assert_eq!(verdict.overall_status, OverallStatus::Green);
}

#[tokio::test]
async fn e2e_vpn_off_key_on_direct_non_ai_vs_key_ai_and_multi_account() {
    let _g = acquire_global_state().await;
    let target_a = MockEchoTarget::spawn().await;
    let target_b = MockEchoTarget::spawn().await;
    let target_direct = MockEchoTarget::spawn().await;

    let entry_a = MockZastavaEntry::spawn(EntryMode::HttpHealthy, Some(target_a.addr)).await;
    let entry_b = MockZastavaEntry::spawn(EntryMode::HttpHealthy, Some(target_b.addr)).await;
    let route_a = entry_a.as_route("key-a", "Key A");
    let route_b = entry_b.as_route("key-b", "Key B");

    let state = AppState::new_in_memory();
    state.upsert_route(route_a.clone()).await.unwrap();
    state.upsert_route(route_b.clone()).await.unwrap();
    state
        .bind_provider_route("anthropic", Some(&route_a.id))
        .await
        .unwrap();
    state
        .bind_provider_route("openai", Some(&route_b.id))
        .await
        .unwrap();

    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "DE",
        block_doh_and_tor: false,
        stun_ip: "185.100.10.2",
        stun_cc: "DE",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    auditor
        .resolver
        .set_cached_for_route(Some(route_a.id.clone()), clean_de_telemetry())
        .await;
    auditor
        .resolver
        .set_cached_for_route(Some(route_b.id.clone()), clean_de_telemetry())
        .await;

    let (srv, srv_task) =
        start_proxy_server(auditor, state.clone(), Some(target_direct.addr), None).await;

    let r1 = send_connect_and_echo(srv.bound_addr, "claude.ai:443", b"A1")
        .await
        .unwrap();
    assert_eq!(r1, b"A1");
    let r2 = send_connect_and_echo(srv.bound_addr, "chatgpt.com:443", b"B1")
        .await
        .unwrap();
    assert_eq!(r2, b"B1");
    let r3 = send_connect_and_echo(srv.bound_addr, "github.com:443", b"D1")
        .await
        .unwrap();
    assert_eq!(r3, b"D1");

    assert!(target_a.connections.load(Ordering::SeqCst) >= 1);
    let a_before_swap = target_a.connections.load(Ordering::SeqCst);
    assert!(target_b.connections.load(Ordering::SeqCst) >= 1);
    let b_before_swap = target_b.connections.load(Ordering::SeqCst);
    assert_eq!(target_direct.connections.load(Ordering::SeqCst), 1);

    state
        .bind_provider_route("anthropic", Some(&route_b.id))
        .await
        .unwrap();
    let r4 = send_connect_and_echo(srv.bound_addr, "claude.ai:443", b"A->B")
        .await
        .unwrap();
    assert_eq!(r4, b"A->B");
    assert_eq!(target_a.connections.load(Ordering::SeqCst), a_before_swap);
    assert!(target_b.connections.load(Ordering::SeqCst) > b_before_swap);
    srv_task.abort();
}

#[tokio::test]
async fn e2e_vpn_off_key_unreachable_or_poisoned_ssrf_fail_closed() {
    let _g = acquire_global_state().await;
    let direct_canary = MockEchoTarget::spawn().await;

    let dead_port = dead_local_port();
    let dead_route = Route {
        id: "dead-key".to_string(),
        label: "Dead Key".to_string(),
        raw_key: format!("http://127.0.0.1:{dead_port}"),
        entries: vec![Entry {
            proto: EntryProto::Http,
            host: "127.0.0.1".to_string(),
            port: dead_port,
            username: None,
            password: None,
            sni: None,
        }],
        exit_ip: None,
        country: Some("DE".to_string()),
        expires_at: None,
        enabled: true,
        added_at: 0,
    };

    let auth_407_entry = MockZastavaEntry::spawn(EntryMode::Auth407, None).await;
    let auth_route = auth_407_entry.as_route("auth-407", "Auth 407");

    let poisoned_route = Route {
        id: "poisoned-key".to_string(),
        label: "Poisoned Key".to_string(),
        raw_key: "socks5://poisoned.zastava.test:1080".to_string(),
        entries: vec![Entry {
            proto: EntryProto::Socks5,
            host: "poisoned.zastava.test".to_string(),
            port: 1080,
            username: None,
            password: None,
            sni: None,
        }],
        exit_ip: None,
        country: Some("DE".to_string()),
        expires_at: None,
        enabled: true,
        added_at: 0,
    };

    let state = AppState::new_in_memory();
    state.upsert_route(dead_route.clone()).await.unwrap();
    state.upsert_route(auth_route.clone()).await.unwrap();
    state.upsert_route(poisoned_route.clone()).await.unwrap();

    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "DE",
        block_doh_and_tor: false,
        stun_ip: "185.100.10.2",
        stun_cc: "DE",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    auditor
        .resolver
        .set_cached_for_route(Some(dead_route.id.clone()), clean_de_telemetry())
        .await;
    auditor
        .resolver
        .set_cached_for_route(Some(auth_route.id.clone()), clean_de_telemetry())
        .await;
    auditor
        .resolver
        .set_cached_for_route(Some(poisoned_route.id.clone()), clean_de_telemetry())
        .await;

    let (srv, srv_task) =
        start_proxy_server(auditor, state.clone(), Some(direct_canary.addr), None).await;

    state
        .bind_provider_route("anthropic", Some(&dead_route.id))
        .await
        .unwrap();
    let err1 = send_connect_and_echo(srv.bound_addr, "claude.ai:443", b"leak?")
        .await
        .unwrap_err();
    assert!(err1.contains("502") || err1.contains("403"), "got: {err1}");

    state
        .bind_provider_route("anthropic", Some(&auth_route.id))
        .await
        .unwrap();
    let err2 = send_connect_and_echo(srv.bound_addr, "claude.ai:443", b"leak?")
        .await
        .unwrap_err();
    assert!(err2.contains("502") || err2.contains("403"), "got: {err2}");

    {
        let _dns_guard = TestEntryDnsGuard::install(Arc::new(|host, port| {
            if host == "poisoned.zastava.test" {
                return Some(Ok(vec![
                    format!("127.0.0.1:{port}").parse().unwrap(),
                    format!("169.254.169.254:{port}").parse().unwrap(),
                ]));
            }
            None
        }));
        state
            .bind_provider_route("anthropic", Some(&poisoned_route.id))
            .await
            .unwrap();
        let err3 = send_connect_and_echo(srv.bound_addr, "claude.ai:443", b"leak?")
            .await
            .unwrap_err();
        assert!(err3.contains("502") || err3.contains("403"), "got: {err3}");
    }

    assert_eq!(
        direct_canary.connections.load(Ordering::SeqCst),
        0,
        "0 bytes may leak direct when Zastava Key fails or is SSRF-poisoned"
    );
    srv_task.abort();
}

#[tokio::test]
async fn e2e_vpn_off_key_on_pac_routes_ai_and_bypasses_non_ai() {
    let _g = acquire_global_state().await;
    let state = AppState::new_in_memory();
    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "DE",
        block_doh_and_tor: false,
        stun_ip: "185.100.10.2",
        stun_cc: "DE",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    let domains = {
        let matrix = auditor.rules.provider_matrix.read().await;
        get_all_ai_domains_filtered(&matrix, &[], &Default::default())
    };
    let pac = generate_pac_script(&domains, "127.0.0.1:8899", None);
    assert!(pac.contains("claude.ai"));
    assert!(pac.contains("return \"PROXY 127.0.0.1:8899\";"));
    assert!(pac.contains("return \"DIRECT\";"));
    assert!(!pac.contains("SOCKS5 "));
    let _ = (RouteSelection::Direct, state);
}

#[tokio::test]
async fn e2e_vpn_off_key_on_dns_country_isolated_for_key_route() {
    use zastava_lib::auditor::AuditProtectionContext;
    use zastava_lib::auditor::cache::TtlCache;
    use zastava_lib::auditor::probes::whoami::{
        AKAMAI_HOST, GOOGLE_TXT_HOST, evaluate_dns_country_for_route_with_protection,
        measure_resolver,
    };
    use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, addr};
    use zastava_lib::auditor::seams::{HttpProbeOutcome, LookupOutcome, TxtOutcome};

    let _g = acquire_global_state().await;
    let dns = FakeDns::new(LookupOutcome::NotFound)
        .with(AKAMAI_HOST, addr("95.179.10.1"))
        .with_txt(
            GOOGLE_TXT_HOST,
            TxtOutcome::Records(vec!["\"95.179.10.1\"".into()]),
        );
    let probe = FakeProbe::new(HttpProbeOutcome::Response {
        status: 200,
        body: r#"{"success":true,"ip":"95.179.10.1","country_code":"NL"}"#.into(),
    });
    let geo_cache = TtlCache::default();
    let view = measure_resolver(&dns, &probe, &geo_cache).await;
    let res = evaluate_dns_country_for_route_with_protection(
        &view,
        "DE",
        true,
        AuditProtectionContext::assumed_active_for_route(),
    );
    assert_eq!(res.status, CheckStatus::Ok);
    assert_eq!(res.code, "DNS_KEY_COUNTRY_ISOLATED");
}

#[tokio::test]
async fn e2e_commercial_socks5_host_port_user_pass_rfc1929_and_cascade() {
    let _g = acquire_global_state().await;
    let echo = MockEchoTarget::spawn().await;
    let entry =
        MockZastavaEntry::spawn_socks5_auth("demo_user", "demo_pass", Some(echo.addr)).await;
    let port = entry.addr.port();

    // 1. Parse both `socks5://127.0.0.1:<port>:demo_user:demo_pass` and bare `127.0.0.1:<port>:demo_user:demo_pass`.
    let route_prefixed = zastava_lib::routing::parse_route_key(
        &format!("socks5://127.0.0.1:{port}:demo_user:demo_pass"),
        1,
    )
    .unwrap();
    let route_bare =
        zastava_lib::routing::parse_route_key(&format!("127.0.0.1:{port}:demo_user:demo_pass"), 2)
            .unwrap();
    assert_eq!(route_bare.entries[0].proto, EntryProto::Socks5);
    assert_eq!(route_bare.entries[0].username.as_deref(), Some("demo_user"));
    assert_eq!(route_bare.entries[0].password.as_deref(), Some("demo_pass"));

    // 2. Tunnel end-to-end through Zastava proxy server -> MockZastavaEntry with RFC 1929 auth.
    for route in [&route_prefixed, &route_bare] {
        let state = AppState::new_in_memory();
        state.upsert_route(route.clone()).await.unwrap();
        state
            .bind_provider_route("anthropic", Some(&route.id))
            .await
            .unwrap();
        let probe = Arc::new(RuIspKeyProbe {
            ipv6_loc: "DE",
            block_doh_and_tor: false,
            stun_ip: "185.100.10.2",
            stun_cc: "DE",
        });
        let dns = Arc::new(OfflineDns {
            block_dnsbl: false,
            resolver_ip: "185.100.10.2",
        });
        let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
        auditor
            .resolver
            .set_cached_for_route(Some(route.id.clone()), clean_de_telemetry())
            .await;
        let (srv, srv_task) = start_proxy_server(auditor, state, None, None).await;
        let payload = send_connect_and_echo(srv.bound_addr, "claude.ai:443", b"ping-rfc1929")
            .await
            .unwrap();
        assert_eq!(payload, b"ping-rfc1929");
        srv_task.abort();
    }
    assert!(entry.counters.connect_requests.load(Ordering::SeqCst) >= 2);

    // 3. Verify `cascade.rs` sends username-only SOCKS5 auth (`demo_user`, empty password).
    let entry_user_only = MockZastavaEntry::spawn_socks5_auth("demo_user", "", None).await;
    let route_user_only = zastava_lib::routing::parse_route_key(
        &format!(
            "socks5://demo_user@127.0.0.1:{}",
            entry_user_only.addr.port()
        ),
        3,
    )
    .unwrap();
    let client =
        zastava_lib::auditor::network::build_entry_client(&route_user_only.entries[0], true, 0)
            .await
            .expect("build_entry_client must succeed for username-only SOCKS5");
    let resp = client
        .get(format!(
            "http://127.0.0.1:{}/echo",
            entry_user_only.addr.port()
        ))
        .send()
        .await;
    assert!(
        resp.is_ok(),
        "SOCKS5 username-only cascade request failed: {resp:?}"
    );
    assert_eq!(
        entry_user_only
            .counters
            .connect_requests
            .load(Ordering::SeqCst),
        1
    );
}
