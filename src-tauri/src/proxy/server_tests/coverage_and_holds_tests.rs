use super::super::*;
use crate::proxy::coverage::{CoverageEnv, PacSource};
use crate::proxy::hold_queue::HoldQueue;
use crate::state::AppState;
use crate::sysproxy::browser_policies::FakePolicyStore;
use crate::sysproxy::platform::FakePlatform;

pub(super) fn offline_test_auditor() -> Auditor {
    use crate::auditor::AuditEnv;
    use crate::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
    use crate::auditor::seams::{HttpProbeOutcome, LookupOutcome};

    let env = AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(FakeProbe::new(HttpProbeOutcome::Timeout)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    };
    Auditor::with_env(env).expect("offline test auditor")
}

pub(super) async fn started() -> Arc<ProxyServer> {
    crate::sysproxy::force_os_dry_run();
    let auditor = offline_test_auditor();
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor,
            AppState::new_in_memory(),
            Arc::new(HoldQueue::new()),
            None,
        )
        .await
        .expect("bind"),
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });
    server
}

pub(super) async fn request(addr: SocketAddr, text: &str) -> Option<String> {
    let mut c = TcpStream::connect(addr).await.ok()?;
    c.write_all(text.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut buf)).await;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[tokio::test]
async fn proxy_pac_is_counted_apart_and_gateway_addr_is_the_real_one() {
    let server = started().await;
    let addr = server.bound_addr;
    let req = format!(
        "GET http://{addr}/proxy.pac HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: curl/8.7.1\r\nConnection: close\r\n\r\n"
    );
    let Some(resp) = request(addr, &req).await else {
        return; // loopback is not available in this sandbox
    };
    assert!(resp.contains("HTTP/1.1 200 OK"), "{resp}");
    // The health page is not an AI request either.
    let _ = request(addr, "GET / HTTP/1.1\r\nUser-Agent: curl/8.7.1\r\n\r\n").await;

    let platform = FakePlatform::new();
    let policy_store = FakePolicyStore::new();
    let env = CoverageEnv {
        platform: &platform,
        policy_store: &*policy_store,
        files: None,
        pac_source: PacSource::Services,
        sysproxy_enabled: false,
        cli_protection_enabled: false,
        chained_proxy: None,
        jetbrains_xml_confirmed: false,
    };
    let snap = server.coverage.snapshot(&env, true);
    let curl = snap.apps.iter().find(|a| a.id == "curl").unwrap();
    assert_eq!(curl.pac_fetches, 1);
    assert_eq!(curl.ai_requests, 0);
    assert_ne!(
        curl.status,
        crate::proxy::coverage::CoverageStatus::Confirmed
    );
    assert_eq!(snap.gateway_addr, Some(addr.to_string()));
    assert_eq!(snap.pac_url, Some(format!("http://{addr}/proxy.pac")));
}

#[tokio::test]
async fn browser_extension_connect_and_ws_tunnel_for_ai_apis_succeeds() {
    let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(_) => return,
    };
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        while let Ok((mut s, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    crate::sysproxy::force_os_dry_run();
    let auditor = Auditor::new().expect("auditor");
    let state = AppState::new_in_memory();
    for p in ["anthropic", "openai", "gemini"] {
        state.allow_provider_for_session(p).await.unwrap();
    }
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state, Arc::new(HoldQueue::new()), Some(echo_addr))
            .await
            .expect("bind"),
    );
    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    let srv_task = tokio::spawn(async move { srv.run().await });

    let cases = [
        (
            "api.anthropic.com",
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        (
            "claude.ai",
            "moz-extension://12345678-1234-1234-1234-123456789abc",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
        ),
        (
            "api.openai.com",
            "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        (
            "chatgpt.com",
            "chrome-extension://cccccccccccccccccccccccccccccccc",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        (
            "gemini.google.com",
            "chrome-extension://dddddddddddddddddddddddddddddddd",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        (
            "generativelanguage.googleapis.com",
            "moz-extension://87654321-4321-4321-4321-cba987654321",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
        ),
        (
            "clients6.google.com",
            "chrome-extension://eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        (
            "aistudio.google.com",
            "chrome-extension://ffffffffffffffffffffffffffffffff",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
    ];

    for (host, origin, ua) in cases {
        let mut client = match TcpStream::connect(addr).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let req = format!(
            "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nOrigin: {origin}\r\nUser-Agent: {ua}\r\nProxy-Connection: keep-alive\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut head_buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut head_buf))
            .await
            .unwrap()
            .unwrap();
        let head = String::from_utf8_lossy(&head_buf[..n]);
        assert!(
            head.starts_with("HTTP/1.1 200 Connection Established"),
            "failed CONNECT for {host} ({origin}): {head}"
        );

        // Simulate WebSocket/HTTPS frame tunneled through the established CONNECT tunnel.
        let payload = format!(
            "GET /v1/ws HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nUpgrade: websocket\r\n\r\n"
        );
        client.write_all(payload.as_bytes()).await.unwrap();
        let mut echo = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut echo))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&echo), payload);
    }

    // Allow spawned coverage lookup/recording to settle, then verify no misclassifications.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let platform = FakePlatform::new();
    let policy_store = FakePolicyStore::new();
    let env = CoverageEnv {
        platform: &platform,
        policy_store: &*policy_store,
        files: None,
        pac_source: PacSource::Services,
        sysproxy_enabled: true,
        cli_protection_enabled: false,
        chained_proxy: None,
        jetbrains_xml_confirmed: false,
    };
    let snap = server.coverage.snapshot(&env, true);
    let browsers = snap.apps.iter().find(|a| a.id == "browsers").unwrap();
    assert!(
        browsers.ai_requests >= 8
            || browsers.status == crate::proxy::coverage::CoverageStatus::Confirmed,
        "expected browser extension requests to be recorded under browsers: {browsers:?}"
    );

    srv_task.abort();
    echo_task.abort();
}

#[tokio::test]
async fn pac_excludes_disabled_providers_and_disables_cache() {
    let server = started().await;
    server
        .state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();
    let addr = server.bound_addr;
    let req = format!(
        "GET http://{addr}/proxy.pac HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    );
    let Some(resp) = request(addr, &req).await else {
        return;
    };
    assert!(resp.contains("Cache-Control: no-store"), "{resp}");
    assert!(resp.contains("anthropic.com"), "{resp}");
    assert!(!resp.contains("gemini.google.com"), "{resp}");
    assert!(!resp.contains("google.com"), "{resp}");
}

#[tokio::test]
async fn disabled_provider_connect_is_bypassed_without_blocking_or_ai_coverage() {
    let server = started().await;
    // Disable gemini and mark it blocked (e.g. from before) + engage AskPopup:
    // disabling cleared its block and CONNECT must treat gemini hosts as direct pass-through
    // without opening hold_queue or counting as AI coverage.
    server
        .state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();
    let addr = server.bound_addr;
    let req = "CONNECT gemini.google.com:443 HTTP/1.1\r\nHost: gemini.google.com:443\r\nUser-Agent: curl/8.7.1\r\n\r\n";
    let Ok(mut conn) = TcpStream::connect(addr).await else {
        return;
    };
    let _ = conn.write_all(req.as_bytes()).await;
    let mut head = [0u8; 256];
    let _ = tokio::time::timeout(Duration::from_millis(500), conn.read(&mut head)).await;
    assert!(server.hold_queue.current_alert().is_none());
    let stats = server.state.stats().snapshot().await;
    assert!(
        stats.direct_bypassed_requests >= 1
            && stats
                .recent_events
                .iter()
                .any(|e| e.host == "gemini.google.com"),
        "expected disabled gemini host to record direct bypass: {stats:?}"
    );
}

#[test]
fn report_allowed_for_state_allows_yellow_and_trusted_exceptions_without_blocking() {
    use crate::auditor::{CheckResult, NetworkTelemetry, OverallStatus, RiskReport};
    use crate::state::AppStateData;

    let ok = CheckResult::ok("T", "ok");
    let base_tel = NetworkTelemetry {
        ip: "5.5.5.5".to_string(),
        country_code: "KZ".to_string(),
        hostname: None,
        asn: Some(1),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: 0,
    };
    let yellow_report = RiskReport {
        provider: ProviderId::Anthropic,
        overall_status: OverallStatus::Yellow,
        trust_score: 70,
        telemetry: base_tel.clone(),
        geo_result: CheckResult::ok("GEO_LOCATION", "KZ"),
        pinning_result: ok.clone(),
        travel_result: ok.clone(),
        dnsbl_result: ok.clone(),
        dnsbl_clean_count: "0/0".to_string(),
        asn_result: ok.clone(),
        ipv6_result: ok.clone(),
        timezone_result: CheckResult::warning("TIMEZONE_MISMATCH", "TZ offset", None),
        ipv6_exit: false,
        checks: vec![
            CheckResult::ok("GEO_LOCATION", "KZ"),
            CheckResult::warning("TIMEZONE_MISMATCH", "TZ offset", None),
        ],
        unknown_count: 0,
        applicable_count: 14,
        incomplete: false,
    };
    let st = AppStateData::default();
    assert!(crate::proxy::guard::report_allowed_for_state(
        &yellow_report,
        &st,
        false
    ));

    let mut red_report = yellow_report.clone();
    red_report.overall_status = OverallStatus::Red;
    red_report.telemetry.country_code = "RU".to_string();
    red_report.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
    red_report.checks = vec![red_report.geo_result.clone()];
    assert!(!crate::proxy::guard::report_allowed_for_state(
        &red_report,
        &st,
        false
    ));

    let mut st_except = st.clone();
    st_except
        .trusted_exceptions
        .insert("anthropic".to_string(), vec!["5.5.5.5".to_string()]);
    assert!(crate::proxy::guard::report_allowed_for_state(
        &red_report,
        &st_except,
        false
    ));
}
