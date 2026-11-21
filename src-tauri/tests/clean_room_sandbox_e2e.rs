//! E2E tests for Clean Room sandbox, per-profile loopback alias isolation (P0 Zero
//! Non-AI Split-IP Leak), anti-SSRF alias port registration, Hard Readiness Gate, and
//! fail-closed Chromium Preferences.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::geo_matrix::ProviderId;
use zastava_lib::auditor::network::NetworkTelemetry;
use zastava_lib::auditor::{Auditor, CheckResult, CheckStatus, OverallStatus, RiskReport};
use zastava_lib::clean_room::CleanProfileId;
use zastava_lib::clean_room::browser_sandbox::{
    build_hardened_chromium_args, write_fail_closed_preferences,
};
use zastava_lib::clean_room::detector::{DetectorEnv, DetectorInput, run_clean_room_audit_with};
use zastava_lib::core::net_safety::{is_alias_port, validate_tunnel_target};
use zastava_lib::proxy::hold_queue::HoldQueue;
use zastava_lib::proxy::{ProxyManager, ProxyServer};
use zastava_lib::routing::net::is_gateway_loop;
use zastava_lib::routing::{Entry, EntryProto, Route};
use zastava_lib::state::{AppState, AppStateData};

fn socks_route(id: &str, port: u16, enabled: bool) -> Route {
    Route {
        id: id.to_string(),
        label: format!("test {id}"),
        country: Some("US".to_string()),
        exit_ip: Some("198.51.100.10".to_string()),
        expires_at: None,
        entries: vec![Entry {
            proto: EntryProto::Socks5,
            host: "127.0.0.1".to_string(),
            port,
            username: None,
            password: None,
            sni: None,
        }],
        raw_key: format!("socks5://127.0.0.1:{port}"),
        enabled,
        added_at: 0,
    }
}

async fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn direct_sink() -> (std::net::SocketAddr, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((_s, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
        }
    });
    (addr, hits)
}

async fn spawn_socks_echo() -> (u16, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU64::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let h = Arc::clone(&h);
            tokio::spawn(async move {
                let mut g = [0u8; 3];
                if s.read_exact(&mut g).await.is_err() {
                    return;
                }
                let _ = s.write_all(&[0x05, 0x00]).await;
                let mut head = [0u8; 4];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut len = [0u8; 1];
                let _ = s.read_exact(&mut len).await;
                let mut rest = vec![0u8; len[0] as usize + 2];
                let _ = s.read_exact(&mut rest).await;
                h.fetch_add(1, Ordering::SeqCst);
                let _ = s
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let mut buf = [0u8; 512];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if buf[..n].starts_with(b"GET ") {
                        let resp =
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                        let _ = s.write_all(resp).await;
                        break;
                    }
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, hits)
}

async fn send_connect(proxy_port: u16, target_host: &str) -> (String, TcpStream) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!("CONNECT {target_host}:443 HTTP/1.1\r\nHost: {target_host}:443\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    (String::from_utf8_lossy(&buf[..n]).into_owned(), stream)
}

async fn send_plain_http(proxy_port: u16, url: &str, host: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn alias_routes_non_ai_connect_and_plain_http_without_direct_fallback() {
    let state = AppState::new_in_memory();
    let (socks_port, socks_hits) = spawn_socks_echo().await;
    let (direct_addr, direct_hits) = direct_sink().await;

    state
        .upsert_route(socks_route("r-us", socks_port, true))
        .await
        .unwrap();

    let auditor = Auditor::new().unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state.clone(), hold_queue, Some(direct_addr))
            .await
            .unwrap(),
    );
    let mgr = ProxyManager::from_server(server);

    let alias_port = mgr
        .ensure_profile_alias("cr-e2e-1", Some("r-us".to_string()))
        .await
        .unwrap();
    assert!(is_alias_port(alias_port));

    // Anti-SSRF: alias port must be rejected by validate_tunnel_target & is_gateway_loop
    assert!(validate_tunnel_target("127.0.0.1", alias_port, mgr.server.bound_addr.port()).is_err());
    assert!(is_gateway_loop(
        &std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        alias_port,
        mgr.server.bound_addr.port()
    ));

    // Non-AI CONNECT targets must all go through the bound route, never direct
    for host in [
        "api.stripe.com",
        "withpersona.com",
        "challenges.cloudflare.com",
        "appleid.apple.com",
        "ipinfo.io",
    ] {
        let (status, mut stream) = send_connect(alias_port, host).await;
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "expected 200 for {host}, got {status}"
        );
        stream.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
    }

    // Plain HTTP non-AI must also go through the bound route, never direct
    let http_resp = send_plain_http(alias_port, "http://ipinfo.io/json", "ipinfo.io").await;
    assert!(
        http_resp.starts_with("HTTP/1.1 200"),
        "expected 200 for plain HTTP via alias, got {http_resp}"
    );
    assert_eq!(socks_hits.load(Ordering::SeqCst), 6);
    assert_eq!(direct_hits.load(Ordering::SeqCst), 0);

    // Disabled route must fail closed with 403 (CONNECT & plain HTTP)
    state.set_route_enabled("r-us", false).await.unwrap();
    let (disabled_connect, _) = send_connect(alias_port, "api.stripe.com").await;
    assert!(
        disabled_connect.starts_with("HTTP/1.1 403"),
        "{disabled_connect}"
    );
    let disabled_http = send_plain_http(alias_port, "http://ipinfo.io/json", "ipinfo.io").await;
    assert!(disabled_http.starts_with("HTTP/1.1 403"), "{disabled_http}");
    assert_eq!(direct_hits.load(Ordering::SeqCst), 0);

    // Unreachable route must fail closed with 502 (CONNECT & plain HTTP)
    let dead_port = closed_port().await;
    state
        .upsert_route(socks_route("r-dead", dead_port, true))
        .await
        .unwrap();
    let dead_alias = mgr
        .ensure_profile_alias("cr-e2e-dead", Some("r-dead".to_string()))
        .await
        .unwrap();
    let (dead_connect, _) = send_connect(dead_alias, "withpersona.com").await;
    assert!(dead_connect.starts_with("HTTP/1.1 502"), "{dead_connect}");
    let dead_http = send_plain_http(dead_alias, "http://ipinfo.io/json", "ipinfo.io").await;
    assert!(dead_http.starts_with("HTTP/1.1 502"), "{dead_http}");
    assert_eq!(direct_hits.load(Ordering::SeqCst), 0);

    mgr.stop_profile_alias("cr-e2e-1").await;
    mgr.stop_profile_alias("cr-e2e-dead").await;
    assert!(!is_alias_port(alias_port));
    assert!(!is_alias_port(dead_alias));
}

struct EmptyEnv;
impl DetectorEnv for EmptyEnv {
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

fn ok_check(code: &str) -> CheckResult {
    CheckResult {
        status: CheckStatus::Ok,
        code: code.to_string(),
        message: "ok".to_string(),
        guide_ref: None,
        reason: None,
        checked_at: None,
        measured_via: None,
        detail: None,
    }
}

#[test]
fn readiness_gate_fail_closed_preferences_and_path_traversal_guard() {
    let mut state = AppStateData::default();
    let report = RiskReport {
        provider: ProviderId::Anthropic,
        overall_status: OverallStatus::Green,
        trust_score: 100,
        telemetry: NetworkTelemetry {
            ip: "198.51.100.20".to_string(),
            country_code: "US".to_string(),
            hostname: None,
            asn: Some(13335),
            org: None,
            isp: Some("Cloudflare".to_string()),
            timezone: Some("America/New_York".to_string()),
            resolved_at: 1_700_000_000,
        },
        geo_result: ok_check("geo"),
        pinning_result: ok_check("pinning"),
        travel_result: ok_check("travel"),
        dnsbl_result: ok_check("dnsbl"),
        dnsbl_clean_count: "5/5".to_string(),
        asn_result: ok_check("asn"),
        ipv6_result: ok_check("ipv6"),
        timezone_result: ok_check("timezone"),
        ipv6_exit: false,
        checks: vec![],
        unknown_count: 0,
        applicable_count: 1,
        incomplete: false,
        gateway_latency_ms: None,
    };

    let clean_audit = run_clean_room_audit_with(
        &EmptyEnv,
        &DetectorInput {
            target_provider: ProviderId::Anthropic,
            target_profile_id: None,
            risk_report: Some(&report),
            audit_error: None,
            state_data: &state,
            claude_profiles: &[],
            os_tz: Some("America/New_York"),
            now_secs: 1_700_000_010,
        },
    );
    assert!(clean_audit.ready_to_launch);

    state.manual_killswitch = true;
    let blocked_audit = run_clean_room_audit_with(
        &EmptyEnv,
        &DetectorInput {
            target_provider: ProviderId::Anthropic,
            target_profile_id: None,
            risk_report: Some(&report),
            audit_error: None,
            state_data: &state,
            claude_profiles: &[],
            os_tz: Some("America/New_York"),
            now_secs: 1_700_000_010,
        },
    );
    assert!(!blocked_audit.ready_to_launch);
    assert!(blocked_audit.critical_count >= 1);

    // Path traversal rejection + fail-closed Preferences + hardened flags
    assert!(CleanProfileId::parse("../outside").is_err());
    assert!(CleanProfileId::parse("a/b").is_err());
    let id = CleanProfileId::parse("e2e-safe-1").unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let profile_dir = tmp.path().join("clean-profiles").join(id.as_str());
    let prefs_path = write_fail_closed_preferences(&profile_dir, 51234).unwrap();
    let prefs: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&prefs_path).unwrap()).unwrap();
    assert_eq!(prefs["proxy"]["mode"], "fixed_servers");
    assert_eq!(prefs["proxy"]["server"], "http://127.0.0.1:51234");
    assert_eq!(prefs["dns_over_https"]["mode"], "off");

    let args = build_hardened_chromium_args(&profile_dir, 51234, Some("https://claude.ai"));
    assert!(args.iter().any(|a| a == "--disable-quic"));
    assert!(args.iter().any(|a| a == "--disable-features=DnsOverHttps"));
    assert!(
        !args
            .iter()
            .any(|a| a.contains("WebRtcHideLocalIpsWithMdns"))
    );
    let _ = HashSet::<String>::new();
}
