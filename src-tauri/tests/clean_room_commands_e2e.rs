//! Command-level & regression E2E tests for Clean Room (P0 #1, #2, #3; P1 #4, #5, #6; P2 #9):
//! - Direct Clean Room profiles (`bound_route_id: None`) normalize to `DIRECT_ROUTE_ID` and
//!   route via `FollowGate` (while unassigned `None` in `ProxyServer` stays fail-closed `403`).
//! - Hard Readiness Gate fails closed (`ready_to_launch == false`) when bound route is
//!   disabled/missing or `risk_report` is `None`.
//! - Server-side `launch_clean_browser` preflight rejects `CleanProfileStatus::Tainted`.
//! - `provider: "custom"` is accepted on profile creation and audited with Anthropic fallback.
//! - Disabling or deleting a bound route aborts live open Clean Room alias tunnels immediately.
//! - Protection flags refresh (`via_zastava_key` Precondition 2) and Windows CLI `claude.exe`
//!   exclusion in `detector_env`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::geo_matrix::ProviderId;
use zastava_lib::auditor::network::current_timestamp;
use zastava_lib::auditor::probes::whoami::{AKAMAI_HOST, GOOGLE_TXT_HOST};
use zastava_lib::auditor::seams::fakes::{FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{
    AuditEnv, BoxFuture, DnsLookup, HttpProbeOutcome, IpProbe, LookupOutcome, TxtOutcome,
};
use zastava_lib::auditor::{AuditProtectionFlags, Auditor, CheckStatus};
use zastava_lib::clean_room::detector::DetectorEnv;
use zastava_lib::clean_room::detector_env::parse_windows_running_ai_processes;
use zastava_lib::clean_room::{
    CleanProfileStatus, CleanRoomFixAction, CreateCleanProfileInput, TraceSeverity,
};
use zastava_lib::commands::clean_room::{
    create_clean_profile_in, delete_clean_profile_in, prepare_clean_browser_launch_with_env,
    resolve_audit_provider, run_clean_room_audit_with_env, run_clean_room_audit_with_route_env,
    untaint_clean_room_ip_in, update_clean_profile_route_in,
};
use zastava_lib::core::net_safety::is_alias_port;
use zastava_lib::proxy::hold_queue::HoldQueue;
use zastava_lib::proxy::{ProxyManager, ProxyServer};
use zastava_lib::routing::{DIRECT_ROUTE_ID, Entry, EntryProto, Route, RouteSelection};
use zastava_lib::state::AppState;
use zastava_lib::sysproxy::force_os_dry_run;

struct EmptyDetectorEnv;
impl DetectorEnv for EmptyDetectorEnv {
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

struct CleanUsProbe;
impl IpProbe for CleanUsProbe {
    fn get<'a>(&'a self, url: &'a str, _limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
        Box::pin(async move {
            if url.contains("ipwho.is") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: json!({
                        "success": true,
                        "ip": "198.51.100.42",
                        "country_code": "US",
                        "connection": { "asn": 13335, "org": "Cloudflare", "isp": "Cloudflare" },
                        "timezone": { "id": "America/New_York" },
                    })
                    .to_string(),
                };
            }
            if url.contains("/cdn-cgi/trace") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: "fl=1\nip=198.51.100.42\nloc=US\ncolo=EWR\n".to_string(),
                };
            }
            if url.contains("torbulkexitlist") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: "192.0.2.99\n".to_string(),
                };
            }
            HttpProbeOutcome::Timeout
        })
    }
}

struct CleanUsDns;
impl DnsLookup for CleanUsDns {
    fn lookup<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, LookupOutcome> {
        Box::pin(async move {
            if host == AKAMAI_HOST {
                let ip: IpAddr = "198.51.100.42".parse().unwrap();
                return LookupOutcome::Addrs(vec![ip]);
            }
            if host.starts_with("42.100.51.198.") {
                return LookupOutcome::NotFound;
            }
            LookupOutcome::Addrs(vec![IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1))])
        })
    }

    fn lookup_uncached<'a>(
        &'a self,
        host: &'a str,
        limit: Duration,
    ) -> BoxFuture<'a, LookupOutcome> {
        self.lookup(host, limit)
    }

    fn lookup_txt<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, TxtOutcome> {
        Box::pin(async move {
            if host == GOOGLE_TXT_HOST {
                return TxtOutcome::Records(vec!["\"198.51.100.42\"".to_string()]);
            }
            TxtOutcome::NotFound
        })
    }
}

fn clean_us_auditor() -> Auditor {
    force_os_dry_run();
    let env = AuditEnv {
        dns: Arc::new(CleanUsDns),
        probe: Arc::new(CleanUsProbe),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        }),
    };
    Auditor::with_env(env).unwrap()
}

fn socks_route(id: &str, port: u16, enabled: bool) -> Route {
    Route {
        id: id.to_string(),
        label: format!("Route {id}"),
        country: Some("US".to_string()),
        exit_ip: Some("198.51.100.42".to_string()),
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

async fn spawn_direct_echo() -> (std::net::SocketAddr, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let h = Arc::clone(&h);
            tokio::spawn(async move {
                h.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 512];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if buf[..n].starts_with(b"GET ") {
                        let _ = s
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect",
                            )
                            .await;
                        break;
                    }
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, hits)
}

async fn spawn_socks_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
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
                let _ = s
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let mut buf = [0u8; 512];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn setup_mgr(
    auditor: Auditor,
    state: AppState,
    direct_addr: std::net::SocketAddr,
) -> ProxyManager {
    let hold = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state, hold, Some(direct_addr))
            .await
            .unwrap(),
    );
    ProxyManager::from_server(server)
}

#[tokio::test]
async fn direct_profile_normalizes_and_routes_via_follow_gate_not_403_unassigned() {
    let tmp = tempfile::tempdir().unwrap();
    let state = AppState::new_in_memory();
    let auditor = clean_us_auditor();
    let (direct_addr, direct_hits) = spawn_direct_echo().await;
    let mgr = setup_mgr(auditor.clone(), state.clone(), direct_addr).await;

    let profile = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "Direct US".to_string(),
            provider: "anthropic".to_string(),
            browser_engine: "chrome".to_string(),
            bound_route_id: None,
        },
        &state,
    )
    .await
    .unwrap();
    assert!(profile.bound_route_id.is_none());

    // Launch preflight must normalize None -> DIRECT_ROUTE_ID and succeed
    let (_id, _prof, audit, alias_port) = prepare_clean_browser_launch_with_env(
        &EmptyDetectorEnv,
        tmp.path(),
        &profile.id,
        &state,
        &auditor,
        &mgr,
    )
    .await
    .expect("direct profile preflight must pass");
    assert!(audit.ready_to_launch);
    assert!(is_alias_port(alias_port));

    // CONNECT & plain HTTP must route via Direct/FollowGate (200), NOT 403 unassigned
    let mut stream = TcpStream::connect(("127.0.0.1", alias_port)).await.unwrap();
    stream
        .write_all(b"CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut resp = [0u8; 256];
    let n = stream.read(&mut resp).await.unwrap();
    let head = String::from_utf8_lossy(&resp[..n]);
    assert!(head.starts_with("HTTP/1.1 200"), "expected 200, got {head}");
    stream.write_all(b"hello").await.unwrap();
    let mut echo = [0u8; 5];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"hello");

    let mut plain = TcpStream::connect(("127.0.0.1", alias_port)).await.unwrap();
    plain
        .write_all(
            b"GET http://ipinfo.io/json HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut plain_buf = Vec::new();
    plain.read_to_end(&mut plain_buf).await.unwrap();
    let plain_str = String::from_utf8_lossy(&plain_buf);
    assert!(plain_str.starts_with("HTTP/1.1 200"), "{plain_str}");
    assert!(plain_str.ends_with("direct"));
    assert_eq!(direct_hits.load(Ordering::SeqCst), 2);

    // Unassigned alias (explicit None passed directly to ensure_profile_alias) stays fail-closed 403
    let unassigned_port = mgr
        .ensure_profile_alias("unassigned-test", None)
        .await
        .unwrap();
    let mut ua = TcpStream::connect(("127.0.0.1", unassigned_port))
        .await
        .unwrap();
    ua.write_all(b"CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut ua_buf = [0u8; 256];
    let ua_n = ua.read(&mut ua_buf).await.unwrap();
    let ua_resp = String::from_utf8_lossy(&ua_buf[..ua_n]);
    assert!(ua_resp.starts_with("HTTP/1.1 403"), "{ua_resp}");
    assert!(
        ua_resp.contains("route key was removed") || ua_resp.contains("fail-closed"),
        "{ua_resp}"
    );

    let _ = DIRECT_ROUTE_ID;
    mgr.stop_profile_alias(&profile.id).await;
    mgr.stop_profile_alias("unassigned-test").await;
}

#[tokio::test]
async fn audit_error_and_tainted_profile_and_custom_provider_enforcement() {
    let tmp = tempfile::tempdir().unwrap();
    let state = AppState::new_in_memory();
    let auditor = clean_us_auditor();
    let (direct_addr, _) = spawn_direct_echo().await;
    let mgr = setup_mgr(auditor.clone(), state.clone(), direct_addr).await;

    // 1. P1 #4: provider: "custom" is accepted and maps to Anthropic only for audit fallback
    assert_eq!(
        resolve_audit_provider(Some("custom")),
        ProviderId::Anthropic
    );
    let custom_prof = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "Custom SaaS".to_string(),
            provider: "custom".to_string(),
            browser_engine: "chrome".to_string(),
            bound_route_id: None,
        },
        &state,
    )
    .await
    .expect("custom provider must be accepted");
    assert_eq!(custom_prof.provider, "custom");
    let custom_audit = run_clean_room_audit_with_env(
        &EmptyDetectorEnv,
        tmp.path(),
        &state,
        &auditor,
        Some(&custom_prof.id),
    )
    .await
    .unwrap();
    assert!(custom_audit.ready_to_launch);

    // 2. P0 #2: bound route missing/disabled => audit errors -> risk_report == None -> Critical + ready_to_launch == false
    state
        .upsert_route(socks_route("r-disabled", 19001, false))
        .await
        .unwrap();
    let disabled_prof = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "Disabled Route".to_string(),
            provider: "anthropic".to_string(),
            browser_engine: "chrome".to_string(),
            bound_route_id: Some("r-disabled".to_string()),
        },
        &state,
    )
    .await
    .unwrap();
    let failed_audit = run_clean_room_audit_with_env(
        &EmptyDetectorEnv,
        tmp.path(),
        &state,
        &auditor,
        Some(&disabled_prof.id),
    )
    .await
    .unwrap();
    assert!(!failed_audit.ready_to_launch);
    assert!(failed_audit.critical_count >= 1);
    assert!(failed_audit.findings.iter().any(|f| {
        f.id == "network_audit_failed"
            && f.severity == TraceSeverity::Critical
            && f.fix_action == Some(CleanRoomFixAction::SwitchRouteOrVpn)
    }));
    let err = prepare_clean_browser_launch_with_env(
        &EmptyDetectorEnv,
        tmp.path(),
        &disabled_prof.id,
        &state,
        &auditor,
        &mgr,
    )
    .await
    .unwrap_err();
    assert!(err.contains("заблокирован проверкой безопасности"), "{err}");

    // 3. P0 #3: Tainted profile must be rejected server-side BEFORE audit/launch
    let tainted_prof = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "Tainted Acc".to_string(),
            provider: "anthropic".to_string(),
            browser_engine: "chrome".to_string(),
            bound_route_id: None,
        },
        &state,
    )
    .await
    .unwrap();
    {
        let mut w = state.write().await;
        w.clean_room
            .profiles
            .iter_mut()
            .find(|p| p.id == tainted_prof.id)
            .unwrap()
            .status = CleanProfileStatus::Tainted;
    }
    let tainted_err = prepare_clean_browser_launch_with_env(
        &EmptyDetectorEnv,
        tmp.path(),
        &tainted_prof.id,
        &state,
        &auditor,
        &mgr,
    )
    .await
    .unwrap_err();
    assert!(
        tainted_err.contains("отмечен после блокировки"),
        "{tainted_err}"
    );
}

#[tokio::test]
async fn disabling_or_removing_bound_route_aborts_live_alias_tunnel_immediately() {
    let state = AppState::new_in_memory();
    let auditor = clean_us_auditor();
    let (direct_addr, _) = spawn_direct_echo().await;
    let socks_port = spawn_socks_echo().await;
    state
        .upsert_route(socks_route("r-live", socks_port, true))
        .await
        .unwrap();

    let mgr = setup_mgr(auditor, state.clone(), direct_addr).await;
    let alias_port = mgr
        .ensure_profile_alias("cr-tunnel", Some("r-live".to_string()))
        .await
        .unwrap();

    // Open active CONNECT tunnel
    let mut tunnel = TcpStream::connect(("127.0.0.1", alias_port)).await.unwrap();
    tunnel
        .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut head = [0u8; 128];
    let n = tunnel.read(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
    tunnel.write_all(b"alive").await.unwrap();
    let mut echo = [0u8; 5];
    tunnel.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"alive");

    // Disable route -> live tunnel MUST abort immediately (EOF/reset)
    state.set_route_enabled("r-live", false).await.unwrap();
    let mut probe_buf = [0u8; 16];
    let closed = tokio::time::timeout(Duration::from_millis(800), tunnel.read(&mut probe_buf))
        .await
        .expect("tunnel did not abort on route disable");
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "expected closed tunnel after disable, got {closed:?}"
    );

    // Re-enable, open second live tunnel, then remove route -> aborts & stops alias listener
    state.set_route_enabled("r-live", true).await.unwrap();
    let mut tunnel2 = TcpStream::connect(("127.0.0.1", alias_port)).await.unwrap();
    tunnel2
        .write_all(b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")
        .await
        .unwrap();
    let n2 = tunnel2.read(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head[..n2]).starts_with("HTTP/1.1 200"));

    state.remove_route("r-live").await.unwrap();
    mgr.stop_aliases_for_route("r-live").await;
    let closed2 = tokio::time::timeout(Duration::from_millis(800), tunnel2.read(&mut probe_buf))
        .await
        .expect("tunnel did not abort on route removal");
    assert!(matches!(closed2, Ok(0) | Err(_)));
    assert!(!is_alias_port(alias_port));
}

#[tokio::test]
async fn protection_flags_and_windows_cli_process_filter() {
    force_os_dry_run();
    let state = AppState::new_in_memory();
    let env = AuditEnv {
        dns: Arc::new(CleanUsDns),
        probe: Arc::new(CleanUsProbe),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem {
            global_ipv6: Some(true),
            dns_listing: Ok("resolver #1\n  nameserver[0] : 77.88.8.8\n".into()),
            ..FakeSystem::healthy()
        }),
    };
    let auditor = Auditor::with_env(env).unwrap();
    let socks_port = spawn_socks_echo().await;
    let route = socks_route("r-dns", socks_port, true);
    state.upsert_route(route.clone()).await.unwrap();
    auditor
        .resolver
        .set_cached_for_route(
            Some("r-dns".to_string()),
            zastava_lib::auditor::network::NetworkTelemetry {
                ip: "198.51.100.42".to_string(),
                country_code: "US".to_string(),
                hostname: None,
                asn: Some(13335),
                org: Some("Cloudflare".to_string()),
                isp: Some("Cloudflare".to_string()),
                timezone: Some("America/New_York".to_string()),
                resolved_at: current_timestamp(),
            },
        )
        .await;

    // Without protection flags -> Yandex/ISP DNS finding stands (not isolated)
    let report_unprotected = auditor
        .evaluate_all_with_selection_protection(
            ProviderId::Anthropic,
            &state,
            &RouteSelection::Route(route.clone()),
            false,
            AuditProtectionFlags {
                sysproxy_active: false,
                cli_or_sandbox_protection_active: false,
                os_pac_deferred: false,
            },
        )
        .await
        .unwrap();
    assert!(
        report_unprotected
            .checks
            .iter()
            .any(|c| c.status != CheckStatus::Ok && c.code.contains("DNS")),
        "expected non-Ok DNS check without protection flags: {:?}",
        report_unprotected.checks
    );

    // Updating protection flags -> DNS_KEY_REMOTE_RESOLVE (Ok)
    let report_protected = auditor
        .evaluate_all_with_selection_protection(
            ProviderId::Anthropic,
            &state,
            &RouteSelection::Route(route),
            false,
            AuditProtectionFlags {
                sysproxy_active: true,
                cli_or_sandbox_protection_active: true,
                os_pac_deferred: false,
            },
        )
        .await
        .unwrap();
    assert!(
        report_protected
            .checks
            .iter()
            .any(|c| c.code == "DNS_KEY_REMOTE_RESOLVE" && c.status == CheckStatus::Ok),
        "expected DNS_KEY_REMOTE_RESOLVE with protection flags: {:?}",
        report_protected.checks
    );
    assert!(auditor.current_protection_flags().sysproxy_active);

    // Windows CLI claude.exe ignored; Claude Desktop MSIX/Classic flagged
    let procs = parse_windows_running_ai_processes(
        "10|claude.exe|C:\\Users\\u\\.local\\bin\\claude.exe\n\
         20|claude.exe|C:\\Users\\u\\AppData\\Local\\AnthropicClaude\\app-1.0\\claude.exe\n",
    );
    assert_eq!(procs, vec!["claude.exe".to_string()]);
}

#[tokio::test]
async fn preflight_defaults_to_active_route_rebinds_and_stops_silent_auto_taint() {
    let tmp = tempfile::tempdir().unwrap();
    let state = AppState::new_in_memory();
    let auditor = clean_us_auditor();
    let (direct_addr, _) = spawn_direct_echo().await;
    let mgr = setup_mgr(auditor.clone(), state.clone(), direct_addr).await;
    let reg = zastava_lib::clean_room::browser_sandbox::SandboxProcessRegistry::new();

    let socks_port = spawn_socks_echo().await;
    state
        .upsert_route(socks_route("r-active", socks_port, true))
        .await
        .unwrap();
    state.set_default_route(Some("r-active")).await.unwrap();
    let active_tel = zastava_lib::auditor::network::NetworkTelemetry {
        ip: "198.51.100.88".into(),
        country_code: "US".into(),
        hostname: None,
        asn: Some(13335),
        org: None,
        isp: Some("Cloudflare".into()),
        timezone: Some("America/New_York".into()),
        resolved_at: current_timestamp(),
    };
    auditor
        .resolver
        .set_cached_for_route(Some("r-active".into()), active_tel)
        .await;

    let a1 = run_clean_room_audit_with_route_env(
        &EmptyDetectorEnv,
        tmp.path(),
        &state,
        &auditor,
        None,
        None,
    )
    .await
    .unwrap();
    let a2 = run_clean_room_audit_with_route_env(
        &EmptyDetectorEnv,
        tmp.path(),
        &state,
        &auditor,
        None,
        Some("direct"),
    )
    .await
    .unwrap();
    assert_eq!(
        (a1.exit_ip.as_deref(), a2.exit_ip.as_deref()),
        (Some("198.51.100.88"), Some("198.51.100.42"))
    );

    let mk = |name: &str| CreateCleanProfileInput {
        label: name.into(),
        provider: "anthropic".into(),
        browser_engine: "chrome".into(),
        bound_route_id: None,
    };
    let prof = create_clean_profile_in(mk("Rebind"), &state).await.unwrap();
    let rebound = update_clean_profile_route_in(&prof.id, Some("r-active"), &state, &mgr)
        .await
        .unwrap();
    assert_eq!(rebound.bound_route_id.as_deref(), Some("r-active"));

    state.write().await.clean_room.profiles[0].last_exit_ip = Some("198.51.100.88".into());
    let d1 = delete_clean_profile_in(&prof.id, None, Some(tmp.path()), &state, &mgr, &reg)
        .await
        .unwrap();
    assert!(!d1.tainted_ips.contains_key("198.51.100.88"));

    let prof2 = create_clean_profile_in(mk("Taint"), &state).await.unwrap();
    state.write().await.clean_room.profiles[0].last_exit_ip = Some("198.51.100.99".into());
    let d2 = delete_clean_profile_in(&prof2.id, Some(true), Some(tmp.path()), &state, &mgr, &reg)
        .await
        .unwrap();
    assert!(d2.tainted_ips.contains_key("198.51.100.99"));
    let d3 = untaint_clean_room_ip_in(" 198.51.100.99 ", &state)
        .await
        .unwrap();
    assert!(!d3.tainted_ips.contains_key("198.51.100.99"));
}
