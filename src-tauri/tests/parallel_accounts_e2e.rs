//! Zero-internet end-to-end tests for real macOS/Windows parallel Claude accounts,
//! Zastava VPN key binding, RU network drops, fail-closed key disable/deletion,
//! restart reconciliation, and path/encoding edge cases.

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::probes::whoami::{AKAMAI_HOST, GOOGLE_TXT_HOST};
use zastava_lib::auditor::profile_switcher::{
    active_profile_binding_state_in, create_claude_profile_in, delete_claude_profile_in_with_home,
    list_claude_profiles_in, mark_profiles_route_removed_in, resolve_claude_desktop_dir_for_platform,
    resolve_route_id_for_key, switch_claude_profile_in_with_home, update_profile_bound_ip_in,
    update_profile_bound_upstream_in,
};
use zastava_lib::auditor::seams::fakes::{FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{
    AuditEnv, BoxFuture, DnsLookup, HttpProbeOutcome, IpProbe, LookupOutcome, TxtOutcome,
};
use zastava_lib::auditor::{Auditor, OverallStatus, ProviderId};
use zastava_lib::commands::claude::sync_active_profile_binding_to_runtime;
use zastava_lib::proxy::guard::{PauseMode, ProbeFn, ResolveFn};
use zastava_lib::proxy::hold_queue::HoldQueue;
use zastava_lib::proxy::{Gate, NetworkGuard, ProxyServer};
use zastava_lib::reconcile_active_profile_binding_async;
use zastava_lib::routing::{RouteSelection, parse_route_key, select_route, snapshot as build_routes_snapshot};
use zastava_lib::state::{AppState, InterceptionBehavior, PROVIDER_ANTHROPIC};
use zastava_lib::sysproxy::force_os_dry_run;

#[derive(Clone)]
struct ExitState {
    ip: String,
    country: String,
    asn: u32,
    org: String,
    timezone: String,
}

impl ExitState {
    fn clean_de() -> Self {
        Self {
            ip: "185.100.10.2".into(),
            country: "DE".into(),
            asn: 24940,
            org: "Hetzner Online GmbH".into(),
            timezone: "Europe/Berlin".into(),
        }
    }

    fn blocked_ru() -> Self {
        Self {
            ip: "95.165.10.22".into(),
            country: "RU".into(),
            asn: 8359,
            org: "MTS PJSC".into(),
            timezone: "Europe/Moscow".into(),
        }
    }

    fn telemetry(&self) -> NetworkTelemetry {
        NetworkTelemetry {
            ip: self.ip.clone(),
            country_code: self.country.clone(),
            hostname: Some("exit.example.net".into()),
            asn: Some(self.asn),
            org: Some(self.org.clone()),
            isp: Some(self.org.clone()),
            timezone: Some(self.timezone.clone()),
            resolved_at: current_timestamp(),
        }
    }
}

struct DynamicProbe {
    exit: Arc<RwLock<ExitState>>,
}

impl IpProbe for DynamicProbe {
    fn get<'a>(&'a self, url: &'a str, _limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
        Box::pin(async move {
            let ex = self.exit.read().await.clone();
            if url.contains("ipwho.is") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: json!({
                        "success": true,
                        "ip": ex.ip,
                        "country_code": ex.country,
                        "connection": { "asn": ex.asn, "org": ex.org, "isp": ex.org },
                        "timezone": { "id": ex.timezone },
                    })
                    .to_string(),
                };
            }
            if url.contains("[2606:") {
                return HttpProbeOutcome::Timeout;
            }
            if url.contains("/cdn-cgi/trace") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: format!("fl=1\nip={}\nloc={}\ncolo=FRA\n", ex.ip, ex.country),
                };
            }
            if url.contains("torbulkexitlist") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: "198.51.100.1\n198.51.100.2\n".into(),
                };
            }
            HttpProbeOutcome::Timeout
        })
    }
}

struct DynamicDns {
    exit: Arc<RwLock<ExitState>>,
}

impl DnsLookup for DynamicDns {
    fn lookup<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, LookupOutcome> {
        Box::pin(async move {
            if host == AKAMAI_HOST {
                let ip: IpAddr = self.exit.read().await.ip.parse().unwrap();
                return LookupOutcome::Addrs(vec![ip]);
            }
            if host.starts_with("2.0.0.127.") {
                return LookupOutcome::Addrs(vec!["127.0.0.2".parse().unwrap()]);
            }
            LookupOutcome::NotFound
        })
    }

    fn lookup_uncached<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, LookupOutcome> {
        self.lookup(host, limit)
    }

    fn lookup_txt<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, TxtOutcome> {
        Box::pin(async move {
            if host == GOOGLE_TXT_HOST {
                let ip = self.exit.read().await.ip.clone();
                return TxtOutcome::Records(vec![format!("\"{ip}\"")]);
            }
            TxtOutcome::NotFound
        })
    }
}

/// Minimal SOCKS5 (no auth) echo upstream that echoes plain streams and closes immediately on TLS ClientHello (0x16).
async fn spawn_socks_echo() -> (u16, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let tunnels = Arc::new(AtomicU64::new(0));
    let tunnels_bg = Arc::clone(&tunnels);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let t = Arc::clone(&tunnels_bg);
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
                if head[3] == 0x03 {
                    let mut len = [0u8; 1];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut rest = vec![0u8; len[0] as usize + 2];
                    if s.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                } else {
                    let mut rest = [0u8; 6];
                    if s.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                }
                let _ = s
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let mut buf = [0u8; 256];
                let Ok(n) = s.read(&mut buf).await else { return };
                if n == 0 || buf[0] == 0x16 {
                    // Immediate close on TLS probe (non-echo audit probe).
                    return;
                }
                t.fetch_add(1, Ordering::SeqCst);
                let _ = s.write_all(&buf[..n]).await;
                while let Ok(k) = s.read(&mut buf).await {
                    if k == 0 || s.write_all(&buf[..k]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, tunnels)
}

async fn spawn_direct_echo_sink() -> (SocketAddr, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let hits_bg = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            hits_bg.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, hits)
}

async fn start_gateway(initial_exit: ExitState) -> (AppState, Arc<ProxyServer>, Arc<NetworkGuard>, Arc<RwLock<ExitState>>, Arc<AtomicU64>, Auditor) {
    force_os_dry_run();
    let exit = Arc::new(RwLock::new(initial_exit));
    let env = AuditEnv {
        dns: Arc::new(DynamicDns { exit: Arc::clone(&exit) }),
        probe: Arc::new(DynamicProbe { exit: Arc::clone(&exit) }),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem { global_ipv6: Some(true), ..FakeSystem::healthy() }),
    };
    let auditor = Auditor::with_env(env).unwrap();
    let state = AppState::new_in_memory();
    state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let (direct_sink, direct_hits) = spawn_direct_echo_sink().await;
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), Arc::clone(&hold_queue), Some(direct_sink))
            .await
            .unwrap(),
    );
    let guard = Arc::clone(&server.guard);
    let probe_exit = Arc::clone(&exit);
    let probe: ProbeFn = Arc::new(move || {
        let e = Arc::clone(&probe_exit);
        Box::pin(async move { Some(e.read().await.ip.clone()) })
    });
    let res_exit = Arc::clone(&exit);
    let resolve: ResolveFn = Arc::new(move || {
        let e = Arc::clone(&res_exit);
        Box::pin(async move { Ok(e.read().await.telemetry()) })
    });
    guard.start_with_test_env(auditor.clone(), state.clone(), hold_queue, Some(probe), Some(resolve));
    let srv_bg = Arc::clone(&server);
    tokio::spawn(async move { srv_bg.run().await });
    (state, server, guard, exit, direct_hits, auditor)
}

async fn wait_for_gate(guard: &NetworkGuard, provider: ProviderId, expected: Gate) {
    for _ in 0..200 {
        if guard.gate_for(provider) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(guard.gate_for(provider), expected, "timed out waiting for {provider:?} gate");
}

async fn connect_and_echo(addr: SocketAddr, host: &str, msg: &[u8]) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut hdr = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut hdr))
        .await
        .expect("gateway response timeout")
        .unwrap();
    let resp = String::from_utf8_lossy(&hdr[..n]).to_string();
    if !resp.starts_with("HTTP/1.1 200") {
        return (resp, Vec::new());
    }
    s.write_all(msg).await.unwrap();
    let mut echo = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut echo))
        .await
        .expect("echo timeout")
        .unwrap();
    (resp, echo)
}

fn route_telemetry(ip: &str, cc: &str) -> NetworkTelemetry {
    NetworkTelemetry {
        ip: ip.into(),
        country_code: cc.into(),
        hostname: Some("k1.proxy.example".into()),
        asn: Some(24940),
        org: Some("Zastava Remote ISP".into()),
        isp: Some("Zastava Remote ISP".into()),
        timezone: Some("Europe/Amsterdam".into()),
        resolved_at: current_timestamp(),
    }
}

#[test]
fn e2e_scenario_1_browser_login_and_desktop_cli_isolation() {
    let tmp = TempDir::new().unwrap();
    let storage_dir = tmp.path().join("profiles");
    let claude_dir = tmp.path().join("Claude");
    let home_dir = tmp.path().join("home");
    fs::create_dir_all(claude_dir.join("Local Storage/leveldb")).unwrap();
    fs::create_dir_all(claude_dir.join("Network")).unwrap();
    fs::create_dir_all(claude_dir.join("DawnWebGPUCache")).unwrap();
    fs::create_dir_all(home_dir.join(".claude")).unwrap();

    // Seed Profile A (default) Desktop + CLI credentials + non-auth MCP settings
    fs::write(claude_dir.join("Network/Cookies"), b"SESSION_COOKIE_ACCOUNT_A").unwrap();
    fs::write(claude_dir.join("Local Storage/leveldb/0001.ldb"), b"STORAGE_A").unwrap();
    fs::write(claude_dir.join("DawnWebGPUCache/blob.bin"), b"CACHE_A").unwrap();
    fs::write(claude_dir.join("Preferences"), r#"{"account":"A"}"#).unwrap();
    fs::write(claude_dir.join("claude_desktop_config.json"), r#"{"mcpServers":{"local":{}}}"#).unwrap();
    fs::write(home_dir.join(".claude/.credentials.json"), r#"{"claudeAiOauth":{"accessToken":"tok-A"}}"#).unwrap();
    fs::write(
        home_dir.join(".claude.json"),
        json!({
            "userID": "user-A",
            "oauthAccount": { "emailAddress": "alice@example.com" },
            "mcpServers": { "github": { "command": "npx" } },
            "theme": "dark"
        })
        .to_string(),
    )
    .unwrap();

    // Create Profile B (for browser login) and Profile C (empty check)
    let list_b = create_claude_profile_in(&storage_dir, &claude_dir, "Account B", None, None, None).unwrap();
    let prof_b = list_b.profiles.iter().find(|p| p.name == "Account B").unwrap().clone();
    let list_c = create_claude_profile_in(&storage_dir, &claude_dir, "Profile C", None, None, None).unwrap();
    let prof_c = list_c.profiles.iter().find(|p| p.name == "Profile C").unwrap().clone();

    // Switch A -> B: B must start clean for fresh browser login while A's backup stays intact
    let sw_b = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_b.id).unwrap();
    assert_eq!(sw_b.active_profile.id, prof_b.id);
    assert!(!claude_dir.join("Network/Cookies").exists(), "A Cookies must not leak to B");
    assert!(!claude_dir.join("Preferences").exists(), "A Preferences must not leak to B");
    assert!(claude_dir.join("claude_desktop_config.json").exists(), "Desktop MCP config must be preserved");
    assert!(!claude_dir.join("DawnWebGPUCache/blob.bin").exists(), "Electron cache must be purged");
    assert!(!home_dir.join(".claude/.credentials.json").exists(), "A CLI credentials must not leak to B");
    let cli_b_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home_dir.join(".claude.json")).unwrap()).unwrap();
    assert!(cli_b_json.get("oauthAccount").is_none());
    assert!(cli_b_json.get("userID").is_none());
    assert!(cli_b_json.get("mcpServers").is_some(), "non-auth mcpServers must survive");
    assert_eq!(
        fs::read_to_string(storage_dir.join("default/snapshot/Network/Cookies")).unwrap(),
        "SESSION_COOKIE_ACCOUNT_A"
    );
    assert!(storage_dir.join("default/snapshot/cli_credentials.json").exists());

    // Switch unlogged B -> C: B still never had real auth, so has_saved_session must remain false
    let _ = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_c.id).unwrap();
    let list_after_c = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
    let b_meta = list_after_c.profiles.iter().find(|p| p.id == prof_b.id).unwrap();
    assert!(!b_meta.has_saved_session, "device-id files alone must not mark has_saved_session=true");
    assert!(list_after_c.profiles.iter().find(|p| p.id == "default").unwrap().has_saved_session);

    // Switch to B, perform browser/CLI login for B, then switch B -> A -> B
    let _ = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_b.id).unwrap();
    fs::create_dir_all(claude_dir.join("Network")).unwrap();
    fs::write(claude_dir.join("Network/Cookies"), b"SESSION_COOKIE_ACCOUNT_B").unwrap();
    fs::write(home_dir.join(".claude/.credentials.json"), r#"{"claudeAiOauth":{"accessToken":"tok-B"}}"#).unwrap();
    fs::write(
        home_dir.join(".claude.json"),
        json!({ "userID": "user-B", "oauthAccount": { "emailAddress": "bob@example.com" }, "mcpServers": { "github": { "command": "npx" } } }).to_string(),
    )
    .unwrap();

    // Back to A: restores A verbatim without touching B's backup
    let _ = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), "default").unwrap();
    assert_eq!(fs::read_to_string(claude_dir.join("Network/Cookies")).unwrap(), "SESSION_COOKIE_ACCOUNT_A");
    assert!(fs::read_to_string(home_dir.join(".claude/.credentials.json")).unwrap().contains("tok-A"));
    assert_eq!(
        fs::read_to_string(storage_dir.join(format!("{}/snapshot/Network/Cookies", prof_b.id))).unwrap(),
        "SESSION_COOKIE_ACCOUNT_B"
    );

    // Switch back to B: restores B verbatim
    let _ = switch_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_b.id).unwrap();
    assert_eq!(fs::read_to_string(claude_dir.join("Network/Cookies")).unwrap(), "SESSION_COOKIE_ACCOUNT_B");
    assert!(fs::read_to_string(home_dir.join(".claude/.credentials.json")).unwrap().contains("tok-B"));

    // Deleting unused Profile C deletes only C without touching active B or backup A
    let after_del = delete_claude_profile_in_with_home(&storage_dir, &claude_dir, Some(&home_dir), &prof_c.id).unwrap();
    assert_eq!(after_del.profiles.len(), 2);
    assert!(!storage_dir.join(&prof_c.id).exists());
    assert_eq!(fs::read_to_string(claude_dir.join("Network/Cookies")).unwrap(), "SESSION_COOKIE_ACCOUNT_B");
    assert_eq!(
        fs::read_to_string(storage_dir.join("default/snapshot/Network/Cookies")).unwrap(),
        "SESSION_COOKIE_ACCOUNT_A"
    );
}

#[tokio::test]
async fn e2e_scenario_2_parallel_accounts_pinned_key_and_unrouted_ai_isolation() {
    let (state, _server, guard, _exit, _hits, auditor) = start_gateway(ExitState::clean_de()).await;
    let (k1_port, _) = spawn_socks_echo().await;
    let k1_raw = format!("socks5://127.0.0.1:{k1_port}#AccountA-NL");
    let k1_id = resolve_route_id_for_key(Some(&k1_raw)).unwrap();
    let ip_a = "185.212.102.40";
    auditor
        .resolver
        .set_cached_for_route(Some(k1_id.clone()), route_telemetry(ip_a, "NL"))
        .await;

    // Global OS VPN pinned for OpenAI & Gemini
    state.set_pinned_ip_for("default", Some("185.100.10.2".into())).await.unwrap();

    let tmp = TempDir::new().unwrap();
    let storage = tmp.path().join("profiles");
    let claude = tmp.path().join("Claude");
    let c = create_claude_profile_in(&storage, &claude, "Account A", Some(ip_a.into()), Some("NL".into()), Some(k1_raw.clone())).unwrap();
    let prof_a = c.profiles.iter().find(|p| p.name == "Account A").unwrap().clone();

    // Activate Profile A -> anthropic gets K1 + IP_A, default pin remains untouched
    let sw_a = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a.id).unwrap();
    sync_active_profile_binding_to_runtime(
        &state,
        &guard,
        sw_a.pinned_ip_updated.clone(),
        sw_a.bound_upstream_key_updated.as_deref(),
        sw_a.active_profile.bound_route_id.as_deref(),
    )
    .await
    .unwrap();

    let st_a = state.get_data().await;
    assert_eq!(st_a.pinned_ips.get("anthropic").map(String::as_str), Some(ip_a));
    assert_eq!(st_a.pinned_ips.get("default").map(String::as_str), Some("185.100.10.2"));
    assert_eq!(st_a.profile_route_id.as_deref(), Some(k1_id.as_str()));

    for p in [ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
        let rep = auditor.evaluate_all(p, &state, false).await.unwrap();
        assert_eq!(rep.overall_status, OverallStatus::Green, "{p:?} should be Green");
    }

    // Switch to Profile B ("default", unrouted / Direct) -> clears anthropic pin only
    let sw_b = switch_claude_profile_in_with_home(&storage, &claude, None, "default").unwrap();
    sync_active_profile_binding_to_runtime(
        &state,
        &guard,
        sw_b.pinned_ip_updated.clone(),
        sw_b.bound_upstream_key_updated.as_deref(),
        sw_b.active_profile.bound_route_id.as_deref(),
    )
    .await
    .unwrap();
    let st_b = state.get_data().await;
    assert!(!st_b.pinned_ips.contains_key("anthropic"));
    assert_eq!(st_b.pinned_ips.get("default").map(String::as_str), Some("185.100.10.2"));
    assert_eq!(st_b.profile_route_id, None);
}

#[tokio::test]
async fn e2e_scenario_3_ru_drop_on_bound_key_a_then_switch_to_direct_b() {
    let (state, server, guard, exit, direct_hits, auditor) = start_gateway(ExitState::clean_de()).await;
    let (k1_port, k1_tunnels) = spawn_socks_echo().await;
    let k1_raw = format!("socks5://127.0.0.1:{k1_port}#KeyA");
    let k1_id = resolve_route_id_for_key(Some(&k1_raw)).unwrap();
    auditor
        .resolver
        .set_cached_for_route(Some(k1_id.clone()), route_telemetry("185.212.102.40", "NL"))
        .await;
    state.set_pinned_ip_for("default", Some("185.100.10.2".into())).await.unwrap();

    // Baseline healthy tick on DE
    guard.tick_test().await;

    let tmp = TempDir::new().unwrap();
    let storage = tmp.path().join("profiles");
    let claude = tmp.path().join("Claude");
    let c = create_claude_profile_in(&storage, &claude, "Account A", Some("185.212.102.40".into()), Some("NL".into()), Some(k1_raw.clone())).unwrap();
    let prof_a_id = c.profiles.iter().find(|p| p.name == "Account A").unwrap().id.clone();

    let sw_a = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a_id).unwrap();
    sync_active_profile_binding_to_runtime(&state, &guard, sw_a.pinned_ip_updated, sw_a.bound_upstream_key_updated.as_deref(), Some(&k1_id))
        .await
        .unwrap();
    guard.tick_test().await;

    let (resp_a1, echo_a1) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"PING_A1").await;
    assert!(resp_a1.starts_with("HTTP/1.1 200"), "{resp_a1}");
    assert_eq!(echo_a1, b"PING_A1");
    let hits_before_ru = direct_hits.load(Ordering::SeqCst);

    // Drop OS VPN to RU while Profile A uses K1
    *exit.write().await = ExitState::blocked_ru();
    guard.tick_test().await;
    wait_for_gate(&guard, ProviderId::Openai, Gate::Blocked).await;
    assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);
    assert_eq!(guard.gate_for(ProviderId::Openai), Gate::Blocked);
    assert_eq!(guard.gate_for(ProviderId::Gemini), Gate::Blocked);

    let (resp_oai, _) = connect_and_echo(server.bound_addr, "chatgpt.com", b"NO").await;
    assert!(resp_oai.starts_with("HTTP/1.1 403"), "OpenAI must block on RU: {resp_oai}");
    let (resp_gem, _) = connect_and_echo(server.bound_addr, "gemini.google.com", b"NO").await;
    assert!(resp_gem.starts_with("HTTP/1.1 403"), "Gemini must block on RU: {resp_gem}");

    // Profile A's Claude through K1 STILL works while OS VPN is on RU!
    let k1_before = k1_tunnels.load(Ordering::SeqCst);
    let (resp_a_ru, echo_a_ru) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"PING_A_ON_RU").await;
    assert!(resp_a_ru.starts_with("HTTP/1.1 200"), "Profile A on K1 must stay open on RU: {resp_a_ru}");
    assert_eq!(echo_a_ru, b"PING_A_ON_RU");
    assert_eq!(k1_tunnels.load(Ordering::SeqCst), k1_before + 1);
    assert_eq!(direct_hits.load(Ordering::SeqCst), hits_before_ru, "no direct leak allowed while on RU");

    // Switch to Profile B (Direct) while STILL on RU -> anthropic MUST fail-closed immediately!
    let sw_b = switch_claude_profile_in_with_home(&storage, &claude, None, "default").unwrap();
    sync_active_profile_binding_to_runtime(&state, &guard, sw_b.pinned_ip_updated, sw_b.bound_upstream_key_updated.as_deref(), None)
        .await
        .unwrap();
    guard.tick_test().await;
    wait_for_gate(&guard, ProviderId::Anthropic, Gate::Blocked).await;
    assert_eq!(guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    let (resp_b_ru, _) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"NO").await;
    assert!(resp_b_ru.starts_with("HTTP/1.1 403"), "Direct Profile B on RU must 403: {resp_b_ru}");
    assert_eq!(direct_hits.load(Ordering::SeqCst), hits_before_ru);

    // Switch back to Profile A -> K1 immediately restores Claude access
    let sw_a2 = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a_id).unwrap();
    sync_active_profile_binding_to_runtime(&state, &guard, sw_a2.pinned_ip_updated, sw_a2.bound_upstream_key_updated.as_deref(), Some(&k1_id))
        .await
        .unwrap();
    guard.tick_test().await;
    let (resp_a2, echo_a2) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"PING_A2").await;
    assert!(resp_a2.starts_with("HTTP/1.1 200"), "{resp_a2}");
    assert_eq!(echo_a2, b"PING_A2");
}

#[tokio::test]
async fn e2e_scenario_4_fail_closed_on_key_disable_or_delete_and_vpn_recovery() {
    let (state, server, guard, exit, direct_hits, auditor) = start_gateway(ExitState::clean_de()).await;
    let (k1_port, _) = spawn_socks_echo().await;
    let k1_raw = format!("socks5://127.0.0.1:{k1_port}#KeyA");
    let k1_id = resolve_route_id_for_key(Some(&k1_raw)).unwrap();
    auditor
        .resolver
        .set_cached_for_route(Some(k1_id.clone()), route_telemetry("185.212.102.40", "NL"))
        .await;
    state.set_pinned_ip_for("default", Some("185.100.10.2".into())).await.unwrap();
    guard.tick_test().await;

    let tmp = TempDir::new().unwrap();
    let storage = tmp.path().join("profiles");
    let claude = tmp.path().join("Claude");
    let c = create_claude_profile_in(&storage, &claude, "Account A", Some("185.212.102.40".into()), Some("NL".into()), Some(k1_raw.clone())).unwrap();
    let prof_a_id = c.profiles.iter().find(|p| p.name == "Account A").unwrap().id.clone();
    let sw_a = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a_id).unwrap();
    sync_active_profile_binding_to_runtime(&state, &guard, sw_a.pinned_ip_updated, sw_a.bound_upstream_key_updated.as_deref(), Some(&k1_id))
        .await
        .unwrap();

    // Drop VPN to RU so direct exit would be blocked anyway
    *exit.write().await = ExitState::blocked_ru();
    guard.tick_test().await;
    wait_for_gate(&guard, ProviderId::Openai, Gate::Blocked).await;
    let hits_before = direct_hits.load(Ordering::SeqCst);

    // Disable route K1 -> must fail closed (403 fail-closed, never Direct!)
    state.set_route_enabled(&k1_id, false).await.unwrap();
    let (resp_dis, _) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"NO").await;
    assert!(resp_dis.starts_with("HTTP/1.1 403") && resp_dis.contains("fail-closed"), "{resp_dis}");
    assert_eq!(direct_hits.load(Ordering::SeqCst), hits_before);

    // Re-enable then delete K1 (mirroring commands::routes::remove_route)
    state.set_route_enabled(&k1_id, true).await.unwrap();
    let active_hit = mark_profiles_route_removed_in(&storage, &claude, &k1_id).unwrap();
    assert!(active_hit);
    assert!(state.remove_route(&k1_id).await.unwrap());
    state.set_profile_route_dangling(k1_id.clone()).await.unwrap();

    let st_del = state.get_data().await;
    assert!(matches!(select_route(&st_del, PROVIDER_ANTHROPIC), RouteSelection::Missing(ref id) if id == &k1_id));
    let snap = build_routes_snapshot(&st_del, state.route_health(), current_timestamp());
    assert!(snap.dangling.iter().any(|d| d.kind == "profile" && d.route_id == k1_id));

    let (resp_del, _) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"NO").await;
    assert!(resp_del.starts_with("HTTP/1.1 403") && resp_del.contains("fail-closed"), "{resp_del}");
    assert_eq!(direct_hits.load(Ordering::SeqCst), hits_before);

    // Return OS VPN back to clean Pinned IP (DE) -> OpenAI/Gemini recover automatically,
    // while Profile A STILL holds DanglingBinding (fail-closed) until explicitly fixed!
    *exit.write().await = ExitState::clean_de();
    guard.tick_test().await;
    wait_for_gate(&guard, ProviderId::Openai, Gate::Open).await;
    assert_eq!(guard.gate_for(ProviderId::Openai), Gate::Open);
    let (resp_oai_rec, echo_oai) = connect_and_echo(server.bound_addr, "chatgpt.com", b"OK_OAI").await;
    assert!(resp_oai_rec.starts_with("HTTP/1.1 200"), "{resp_oai_rec}");
    assert_eq!(echo_oai, b"OK_OAI");

    let (resp_still_dangling, _) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"STILL_BLOCKED").await;
    assert!(resp_still_dangling.starts_with("HTTP/1.1 403") && resp_still_dangling.contains("fail-closed"), "{resp_still_dangling}");
}

#[tokio::test]
async fn e2e_scenario_5_restart_reconciliation_and_concurrency_resilience() {
    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state.json");
    let storage = tmp.path().join("profiles");
    let claude = tmp.path().join("Claude");

    let k1_raw = "socks5://127.0.0.1:19999#RestartKey";
    let k1_route = parse_route_key(k1_raw, 1).unwrap();
    let k1_id = k1_route.id.clone();

    // Pre-restart session: active Profile A bound to K1, trusted exception + stale blocked_providers
    let c = create_claude_profile_in(&storage, &claude, "Account A", Some("185.212.102.40".into()), Some("NL".into()), Some(k1_raw.into())).unwrap();
    let prof_a_id = c.profiles.iter().find(|p| p.name == "Account A").unwrap().id.clone();
    let _ = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a_id).unwrap();

    let state1 = AppState::load_or_default(state_path.clone());
    state1.apply_profile_route(k1_route).await.unwrap();
    state1.add_trusted_exception("openai", "203.0.113.77").await.unwrap();
    state1.block_provider(PROVIDER_ANTHROPIC).await.unwrap();
    state1.block_provider("openai").await.unwrap();
    drop(state1);

    // Simulate app restart
    let state2 = AppState::load_or_default(state_path.clone());
    let binding = active_profile_binding_state_in(&storage).unwrap().unwrap();
    reconcile_active_profile_binding_async(&state2, binding).await;

    let st = state2.get_data().await;
    assert_eq!(st.profile_route_id.as_deref(), Some(k1_id.as_str()));
    assert_eq!(st.pinned_ips.get("anthropic").map(String::as_str), Some("185.212.102.40"));
    assert!(st.is_ip_trusted_for_provider("openai", "203.0.113.77"));
    assert!(!st.blocked_providers.iter().any(|b| b == PROVIDER_ANTHROPIC), "stale anthropic block clears on restart with active key");
    assert!(st.blocked_providers.iter().any(|b| b == "openai"), "non-profile provider block stays until audited");

    // Simulate deleted-route dangling survival across restart
    assert!(mark_profiles_route_removed_in(&storage, &claude, &k1_id).unwrap());
    state2.remove_route(&k1_id).await.unwrap();
    state2.set_profile_route_dangling(k1_id.clone()).await.unwrap();
    drop(state2);

    let state3 = AppState::load_or_default(state_path);
    let binding3 = active_profile_binding_state_in(&storage).unwrap().unwrap();
    reconcile_active_profile_binding_async(&state3, binding3).await;
    let st3 = state3.get_data().await;
    assert!(matches!(select_route(&st3, PROVIDER_ANTHROPIC), RouteSelection::Missing(ref id) if id == &k1_id));

    // Concurrent profile reads/updates leave valid profiles.json with zero .tmp residue
    std::thread::scope(|s| {
        for i in 0..8 {
            let (st_dir, cl_dir, pid) = (&storage, &claude, &prof_a_id);
            s.spawn(move || {
                let _ = list_claude_profiles_in(st_dir, cl_dir, None);
                if i % 2 == 0 {
                    let _ = update_profile_bound_ip_in(st_dir, cl_dir, pid, Some("185.212.102.40".into()), Some("NL".into()));
                } else {
                    let _ = update_profile_bound_upstream_in(st_dir, cl_dir, pid, Some(k1_raw.into()));
                }
            });
        }
    });
    let profiles_raw = fs::read_to_string(storage.join("profiles.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&profiles_raw).expect("profiles.json must remain valid JSON");
    assert!(parsed.get("profiles").is_some());
    assert!(!storage.join("profiles.json.tmp").exists());
}

#[test]
fn e2e_scenario_6_windows_macos_path_bom_crlf_symlink_parity() {
    let tmp = TempDir::new().unwrap();

    // Windows standard %APPDATA%\Claude vs MSIX Microsoft Store vs macOS
    let win_home = tmp.path().join("win_user");
    let win_roaming = win_home.join("AppData/Roaming");
    let win_local = win_home.join("AppData/Local");
    let msix_claude = win_local.join("Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude");
    fs::create_dir_all(&msix_claude).unwrap();
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("windows", None, Some(&win_roaming), Some(&win_local)),
        Some(msix_claude.clone())
    );
    let direct_win_claude = win_roaming.join("Claude");
    fs::create_dir_all(&direct_win_claude).unwrap();
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("windows", None, Some(&win_roaming), Some(&win_local)),
        Some(direct_win_claude)
    );

    let mac_home = tmp.path().join("mac_user");
    let mac_claude = mac_home.join("Library/Application Support/Claude");
    fs::create_dir_all(&mac_claude).unwrap();
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("macos", Some(&mac_home), None, None),
        Some(mac_claude)
    );

    // UTF-8 BOM + CRLF profiles.json & .claude.json safety
    let storage = tmp.path().join("profiles_bom");
    let claude = tmp.path().join("Claude_bom");
    let home = tmp.path().join("home_bom");
    fs::create_dir_all(&storage).unwrap();
    fs::create_dir_all(claude.join("Network")).unwrap();
    fs::create_dir_all(home.join(".claude")).unwrap();

    let bom_profiles = "\u{FEFF}{\r\n  \"version\": 1,\r\n  \"profiles\": [\r\n    {\r\n      \"id\": \"default\",\r\n      \"name\": \"Основной\",\r\n      \"isolated_device_id\": \"dev-1\",\r\n      \"created_at\": 1,\r\n      \"last_used_at\": 1,\r\n      \"is_active\": true,\r\n      \"has_saved_session\": false\r\n    }\r\n  ]\r\n}\r\n";
    fs::write(storage.join("profiles.json"), bom_profiles.as_bytes()).unwrap();

    let bom_claude_json = "\u{FEFF}{\r\n  \"userID\": \"u1\",\r\n  \"oauthAccount\": {\"emailAddress\": \"bom@example.com\"},\r\n  \"mcpServers\": {\"fs\": {\"command\": \"npx\"}}\r\n}\r\n";
    fs::write(home.join(".claude.json"), bom_claude_json.as_bytes()).unwrap();
    let list = create_claude_profile_in(&storage, &claude, "Second", None, None, None).unwrap();
    let second_id = list.profiles.iter().find(|p| p.name == "Second").unwrap().id.clone();

    #[cfg(unix)]
    {
        // Planted symlink inside .credentials.json pointing outside must never leak secret target
        let decoy = tmp.path().join("outside_secret.txt");
        fs::write(&decoy, "DO_NOT_COPY_THIS_SECRET").unwrap();
        std::os::unix::fs::symlink(&decoy, home.join(".claude/.credentials.json")).unwrap();
    }

    let _ = switch_claude_profile_in_with_home(&storage, &claude, Some(&home), &second_id).unwrap();
    assert!(!storage.join("default/snapshot/cli_credentials.json").exists(), "symlink credentials must not be snapshotted");
    assert!(!home.join(".claude/.credentials.json").exists(), "symlink credentials must be removed on switch");
    assert!(fs::read_to_string(storage.join("default/snapshot/cli_oauth.json")).unwrap().contains("bom@example.com"));
}

#[test]
fn e2e_scenario_6b_claude_desktop_dir_missing_returns_none_cleanly() {
    let tmp = TempDir::new().unwrap();
    let empty_home = tmp.path().join("no_claude");
    fs::create_dir_all(&empty_home).unwrap();
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("macos", None, None, None),
        None
    );
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("windows", None, None, None),
        None
    );
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("macos", Some(&empty_home), None, None),
        Some(empty_home.join("Library/Application Support/Claude"))
    );
    assert_eq!(
        resolve_claude_desktop_dir_for_platform("windows", None, Some(&empty_home), Some(&empty_home)),
        Some(empty_home.join("Claude"))
    );
    let _ = Path::new(".");
}
