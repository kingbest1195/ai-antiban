//! End-to-End tests for §7.7 & §8.3 п.8: strict fail-closed proxy & tunnel teardown during
//! VPN server switches, transient offline probes (`probe() == None`), and stale session/cache state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

use zastava_lib::auditor::AuditEnv;
use zastava_lib::auditor::Auditor;
use zastava_lib::auditor::geo_matrix::ProviderId;
use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{HttpProbeOutcome, LookupOutcome};
use zastava_lib::proxy::hold_queue::{HoldQueue, HoldResolution};
use zastava_lib::proxy::{Gate, ProxyServer};
use zastava_lib::routing::{Entry, EntryProto, Route};
use zastava_lib::state::AppState;

fn offline_auditor_with_probe(probe_outcome: HttpProbeOutcome) -> Auditor {
    let env = AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(FakeProbe::new(probe_outcome)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    };
    Auditor::with_env(env).expect("offline test auditor")
}

async fn spawn_echo_upstream() -> Option<(std::net::SocketAddr, Arc<AtomicU64>)> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("bind echo upstream: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let hits_clone = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            hits_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Some((addr, hits))
}

async fn send_connect(addr: std::net::SocketAddr, host: &str) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect proxy");
    let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut buf))
        .await
        .expect("gateway response timeout")
        .unwrap();
    (stream, String::from_utf8_lossy(&buf[..n]).to_string())
}

#[tokio::test]
async fn e2e_offline_probe_freezes_connect_even_with_stale_session_and_cached_telemetry() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let auditor = offline_auditor_with_probe(HttpProbeOutcome::Timeout);
    auditor
        .resolver
        .set_cached(NetworkTelemetry {
            ip: "1.1.1.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(13335),
            org: Some("Cloudflare".to_string()),
            isp: Some("Cloudflare".to_string()),
            timezone: Some("Europe/Amsterdam".to_string()),
            resolved_at: current_timestamp(),
        })
        .await;

    let state = AppState::new_in_memory();
    state
        .allow_provider_for_session("anthropic")
        .await
        .expect("session allow");
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor.clone(),
            state.clone(),
            hold_queue.clone(),
            Some(upstream_addr),
        )
        .await
        .expect("bind proxy"),
    );

    let online = Arc::new(AtomicBool::new(true));
    let online_probe = Arc::clone(&online);
    server.guard.start_with_test_env(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(move || {
            let is_on = online_probe.load(Ordering::SeqCst);
            Box::pin(async move {
                if is_on {
                    Some("1.1.1.1".to_string())
                } else {
                    None
                }
            })
        })),
        None,
    );
    server
        .guard
        .seed_baseline_for_test("1.1.1.1", "NL", None)
        .await;
    // Align observed_ip with steady-state baseline after seed.
    server.guard.ensure_fresh().await;

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // 1) Baseline verified & Gate::Open -> CONNECT succeeds and echoes traffic.
    let (mut s1, resp1) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(
        resp1.contains("200 Connection Established"),
        "expected 200 on baseline, got: {resp1}"
    );
    s1.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    s1.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // 2) Simulate mid-VPN switch (`probe() == None`, same local route fingerprint).
    online.store(false, Ordering::SeqCst);
    // Allow immediate re-probe by clearing throttling timestamp via wake helper and invoking ensure_fresh.
    server.guard.wake_immediate_probe().await;
    let t0 = Instant::now();
    server.guard.ensure_fresh().await;
    assert!(
        t0.elapsed() < Duration::from_millis(150),
        "offline probe freeze took {:?}",
        t0.elapsed()
    );
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
    assert!(!state.is_provider_session_allowed("anthropic").await);
    assert!(
        auditor
            .resolver
            .cached_direct_country("1.1.1.1")
            .await
            .is_none()
    );

    // 3) Canary check while Pending must fail closed immediately without touching upstream.
    let (_s2, resp_canary) =
        send_connect(server.bound_addr, "canary-test.anthropic.zastava.local").await;
    assert!(
        !resp_canary.contains("200 Connection Established"),
        "canary must not pass while Gate::Pending: {resp_canary}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // 4) Real CONNECT to claude.ai waits on Gate::Pending and blocks once user denies (`HoldResolution::Block`).
    let q = Arc::clone(&hold_queue);
    tokio::spawn(async move {
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            if q.resolve_all_for_provider("all", HoldResolution::Block)
                .await
                > 0
            {
                break;
            }
        }
    });
    let (_s3, resp_blocked) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(
        resp_blocked.contains("403"),
        "expected 403 fail-closed after Block, got: {resp_blocked}"
    );
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        1,
        "no direct leak allowed while blocked"
    );
}

#[tokio::test]
async fn e2e_established_unrouted_tunnel_tears_down_immediately_on_offline_probe_drop() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, _)) = spawn_echo_upstream().await else {
        return;
    };

    let auditor = offline_auditor_with_probe(HttpProbeOutcome::Timeout);
    auditor
        .resolver
        .set_cached(NetworkTelemetry {
            ip: "1.1.1.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(13335),
            org: Some("Cloudflare".to_string()),
            isp: Some("Cloudflare".to_string()),
            timezone: Some("Europe/Amsterdam".to_string()),
            resolved_at: current_timestamp(),
        })
        .await;

    let state = AppState::new_in_memory();
    state.allow_provider_for_session("anthropic").await.unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor.clone(),
            state.clone(),
            hold_queue.clone(),
            Some(upstream_addr),
        )
        .await
        .unwrap(),
    );

    let online = Arc::new(AtomicBool::new(true));
    let online_probe = Arc::clone(&online);
    server.guard.start_with_test_env(
        auditor,
        state,
        hold_queue,
        Some(Arc::new(move || {
            let is_on = online_probe.load(Ordering::SeqCst);
            Box::pin(async move {
                if is_on {
                    Some("1.1.1.1".to_string())
                } else {
                    None
                }
            })
        })),
        None,
    );
    server
        .guard
        .seed_baseline_for_test("1.1.1.1", "NL", None)
        .await;
    server.guard.ensure_fresh().await;

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // Open live tunnel and exchange bytes through it.
    let (mut client, resp) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(resp.contains("200 Connection Established"));
    client.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");

    // Simulate transient VPN drop (`probe() == None`) -> active tunnel MUST tear down immediately (<500ms).
    online.store(false, Ordering::SeqCst);
    server.guard.wake_immediate_probe().await;
    server.guard.ensure_fresh().await;
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);

    let mut buf = [0u8; 64];
    let closed = tokio::time::timeout(Duration::from_millis(500), client.read(&mut buf))
        .await
        .expect("active tunnel did not close promptly on gate exit from Open");
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "active tunnel should close immediately on Pending gate, got {closed:?}"
    );
}

#[tokio::test]
async fn e2e_cold_offline_start_blocks_stale_persisted_session_without_baseline() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let auditor = offline_auditor_with_probe(HttpProbeOutcome::Timeout);
    let state = AppState::new_in_memory();
    state.allow_provider_for_session("anthropic").await.unwrap();

    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor.clone(),
            state.clone(),
            hold_queue.clone(),
            Some(upstream_addr),
        )
        .await
        .unwrap(),
    );
    server.guard.start_with_test_env(
        auditor.clone(),
        state,
        hold_queue,
        Some(Arc::new(|| Box::pin(async { None }))),
        None,
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // Even with Gate::Open (cold offline start) + stale persisted session allow,
    // Step 2 must not bypass (`baseline.is_none()`) and Step 3 fails offline!
    let (_s, resp) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(
        !resp.contains("200 Connection Established"),
        "stale session leaked on cold offline start: {resp}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    // Even if 15s direct telemetry cache was populated before an IP change, once baseline/observed
    // IP mismatches cached IP ("2.2.2.2" vs cached "1.1.1.1"), Step 3 invalidates stale cache!
    auditor
        .resolver
        .set_cached(NetworkTelemetry {
            ip: "1.1.1.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: Some(13335),
            org: Some("Cloudflare".to_string()),
            isp: Some("Cloudflare".to_string()),
            timezone: Some("Europe/Amsterdam".to_string()),
            resolved_at: current_timestamp(),
        })
        .await;
    server
        .guard
        .seed_baseline_for_test("2.2.2.2", "DE", None)
        .await;
    let q_clone = Arc::clone(&server.hold_queue);
    tokio::spawn(async move {
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            if q_clone
                .resolve_all_for_provider("all", HoldResolution::Block)
                .await
                > 0
            {
                break;
            }
        }
    });
    let (_s2, resp2) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(
        resp2.contains("403"),
        "stale cached telemetry must fail closed on offline baseline switch: {resp2}"
    );
    assert!(
        auditor
            .resolver
            .cached_direct_country("1.1.1.1")
            .await
            .is_none(),
        "stale cached telemetry must be invalidated on IP/offline transition"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn e2e_unavailable_route_never_falls_back_to_direct_and_records_route_down() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((direct_addr, direct_hits)) = spawn_echo_upstream().await else {
        return;
    };
    let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed_listener.local_addr().unwrap().port();
    drop(closed_listener);

    let state = AppState::new_in_memory();
    state
        .upsert_route(Route {
            id: "dead-key".to_string(),
            label: "dead key".to_string(),
            country: Some("NL".to_string()),
            exit_ip: None,
            expires_at: None,
            sub_url: None,
            grace_extended: false,
            entries: vec![Entry {
                proto: EntryProto::Socks5,
                host: "127.0.0.1".to_string(),
                port: closed_port,
                username: None,
                password: None,
                sni: None,
            }],
            raw_key: format!("socks5://127.0.0.1:{closed_port}"),
            enabled: true,
            added_at: 0,
        })
        .await
        .unwrap();
    state
        .bind_provider_route("anthropic", Some("dead-key"))
        .await
        .unwrap();
    state.allow_provider_for_session("anthropic").await.unwrap();

    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_auditor_with_probe(HttpProbeOutcome::Timeout),
            state.clone(),
            Arc::new(HoldQueue::new()),
            Some(direct_addr),
        )
        .await
        .unwrap(),
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let (_s, resp) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(
        resp.contains("502") || resp.contains("403"),
        "expected fail-closed error, got: {resp}"
    );
    assert_eq!(
        direct_hits.load(Ordering::SeqCst),
        0,
        "must never leak to direct"
    );
    assert!(
        state
            .stats()
            .snapshot_sync()
            .recent_events
            .iter()
            .any(|e| e.action == "ROUTE_DOWN"),
        "ROUTE_DOWN stat must be recorded"
    );
}

#[tokio::test]
async fn e2e_switch_to_clean_unpinned_foreign_ip_never_auto_allows_under_ask_popup_or_silent() {
    use zastava_lib::auditor::seams::IpProbe;
    use zastava_lib::state::InterceptionBehavior;

    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    struct DynamicIpProbe(Arc<std::sync::Mutex<(String, String)>>);
    impl IpProbe for DynamicIpProbe {
        fn get<'a>(
            &'a self,
            url: &'a str,
            _limit: Duration,
        ) -> zastava_lib::auditor::seams::BoxFuture<'a, HttpProbeOutcome> {
            let (ip, cc) = self.0.lock().unwrap().clone();
            let body = if url.contains("ipwho.is") {
                format!(
                    r#"{{"success":true,"ip":"{ip}","country_code":"{cc}","connection":{{"asn":24940,"org":"Hetzner","isp":"Hetzner","domain":"hetzner.de"}},"timezone":{{"id":"Europe/Berlin"}}}}"#
                )
            } else {
                format!("fl=1\nip={ip}\nloc={cc}\ncolo=FRA\n")
            };
            Box::pin(async move { HttpProbeOutcome::Response { status: 200, body } })
        }
    }

    let exit = Arc::new(std::sync::Mutex::new((
        "1.1.1.1".to_string(),
        "DE".to_string(),
    )));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicIpProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    auditor
        .resolver
        .set_cached(NetworkTelemetry {
            ip: "1.1.1.1".to_string(),
            country_code: "DE".to_string(),
            hostname: Some("h1.hetzner.de".to_string()),
            asn: Some(24940),
            org: Some("Hetzner".to_string()),
            isp: Some("Hetzner".to_string()),
            timezone: Some("Europe/Berlin".to_string()),
            resolved_at: current_timestamp(),
        })
        .await;

    let state = AppState::new_in_memory();
    assert_eq!(
        state.get_interception_behavior().await,
        InterceptionBehavior::AskPopup
    );
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor.clone(),
            state.clone(),
            hold_queue.clone(),
            Some(upstream_addr),
        )
        .await
        .unwrap(),
    );

    let exit_probe = Arc::clone(&exit);
    server.guard.start_with_test_env(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(move || {
            let ip = exit_probe.lock().unwrap().0.clone();
            Box::pin(async move { Some(ip) })
        })),
        None,
    );
    server
        .guard
        .seed_baseline_for_test("1.1.1.1", "DE", None)
        .await;
    server.guard.ensure_fresh().await;

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // 1) Switch to a NEW, CLEAN foreign IP ("2.2.2.2", DE, NO pin, NO trusted_exceptions)
    //    under default AskPopup -> MUST hold in Pending/alert-popup, NEVER silently open!
    *exit.lock().unwrap() = ("2.2.2.2".to_string(), "DE".to_string());
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;
    for _ in 0..200 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.phase == "ready")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
    let alert = hold_queue.current_alert().expect("alert must stay open");
    assert_eq!(alert.phase, "ready");
    assert_eq!(
        alert
            .network_change
            .as_ref()
            .and_then(|n| n.new_ip.as_deref()),
        Some("2.2.2.2")
    );

    // Denying the alert blocks Claude (`403`, 0 upstream hits).
    assert!(hold_queue.resolve(&alert.id, HoldResolution::Block).await);
    for _ in 0..100 {
        if server.guard.gate_for(ProviderId::Anthropic) == Gate::Blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (_s_blk, resp_blk) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(resp_blk.contains("403"), "expected 403 block: {resp_blk}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    // 2) Switch to another clean DE/AS24940 IP ("3.3.3.3") under AutoLockSilent
    //    -> MUST lock silently (`Gate::Blocked`) without popup (wait for `3.3.3.3` to finish).
    state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    *exit.lock().unwrap() = ("3.3.3.3".to_string(), "DE".to_string());
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;
    for _ in 0..200 {
        if server.guard.gate_for(ProviderId::Anthropic) == Gate::Blocked
            && state.is_provider_blocked("anthropic").await
            && server
                .guard
                .gate_reason()
                .as_deref()
                .is_some_and(|r| r.contains("3.3.3.3"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(hold_queue.current_alert().is_none());
    let (_s_sil, resp_sil) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(
        resp_sil.contains("403"),
        "expected 403 silent lock: {resp_sil}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    // 3) Under AutoAllowTrusted, clean DE/AS24940 IP ("4.4.4.4") DOES auto-open and tunnel!
    state
        .set_interception_behavior(InterceptionBehavior::AutoAllowTrusted)
        .await
        .unwrap();
    *exit.lock().unwrap() = ("4.4.4.4".to_string(), "DE".to_string());
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;
    for _ in 0..200 {
        if server.guard.gate_for(ProviderId::Anthropic) == Gate::Open
            && !state.is_provider_blocked("anthropic").await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        (
            server.guard.gate_for(ProviderId::Anthropic),
            state.is_provider_blocked("anthropic").await,
            server.guard.gate_reason()
        ),
        (Gate::Open, false, None)
    );
    let (mut s_ok, resp_ok) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(
        resp_ok.contains("200 Connection Established"),
        "AutoAllowTrusted should pass clean foreign IP: {resp_ok}"
    );
    s_ok.write_all(b"ok").await.unwrap();
    let mut echo = [0u8; 2];
    s_ok.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ok");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
}
