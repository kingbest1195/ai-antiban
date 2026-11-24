//! End-to-End tests for pinned IP / trusted_exceptions unlock across multi-hop switches,
//! offline transitions, per-provider `pinned_ips`, and repeated `CONNECT` silent recovery.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::geo_matrix::ProviderId;
use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{HttpProbeOutcome, IpProbe, LookupOutcome};
use zastava_lib::auditor::{AuditEnv, Auditor};
use zastava_lib::proxy::guard::PauseMode;
use zastava_lib::proxy::hold_queue::{HoldQueue, HoldResolution};
use zastava_lib::proxy::{Gate, ProxyServer};
use zastava_lib::routing::RouteSelection;
use zastava_lib::state::{AppState, IpHistoryEntry, KNOWN_PROVIDERS};

struct DynamicExitProbe(Arc<std::sync::Mutex<Option<(String, String, u32)>>>);

impl IpProbe for DynamicExitProbe {
    fn get<'a>(
        &'a self,
        url: &'a str,
        _limit: Duration,
    ) -> zastava_lib::auditor::seams::BoxFuture<'a, HttpProbeOutcome> {
        let snap = self.0.lock().unwrap().clone();
        Box::pin(async move {
            let Some((ip, cc, asn)) = snap else {
                return HttpProbeOutcome::Timeout;
            };
            let body = if url.contains("ipwho.is") {
                if cc.is_empty() {
                    return HttpProbeOutcome::Timeout;
                }
                format!(
                    r#"{{"success":true,"ip":"{ip}","country_code":"{cc}","connection":{{"asn":{asn},"org":"MyPersonalVPS","isp":"MyPersonalVPS","domain":"vps.example"}},"timezone":{{"id":"Europe/Berlin"}}}}"#
                )
            } else {
                let loc = if cc.is_empty() { "XX" } else { &cc };
                format!("fl=1\nip={ip}\nloc={loc}\ncolo=FRA\n")
            };
            HttpProbeOutcome::Response { status: 200, body }
        })
    }
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

async fn assert_connect_ok_echo(addr: std::net::SocketAddr, host: &str) {
    let (mut s, resp) = send_connect(addr, host).await;
    assert!(
        resp.contains("200 Connection Established"),
        "expected 200 for {host}, got: {resp}"
    );
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn e2e_pinned_offline_multihop_ru_de_return_to_pinned_recovers_without_sticky_lock() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "1.1.1.1".to_string(),
        "DE".to_string(),
        24940u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let state = AppState::new_in_memory();
    state
        .set_pinned_ip(Some("1.1.1.1".to_string()))
        .await
        .unwrap();

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
            let ip = exit_probe.lock().unwrap().as_ref().map(|x| x.0.clone());
            Box::pin(async move { ip })
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

    // 1. Pinned 1.1.1.1 works.
    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // 2. Offline -> freezes Pending, blocks connect on hold deny.
    *exit.lock().unwrap() = None;
    server.guard.wake_immediate_probe().await;
    server.guard.ensure_fresh().await;
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);

    // 3. Hop to RU (5.5.5.5) -> user blocks -> blocked_providers + PauseMode::UntilNetworkChange.
    *exit.lock().unwrap() = Some(("5.5.5.5".to_string(), "RU".to_string(), 9009));
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;
    for _ in 0..100 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.phase == "ready")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let alert_ru = hold_queue.current_alert().expect("RU alert");
    assert!(
        hold_queue
            .resolve(&alert_ru.id, HoldResolution::Block)
            .await
    );
    for _ in 0..100 {
        if server.guard.pause_mode() == PauseMode::UntilNetworkChange
            && server.guard.gate_for(ProviderId::Anthropic) == Gate::Blocked
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (_s_ru, resp_ru) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(resp_ru.contains("403"), "expected 403 on RU: {resp_ru}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // 4. Hop to clean unpinned DE (2.2.2.2) -> AskPopup prompts for confirmation; user allows once (shifts baseline!).
    *exit.lock().unwrap() = Some(("2.2.2.2".to_string(), "DE".to_string(), 12345));
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;
    for _ in 0..100 {
        if hold_queue
            .current_alert()
            .is_some_and(|a| a.phase == "ready")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let alert_de = hold_queue.current_alert().expect("DE reconfirm alert");
    assert!(
        hold_queue
            .resolve(&alert_de.id, HoldResolution::Allow)
            .await
    );
    for _ in 0..100 {
        if server.guard.gate_for(ProviderId::Anthropic) == Gate::Open
            && state.get_data().await.blocked_providers.is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Record recent DE hop into Direct ip_history to exercise travel/ASN-jump on pinned return.
    state
        .record_ip_history_for_selection(
            "anthropic",
            &RouteSelection::Direct,
            IpHistoryEntry::new("2.2.2.2", "DE", Some(12345), current_timestamp()),
        )
        .await
        .unwrap();

    // 5. Return to Pinned (1.1.1.1, DE) -> recovers silently, clears blocks, tunnels 200!
    *exit.lock().unwrap() = Some(("1.1.1.1".to_string(), "DE".to_string(), 24940));
    auditor.resolver.invalidate_direct_cache().await;
    server.guard.tick_test().await;
    for _ in 0..100 {
        if server.guard.gate_for(ProviderId::Anthropic) == Gate::Open
            && state.get_data().await.blocked_providers.is_empty()
            && server.guard.pause_mode() == PauseMode::None
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(state.get_data().await.blocked_providers.is_empty());
    assert_eq!(server.guard.pause_mode(), PauseMode::None);
    assert!(hold_queue.current_alert().is_none());
    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn e2e_connect_silent_recovery_works_repeatedly_and_respects_killswitch() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "9.9.9.9".to_string(),
        "RU".to_string(),
        9009u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let state = AppState::new_in_memory();
    state
        .set_pinned_ip(Some("1.1.1.1".to_string()))
        .await
        .unwrap();
    state
        .add_trusted_exception("anthropic", "7.7.7.7")
        .await
        .unwrap();

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
            let ip = exit_probe.lock().unwrap().as_ref().map(|x| x.0.clone());
            Box::pin(async move { ip })
        })),
        None,
    );
    server
        .guard
        .seed_baseline_for_test("9.9.9.9", "RU", None)
        .await;
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // Cycle 1: Blocked on RU with baseline + UntilNetworkChange, then switch back to pinned 1.1.1.1
    // WITHOUT running guard tick (simulating immediate CONNECT inside PROBE_MIN_GAP_MS).
    for p in KNOWN_PROVIDERS {
        state.block_provider(p).await.unwrap();
    }
    server
        .guard
        .mark_paused_until_network_change(Some("RU block".to_string()))
        .await;
    server.guard.sync_gates_with_state(&state).await;

    *exit.lock().unwrap() = Some(("1.1.1.1".to_string(), "DE".to_string(), 24940));
    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
    assert!(!state.is_provider_blocked("anthropic").await);
    assert_eq!(server.guard.pause_mode(), PauseMode::None);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Cycle 2: Block again on 8.8.8.8, then switch to trusted exception 7.7.7.7 -> MUST recover
    // again on incoming CONNECT (never blocked by one-shot flag!).
    state.block_provider("anthropic").await.unwrap();
    server
        .guard
        .mark_paused_until_network_change(Some("Second block".to_string()))
        .await;
    server.guard.sync_gates_with_state(&state).await;

    *exit.lock().unwrap() = Some(("7.7.7.7".to_string(), "NL".to_string(), 13335));
    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
    assert!(!state.is_provider_blocked("anthropic").await);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);

    // Manual Kill-Switch MUST NEVER be bypassed even on pinned IP 1.1.1.1.
    *exit.lock().unwrap() = Some(("1.1.1.1".to_string(), "DE".to_string(), 24940));
    server.guard.set_manual_killswitch(true, &state).await;
    let (_s_ks, resp_ks) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(
        resp_ks.contains("403"),
        "manual killswitch must stay 403 on pinned IP: {resp_ks}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn e2e_per_provider_pinned_ips_and_transient_unknown_geo_never_sticky_locks() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };

    // Start with empty country (transient Unknown geo during utun handshake) on 1.1.1.1.
    let exit = Arc::new(std::sync::Mutex::new(Some((
        "1.1.1.1".to_string(),
        String::new(),
        24940u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let state = AppState::new_in_memory();
    state
        .set_interception_behavior(zastava_lib::state::InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    state
        .set_pinned_ip_for("anthropic", Some("1.1.1.1".to_string()))
        .await
        .unwrap();
    state
        .set_pinned_ip_for("openai", Some("2.2.2.2".to_string()))
        .await
        .unwrap();
    state.set_strict_pinning_enabled(true).await.unwrap();
    state
        .set_provider_monitoring("gemini", false)
        .await
        .unwrap();

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
    let wake_flag = Arc::new(AtomicBool::new(true));
    let _ = &wake_flag;
    server.guard.start_with_test_env(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(move || {
            let ip = exit_probe.lock().unwrap().as_ref().map(|x| x.0.clone());
            Box::pin(async move { ip })
        })),
        None,
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // 1. Transient Unknown geo on pinned 1.1.1.1 fails closed for CONNECT without writing to blocked_providers.
    let (_s_unk, resp_unk) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(
        resp_unk.contains("403"),
        "expected 403 on unknown geo: {resp_unk}"
    );
    assert!(
        !state.is_provider_blocked("anthropic").await,
        "transient unknown geo on pinned IP must not persist block"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    // 2. Now block both on RU, then return to 1.1.1.1 with DE resolved -> anthropic opens, openai stays blocked.
    state.block_provider("anthropic").await.unwrap();
    state.block_provider("openai").await.unwrap();
    server
        .guard
        .mark_paused_until_network_change(Some("RU block".to_string()))
        .await;
    server.guard.sync_gates_with_state(&state).await;

    *exit.lock().unwrap() = Some(("1.1.1.1".to_string(), "DE".to_string(), 24940));
    auditor.resolver.invalidate_direct_cache().await;
    auditor
        .resolver
        .set_cached(NetworkTelemetry {
            ip: "1.1.1.1".to_string(),
            country_code: "DE".to_string(),
            hostname: None,
            asn: Some(24940),
            org: Some("MyPersonalVPS".to_string()),
            isp: Some("MyPersonalVPS".to_string()),
            timezone: Some("Europe/Berlin".to_string()),
            resolved_at: current_timestamp(),
        })
        .await;
    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
    assert!(!state.is_provider_blocked("anthropic").await);
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert!(state.is_provider_blocked("openai").await);
    let (_s_oai, resp_oai) = send_connect(server.bound_addr, "api.openai.com").await;
    assert!(
        resp_oai.contains("403"),
        "mismatched per-provider pin openai must remain 403: {resp_oai}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn e2e_routed_cold_startup_recovery_never_poisons_direct_baseline() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_hits)) = spawn_echo_upstream().await else {
        return;
    };
    let entry_listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("bind mock entry: {e}"),
    };
    let entry_addr = entry_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = entry_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                if let Ok(n) = client.read(&mut buf).await
                    && n > 0
                    && let Ok(mut target) = TcpStream::connect(upstream_addr).await
                {
                    let _ = client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                }
            });
        }
    });

    let exit = Arc::new(std::sync::Mutex::new(Some((
        "1.1.1.1".to_string(),
        "DE".to_string(),
        24940u32,
    ))));
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(DynamicExitProbe(Arc::clone(&exit))),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let state = AppState::new_in_memory();
    let route = zastava_lib::routing::Route {
        id: "r_test".to_string(),
        label: "Test Key".to_string(),
        raw_key: format!("http://{entry_addr}"),
        entries: vec![zastava_lib::routing::Entry {
            proto: zastava_lib::routing::EntryProto::Http,
            host: entry_addr.ip().to_string(),
            port: entry_addr.port(),
            username: None,
            password: None,
            sni: None,
        }],
        country: Some("NL".to_string()),
        exit_ip: Some("99.99.99.99".to_string()),
        expires_at: None,
        sub_url: None,
        grace_extended: false,
        enabled: true,
        added_at: 0,
    };
    state.upsert_route(route).await.unwrap();
    state
        .bind_provider_route("anthropic", Some("r_test"))
        .await
        .unwrap();
    state.block_provider("anthropic").await.unwrap();
    auditor
        .resolver
        .set_cached_for_route(
            Some("r_test".to_string()),
            NetworkTelemetry {
                ip: "99.99.99.99".to_string(),
                country_code: "NL".to_string(),
                hostname: None,
                asn: Some(24940),
                org: Some("TestKeyVPS".to_string()),
                isp: Some("TestKeyVPS".to_string()),
                timezone: Some("Europe/Amsterdam".to_string()),
                resolved_at: current_timestamp(),
            },
        )
        .await;

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
        state.clone(),
        hold_queue.clone(),
        None,
        None,
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // Cold startup recovery on routed `anthropic`: unblocks `anthropic` and leaves direct
    // guard baseline / observed_ip untouched (`None`).
    assert_connect_ok_echo(server.bound_addr, "claude.ai").await;
    assert!(upstream_hits.load(Ordering::SeqCst) >= 1);
    assert!(!state.is_provider_blocked("anthropic").await);
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert!(
        server.guard.current_observed_ip().await.is_none(),
        "routed provider recovery must not poison direct guard observed_ip/baseline"
    );
}
