//! End-to-End tests for instant popup on VPN/route switch and PauseMode::UntilNetworkChange
//! stability during `detecting` -> IP resolution.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::AuditEnv;
use zastava_lib::auditor::Auditor;
use zastava_lib::auditor::geo_matrix::ProviderId;
use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{HttpProbeOutcome, LookupOutcome};
use zastava_lib::proxy::hold_queue::{HoldQueue, HoldResolution};
use zastava_lib::proxy::{Gate, ProxyServer};
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
async fn e2e_pause_during_detecting_stays_paused_after_probe_resolves() {
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

    let current_ip = Arc::new(std::sync::Mutex::new(Some("1.1.1.1".to_string())));
    let probe_ip = Arc::clone(&current_ip);
    server.guard.start_with_test_env(
        auditor.clone(),
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(move || {
            let ip = probe_ip.lock().unwrap().clone();
            Box::pin(async move { ip })
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

    // 1. Baseline CONNECT succeeds.
    let (mut s1, resp1) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(resp1.contains("200 Connection Established"), "{resp1}");
    s1.write_all(b"ok").await.unwrap();
    let mut echo = [0u8; 2];
    s1.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ok");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // 2. Simulate VPN drop (offline probe -> instant Gate::Pending + detecting alert).
    *current_ip.lock().unwrap() = None;
    server.guard.wake_immediate_probe().await;
    server.guard.ensure_fresh().await;
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
    let alert = hold_queue.current_alert().expect("detecting alert open");
    assert_eq!(alert.phase, "detecting");

    // 3. User clicks "Пауза до смены сети" while still in `detecting`.
    let status = server
        .guard
        .pause_until_network_change(&state, Some("Пауза до смены сети".to_string()))
        .await;
    assert!(status.paused);
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert!(hold_queue.current_alert().is_none());

    // 4. In-flight probe resolves new IP "9.9.9.9" -> MUST adopt IP and NOT re-open alert.
    *current_ip.lock().unwrap() = Some("9.9.9.9".to_string());
    server.guard.tick_test().await;
    assert!(
        server.guard.pause_status().paused,
        "pause must stay active after resolving new IP"
    );
    assert!(
        hold_queue.current_alert().is_none(),
        "alert must not re-open while paused"
    );

    // 5. CONNECT while paused fails closed immediately with 403 and 0 new upstream hits.
    let (_s2, resp2) = send_connect(server.bound_addr, "claude.ai").await;
    assert!(resp2.contains("403"), "expected 403 while paused: {resp2}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // 6. Subsequent real IP change to "8.8.8.8" clears pause and opens detecting alert.
    *current_ip.lock().unwrap() = Some("8.8.8.8".to_string());
    server.guard.tick_test().await;
    assert!(!server.guard.pause_status().paused);
    let _ = hold_queue
        .resolve_all_for_provider("all", HoldResolution::Block)
        .await;
}

#[tokio::test]
async fn e2e_fast_fail_offline_transition_freezes_gate_and_emits_detecting_without_delay() {
    zastava_lib::sysproxy::force_os_dry_run();
    let auditor = offline_auditor_with_probe(HttpProbeOutcome::Timeout);
    let state = AppState::new_in_memory();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), hold_queue.clone(), None)
            .await
            .expect("bind proxy"),
    );

    let current_ip = Arc::new(std::sync::Mutex::new(Some("1.1.1.1".to_string())));
    let probe_ip = Arc::clone(&current_ip);
    server.guard.start_with_test_env(
        auditor,
        state.clone(),
        hold_queue.clone(),
        Some(Arc::new(move || {
            let ip = probe_ip.lock().unwrap().clone();
            Box::pin(async move { ip })
        })),
        None,
    );
    server
        .guard
        .seed_baseline_for_test("1.1.1.1", "NL", None)
        .await;

    // Simulate dead keep-alive / VPN server switch inside TUN (probe returns None).
    *current_ip.lock().unwrap() = None;
    let t0 = std::time::Instant::now();
    server.guard.wake_immediate_probe().await;
    server.guard.ensure_fresh().await;
    let elapsed = t0.elapsed();

    assert!(
        elapsed < Duration::from_millis(200),
        "detecting transition must be instant (<200ms), took {elapsed:?}"
    );
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
    let status = server.guard.pause_status();
    assert_eq!(status.gate, "pending");
    assert_eq!(
        status.pending_providers,
        vec!["anthropic", "gemini", "openai"]
    );

    let alert = hold_queue.current_alert().expect("detecting alert open");
    assert_eq!(alert.phase, "detecting");
    assert!(
        alert
            .network_change
            .as_ref()
            .and_then(|n| n.new_ip.as_ref())
            .is_none()
    );

    let _ = hold_queue
        .resolve_all_for_provider("all", HoldResolution::Superseded)
        .await;
}
