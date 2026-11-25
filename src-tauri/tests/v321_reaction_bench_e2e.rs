//! Reaction latency benchmark and 0-byte leak E2E suite for Zastava v3.2.1 (`spec-v3.2.1.md` §13).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::geo_matrix::ProviderId;
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{HttpProbeOutcome, LookupOutcome};
use zastava_lib::auditor::{AuditEnv, Auditor, NetworkTelemetry};
use zastava_lib::proxy::guard::{
    GuardTestObserver, ProbeFn, UtunDebounceState, stabilize_non_default_utun_for_test,
};
use zastava_lib::proxy::hold_queue::{HoldQueue, HoldResolution};
use zastava_lib::proxy::transit::{DialFn, ResolveFn, Transit};
use zastava_lib::proxy::{Gate, NetworkGuard, ProxyServer};
use zastava_lib::state::AppState;

fn offline_auditor() -> Auditor {
    Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(FakeProbe::new(HttpProbeOutcome::Timeout)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap()
}

async fn spawn_counting_echo() -> Option<(SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>)> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("bind counting echo: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let (c2, b2) = (Arc::clone(&conns), Arc::clone(&bytes));
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            c2.fetch_add(1, Ordering::SeqCst);
            let b3 = Arc::clone(&b2);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    b3.fetch_add(n, Ordering::SeqCst);
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Some((addr, conns, bytes))
}

async fn send_connect(addr: SocketAddr, host: &str) -> (TcpStream, String) {
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
async fn bench_warm_cache_check_route_fingerprint_sync_p50_p99() {
    let guard = Arc::new(NetworkGuard::new());
    guard
        .seed_baseline_for_test("185.10.20.30", "DE", None)
        .await;
    // Warm IFACE_CACHE / DNS_CACHE and initialize last_route_fp.
    let _ = guard.check_route_fingerprint_sync(None);

    let mut samples_ms = Vec::with_capacity(50);
    for _ in 0..50 {
        let t0 = Instant::now();
        let changed = guard.check_route_fingerprint_sync(None);
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert!(!changed, "warm-cache steady check must not report change");
        samples_ms.push(elapsed_ms);
    }
    samples_ms.sort_by(|a, b| a.total_cmp(b));
    let p50 = samples_ms[samples_ms.len() / 2];
    let p99_idx = ((samples_ms.len() * 99) / 100).min(samples_ms.len() - 1);
    let p99 = samples_ms[p99_idx];
    let max = *samples_ms.last().unwrap();
    println!(
        "[bench] check_route_fingerprint_sync warm_cache n=50 p50_ms={p50:.4} p99_ms={p99:.4} max_ms={max:.4}"
    );
    assert!(
        p99 < 1.0,
        "warm-cache check_route_fingerprint_sync P99 must be < 1.0 ms (got {p99:.4} ms)"
    );
}

#[tokio::test]
async fn e2e_a_default_udp_route_drop_freezes_gate_with_zero_upstream_bytes() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, conns, bytes)) = spawn_counting_echo().await else {
        return;
    };
    let state = AppState::new_in_memory();
    state.allow_provider_for_session("anthropic").await.unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_auditor(),
            state.clone(),
            hold_queue.clone(),
            Some(upstream_addr),
        )
        .await
        .unwrap(),
    );

    let fp = Arc::new(Mutex::new(
        "10.8.0.2|10.8.0.2|none|dns:10.8.0.1|if:utun4=10.8.0.2|upstream:".to_string(),
    ));
    let fp_reader = Arc::clone(&fp);
    server
        .guard
        .set_route_fingerprint_fn_for_test(Some(Arc::new(move |_| {
            fp_reader.lock().unwrap().clone()
        })));
    let observer = Arc::new(GuardTestObserver::default());
    let probe: ProbeFn = Arc::new(|| Box::pin(async { None }));
    server.guard.start_with_test_env_observed(
        offline_auditor(),
        state.clone(),
        hold_queue.clone(),
        Some(probe),
        None,
        observer,
    );
    server
        .guard
        .seed_baseline_for_test("185.10.20.30", "DE", None)
        .await;
    assert!(!server.guard.check_route_fingerprint_sync(None));
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // Default UDP route drops before incoming AI CONNECT.
    *fp.lock().unwrap() = "none|none|none|dns:none|if:none|upstream:".to_string();

    let proxy_addr = server.bound_addr;
    let t_req = Instant::now();
    let connect_task =
        tokio::spawn(async move { send_connect(proxy_addr, "api.anthropic.com").await });

    for _ in 0..100 {
        if server.guard.gate_for(ProviderId::Anthropic) == Gate::Pending {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let freeze_ms = t_req.elapsed().as_secs_f64() * 1000.0;
    println!("[bench] default_udp_drop_freeze latency_ms={freeze_ms:.3}");
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
    assert_eq!(conns.load(Ordering::SeqCst), 0);
    assert_eq!(bytes.load(Ordering::SeqCst), 0);

    let alert = loop {
        if let Some(a) = hold_queue.current_alert() {
            break a;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(hold_queue.resolve(&alert.id, HoldResolution::Block).await);
    let (_sock, resp) = connect_task.await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert_eq!(conns.load(Ordering::SeqCst), 0);
    assert_eq!(bytes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn e2e_b_canary_connect_under_blocked_gate_with_pinned_ip_completes_under_50ms() {
    zastava_lib::sysproxy::force_os_dry_run();
    let state = AppState::new_in_memory();
    state
        .set_pinned_ip(Some("203.0.113.10".to_string()))
        .await
        .unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(offline_auditor(), state.clone(), hold_queue.clone(), None)
            .await
            .unwrap(),
    );
    let observer = Arc::new(GuardTestObserver::default());
    // Probe sleeps 2500ms if invoked: canary under Gate::Blocked MUST never invoke it.
    let slow_probe: ProbeFn = Arc::new(|| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(2500)).await;
            Some("203.0.113.10".to_string())
        })
    });
    server.guard.start_with_test_env_observed(
        offline_auditor(),
        state.clone(),
        hold_queue,
        Some(slow_probe),
        None,
        observer,
    );
    server
        .guard
        .seed_baseline_for_test("203.0.113.10", "DE", None)
        .await;
    server.guard.freeze_for_test().await;
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let t0 = Instant::now();
    let (_sock, resp) =
        send_connect(server.bound_addr, "canary-test.anthropic.zastava.local").await;
    let elapsed = t0.elapsed();
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    println!("[bench] canary_under_blocked_pinned latency_ms={elapsed_ms:.3}");
    assert!(
        resp.contains("503 Service Unavailable") && resp.contains("INTERCEPTED_BY_KILLSWITCH"),
        "unexpected canary response: {resp}"
    );
    assert!(
        elapsed < Duration::from_millis(50),
        "canary under Gate::Blocked + pinned_ip must complete in < 50ms (took {elapsed_ms:.2}ms)"
    );
}

#[tokio::test]
async fn e2e_c_dead_local_chained_proxy_fails_closed_with_zero_direct_connects() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, upstream_conns, upstream_bytes)) = spawn_counting_echo().await else {
        return;
    };
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);

    let direct_dials = Arc::new(AtomicUsize::new(0));
    let dials_clone = Arc::clone(&direct_dials);
    let resolver: ResolveFn = Arc::new(|_host| {
        Box::pin(async move { Ok(vec!["93.184.216.34".parse::<IpAddr>().unwrap()]) })
    });
    let dial: DialFn = Arc::new(move |_addr| {
        dials_clone.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { TcpStream::connect(upstream_addr).await })
    });
    let dead_url = format!("http://{dead_addr}");
    let transit = Transit::with_backends(resolver, dial, Arc::new(Instant::now))
        .with_chained(Arc::new(move || Some(dead_url.clone())));

    let auditor = offline_auditor();
    auditor
        .resolver
        .set_cached(NetworkTelemetry {
            ip: "185.100.10.2".to_string(),
            country_code: "NL".to_string(),
            hostname: Some("nl-vpn.example.net".to_string()),
            asn: Some(20473),
            org: Some("Choopa".to_string()),
            isp: Some("Choopa".to_string()),
            timezone: Some("Europe/Amsterdam".to_string()),
            resolved_at: zastava_lib::auditor::network::current_timestamp(),
        })
        .await;
    let state = AppState::new_in_memory();
    state.allow_provider_for_session("anthropic").await.unwrap();
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state, Arc::new(HoldQueue::new()), None)
            .await
            .unwrap()
            .with_transit(transit),
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let (_sock, resp) = send_connect(server.bound_addr, "api.anthropic.com").await;
    assert!(
        resp.starts_with("HTTP/1.1 502"),
        "dead chained_proxy must fail closed with 502, got: {resp}"
    );
    assert_eq!(direct_dials.load(Ordering::SeqCst), 0);
    assert_eq!(server.direct_connect_count(), 0);
    assert_eq!(upstream_conns.load(Ordering::SeqCst), 0);
    assert_eq!(upstream_bytes.load(Ordering::SeqCst), 0);
}

#[test]
fn e2e_d_non_default_utun_disappearance_detected_at_zero_ms() {
    let mut st = UtunDebounceState::default();
    let t0 = Instant::now();
    let udp = "192.168.1.10|192.168.1.10|none";

    let init = stabilize_non_default_utun_for_test(
        &mut st,
        udp,
        vec!["en0=192.168.1.10".into()],
        vec!["utun4=10.8.0.2".into()],
        t0,
    );
    assert_eq!(init, "en0=192.168.1.10,utun4=10.8.0.2");

    // Additive IPv6 churn while utun4 IPv4 remains up is still debounced.
    let churn = stabilize_non_default_utun_for_test(
        &mut st,
        udp,
        vec!["en0=192.168.1.10".into()],
        vec!["utun4=10.8.0.2".into(), "utun4=fd7a:115c::/64".into()],
        t0 + Duration::from_millis(100),
    );
    assert_eq!(churn, "en0=192.168.1.10,utun4=10.8.0.2");

    // Utun disappearance surfaces immediately (0ms debounce).
    let dropped = stabilize_non_default_utun_for_test(
        &mut st,
        udp,
        vec!["en0=192.168.1.10".into()],
        vec![],
        t0 + Duration::from_millis(100),
    );
    assert_eq!(dropped, "en0=192.168.1.10");
}

#[tokio::test]
async fn e2e_e_active_half_relay_during_gate_pending_writes_zero_bytes_to_upstream() {
    zastava_lib::sysproxy::force_os_dry_run();
    let Some((upstream_addr, _conns, upstream_bytes)) = spawn_counting_echo().await else {
        return;
    };
    let state = AppState::new_in_memory();
    state.allow_provider_for_session("anthropic").await.unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_auditor(),
            state.clone(),
            hold_queue.clone(),
            Some(upstream_addr),
        )
        .await
        .unwrap(),
    );
    let fp = Arc::new(Mutex::new(
        "10.8.0.2|10.8.0.2|none|dns:10.8.0.1|if:utun4=10.8.0.2|upstream:".to_string(),
    ));
    let fp_reader = Arc::clone(&fp);
    server
        .guard
        .set_route_fingerprint_fn_for_test(Some(Arc::new(move |_| {
            fp_reader.lock().unwrap().clone()
        })));
    server
        .guard
        .seed_baseline_for_test("185.10.20.30", "DE", None)
        .await;
    let _ = server.guard.check_route_fingerprint_sync(None);

    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let (mut client, head) = send_connect(server.bound_addr, "api.anthropic.com").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let pre = b"before-pending";
    client.write_all(pre).await.unwrap();
    client.flush().await.unwrap();
    let mut echo_buf = vec![0u8; pre.len()];
    client.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, pre);
    assert_eq!(upstream_bytes.load(Ordering::SeqCst), pre.len());

    // Non-default `if:` change freezes Gate::Pending via check_route_fingerprint_sync without
    // aborting the socket immediately; HalfRelay must still forward 0 bytes while Pending.
    *fp.lock().unwrap() =
        "10.8.0.2|10.8.0.2|none|dns:10.8.0.1|if:utun5=10.9.0.2|upstream:".to_string();
    assert!(server.guard.check_route_fingerprint_sync(None));
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Pending);

    tokio::time::sleep(Duration::from_millis(20)).await;
    client
        .write_all(b"secret-payload-while-gate-is-pending")
        .await
        .unwrap();
    client.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(
        upstream_bytes.load(Ordering::SeqCst),
        pre.len(),
        "HalfRelay must write 0 bytes to upstream during Gate::Pending"
    );

    server.guard.freeze_for_test().await;
    let mut closed_buf = [0u8; 32];
    let read_res = tokio::time::timeout(Duration::from_secs(2), client.read(&mut closed_buf)).await;
    assert!(matches!(read_res, Ok(Ok(0)) | Ok(Err(_))));
    assert_eq!(upstream_bytes.load(Ordering::SeqCst), pre.len());
}
