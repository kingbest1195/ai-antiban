//! E2E regression tests for long-lived routed sessions (reasoning pauses, half-close,
//! large streaming responses, HTTPS TLS backpressure, metadata-only route refresh,
//! connection limit 503, bounded half-close drain, and transient background GeoIP failures).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{AuditEnv, HttpProbeOutcome, LookupOutcome};
use zastava_lib::auditor::{AuditProtectionFlags, Auditor, NetworkTelemetry};
use zastava_lib::proxy::server::{HALF_CLOSE_DRAIN_TIMEOUT, MAX_CONCURRENT_CONNECTIONS};
use zastava_lib::proxy::upstream::build_test_tls_config;
use zastava_lib::proxy::{HoldQueue, ProxyServer};
use zastava_lib::routing::{Entry, EntryProto, Route};
use zastava_lib::state::AppState;

fn socks_route(id: &str, host: &str, port: u16) -> Route {
    Route {
        id: id.to_string(),
        label: format!("test {id}"),
        country: Some("NL".to_string()),
        exit_ip: None,
        expires_at: None,
        sub_url: None,
        grace_extended: false,
        entries: vec![Entry {
            proto: EntryProto::Socks5,
            host: host.to_string(),
            port,
            username: None,
            password: None,
            sni: None,
        }],
        raw_key: format!("socks5://{host}:{port}"),
        enabled: true,
        added_at: 0,
    }
}

fn https_route(id: &str, host: &str, port: u16, expires_at: Option<u64>) -> Route {
    Route {
        id: id.to_string(),
        label: format!("https {id}"),
        country: Some("NL".to_string()),
        exit_ip: None,
        expires_at,
        sub_url: None,
        grace_extended: false,
        entries: vec![Entry {
            proto: EntryProto::Https,
            host: host.to_string(),
            port,
            username: None,
            password: None,
            sni: Some("localhost".to_string()),
        }],
        raw_key: format!("https://{host}:{port}"),
        enabled: true,
        added_at: 0,
    }
}

struct TestTlsFixture {
    acceptor: TlsAcceptor,
    client_cfg: Arc<ClientConfig>,
}

fn make_tls_fixture() -> TestTlsFixture {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Zastava E2E Test CA");
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    let cert_der: CertificateDer<'static> = leaf_cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut srv_cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    srv_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let client_cfg = build_test_tls_config(roots).unwrap();

    TestTlsFixture {
        acceptor: TlsAcceptor::from(Arc::new(srv_cfg)),
        client_cfg,
    }
}

async fn read_http_connect_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut b).await.unwrap_or(0) == 0 {
            break;
        }
        head.push(b[0]);
    }
    String::from_utf8_lossy(&head).to_string()
}

/// Spawns a SOCKS5 server that waits `reasoning_pause` after receiving the client request (and
/// optional half-close), then streams `response_bytes` back to the client.
async fn spawn_reasoning_socks_server(reasoning_pause: Duration, response_bytes: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
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
                if s.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut rest = vec![0u8; len[0] as usize + 2];
                if s.read_exact(&mut rest).await.is_err() {
                    return;
                }
                let _ = s
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;

                // Read client request until EOF (half-close) or initial chunk.
                let mut req_buf = [0u8; 256];
                let _ = tokio::time::timeout(Duration::from_millis(300), async {
                    loop {
                        match s.read(&mut req_buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                })
                .await;

                // Simulate silent model reasoning pause before first token.
                tokio::time::sleep(reasoning_pause).await;

                let payload = vec![b'R'; response_bytes];
                for chunk in payload.chunks(8192) {
                    if s.write_all(chunk).await.is_err() {
                        return;
                    }
                }
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

async fn setup_routed_server_opts(
    route: Route,
    tls_override: Option<Arc<ClientConfig>>,
    max_conns: Option<usize>,
    half_close_drain: Option<Duration>,
) -> (Arc<ProxyServer>, AppState) {
    let state = AppState::new_in_memory();
    state.upsert_route(route.clone()).await.unwrap();
    state
        .bind_provider_route("anthropic", Some(&route.id))
        .await
        .unwrap();

    let mut probe = FakeProbe::new(HttpProbeOutcome::Timeout);
    probe = probe.with_route("torproject", HttpProbeOutcome::Timeout);
    let env = AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::Timeout)),
        probe: Arc::new(probe),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    };
    let auditor = Auditor::with_env(env).unwrap();
    auditor.set_protection_flags(AuditProtectionFlags {
        sysproxy_active: true,
        cli_or_sandbox_protection_active: true,
        os_pac_deferred: false,
    });
    auditor
        .resolver
        .set_cached_for_route(
            Some(route.id.clone()),
            NetworkTelemetry {
                ip: "185.220.10.50".to_string(),
                country_code: "NL".to_string(),
                hostname: Some("nl-vps.example.net".to_string()),
                asn: Some(20473),
                org: Some("Choopa".to_string()),
                isp: Some("Choopa".to_string()),
                timezone: Some("Europe/Amsterdam".to_string()),
                resolved_at: zastava_lib::auditor::network::current_timestamp(),
            },
        )
        .await;

    let mut srv =
        ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::new(HoldQueue::new()), None)
            .await
            .unwrap();
    if let Some(cfg) = tls_override {
        srv = srv.with_route_tls_config(cfg);
    }
    if let Some(limit) = max_conns {
        srv = srv.with_max_concurrent_connections(limit);
    }
    if let Some(drain) = half_close_drain {
        srv = srv.with_half_close_drain_timeout(drain);
    }
    let server = Arc::new(srv);
    let srv_task = Arc::clone(&server);
    tokio::spawn(async move { srv_task.run().await });
    (server, state)
}

async fn open_connect_tunnel(addr: std::net::SocketAddr) -> tokio::net::TcpStream {
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut head = [0u8; 128];
    let n = client.read(&mut head).await.unwrap();
    assert!(
        String::from_utf8_lossy(&head[..n]).contains("200"),
        "expected 200 Connection Established, got: {}",
        String::from_utf8_lossy(&head[..n])
    );
    client
}

#[tokio::test]
async fn long_silent_reasoning_with_half_close_and_geoip_timeouts_survives() {
    let response_len = 128 * 1024; // >64 KiB to exercise multi-chunk relay
    let socks_port = spawn_reasoning_socks_server(Duration::from_millis(600), response_len).await;
    let route = socks_route("long-reasoning", "127.0.0.1", socks_port);
    let (server, state) = setup_routed_server_opts(route.clone(), None, None, None).await;

    // 1. Long-lived primary reasoning stream: client sends prompt, half-closes write side,
    //    waits silently for reasoning pause, and receives full >64 KiB response.
    let mut primary = open_connect_tunnel(server.bound_addr).await;
    primary.write_all(b"POST /v1/messages").await.unwrap();
    primary.shutdown().await.unwrap();

    // 2. While primary is silently reasoning and external GeoIP probes time out,
    //    open an auxiliary CONNECT request: must succeed and NOT mark route unreachable.
    let mut aux = tokio::net::TcpStream::connect(server.bound_addr)
        .await
        .unwrap();
    aux.write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut head = [0u8; 128];
    let n_aux = tokio::time::timeout(Duration::from_secs(2), aux.read(&mut head))
        .await
        .expect("auxiliary CONNECT must not stall on GeoIP timeout")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&head[..n_aux]).contains("200"),
        "auxiliary CONNECT must succeed without RouteDownReason::Unreachable"
    );

    // 3. Primary stream finishes reading the full >64 KiB streaming response after pause.
    let mut received = Vec::with_capacity(response_len);
    tokio::time::timeout(Duration::from_secs(5), primary.read_to_end(&mut received))
        .await
        .expect("primary reasoning stream must complete")
        .unwrap();
    assert_eq!(received.len(), response_len);
    assert!(received.iter().all(|&b| b == b'R'));

    assert_eq!(
        state
            .route_health()
            .get(&route.id)
            .and_then(|h| h.reachable),
        Some(true),
        "route must remain healthy when entry node is alive"
    );
    assert!(
        !state
            .stats()
            .snapshot_sync()
            .recent_events
            .iter()
            .any(|e| e.action == "ROUTE_DOWN"),
        "no ROUTE_DOWN event may be recorded while entry node is alive"
    );
}

#[tokio::test]
async fn https_entry_large_payload_under_backpressure_completes_without_stalled_tls() {
    let fixture = make_tls_fixture();
    let acceptor = fixture.acceptor.clone();
    let total_upload = 1536 * 1024; // 1.5 MiB large context payload

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let req = read_http_connect_head(&mut tls).await;
                if !req.starts_with("CONNECT api.anthropic.com:443 HTTP/1.1") {
                    return;
                }
                let _ = tls
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;

                // Drain 1.5 MiB slowly in 4 KiB chunks with periodic pauses to create TCP
                // backpressure (`WouldBlock` on sender's TlsStream) without waiting for EOF.
                let mut received = 0usize;
                let mut chunk = [0u8; 4096];
                let mut step = 0usize;
                while received < total_upload {
                    let need = (total_upload - received).min(chunk.len());
                    let Ok(n) = tls.read(&mut chunk[..need]).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    for (i, &b) in chunk[..n].iter().enumerate() {
                        let expected = ((received + i) % 251) as u8;
                        assert_eq!(b, expected, "payload mismatch at byte {}", received + i);
                    }
                    received += n;
                    step += 1;
                    if step.is_multiple_of(8) {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
                let ack = format!("ACK:{received}\n");
                let _ = tls.write_all(ack.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });

    let route = https_route("https-backpressure", "127.0.0.1", port, None);
    let (server, _) = setup_routed_server_opts(route, Some(fixture.client_cfg), None, None).await;

    let mut client = open_connect_tunnel(server.bound_addr).await;
    let payload: Vec<u8> = (0..total_upload).map(|i| (i % 251) as u8).collect();
    // Write full 1.5 MiB and do NOT call shutdown(): server only responds after receiving the
    // final encrypted TLS record, proving zero bytes are stranded in rustls sendable_tls.
    tokio::time::timeout(Duration::from_secs(15), client.write_all(&payload))
        .await
        .expect("large payload write must not stall")
        .unwrap();

    let expected_ack = format!("ACK:{total_upload}\n");
    let mut ack_buf = vec![0u8; expected_ack.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut ack_buf))
        .await
        .expect("HTTPS entry proxy must receive entire payload without client EOF")
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&ack_buf), expected_ack);
}

#[tokio::test]
async fn https_entry_client_half_close_preserves_outer_tls_without_close_notify() {
    let fixture = make_tls_fixture();
    let acceptor = fixture.acceptor.clone();
    let response_len = 128 * 1024;
    let saw_premature_close_notify = Arc::new(AtomicBool::new(false));
    let saw_flag = Arc::clone(&saw_premature_close_notify);
    let saw_flag_srv = Arc::clone(&saw_premature_close_notify);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let saw_flag = Arc::clone(&saw_flag);
            let saw_flag_srv = Arc::clone(&saw_flag_srv);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let req = read_http_connect_head(&mut tls).await;
                if !req.starts_with("CONNECT api.anthropic.com:443 HTTP/1.1") {
                    return;
                }
                let _ = tls
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;

                let (mut tr, mut tw) = tokio::io::split(tls);
                let mut req_buf = [0u8; 64];
                let Ok(n) = tr.read(&mut req_buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                assert_eq!(&req_buf[..n], b"POST /v1/messages");

                // Monitor outer TLS stream for premature `close_notify` (Ok(0)) while streaming.
                let streaming_done = Arc::new(AtomicBool::new(false));
                let done_flag = Arc::clone(&streaming_done);
                let reader_task = tokio::spawn(async move {
                    let mut extra = [0u8; 64];
                    if let Ok(0) = tr.read(&mut extra).await
                        && !done_flag.load(Ordering::SeqCst)
                    {
                        saw_flag.store(true, Ordering::SeqCst);
                        return true;
                    }
                    false
                });

                tokio::time::sleep(Duration::from_millis(350)).await;
                if saw_flag_srv.load(Ordering::SeqCst) {
                    return;
                }
                let body = vec![b'H'; response_len];
                for chunk in body.chunks(8192) {
                    if tw.write_all(chunk).await.is_err() {
                        return;
                    }
                }
                let _ = tw.flush().await;
                streaming_done.store(true, Ordering::SeqCst);
                let _ = tw.shutdown().await;
                let _ = reader_task.await;
            });
        }
    });

    let route = https_route("https-half-close", "127.0.0.1", port, None);
    let (server, _) = setup_routed_server_opts(route, Some(fixture.client_cfg), None, None).await;

    let mut client = open_connect_tunnel(server.bound_addr).await;
    client.write_all(b"POST /v1/messages").await.unwrap();
    client.shutdown().await.unwrap();

    let mut received = Vec::with_capacity(response_len);
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut received))
        .await
        .expect("delayed HTTPS response must drain after client half-close")
        .unwrap();
    assert!(!saw_premature_close_notify.load(Ordering::SeqCst));
    assert_eq!(received.len(), response_len);
    assert!(received.iter().all(|&b| b == b'H'));
}

#[tokio::test]
async fn https_entry_metadata_only_route_refresh_keeps_live_tunnel_open() {
    let fixture = make_tls_fixture();
    let acceptor = fixture.acceptor.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = read_http_connect_head(&mut tls).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                let mut buf = [0u8; 64];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 || tls.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = tls.flush().await;
                }
            });
        }
    });

    let now = zastava_lib::auditor::network::current_timestamp();
    let mut route = https_route("https-meta-refresh", "127.0.0.1", port, Some(now + 3600));
    let (server, state) =
        setup_routed_server_opts(route.clone(), Some(fixture.client_cfg), None, None).await;

    let mut client = open_connect_tunnel(server.bound_addr).await;
    client.write_all(b"PING_1").await.unwrap();
    let mut echo = [0u8; 6];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"PING_1");

    // Metadata-only refresh (`expires_at`, `grace_extended`, `label`), identical `id` and `entries`.
    route.expires_at = Some(now + 7200);
    route.grace_extended = true;
    route.label = "refreshed subscription label".to_string();
    state.upsert_route(route.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    client.write_all(b"PING_2").await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut echo))
        .await
        .expect("live tunnel must stay open after metadata-only route refresh")
        .unwrap();
    assert_eq!(&echo, b"PING_2");

    // Real transport change (`entries` port changed) must immediately tear down the live tunnel.
    route.entries[0].port += 1;
    state.upsert_route(route).await.unwrap();
    let mut tail = [0u8; 8];
    let res = tokio::time::timeout(Duration::from_secs(2), client.read(&mut tail))
        .await
        .expect("transport entry change must abort tunnel");
    assert!(matches!(res, Ok(0) | Err(_)));
}

#[tokio::test]
async fn connection_limit_returns_503_and_half_close_drain_releases_permit() {
    assert_eq!(MAX_CONCURRENT_CONNECTIONS, 1024);
    assert_eq!(HALF_CLOSE_DRAIN_TIMEOUT, Duration::from_secs(45));

    // Part 1: Saturating connection limit writes explicit HTTP 503 instead of silent EOF.
    let fixture = make_tls_fixture();
    let acceptor = fixture.acceptor.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = read_http_connect_head(&mut tls).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                let mut buf = [0u8; 64];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 || buf[..n].starts_with(b"CLOSE") {
                        let _ = tls.shutdown().await;
                        break;
                    }
                }
            });
        }
    });

    let route = https_route("https-limit", "127.0.0.1", port, None);
    let (server, _) =
        setup_routed_server_opts(route, Some(Arc::clone(&fixture.client_cfg)), Some(2), None).await;

    let mut c1 = open_connect_tunnel(server.bound_addr).await;
    let _c2 = open_connect_tunnel(server.bound_addr).await;

    let mut c3 = tokio::net::TcpStream::connect(server.bound_addr)
        .await
        .unwrap();
    c3.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut head_buf = [0u8; 256];
    let n3 = tokio::time::timeout(Duration::from_secs(2), c3.read(&mut head_buf))
        .await
        .expect("saturated proxy must send HTTP 503 rather than stall")
        .unwrap();
    let resp_str = String::from_utf8_lossy(&head_buf[..n3]);
    assert!(
        resp_str.starts_with("HTTP/1.1 503 Service Unavailable"),
        "expected 503 Service Unavailable, got: {resp_str}"
    );

    c1.write_all(b"CLOSE").await.unwrap();
    let mut eof_buf = [0u8; 8];
    let _ = c1.read(&mut eof_buf).await;
    drop(c1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _c4 = open_connect_tunnel(server.bound_addr).await;

    // Part 2: Bounded half-close drain closes half-dead tunnel and releases semaphore permit.
    let drain_route = https_route("https-drain", "127.0.0.1", port, None);
    let (drain_srv, _) = setup_routed_server_opts(
        drain_route,
        Some(fixture.client_cfg),
        Some(1),
        Some(Duration::from_millis(350)),
    )
    .await;

    let mut half_dead = open_connect_tunnel(drain_srv.bound_addr).await;
    half_dead.write_all(b"REQ").await.unwrap();
    half_dead.shutdown().await.unwrap();

    // Before drain timeout expires, the single permit is still occupied -> 503.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut blocked = tokio::net::TcpStream::connect(drain_srv.bound_addr)
        .await
        .unwrap();
    blocked
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let n_blk = tokio::time::timeout(Duration::from_secs(2), blocked.read(&mut head_buf))
        .await
        .expect("expected 503 while draining")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&head_buf[..n_blk]).starts_with("HTTP/1.1 503 Service Unavailable"),
        "expected 503 while half-close is draining"
    );

    // After drain timeout expires, half-dead tunnel closes and frees its permit -> 200 succeeds.
    tokio::time::sleep(Duration::from_millis(350)).await;
    let _recovered = open_connect_tunnel(drain_srv.bound_addr).await;
}
