//! E2E regression tests for long-lived routed sessions (reasoning pauses, half-close,
//! large streaming responses, and transient background GeoIP failures).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{AuditEnv, HttpProbeOutcome, LookupOutcome};
use zastava_lib::auditor::{AuditProtectionFlags, Auditor, NetworkTelemetry};
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

async fn setup_routed_server(route: Route) -> (Arc<ProxyServer>, AppState) {
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

    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::new(HoldQueue::new()), None)
            .await
            .unwrap(),
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });
    (server, state)
}

#[tokio::test]
async fn long_silent_reasoning_with_half_close_and_geoip_timeouts_survives() {
    let response_len = 128 * 1024; // >64 KiB to exercise multi-chunk relay
    let socks_port = spawn_reasoning_socks_server(Duration::from_millis(600), response_len).await;
    let route = socks_route("long-reasoning", "127.0.0.1", socks_port);
    let (server, state) = setup_routed_server(route.clone()).await;

    // 1. Long-lived primary reasoning stream: client sends prompt, half-closes write side,
    //    waits silently for reasoning pause, and receives full >64 KiB response.
    let mut primary = tokio::net::TcpStream::connect(server.bound_addr)
        .await
        .unwrap();
    primary
        .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut head = [0u8; 128];
    let n = primary.read(&mut head).await.unwrap();
    assert!(
        String::from_utf8_lossy(&head[..n]).contains("200"),
        "expected 200 Connection Established"
    );

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
