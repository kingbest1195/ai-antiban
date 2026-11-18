//! Routes in the gateway: fail-closed behavior and interaction with the network guard.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::Auditor;
use zastava_lib::proxy::hold_queue::HoldQueue;
use zastava_lib::proxy::{Gate, ProxyServer, Transit};
use zastava_lib::routing::{Entry, EntryProto, Route};
use zastava_lib::state::AppState;

fn socks_route(id: &str, port: u16) -> Route {
    Route {
        id: id.to_string(),
        label: format!("test {id}"),
        country: Some("NL".to_string()),
        exit_ip: None,
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
        enabled: true,
        added_at: 0,
    }
}

async fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Listener standing in for the "direct" path (server's test redirect): counts any connection.
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

/// Minimal SOCKS5 (no auth) that accepts any CONNECT and echoes.
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
                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn start(state: AppState, redirect: Option<std::net::SocketAddr>) -> Arc<ProxyServer> {
    let auditor = Auditor::new().unwrap();
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state, Arc::new(HoldQueue::new()), redirect)
            .await
            .unwrap(),
    );
    let s = Arc::clone(&server);
    tokio::spawn(async move { s.run().await });
    server
}

async fn connect(server: &ProxyServer, host: &str) -> Option<(TcpStream, String)> {
    let mut c = match TcpStream::connect(server.bound_addr).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("connect to gateway: {e}"),
    };
    c.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(20), c.read(&mut buf))
        .await
        .expect("gateway answer timed out")
        .unwrap();
    Some((c, String::from_utf8_lossy(&buf[..n]).to_string()))
}

fn route_down_events(state: &AppState) -> usize {
    state
        .stats()
        .snapshot_sync()
        .recent_events
        .iter()
        .filter(|e| e.action == "ROUTE_DOWN")
        .count()
}

#[tokio::test]
async fn test_bound_route_on_closed_port_is_fail_closed() {
    let state = AppState::new_in_memory();
    let route = socks_route("dead", closed_port().await);
    state.upsert_route(route).await.unwrap();
    state
        .bind_provider_route("anthropic", Some("dead"))
        .await
        .unwrap();

    let (sink, sink_hits) = direct_sink().await;
    let server = start(state.clone(), Some(sink)).await;

    // a) Session allowed (audit skipped): the tunnel through the route fails -> 502, not direct.
    state.allow_provider_for_session("anthropic").await.unwrap();
    let Some((_c, resp)) = connect(&server, "api.anthropic.com").await else {
        return;
    };
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    assert!(resp.contains("fail-closed"), "{resp}");

    // b) No allowance: the audit through the dead route fails -> refused as well.
    state
        .revoke_session_allowed_provider("anthropic")
        .await
        .unwrap();
    let (_c, resp) = connect(&server, "claude.ai").await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");

    assert_eq!(
        server.direct_connect_count(),
        0,
        "no direct connection may be attempted"
    );
    assert_eq!(sink_hits.load(Ordering::SeqCst), 0);
    assert_eq!(route_down_events(&state), 2);
    assert_eq!(state.stats().snapshot_sync().direct_bypassed_requests, 0);
    assert_eq!(
        state.route_health().get("dead").and_then(|h| h.reachable),
        Some(false)
    );
}

#[tokio::test]
async fn test_expired_disabled_and_missing_routes_are_refused() {
    let state = AppState::new_in_memory();
    let live = spawn_socks_echo().await;

    let mut expired = socks_route("expired", live);
    expired.expires_at = Some(1);
    let mut disabled = socks_route("disabled", live);
    disabled.enabled = false;
    state.upsert_route(expired).await.unwrap();
    state.upsert_route(disabled).await.unwrap();
    state
        .bind_provider_route("anthropic", Some("expired"))
        .await
        .unwrap();
    state
        .bind_provider_route("openai", Some("disabled"))
        .await
        .unwrap();
    for p in ["anthropic", "openai"] {
        state.allow_provider_for_session(p).await.unwrap();
    }

    let (sink, sink_hits) = direct_sink().await;
    let server = start(state.clone(), Some(sink)).await;

    let Some((_c, resp)) = connect(&server, "api.anthropic.com").await else {
        return;
    };
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("expired"), "{resp}");

    let (_c, resp) = connect(&server, "api.openai.com").await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("disabled"), "{resp}");

    assert_eq!(server.direct_connect_count(), 0);
    assert_eq!(sink_hits.load(Ordering::SeqCst), 0);
    assert_eq!(route_down_events(&state), 2);
}

#[tokio::test]
async fn test_routed_provider_ignores_auto_freeze_but_obeys_manual_killswitch() {
    let state = AppState::new_in_memory();
    let socks = spawn_socks_echo().await;
    state
        .upsert_route(socks_route("live", socks))
        .await
        .unwrap();
    state
        .bind_provider_route("anthropic", Some("live"))
        .await
        .unwrap();
    state.allow_provider_for_session("anthropic").await.unwrap();
    state.allow_provider_for_session("gemini").await.unwrap();

    let (sink, sink_hits) = direct_sink().await;
    let server = start(state.clone(), Some(sink)).await;

    // Established routed tunnel.
    let Some((mut tunnel, resp)) = connect(&server, "api.anthropic.com").await else {
        return;
    };
    assert!(resp.contains("200 Connection Established"), "{resp}");

    // Automatic freeze (VPN drop / network change): gate closes, unrouted tunnels are aborted.
    server.guard.freeze_for_test().await;
    server.guard.abort_active_tunnels();
    assert_eq!(server.guard.gate(), Gate::Blocked);
    assert!(!server.guard.is_manual_killswitch());

    // The routed tunnel keeps working ...
    tunnel.write_all(b"still-alive").await.unwrap();
    let mut echo = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(3), tunnel.read_exact(&mut echo))
        .await
        .expect("routed tunnel must not be frozen")
        .unwrap();
    assert_eq!(&echo, b"still-alive");

    // ... new routed connections pass ...
    let (_c2, resp) = connect(&server, "claude.ai").await.unwrap();
    assert!(resp.contains("200 Connection Established"), "{resp}");

    // ... while the unrouted provider is held by the guard (and nothing goes direct).
    let (_c3, resp) = connect(&server, "gemini.google.com").await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert_eq!(sink_hits.load(Ordering::SeqCst), 0);

    // Manual kill-switch stops everything, routed traffic included.
    server.guard.set_manual_killswitch(true, &state).await;
    let mut buf = [0u8; 16];
    let res = tokio::time::timeout(Duration::from_secs(3), tunnel.read(&mut buf))
        .await
        .expect("routed tunnel must be torn down by the kill-switch");
    assert!(matches!(res, Ok(0) | Err(_)), "tunnel still open: {res:?}");

    let (_c4, resp) = connect(&server, "api.anthropic.com").await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("kill-switch"), "{resp}");

    // Lifting it restores routed traffic.
    server.guard.set_manual_killswitch(false, &state).await;
    state.allow_provider_for_session("anthropic").await.unwrap();
    let (_c5, resp) = connect(&server, "api.anthropic.com").await.unwrap();
    assert!(resp.contains("200 Connection Established"), "{resp}");
}

#[tokio::test]
async fn test_default_route_carries_unbound_providers() {
    let state = AppState::new_in_memory();
    let socks = spawn_socks_echo().await;
    state.upsert_route(socks_route("def", socks)).await.unwrap();
    state.set_default_route(Some("def")).await.unwrap();
    state.allow_provider_for_session("openai").await.unwrap();

    let (sink, sink_hits) = direct_sink().await;
    let server = start(state.clone(), Some(sink)).await;
    let Some((mut c, resp)) = connect(&server, "api.openai.com").await else {
        return;
    };
    assert!(resp.contains("200 Connection Established"), "{resp}");
    c.write_all(b"via-default").await.unwrap();
    let mut echo = [0u8; 11];
    c.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"via-default");
    assert_eq!(sink_hits.load(Ordering::SeqCst), 0);
    assert_eq!(server.direct_connect_count(), 0);
}

fn public_socks_route(id: &str, host: &str, port: u16) -> Route {
    Route {
        id: id.to_string(),
        label: format!("public {id}"),
        country: Some("NL".to_string()),
        exit_ip: None,
        expires_at: None,
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

/// Local HTTP CONNECT proxy stub that redirects `CONNECT <expected_target>` to `bridge_port`.
async fn spawn_chained_http_bridge(expected_target: String, bridge_port: u16) -> (u16, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU64::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = l.accept().await {
            let expected = expected_target.clone();
            let h = Arc::clone(&h);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let req = String::from_utf8_lossy(&head);
                let first = req.lines().next().unwrap_or("");
                assert!(
                    first.starts_with(&format!("CONNECT {expected} ")),
                    "unexpected chained CONNECT target: {first}"
                );
                h.fetch_add(1, Ordering::SeqCst);
                let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", bridge_port)).await else {
                    let _ = client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        .await;
                    return;
                };
                let _ = client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    (port, hits)
}

async fn start_with_chained(
    state: AppState,
    redirect: Option<std::net::SocketAddr>,
    chained: Option<String>,
) -> Arc<ProxyServer> {
    let auditor = Auditor::new().unwrap();
    let transit = Transit::system().with_chained(Arc::new(move || chained.clone()));
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state, Arc::new(HoldQueue::new()), redirect)
            .await
            .unwrap()
            .with_transit(transit),
    );
    let s = Arc::clone(&server);
    tokio::spawn(async move { s.run().await });
    server
}

#[tokio::test]
async fn test_public_route_falls_back_via_chained_proxy_when_direct_fails() {
    let state = AppState::new_in_memory();
    let socks_echo_port = spawn_socks_echo().await;
    // Public entry IP (unreachable directly) on an unused high port; chained proxy bridges to echo.
    let entry_host = "93.184.216.34";
    let entry_port = 19999;
    state
        .upsert_route(public_socks_route("pub", entry_host, entry_port))
        .await
        .unwrap();
    state
        .bind_provider_route("anthropic", Some("pub"))
        .await
        .unwrap();
    state.allow_provider_for_session("anthropic").await.unwrap();

    let (cp_port, cp_hits) =
        spawn_chained_http_bridge(format!("{entry_host}:{entry_port}"), socks_echo_port).await;
    let (sink, sink_hits) = direct_sink().await;
    let server = start_with_chained(
        state.clone(),
        Some(sink),
        Some(format!("127.0.0.1:{cp_port}")),
    )
    .await;

    let Some((mut c, resp)) = connect(&server, "api.anthropic.com").await else {
        return;
    };
    assert!(resp.contains("200 Connection Established"), "{resp}");
    c.write_all(b"via-chained").await.unwrap();
    let mut echo = [0u8; 11];
    c.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"via-chained");
    assert_eq!(cp_hits.load(Ordering::SeqCst), 1);
    assert_eq!(sink_hits.load(Ordering::SeqCst), 0);
    assert_eq!(server.direct_connect_count(), 0);
}

#[tokio::test]
async fn test_both_direct_and_chained_unreachable_is_fail_closed_with_diagnostics() {
    let state = AppState::new_in_memory();
    let dead_cp_port = closed_port().await;
    state
        .upsert_route(public_socks_route("pub-dead", "93.184.216.34", 19998))
        .await
        .unwrap();
    state
        .bind_provider_route("anthropic", Some("pub-dead"))
        .await
        .unwrap();
    state.allow_provider_for_session("anthropic").await.unwrap();

    let (sink, sink_hits) = direct_sink().await;
    let server = start_with_chained(
        state.clone(),
        Some(sink),
        Some(format!("127.0.0.1:{dead_cp_port}")),
    )
    .await;

    let Some((_c, resp)) = connect(&server, "api.anthropic.com").await else {
        return;
    };
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    assert!(resp.contains("fail-closed"), "{resp}");
    assert_eq!(sink_hits.load(Ordering::SeqCst), 0);
    assert_eq!(server.direct_connect_count(), 0);
    assert_eq!(route_down_events(&state), 1);

    let diag = zastava_lib::diagnostics::dump();
    assert!(
        diag.iter()
            .any(|line| line.contains("[proxy:route]") && line.contains("pub-dead")),
        "expected [proxy:route] diagnostic entry, got: {diag:?}"
    );
}

#[tokio::test]
async fn test_happy_eyeballs_connects_when_first_ip_is_dead() {
    let state = AppState::new_in_memory();
    let socks_port = spawn_socks_echo().await;
    // `localhost` resolves to both ::1 and 127.0.0.1 on dual-stack hosts; our echo listener
    // binds 127.0.0.1 only, so ::1 (ordered first per RFC 8305) fails and Happy Eyeballs
    // connects to 127.0.0.1 without stalling.
    let mut route = socks_route("he", socks_port);
    route.entries[0].host = "localhost".to_string();
    route.raw_key = format!("socks5://localhost:{socks_port}");
    state.upsert_route(route).await.unwrap();
    state
        .bind_provider_route("anthropic", Some("he"))
        .await
        .unwrap();
    state.allow_provider_for_session("anthropic").await.unwrap();

    let (sink, sink_hits) = direct_sink().await;
    let server = start(state.clone(), Some(sink)).await;

    let started = std::time::Instant::now();
    let Some((mut c, resp)) = connect(&server, "api.anthropic.com").await else {
        return;
    };
    assert!(resp.contains("200 Connection Established"), "{resp}");
    assert!(started.elapsed() < Duration::from_secs(3));
    c.write_all(b"he-ok").await.unwrap();
    let mut echo = [0u8; 5];
    c.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"he-ok");
    assert_eq!(sink_hits.load(Ordering::SeqCst), 0);
    assert_eq!(server.direct_connect_count(), 0);
}
