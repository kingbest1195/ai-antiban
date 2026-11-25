use super::super::*;
use super::transit_helpers_tests::*;

/// Streams `pieces` x 64 KiB with a pause between the pieces, then closes.
async fn spawn_slow_download(pieces: usize) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind download");
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let piece = vec![7u8; 64 * 1024];
                for _ in 0..pieces {
                    if c.write_all(&piece).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(80)).await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn running_transit_stream_survives_a_gate_freeze_and_new_ones_are_not_held() {
    // Transit never looks at the guard: neither the freeze nor the abort of unrouted tunnels
    // (what a network re-check does together with `Gate::Pending`) may touch it. `Pending`
    // itself can only be set from inside `guard`; `freeze_for_test` closes the gate harder
    // (`Blocked`) and aborts the tunnels, which is a superset of what Pending does.
    let download = spawn_slow_download(6).await;
    let echo = spawn_echo().await;
    let dl_env = start(download, &[PUBLIC_V4], None).await;
    let (mut dl, head) = open_tunnel(dl_env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    // Body bytes that came with the header are part of the download too (see `open_tunnel`).
    let mut got = head.find("\r\n\r\n").map_or(0, |i| head.len() - (i + 4));
    let mut buf = vec![0u8; 64 * 1024];
    // First piece arrives before the freeze.
    got += dl.read(&mut buf).await.unwrap();
    assert!(got > 0);

    dl_env.server.guard.freeze_for_test().await;
    dl_env.server.guard.abort_active_tunnels();
    assert_eq!(dl_env.server.guard.gate(), Gate::Blocked);

    // The download keeps flowing to the end and then closes cleanly (EOF, not a reset).
    loop {
        match tokio::time::timeout(Duration::from_secs(5), dl.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => got += n,
            Ok(Err(e)) => panic!("download was reset after the freeze: {e}"),
            Err(_) => panic!("download stalled after the freeze"),
        }
    }
    assert_eq!(got, 6 * 64 * 1024, "every byte arrived");

    // A new transit connection while the gate is closed goes through at once.
    let env = start(echo, &[PUBLIC_V4], None).await;
    env.server.guard.freeze_for_test().await;
    let started = std::time::Instant::now();
    let (mut c, head) = open_tunnel(env.addr(), "github.com:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping(&mut c, b"new stream during freeze").await;
    assert!(started.elapsed() < Duration::from_secs(2));

    // Plain HTTP is not held either.
    let (origin, _seen) = spawn_http_server("fine").await;
    let env2 = start(origin, &[PUBLIC_V4], None).await;
    env2.server.guard.freeze_for_test().await;
    let resp = exchange(
        env2.addr(),
        b"GET http://files.example.test/ HTTP/1.1\r\n\r\n",
    )
    .await;
    assert!(resp.ends_with("fine"), "{resp}");
}

#[tokio::test]
async fn idle_transit_stream_is_not_cut_by_an_abort_and_keeps_working() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V4], None).await;
    let (mut c, head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping(&mut c, b"before").await;
    env.server.guard.freeze_for_test().await;
    env.server.guard.abort_active_tunnels();
    tokio::time::sleep(Duration::from_millis(200)).await;
    ping(&mut c, b"after").await;
}

#[tokio::test]
async fn ai_connection_is_still_refused_while_the_gate_is_closed() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V4], None).await;
    env.server.guard.freeze_for_test().await;
    let (_c, head) = open_tunnel(env.addr(), "api.anthropic.com:443").await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert!(head.contains("Network change blocked"), "{head}");
    assert_eq!(
        env.dial_count(),
        0,
        "an AI host is never dialed behind a closed gate"
    );
}

async fn engage_killswitch(env: &Env, on: bool) {
    env.server
        .guard
        .set_manual_killswitch(on, &env.server.state)
        .await;
}

#[tokio::test]
async fn manual_killswitch_allows_non_ai_transit_while_blocking_ai_and_payment_hosts() {
    let echo = spawn_echo().await;
    let (origin, _seen) = spawn_http_server("fine").await;
    let env = start(echo, &[PUBLIC_V4], None).await;
    engage_killswitch(&env, true).await;

    // Non-AI transit CONNECT (Discord/PUBG/GitHub) passes cleanly even under manual_killswitch.
    let (mut c, head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping(&mut c, b"transit during manual killswitch").await;

    // Non-AI plain HTTP passes cleanly without 503.
    let env_http = start(origin, &[PUBLIC_V4], None).await;
    engage_killswitch(&env_http, true).await;
    let resp = exchange(
        env_http.addr(),
        b"GET http://files.example.test/ HTTP/1.1\r\n\r\n",
    )
    .await;
    assert!(resp.ends_with("fine"), "{resp}");

    // AI and payment/KYC hosts stay strictly blocked under manual_killswitch.
    let (_c_ai, ai_head) = open_tunnel(env.addr(), "api.anthropic.com:443").await;
    assert!(ai_head.starts_with("HTTP/1.1 403"), "{ai_head}");
    let (_c_pay, pay_head) = open_tunnel(env.addr(), "checkout.stripe.com:443").await;
    assert!(pay_head.starts_with("HTTP/1.1 403"), "{pay_head}");
    let pay_http = exchange(
        env.addr(),
        b"GET http://checkout.stripe.com/ HTTP/1.1\r\n\r\n",
    )
    .await;
    assert!(pay_http.starts_with("HTTP/1.1 503"), "{pay_http}");
    assert!(pay_http.contains("Сеть остановлена вручную"), "{pay_http}");

    engage_killswitch(&env, false).await;
    let (_c_pay2, pay_head2) = open_tunnel(env.addr(), "api.stripe.com:443").await;
    assert!(pay_head2.starts_with("HTTP/1.1 200"), "{pay_head2}");
}

#[tokio::test]
async fn manual_killswitch_keeps_non_ai_transit_running_and_cuts_payment_streams() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V4], None).await;
    let (mut transit_c, transit_head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(transit_head.starts_with("HTTP/1.1 200"), "{transit_head}");
    ping(&mut transit_c, b"alive-transit").await;

    let (mut pay_c, pay_head) = open_tunnel(env.addr(), "api.stripe.com:443").await;
    assert!(pay_head.starts_with("HTTP/1.1 200"), "{pay_head}");
    ping(&mut pay_c, b"alive-pay").await;

    engage_killswitch(&env, true).await;

    // Non-AI transit stream keeps working cleanly.
    ping(&mut transit_c, b"still-alive-transit").await;

    // Payment/KYC stream is cut immediately.
    let mut buf = [0u8; 16];
    match tokio::time::timeout(Duration::from_secs(3), pay_c.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("payment tunnel must be cut by the kill-switch: {other:?}"),
    }

    // Plain HTTP slow download on non-AI host survives manual_killswitch.
    let download = spawn_slow_download(4).await;
    let env_dl = start(download, &[PUBLIC_V4], None).await;
    let mut c = TcpStream::connect(env_dl.addr()).await.unwrap();
    c.write_all(b"GET http://files.example.test/big HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut got = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    got += c.read(&mut buf).await.unwrap();
    assert!(got > 0);
    engage_killswitch(&env_dl, true).await;
    let end = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match c.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
    })
    .await;
    assert!(end.is_ok(), "non-AI plain HTTP stream should finish");
    assert!(
        got >= 4 * 64 * 1024,
        "non-AI plain HTTP download was unexpectedly cut ({got} bytes)"
    );
}

#[tokio::test]
async fn automatic_freeze_does_not_cut_transit_or_payment_but_manual_switch_cuts_payment() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V4], None).await;
    let (mut transit_c, _) = open_tunnel(env.addr(), "ghcr.io:443").await;
    let (mut pay_c, _) = open_tunnel(env.addr(), "api.stripe.com:443").await;
    ping(&mut transit_c, b"one").await;
    ping(&mut pay_c, b"pay-one").await;

    env.server.guard.freeze_for_test().await;
    ping(&mut transit_c, b"two").await;
    ping(&mut pay_c, b"pay-two").await;
    assert!(!env.server.guard.is_manual_killswitch());

    engage_killswitch(&env, true).await;
    ping(&mut transit_c, b"three").await;
    let mut buf = [0u8; 4];
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), pay_c.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
}

#[tokio::test]
async fn pending_gate_keeps_direct_streams_and_new_transit_but_holds_ai_hosts() {
    let download = spawn_slow_download(6).await;
    let env = start(download, &[PUBLIC_V4], None).await;
    let (mut dl, head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let mut buf = vec![0u8; 64 * 1024];
    // `open_tunnel` reads the answer in small chunks and may already hold the first body bytes
    // that followed the header; they belong to the download too.
    let body_in_head = head.find("\r\n\r\n").map_or(0, |i| head.len() - (i + 4));
    let mut got = body_in_head + dl.read(&mut buf).await.unwrap();

    env.server.guard.set_gate_for_test(Gate::Pending);
    env.server.guard.abort_active_tunnels();
    assert_eq!(env.server.guard.gate(), Gate::Pending);

    // A new transit CONNECT is not made to wait.
    let echo = spawn_echo().await;
    let env2 = start(echo, &[PUBLIC_V4], None).await;
    env2.server.guard.set_gate_for_test(Gate::Pending);
    let started = std::time::Instant::now();
    let (mut c, head) = open_tunnel(env2.addr(), "github.com:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping(&mut c, b"during pending").await;
    assert!(started.elapsed() < Duration::from_secs(2));

    // An AI host waits for the user's decision: no answer, nothing dialed.
    let mut ai = TcpStream::connect(env2.addr()).await.unwrap();
    ai.write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut b = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(600), ai.read(&mut b))
            .await
            .is_err(),
        "an AI connection must wait while the gate is pending"
    );
    assert_eq!(
        env2.dial_count(),
        1,
        "only the transit connection was dialed"
    );

    // The running download went on to the end.
    loop {
        match tokio::time::timeout(Duration::from_secs(5), dl.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => got += n,
            Ok(Err(e)) => panic!("download reset during Pending: {e}"),
            Err(_) => panic!("download stalled during Pending"),
        }
    }
    assert_eq!(got, 6 * 64 * 1024);
}

#[tokio::test]
async fn abort_all_tunnels_on_shutdown_cuts_transit_and_routed_tunnels() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V4], None).await;

    // 1. Open a transit tunnel and verify it works.
    let (mut transit_stream, _) = open_tunnel(env.addr(), "ghcr.io:443").await;
    ping(&mut transit_stream, b"transit-ok").await;

    // 2. Open a routed (KillSwitchOnly) tunnel through `tunnel::pump`.
    let client_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_l.local_addr().unwrap();
    let target_addr = target_l.local_addr().unwrap();
    let guard = Arc::clone(&env.server.guard);
    tokio::spawn(async move {
        let (mut srv_client, _) = client_l.accept().await.unwrap();
        let srv_target = TcpStream::connect(target_addr).await.unwrap();
        let mut upstream = crate::proxy::upstream::UpstreamStream::Plain(srv_target);
        let _ = super::super::tunnel::pump(
            &mut srv_client,
            &mut upstream,
            &guard,
            TunnelPolicy::KillSwitchOnly,
            None,
            None,
        )
        .await;
    });
    tokio::spawn(async move {
        let (mut t, _) = target_l.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        while let Ok(n) = t.read(&mut buf).await {
            if n == 0 || t.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    let mut routed_stream = TcpStream::connect(client_addr).await.unwrap();
    ping(&mut routed_stream, b"routed-ok").await;

    // Normal `abort_active_tunnels()` must NOT cut transit or KillSwitchOnly tunnels.
    env.server.guard.abort_active_tunnels();
    tokio::time::sleep(Duration::from_millis(50)).await;
    ping(&mut transit_stream, b"still-live").await;
    ping(&mut routed_stream, b"still-routed").await;

    // Shutdown abort must close BOTH transit_tunnel and routed KillSwitchOnly tunnels.
    env.server.guard.abort_all_tunnels_on_shutdown();

    let mut buf = [0u8; 8];
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), transit_stream.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), routed_stream.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
}

#[tokio::test]
async fn ai_and_payment_connect_fail_closed_when_chained_proxy_is_dead() {
    let echo = spawn_echo().await;
    let dead = dead_addr().await;
    let env = start(echo, &[PUBLIC_V4], Some(dead)).await;

    // 1. Direct call to connect_ai_transit must fail closed with 0 direct connects.
    let err = env
        .server
        .connect_ai_transit("api.anthropic.com", 443)
        .await
        .err()
        .expect("connect_ai_transit must fail closed when chained proxy is unreachable");
    assert!(
        err.to_string().contains("fail-closed"),
        "unexpected error: {err}"
    );
    assert_eq!(env.dial_count(), 0);
    assert_eq!(env.server.direct_connect_count(), 0);

    // 2. Payment/KYC CONNECT over gateway must fail closed (502) with 0 direct connects.
    let (_pay_c, pay_head) = open_tunnel(env.addr(), "api.stripe.com:443").await;
    assert!(pay_head.starts_with("HTTP/1.1 502"), "{pay_head}");
    assert_eq!(env.dial_count(), 0);

    // 3. Unrouted AI CONNECT over gateway must also fail closed (502) with 0 direct connects.
    // Seed cached telemetry so auditor passes and tunnel_to_target reaches connect_ai_transit.
    env.server
        .auditor
        .resolver
        .set_cached(crate::auditor::NetworkTelemetry {
            ip: "185.100.10.2".to_string(),
            country_code: "NL".to_string(),
            hostname: Some("nl-vps.example.net".to_string()),
            asn: Some(20473),
            org: Some("Choopa".to_string()),
            isp: Some("Choopa".to_string()),
            timezone: Some("Europe/Amsterdam".to_string()),
            resolved_at: crate::auditor::network::current_timestamp(),
        })
        .await;
    let (_ai_c, ai_head) = open_tunnel(env.addr(), "api.anthropic.com:443").await;
    assert!(
        ai_head.starts_with("HTTP/1.1 502"),
        "AI CONNECT must fail closed (502) when chained proxy is dead, got: {ai_head}"
    );
    assert_eq!(env.dial_count(), 0);

    // 4. Non-AI transit CONNECT still falls back to direct once.
    let (mut non_ai_c, non_ai_head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(non_ai_head.starts_with("HTTP/1.1 200"), "{non_ai_head}");
    ping(&mut non_ai_c, b"transit fallback ok").await;
    assert_eq!(env.dial_count(), 1);
}
