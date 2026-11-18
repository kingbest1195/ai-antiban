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
async fn manual_killswitch_refuses_new_transit_until_it_is_released() {
    let echo = spawn_echo().await;
    let (origin, _seen) = spawn_http_server("fine").await;
    let env = start(echo, &[PUBLIC_V4], None).await;
    engage_killswitch(&env, true).await;

    let (_c, head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert!(head.contains("Сеть остановлена вручную"), "{head}");
    let resp = exchange(
        env.addr(),
        b"GET http://files.example.test/ HTTP/1.1\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 503"), "{resp}");
    assert!(resp.contains("Сеть остановлена вручную"), "{resp}");
    assert_eq!(env.dial_count(), 0);

    engage_killswitch(&env, false).await;
    let (mut c, head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping(&mut c, b"after release").await;

    let env2 = start(origin, &[PUBLIC_V4], None).await;
    engage_killswitch(&env2, true).await;
    engage_killswitch(&env2, false).await;
    let resp = exchange(
        env2.addr(),
        b"GET http://files.example.test/ HTTP/1.1\r\n\r\n",
    )
    .await;
    assert!(resp.ends_with("fine"), "{resp}");
}

#[tokio::test]
async fn manual_killswitch_cuts_running_transit_streams() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V4], None).await;
    let (mut c, head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping(&mut c, b"alive").await;
    engage_killswitch(&env, true).await;
    let mut buf = [0u8; 16];
    match tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("the tunnel must be cut by the kill-switch: {other:?}"),
    }
    // Releasing the switch does not bring the closed tunnel back.
    engage_killswitch(&env, false).await;
    assert!(c.write_all(b"x").await.is_err() || matches!(c.read(&mut buf).await, Ok(0) | Err(_)));

    // Plain HTTP stream (slow download) is cut as well.
    let download = spawn_slow_download(20).await;
    let env = start(download, &[PUBLIC_V4], None).await;
    let mut c = TcpStream::connect(env.addr()).await.unwrap();
    c.write_all(b"GET http://files.example.test/big HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut got = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    got += c.read(&mut buf).await.unwrap();
    assert!(got > 0);
    engage_killswitch(&env, true).await;
    let end = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match c.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
    })
    .await;
    assert!(end.is_ok(), "plain HTTP stream must be cut");
    assert!(
        got < 20 * 64 * 1024,
        "the download was interrupted ({got} bytes)"
    );
}

#[tokio::test]
async fn automatic_freeze_does_not_cut_transit_but_the_manual_switch_does() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V4], None).await;
    let (mut c, _) = open_tunnel(env.addr(), "ghcr.io:443").await;
    ping(&mut c, b"one").await;
    env.server.guard.freeze_for_test().await;
    ping(&mut c, b"two").await;
    assert!(!env.server.guard.is_manual_killswitch());
    engage_killswitch(&env, true).await;
    let mut buf = [0u8; 4];
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf)).await,
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
