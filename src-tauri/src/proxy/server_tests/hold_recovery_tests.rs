use super::super::*;
use super::coverage_and_holds_tests::offline_test_auditor;
use crate::proxy::hold_queue::HoldQueue;
use crate::state::AppState;

#[tokio::test]
async fn concurrent_critical_connects_coalesce_hold_and_resolve_together() {
    crate::sysproxy::force_os_dry_run();
    let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(_) => return,
    };
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        while let Ok((mut s, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await
                    && n > 0
                {
                    let _ = s.write_all(&buf[..n]).await;
                }
            });
        }
    });

    let auditor = offline_test_auditor();
    let ru_tel = crate::auditor::NetworkTelemetry {
        ip: "5.5.5.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(9009),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: crate::auditor::network::current_timestamp(),
    };
    auditor.resolver.set_cached(ru_tel).await;

    let state = AppState::new_in_memory();
    let hq = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::clone(&hq), Some(echo_addr))
            .await
            .expect("bind"),
    );
    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    let srv_task = tokio::spawn(async move { srv.run().await });

    let mut c1 = match TcpStream::connect(addr).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut c2 = TcpStream::connect(addr).await.unwrap();
    let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    c1.write_all(req.as_bytes()).await.unwrap();
    c2.write_all(req.as_bytes()).await.unwrap();

    let mut alert_id = None;
    for _ in 0..200 {
        if let Some(alert) = hq.current_alert() {
            alert_id = Some(alert.id);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let alert_id = alert_id.expect("single coalesced alert created");
    // Give the second CONNECT a moment to coalesce into the same hold entry.
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(hq.active_entry_count().await, 1);

    // Resolving the single hold ID unblocks BOTH parallel CONNECTs.
    assert!(hq.resolve(&alert_id, HoldResolution::Allow).await);

    let mut b1 = [0u8; 128];
    let mut b2 = [0u8; 128];
    let n1 = tokio::time::timeout(Duration::from_secs(2), c1.read(&mut b1))
        .await
        .unwrap()
        .unwrap();
    let n2 = tokio::time::timeout(Duration::from_secs(2), c2.read(&mut b2))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&b1[..n1]).starts_with("HTTP/1.1 200"));
    assert!(String::from_utf8_lossy(&b2[..n2]).starts_with("HTTP/1.1 200"));

    srv_task.abort();
    echo_task.abort();
}

#[tokio::test]
async fn critical_hold_timeout_blocks_provider_and_closes_gate() {
    crate::sysproxy::force_os_dry_run();
    let auditor = offline_test_auditor();
    let ru_tel = crate::auditor::NetworkTelemetry {
        ip: "5.5.5.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(9009),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: crate::auditor::network::current_timestamp(),
    };
    auditor.resolver.set_cached(ru_tel).await;

    let state = AppState::new_in_memory();
    let hq = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::clone(&hq), None)
            .await
            .expect("bind")
            .with_hold_ttl(Duration::from_millis(80)),
    );
    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    let srv_task = tokio::spawn(async move { srv.run().await });

    let mut client = match TcpStream::connect(addr).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    client.write_all(req.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), client.read_to_end(&mut buf))
        .await
        .expect("client gets 403 after hold timeout")
        .unwrap();
    let resp = String::from_utf8_lossy(&buf);
    assert!(resp.contains("HTTP/1.1 403 Forbidden"), "{resp}");
    assert!(state.is_provider_blocked("anthropic").await);
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert!(hq.current_alert().is_none());

    srv_task.abort();
}

#[tokio::test]
async fn active_per_provider_hold_from_vpn_jump_cannot_reblock_after_restore_to_pinned_ip() {
    crate::sysproxy::force_os_dry_run();
    let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(_) => return,
    };
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        while let Ok((mut s, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await
                    && n > 0
                {
                    let _ = s.write_all(&buf[..n]).await;
                }
            });
        }
    });

    let auditor = offline_test_auditor();
    let ru_tel = crate::auditor::NetworkTelemetry {
        ip: "5.5.5.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(9009),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: crate::auditor::network::current_timestamp(),
    };
    auditor.resolver.set_cached(ru_tel).await;

    let state = AppState::new_in_memory();
    state
        .set_pinned_ip(Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    state.set_strict_pinning_enabled(true).await.unwrap();

    let hq = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor.clone(),
            state.clone(),
            Arc::clone(&hq),
            Some(echo_addr),
        )
        .await
        .expect("bind")
        .with_hold_ttl(Duration::from_millis(600)),
    );
    server
        .guard
        .install_noop_env_for_test(auditor.clone(), state.clone(), Arc::clone(&hq));
    let epoch_before = server.guard.restore_epoch();

    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    let srv_task = tokio::spawn(async move { srv.run().await });

    let mut client = match TcpStream::connect(addr).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    client.write_all(req.as_bytes()).await.unwrap();

    // Wait for the per-provider hold to be registered in HoldQueue.
    let mut hold_seen = false;
    for _ in 0..400 {
        if hq.current_alert().is_some() && hq.active_entry_count().await == 1 {
            hold_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(hold_seen, "expected active per-provider hold in HoldQueue");

    // Now simulate returning to the clean pinned IP (`restore_locked`): bumps `restore_epoch`
    // and calls `cancel_all_superseded()` before the hold timer expires.
    server.guard.restore_for_test().await;
    assert_eq!(server.guard.restore_epoch(), epoch_before + 1);
    assert_eq!(hq.active_entry_count().await, 0);
    assert!(hq.current_alert().is_none());

    let mut head = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut head))
        .await
        .expect("superseded hold must unblock immediately without waiting for TTL")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"),
        "expected 200 Connection Established after restore, got: {}",
        String::from_utf8_lossy(&head[..n])
    );

    // Wait well past the original hold TTL to prove no orphaned timeout relapses into block.
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert!(!state.is_provider_blocked("anthropic").await);
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert!(
        state
            .get_data()
            .await
            .ip_history
            .values()
            .all(Vec::is_empty),
        "superseded hold must NOT record stale pre-restore IP into ip_history"
    );

    srv_task.abort();
    echo_task.abort();
}

#[tokio::test]
async fn hold_timeout_with_changed_restore_epoch_or_trusted_exception_never_blocks() {
    crate::sysproxy::force_os_dry_run();
    let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(_) => return,
    };
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        while let Ok((mut s, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let _ = s.read(&mut buf).await;
            });
        }
    });

    // Case 1: `restore_epoch` bumped directly before `Err(_)` fires -> must NOT block.
    let auditor = offline_test_auditor();
    let ru_tel = crate::auditor::NetworkTelemetry {
        ip: "5.5.5.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(9009),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: crate::auditor::network::current_timestamp(),
    };
    auditor.resolver.set_cached(ru_tel.clone()).await;

    let state = AppState::new_in_memory();
    let hq = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::clone(&hq), Some(echo_addr))
            .await
            .expect("bind")
            .with_hold_ttl(Duration::from_millis(120)),
    );
    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    let srv_task = tokio::spawn(async move { srv.run().await });

    let mut c1 = match TcpStream::connect(addr).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    c1.write_all(req.as_bytes()).await.unwrap();

    let mut seen1 = false;
    for _ in 0..400 {
        if hq.current_alert().is_some() {
            seen1 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(seen1, "expected active hold before timeout");
    // Bump restore_epoch without draining `hq` to directly exercise the `Err(_)` epoch guard.
    server.guard.bump_restore_epoch_for_test();

    let mut head = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(2), c1.read(&mut head))
        .await
        .expect("timeout handler finishes")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"),
        "unexpected response: {}",
        String::from_utf8_lossy(&head[..n])
    );
    assert!(!state.is_provider_blocked("anthropic").await);
    assert_eq!(server.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    srv_task.abort();

    // Case 2: `(provider, exit_ip)` becomes trusted before timeout expires -> must NOT block.
    let auditor2 = offline_test_auditor();
    auditor2.resolver.set_cached(ru_tel).await;
    let state2 = AppState::new_in_memory();
    let hq2 = Arc::new(HoldQueue::new());
    let server2 = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor2,
            state2.clone(),
            Arc::clone(&hq2),
            Some(echo_addr),
        )
        .await
        .expect("bind")
        .with_hold_ttl(Duration::from_millis(120)),
    );
    let addr2 = server2.bound_addr;
    let srv2 = Arc::clone(&server2);
    let srv_task2 = tokio::spawn(async move { srv2.run().await });

    let mut c2 = TcpStream::connect(addr2).await.unwrap();
    c2.write_all(req.as_bytes()).await.unwrap();
    let mut seen2 = false;
    for _ in 0..400 {
        if hq2.current_alert().is_some() {
            seen2 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(seen2, "expected active hold2 before timeout");
    state2
        .add_trusted_exception("anthropic", "5.5.5.5")
        .await
        .unwrap();

    let mut head2 = [0u8; 128];
    let n2 = tokio::time::timeout(Duration::from_secs(2), c2.read(&mut head2))
        .await
        .expect("timeout handler finishes")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&head2[..n2]).starts_with("HTTP/1.1 200"),
        "unexpected response: {}",
        String::from_utf8_lossy(&head2[..n2])
    );
    assert!(!state2.is_provider_blocked("anthropic").await);
    assert_eq!(server2.guard.gate_for(ProviderId::Anthropic), Gate::Open);

    srv_task2.abort();
    echo_task.abort();
}

#[tokio::test]
async fn manual_killswitch_blocks_even_disabled_provider_on_superseded_hold() {
    crate::sysproxy::force_os_dry_run();
    let echo_listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(_) => return,
    };
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        while let Ok((mut s, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let _ = s.read(&mut buf).await;
            });
        }
    });

    let auditor = offline_test_auditor();
    let ru_tel = crate::auditor::NetworkTelemetry {
        ip: "5.5.5.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(9009),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: crate::auditor::network::current_timestamp(),
    };
    auditor.resolver.set_cached(ru_tel).await;

    let state = AppState::new_in_memory();
    let hq = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::clone(&hq), Some(echo_addr))
            .await
            .expect("bind")
            .with_hold_ttl(Duration::from_secs(5)),
    );
    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    let srv_task = tokio::spawn(async move { srv.run().await });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    client.write_all(req.as_bytes()).await.unwrap();

    let mut hold_seen = false;
    for _ in 0..400 {
        if hq.current_alert().is_some() {
            hold_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(hold_seen, "expected active hold");

    // Disable monitoring AND engage manual kill-switch, then supersede the hold.
    state.set_provider_monitoring("anthropic", false).await.unwrap();
    server.guard.set_manual_killswitch(true, &state).await;
    hq.cancel_all_superseded().await;

    let mut head = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut head))
        .await
        .expect("superseded hold completes")
        .unwrap();
    let resp = String::from_utf8_lossy(&head[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "manual killswitch must block even disabled provider, got: {resp}"
    );
    srv_task.abort();
    echo_task.abort();
}
