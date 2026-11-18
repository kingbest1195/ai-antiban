use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, addr};
use zastava_lib::auditor::seams::{HttpProbeOutcome, LookupOutcome, TxtOutcome};
use zastava_lib::auditor::{OverallStatus, ProviderId};
use zastava_lib::proxy::ProxyServer;
use zastava_lib::proxy::hold_queue::{HoldQueue, HoldResolution};
use zastava_lib::routing::RouteSelection;
use zastava_lib::state::{AppState, InterceptionBehavior};

use crate::helpers::{offline_test_auditor, offline_test_auditor_with};

/// Integration Test 2: Connection Hold and Block
/// Spec: Simulating dangerous IP (e.g. TR for Gemini) sends CONNECT gemini.google.com:443.
/// Proxy pauses connection in HoldQueue. When Block action is resolved,
/// returns HTTP/1.1 403 Forbidden and closes connection.
#[tokio::test]
async fn test_connect_hold_and_block() {
    zastava_lib::sysproxy::force_os_dry_run();
    let auditor = offline_test_auditor();

    // Pre-populate telemetry with Critical blocked location: Russia (RU)
    let dangerous_telemetry = NetworkTelemetry {
        ip: "185.220.101.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(9009),
        org: Some("M247 Europe SRL".to_string()),
        isp: Some("M247 Europe SRL".to_string()),
        timezone: Some("Europe/Moscow".to_string()),
        resolved_at: current_timestamp(),
    };
    auditor.resolver.set_cached(dangerous_telemetry).await;

    let state = AppState::new_in_memory();
    let hold_queue = Arc::new(HoldQueue::new());
    let queue_clone = Arc::clone(&hold_queue);

    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state, hold_queue, None)
            .await
            .expect("Proxy server bind failed"),
    );

    let bound_addr = server.bound_addr;
    let srv_clone = Arc::clone(&server);
    let srv_handle = tokio::spawn(async move {
        srv_clone.run().await;
    });

    // Connect via client and send CONNECT for Gemini (blocked in Turkey)
    let mut client = match TcpStream::connect(bound_addr).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("Skipping test due to sandbox network restrictions: {e}");
            return;
        }
        Err(e) => panic!("Failed to connect to proxy: {e}"),
    };

    let connect_req =
        "CONNECT gemini.google.com:443 HTTP/1.1\r\nHost: gemini.google.com:443\r\n\r\n";
    client
        .write_all(connect_req.as_bytes())
        .await
        .expect("Failed to send CONNECT");
    client.flush().await.expect("Failed to flush CONNECT");

    // In background, simulate user clicking 'BlockUntilNetworkChange'
    tokio::spawn(async move {
        // Wait briefly for connection to be held in queue
        for _ in 0..500 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let resolved = queue_clone
                .resolve_all_for_provider("gemini", HoldResolution::Block)
                .await;
            if resolved > 0 {
                return;
            }
        }
    });

    let mut response = Vec::new();
    let read_res =
        tokio::time::timeout(Duration::from_secs(4), client.read_to_end(&mut response)).await;

    assert!(read_res.is_ok(), "Client read timed out during hold");
    let resp_str = String::from_utf8_lossy(&response);

    // Verify 403 Forbidden is received and connection closed
    assert!(
        resp_str.contains("HTTP/1.1 403 Forbidden"),
        "Expected 403 Forbidden, got: {resp_str}"
    );
    assert!(
        resp_str.contains("Zastava Risk Auditor"),
        "Expected risk auditor reason in body: {resp_str}"
    );

    srv_handle.abort();
}

/// Integration Test 3: Connection Hold and Allow Session
/// Spec: When UserAction::AllowSession is executed, held connection receives
/// HTTP/1.1 200 Connection Established and tunnel is established.
#[tokio::test]
async fn test_connect_hold_and_allow_session() {
    zastava_lib::sysproxy::force_os_dry_run();
    // 1. Setup mock upstream target TCP echo server
    let mock_target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind mock target listener");
    let mock_addr = mock_target.local_addr().unwrap();

    let mock_handle = tokio::spawn(async move {
        if let Ok((mut stream, _)) = mock_target.accept().await {
            let mut buf = [0u8; 128];
            if let Ok(n) = stream.read(&mut buf).await
                && n > 0
            {
                let _ = stream.write_all(&buf[..n]).await;
            }
        }
    });

    let auditor = offline_test_auditor();
    // Telemetry with Critical risk: Russia (RU)
    let dangerous_telemetry = NetworkTelemetry {
        ip: "185.220.101.5".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(9009),
        org: Some("M247 Europe SRL".to_string()),
        isp: Some("M247 Europe SRL".to_string()),
        timezone: Some("Europe/Moscow".to_string()),
        resolved_at: current_timestamp(),
    };
    auditor.resolver.set_cached(dangerous_telemetry).await;

    let state = AppState::new_in_memory();
    let hold_queue = Arc::new(HoldQueue::new());
    let queue_clone = Arc::clone(&hold_queue);

    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state, hold_queue, Some(mock_addr))
            .await
            .expect("Proxy server bind failed"),
    );

    let bound_addr = server.bound_addr;
    let srv_clone = Arc::clone(&server);
    let srv_handle = tokio::spawn(async move {
        srv_clone.run().await;
    });

    let mut client = match TcpStream::connect(bound_addr).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("Skipping test due to sandbox network restrictions: {e}");
            return;
        }
        Err(e) => panic!("Failed to connect to proxy: {e}"),
    };

    let connect_req =
        "CONNECT gemini.google.com:443 HTTP/1.1\r\nHost: gemini.google.com:443\r\n\r\n";
    client
        .write_all(connect_req.as_bytes())
        .await
        .expect("Failed to send CONNECT");
    client.flush().await.expect("Failed to flush CONNECT");

    // Simulate User clicking 'AllowSession'
    tokio::spawn(async move {
        for _ in 0..500 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let resolved = queue_clone
                .resolve_all_for_provider("gemini", HoldResolution::Allow)
                .await;
            if resolved > 0 {
                return;
            }
        }
    });

    // Read the HTTP/1.1 200 Connection Established response
    let mut resp_buf = [0u8; 256];
    let n = client
        .read(&mut resp_buf)
        .await
        .expect("Failed to read proxy response");
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

    assert!(
        resp_str.contains("HTTP/1.1 200 Connection Established"),
        "Expected 200 Connection Established, got: {resp_str}"
    );

    // Verify bidirectional tunnel works through the proxy to mock server
    let ping_msg = b"HELLO_ZASTAVA_TUNNEL\n";
    client
        .write_all(ping_msg)
        .await
        .expect("Failed to write to tunnel");
    client.flush().await.expect("Failed to flush tunnel");

    let mut echo_buf = [0u8; 128];
    let echo_n = client
        .read(&mut echo_buf)
        .await
        .expect("Failed to read from tunnel");
    assert_eq!(&echo_buf[..echo_n], ping_msg);

    srv_handle.abort();
    mock_handle.abort();
}

/// Integration Test 3b: Yellow (allowed geo, warning checks, zero critical) passes silently
/// without holding in HoldQueue or blocking under both AskPopup and AutoLockSilent,
/// including when DNS whoami sources disagree (`DNS_WHOAMI_DISAGREE`).
#[tokio::test]
async fn test_connect_yellow_passes_without_hold_or_block() {
    zastava_lib::sysproxy::force_os_dry_run();
    for (behavior, cc, host, provider, simulate_dns_disagree) in [
        (
            InterceptionBehavior::AskPopup,
            "TR",
            "gemini.google.com",
            ProviderId::Gemini,
            false,
        ),
        (
            InterceptionBehavior::AutoLockSilent,
            "KZ",
            "api.anthropic.com",
            ProviderId::Anthropic,
            false,
        ),
        (
            InterceptionBehavior::AskPopup,
            "TR",
            "gemini.google.com",
            ProviderId::Gemini,
            true,
        ),
    ] {
        let mock_target = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind mock target listener");
        let mock_addr = mock_target.local_addr().unwrap();

        let mock_handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = mock_target.accept().await {
                let mut buf = [0u8; 128];
                if let Ok(n) = stream.read(&mut buf).await
                    && n > 0
                {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
        });

        let auditor = if simulate_dns_disagree {
            let dns = FakeDns::new(LookupOutcome::NotFound)
                .with("whoami.akamai.net", addr("195.10.20.30"))
                .with_txt(
                    "o-o.myaddr.l.google.com",
                    TxtOutcome::Records(vec!["212.10.20.30".to_string()]),
                );
            offline_test_auditor_with(dns, FakeProbe::new(HttpProbeOutcome::Timeout))
        } else {
            offline_test_auditor()
        };
        let yellow_telemetry = NetworkTelemetry {
            ip: "185.220.101.5".to_string(),
            country_code: cc.to_string(),
            hostname: None,
            asn: Some(9009),
            org: Some("M247 Europe SRL".to_string()),
            isp: Some("M247 Europe SRL".to_string()),
            timezone: Some("Europe/Istanbul".to_string()),
            resolved_at: current_timestamp(),
        };
        auditor.resolver.set_cached(yellow_telemetry).await;

        let state = AppState::new_in_memory();
        state.set_interception_behavior(behavior).await.unwrap();
        let hold_queue = Arc::new(HoldQueue::new());

        let server = Arc::new(
            ProxyServer::bind_ephemeral(
                auditor.clone(),
                state.clone(),
                Arc::clone(&hold_queue),
                Some(mock_addr),
            )
            .await
            .expect("Proxy server bind failed"),
        );

        let bound_addr = server.bound_addr;
        let srv_clone = Arc::clone(&server);
        let srv_handle = tokio::spawn(async move {
            srv_clone.run().await;
        });

        let mut client = match TcpStream::connect(bound_addr).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("Skipping test due to sandbox network restrictions: {e}");
                return;
            }
            Err(e) => panic!("Failed to connect to proxy: {e}"),
        };

        let connect_req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
        client.write_all(connect_req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let mut resp_buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(4), client.read(&mut resp_buf))
            .await
            .expect("Yellow connect timed out")
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(
            resp_str.contains("HTTP/1.1 200 Connection Established"),
            "Yellow {cc} ({host}) under {behavior:?} must tunnel immediately: {resp_str}"
        );

        let ping_msg = b"YELLOW_PASS_OK\n";
        client.write_all(ping_msg).await.unwrap();
        client.flush().await.unwrap();
        let mut echo_buf = [0u8; 128];
        let echo_n = client.read(&mut echo_buf).await.unwrap();
        assert_eq!(&echo_buf[..echo_n], ping_msg);

        assert!(hold_queue.current_alert().is_none());
        assert!(state.get_data().await.blocked_providers.is_empty());

        let report = auditor
            .evaluate_all_with(provider, &state, &RouteSelection::Direct, false)
            .await
            .expect("offline yellow audit");
        assert_eq!(report.overall_status, OverallStatus::Yellow);
        assert!(
            report.checks.iter().all(|c| !c.status.is_critical()),
            "yellow report must have zero critical checks: {:?}",
            report.checks
        );
        if simulate_dns_disagree {
            assert!(
                report.checks.iter().any(|c| c.code == "DNS_WHOAMI_DISAGREE"),
                "expected DNS_WHOAMI_DISAGREE in checks: {:?}",
                report.checks
            );
        }

        srv_handle.abort();
        mock_handle.abort();
    }
}
