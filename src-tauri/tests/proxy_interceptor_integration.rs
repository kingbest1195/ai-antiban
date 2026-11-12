use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::network::{current_timestamp, NetworkTelemetry};
use zastava_lib::auditor::Auditor;
use zastava_lib::proxy::hold_queue::{HoldQueue, HoldResolution};
use zastava_lib::proxy::ProxyServer;
use zastava_lib::state::AppState;
use zastava_lib::sysproxy::SysProxy;

/// Integration Test 1: PAC File Generation & Routing Validation
/// Spec: GET http://127.0.0.1:8899/proxy.pac returns 200 OK and valid JS code
/// routing claude.ai, chatgpt.com, gemini.google.com through PROXY, and others DIRECT.
#[tokio::test]
async fn test_pac_file_generation() {
    zastava_lib::sysproxy::force_os_dry_run();
    let auditor = Auditor::new().expect("Auditor initialization failed");
    let state = AppState::new_in_memory();
    let hold_queue = Arc::new(HoldQueue::new());

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

    // Connect to local proxy and request PAC file
    let mut client = match TcpStream::connect(bound_addr).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("Skipping test due to sandbox network restrictions: {e}");
            return;
        }
        Err(e) => panic!("Failed to connect to proxy server: {e}"),
    };

    let req = format!(
        "GET http://{bound_addr}/proxy.pac HTTP/1.1\r\nHost: {bound_addr}\r\nConnection: close\r\n\r\n"
    );
    client
        .write_all(req.as_bytes())
        .await
        .expect("Failed to write PAC request");
    client.flush().await.expect("Failed to flush PAC request");

    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("Failed to read PAC response");

    let resp_str = String::from_utf8_lossy(&response);

    // Verify 200 OK and PAC content type
    assert!(
        resp_str.contains("HTTP/1.1 200 OK"),
        "Response header missing 200 OK: {resp_str}"
    );
    assert!(
        resp_str.contains("Content-Type: application/x-ns-proxy-autoconfig"),
        "Missing PAC Content-Type header"
    );

    // Verify JS routing logic
    assert!(resp_str.contains("function FindProxyForURL(url, host)"));
    assert!(resp_str.contains("\"claude.ai\""));
    assert!(resp_str.contains("\"chatgpt.com\""));
    assert!(resp_str.contains("\"gemini.google.com\""));
    assert!(resp_str.contains(&format!("PROXY {bound_addr}")));
    assert!(resp_str.contains("return \"DIRECT\";"));

    srv_handle.abort();
}

/// Integration Test 2: Connection Hold and Block
/// Spec: Simulating dangerous IP (e.g. TR for Gemini) sends CONNECT gemini.google.com:443.
/// Proxy pauses connection in HoldQueue. When Block action is resolved,
/// returns HTTP/1.1 403 Forbidden and closes connection.
#[tokio::test]
async fn test_connect_hold_and_block() {
    zastava_lib::sysproxy::force_os_dry_run();
    let auditor = Auditor::new().expect("Auditor initialization failed");

    // Pre-populate telemetry with dangerous location: Turkey (TR)
    let dangerous_telemetry = NetworkTelemetry {
        ip: "185.220.101.5".to_string(),
        country_code: "TR".to_string(),
        hostname: None,
        asn: Some(9009),
        org: Some("M247 Europe SRL".to_string()),
        isp: Some("M247 Europe SRL".to_string()),
        timezone: Some("Europe/Istanbul".to_string()),
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

    let connect_req = "CONNECT gemini.google.com:443 HTTP/1.1\r\nHost: gemini.google.com:443\r\n\r\n";
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
    let read_res = tokio::time::timeout(
        Duration::from_secs(4),
        client.read_to_end(&mut response),
    )
    .await;

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
            if let Ok(n) = stream.read(&mut buf).await {
                if n > 0 {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
        }
    });

    let auditor = Auditor::new().expect("Auditor initialization failed");
    // Telemetry with warning/critical: Turkey (TR)
    let dangerous_telemetry = NetworkTelemetry {
        ip: "185.220.101.5".to_string(),
        country_code: "TR".to_string(),
        hostname: None,
        asn: Some(9009),
        org: Some("M247 Europe SRL".to_string()),
        isp: Some("M247 Europe SRL".to_string()),
        timezone: Some("Europe/Istanbul".to_string()),
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

    let connect_req = "CONNECT gemini.google.com:443 HTTP/1.1\r\nHost: gemini.google.com:443\r\n\r\n";
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

/// Integration Test 4: Graceful Proxy Cleanup
/// Spec: SysProxy::disable() cleans up system proxy settings safely without panic
/// and sets is_active() to false.
#[test]
fn test_graceful_proxy_cleanup() {
    // This test links the lib without cfg(test): force OS dry-run before anything can touch
    // networksetup / launchctl / the registry / the real $HOME.
    zastava_lib::sysproxy::force_os_dry_run();
    assert!(!zastava_lib::sysproxy::os_effects_enabled());
    let before = zastava_lib::sysproxy::dry_run_blocked_calls();

    SysProxy::disable();
    assert!(
        !SysProxy::is_active(),
        "SysProxy must report inactive after disable"
    );

    // On macOS/Windows the disable path issues OS commands; every one of them was a counted no-op.
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        assert!(
            zastava_lib::sysproxy::dry_run_blocked_calls() > before,
            "OS commands must have been blocked, got {:?}",
            zastava_lib::sysproxy::dry_run_blocked_programs()
        );
    }
}

/// Integration Test 5: Upstream Gateway Selective Routing
/// Spec: When UpstreamProxyConfig is enabled, CONNECT to AI domain (api.anthropic.com:443)
/// is routed through the upstream proxy tunnel.
#[tokio::test]
async fn test_upstream_proxy_selective_routing() {
    use zastava_lib::state::UpstreamProxyConfig;
    zastava_lib::sysproxy::force_os_dry_run();

    // 1. Start mock SOCKS5 upstream server
    let mock_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = mock_socks.local_addr().unwrap();

    let mock_socks_handle = tokio::spawn(async move {
        let (mut socket, _) = mock_socks.accept().await.unwrap();
        // Handshake
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        socket.write_all(&[0x05, 0x00]).await.unwrap();

        // Connect request
        let mut req_head = [0u8; 4];
        socket.read_exact(&mut req_head).await.unwrap();
        let mut dlen = [0u8; 1];
        socket.read_exact(&mut dlen).await.unwrap();
        let mut domain = vec![0u8; dlen[0] as usize];
        socket.read_exact(&mut domain).await.unwrap();
        let mut port_bytes = [0u8; 2];
        socket.read_exact(&mut port_bytes).await.unwrap();

        assert_eq!(String::from_utf8_lossy(&domain), "api.anthropic.com");
        assert_eq!(u16::from_be_bytes(port_bytes), 443);

        // Success reply
        socket
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 1, 187])
            .await
            .unwrap();

        // Relay echo
        let mut buf = [0u8; 16];
        let n = socket.read(&mut buf).await.unwrap();
        socket.write_all(&buf[..n]).await.unwrap();
    });

    let auditor = Auditor::new().expect("Auditor initialization failed");
    let clean_telemetry = NetworkTelemetry {
        ip: "185.10.10.1".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: Some(20473),
        org: Some("Choopa".to_string()),
        isp: Some("Choopa".to_string()),
        timezone: Some("Europe/Amsterdam".to_string()),
        resolved_at: current_timestamp(),
    };

    let raw_key = format!("socks5://127.0.0.1:{}", socks_addr.port());
    auditor
        .resolver
        .set_cached_for_key(Some(raw_key.clone()), clean_telemetry)
        .await;

    let state = AppState::new_in_memory();
    let cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key,
        protocol: "socks5".to_string(),
        host: "127.0.0.1".to_string(),
        port: socks_addr.port(),
        username: None,
        password: None,
        label: Some("Mock NL Gateway".to_string()),
    };
    state.set_upstream_proxy(Some(cfg)).await.unwrap();
    state.allow_provider_for_session("anthropic").await.unwrap();

    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state, hold_queue, None)
            .await
            .expect("bind ephemeral failed"),
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
    let connect_req = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    client.write_all(connect_req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();

    let mut resp_buf = [0u8; 256];
    let n = client.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(
        resp_str.contains("HTTP/1.1 200 Connection Established"),
        "Expected 200 Connection Established, got: {resp_str}"
    );

    // Verify data passed through the mock socks5 gateway
    client.write_all(b"TEST_PROXY_FLOW").await.unwrap();
    client.flush().await.unwrap();

    let mut echo = [0u8; 15];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"TEST_PROXY_FLOW");

    srv_handle.abort();
    mock_socks_handle.abort();
}
