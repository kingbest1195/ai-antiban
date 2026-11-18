use super::*;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use crate::routing::{Entry, EntryProto};

#[test]
fn test_parse_socks5_url_direct() {
    let input = "socks5://user:pass@185.10.10.1:1080#Zastava%202-Hop%20(NL)";
    let cfg = parse_upstream_key(input).expect("parse failed");
    assert!(cfg.enabled);
    assert_eq!(cfg.protocol, "socks5");
    assert_eq!(cfg.host, "185.10.10.1");
    assert_eq!(cfg.port, 1080);
    assert_eq!(cfg.username.as_deref(), Some("user"));
    assert_eq!(cfg.password.as_deref(), Some("pass"));
    assert_eq!(cfg.label.as_deref(), Some("Zastava 2-Hop (NL)"));
}

#[test]
fn test_parse_socks5h_and_unescaped_label() {
    // Link-local / metadata / reserved entry hosts are rejected even for manual URL keys.
    assert!(parse_upstream_key("socks5h://169.254.169.254:9050#Custom Gateway").is_err());

    let input = "socks5h://95.217.1.100:9050#Custom Gateway";
    let cfg = parse_upstream_key(input).expect("parse failed");
    assert_eq!(cfg.protocol, "socks5");
    assert_eq!(cfg.host, "95.217.1.100");
    assert_eq!(cfg.port, 9050);
    assert_eq!(cfg.username, None);
    assert_eq!(cfg.password, None);
    assert_eq!(cfg.label.as_deref(), Some("Custom Gateway"));
}

#[test]
fn test_parse_http_url_direct() {
    let input = "http://admin:secret@proxy.org:8080#HTTP Gate";
    let cfg = parse_upstream_key(input).expect("parse failed");
    assert_eq!(cfg.protocol, "http");
    assert_eq!(cfg.host, "proxy.org");
    assert_eq!(cfg.port, 8080);
    assert_eq!(cfg.username.as_deref(), Some("admin"));
    assert_eq!(cfg.password.as_deref(), Some("secret"));
    assert_eq!(cfg.label.as_deref(), Some("HTTP Gate"));
}

#[test]
fn test_parse_zastava_json_base64_standard() {
    let json = r#"{"protocol":"socks5","host":"45.1.2.3","port":1080,"username":"u1","password":"p1","label":"NL-Fast"}"#;
    let b64 = STANDARD.encode(json.as_bytes());
    let input = format!("zastava://{b64}");

    let cfg = parse_upstream_key(&input).expect("parse failed");
    assert_eq!(cfg.protocol, "socks5");
    assert_eq!(cfg.host, "45.1.2.3");
    assert_eq!(cfg.port, 1080);
    assert_eq!(cfg.username.as_deref(), Some("u1"));
    assert_eq!(cfg.password.as_deref(), Some("p1"));
    assert_eq!(cfg.label.as_deref(), Some("NL-Fast"));
    assert_eq!(cfg.raw_key, input);
}

#[test]
fn test_parse_zastava_url_base64_url_safe_no_pad() {
    let url = "socks5://u2:p2@nl-node.example.com:1085#Zastava 2-Hop";
    let b64 = URL_SAFE_NO_PAD.encode(url.as_bytes());
    let input = format!("zastava://{b64}");

    let cfg = parse_upstream_key(&input).expect("parse failed");
    assert_eq!(cfg.protocol, "socks5");
    assert_eq!(cfg.host, "nl-node.example.com");
    assert_eq!(cfg.port, 1085);
    assert_eq!(cfg.username.as_deref(), Some("u2"));
    assert_eq!(cfg.password.as_deref(), Some("p2"));
    assert_eq!(cfg.label.as_deref(), Some("Zastava 2-Hop"));
}

#[test]
fn test_parse_invalid_keys() {
    assert!(parse_upstream_key("").is_err());
    assert!(parse_upstream_key("   ").is_err());
    assert!(parse_upstream_key("ftp://1.2.3.4:21").is_err());
    assert!(parse_upstream_key("zastava://not-valid-base64???").is_err());
}

#[tokio::test]
async fn test_connect_via_upstream_socks5_no_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Spawn mock SOCKS5 server
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Read greeting [0x05, 0x01, 0x00]
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting[0], 0x05);
        // Select NO_AUTH (0x00)
        socket.write_all(&[0x05, 0x00]).await.unwrap();

        // Read connect request [0x05, 0x01, 0x00, 0x03, domain_len, ...domain, port]
        let mut req_head = [0u8; 4];
        socket.read_exact(&mut req_head).await.unwrap();
        assert_eq!(req_head[0], 0x05);
        assert_eq!(req_head[1], 0x01); // CONNECT
        assert_eq!(req_head[3], 0x03); // Domain

        let mut dlen = [0u8; 1];
        socket.read_exact(&mut dlen).await.unwrap();
        let mut domain = vec![0u8; dlen[0] as usize];
        socket.read_exact(&mut domain).await.unwrap();
        let mut port_bytes = [0u8; 2];
        socket.read_exact(&mut port_bytes).await.unwrap();

        assert_eq!(String::from_utf8_lossy(&domain), "api.anthropic.com");
        assert_eq!(u16::from_be_bytes(port_bytes), 443);

        // Send success reply (IPv4 bind 0.0.0.0:0)
        socket
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        // Echo test
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.unwrap();
        socket.write_all(&buf).await.unwrap();
    });

    let cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: format!("socks5://127.0.0.1:{port}"),
        protocol: "socks5".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: None,
        password: None,
        label: None,
    };

    let stream_res =
        connect_via_upstream(&cfg, "api.anthropic.com", 443, Duration::from_secs(3)).await;
    let mut stream = match stream_res {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("Skipping test due to sandbox network restrictions: {e}");
            return;
        }
        Err(e) => panic!("socks5 connection failed: {e}"),
    };

    stream.write_all(b"ping").await.unwrap();
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"ping");
}

#[tokio::test]
async fn test_connect_via_upstream_socks5_with_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 4];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting[0], 0x05);
        // Select USER_PASS (0x02)
        socket.write_all(&[0x05, 0x02]).await.unwrap();

        // Read auth subnegotiation: 0x01, ulen, username..., plen, password...
        let mut ver = [0u8; 2];
        socket.read_exact(&mut ver).await.unwrap();
        assert_eq!(ver[0], 0x01);
        let ulen = ver[1] as usize;
        let mut uname = vec![0u8; ulen];
        socket.read_exact(&mut uname).await.unwrap();

        let mut plen_buf = [0u8; 1];
        socket.read_exact(&mut plen_buf).await.unwrap();
        let plen = plen_buf[0] as usize;
        let mut pword = vec![0u8; plen];
        socket.read_exact(&mut pword).await.unwrap();

        assert_eq!(String::from_utf8_lossy(&uname), "testuser");
        assert_eq!(String::from_utf8_lossy(&pword), "testpass");

        // Auth success
        socket.write_all(&[0x01, 0x00]).await.unwrap();

        // Connect request
        let mut req_head = [0u8; 4];
        socket.read_exact(&mut req_head).await.unwrap();
        assert_eq!(req_head[1], 0x01);
        let mut dlen = [0u8; 1];
        socket.read_exact(&mut dlen).await.unwrap();
        let mut domain = vec![0u8; dlen[0] as usize + 2]; // domain + port
        socket.read_exact(&mut domain).await.unwrap();

        // Success reply
        socket
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });

    let cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: format!("socks5://testuser:testpass@127.0.0.1:{port}"),
        protocol: "socks5".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: Some("testuser".to_string()),
        password: Some("testpass".to_string()),
        label: None,
    };

    let stream_res =
        connect_via_upstream(&cfg, "api.openai.com", 443, Duration::from_secs(3)).await;
    let stream = match stream_res {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("Skipping test due to sandbox network restrictions: {e}");
            return;
        }
        Err(e) => panic!("authenticated socks5 connect failed: {e}"),
    };
    drop(stream);
}

#[tokio::test]
async fn test_connect_via_upstream_socks5_auth_rejection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 4];
        let _ = socket.read_exact(&mut greeting).await;
        socket.write_all(&[0x05, 0x02]).await.unwrap();

        let mut ver = [0u8; 2];
        let _ = socket.read_exact(&mut ver).await;
        let ulen = ver[1] as usize;
        let mut uname = vec![0u8; ulen];
        let _ = socket.read_exact(&mut uname).await;
        let mut plen_buf = [0u8; 1];
        let _ = socket.read_exact(&mut plen_buf).await;
        let plen = plen_buf[0] as usize;
        let mut pword = vec![0u8; plen];
        let _ = socket.read_exact(&mut pword).await;

        // Reject auth
        socket.write_all(&[0x01, 0x01]).await.unwrap();
    });

    let cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: format!("socks5://bad:wrong@127.0.0.1:{port}"),
        protocol: "socks5".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: Some("bad".to_string()),
        password: Some("wrong".to_string()),
        label: None,
    };

    let res = connect_via_upstream(&cfg, "api.openai.com", 443, Duration::from_secs(3)).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_connect_via_upstream_http_with_basic_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);

        assert!(req.starts_with("CONNECT api.openai.com:443 HTTP/1.1"));
        assert!(req.contains("Proxy-Authorization: Basic YWRtaW46c2VjcmV0")); // admin:secret in b64

        let resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        socket.write_all(resp.as_bytes()).await.unwrap();

        // Echo test
        let mut echo_buf = [0u8; 5];
        socket.read_exact(&mut echo_buf).await.unwrap();
        socket.write_all(&echo_buf).await.unwrap();
    });

    let cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: format!("http://admin:secret@127.0.0.1:{port}"),
        protocol: "http".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: Some("admin".to_string()),
        password: Some("secret".to_string()),
        label: None,
    };

    let stream_res =
        connect_via_upstream(&cfg, "api.openai.com", 443, Duration::from_secs(3)).await;
    let mut stream = match stream_res {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("Skipping test due to sandbox network restrictions: {e}");
            return;
        }
        Err(e) => panic!("http connect failed: {e}"),
    };

    stream.write_all(b"hello").await.unwrap();
    let mut echo = [0u8; 5];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"hello");
}

#[tokio::test]
async fn test_connect_via_upstream_http_forbidden() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        let resp = "HTTP/1.1 403 Forbidden\r\n\r\n";
        socket.write_all(resp.as_bytes()).await.unwrap();
    });

    let cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: format!("http://127.0.0.1:{port}"),
        protocol: "http".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: None,
        password: None,
        label: None,
    };

    let res = connect_via_upstream(&cfg, "api.openai.com", 443, Duration::from_secs(3)).await;
    assert!(res.is_err());
}

// --- HTTPS (TLS) entry tests: local stub with a throwaway CA ---

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

struct TestCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

fn make_ca() -> TestCa {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Zastava Test CA");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    TestCa { cert, key }
}

fn leaf(ca: &TestCa) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// Test-only client config trusting `ca` (the production path has no such hook).
fn client_cfg_trusting(ca: &TestCa) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert.der().clone()).unwrap();
    Arc::new(build_tls_config(roots).unwrap())
}

#[derive(Clone, Copy)]
enum StubReply {
    Ok,
    AuthRequired,
    Forbidden,
}

/// TLS CONNECT proxy stub: checks Basic auth, answers per `reply`, then echoes.
async fn spawn_tls_proxy(ca: &TestCa, expected_auth: &'static str, reply: StubReply) -> u16 {
    let (cert, key) = leaf(ca);
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if tls.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let req = String::from_utf8_lossy(&head).to_string();
                assert!(
                    req.starts_with("CONNECT api.anthropic.com:443 HTTP/1.1"),
                    "{req}"
                );
                let authed =
                    req.contains(&format!("Proxy-Authorization: Basic {expected_auth}\r\n"));
                let resp: &[u8] = match (reply, authed) {
                    (StubReply::Forbidden, _) => b"HTTP/1.1 403 Forbidden\r\n\r\n",
                    (StubReply::AuthRequired, _) | (StubReply::Ok, false) => {
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"
                    }
                    (StubReply::Ok, true) => b"HTTP/1.1 200 Connection Established\r\n\r\n",
                };
                let _ = tls.write_all(resp).await;
                let mut buf = [0u8; 64];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 || tls.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

fn https_entry(port: u16, password: &str) -> Entry {
    Entry {
        proto: EntryProto::Https,
        host: "127.0.0.1".to_string(),
        port,
        username: Some("alice".to_string()),
        password: Some(password.to_string()),
        sni: Some("localhost".to_string()),
    }
}

fn route_of(entries: Vec<Entry>) -> Route {
    Route {
        id: "test".into(),
        label: "test".into(),
        country: None,
        exit_ip: None,
        expires_at: None,
        entries,
        raw_key: String::new(),
        enabled: true,
        added_at: 0,
    }
}

// base64("alice:wonderland")
const ALICE_AUTH: &str = "YWxpY2U6d29uZGVybGFuZA==";

fn sandboxed(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied && !e.to_string().contains("40")
}

#[tokio::test]
async fn test_https_entry_connect_with_basic_auth() {
    let ca = make_ca();
    let port = spawn_tls_proxy(&ca, ALICE_AUTH, StubReply::Ok).await;
    let route = route_of(vec![https_entry(port, "wonderland")]);
    let res = connect_via_route_with(
        &route,
        "api.anthropic.com",
        443,
        Duration::from_secs(3),
        &client_cfg_trusting(&ca),
        0,
    )
    .await;
    let mut s = match res {
        Ok(s) => s,
        Err(e) if sandboxed(&e) => return,
        Err(e) => panic!("https connect failed: {e}"),
    };
    assert!(matches!(s, UpstreamStream::Tls(_)));
    s.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    s.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
}

#[tokio::test]
async fn test_https_entry_407_and_403() {
    let ca = make_ca();
    let cfg = client_cfg_trusting(&ca);

    let port = spawn_tls_proxy(&ca, ALICE_AUTH, StubReply::Ok).await;
    let route = route_of(vec![https_entry(port, "WrongSecret77")]);
    let err = connect_via_route_with(
        &route,
        "api.anthropic.com",
        443,
        Duration::from_secs(3),
        &cfg,
        0,
    )
    .await
    .err()
    .expect("wrong password must fail");
    assert!(err.to_string().contains("407"), "{err}");
    assert!(!err.to_string().contains("WrongSecret77"));

    let port = spawn_tls_proxy(&ca, ALICE_AUTH, StubReply::AuthRequired).await;
    let route = route_of(vec![https_entry(port, "wonderland")]);
    let err = connect_via_route_with(
        &route,
        "api.anthropic.com",
        443,
        Duration::from_secs(3),
        &cfg,
        0,
    )
    .await
    .err()
    .expect("407 must fail");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    let port = spawn_tls_proxy(&ca, ALICE_AUTH, StubReply::Forbidden).await;
    let route = route_of(vec![https_entry(port, "wonderland")]);
    let err = connect_via_route_with(
        &route,
        "api.anthropic.com",
        443,
        Duration::from_secs(3),
        &cfg,
        0,
    )
    .await
    .err()
    .expect("403 must fail");
    assert!(err.to_string().contains("403"), "{err}");
}

#[tokio::test]
async fn test_https_entry_rejects_untrusted_certificate() {
    let ca = make_ca();
    let other_ca = make_ca();
    let port = spawn_tls_proxy(&ca, ALICE_AUTH, StubReply::Ok).await;
    let route = route_of(vec![https_entry(port, "wonderland")]);

    // Client trusts a different CA.
    let err = connect_via_route_with(
        &route,
        "api.anthropic.com",
        443,
        Duration::from_secs(3),
        &client_cfg_trusting(&other_ca),
        0,
    )
    .await
    .err()
    .expect("untrusted cert must fail");
    assert!(err.to_string().contains("TLS handshake failed"), "{err}");

    // Production path (public roots only) rejects the private CA as well.
    let err = connect_via_route(&route, "api.anthropic.com", 443, Duration::from_secs(3), 0)
        .await
        .err()
        .expect("production roots must reject a private CA");
    assert!(err.to_string().contains("TLS handshake failed"), "{err}");

    // SNI that the certificate does not cover is rejected too.
    let mut bad_sni = https_entry(port, "wonderland");
    bad_sni.sni = Some("evil.example.com".to_string());
    let err = connect_via_route_with(
        &route_of(vec![bad_sni]),
        "api.anthropic.com",
        443,
        Duration::from_secs(3),
        &client_cfg_trusting(&ca),
        0,
    )
    .await
    .err()
    .expect("name mismatch must fail");
    assert!(err.to_string().contains("TLS handshake failed"), "{err}");
}

#[tokio::test]
async fn test_route_failover_to_second_entry() {
    let ca = make_ca();
    let good = spawn_tls_proxy(&ca, ALICE_AUTH, StubReply::Ok).await;
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let route = route_of(vec![
        https_entry(closed, "wonderland"),
        https_entry(good, "wonderland"),
    ]);
    let mut s = match connect_via_route_with(
        &route,
        "api.anthropic.com",
        443,
        Duration::from_secs(3),
        &client_cfg_trusting(&ca),
        0,
    )
    .await
    {
        Ok(s) => s,
        Err(e) if sandboxed(&e) => return,
        Err(e) => panic!("failover failed: {e}"),
    };
    s.write_all(b"pong").await.unwrap();
    let mut echo = [0u8; 4];
    s.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"pong");

    // All entries down -> one aggregated error, no secrets.
    let route = route_of(vec![
        https_entry(closed, "wonderland"),
        https_entry(closed, "wonderland"),
    ]);
    let err = connect_via_route_with(
        &route,
        "api.anthropic.com",
        443,
        Duration::from_secs(1),
        &client_cfg_trusting(&ca),
        0,
    )
    .await
    .err()
    .expect("all down must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("entry #1") && msg.contains("entry #2"),
        "{msg}"
    );
    assert!(!msg.contains("wonderland"));
}
