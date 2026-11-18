use super::super::*;
use super::transit_helpers_tests::*;

#[tokio::test]
async fn plain_get_is_forwarded_in_origin_form_without_hop_by_hop_headers() {
    let (origin, seen) = spawn_http_server("hello from origin").await;
    let env = start(origin, &[PUBLIC_V4], None).await;
    let req = "GET http://files.example.test/a/b?x=1 HTTP/1.1\r\n\
Host: wrong.example\r\n\
Proxy-Connection: keep-alive\r\n\
Connection: keep-alive\r\n\
Proxy-Authorization: Basic c2VjcmV0\r\n\
Keep-Alive: 5\r\n\
User-Agent: curl/8.7.1\r\n\
X-Custom: 1\r\n\r\n";
    let resp = exchange(env.addr(), req.as_bytes()).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(resp.ends_with("hello from origin"), "{resp}");

    let got = last_request(&seen);
    assert!(
        got.starts_with("GET /a/b?x=1 HTTP/1.1\r\nHost: files.example.test\r\n"),
        "{got}"
    );
    let lower = got.to_ascii_lowercase();
    for gone in [
        "proxy-connection",
        "proxy-authorization",
        "keep-alive",
        "wrong.example",
        "c2vjcmv0",
    ] {
        assert!(!lower.contains(gone), "{gone} leaked upstream: {got}");
    }
    assert!(lower.contains("x-custom: 1") && lower.contains("user-agent: curl/8.7.1"));
    assert!(lower.contains("connection: close"));
    assert_eq!(
        env.dials.lock().unwrap().as_slice(),
        &[SocketAddr::new(PUBLIC_V4.parse().unwrap(), 80)]
    );
}

#[tokio::test]
async fn plain_post_with_content_length_body_arrives_whole() {
    let (origin, seen) = spawn_http_server("stored").await;
    let env = start(origin, &[PUBLIC_V4], None).await;
    let mut c = TcpStream::connect(env.addr()).await.unwrap();
    c.write_all(b"POST http://api.example.test/upload HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    c.write_all(b" world").await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out)).await;
    let resp = String::from_utf8_lossy(&out);
    assert!(
        resp.starts_with("HTTP/1.1 200 OK") && resp.ends_with("stored"),
        "{resp}"
    );
    let got = last_request(&seen);
    assert!(got.starts_with("POST /upload HTTP/1.1\r\n"), "{got}");
    assert!(got.contains("Content-Length: 11\r\n"));
    assert!(got.ends_with("\r\n\r\nhello world"), "{got}");
}

#[tokio::test]
async fn plain_post_with_chunked_body_is_relayed_raw() {
    let (origin, seen) = spawn_http_server("ok").await;
    let env = start(origin, &[PUBLIC_V4], None).await;
    let mut c = TcpStream::connect(env.addr()).await.unwrap();
    c.write_all(b"PUT http://api.example.test/obj HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    c.write_all(b"6\r\n world\r\n0\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out)).await;
    let resp = String::from_utf8_lossy(&out);
    assert!(
        resp.starts_with("HTTP/1.1 200 OK") && resp.ends_with("ok"),
        "{resp}"
    );
    let got = last_request(&seen);
    assert!(got.starts_with("PUT /obj HTTP/1.1\r\n"), "{got}");
    assert!(got.contains("Transfer-Encoding: chunked\r\n"));
    assert!(!got.contains("Content-Length"));
    assert!(
        got.ends_with("\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
        "{got}"
    );
}

#[tokio::test]
async fn head_requests_and_other_methods_are_forwarded() {
    let (origin, seen) = spawn_http_server("").await;
    let env = start(origin, &[PUBLIC_V4], None).await;
    for method in ["HEAD", "DELETE", "OPTIONS"] {
        let req = format!("{method} http://files.example.test/x HTTP/1.1\r\n\r\n");
        let resp = exchange(env.addr(), req.as_bytes()).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{method}: {resp}");
        assert!(last_request(&seen).starts_with(&format!("{method} /x HTTP/1.1\r\n")));
    }
}

#[tokio::test]
async fn info_page_is_only_for_requests_to_the_gateway_itself() {
    let (origin, seen) = spawn_http_server("from origin").await;
    let env = start(origin, &[PUBLIC_V4], None).await;
    let gw = env.addr();

    let info = exchange(gw, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(info.contains("Zastava Gateway Active"), "{info}");
    let info = exchange(gw, format!("GET http://{gw}/ HTTP/1.1\r\n\r\n").as_bytes()).await;
    assert!(info.contains("Zastava Gateway Active"), "{info}");
    let info = exchange(
        gw,
        format!("GET http://localhost:{}/health HTTP/1.1\r\n\r\n", gw.port()).as_bytes(),
    )
    .await;
    assert!(info.contains("Zastava Gateway Active"), "{info}");
    assert_eq!(
        env.dial_count(),
        0,
        "requests to the gateway are never forwarded"
    );

    // The PAC is still served, relative and absolute to the gateway.
    for target in ["/proxy.pac".to_string(), format!("http://{gw}/proxy.pac")] {
        let pac = exchange(gw, format!("GET {target} HTTP/1.1\r\n\r\n").as_bytes()).await;
        assert!(pac.contains("FindProxyForURL"), "{target}: {pac}");
    }

    // Somebody else's /proxy.pac is just a plain HTTP request.
    let other = exchange(
        gw,
        b"GET http://corp.example.test/proxy.pac HTTP/1.1\r\n\r\n",
    )
    .await;
    assert!(other.ends_with("from origin"), "{other}");
    assert!(last_request(&seen).starts_with("GET /proxy.pac HTTP/1.1"));
}

#[tokio::test]
async fn ai_host_over_plain_http_is_refused_without_touching_the_network() {
    let (origin, seen) = spawn_http_server("must not be reached").await;
    let env = start(origin, &[PUBLIC_V4], None).await;
    for host in [
        "api.anthropic.com",
        "API.Anthropic.COM.",
        "chatgpt.com",
        "generativelanguage.googleapis.com",
    ] {
        let req = format!(
            "POST http://{host}/v1/messages HTTP/1.1\r\nHost: {host}\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        let resp = exchange(env.addr(), req.as_bytes()).await;
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "{host}: {resp}");
        assert!(resp.contains("HTTPS"), "{resp}");
    }
    // The Host header cannot smuggle an AI host past a harmless URI either way round: the URI wins.
    let resp = exchange(
        env.addr(),
        b"GET http://files.example.test/ HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(last_request(&seen).starts_with("GET / HTTP/1.1\r\nHost: files.example.test\r\n"));
    // ...and nothing was resolved or dialed for the refused ones (only the one harmless request).
    assert_eq!(env.resolves.load(Ordering::SeqCst), 1);
    assert_eq!(env.dial_count(), 1);
}

#[tokio::test]
async fn private_loopback_and_odd_port_targets_are_refused_over_plain_http() {
    let (origin, seen) = spawn_http_server("must not be reached").await;
    let env = start(origin, &[PUBLIC_V4], None).await;
    for target in [
        "127.0.0.1",
        "127.0.0.1:80",
        "10.1.2.3",
        "192.168.0.10",
        "169.254.169.254",
        "[::1]",
        "localhost",
        "printer.local",
        "metadata.google.internal",
        "files.example.test:8080",
    ] {
        let req = format!("GET http://{target}/ HTTP/1.1\r\n\r\n");
        let resp = exchange(env.addr(), req.as_bytes()).await;
        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden"),
            "{target}: {resp}"
        );
    }
    assert_eq!(env.dial_count(), 0);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn name_that_resolves_to_a_private_address_is_not_dialed() {
    let (origin, seen) = spawn_http_server("must not be reached").await;
    let env = start(origin, &["10.0.0.5"], None).await;
    let resp = exchange(
        env.addr(),
        b"GET http://rebind.example.test/ HTTP/1.1\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    assert_eq!(env.dial_count(), 0);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn malformed_plain_requests_get_400_and_unsupported_ones_501() {
    let (origin, _seen) = spawn_http_server("x").await;
    let env = start(origin, &[PUBLIC_V4], None).await;
    let both = "POST http://a.example.test/ HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert!(
        exchange(env.addr(), both.as_bytes())
            .await
            .starts_with("HTTP/1.1 400")
    );
    assert!(
        exchange(env.addr(), b"GET http://a.example.test/ HTTP/2.0\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 501")
    );
    assert_eq!(env.dial_count(), 0);
}

#[tokio::test]
async fn plain_http_goes_through_the_chained_proxy_in_absolute_form() {
    let (origin, origin_seen) = spawn_http_server("direct").await;
    let (proxy, proxy_seen) = spawn_fake_proxy(None, "via proxy").await;
    let env = start(origin, &[PUBLIC_V4], Some(proxy.to_string())).await;
    let resp = exchange(
        env.addr(),
        b"GET http://files.example.test/p?q=1 HTTP/1.1\r\nUser-Agent: npm\r\n\r\n",
    )
    .await;
    assert!(resp.ends_with("via proxy"), "{resp}");
    assert_eq!(
        proxy_seen.lock().unwrap().as_slice(),
        &["GET http://files.example.test/p?q=1 HTTP/1.1".to_string()]
    );
    assert_eq!(env.dial_count(), 0, "nothing went direct");
    assert!(origin_seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn plain_http_falls_back_to_direct_when_the_chained_proxy_is_down() {
    let (origin, origin_seen) = spawn_http_server("direct").await;
    let env = start(origin, &[PUBLIC_V4], Some(dead_addr().await)).await;
    let resp = exchange(
        env.addr(),
        b"GET http://files.example.test/ HTTP/1.1\r\n\r\n",
    )
    .await;
    assert!(resp.ends_with("direct"), "{resp}");
    assert_eq!(origin_seen.lock().unwrap().len(), 1);
    assert_eq!(env.dial_count(), 1);
}

#[tokio::test]
async fn connect_goes_through_the_chained_proxy() {
    let echo = spawn_echo().await;
    let (proxy, proxy_seen) = spawn_fake_proxy(None, "").await;
    let env = start(echo, &[PUBLIC_V4], Some(proxy.to_string())).await;
    for target in ["ghcr.io:443", "registry.npmjs.org:443", "github.com:443"] {
        let (mut c, head) = open_tunnel(env.addr(), target).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{target}: {head}");
        ping(&mut c, b"hello tunnel").await;
    }
    assert_eq!(proxy_seen.lock().unwrap().len(), 3);
    assert!(
        proxy_seen
            .lock()
            .unwrap()
            .iter()
            .all(|l| l.starts_with("CONNECT ") && l.ends_with("HTTP/1.1"))
    );
    assert_eq!(env.dial_count(), 0, "nothing went direct");
}

#[tokio::test]
async fn connect_falls_back_to_direct_once_when_the_chained_proxy_is_down() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V4], Some(dead_addr().await)).await;
    let (mut c, head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping(&mut c, b"direct after fallback").await;
    assert_eq!(env.dial_count(), 1, "exactly one direct attempt");
}

#[tokio::test]
async fn chained_proxy_error_status_is_final_and_does_not_fall_back() {
    let echo = spawn_echo().await;
    let (proxy, _seen) = spawn_fake_proxy(Some("403 Forbidden"), "").await;
    let env = start(echo, &[PUBLIC_V4], Some(proxy.to_string())).await;
    let (_c, head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(
        env.dial_count(),
        0,
        "a refusal by the proxy is not a reason to go around it"
    );

    let (proxy, _seen) = spawn_fake_proxy(Some("502 Bad Gateway"), "").await;
    let env = start(echo, &[PUBLIC_V4], Some(proxy.to_string())).await;
    let (_c, head) = open_tunnel(env.addr(), "ghcr.io:443").await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(env.dial_count(), 0);
}

#[tokio::test]
async fn blackholed_ipv6_does_not_stall_a_connect() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V6, PUBLIC_V4], None).await;
    let started = std::time::Instant::now();
    let (mut c, head) = open_tunnel(env.addr(), "github.com:443").await;
    let took = started.elapsed();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    ping(&mut c, b"through v4").await;
    // 250 ms Happy Eyeballs step (the strict <= 350 ms bound is asserted on virtual time in
    // `transit::tests`); the margin here only guards against the old multi-second stall.
    assert!(took < Duration::from_secs(2), "{took:?}");
    let dials = env.dials.lock().unwrap().clone();
    assert!(dials[0].is_ipv6(), "IPv6 is tried first: {dials:?}");
    assert!(dials.iter().any(|a| a.is_ipv4()), "{dials:?}");
}

#[tokio::test]
async fn repeated_connects_to_one_host_resolve_it_once() {
    let echo = spawn_echo().await;
    let env = start(echo, &[PUBLIC_V4], None).await;
    for _ in 0..3 {
        let (mut c, head) = open_tunnel(env.addr(), "registry.npmjs.org:443").await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        ping(&mut c, b"x").await;
    }
    assert_eq!(env.resolves.load(Ordering::SeqCst), 1);
    assert_eq!(env.dial_count(), 3);
}
