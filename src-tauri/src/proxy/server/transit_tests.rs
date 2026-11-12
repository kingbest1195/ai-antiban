//! Gateway-level tests for transit (non-AI) traffic: plain HTTP forwarding, chained proxy with
//! fallback, Happy Eyeballs through `connect_direct`, DNS cache and independence from the gate.
//! Everything runs on loopback sockets; names are resolved by a fake resolver and "public"
//! addresses are mapped to local listeners by a fake dialer.

use super::*;
use crate::proxy::hold_queue::HoldQueue;
use crate::proxy::http_forward::find_head_end;
use crate::proxy::transit::{DialFn, ResolveFn, Transit};
use crate::state::AppState;
use std::sync::Mutex;

const PUBLIC_V4: &str = "93.184.216.34";
const PUBLIC_V6: &str = "2606:2800:220:1:248:1893:25c8:1946";

struct Env {
    server: Arc<ProxyServer>,
    dials: Arc<Mutex<Vec<SocketAddr>>>,
    resolves: Arc<AtomicU64>,
}

impl Env {
    fn addr(&self) -> SocketAddr {
        self.server.bound_addr
    }
    fn dial_count(&self) -> usize {
        self.dials.lock().unwrap().len()
    }
}

/// Gateway whose "public" addresses all lead to `origin`; IPv6 addresses are black holes.
async fn start(origin: SocketAddr, resolved: &[&str], chained: Option<String>) -> Env {
    crate::sysproxy::force_os_dry_run();
    let ips: Vec<IpAddr> = resolved.iter().map(|s| s.parse().unwrap()).collect();
    let resolves = Arc::new(AtomicU64::new(0));
    let r = Arc::clone(&resolves);
    let resolver: ResolveFn = Arc::new(move |_host| {
        r.fetch_add(1, Ordering::SeqCst);
        let ips = ips.clone();
        Box::pin(async move { Ok(ips) })
    });
    let dials = Arc::new(Mutex::new(Vec::new()));
    let d = Arc::clone(&dials);
    let dial: DialFn = Arc::new(move |addr| {
        d.lock().unwrap().push(addr);
        Box::pin(async move {
            if addr.is_ipv6() {
                std::future::pending::<()>().await;
            }
            TcpStream::connect(origin).await
        })
    });
    let transit = Transit::with_backends(resolver, dial, Arc::new(Instant::now))
        .with_chained(Arc::new(move || chained.clone()));
    let server = ProxyServer::bind_ephemeral(
        Auditor::new().expect("auditor"),
        AppState::new_in_memory(),
        Arc::new(HoldQueue::new()),
        None,
    )
    .await
    .expect("bind")
    .with_transit(transit);
    let server = Arc::new(server);
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });
    Env {
        server,
        dials,
        resolves,
    }
}

async fn read_request(s: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(he) = find_head_end(&buf) {
            let head = String::from_utf8_lossy(&buf[..he]).to_ascii_lowercase();
            let body_len = buf.len() - he;
            let cl = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map(|v| v.trim().parse::<usize>().unwrap());
            match cl {
                Some(n) if body_len < n => {}
                Some(_) => break,
                None if head.contains("transfer-encoding: chunked") => {
                    if buf.ends_with(b"0\r\n\r\n") {
                        break;
                    }
                }
                None => break,
            }
        }
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut tmp)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }
    buf
}

/// Fake origin / upstream HTTP server: records each request it fully received and answers `body`.
async fn spawn_http_server(body: &'static str) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let seen = Arc::clone(&s2);
            tokio::spawn(async move {
                let req = read_request(&mut c).await;
                seen.lock().unwrap().push(req);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = c.write_all(resp.as_bytes()).await;
            });
        }
    });
    (addr, seen)
}

async fn spawn_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf).await {
                    if n == 0 || c.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Fake chained HTTP proxy. `connect_status = None`: CONNECT -> 200 + echo; `Some(line)`: that
/// status is the answer. Plain requests are recorded and answered with `body`.
async fn spawn_fake_proxy(
    connect_status: Option<&'static str>,
    body: &'static str,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let seen = Arc::clone(&s2);
            tokio::spawn(async move {
                let req = read_request(&mut c).await;
                let text = String::from_utf8_lossy(&req).into_owned();
                let first = text.lines().next().unwrap_or("").to_string();
                seen.lock().unwrap().push(first.clone());
                if first.starts_with("CONNECT ") {
                    match connect_status {
                        Some(st) => {
                            let _ = c
                                .write_all(
                                    format!("HTTP/1.1 {st}\r\nContent-Length: 0\r\n\r\n")
                                        .as_bytes(),
                                )
                                .await;
                        }
                        None => {
                            let _ = c
                                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                                .await;
                            let mut buf = [0u8; 4096];
                            while let Ok(n) = c.read(&mut buf).await {
                                if n == 0 || c.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = c.write_all(resp.as_bytes()).await;
                }
            });
        }
    });
    (addr, seen)
}

/// A local address nobody listens on.
async fn dead_addr() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

async fn exchange(gateway: SocketAddr, request: &[u8]) -> String {
    let mut c = TcpStream::connect(gateway).await.expect("connect gateway");
    c.write_all(request).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn open_tunnel(gateway: SocketAddr, target: &str) -> (TcpStream, String) {
    let mut c = TcpStream::connect(gateway).await.expect("connect gateway");
    c.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 512];
    while find_head_end(&buf).is_none() {
        let n = tokio::time::timeout(Duration::from_secs(10), c.read(&mut tmp))
            .await
            .expect("gateway answer timed out")
            .unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    (c, String::from_utf8_lossy(&buf).into_owned())
}

async fn ping(c: &mut TcpStream, msg: &[u8]) {
    c.write_all(msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut got))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(got, msg);
}

fn last_request(seen: &Arc<Mutex<Vec<Vec<u8>>>>) -> String {
    String::from_utf8_lossy(seen.lock().unwrap().last().expect("origin got no request"))
        .into_owned()
}

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
