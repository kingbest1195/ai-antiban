//! Gateway-level tests for transit (non-AI) traffic: plain HTTP forwarding, chained proxy with
//! fallback, Happy Eyeballs through `connect_direct`, DNS cache and independence from the gate.
//! Everything runs on loopback sockets; names are resolved by a fake resolver and "public"
//! addresses are mapped to local listeners by a fake dialer.

use super::super::*;
use crate::proxy::hold_queue::HoldQueue;
use crate::proxy::http_forward::find_head_end;
use crate::proxy::transit::{DialFn, ResolveFn, Transit};
use crate::state::AppState;
use std::sync::Mutex;

pub(super) const PUBLIC_V4: &str = "93.184.216.34";
pub(super) const PUBLIC_V6: &str = "2606:2800:220:1:248:1893:25c8:1946";

pub(super) struct Env {
    pub(super) server: Arc<ProxyServer>,
    pub(super) dials: Arc<Mutex<Vec<SocketAddr>>>,
    pub(super) resolves: Arc<AtomicU64>,
}

impl Env {
    pub(super) fn addr(&self) -> SocketAddr {
        self.server.bound_addr
    }
    pub(super) fn dial_count(&self) -> usize {
        self.dials.lock().unwrap().len()
    }
}

/// Gateway whose "public" addresses all lead to `origin`; IPv6 addresses are black holes.
pub(super) async fn start(origin: SocketAddr, resolved: &[&str], chained: Option<String>) -> Env {
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

pub(super) async fn read_request(s: &mut TcpStream) -> Vec<u8> {
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
pub(super) async fn spawn_http_server(
    body: &'static str,
) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
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

pub(super) async fn spawn_echo() -> SocketAddr {
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
pub(super) async fn spawn_fake_proxy(
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
pub(super) async fn dead_addr() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a.to_string()
}

pub(super) async fn exchange(gateway: SocketAddr, request: &[u8]) -> String {
    let mut c = TcpStream::connect(gateway).await.expect("connect gateway");
    c.write_all(request).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) async fn open_tunnel(gateway: SocketAddr, target: &str) -> (TcpStream, String) {
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

pub(super) async fn ping(c: &mut TcpStream, msg: &[u8]) {
    c.write_all(msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut got))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(got, msg);
}

pub(super) fn last_request(seen: &Arc<Mutex<Vec<Vec<u8>>>>) -> String {
    String::from_utf8_lossy(seen.lock().unwrap().last().expect("origin got no request"))
        .into_owned()
}
