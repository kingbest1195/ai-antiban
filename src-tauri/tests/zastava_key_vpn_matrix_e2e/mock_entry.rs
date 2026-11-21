use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use zastava_lib::routing::{Entry, EntryProto, Route};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EntryMode {
    HttpHealthy,
    Socks5Healthy,
    Auth407,
    Blackhole,
}

#[derive(Default)]
pub struct EntryCounters {
    pub connections: AtomicUsize,
    pub connect_requests: AtomicUsize,
    pub last_target: Mutex<Option<String>>,
}

pub struct MockZastavaEntry {
    pub addr: SocketAddr,
    pub proto: EntryProto,
    pub counters: Arc<EntryCounters>,
    task: JoinHandle<()>,
}

impl Drop for MockZastavaEntry {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockZastavaEntry {
    pub async fn spawn(mode: EntryMode, upstream: Option<SocketAddr>) -> Self {
        Self::spawn_with_auth(mode, upstream, None).await
    }

    pub async fn spawn_socks5_auth(
        expected_user: &str,
        expected_pass: &str,
        upstream: Option<SocketAddr>,
    ) -> Self {
        Self::spawn_with_auth(
            EntryMode::Socks5Healthy,
            upstream,
            Some((expected_user.to_string(), expected_pass.to_string())),
        )
        .await
    }

    async fn spawn_with_auth(
        mode: EntryMode,
        upstream: Option<SocketAddr>,
        socks_auth: Option<(String, String)>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let proto = match mode {
            EntryMode::Socks5Healthy => EntryProto::Socks5,
            _ => EntryProto::Http,
        };
        let counters = Arc::new(EntryCounters::default());
        let c = Arc::clone(&counters);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let c = Arc::clone(&c);
                let auth = socks_auth.clone();
                tokio::spawn(async move {
                    let _ = handle_entry_conn(stream, mode, upstream, c, auth).await;
                });
            }
        });
        Self {
            addr,
            proto,
            counters,
            task,
        }
    }

    pub fn as_route(&self, id: &str, label: &str) -> Route {
        Route {
            id: id.to_string(),
            label: label.to_string(),
            raw_key: format!(
                "{}://{}:{}",
                self.proto.as_str(),
                self.addr.ip(),
                self.addr.port()
            ),
            entries: vec![Entry {
                proto: self.proto,
                host: self.addr.ip().to_string(),
                port: self.addr.port(),
                username: None,
                password: None,
                sni: None,
            }],
            exit_ip: Some("185.100.10.2".to_string()),
            country: Some("DE".to_string()),
            expires_at: None,
            enabled: true,
            added_at: 0,
        }
    }

    pub fn as_domain_route(&self, id: &str, label: &str, domain: &str) -> Route {
        Route {
            id: id.to_string(),
            label: label.to_string(),
            raw_key: format!("{}://{domain}:{}", self.proto.as_str(), self.addr.port()),
            entries: vec![Entry {
                proto: self.proto,
                host: domain.to_string(),
                port: self.addr.port(),
                username: None,
                password: None,
                sni: None,
            }],
            exit_ip: Some("185.100.10.2".to_string()),
            country: Some("DE".to_string()),
            expires_at: None,
            enabled: true,
            added_at: 0,
        }
    }
}

async fn handle_entry_conn(
    mut client: TcpStream,
    mode: EntryMode,
    upstream: Option<SocketAddr>,
    c: Arc<EntryCounters>,
    socks_auth: Option<(String, String)>,
) -> std::io::Result<()> {
    c.connections.fetch_add(1, Ordering::SeqCst);
    if mode == EntryMode::Blackhole {
        tokio::time::sleep(Duration::from_secs(30)).await;
        return Ok(());
    }
    if mode == EntryMode::Socks5Healthy {
        let mut hdr_greet = [0u8; 2];
        client.read_exact(&mut hdr_greet).await?;
        let mut methods = vec![0u8; hdr_greet[1] as usize];
        client.read_exact(&mut methods).await?;
        if let Some((expected_u, expected_p)) = socks_auth {
            if !methods.contains(&0x02) {
                client.write_all(&[0x05, 0xFF]).await?;
                return Ok(());
            }
            client.write_all(&[0x05, 0x02]).await?;
            let mut auth_hdr = [0u8; 2];
            client.read_exact(&mut auth_hdr).await?;
            let mut ubuf = vec![0u8; auth_hdr[1] as usize];
            client.read_exact(&mut ubuf).await?;
            let mut plen = [0u8; 1];
            client.read_exact(&mut plen).await?;
            let mut pbuf = vec![0u8; plen[0] as usize];
            client.read_exact(&mut pbuf).await?;
            if ubuf == expected_u.as_bytes() && pbuf == expected_p.as_bytes() {
                client.write_all(&[0x01, 0x00]).await?;
            } else {
                client.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }
        } else {
            client.write_all(&[0x05, 0x00]).await?;
        }
        let mut hdr = [0u8; 4];
        client.read_exact(&mut hdr).await?;
        let host = match hdr[3] {
            0x03 => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                let mut hb = vec![0u8; len[0] as usize];
                client.read_exact(&mut hb).await?;
                String::from_utf8_lossy(&hb).to_string()
            }
            0x01 => {
                let mut ip = [0u8; 4];
                client.read_exact(&mut ip).await?;
                std::net::Ipv4Addr::from(ip).to_string()
            }
            _ => return Ok(()),
        };
        let mut pb = [0u8; 2];
        client.read_exact(&mut pb).await?;
        let port = u16::from_be_bytes(pb);
        c.connect_requests.fetch_add(1, Ordering::SeqCst);
        *c.last_target.lock().unwrap() = Some(format!("{host}:{port}"));
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await?;
        if let Some(u) = upstream
            && let Ok(mut up) = TcpStream::connect(u).await
        {
            let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
        } else {
            serve_synthetic_echo_or_http(client).await?;
        }
        return Ok(());
    }

    let mut buf = [0u8; 4096];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    if mode == EntryMode::Auth407 {
        client
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let mut parts = req.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    c.connect_requests.fetch_add(1, Ordering::SeqCst);
    *c.last_target.lock().unwrap() = Some(target.to_string());
    if method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if let Some(u) = upstream
            && let Ok(mut up) = TcpStream::connect(u).await
        {
            let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
        } else {
            serve_synthetic_echo_or_http(client).await?;
        }
    } else {
        let body = r#"{"success":true,"ip":"185.100.10.2","country_code":"DE"}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        client.write_all(resp.as_bytes()).await?;
    }
    Ok(())
}

pub async fn serve_synthetic_echo_or_http(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    while let Ok(n) = stream.read(&mut buf).await {
        if n == 0 {
            break;
        }
        let s = String::from_utf8_lossy(&buf[..n]);
        if s.starts_with("GET ") || s.starts_with("POST ") || s.starts_with("HEAD ") {
            let body = r#"{"ok":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(resp.as_bytes()).await?;
            break;
        }
        stream.write_all(&buf[..n]).await?;
    }
    Ok(())
}
