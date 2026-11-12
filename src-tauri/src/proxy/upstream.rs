//! Egress through a route's entry nodes: SOCKS5, HTTP CONNECT and HTTP CONNECT over TLS (`https`).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::routing::net::resolve_entry_checked;
use crate::routing::{parse_route_key, Entry, EntryProto, Route};
use crate::state::UpstreamProxyConfig;

/// Parses a key or proxy URL into the legacy single-proxy view (first entry).
/// See [`crate::routing::key`] for the accepted formats and validation rules.
pub fn parse_upstream_key(input: &str) -> Result<UpstreamProxyConfig, String> {
    let route = parse_route_key(input, crate::auditor::network::current_timestamp())?;
    route
        .to_legacy(true)
        .ok_or_else(|| "Key has no entry nodes".to_string())
}

/// Stream to the target through an entry node (or a direct TCP connection).
pub enum UpstreamStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_flush(cx),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

fn build_tls_config(roots: RootCertStore) -> io::Result<ClientConfig> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("TLS setup failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Production TLS config: Mozilla roots (webpki-roots, same as reqwest), full verification.
/// There is intentionally no way to inject roots or disable verification on this path.
fn production_tls_config() -> io::Result<Arc<ClientConfig>> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(c) = CFG.get() {
        return Ok(Arc::clone(c));
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = Arc::new(build_tls_config(roots)?);
    Ok(Arc::clone(CFG.get_or_init(|| cfg)))
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Resolves the entry host once, checks EVERY address (see [`crate::routing::net`]) and connects to
/// a checked `SocketAddr` — the name is never resolved a second time.
async fn tcp_connect(entry: &Entry, allow_local: bool, gateway_port: u16) -> io::Result<TcpStream> {
    let addrs = resolve_entry_checked(entry, allow_local, gateway_port).await?;
    let mut last_err: Option<io::Error> = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no entry address")))
}

async fn socks5_handshake(
    stream: &mut TcpStream,
    entry: &Entry,
    target_host: &str,
    target_port: u16,
) -> io::Result<()> {
    // 1. Greeting (RFC 1928)
    if entry.username.is_some() {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    stream.flush().await?;

    // 2. Method choice
    let mut method_buf = [0u8; 2];
    stream.read_exact(&mut method_buf).await?;
    if method_buf[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SOCKS version: 0x{:02x}", method_buf[0]),
        ));
    }
    match method_buf[1] {
        0x00 => {}
        0x02 => {
            // Username/password authentication (RFC 1929)
            let u = entry.username.as_deref().unwrap_or("").as_bytes();
            let p = entry.password.as_deref().unwrap_or("").as_bytes();
            if u.len() > 255 || p.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 username or password exceeds 255 bytes",
                ));
            }
            let mut auth = Vec::with_capacity(3 + u.len() + p.len());
            auth.push(0x01);
            auth.push(u.len() as u8);
            auth.extend_from_slice(u);
            auth.push(p.len() as u8);
            auth.extend_from_slice(p);
            stream.write_all(&auth).await?;
            stream.flush().await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("SOCKS5 authentication failed (status: 0x{:02x})", auth_resp[1]),
                ));
            }
        }
        0xFF => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "SOCKS5: No acceptable authentication methods offered by proxy server",
            ));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported SOCKS5 auth method selected by server: 0x{other:02x}"),
            ));
        }
    }

    // 3. CONNECT request (CMD=0x01)
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ipv4) = target_host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target_host.parse::<Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ipv6.octets());
    } else {
        let d = target_host.as_bytes();
        if d.len() > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Target domain exceeds 255 bytes"));
        }
        req.push(0x03);
        req.push(d.len() as u8);
        req.extend_from_slice(d);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;
    stream.flush().await?;

    // 4. Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SOCKS response version: 0x{:02x}", head[0]),
        ));
    }
    let rep = head[1];
    if rep != 0x00 {
        let msg = match rep {
            0x01 => "General SOCKS server failure",
            0x02 => "Connection not allowed by ruleset",
            0x03 => "Network unreachable",
            0x04 => "Host unreachable",
            0x05 => "Connection refused",
            0x06 => "TTL expired",
            0x07 => "Command not supported",
            0x08 => "Address type not supported",
            _ => "Unknown SOCKS error",
        };
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 connect failed: {msg} (code: 0x{rep:02x})"),
        ));
    }
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported address type in SOCKS response: 0x{other:02x}"),
            ));
        }
    }
    Ok(())
}

/// `CONNECT` handshake over any stream (plain TCP for `http`, TLS for `https`).
async fn http_connect_handshake<S>(
    stream: &mut S,
    entry: &Entry,
    target_host: &str,
    target_port: u16,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (code, status_line) = http_connect_exchange(stream, entry, target_host, target_port).await?;
    match code.as_str() {
        "200" => Ok(()),
        "407" => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy authentication required (407): check the key credentials",
        )),
        "403" => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("proxy refused the tunnel (403): {status_line}"),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("HTTP CONNECT proxy returned status {code}: {status_line}"),
        )),
    }
}

/// Sends `CONNECT` and reads the proxy's answer head: `(status code, status line)`. An `Err` is a
/// transport failure (nothing, or no complete answer, came back); an answer of any status is `Ok`.
async fn http_connect_exchange<S>(
    stream: &mut S,
    entry: &Entry,
    target_host: &str,
    target_port: u16,
) -> io::Result<(String, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = authority(target_host, target_port);
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(ref u) = entry.username {
        let p = entry.password.as_deref().unwrap_or("");
        let encoded = STANDARD.encode(format!("{u}:{p}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    req.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read headers byte-by-byte up to \r\n\r\n so no tunneled payload is swallowed.
    let mut header = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    let mut matched = 0;
    loop {
        if header.len() >= 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP proxy response headers too large"));
        }
        let n = stream.read(&mut b).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP proxy closed connection prematurely",
            ));
        }
        header.push(b[0]);
        matched = match (matched, b[0]) {
            (0, b'\r') | (2, b'\r') => matched + 1,
            (1, b'\n') => 2,
            (3, b'\n') => break,
            (_, b'\r') => 1,
            _ => 0,
        };
    }

    let resp = String::from_utf8_lossy(&header);
    let status_line: String = resp.lines().next().unwrap_or("").chars().take(120).collect();
    let code = status_line.split_whitespace().nth(1).unwrap_or("").to_string();
    Ok((code, status_line))
}

async fn connect_entry_with(
    entry: &Entry,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
    tls: &Arc<ClientConfig>,
    allow_local: bool,
    gateway_port: u16,
) -> io::Result<UpstreamStream> {
    let fut = async {
        match entry.proto {
            EntryProto::Socks5 => {
                let mut s = tcp_connect(entry, allow_local, gateway_port).await?;
                socks5_handshake(&mut s, entry, target_host, target_port).await?;
                Ok(UpstreamStream::Plain(s))
            }
            EntryProto::Http => {
                let mut s = tcp_connect(entry, allow_local, gateway_port).await?;
                http_connect_handshake(&mut s, entry, target_host, target_port).await?;
                Ok(UpstreamStream::Plain(s))
            }
            EntryProto::Https => {
                let server_name = ServerName::try_from(entry.tls_server_name().to_string())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
                let tcp = tcp_connect(entry, allow_local, gateway_port).await?;
                let mut tls_stream = TlsConnector::from(Arc::clone(tls))
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| io::Error::new(e.kind(), format!("TLS handshake failed: {e}")))?;
                http_connect_handshake(&mut tls_stream, entry, target_host, target_port).await?;
                Ok(UpstreamStream::Tls(Box::new(tls_stream)))
            }
        }
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{} entry connection timed out", entry.proto.as_str()),
        )
    })?
}

async fn connect_via_route_with(
    route: &Route,
    target_host: &str,
    target_port: u16,
    per_entry_timeout: Duration,
    tls: &Arc<ClientConfig>,
    gateway_port: u16,
) -> io::Result<UpstreamStream> {
    if route.entries.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "route has no entry nodes"));
    }
    let mut errors = Vec::with_capacity(route.entries.len());
    let mut last_kind = io::ErrorKind::Other;
    let allow_local = route.allows_local_entries();
    for (i, entry) in route.entries.iter().enumerate() {
        match connect_entry_with(
            entry,
            target_host,
            target_port,
            per_entry_timeout,
            tls,
            allow_local,
            gateway_port,
        )
        .await
        {
            Ok(s) => return Ok(s),
            Err(e) => {
                last_kind = e.kind();
                errors.push(format!(
                    "entry #{} {} {}: {e}",
                    i + 1,
                    entry.proto.as_str(),
                    entry.endpoint()
                ));
            }
        }
    }
    Err(io::Error::new(
        last_kind,
        format!("all entry nodes failed ({})", errors.join("; ")),
    ))
}

/// Opens a tunnel to `target_host:target_port` through the route's entries, tried in order with
/// `per_entry_timeout` each. Fails only when every entry failed. `gateway_port` is the port of the
/// local gateway (0 = unknown): an entry pointing back at it is refused (loop).
pub async fn connect_via_route(
    route: &Route,
    target_host: &str,
    target_port: u16,
    per_entry_timeout: Duration,
    gateway_port: u16,
) -> io::Result<UpstreamStream> {
    let tls = production_tls_config()?;
    connect_via_route_with(route, target_host, target_port, per_entry_timeout, &tls, gateway_port).await
}

/// Why a connection through the chained (system) proxy failed.
#[derive(Debug)]
pub enum ChainedError {
    /// No answer from the proxy: refused / unreachable / timed out / broken handshake. The caller
    /// may fall back to a direct connection.
    Unreachable(io::Error),
    /// The proxy answered the `CONNECT` with a non-2xx status. That is its decision: no fallback.
    Refused { status: String },
}

impl std::fmt::Display for ChainedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainedError::Unreachable(e) => write!(f, "chained proxy unreachable: {e}"),
            ChainedError::Refused { status } => write!(f, "chained proxy refused the tunnel (status {status})"),
        }
    }
}

/// Splits the chained proxy string (`host:port`, no scheme, no credentials) into an entry.
fn chained_entry(chained: &str) -> io::Result<Entry> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, "invalid chained proxy address");
    let (host, port) = chained.trim().rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || port == 0 {
        return Err(bad());
    }
    Ok(Entry {
        proto: EntryProto::Http,
        host: host.to_string(),
        port,
        username: None,
        password: None,
        sni: None,
    })
}

/// Plain TCP connection to the chained HTTP proxy (the user's own proxy: loopback / private
/// addresses are fine, the gateway itself is refused).
pub async fn connect_chained_tcp(
    chained: &str,
    timeout: Duration,
    gateway_port: u16,
) -> io::Result<TcpStream> {
    let entry = chained_entry(chained)?;
    tokio::time::timeout(timeout, tcp_connect(&entry, true, gateway_port))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "chained proxy connect timed out"))?
}

/// `CONNECT target` through the chained HTTP proxy.
pub async fn connect_via_chained_proxy(
    chained: &str,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
    gateway_port: u16,
) -> Result<UpstreamStream, ChainedError> {
    let entry = chained_entry(chained).map_err(ChainedError::Unreachable)?;
    let fut = async {
        let mut s = tcp_connect(&entry, true, gateway_port)
            .await
            .map_err(ChainedError::Unreachable)?;
        let (code, _line) = http_connect_exchange(&mut s, &entry, target_host, target_port)
            .await
            .map_err(ChainedError::Unreachable)?;
        if code.starts_with('2') {
            Ok(UpstreamStream::Plain(s))
        } else {
            Err(ChainedError::Refused { status: code })
        }
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(ChainedError::Unreachable(io::Error::new(
            io::ErrorKind::TimedOut,
            "chained proxy handshake timed out",
        ))),
    }
}

/// Legacy entry point: connects through a single v1.3.x upstream config.
pub async fn connect_via_upstream(
    cfg: &UpstreamProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> io::Result<UpstreamStream> {
    let route = Route::from_legacy(cfg, 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported upstream proxy protocol: {}", cfg.protocol),
        )
    })?;
    connect_via_route(&route, target_host, target_port, timeout, 0).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use tokio::net::TcpListener;

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
            socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();

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

        let stream_res = connect_via_upstream(&cfg, "api.anthropic.com", 443, Duration::from_secs(3)).await;
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
            socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
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

        let stream_res = connect_via_upstream(&cfg, "api.openai.com", 443, Duration::from_secs(3)).await;
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

        let stream_res = connect_via_upstream(&cfg, "api.openai.com", 443, Duration::from_secs(3)).await;
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

    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

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
                    assert!(req.starts_with("CONNECT api.anthropic.com:443 HTTP/1.1"), "{req}");
                    let authed = req.contains(&format!("Proxy-Authorization: Basic {expected_auth}\r\n"));
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
        let res = connect_via_route_with(&route, "api.anthropic.com", 443, Duration::from_secs(3), &client_cfg_trusting(&ca), 0).await;
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
        let err = connect_via_route_with(&route, "api.anthropic.com", 443, Duration::from_secs(3), &cfg, 0)
            .await
            .err()
            .expect("wrong password must fail");
        assert!(err.to_string().contains("407"), "{err}");
        assert!(!err.to_string().contains("WrongSecret77"));

        let port = spawn_tls_proxy(&ca, ALICE_AUTH, StubReply::AuthRequired).await;
        let route = route_of(vec![https_entry(port, "wonderland")]);
        let err = connect_via_route_with(&route, "api.anthropic.com", 443, Duration::from_secs(3), &cfg, 0)
            .await
            .err()
            .expect("407 must fail");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        let port = spawn_tls_proxy(&ca, ALICE_AUTH, StubReply::Forbidden).await;
        let route = route_of(vec![https_entry(port, "wonderland")]);
        let err = connect_via_route_with(&route, "api.anthropic.com", 443, Duration::from_secs(3), &cfg, 0)
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
        let err = connect_via_route_with(&route, "api.anthropic.com", 443, Duration::from_secs(3), &client_cfg_trusting(&other_ca), 0)
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
        let err = connect_via_route_with(&route_of(vec![bad_sni]), "api.anthropic.com", 443, Duration::from_secs(3), &client_cfg_trusting(&ca), 0)
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
        let route = route_of(vec![https_entry(closed, "wonderland"), https_entry(good, "wonderland")]);
        let mut s = match connect_via_route_with(&route, "api.anthropic.com", 443, Duration::from_secs(3), &client_cfg_trusting(&ca), 0).await {
            Ok(s) => s,
            Err(e) if sandboxed(&e) => return,
            Err(e) => panic!("failover failed: {e}"),
        };
        s.write_all(b"pong").await.unwrap();
        let mut echo = [0u8; 4];
        s.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"pong");

        // All entries down -> one aggregated error, no secrets.
        let route = route_of(vec![https_entry(closed, "wonderland"), https_entry(closed, "wonderland")]);
        let err = connect_via_route_with(&route, "api.anthropic.com", 443, Duration::from_secs(1), &client_cfg_trusting(&ca), 0)
            .await
            .err()
            .expect("all down must fail");
        let msg = err.to_string();
        assert!(msg.contains("entry #1") && msg.contains("entry #2"), "{msg}");
        assert!(!msg.contains("wonderland"));
    }
}
