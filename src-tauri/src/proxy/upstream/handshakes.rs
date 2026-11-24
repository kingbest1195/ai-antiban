use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::proxy::transit::{HAPPY_EYEBALLS_STEP, race_connect};
use crate::routing::Entry;
use crate::routing::net::resolve_entry_checked;

const IPV6_DEGRADATION_COOLDOWN_SECS: u64 = 120;
const IPV6_HEALTHY_TTL_SECS: u64 = 300;
static LAST_IPV6_FAILURE_SECS: AtomicU64 = AtomicU64::new(0);
static LAST_IPV6_SUCCESS_SECS: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn record_ipv6_failure() {
    LAST_IPV6_FAILURE_SECS.store(now_secs(), Ordering::Relaxed);
}

pub(crate) fn record_ipv6_success() {
    LAST_IPV6_SUCCESS_SECS.store(now_secs(), Ordering::Relaxed);
}

fn has_working_ipv6() -> bool {
    let ok = LAST_IPV6_SUCCESS_SECS.load(Ordering::Relaxed);
    let fail = LAST_IPV6_FAILURE_SECS.load(Ordering::Relaxed);
    ok > 0 && ok >= fail && now_secs().saturating_sub(ok) <= IPV6_HEALTHY_TTL_SECS
}

fn should_prefer_v4(prefer_v4_hint: bool) -> bool {
    if prefer_v4_hint || crate::sysproxy::get_chained_proxy().is_some() {
        return true;
    }
    let last = LAST_IPV6_FAILURE_SECS.load(Ordering::Relaxed);
    if last > 0 && now_secs().saturating_sub(last) <= IPV6_DEGRADATION_COOLDOWN_SECS {
        return true;
    }
    !has_working_ipv6()
}

fn configure_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}

fn order_socket_addrs_with_priority(addrs: &[SocketAddr], prefer_v4: bool) -> Vec<SocketAddr> {
    if addrs.len() <= 1 {
        return addrs.to_vec();
    }
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();
    for &addr in addrs {
        let list = if addr.is_ipv6() { &mut v6 } else { &mut v4 };
        if !list.contains(&addr) {
            list.push(addr);
        }
    }
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let (mut first, mut second) = if prefer_v4 {
        (v4.into_iter(), v6.into_iter())
    } else {
        (v6.into_iter(), v4.into_iter())
    };
    loop {
        match (first.next(), second.next()) {
            (None, None) => break,
            (x, y) => {
                out.extend(x);
                out.extend(y);
            }
        }
    }
    out
}

pub(crate) async fn tcp_connect_addrs_with_v4_priority(
    addrs: Vec<SocketAddr>,
    tcp_timeout: Duration,
    prefer_v4_hint: bool,
) -> io::Result<TcpStream> {
    let ordered = order_socket_addrs_with_priority(&addrs, should_prefer_v4(prefer_v4_hint));
    race_connect(
        ordered,
        HAPPY_EYEBALLS_STEP,
        tcp_timeout,
        |addr| async move {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    if addr.is_ipv6() {
                        record_ipv6_success();
                    }
                    configure_tcp_stream(&stream);
                    Ok(stream)
                }
                Err(e) => {
                    if addr.is_ipv6() {
                        record_ipv6_failure();
                    }
                    Err(e)
                }
            }
        },
    )
    .await
}

pub(super) async fn tcp_connect_addrs(
    addrs: Vec<SocketAddr>,
    tcp_timeout: Duration,
) -> io::Result<TcpStream> {
    tcp_connect_addrs_with_v4_priority(addrs, tcp_timeout, !has_working_ipv6()).await
}

/// Resolves the entry host once, checks EVERY address (see [`crate::routing::net`]) and connects to
/// a checked `SocketAddr` via Happy Eyeballs — the name is never resolved a second time.
pub(super) async fn tcp_connect_with_timeout(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let addrs = resolve_entry_checked(entry, allow_local, gateway_port).await?;
    tcp_connect_addrs(addrs, timeout).await
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(super) async fn socks5_handshake(
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
                    format!(
                        "SOCKS5 authentication failed (status: 0x{:02x})",
                        auth_resp[1]
                    ),
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target domain exceeds 255 bytes",
            ));
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
/// Returns any pipelined bytes buffered beyond `\r\n\r\n` so callers never lose tunneled payload.
pub(super) async fn http_connect_handshake<S>(
    stream: &mut S,
    entry: &Entry,
    target_host: &str,
    target_port: u16,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (code, status_line, leftover) =
        http_connect_exchange(stream, entry, target_host, target_port).await?;
    match code.as_str() {
        "200" => Ok(leftover),
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

/// Sends `CONNECT` and reads the proxy's answer head using buffered `BufReader`:
/// `(status code, status line, leftover bytes after \r\n\r\n)`.
pub(super) async fn http_connect_exchange<S>(
    stream: &mut S,
    entry: &Entry,
    target_host: &str,
    target_port: u16,
) -> io::Result<(String, String, Vec<u8>)>
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

    let mut reader = BufReader::new(stream);
    let mut header = Vec::with_capacity(512);
    loop {
        if header.len() >= 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP proxy response headers too large",
            ));
        }
        let n = reader.read_until(b'\n', &mut header).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP proxy closed connection prematurely",
            ));
        }
        if header.len() > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP proxy response headers too large",
            ));
        }
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let leftover = reader.buffer().to_vec();

    let resp = String::from_utf8_lossy(&header);
    let status_line: String = resp
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(120)
        .collect();
    let code = status_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    Ok((code, status_line, leftover))
}
