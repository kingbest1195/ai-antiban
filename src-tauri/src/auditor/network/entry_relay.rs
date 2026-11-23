//! Hedged loopback relay for audit entry clients when an external `chained_proxy` is active.
//!
//! Avoids sequential 4s timeouts when direct TCP/DNS to the entry node is blocked, while keeping
//! the direct path primary when reachable within the 700ms headstart.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::{TcpListener, TcpStream};

use crate::routing::net::resolve_entry_checked;
use crate::routing::{Entry, EntryProto};

const DIRECT_HEADSTART: Duration = Duration::from_millis(700);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(3500);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChainedScheme {
    Http,
    Socks5,
}

fn parse_chained(cp: &str) -> Option<(ChainedScheme, String, u16)> {
    let trimmed = cp.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let parsed = url::Url::parse(&normalized).ok()?;
    let scheme = match parsed.scheme().to_ascii_lowercase().as_str() {
        "socks5" | "socks5h" | "socks" => ChainedScheme::Socks5,
        "http" => ChainedScheme::Http,
        _ => return None,
    };
    let host = parsed.host_str()?.trim_matches(['[', ']']).to_string();
    let port = parsed.port_or_known_default()?;
    Some((scheme, host, port))
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_matches(['[', ']']).trim_end_matches('.');
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn same_target_as_chained(entry: &Entry, cp_host: &str, cp_port: u16) -> bool {
    if entry.port != cp_port {
        return false;
    }
    entry.host.eq_ignore_ascii_case(cp_host)
        || (is_loopback_host(&entry.host) && is_loopback_host(cp_host))
}

/// Spawns a short-lived loopback relay forwarding to `entry` via hedged direct + `chained_proxy`.
/// Returns `Ok(None)` if `chained_proxy` is unusable or equals `entry`.
pub(super) async fn spawn_entry_relay(
    entry: &Entry,
    chained_proxy: &str,
    allow_local: bool,
    gateway_port: u16,
) -> Result<Option<SocketAddr>, String> {
    let Some((scheme, cp_host, cp_port)) = parse_chained(chained_proxy) else {
        return Ok(None);
    };
    if same_target_as_chained(entry, &cp_host, cp_port) {
        return Ok(None);
    }
    if let Ok(ip) = entry.host.parse::<std::net::IpAddr>() {
        crate::routing::net::check_entry_ip(&ip, entry.port, false, allow_local, gateway_port)
            .map_err(|e| format!("Entry node {} rejected: {e}", entry.endpoint()))?;
    }

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind audit entry relay: {e}"))?;
    let relay_addr = listener
        .local_addr()
        .map_err(|e| format!("Failed to inspect audit entry relay address: {e}"))?;

    let wrap_tls = entry.proto == EntryProto::Https
        && entry.tls_server_name().parse::<std::net::IpAddr>().is_ok();
    let entry = entry.clone();
    tokio::spawn(async move {
        while let Ok(Ok((mut inbound, _))) =
            tokio::time::timeout(RELAY_IDLE_TIMEOUT, listener.accept()).await
        {
            let e = entry.clone();
            let host = cp_host.clone();
            tokio::spawn(async move {
                if let Ok((tcp, leftover)) =
                    connect_hedged(&e, scheme, &host, cp_port, allow_local, gateway_port).await
                {
                    let mut outbound = MaybePrefixed::new(tcp, leftover);
                    if wrap_tls {
                        if let Ok(tls_cfg) = crate::proxy::upstream::production_tls_config()
                            && let Ok(sni) = tokio_rustls::rustls::pki_types::ServerName::try_from(
                                e.tls_server_name().to_string(),
                            )
                            && let Ok(mut tls_out) = tokio_rustls::TlsConnector::from(tls_cfg)
                                .connect(sni, outbound)
                                .await
                        {
                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut tls_out).await;
                        }
                    } else {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                }
            });
        }
    });

    Ok(Some(relay_addr))
}

struct MaybePrefixed {
    prefix: std::io::Cursor<Vec<u8>>,
    tcp: TcpStream,
}

impl MaybePrefixed {
    fn new(tcp: TcpStream, leftover: Vec<u8>) -> Self {
        Self {
            prefix: std::io::Cursor::new(leftover),
            tcp,
        }
    }
}

impl AsyncRead for MaybePrefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let pos = self.prefix.position() as usize;
        let data = self.prefix.get_ref();
        if pos < data.len() {
            let avail = &data[pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            self.prefix.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for MaybePrefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tcp).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

async fn connect_hedged(
    entry: &Entry,
    scheme: ChainedScheme,
    cp_host: &str,
    cp_port: u16,
    allow_local: bool,
    gateway_port: u16,
) -> io::Result<(TcpStream, Vec<u8>)> {
    let direct_addrs = match resolve_entry_checked(entry, allow_local, gateway_port).await {
        Ok(addrs) => Some(addrs),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(e),
        Err(_) => None,
    };

    let Some(addrs) = direct_addrs else {
        if !allow_local && crate::core::net_safety::is_internal_hostname(&entry.host) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "SSRF Protection: internal hostname {} blocked without allow_local",
                    entry.host
                ),
            ));
        }
        return connect_via_chained(scheme, cp_host, cp_port, &entry.host, entry.port).await;
    };

    let direct_fut = crate::proxy::upstream::handshakes::tcp_connect_addrs_with_v4_priority(
        addrs,
        CONNECT_TIMEOUT,
        true,
    );
    tokio::pin!(direct_fut);

    let headstart = tokio::time::sleep(DIRECT_HEADSTART);
    tokio::pin!(headstart);

    tokio::select! {
        res = &mut direct_fut => {
            if let Ok(stream) = res {
                return Ok((stream, Vec::new()));
            }
            connect_via_chained(scheme, cp_host, cp_port, &entry.host, entry.port).await
        }
        () = &mut headstart => {
            let chained_fut =
                connect_via_chained(scheme, cp_host, cp_port, &entry.host, entry.port);
            tokio::pin!(chained_fut);
            tokio::select! {
                res = &mut direct_fut => match res {
                    Ok(stream) => Ok((stream, Vec::new())),
                    _ => chained_fut.await,
                },
                res = &mut chained_fut => match res {
                    Ok(pair) => Ok(pair),
                    Err(e) => match direct_fut.await {
                        Ok(stream) => Ok((stream, Vec::new())),
                        _ => Err(e),
                    },
                }
            }
        }
    }
}

async fn connect_via_chained(
    scheme: ChainedScheme,
    cp_host: &str,
    cp_port: u16,
    target_host: &str,
    target_port: u16,
) -> io::Result<(TcpStream, Vec<u8>)> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((cp_host, cp_port)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "chained proxy connect timeout"))??;
    let leftover = match scheme {
        ChainedScheme::Http => http_connect(&mut stream, target_host, target_port).await?,
        ChainedScheme::Socks5 => {
            socks5_connect(&mut stream, target_host, target_port).await?;
            Vec::new()
        }
    };
    Ok((stream, leftover))
}

async fn http_connect(stream: &mut TcpStream, host: &str, port: u16) -> io::Result<Vec<u8>> {
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    tokio::time::timeout(CONNECT_TIMEOUT, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "chained HTTP CONNECT write timeout",
            )
        })??;
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::with_capacity(512);
        loop {
            if buf.len() >= 4096 {
                return Err(io::Error::other("chained HTTP CONNECT header too large"));
            }
            let n = reader.read_until(b'\n', &mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "chained HTTP EOF",
                ));
            }
            if buf.len() > 4096 {
                return Err(io::Error::other("chained HTTP CONNECT header too large"));
            }
            if buf.ends_with(b"\r\n\r\n") {
                let first_line = String::from_utf8_lossy(&buf);
                let ok = first_line
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .is_some_and(|code| code == "200");
                if !ok {
                    return Err(io::Error::other("chained HTTP CONNECT non-200 status"));
                }
                return Ok(reader.buffer().to_vec());
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "chained HTTP CONNECT read timeout"))?
}

async fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> io::Result<()> {
    if host.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 host > 255 bytes",
        ));
    }
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await?;
        if method != [0x05, 0x00] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 auth unsupported",
            ));
        }
        let mut req = Vec::with_capacity(7 + host.len());
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&req).await?;

        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr).await?;
        if hdr[0] != 0x05 || hdr[1] != 0x00 {
            return Err(io::Error::other(format!(
                "SOCKS5 connect failed: {}",
                hdr[1]
            )));
        }
        let tail_len = match hdr[3] {
            0x01 => 6,
            0x04 => 18,
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                len[0] as usize + 2
            }
            _ => return Err(io::Error::other("SOCKS5 invalid ATYP")),
        };
        let mut discard = vec![0u8; tail_len];
        stream.read_exact(&mut discard).await?;
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "chained SOCKS5 connect timeout"))?
}

#[cfg(test)]
#[path = "entry_relay_tests.rs"]
mod tests;
