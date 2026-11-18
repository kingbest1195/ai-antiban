use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;

use crate::core::net_safety::{is_forbidden_ip, is_internal_hostname, is_tun_fake_ip};
use crate::routing::net::is_user_local_ip;
use crate::routing::{Entry, EntryProto};

use super::UpstreamStream;
use super::handshakes::{http_connect_exchange, socks5_handshake, tcp_connect_with_timeout};

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
            ChainedError::Refused { status } => {
                write!(f, "chained proxy refused the tunnel (status {status})")
            }
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
    tokio::time::timeout(
        timeout,
        tcp_connect_with_timeout(&entry, true, gateway_port, timeout),
    )
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
        let mut s = tcp_connect_with_timeout(&entry, true, gateway_port, timeout)
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

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn hosts_same_loopback(a: &str, b: &str) -> bool {
    let is_lb = |h: &str| matches!(h, "localhost" | "127.0.0.1" | "::1");
    is_lb(a) && is_lb(b)
}

/// Returns `true` only when `entry` is a public endpoint distinct from both Zastava's gateway and
/// `chained`, so tunneling `entry` through `chained` cannot create a loop or reach private nets.
pub(super) fn is_chained_eligible_for_entry(
    entry: &Entry,
    resolved_addrs: Option<&[SocketAddr]>,
    gateway_port: u16,
    chained: &str,
) -> bool {
    let Ok(cp) = chained_entry(chained) else {
        return false;
    };
    if crate::sysproxy::is_gateway_target(&cp.host, cp.port, Some(gateway_port)) {
        return false;
    }
    let entry_host = normalize_host(&entry.host);
    let cp_host = normalize_host(&cp.host);
    if entry_host.is_empty() || is_internal_hostname(&entry_host) {
        return false;
    }
    if entry.port == cp.port && (entry_host == cp_host || hosts_same_loopback(&entry_host, &cp_host)) {
        return false;
    }
    if let Ok(ip) = entry_host.parse::<IpAddr>()
        && (is_forbidden_ip(&ip) || is_user_local_ip(&ip))
    {
        return false;
    }
    if let Some(addrs) = resolved_addrs {
        for addr in addrs {
            let ip = addr.ip();
            if is_user_local_ip(&ip) || (is_forbidden_ip(&ip) && !is_tun_fake_ip(&ip)) {
                return false;
            }
            if addr.port() == cp.port && ip.to_string() == cp_host {
                return false;
            }
        }
    }
    true
}

pub(super) fn should_try_chained_for_entry(
    entry: &Entry,
    resolved_addrs: Option<&[SocketAddr]>,
    gateway_port: u16,
    chained: &str,
    allow_on_phase: bool,
) -> bool {
    if !allow_on_phase {
        return false;
    }
    is_chained_eligible_for_entry(entry, resolved_addrs, gateway_port, chained)
}

/// Opens a tunneled TCP stream to `entry.host:entry.port` via `chained`: tries HTTP `CONNECT`
/// first, and if `chained` closes/rejects non-HTTP bytes (e.g. a SOCKS5-only local proxy), falls
/// back once to unauthenticated SOCKS5 `CONNECT`.
pub(super) async fn connect_entry_tcp_via_chained(
    chained: &str,
    entry: &Entry,
    timeout: Duration,
    gateway_port: u16,
) -> Result<TcpStream, ChainedError> {
    match connect_via_chained_proxy(chained, &entry.host, entry.port, timeout, gateway_port).await {
        Ok(UpstreamStream::Plain(s)) => return Ok(s),
        Ok(UpstreamStream::Tls(_)) => {
            return Err(ChainedError::Unreachable(io::Error::other(
                "unexpected TLS stream from chained proxy",
            )));
        }
        Err(ChainedError::Refused { status }) => {
            if !status.is_empty() {
                return Err(ChainedError::Refused { status });
            }
        }
        Err(ChainedError::Unreachable(e))
            if !matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
            ) =>
        {
            return Err(ChainedError::Unreachable(e));
        }
        Err(ChainedError::Unreachable(_)) => {}
    }

    let cp = chained_entry(chained).map_err(ChainedError::Unreachable)?;
    let fut = async {
        let mut s = tcp_connect_with_timeout(&cp, true, gateway_port, timeout)
            .await
            .map_err(ChainedError::Unreachable)?;
        socks5_handshake(&mut s, &cp, &entry.host, entry.port)
            .await
            .map_err(ChainedError::Unreachable)?;
        Ok(s)
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        ChainedError::Unreachable(io::Error::new(
            io::ErrorKind::TimedOut,
            "chained SOCKS5 handshake timed out",
        ))
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::upstream::handshakes::tcp_connect_addrs;
    use tokio::net::TcpListener;

    fn mk_entry(host: &str, port: u16) -> Entry {
        Entry {
            proto: EntryProto::Socks5,
            host: host.into(),
            port,
            username: None,
            password: None,
            sni: None,
        }
    }

    #[test]
    fn chained_fallback_blocks_loopback_private_and_self_loops() {
        assert!(!should_try_chained_for_entry(
            &mk_entry("127.0.0.1", 1080),
            None,
            8899,
            "127.0.0.1:10808",
            true,
        ));
        assert!(!should_try_chained_for_entry(
            &mk_entry("10.0.0.5", 1080),
            None,
            8899,
            "127.0.0.1:10808",
            true,
        ));
        assert!(!should_try_chained_for_entry(
            &mk_entry("localhost", 1080),
            None,
            8899,
            "127.0.0.1:10808",
            true,
        ));
        assert!(!should_try_chained_for_entry(
            &mk_entry("203.0.113.5", 1080),
            None,
            8899,
            "203.0.113.5:1080",
            true,
        ));
        assert!(!should_try_chained_for_entry(
            &mk_entry("93.184.216.34", 443),
            None,
            8899,
            "127.0.0.1:8899",
            true,
        ));
        // SSRF/auth denial must not chain even for public hosts.
        assert!(!should_try_chained_for_entry(
            &mk_entry("93.184.216.34", 443),
            None,
            8899,
            "127.0.0.1:10808",
            false,
        ));
        // Public entry + distinct local chained proxy is allowed.
        assert!(should_try_chained_for_entry(
            &mk_entry("93.184.216.34", 443),
            None,
            8899,
            "127.0.0.1:10808",
            true,
        ));
    }

    #[tokio::test]
    async fn happy_eyeballs_connects_around_dead_first_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = listener.local_addr().unwrap();
        let dead_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let dead_addr: SocketAddr = format!("[::1]:{dead_port}").parse().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let started = std::time::Instant::now();
        let res = tcp_connect_addrs(vec![dead_addr, live_addr], Duration::from_secs(3)).await;
        match res {
            Ok(stream) => {
                assert!(started.elapsed() < Duration::from_secs(2));
                assert_eq!(stream.peer_addr().unwrap(), live_addr);
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {}
            Err(e) => panic!("happy eyeballs failed: {e}"),
        }
    }
}
