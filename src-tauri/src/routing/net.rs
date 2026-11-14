//! Address policy for entry nodes: resolve once, check every address, connect to the checked one.
//!
//! * Keys that come from outside (`zastava://…`) may only point to public addresses.
//! * Keys the user typed in URL form (`socks5://`, `http://`, `https://`) may also point to
//!   loopback / private addresses: that is the user's own local proxy (Xray, sing-box, …).
//! * Nothing may point back to the gateway itself (loop), and link-local / metadata / multicast /
//!   reserved ranges stay forbidden for everyone.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::Entry;
use crate::proxy::server::{
    DEFAULT_PROXY_PORT, FALLBACK_PROXY_PORT, embedded_ipv4, is_forbidden_ip, is_tun_fake_ip,
};

/// DNS lookup limit for entry hosts.
pub const ENTRY_DNS_TIMEOUT: Duration = Duration::from_secs(4);

fn unwrap_embedded(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => embedded_ipv4(v6).map(IpAddr::V4).unwrap_or(*ip),
        IpAddr::V4(_) => *ip,
    }
}

/// Loopback, private (RFC 1918 / ULA) and shared (RFC 6598, e.g. a tailnet) addresses: the
/// "user's own network" that manual URL keys may point to.
pub fn is_user_local_ip(ip: &IpAddr) -> bool {
    match unwrap_embedded(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback() || v4.is_private() || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn is_loopback_or_unspecified(ip: &IpAddr) -> bool {
    match unwrap_embedded(ip) {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// True when `ip:port` is (or may be) the gateway itself. `gateway_port == 0` means "unknown":
/// then both default gateway ports are assumed.
pub fn is_gateway_loop(ip: &IpAddr, port: u16, gateway_port: u16) -> bool {
    if !is_loopback_or_unspecified(ip) {
        return false;
    }
    if gateway_port != 0 {
        port == gateway_port
    } else {
        port == DEFAULT_PROXY_PORT || port == FALLBACK_PROXY_PORT
    }
}

/// Checks one resolved entry address. `via_hostname`: the address came from a DNS name (a TUN
/// FakeIP answer is then acceptable, as for direct connections).
pub fn check_entry_ip(
    ip: &IpAddr,
    port: u16,
    via_hostname: bool,
    allow_local: bool,
    gateway_port: u16,
) -> Result<(), &'static str> {
    if is_gateway_loop(ip, port, gateway_port) {
        return Err("entry node points to the Zastava gateway itself");
    }
    if !is_forbidden_ip(ip) {
        return Ok(());
    }
    if via_hostname && is_tun_fake_ip(ip) {
        return Ok(());
    }
    if allow_local && is_user_local_ip(ip) {
        return Ok(());
    }
    Err("entry node address belongs to a restricted local or reserved network")
}

/// Resolves the entry host (once) and verifies EVERY returned address. The caller must connect to
/// one of the returned `SocketAddr`s and never resolve the name again.
pub async fn resolve_entry_checked(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let (addrs, via_hostname) = match entry.host.parse::<IpAddr>() {
        Ok(ip) => (vec![SocketAddr::new(ip, entry.port)], false),
        Err(_) => {
            let resolved = tokio::time::timeout(
                ENTRY_DNS_TIMEOUT,
                tokio::net::lookup_host((entry.host.as_str(), entry.port)),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "entry DNS lookup timed out"))??;
            (resolved.collect::<Vec<_>>(), true)
        }
    };
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "entry host did not resolve to any address",
        ));
    }
    for a in &addrs {
        check_entry_ip(&a.ip(), a.port(), via_hostname, allow_local, gateway_port)
            .map_err(|m| io::Error::new(io::ErrorKind::PermissionDenied, m))?;
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_forbidden_ip_gaps_closed() {
        for s in [
            "0.0.0.0",
            "0.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
            "127.0.0.1",
            "10.1.2.3",
            "::127.0.0.1",
            "::10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b::c0a8:1",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "::",
            "::1",
            "100::1",
        ] {
            assert!(is_forbidden_ip(&ip(s)), "{s} must be forbidden");
        }
        for s in [
            "8.8.8.8",
            "185.10.10.2",
            "2606:4700:4700::1111",
            "64:ff9b::808:808",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_forbidden_ip(&ip(s)), "{s} must be allowed");
        }
    }

    #[test]
    fn test_local_policy_for_manual_keys() {
        // zastava:// keys: public only.
        assert!(check_entry_ip(&ip("127.0.0.1"), 10808, false, false, 8899).is_err());
        assert!(check_entry_ip(&ip("10.0.0.1"), 8080, false, false, 8899).is_err());
        assert!(check_entry_ip(&ip("185.1.1.1"), 1080, false, false, 8899).is_ok());
        // Manual URL keys: the user's own proxy is fine ...
        assert!(check_entry_ip(&ip("127.0.0.1"), 10808, false, true, 8899).is_ok());
        assert!(check_entry_ip(&ip("10.0.0.1"), 8080, false, true, 8899).is_ok());
        assert!(check_entry_ip(&ip("::1"), 10808, false, true, 8899).is_ok());
        assert!(check_entry_ip(&ip("::ffff:127.0.0.1"), 10808, false, true, 8899).is_ok());
        // ... but never the gateway itself, metadata or reserved ranges.
        assert!(check_entry_ip(&ip("127.0.0.1"), 8899, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("::1"), 8899, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("0.0.0.0"), 8899, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("::ffff:127.0.0.1"), 8899, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("169.254.169.254"), 80, false, true, 8899).is_err());
        assert!(check_entry_ip(&ip("0.0.0.0"), 1080, false, true, 8899).is_err());
        // Unknown gateway port: both defaults are protected.
        assert!(check_entry_ip(&ip("127.0.0.1"), 8900, false, true, 0).is_err());
        assert!(check_entry_ip(&ip("127.0.0.1"), 8901, false, true, 0).is_ok());
        // TUN FakeIP is acceptable only for names.
        assert!(check_entry_ip(&ip("198.18.0.5"), 443, true, false, 8899).is_ok());
        assert!(check_entry_ip(&ip("198.18.0.5"), 443, false, false, 8899).is_err());
    }

    fn entry(host: &str, port: u16) -> Entry {
        Entry {
            proto: super::super::EntryProto::Socks5,
            host: host.into(),
            port,
            username: None,
            password: None,
            sni: None,
        }
    }

    #[tokio::test]
    async fn test_resolve_checks_every_address() {
        // Names that resolve to loopback are rejected for external keys even though the text
        // looks like a public domain ...
        let e = resolve_entry_checked(&entry("localhost", 1080), false, 8899).await;
        assert_eq!(e.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        // ... and accepted for the user's own keys.
        let ok = resolve_entry_checked(&entry("localhost", 1080), true, 8899)
            .await
            .unwrap();
        assert!(!ok.is_empty() && ok.iter().all(|a| a.ip().is_loopback()));
        // Odd numeric spellings go through the system resolver as IPv4 literals and are caught.
        if let Ok(res) = resolve_entry_checked(&entry("127.1", 1080), false, 8899).await {
            panic!("127.1 must not pass: {res:?}");
        }
        let loopback_gw = resolve_entry_checked(&entry("127.0.0.1", 8899), true, 8899).await;
        assert_eq!(
            loopback_gw.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
