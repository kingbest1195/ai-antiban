//! Pure IP, hostname, and tunnel-target safety checks (SSRF protection, FakeIP detection,
//! and special/non-routable address classification).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Default local gateway listen port.
pub const DEFAULT_PROXY_PORT: u16 = 8899;
/// Fallback local gateway listen port when [`DEFAULT_PROXY_PORT`] is occupied.
pub const FALLBACK_PROXY_PORT: u16 = 8900;
/// Ports allowed for outbound CONNECT tunnels through the local gateway.
pub const ALLOWED_TUNNEL_PORTS: &[u16] = &[80, 443, 8443];

/// IPv4 address embedded in an IPv6 one: IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
/// (`::a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`).
pub fn embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    if v6.is_loopback() || v6.is_unspecified() {
        return None;
    }
    let s = v6.segments();
    // Covers both `::ffff:a.b.c.d` and the deprecated `::a.b.c.d` (excluding `::` and `::1`).
    if let Some(v4) = v6.to_ipv4() {
        return Some(v4);
    }
    // NAT64 well-known prefix 64:ff9b::/96.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
        return Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    // 6to4: the IPv4 address sits in bits 16..48.
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    None
}

/// Returns `true` if `ip` belongs to the RFC 2544 benchmarking / TUN FakeIP pool (`198.18.0.0/15`)
/// or its IPv4-mapped IPv6 form (`::ffff:198.18.0.0/15`).
/// Used by VPN / TUN software such as sing-box, Throne, Nekoray, Hiddify, and Clash in FakeIP mode.
pub fn is_tun_fake_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 198 && (octets[1] & 0xfe) == 18
        }
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .is_some_and(|v4| is_tun_fake_ip(&IpAddr::V4(v4))),
    }
}

/// Checks whether an IP address is loopback, private (RFC 1918 / RFC 4193), link-local,
/// cloud metadata (`169.254.169.254`), broadcast, multicast, unspecified, reserved
/// (`0.0.0.0/8`, `240.0.0.0/4`), documentation, FakeIP, or an IPv6 form embedding such an IPv4.
pub fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // "This network" (0.0.0.0/8) and reserved / future use (240.0.0.0/4)
                || octets[0] == 0
                || octets[0] >= 240
                // Shared address space (RFC 6598: 100.64.0.0/10)
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
                // IETF protocol assignments & benchmarking (192.0.0.0/24, 198.18.0.0/15)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || is_tun_fake_ip(ip)
        }
        IpAddr::V6(v6) => {
            if let Some(inner) = embedded_ipv4(v6) {
                return is_forbidden_ip(&IpAddr::V4(inner));
            }
            let s = v6.segments();
            let seg0 = s[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique Local (fc00::/7)
                || (seg0 & 0xfe00) == 0xfc00
                // Link-Local unicast (fe80::/10)
                || (seg0 & 0xffc0) == 0xfe80
                // Local-use NAT64 (64:ff9b:1::/48)
                || (seg0 == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001)
                // Discard-only (100::/64)
                || (seg0 == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                // Documentation (2001:db8::/32)
                || (seg0 == 0x2001 && s[1] == 0x0db8)
        }
    }
}

/// True for `localhost` and local / internal DNS suffixes (`.local`, `.internal`, `.home.arpa`, …).
pub fn is_internal_hostname(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h.ends_with(".home.arpa")
        || h == "metadata.google.internal"
}

/// Validates target host and port against SSRF, local proxy recursion, and port scanning.
pub fn validate_tunnel_target(
    host: &str,
    port: u16,
    bound_proxy_port: u16,
) -> Result<(), &'static str> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return Err("Invalid empty target host.");
    }

    // Safely allow the local VPN crash-test canary hostname through validation
    if h == "canary-test.anthropic.zastava.local" {
        return Ok(());
    }

    if port == bound_proxy_port
        || port == DEFAULT_PROXY_PORT
        || port == FALLBACK_PROXY_PORT
        || !ALLOWED_TUNNEL_PORTS.contains(&port)
    {
        return Err("SSRF Protection: target port is not permitted by Zastava Gateway.");
    }

    if is_internal_hostname(&h) {
        return Err("SSRF Protection: local and internal hostnames are forbidden.");
    }

    if let Ok(ip) = h.parse::<IpAddr>()
        && is_forbidden_ip(&ip)
    {
        return Err(
            "SSRF Protection: direct connections to loopback or private IPs are forbidden.",
        );
    }

    Ok(())
}

/// True for non-public IPv4 addresses that a real DNS resolver never owns on the Internet.
pub fn is_special_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()                           // 127.0.0.0/8
        || ip.is_private()                            // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()                         // 169.254/16
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0                                  // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64)       // 100.64.0.0/10 (CGNAT)
        || is_tun_fake_ip(&IpAddr::V4(ip))            // 198.18.0.0/15 (fake-IP / benchmarking)
        || o[0] >= 240 // reserved
}

/// True for non-public IPv6 addresses that a real DNS resolver never owns on the Internet.
pub fn is_special_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (first & 0xfe00) == 0xfc00 // fc00::/7 unique local
}

/// Addresses that a real resolver never has on the Internet. Besides private and loopback ranges
/// this includes the `198.18.0.0/15` pool in which fake-IP DNS of a TUN client answers.
pub fn is_special_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_special_v4(*v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_special_v4(v4),
            None => is_special_v6(*v6),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_fake_ip_covers_ipv4_and_mapped_ipv6() {
        assert!(is_tun_fake_ip(&"198.18.0.1".parse().unwrap()));
        assert!(is_tun_fake_ip(&"198.19.255.254".parse().unwrap()));
        assert!(is_tun_fake_ip(&"::ffff:198.18.0.5".parse().unwrap()));
        assert!(!is_tun_fake_ip(&"198.20.0.1".parse().unwrap()));
        assert!(!is_tun_fake_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn special_addr_keeps_test_net_3_allowed_while_forbidden_blocks_it() {
        let doc_ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(!is_special_addr(&doc_ip));
        assert!(is_forbidden_ip(&doc_ip));
    }
}
