//! Public DNS operators by address range.
//!
//! The whoami sources (Akamai, Google) are asked through the same resolver but may reach us from
//! different addresses of its anycast fleet (for Cloudflare 172.70.x.x and 172.71.x.x, for
//! example). Two different addresses of one operator are therefore an agreement, not a conflict.
//! Only well-known public DNS services are listed; whatever is not here is not guessed.
//!
//! Sources (checked 2026-11-12):
//! * Cloudflare: https://www.cloudflare.com/ips-v4 and /ips-v6 (the published edge ranges, which
//!   the resolver egress addresses belong to) plus the resolver blocks 1.1.1.0/24 and 1.0.0.0/24.
//! * Google: https://www.gstatic.com/ipranges/publicdns.json (Google Public DNS egress ranges),
//!   plus 8.8.8.0/24 and 8.8.4.0/24 of the service addresses.
//! * Quad9: docs.quad9.net/services (9.9.9.x, 149.112.112.x, 2620:fe::); the covering /24 and /48
//!   are the blocks of those addresses.
//! * Cisco OpenDNS: 208.67.216.0/21 (ARIN: 208.67.216.0 - 208.67.223.255, AS36692).
//! * AdGuard DNS: adguard-dns.io/en/public-dns.html (94.140.14.x, 94.140.15.x, 2a10:50c0::); the
//!   covering /24 and /32 are the blocks of those addresses.
//! NextDNS is not listed: its egress ranges are not published, so nothing is assumed.

use std::net::IpAddr;

/// `(CIDR, operator)`. The operator names are those of `whoami::PUBLIC_DNS_SERVICES`.
const RANGES: &[(&str, &str)] = &[
    // Cloudflare
    ("1.1.1.0/24", "Cloudflare"),
    ("1.0.0.0/24", "Cloudflare"),
    ("173.245.48.0/20", "Cloudflare"),
    ("103.21.244.0/22", "Cloudflare"),
    ("103.22.200.0/22", "Cloudflare"),
    ("103.31.4.0/22", "Cloudflare"),
    ("141.101.64.0/18", "Cloudflare"),
    ("108.162.192.0/18", "Cloudflare"),
    ("190.93.240.0/20", "Cloudflare"),
    ("188.114.96.0/20", "Cloudflare"),
    ("197.234.240.0/22", "Cloudflare"),
    ("198.41.128.0/17", "Cloudflare"),
    ("162.158.0.0/15", "Cloudflare"),
    ("104.16.0.0/13", "Cloudflare"),
    ("104.24.0.0/14", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("131.0.72.0/22", "Cloudflare"),
    ("2400:cb00::/32", "Cloudflare"),
    ("2606:4700::/32", "Cloudflare"),
    ("2803:f800::/32", "Cloudflare"),
    ("2405:b500::/32", "Cloudflare"),
    ("2405:8100::/32", "Cloudflare"),
    ("2a06:98c0::/29", "Cloudflare"),
    ("2c0f:f248::/32", "Cloudflare"),
    // Google Public DNS
    ("8.8.8.0/24", "Google Public DNS"),
    ("8.8.4.0/24", "Google Public DNS"),
    ("74.125.0.0/16", "Google Public DNS"),
    ("142.250.0.0/15", "Google Public DNS"),
    ("172.217.0.0/16", "Google Public DNS"),
    ("172.253.0.0/16", "Google Public DNS"),
    ("173.194.0.0/16", "Google Public DNS"),
    ("209.85.128.0/17", "Google Public DNS"),
    ("2001:4860::/32", "Google Public DNS"),
    ("2404:6800::/32", "Google Public DNS"),
    ("2607:f8b0::/32", "Google Public DNS"),
    ("2a00:1450::/32", "Google Public DNS"),
    // Quad9
    ("9.9.9.0/24", "Quad9"),
    ("149.112.112.0/24", "Quad9"),
    ("2620:fe::/48", "Quad9"),
    ("2620:fe:fe::/48", "Quad9"),
    // Cisco OpenDNS
    ("208.67.216.0/21", "Cisco OpenDNS"),
    // AdGuard DNS
    ("94.140.14.0/24", "AdGuard DNS"),
    ("94.140.15.0/24", "AdGuard DNS"),
    ("2a10:50c0::/32", "AdGuard DNS"),
    // NextDNS
    ("45.90.28.0/24", "NextDNS"),
    ("45.90.30.0/24", "NextDNS"),
    // Control D
    ("76.76.2.0/24", "Control D"),
    ("76.76.10.0/24", "Control D"),
    // Mullvad DNS
    ("194.242.2.0/24", "Mullvad DNS"),
];

/// Whether `ip` lies in `cidr` (`a.b.c.d/n` or `x::/n`); a malformed or mixed-family entry never matches.
fn in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((base, bits)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(base), Ok(bits)) = (base.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (ip, base) {
        (IpAddr::V4(ip), IpAddr::V4(base)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(ip) & mask == u32::from(base) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(ip) & mask == u128::from(base) & mask
        }
        _ => false,
    }
}

/// The public DNS service whose range contains `ip` (IPv4-mapped IPv6 counts as IPv4).
pub fn operator_of(ip: IpAddr) -> Option<&'static str> {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    RANGES
        .iter()
        .find(|(cidr, _)| in_cidr(ip, cidr))
        .map(|(_, op)| *op)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::probes::whoami::PUBLIC_DNS_SERVICES;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cloudflare_addresses_of_the_owner_case_are_one_operator() {
        assert_eq!(operator_of(ip("172.70.161.26")), Some("Cloudflare"));
        assert_eq!(operator_of(ip("172.71.240.11")), Some("Cloudflare"));
        assert_eq!(operator_of(ip("1.1.1.1")), Some("Cloudflare"));
        assert_eq!(operator_of(ip("2606:4700:4700::1111")), Some("Cloudflare"));
    }

    #[test]
    fn other_operators_and_ranges_edges() {
        assert_eq!(operator_of(ip("8.8.8.8")), Some("Google Public DNS"));
        assert_eq!(operator_of(ip("74.125.99.1")), Some("Google Public DNS"));
        assert_eq!(operator_of(ip("2001:4860:4860::8888")), Some("Google Public DNS"));
        assert_eq!(operator_of(ip("9.9.9.9")), Some("Quad9"));
        assert_eq!(operator_of(ip("208.67.222.222")), Some("Cisco OpenDNS"));
        assert_eq!(operator_of(ip("94.140.14.14")), Some("AdGuard DNS"));
        assert_eq!(operator_of(ip("45.90.28.10")), Some("NextDNS"));
        assert_eq!(operator_of(ip("45.90.30.10")), Some("NextDNS"));
        assert_eq!(operator_of(ip("76.76.2.0")), Some("Control D"));
        assert_eq!(operator_of(ip("194.242.2.2")), Some("Mullvad DNS"));
        assert_eq!(operator_of(ip("142.250.185.14")), Some("Google Public DNS"));
        assert_eq!(operator_of(ip("209.85.200.1")), Some("Google Public DNS"));
        // Just outside of 172.64.0.0/13 (172.64.0.0 - 172.71.255.255) and 208.67.216.0/21.
        assert_eq!(operator_of(ip("172.72.0.1")), None);
        assert_eq!(operator_of(ip("208.67.224.1")), None);
        assert_eq!(operator_of(ip("172.71.255.255")), Some("Cloudflare"));
        // Ordinary provider resolvers (including a Russian one) are not public services.
        assert_eq!(operator_of(ip("77.88.8.8")), None);
        assert_eq!(operator_of(ip("203.0.113.53")), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_is_matched_as_ipv4() {
        assert_eq!(operator_of(ip("::ffff:172.70.161.26")), Some("Cloudflare"));
    }

    #[test]
    fn every_entry_is_well_formed_and_names_a_known_service() {
        for (cidr, op) in RANGES {
            let (base, bits) = cidr.split_once('/').expect(cidr);
            let base: IpAddr = base.parse().expect(cidr);
            let bits: u32 = bits.parse().expect(cidr);
            assert!(bits <= if base.is_ipv4() { 32 } else { 128 }, "{cidr}");
            assert!(PUBLIC_DNS_SERVICES.iter().any(|s| s.name == *op), "{op}");
            assert!(in_cidr(base, cidr), "{cidr}");
        }
    }
}
