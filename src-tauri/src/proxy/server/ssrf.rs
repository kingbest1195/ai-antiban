pub use crate::core::net_safety::{
    DEFAULT_PROXY_PORT, FALLBACK_PROXY_PORT, embedded_ipv4, is_forbidden_ip,
    is_internal_hostname, is_tun_fake_ip, validate_tunnel_target,
};

pub fn parse_host_port(target: &str) -> (String, u16) {
    let trimmed = target.trim();
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some((ipv6_host, after_bracket)) = rest.split_once(']')
    {
        let port = after_bracket
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(443);
        return (ipv6_host.trim().to_string(), port);
    }

    // If there are multiple colons (unbracketed IPv6 literal without port)
    if trimmed.matches(':').count() > 1 {
        return (trimmed.to_string(), 443);
    }

    if let Some((h, p)) = trimmed.rsplit_once(':') {
        let port = p.parse::<u16>().unwrap_or(443);
        let clean_host = h.trim().trim_end_matches('.').to_string();
        (clean_host, port)
    } else {
        (trimmed.trim_end_matches('.').to_string(), 443)
    }
}
