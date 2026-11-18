//! Diagnostic text redaction and IP-address masking helpers (secrets, URLs, IPv4/IPv6).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MASKED_IPV4: &str = "xxx.xxx.xxx.xxx";
const MASKED_IPV6: &str = "xxxx:xxxx::xxxx";

/// Masks a single IPv4 or IPv6 address literal. Non-IP inputs are passed through
/// [`sanitize_diagnostic_text`]; empty inputs return `""`.
pub fn mask_ip_address(ip: &str) -> String {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => MASKED_IPV4.to_string(),
        Ok(IpAddr::V6(_)) => MASKED_IPV6.to_string(),
        Err(_) => sanitize_diagnostic_text(trimmed),
    }
}

fn mask_ip_token(core: &str) -> Option<String> {
    if core.is_empty() {
        return None;
    }
    // CIDR notation (e.g. `185.220.101.0/24` or `2001:db8::/32`).
    if let Some((addr, prefix)) = core.split_once('/')
        && !prefix.is_empty()
        && prefix.chars().all(|c| c.is_ascii_digit())
        && let Ok(ip) = addr.parse::<IpAddr>()
    {
        let masked = match ip {
            IpAddr::V4(_) => MASKED_IPV4,
            IpAddr::V6(_) => MASKED_IPV6,
        };
        return Some(format!("{masked}/{prefix}"));
    }
    // Bracketed IPv6 with optional port: `[2001:db8::1]:443` or `[2001:db8::1]`.
    if let Some(after_open) = core.strip_prefix('[') {
        if let Some((inside, port)) = after_open.split_once("]:")
            && inside.parse::<Ipv6Addr>().is_ok()
            && !port.is_empty()
            && port.chars().all(|c| c.is_ascii_digit())
        {
            return Some(format!("[{MASKED_IPV6}]:xxx"));
        }
        if let Some(inside) = after_open.strip_suffix(']')
            && inside.parse::<Ipv6Addr>().is_ok()
        {
            return Some(format!("[{MASKED_IPV6}]"));
        }
    }
    // Plain IPv4:port.
    if let Some((host, port)) = core.rsplit_once(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
        && host.parse::<Ipv4Addr>().is_ok()
    {
        return Some(format!("{MASKED_IPV4}:xxx"));
    }
    match core.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Some(MASKED_IPV4.to_string()),
        Ok(IpAddr::V6(_)) => Some(MASKED_IPV6.to_string()),
        Err(_) => None,
    }
}

/// Redacts scheme URLs (`zastava://`, `socks*://`, `http(s)://`, `ws(s)://`, or any URL with `@`).
pub fn redact_scheme_urls(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut cursor = 0usize;

    while let Some(rel) = lower[cursor..].find("://") {
        let sep = cursor + rel;
        let mut scheme_start = sep;
        while scheme_start > cursor {
            let prev = bytes[scheme_start - 1];
            if prev.is_ascii_alphanumeric() || prev == b'+' || prev == b'-' {
                scheme_start -= 1;
            } else {
                break;
            }
        }
        let scheme = &lower[scheme_start..sep];
        let mut url_end = sep + 3;
        while url_end < raw.len() {
            let ch = raw[url_end..].chars().next().unwrap();
            if ch.is_whitespace() || matches!(ch, '"' | '\'' | ')' | ']' | '>' | ',' | ';') {
                break;
            }
            url_end += ch.len_utf8();
        }
        let full_url = &raw[scheme_start..url_end];
        let should_redact = !scheme.is_empty()
            && (scheme == "zastava"
                || scheme.starts_with("socks")
                || full_url.contains('@')
                || matches!(scheme, "http" | "https" | "ws" | "wss"));

        if should_redact {
            out.push_str(&raw[cursor..scheme_start]);
            out.push_str(scheme);
            out.push_str("://[REDACTED]");
            cursor = url_end;
        } else {
            out.push_str(&raw[cursor..sep + 3]);
            cursor = sep + 3;
        }
    }
    out.push_str(&raw[cursor..]);
    out
}

/// Redacts `key=value` / `key:value` pairs for sensitive keys and `Bearer <token>` values.
pub fn redact_sensitive_kv(token: &str, prev_was_bearer: bool) -> String {
    if prev_was_bearer && !token.is_empty() {
        return "[REDACTED]".to_string();
    }
    const SENSITIVE_KEYS: [&str; 9] = [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "proxy_url",
        "raw_key",
    ];
    for sep in ['=', ':'] {
        if let Some((k, _)) = token.split_once(sep) {
            let kl = k
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .to_ascii_lowercase();
            if SENSITIVE_KEYS.contains(&kl.as_str()) {
                return format!("{k}{sep}[REDACTED]");
            }
        }
    }
    token.to_string()
}

/// Masks IPv4/IPv6 addresses, raw proxy URLs, `zastava://` keys, and credential tokens in
/// diagnostic strings before export.
pub fn sanitize_diagnostic_text(raw: &str) -> String {
    let url_redacted = redact_scheme_urls(raw);
    let mut out = String::with_capacity(url_redacted.len());
    let mut i = 0usize;
    let mut prev_was_bearer = false;

    while i < url_redacted.len() {
        let ch = url_redacted[i..].chars().next().unwrap();
        let is_delim = ch.is_whitespace()
            || matches!(
                ch,
                '(' | ')' | ',' | ';' | '<' | '>' | '"' | '\'' | '«' | '»'
            );
        if is_delim {
            out.push(ch);
            i += ch.len_utf8();
            if !ch.is_whitespace() {
                prev_was_bearer = false;
            }
            continue;
        }
        let start = i;
        while i < url_redacted.len() {
            let c = url_redacted[i..].chars().next().unwrap();
            if c.is_whitespace()
                || matches!(
                    c,
                    '(' | ')' | ',' | ';' | '<' | '>' | '"' | '\'' | '«' | '»'
                )
            {
                break;
            }
            i += c.len_utf8();
        }
        let tok = &url_redacted[start..i];
        let kv_cleaned = redact_sensitive_kv(tok, prev_was_bearer);
        prev_was_bearer = tok.trim_end_matches(':').eq_ignore_ascii_case("bearer");

        // Handle sentence trailing periods (`185.220.101.5.`) without losing valid IPv6 `::`.
        let (core, trailing_dots) = if kv_cleaned.ends_with('.') {
            let stripped = kv_cleaned.trim_end_matches('.');
            (stripped, &kv_cleaned[stripped.len()..])
        } else {
            (kv_cleaned.as_str(), "")
        };
        if let Some(masked) = mask_ip_token(core) {
            out.push_str(&masked);
            out.push_str(trailing_dots);
        } else if let Some((k, v)) = core.split_once(':')
            && let Some(masked) = mask_ip_token(v)
        {
            // Cases like `ip:185.220.101.5` (while leaving full IPv6 literals caught above).
            out.push_str(k);
            out.push(':');
            out.push_str(&masked);
            out.push_str(trailing_dots);
        } else {
            out.push_str(&kv_cleaned);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_ips_and_redacts_urls_and_tokens() {
        assert_eq!(mask_ip_address("185.220.101.5"), MASKED_IPV4);
        assert_eq!(mask_ip_address("2001:db8::1"), MASKED_IPV6);
        assert_eq!(mask_ip_address("   "), "");
        let clean = sanitize_diagnostic_text(
            "ip:185.220.101.5 socks5://u:p@1.2.3.4:1080 password=secret Bearer abc123",
        );
        assert!(!clean.contains("185.220.101.5"));
        assert!(!clean.contains("secret"));
        assert!(!clean.contains("abc123"));
        assert!(clean.contains("socks5://[REDACTED]"));
    }
}
