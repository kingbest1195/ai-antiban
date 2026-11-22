use super::state::state;

/// Returns the currently discovered/configured upstream chained proxy (e.g. "127.0.0.1:10808"), if any.
pub fn get_chained_proxy() -> Option<String> {
    state().chained_proxy()
}

/// Sets or clears the upstream chained proxy with loop protection against Zastava's gateway.
pub fn set_chained_proxy(proxy: Option<String>) {
    state().set_chained_proxy(proxy);
}

/// Extracts gateway port from a PAC URL (e.g. "http://127.0.0.1:8899/proxy.pac" -> 8899).
pub fn parse_gateway_port_from_pac_url(pac_url: &str) -> Option<u16> {
    let without_scheme = pac_url
        .strip_prefix("http://")
        .or_else(|| pac_url.strip_prefix("https://"))
        .unwrap_or(pac_url);
    let host_port = without_scheme.split('/').next().unwrap_or("");
    host_port
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
}

/// Checks whether `server:port` points to Zastava's own gateway port or default loopback ports,
/// preventing recursive proxy loops.
pub fn is_gateway_target(server: &str, port: u16, gateway_port: Option<u16>) -> bool {
    if port == 0 {
        return true;
    }
    if gateway_port.is_some_and(|gp| gp > 0 && port == gp) {
        return true;
    }
    let s = server
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let is_loopback = s == "127.0.0.1" || s == "localhost" || s == "::1";
    is_loopback && (port == 8899 || port == 8900)
}

/// Strips a known proxy URL scheme (`http://`, `https://`, `socks5h://`, `socks5://`, `socks://`),
/// returning `(normalized_scheme, host_port)`.
pub(crate) fn strip_proxy_scheme(raw: &str) -> (Option<&'static str>, &str) {
    let t = raw.trim();
    let lower = t.to_ascii_lowercase();
    for (prefix, scheme) in [
        ("socks5h://", "socks5h"),
        ("socks5://", "socks5"),
        ("socks://", "socks5"),
        ("https://", "https"),
        ("http://", "http"),
    ] {
        if lower.starts_with(prefix) {
            return (Some(scheme), &t[prefix.len()..]);
        }
    }
    (None, t)
}

/// Helper that checks `host:port` (or `scheme://host:port`) string against gateway loop.
pub fn is_gateway_host_port(host_port: &str, gateway_port: Option<u16>) -> bool {
    let (_, rest) = strip_proxy_scheme(host_port);
    let trimmed = rest.trim().trim_end_matches('/');
    if let Some((host, port_str)) = trimmed.rsplit_once(':') {
        match port_str.parse::<u16>() {
            Ok(port) => is_gateway_target(host, port, gateway_port),
            Err(_) => true,
        }
    } else {
        true
    }
}

/// Parses the output of macOS `networksetup -getwebproxy <service>` or `-getsecurewebproxy <service>`.
/// Returns `Some((server, port))` only when enabled is "Yes", server is non-empty, and port > 0.
pub fn parse_networksetup_webproxy_output(output: &str) -> Option<(String, u16)> {
    let mut enabled = false;
    let mut server = String::new();
    let mut port: u16 = 0;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "enabled" => {
                    enabled = val.eq_ignore_ascii_case("yes");
                }
                "server" => {
                    server = val.to_string();
                }
                "port" => {
                    port = val.parse::<u16>().unwrap_or(0);
                }
                _ => {}
            }
        }
    }

    if enabled && !server.is_empty() && port > 0 {
        Some((server, port))
    } else {
        None
    }
}

/// Formats a normalized proxy URL (`scheme://host:port` or `scheme://[ipv6]:port`).
pub(crate) fn format_proxy_url(scheme: &str, host: &str, port: u16) -> String {
    let clean_host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if clean_host.contains(':') {
        format!("{scheme}://[{clean_host}]:{port}")
    } else {
        format!("{scheme}://{clean_host}:{port}")
    }
}

/// Parses Windows registry `ProxyServer` value into a scheme-preserved proxy URL (`http://host:port`
/// or `socks5://host:port`).
/// Supports both plain format `"127.0.0.1:10808"` and protocol format
/// `"http=127.0.0.1:10809;https=127.0.0.1:10809"` / `"socks=127.0.0.1:10808"`.
/// Returns `None` if the proxy points to Zastava's gateway (loop prevention) or is invalid.
pub fn parse_windows_proxy_server(raw: &str, gateway_port: Option<u16>) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let (proto_hint, target) = if raw.contains('=') {
        let parts: Vec<&str> = raw
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let find_proto = |proto: &str| -> Option<(&'static str, &str)> {
            parts.iter().find_map(|p| {
                let (k, v) = p.split_once('=')?;
                if k.trim().eq_ignore_ascii_case(proto) {
                    let scheme = if proto.eq_ignore_ascii_case("socks") {
                        "socks5"
                    } else {
                        "http"
                    };
                    Some((scheme, v.trim()))
                } else {
                    None
                }
            })
        };

        find_proto("https")
            .or_else(|| find_proto("http"))
            .or_else(|| find_proto("socks"))
            .or_else(|| {
                parts.first().map(|p| {
                    p.split_once('=')
                        .map(|(k, v)| {
                            let scheme = if k.trim().to_ascii_lowercase().starts_with("socks") {
                                "socks5"
                            } else {
                                "http"
                            };
                            (scheme, v.trim())
                        })
                        .unwrap_or(("http", *p))
                })
            })?
    } else {
        ("http", raw)
    };

    let target = target.trim();
    if target.is_empty() {
        return None;
    }

    let (explicit_scheme, clean_target) = strip_proxy_scheme(target);
    let scheme = match explicit_scheme {
        Some("socks5h") => "socks5h",
        Some("socks5") => "socks5",
        Some("http" | "https") => "http",
        _ => proto_hint,
    };

    let (host, port_str) = clean_target.trim_end_matches('/').rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }

    let clean_host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if clean_host.is_empty() {
        return None;
    }

    if is_gateway_target(clean_host, port, gateway_port) {
        return None;
    }

    Some(format_proxy_url(scheme, clean_host, port))
}

/// Parses Windows registry `ProxyOverride` (`;` separated entries).
pub fn parse_windows_proxy_override(raw: &str) -> Vec<String> {
    raw.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// True when Windows `ProxyOverride` has a catch-all `*` rule that bypasses the explicit proxy
/// for every destination.
pub fn windows_proxy_override_bypasses_all(raw: Option<&str>) -> bool {
    raw.is_some_and(|r| {
        parse_windows_proxy_override(r)
            .iter()
            .any(|entry| entry == "*")
    })
}

/// Checks whether a loopback chained proxy port is accepting TCP connections (fast 150ms probe).
/// Non-loopback targets are assumed reachable here so OS detection does not stall on remote IPs.
pub(crate) fn is_local_proxy_reachable(proxy: &str) -> bool {
    let (_, rest) = strip_proxy_scheme(proxy);
    let trimmed = rest.trim().trim_end_matches('/');
    let Some((host, port_str)) = trimmed.rsplit_once(':') else {
        return false;
    };
    let Ok(port) = port_str.parse::<u16>() else {
        return false;
    };
    let clean_host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let loopback_ip: std::net::IpAddr = match clean_host.as_str() {
        "127.0.0.1" | "localhost" => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "::1" => std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        _ => return true,
    };
    let addr = std::net::SocketAddr::new(loopback_ip, port);
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(150)).is_ok()
}

/// Parses a REG_DWORD integer value from Windows `reg query` output.
pub fn parse_reg_dword(output: &str, value_name: &str) -> Option<u32> {
    for line in output.lines() {
        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 3
            && parts[0].eq_ignore_ascii_case(value_name)
            && parts[1].eq_ignore_ascii_case("REG_DWORD")
        {
            let v = parts[2].trim_start_matches("0x").trim_start_matches("0X");
            return u32::from_str_radix(v, 16)
                .or_else(|_| parts[2].parse::<u32>())
                .ok();
        }
    }
    None
}

/// Parses a REG_SZ string value from Windows `reg query` output.
pub fn parse_reg_sz(output: &str, value_name: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2
            && parts[0].eq_ignore_ascii_case(value_name)
            && parts[1].eq_ignore_ascii_case("REG_SZ")
        {
            let idx = trimmed.find("REG_SZ")?;
            let rest = trimmed[idx + 6..].trim();
            return Some(rest.to_string());
        }
    }
    None
}
