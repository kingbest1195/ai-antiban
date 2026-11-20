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
    if is_loopback && (port == 8899 || port == 8900) {
        return true;
    }
    false
}

/// Helper that checks `host:port` string against gateway loop.
pub fn is_gateway_host_port(host_port: &str, gateway_port: Option<u16>) -> bool {
    let trimmed = host_port.trim();
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

/// Parses Windows registry ProxyServer value into a `host:port` string.
/// Supports both plain format "127.0.0.1:10808" and protocol format "http=127.0.0.1:10808;https=127.0.0.1:10808".
/// Returns `None` if the proxy points to Zastava's gateway (loop prevention) or is invalid.
pub fn parse_windows_proxy_server(raw: &str, gateway_port: Option<u16>) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let candidate = if raw.contains('=') {
        let parts: Vec<&str> = raw
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let find_proto = |proto: &str| -> Option<&str> {
            parts.iter().find_map(|p| {
                let (k, v) = p.split_once('=')?;
                if k.trim().eq_ignore_ascii_case(proto) {
                    Some(v.trim())
                } else {
                    None
                }
            })
        };

        find_proto("https")
            .or_else(|| find_proto("http"))
            .or_else(|| find_proto("socks"))
            .or_else(|| {
                parts
                    .first()
                    .and_then(|p| p.split_once('=').map(|(_, v)| v.trim()).or(Some(p)))
            })
    } else {
        Some(raw)
    };

    let target = candidate?.trim();
    if target.is_empty() {
        return None;
    }

    let clean_target = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .or_else(|| target.strip_prefix("socks://"))
        .unwrap_or(target);

    let (host, port_str) = clean_target.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }

    let clean_host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if clean_host.is_empty() {
        return None;
    }

    if is_gateway_target(&clean_host, port, gateway_port) {
        return None;
    }

    Some(format!("{clean_host}:{port}"))
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
