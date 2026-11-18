//! Windows `ipconfig /all` adapter parser and unproxied OS network/DNS snapshot collector.

use crate::sysproxy;
use std::net::IpAddr;

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn is_tun_vpn_adapter(name: &str, description: Option<&str>) -> bool {
    const MARKERS: &[&str] = &[
        "wintun",
        "tun",
        "tap",
        "wireguard",
        "happ",
        "sing-box",
        "singbox",
        "clash",
        "xray",
        "v2ray",
        "nekoray",
        "openvpn",
        "tailscale",
        "zerotier",
        "vpn",
        "utun",
    ];
    let combined = match description {
        Some(desc) => format!("{name} {desc}").to_ascii_lowercase(),
        None => name.to_ascii_lowercase(),
    };
    if combined.contains("teredo") || combined.contains("isatap") || combined.contains("6to4") {
        return false;
    }
    MARKERS.iter().any(|m| combined.contains(m))
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn extract_ip_token(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .split('(')
        .next()
        .unwrap_or("")
        .trim()
        .split('%')
        .next()
        .unwrap_or("")
        .trim();
    if trimmed.parse::<IpAddr>().is_ok() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn parse_windows_ipconfig_snapshot(output: &str) -> Vec<String> {
    #[derive(Default)]
    struct AdapterInfo {
        name: String,
        description: Option<String>,
        disconnected: bool,
        has_ip: bool,
        dns_servers: Vec<String>,
    }

    let mut adapters: Vec<AdapterInfo> = Vec::new();
    let mut current: Option<AdapterInfo> = None;
    let mut in_dns_servers = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            in_dns_servers = false;
            continue;
        }
        let is_indented = line.starts_with(' ') || line.starts_with('\t');
        if !is_indented && trimmed.ends_with(':') {
            in_dns_servers = false;
            if let Some(prev) = current.take() {
                adapters.push(prev);
            }
            let lower = trimmed.to_ascii_lowercase();
            // Skip the top-level "Windows IP Configuration:" header (has no adapter fields).
            if lower.contains("windows ip configuration")
                || trimmed.contains("Настройка протокола IP")
            {
                continue;
            }
            current = Some(AdapterInfo {
                name: trimmed.trim_end_matches(':').trim().to_string(),
                ..Default::default()
            });
            continue;
        }

        let Some(adapter) = current.as_mut() else {
            continue;
        };

        if let Some((key_raw, val_raw)) = trimmed.split_once(':') {
            let key = key_raw.trim_end_matches(['.', ' ']).to_ascii_lowercase();
            let val = val_raw.trim();
            let val_lower = val.to_ascii_lowercase();
            in_dns_servers = false;

            if (key.contains("media state") || key.contains("состояние среды"))
                && (val_lower.contains("disconnected")
                    || val.contains("недоступна")
                    || val.contains("отключена"))
            {
                adapter.disconnected = true;
            } else if key.contains("description") || key.contains("описание") {
                if !val.is_empty() {
                    adapter.description = Some(val.to_string());
                }
            } else if key.contains("dns")
                && (key.contains("server") || key.contains("сервер"))
            {
                in_dns_servers = true;
                if let Some(ip) = extract_ip_token(val)
                    && !adapter.dns_servers.contains(&ip)
                {
                    adapter.dns_servers.push(ip);
                }
            } else if (key.contains("ip address")
                || key.contains("ipv4")
                || key.contains("ipv6")
                || key.contains("default gateway")
                || key.contains("основной шлюз"))
                && extract_ip_token(val).is_some()
            {
                adapter.has_ip = true;
            }
        } else if in_dns_servers
            && let Some(ip) = extract_ip_token(trimmed)
            && !adapter.dns_servers.contains(&ip)
        {
            adapter.dns_servers.push(ip);
        }
    }
    if let Some(last) = current.take() {
        adapters.push(last);
    }

    let mut active_summaries = Vec::new();
    let mut all_dns = Vec::new();
    for a in adapters {
        if a.disconnected {
            continue;
        }
        let tun_vpn = is_tun_vpn_adapter(&a.name, a.description.as_deref());
        if !a.has_ip && a.dns_servers.is_empty() && !tun_vpn {
            continue;
        }
        for dns in &a.dns_servers {
            if !all_dns.contains(dns) {
                all_dns.push(dns.clone());
            }
        }
        let mut details = Vec::new();
        if let Some(desc) = a.description.as_deref() {
            details.push(format!("desc={desc}"));
        }
        if tun_vpn {
            details.push("TUN/VPN".to_string());
        }
        if !a.dns_servers.is_empty() {
            details.push(format!("dns=[{}]", a.dns_servers.join(", ")));
        }
        if details.is_empty() {
            active_summaries.push(a.name);
        } else {
            active_summaries.push(format!("{}({})", a.name, details.join(", ")));
        }
    }

    let mut lines = Vec::new();
    if !active_summaries.is_empty() {
        lines.push(format!("active_adapters: {}", active_summaries.join("; ")));
    }
    if !all_dns.is_empty() {
        lines.push(format!("dns_servers: {}", all_dns.join(", ")));
    }
    lines
}

pub fn collect_unproxied_os_network_snapshot() -> Vec<String> {
    if !sysproxy::os_effects_enabled() {
        return Vec::new();
    }
    let mut lines = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = sysproxy::silent_command("ipconfig").arg("/all").output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            lines.extend(parse_windows_ipconfig_snapshot(&text));
        }
    }

    if let Ok((cfg, _)) = hickory_resolver::system_conf::read_system_conf() {
        let mut servers = Vec::new();
        for ns in cfg.name_servers {
            let ip_str = ns.ip.to_string();
            if !servers.contains(&ip_str) {
                servers.push(ip_str);
            }
        }
        if !servers.is_empty() {
            lines.push(format!("system_dns_servers: {}", servers.join(", ")));
        }
    }

    lines
}
