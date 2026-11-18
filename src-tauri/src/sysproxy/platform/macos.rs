//! Pure macOS `networksetup` / `scutil` parsers, service classification, and macOS CLI helpers.

use super::{
    EffectiveProxy, PResult, PacState, Platform, ProxyEndpoint, ServiceId, ServiceKind,
    VpnConnection, real::run_ok,
};

/// `networksetup -setproxybypassdomains` takes the word `Empty` for "no domains".
pub(super) const BYPASS_EMPTY_ARG: &str = "Empty";

/// `networksetup -getautoproxyurl` -> `PacState`. `URL: (null)` and a missing line mean absent.
pub fn parse_autoproxy(output: &str) -> PacState {
    let mut st = PacState::default();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "url" => {
                    st.url = if v == "(null)" {
                        None
                    } else {
                        Some(v.to_string())
                    }
                }
                "enabled" => st.enabled = Some(v.eq_ignore_ascii_case("yes") || v == "1"),
                _ => {}
            }
        }
    }
    st
}

/// `networksetup -getwebproxy` / `-getsecurewebproxy` -> `ProxyEndpoint` (absent lines stay `None`).
pub fn parse_webproxy(output: &str) -> ProxyEndpoint {
    let mut ep = ProxyEndpoint::default();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "enabled" => ep.enabled = Some(v.eq_ignore_ascii_case("yes") || v == "1"),
                "server" => ep.server = Some(v.to_string()),
                "port" => ep.port = v.parse::<u16>().ok(),
                "authenticated proxy enabled" => {
                    ep.authenticated = Some(v.eq_ignore_ascii_case("yes") || v == "1")
                }
                _ => {}
            }
        }
    }
    ep
}

/// `networksetup -getproxybypassdomains` -> domains, one per line. Quirk: an empty list is
/// printed as "There aren't any bypass domains set on <service>." and means no domains.
pub fn parse_bypass_domains(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("There aren't any bypass domains"))
        .map(str::to_string)
        .collect()
}

/// `networksetup -listnetworkserviceorder` -> services with device + hardware port + enabled flag.
pub fn parse_service_order(output: &str) -> Vec<ServiceId> {
    let mut out = Vec::new();
    let mut pending: Option<(String, bool)> = None;
    for line in output.lines() {
        let t = line.trim();
        if t.starts_with('(') && !t.starts_with("(Hardware Port:") {
            // "(1) Wi-Fi" or "(*) Disabled Service"
            if let Some(end) = t.find(')') {
                let marker = &t[1..end];
                let name = t[end + 1..].trim().to_string();
                pending = Some((name, marker != "*"));
            }
        } else if t.starts_with("(Hardware Port:")
            && let Some((name, enabled)) = pending.take()
        {
            let inner = t.trim_start_matches('(').trim_end_matches(')');
            let mut port = String::new();
            let mut device = String::new();
            if let Some((p, d)) = inner.split_once(", Device:") {
                port = p.trim_start_matches("Hardware Port:").trim().to_string();
                device = d.trim().to_string();
            }
            out.push(ServiceId {
                device,
                hardware_port: port,
                name,
                enabled,
            });
        }
    }
    out
}

/// `scutil --nc list` -> connection services. A line looks like
/// `* (Connected)      <UUID> VPN (<id>) "<name>"  [VPN:<id>]`; the leading `*` marks an enabled
/// one. Only the state and the quoted name are read. Header and blank lines are skipped.
pub fn parse_nc_list(output: &str) -> Vec<VpnConnection> {
    let mut out = Vec::new();
    for line in output.lines() {
        let t = line.trim().trim_start_matches('*').trim_start();
        let Some(rest) = t.strip_prefix('(') else {
            continue;
        };
        let Some((state, tail)) = rest.split_once(')') else {
            continue;
        };
        let (Some(first), Some(last)) = (tail.find('"'), tail.rfind('"')) else {
            continue;
        };
        if last <= first {
            continue;
        }
        let name = &tail[first + 1..last];
        if state.trim().is_empty() || name.is_empty() {
            continue;
        }
        out.push(VpnConnection {
            name: name.to_string(),
            connected: !state.trim().eq_ignore_ascii_case("disconnected"),
        });
    }
    out
}

/// Returns `true` for macOS virtual tunnel interface names (`utun*`, `tun*`, `tap*`, `ppp*`,
/// `ipsec*`) used by VPN clients even when absent from `scutil --nc list`.
pub fn is_virtual_tunnel_device(device: &str) -> bool {
    let d = device.trim().to_ascii_lowercase();
    ["utun", "tun", "tap", "ppp", "ipsec"]
        .iter()
        .any(|prefix| d.starts_with(prefix))
}

/// Decides what a service is. A VPN is a service listed by `scutil --nc list` (matched by name),
/// a service without a device in `networksetup -listnetworkserviceorder`, or a virtual tunnel
/// device (`utun*`, `tun*`, `tap*`, `ppp*`, `ipsec*`). When the connection list could not be read
/// (`nc` is `None`) a service with a non-tunnel device cannot be vouched for and is `Unknown`;
/// one without a device or with a tunnel device is a VPN whose state is not known, i.e. connected.
pub fn classify_service(svc: &ServiceId, nc: Option<&[VpnConnection]>) -> ServiceKind {
    let is_tunnel = svc.device.is_empty() || is_virtual_tunnel_device(&svc.device);
    let Some(list) = nc else {
        return if is_tunnel {
            ServiceKind::Vpn { connected: true }
        } else {
            ServiceKind::Unknown
        };
    };
    let listed: Vec<&VpnConnection> = list.iter().filter(|c| c.name == svc.name).collect();
    if !listed.is_empty() {
        // Two entries with one name: the more careful reading wins.
        return ServiceKind::Vpn {
            connected: listed.iter().any(|c| c.connected),
        };
    }
    if is_tunnel {
        ServiceKind::Vpn { connected: true }
    } else {
        ServiceKind::Physical
    }
}

/// Classifies every service from one read of the connection list.
pub fn classify_services(
    p: &dyn Platform,
    services: &[ServiceId],
) -> Vec<(ServiceId, ServiceKind)> {
    let nc = p.vpn_connections().ok();
    services
        .iter()
        .map(|s| (s.clone(), classify_service(s, nc.as_deref())))
        .collect()
}

/// `scutil --proxy` -> the PAC part of the effective proxy. Only the two keys of the outermost
/// dictionary are read: the `__SCOPED__` block below it repeats them per interface and is not
/// what an application without an interface binding gets.
pub fn parse_scutil_proxy(output: &str) -> EffectiveProxy {
    let mut st = EffectiveProxy::default();
    let mut depth = 0usize;
    for line in output.lines() {
        let t = line.trim();
        if depth == 1
            && let Some((k, v)) = t.split_once(" : ")
        {
            let v = v.trim();
            match k.trim() {
                "ProxyAutoConfigEnable" => st.pac_enabled = Some(v == "1"),
                "ProxyAutoConfigURLString" if !v.is_empty() => st.pac_url = Some(v.to_string()),
                _ => {}
            }
        }
        if t.ends_with('{') {
            depth += 1;
        } else if t == "}" {
            depth = depth.saturating_sub(1);
        }
    }
    st
}

/// Returns `true` when macOS `networksetup` (or another OS tool) failed because
/// administrator authorization / authentication is required or was denied.
pub fn is_admin_auth_error(stdout: &str, stderr: &str) -> bool {
    let check = |s: &str| {
        let lower = s.to_ascii_lowercase();
        lower.contains("-60005")
            || lower.contains("-60007")
            || lower.contains("-60008")
            || lower.contains("-60031")
            || lower.contains("requires administrator")
            || lower.contains("requires admin")
            || lower.contains("requires at least admin privileges")
            || lower.contains("root privileges are required")
            || lower.contains("admin privileges")
            || lower.contains("administrator privileges")
            || lower.contains("must be run as root")
            || lower.contains("must be root")
            || lower.contains("errauthorization")
            || lower.contains("authorization failed")
            || lower.contains("not authorized")
            || lower.contains("while authenticating")
            || lower.contains("authentication failed")
            || lower.contains("authentication required")
            || lower.contains("user canceled")
            || lower.contains("operation not permitted")
            || lower.contains("permission denied")
            || lower.contains("администратор")
            || lower.contains("суперпользовател")
    };
    check(stderr) || check(stdout)
}

/// The one place that knows how a PAC URL is cleared. `networksetup` has no "unset"; clearing it
/// with an empty argument (`-setautoproxyurl <service> ""`) is the assumed way and is still to be
/// confirmed on a real macOS (manual gate S2c). If it turns out wrong, only this function changes.
pub(super) fn clear_pac_url(service_name: &str) -> PResult<()> {
    run_ok(
        "networksetup",
        &["-setautoproxyurl", service_name, ""],
        "set_pac",
    )
}
