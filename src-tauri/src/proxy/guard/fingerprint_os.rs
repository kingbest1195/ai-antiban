//! Cached OS interface and DNS enumeration plus route-fingerprint diffing helpers.

#[cfg(unix)]
use std::ffi::CStr;
#[cfg(any(unix, target_os = "windows", test, feature = "test-support"))]
use std::net::IpAddr;
#[cfg(unix)]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const IFACE_CACHE_TTL: Duration = Duration::from_millis(1000);
const DNS_CACHE_TTL: Duration = Duration::from_millis(2000);
#[cfg(any(unix, test, feature = "test-support"))]
const UTUN_DEBOUNCE_WINDOW: Duration = Duration::from_millis(2000);

#[derive(Default)]
struct CachedSig {
    value: String,
    updated_at: Option<Instant>,
}

#[cfg(any(unix, test, feature = "test-support"))]
#[derive(Default)]
pub struct UtunDebounceState {
    last_udp_sig: String,
    stable_non_default: String,
    candidate_non_default: Option<(String, Instant)>,
}

static IFACE_CACHE: OnceLock<Mutex<CachedSig>> = OnceLock::new();
static DNS_CACHE: OnceLock<Mutex<CachedSig>> = OnceLock::new();
#[cfg(unix)]
static UTUN_DEBOUNCE: OnceLock<Mutex<UtunDebounceState>> = OnceLock::new();

#[cfg(any(target_os = "windows", test, feature = "test-support"))]
pub(super) fn is_tunnel_interface_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("utun")
        || lower.starts_with("tun")
        || lower.starts_with("tap")
        || lower.starts_with("wg")
        || lower.starts_with("ppp")
        || lower.starts_with("ipsec")
        || lower.contains("wintun")
        || lower.contains("wireguard")
        || lower.contains("openvpn")
        || lower.contains("sing-box")
        || lower.contains("singbox")
        || lower.contains("tailscale")
        || lower.contains("amnezia")
        || lower.contains("warp")
        || lower.contains("mullvad")
        || lower.contains("proton")
        || lower.contains("nordlynx")
        || lower.contains("zerotier")
        || lower.contains("happ")
        || lower.contains("clash")
        || lower.contains("mihomo")
        || lower.contains("xray")
        || lower.contains("v2ray")
}

#[cfg(any(target_os = "windows", test, feature = "test-support"))]
fn is_noisy_windows_adapter(adapter: &crate::win_native::network::AdapterInfo) -> bool {
    let fields = [
        adapter.friendly_name.to_ascii_lowercase(),
        adapter.description.to_ascii_lowercase(),
        adapter.adapter_name.to_ascii_lowercase(),
    ];
    let noisy_markers = [
        "vethernet",
        "hyper-v",
        "wsl",
        "default switch",
        "teredo",
        "isatap",
        "6to4",
        "iphttps",
        "ip-https",
        "kernel debug",
        "wi-fi direct virtual",
        "bluetooth device",
        "npcap loopback",
    ];
    fields
        .iter()
        .any(|f| noisy_markers.iter().any(|m| f.contains(m)))
}

/// Stabilizes IPv6 addresses to their `/64` prefix when `mask_v6_64` is true (used across all
/// macOS/Unix interfaces including `utun*`, and non-tunnel Windows adapters).
#[cfg(any(unix, target_os = "windows", test, feature = "test-support"))]
pub(super) fn format_stable_ip_for_fp(ip: IpAddr, mask_v6_64: bool) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if mask_v6_64 {
                let seg = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", seg[0], seg[1], seg[2], seg[3])
            } else {
                v6.to_string()
            }
        }
    }
}

/// Extracts the fast default-UDP-route + upstream portion of a fingerprint so non-default-route
/// `dns:` and `if:` jitter does not falsely look like a default route drop.
pub(super) fn default_udp_route_changed(old_fp: &str, new_fp: &str) -> bool {
    match (
        old_fp
            .split_once("|dns:")
            .and_then(|(u, r)| r.split_once("|upstream:").map(|(_, up)| (u, up))),
        new_fp
            .split_once("|dns:")
            .and_then(|(u, r)| r.split_once("|upstream:").map(|(_, up)| (u, up))),
    ) {
        (Some(a), Some(b)) => a != b,
        _ => old_fp != new_fp,
    }
}

pub(super) fn is_default_udp_route_dropped(fp: &str) -> bool {
    let Some((udp, _)) = fp.split_once("|dns:") else {
        return false;
    };
    let mut parts = udp.split('|');
    let ip_cf = parts.next().unwrap_or("none");
    let ip_dns = parts.next().unwrap_or("none");
    let ip_v6 = parts.next().unwrap_or("none");
    ip_cf == "none" && ip_dns == "none" && ip_v6 == "none"
}

#[cfg(any(unix, test, feature = "test-support"))]
fn utun_dropped(prev_str: &str, cur_entries: &[String]) -> bool {
    if prev_str.is_empty() {
        return false;
    }
    let cur_ifaces: std::collections::HashSet<&str> = cur_entries
        .iter()
        .filter_map(|e| e.split_once('=').map(|(name, _)| name))
        .collect();
    for prev_entry in prev_str.split(',').filter(|s| !s.is_empty()) {
        let Some((name, ip)) = prev_entry.split_once('=') else {
            continue;
        };
        if !cur_ifaces.contains(name) {
            return true;
        }
        if !ip.contains(':') && !cur_entries.iter().any(|c| c == prev_entry) {
            return true;
        }
    }
    false
}

#[cfg(any(unix, test, feature = "test-support"))]
pub(super) fn stabilize_non_default_utun_entries_in(
    st: &mut UtunDebounceState,
    udp_sig: &str,
    default_entries: Vec<String>,
    non_default_utun: Vec<String>,
    now: Instant,
) -> String {
    let mut entries = default_entries;
    let non_default_str = non_default_utun.join(",");
    let accepted = if st.last_udp_sig != udp_sig {
        st.last_udp_sig = udp_sig.to_string();
        st.stable_non_default = non_default_str;
        st.candidate_non_default = None;
        st.stable_non_default.clone()
    } else if non_default_str == st.stable_non_default {
        st.candidate_non_default = None;
        st.stable_non_default.clone()
    } else if utun_dropped(&st.stable_non_default, &non_default_utun) {
        // Asymmetric fail-closed: surface a dropped utun interface or IPv4 immediately (0ms).
        st.stable_non_default = non_default_str;
        st.candidate_non_default = None;
        st.stable_non_default.clone()
    } else {
        match &st.candidate_non_default {
            Some((cand, since)) if *cand == non_default_str => {
                if now.saturating_duration_since(*since) >= UTUN_DEBOUNCE_WINDOW {
                    st.stable_non_default = non_default_str;
                    st.candidate_non_default = None;
                }
            }
            _ => {
                st.candidate_non_default = Some((non_default_str, now));
            }
        }
        st.stable_non_default.clone()
    };
    if !accepted.is_empty() {
        entries.extend(accepted.split(',').map(str::to_string));
    }
    entries.sort();
    entries.dedup();
    if entries.is_empty() {
        "none".to_string()
    } else {
        entries.join(",")
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn stabilize_non_default_utun_for_test(
    st: &mut UtunDebounceState,
    udp_sig: &str,
    default_entries: Vec<String>,
    non_default_utun: Vec<String>,
    now: Instant,
) -> String {
    stabilize_non_default_utun_entries_in(st, udp_sig, default_entries, non_default_utun, now)
}

#[cfg(unix)]
fn stabilize_non_default_utun_entries(
    udp_sig: &str,
    default_entries: Vec<String>,
    non_default_utun: Vec<String>,
) -> String {
    let lock = UTUN_DEBOUNCE.get_or_init(|| Mutex::new(UtunDebounceState::default()));
    let mut st = lock.lock().unwrap_or_else(|p| p.into_inner());
    stabilize_non_default_utun_entries_in(
        &mut st,
        udp_sig,
        default_entries,
        non_default_utun,
        Instant::now(),
    )
}

#[cfg(unix)]
fn query_unix_interfaces_signature(udp_ips: &[&str], udp_sig: &str) -> String {
    struct IfAddrsGuard(*mut libc::ifaddrs);
    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { libc::freeifaddrs(self.0) };
            }
        }
    }

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return "none".to_string();
    }
    let _guard = IfAddrsGuard(ifap);

    let mut default_entries: Vec<String> = Vec::new();
    let mut non_default_utun: Vec<String> = Vec::new();
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        let flags = ifa.ifa_flags;
        let is_up_running = (flags & (libc::IFF_UP as u32)) != 0
            && (flags & (libc::IFF_RUNNING as u32)) != 0
            && (flags & (libc::IFF_LOOPBACK as u32)) == 0;
        if !is_up_running || ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }

        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        let ip: Option<IpAddr> = match family {
            libc::AF_INET => {
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let v4 = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                (!v4.is_link_local()).then_some(IpAddr::V4(v4))
            }
            libc::AF_INET6 => {
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                (!addr.is_unicast_link_local()).then_some(IpAddr::V6(addr))
            }
            _ => None,
        };
        let Some(ip) = ip.filter(|addr| !addr.is_loopback() && !addr.is_unspecified()) else {
            continue;
        };

        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        let stable_ip = format_stable_ip_for_fp(ip, true);
        let raw_ip = ip.to_string();
        let is_default_ip = udp_ips
            .iter()
            .any(|u| *u != "none" && (*u == raw_ip || *u == stable_ip));
        let entry = format!("{name}={stable_ip}");
        if name.starts_with("utun") && !is_default_ip {
            non_default_utun.push(entry);
        } else {
            default_entries.push(entry);
        }
    }
    non_default_utun.sort();
    non_default_utun.dedup();
    stabilize_non_default_utun_entries(udp_sig, default_entries, non_default_utun)
}

#[cfg(any(target_os = "windows", test, feature = "test-support"))]
pub fn format_windows_interfaces_signature(
    adapters: &[crate::win_native::network::AdapterInfo],
) -> String {
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    let mut entries: Vec<String> = Vec::new();
    for adapter in adapters {
        if !adapter.is_up
            || adapter.if_type == IF_TYPE_SOFTWARE_LOOPBACK
            || is_noisy_windows_adapter(adapter)
        {
            continue;
        }
        let name = {
            let trimmed = adapter.adapter_name.trim();
            if trimmed.is_empty() {
                adapter.friendly_name.trim()
            } else {
                trimmed
            }
        };
        if name.is_empty() {
            continue;
        }
        let is_tunnel = is_tunnel_interface_name(name)
            || is_tunnel_interface_name(&adapter.friendly_name)
            || is_tunnel_interface_name(&adapter.description)
            || adapter.if_type == 53
            || adapter.if_type == 131;
        for raw in adapter.ipv4_addrs.iter().chain(adapter.ipv6_addrs.iter()) {
            let Ok(ip) = raw.trim().parse::<IpAddr>() else {
                continue;
            };
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            if let IpAddr::V4(v4) = ip
                && v4.is_link_local()
            {
                continue;
            }
            if let IpAddr::V6(v6) = ip
                && v6.is_unicast_link_local()
            {
                continue;
            }
            let stable_ip = format_stable_ip_for_fp(ip, !is_tunnel);
            entries.push(format!("{name}={stable_ip}"));
        }
    }
    entries.sort();
    entries.dedup();
    if entries.is_empty() {
        "none".to_string()
    } else {
        entries.join(",")
    }
}

#[cfg(target_os = "windows")]
fn format_windows_dns_signature(adapters: &[crate::win_native::network::AdapterInfo]) -> String {
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    let mut ips: Vec<String> = Vec::new();
    for adapter in adapters {
        if !adapter.is_up
            || adapter.if_type == IF_TYPE_SOFTWARE_LOOPBACK
            || is_noisy_windows_adapter(adapter)
        {
            continue;
        }
        for raw in &adapter.dns_servers {
            let Ok(ip) = raw.trim().parse::<IpAddr>() else {
                continue;
            };
            if !ip.is_unspecified() {
                ips.push(ip.to_string());
            }
        }
    }
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        "none".to_string()
    } else {
        ips.join(",")
    }
}

#[cfg(not(target_os = "windows"))]
fn query_system_dns_signature() -> String {
    let Ok((cfg, _)) = hickory_resolver::system_conf::read_system_conf() else {
        return "none".to_string();
    };
    let mut ips: Vec<String> = cfg
        .name_servers()
        .iter()
        .map(|ns| ns.ip.to_string())
        .collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        "none".to_string()
    } else {
        ips.join(",")
    }
}

pub(super) fn cached_interfaces_and_dns(udp_ips: &[&str], udp_sig: &str) -> (String, String) {
    let now = Instant::now();
    #[cfg(target_os = "windows")]
    {
        let _ = (udp_ips, udp_sig);
        let iface_lock = IFACE_CACHE.get_or_init(|| Mutex::new(CachedSig::default()));
        let dns_lock = DNS_CACHE.get_or_init(|| Mutex::new(CachedSig::default()));
        let iface_stale = iface_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .updated_at
            .is_none_or(|t| now.saturating_duration_since(t) >= IFACE_CACHE_TTL);
        let dns_stale = dns_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .updated_at
            .is_none_or(|t| now.saturating_duration_since(t) >= DNS_CACHE_TTL);
        if (iface_stale || dns_stale)
            && let Ok(adapters) = crate::win_native::network::get_adapters_addresses()
        {
            if iface_stale {
                let mut ic = iface_lock.lock().unwrap_or_else(|p| p.into_inner());
                ic.value = format_windows_interfaces_signature(&adapters);
                ic.updated_at = Some(now);
            }
            if dns_stale {
                let mut dc = dns_lock.lock().unwrap_or_else(|p| p.into_inner());
                dc.value = format_windows_dns_signature(&adapters);
                dc.updated_at = Some(now);
            }
        }
        let if_sig = iface_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .value
            .clone();
        let dns_sig = dns_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .value
            .clone();
        (
            if if_sig.is_empty() {
                "none".to_string()
            } else {
                if_sig
            },
            if dns_sig.is_empty() {
                "none".to_string()
            } else {
                dns_sig
            },
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        let if_sig = {
            let lock = IFACE_CACHE.get_or_init(|| Mutex::new(CachedSig::default()));
            let mut c = lock.lock().unwrap_or_else(|p| p.into_inner());
            if c.updated_at
                .is_none_or(|t| now.saturating_duration_since(t) >= IFACE_CACHE_TTL)
            {
                #[cfg(unix)]
                {
                    c.value = query_unix_interfaces_signature(udp_ips, udp_sig);
                }
                #[cfg(not(unix))]
                {
                    let _ = (udp_ips, udp_sig);
                    c.value = "none".to_string();
                }
                c.updated_at = Some(now);
            }
            c.value.clone()
        };
        let dns_sig = {
            let lock = DNS_CACHE.get_or_init(|| Mutex::new(CachedSig::default()));
            let mut c = lock.lock().unwrap_or_else(|p| p.into_inner());
            if c.updated_at
                .is_none_or(|t| now.saturating_duration_since(t) >= DNS_CACHE_TTL)
            {
                c.value = query_system_dns_signature();
                c.updated_at = Some(now);
            }
            c.value.clone()
        };
        (if_sig, dns_sig)
    }
}
