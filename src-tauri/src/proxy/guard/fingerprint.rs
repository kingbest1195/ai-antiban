//! Fast (< 0.1ms) in-process route, interface, and DNS fingerprint helpers (zero subprocesses).

#[cfg(unix)]
use std::ffi::CStr;
#[cfg(any(unix, target_os = "windows", test, feature = "test-support"))]
use std::net::IpAddr;
#[cfg(unix)]
use std::net::{Ipv4Addr, Ipv6Addr};

fn udp_route_ip(bind: &str, target: &str) -> String {
    std::net::UdpSocket::bind(bind)
        .ok()
        .and_then(|s| s.connect(target).ok().and_then(|_| s.local_addr().ok()))
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn system_dns_signature() -> String {
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

#[cfg(unix)]
fn active_interfaces_signature() -> String {
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

    let mut entries: Vec<String> = Vec::new();
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
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))))
            }
            libc::AF_INET6 => {
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                if addr.is_unicast_link_local() {
                    None
                } else {
                    Some(IpAddr::V6(addr))
                }
            }
            _ => None,
        };
        let Some(ip) = ip.filter(|addr| !addr.is_loopback() && !addr.is_unspecified()) else {
            continue;
        };

        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        entries.push(format!("{name}={ip}"));
    }

    entries.sort();
    entries.dedup();
    if entries.is_empty() {
        "none".to_string()
    } else {
        entries.join(",")
    }
}

#[cfg(any(target_os = "windows", test, feature = "test-support"))]
pub fn format_windows_interfaces_signature(
    adapters: &[crate::win_native::network::AdapterInfo],
) -> String {
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    let mut entries: Vec<String> = Vec::new();
    for adapter in adapters {
        if !adapter.is_up || adapter.if_type == IF_TYPE_SOFTWARE_LOOPBACK {
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
        for raw in adapter.ipv4_addrs.iter().chain(adapter.ipv6_addrs.iter()) {
            let Ok(ip) = raw.trim().parse::<IpAddr>() else {
                continue;
            };
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            if let IpAddr::V6(v6) = ip
                && v6.is_unicast_link_local()
            {
                continue;
            }
            entries.push(format!("{name}={ip}"));
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
fn active_interfaces_signature() -> String {
    match crate::win_native::network::get_adapters_addresses() {
        Ok(adapters) => format_windows_interfaces_signature(&adapters),
        Err(_) => "none".to_string(),
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn active_interfaces_signature() -> String {
    "none".to_string()
}

/// Computes the local default-route, active-interface (`utun`/tunnel), and DNS fingerprint
/// in < 0.1ms using in-process lookups without spawning any subprocesses or transmitting packets.
pub fn compute_local_route_fingerprint(upstream_key: Option<&str>) -> String {
    let ip_cf = udp_route_ip("0.0.0.0:0", "1.1.1.1:80");
    let ip_dns = udp_route_ip("0.0.0.0:0", "8.8.8.8:53");
    let ip_v6 = udp_route_ip("[::]:0", "[2606:4700:4700::1111]:80");
    let dns_sig = system_dns_signature();
    let if_sig = active_interfaces_signature();
    format!(
        "{ip_cf}|{ip_dns}|{ip_v6}|dns:{dns_sig}|if:{if_sig}|upstream:{}",
        upstream_key.unwrap_or("")
    )
}

/// Tracks the last route/proxy state synced via `refresh_if_services_changed()` so steady-state
/// ticks never re-open the ownership journal or rewrite WinINet/browser policies every 5 seconds.
/// When `os_pac_deferred` is set (macOS temporary VPN DNS), retries at most once every 5s;
/// otherwise performs a low-frequency self-heal & newly-installed-browser check every 120s.
#[derive(Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct PeriodicSysproxySync {
    last_route_fp: Option<String>,
    last_active: bool,
    last_refresh_at: Option<std::time::Instant>,
}

impl PeriodicSysproxySync {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) const DEFERRED_RETRY_INTERVAL: std::time::Duration =
        std::time::Duration::from_secs(5);
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) const SELF_HEAL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(120);

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn should_refresh(
        &mut self,
        route_fp: &str,
        sysproxy_active: bool,
        os_pac_deferred: bool,
    ) -> bool {
        self.should_refresh_at(
            route_fp,
            sysproxy_active,
            os_pac_deferred,
            std::time::Instant::now(),
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn should_refresh_at(
        &mut self,
        route_fp: &str,
        sysproxy_active: bool,
        os_pac_deferred: bool,
        now: std::time::Instant,
    ) -> bool {
        if !sysproxy_active {
            self.last_active = false;
            self.last_route_fp = None;
            self.last_refresh_at = None;
            return false;
        }
        let route_or_active_changed =
            !self.last_active || self.last_route_fp.as_deref() != Some(route_fp);
        let interval = if os_pac_deferred {
            Self::DEFERRED_RETRY_INTERVAL
        } else {
            Self::SELF_HEAL_INTERVAL
        };
        let timer_due = self
            .last_refresh_at
            .is_none_or(|t| now.saturating_duration_since(t) >= interval);
        let refresh = route_or_active_changed || timer_due;
        if refresh {
            self.last_active = true;
            self.last_route_fp = Some(route_fp.to_string());
            self.last_refresh_at = Some(now);
        }
        refresh
    }
}
