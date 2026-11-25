//! Fast (< 0.1ms) in-process route, interface, and DNS fingerprint helpers (zero subprocesses).

#[cfg(any(unix, target_os = "windows", test, feature = "test-support"))]
use std::net::IpAddr;

#[cfg(any(target_os = "windows", test, feature = "test-support"))]
pub use super::fingerprint_os::format_windows_interfaces_signature;
use super::fingerprint_os::{cached_interfaces_and_dns, format_stable_ip_for_fp};
pub(super) use super::fingerprint_os::{default_udp_route_changed, is_default_udp_route_dropped};

fn udp_route_ip(bind: &str, target: &str) -> String {
    std::net::UdpSocket::bind(bind)
        .ok()
        .and_then(|s| s.connect(target).ok().and_then(|_| s.local_addr().ok()))
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "none".to_string())
}

/// Computes the local default-route, active-interface (`utun`/tunnel), and DNS fingerprint
/// using cached OS interface/DNS lookups (>= 1000ms / >= 2000ms) and fast 250ms UDP route checks.
pub fn compute_local_route_fingerprint(upstream_key: Option<&str>) -> String {
    let ip_cf = udp_route_ip("0.0.0.0:0", "1.1.1.1:80");
    let ip_dns = udp_route_ip("0.0.0.0:0", "8.8.8.8:53");
    let ip_v6_raw = udp_route_ip("[::]:0", "[2606:4700:4700::1111]:80");
    let ip_v6 = if ip_cf == "none" {
        ip_v6_raw.clone()
    } else if let Ok(IpAddr::V6(v6)) = ip_v6_raw.parse::<IpAddr>() {
        format_stable_ip_for_fp(IpAddr::V6(v6), true)
    } else {
        ip_v6_raw.clone()
    };
    let udp_sig = format!("{ip_cf}|{ip_dns}|{ip_v6}");
    let (if_sig, dns_sig) = cached_interfaces_and_dns(&[&ip_cf, &ip_dns, &ip_v6_raw], &udp_sig);
    format!(
        "{udp_sig}|dns:{dns_sig}|if:{if_sig}|upstream:{}",
        upstream_key.unwrap_or("")
    )
}

/// Tracks the last route/proxy state synced via `refresh_if_services_changed()` so steady-state
/// ticks never re-open the ownership journal or rewrite WinINet/browser policies every 5 seconds.
/// When `os_pac_deferred` is set (macOS temporary VPN DNS), retries at most once every 5s;
/// otherwise performs a low-frequency self-heal & newly-installed-browser check every 120s.
#[derive(Default)]
pub(super) struct PeriodicSysproxySync {
    last_route_fp: Option<String>,
    last_active: bool,
    last_refresh_at: Option<std::time::Instant>,
}

impl PeriodicSysproxySync {
    pub(super) const DEFERRED_RETRY_INTERVAL: std::time::Duration =
        std::time::Duration::from_secs(5);
    pub(super) const SELF_HEAL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(120);

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
