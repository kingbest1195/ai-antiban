//! The single seam between Zastava and the operating system's proxy-related settings.
//!
//! `trait Platform` covers `networksetup` / `scutil` (macOS), `reg` + WinINet (Windows) and
//! `launchctl` (macOS user environment). `RealPlatform` is the only code that may start those
//! programs; every one of its methods checks [`crate::sysproxy::os_effects_enabled`] first (dry-run =
//! no-op that is counted, reads fail with `DryRun` so nobody mistakes a blank for a real value).
//! `FakePlatform` (tests / `test-support`) keeps everything in memory and counts OS writes.
//!
//! Values (PAC URLs, proxy hosts, credentials) are never printed: `Debug` of every value type is
//! redacted and `PlatformError` carries only an operation name.

mod diagnostics;
mod dns;
mod macos;
mod real;
mod windows;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

pub use diagnostics::{
    clear_last_os_error, collect_os_diagnostic_snapshot, last_os_error, write_text_to_clipboard,
};
pub use dns::{
    DnsDict, SetupDnsEntry, extract_active_service_ids, has_physical_temp_dns_override,
    has_physical_temp_dns_override_active, parse_getdnsservers, parse_getsearchdomains,
    parse_scutil_dns,
};
pub use macos::{
    classify_service, classify_services, is_admin_auth_error, is_virtual_tunnel_device,
    parse_autoproxy, parse_bypass_domains, parse_nc_list, parse_scutil_proxy, parse_service_order,
    parse_webproxy,
};
pub use real::RealPlatform;
pub use windows::{parse_reg_query_names, parse_reg_query_value, reg_read_outcome};

/// Stable identity of a macOS network service: device + hardware port, not the (localizable,
/// renameable) display name. Equality and the journal key use `key()` only.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceId {
    pub device: String,
    pub hardware_port: String,
    /// Display name, used to invoke `networksetup`; may change between runs.
    pub name: String,
    /// `false` for services the user disabled.
    pub enabled: bool,
}

impl ServiceId {
    pub fn new(device: &str, hardware_port: &str, name: &str) -> Self {
        Self {
            device: device.to_string(),
            hardware_port: hardware_port.to_string(),
            name: name.to_string(),
            enabled: true,
        }
    }

    /// Stable key. Services without a device (VPN) fall back to port + name.
    pub fn key(&self) -> String {
        if self.device.is_empty() {
            format!("svc:{}/{}", self.hardware_port, self.name)
        } else {
            format!("dev:{}/{}", self.device, self.hardware_port)
        }
    }
}

impl PartialEq for ServiceId {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}
impl Eq for ServiceId {}

impl fmt::Debug for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceId({})", self.key())
    }
}

/// Auto Proxy (PAC) state of a service. `None` = the key is absent / unknown.
/// When passed to `set_pac`: `url: Some("")` clears the URL, `None` leaves it untouched;
/// `enabled: None` leaves the flag untouched.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PacState {
    pub url: Option<String>,
    pub enabled: Option<bool>,
}

impl fmt::Debug for PacState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PacState(url: {}, enabled: {:?})",
            redact(self.url.is_some()),
            self.enabled
        )
    }
}

/// One explicit proxy (web or secure web) of a service. `None` = absent; `Some("")` / `Some(0)`
/// are real values and differ from absence.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProxyEndpoint {
    pub enabled: Option<bool>,
    pub server: Option<String>,
    pub port: Option<u16>,
    /// `Authenticated Proxy Enabled` as reported by the OS. Read-only: Zastava never writes
    /// credentials and a restore never touches this flag.
    #[serde(default)]
    pub authenticated: Option<bool>,
}

impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyEndpoint(enabled: {:?}, <redacted>)", self.enabled)
    }
}

/// Explicit HTTP and HTTPS upstream of a service; kept apart, never merged into one.
#[derive(Clone, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
pub struct ChainState {
    pub http: ProxyEndpoint,
    pub https: ProxyEndpoint,
}

/// What a network service is, for the one rule that matters here: Zastava writes proxy settings
/// into physical services only. A VPN service (a NetworkExtension / PPP / IPSec connection) is
/// reconfigured by the system when anybody writes into it, and a connected tunnel can drop.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServiceKind {
    /// Wi-Fi, Ethernet, a USB or Thunderbolt adapter: has a device and is not a connection service.
    Physical,
    /// A VPN connection service. `connected` is `false` only when the system says "Disconnected";
    /// every other state (and an unknown one) counts as connected.
    Vpn { connected: bool },
    /// The type could not be established (the connection list is unreadable). Treated as a VPN.
    Unknown,
}

impl ServiceKind {
    /// The only kind Zastava writes into.
    pub fn is_physical(self) -> bool {
        self == ServiceKind::Physical
    }

    /// A VPN service that is surely not connected: the one case where an old Zastava leftover may
    /// be cleared without risk to a tunnel.
    pub fn is_idle_vpn(self) -> bool {
        self == ServiceKind::Vpn { connected: false }
    }
}

/// One entry of `scutil --nc list`: a connection service and whether it is up.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VpnConnection {
    /// The user-visible service name; the same string `networksetup` uses.
    pub name: String,
    /// `false` only for "Disconnected".
    pub connected: bool,
}

/// The proxy the system actually hands to applications (`scutil --proxy`): the global dictionary
/// that follows the primary service, so it shows whether a VPN overrides what is set on Wi-Fi.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct EffectiveProxy {
    pub pac_enabled: Option<bool>,
    pub pac_url: Option<String>,
}

impl fmt::Debug for EffectiveProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EffectiveProxy(pac_enabled: {:?}, url: {})",
            self.pac_enabled,
            redact(self.pac_url.is_some())
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RegKind {
    Sz,
    ExpandSz,
    Dword,
}

/// A registry value with its exact type. `Dword` data is the canonical decimal string.
/// "No value" is expressed as `Option<RegValue>::None`, never as an empty `data`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegValue {
    pub kind: RegKind,
    pub data: String,
}

impl RegValue {
    pub fn sz(s: &str) -> Self {
        Self {
            kind: RegKind::Sz,
            data: s.to_string(),
        }
    }
    pub fn expand_sz(s: &str) -> Self {
        Self {
            kind: RegKind::ExpandSz,
            data: s.to_string(),
        }
    }
    pub fn dword(n: u32) -> Self {
        Self {
            kind: RegKind::Dword,
            data: n.to_string(),
        }
    }
}

impl fmt::Debug for RegValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegValue({:?}, <redacted>)", self.kind)
    }
}

fn redact(present: bool) -> &'static str {
    if present { "<redacted>" } else { "None" }
}

/// Failure of a platform call. Carries only the operation name, never output or values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlatformError {
    /// OS dry-run mode: nothing was read or written.
    DryRun,
    /// Not available on this OS / value type is not safely manageable.
    Unsupported(&'static str),
    /// The service / value does not exist any more.
    NotFound(&'static str),
    /// macOS authorization / admin password is required (`networksetup` `-60005`, etc.).
    AdminAuthRequired(&'static str),
    /// The external program or API call failed.
    Failed(&'static str),
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformError::DryRun => write!(f, "OS dry-run mode"),
            PlatformError::Unsupported(op) => write!(f, "{op}: unsupported"),
            PlatformError::NotFound(op) => write!(f, "{op}: not found"),
            PlatformError::AdminAuthRequired(op) => write!(f, "{op}: admin auth required"),
            PlatformError::Failed(op) => write!(f, "{op}: failed"),
        }
    }
}

impl std::error::Error for PlatformError {}

pub type PResult<T> = Result<T, PlatformError>;

/// Everything Zastava needs from the OS. Implemented by `RealPlatform` and `FakePlatform`.
pub trait Platform: Send + Sync {
    /// All network services (macOS), including disabled ones (`enabled == false`).
    fn list_services(&self) -> PResult<Vec<ServiceId>>;
    fn get_pac(&self, svc: &ServiceId) -> PResult<PacState>;
    fn set_pac(&self, svc: &ServiceId, pac: &PacState) -> PResult<()>;
    fn get_chain(&self, svc: &ServiceId) -> PResult<ChainState>;
    fn set_chain(&self, svc: &ServiceId, chain: &ChainState) -> PResult<()>;
    /// Proxy bypass domains of a service (`networksetup -getproxybypassdomains`); empty = none.
    fn get_proxy_bypass_domains(&self, svc: &ServiceId) -> PResult<Vec<String>>;
    /// Replaces the bypass domains of a service; an empty list means "none". Writes only when the
    /// list really differs from what the service holds.
    fn set_proxy_bypass_domains(&self, svc: &ServiceId, domains: &[String]) -> PResult<()>;
    /// Read-only: does an active VPN keep temporary DNS settings that differ from the saved ones?
    fn temp_dns_overrides(&self) -> PResult<bool>;
    /// Read-only: the connection services (`scutil --nc list`) with their state.
    fn vpn_connections(&self) -> PResult<Vec<VpnConnection>>;
    /// Read-only: the proxy the system effectively applies now (`scutil --proxy`).
    fn effective_proxy(&self) -> PResult<EffectiveProxy>;
    /// Classifies one service. See [`classify_service`] for the rule.
    fn service_kind(&self, svc: &ServiceId) -> ServiceKind {
        let nc = self.vpn_connections().ok();
        classify_service(svc, nc.as_deref())
    }
    /// User environment: `launchctl getenv` (macOS) / `HKCU\Environment` (Windows).
    fn get_user_env(&self, key: &str) -> PResult<Option<String>>;
    fn set_user_env(&self, key: &str, value: &str) -> PResult<()>;
    fn unset_user_env(&self, key: &str) -> PResult<()>;
    /// Names of all user environment variables where the OS can list them (`HKCU\Environment`);
    /// `Unsupported` where it cannot (launchd has no listing).
    fn list_user_env_names(&self) -> PResult<Vec<String>>;
    /// WinINet values under `HKCU\...\Internet Settings`.
    fn get_inet(&self, name: &str) -> PResult<Option<RegValue>>;
    fn set_inet(&self, name: &str, value: &RegValue) -> PResult<()>;
    fn delete_inet(&self, name: &str) -> PResult<()>;
    fn notify_inet_refresh(&self) -> PResult<()>;
    fn broadcast_env_change(&self) -> PResult<()>;
    /// Best-effort exclusion of a directory from Time Machine (`tmutil addexclusion`).
    fn exclude_from_backup(&self, path: &Path) -> PResult<()>;
}

#[cfg(test)]
#[path = "../platform_tests.rs"]
mod tests;

#[cfg(any(test, feature = "test-support"))]
mod fakes;
#[cfg(any(test, feature = "test-support"))]
pub use fakes::{FakePlatform, PlatOp};

#[cfg(test)]
use real::{dry_run_gate, write_gate};
