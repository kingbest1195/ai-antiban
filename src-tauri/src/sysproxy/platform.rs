//! The single seam between Zastava and the operating system's proxy-related settings.
//!
//! `trait Platform` covers `networksetup` / `scutil` (macOS), `reg` + WinINet (Windows) and
//! `launchctl` (macOS user environment). `RealPlatform` is the only code that may start those
//! programs; every one of its methods checks [`super::os_effects_enabled`] first (dry-run =
//! no-op that is counted, reads fail with `DryRun` so nobody mistakes a blank for a real value).
//! `FakePlatform` (tests / `test-support`) keeps everything in memory and counts OS writes.
//!
//! Values (PAC URLs, proxy hosts, credentials) are never printed: `Debug` of every value type is
//! redacted and `PlatformError` carries only an operation name.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

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

// ---------------------------------------------------------------------------------------------
// Pure parsers (testable on any OS)
// ---------------------------------------------------------------------------------------------

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
pub fn classify_services(p: &dyn Platform, services: &[ServiceId]) -> Vec<(ServiceId, ServiceKind)> {
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

/// `reg query <key> /v <name>` -> value with exact type. `None` = no such value.
/// Not used by `RealPlatform` any more (it reads the registry through the API, see
/// [`reg_read_outcome`]): `reg.exe` prints in the OEM code page.
pub fn parse_reg_query_value(output: &str, name: &str) -> Option<RegValue> {
    for line in output.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix(name) else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let rest = rest.trim_start();
        for (tag, kind) in [
            ("REG_EXPAND_SZ", RegKind::ExpandSz),
            ("REG_SZ", RegKind::Sz),
            ("REG_DWORD", RegKind::Dword),
        ] {
            if let Some(data) = rest.strip_prefix(tag) {
                if !(data.is_empty() || data.starts_with(char::is_whitespace)) {
                    continue;
                }
                let data = data
                    .strip_prefix("    ")
                    .unwrap_or_else(|| data.trim_start());
                return match kind {
                    RegKind::Dword => {
                        let d = data.trim();
                        let n = d
                            .strip_prefix("0x")
                            .or_else(|| d.strip_prefix("0X"))
                            .map(|h| u32::from_str_radix(h, 16))
                            .unwrap_or_else(|| d.parse::<u32>());
                        n.ok().map(RegValue::dword)
                    }
                    _ => Some(RegValue {
                        kind,
                        data: data.to_string(),
                    }),
                };
            }
        }
    }
    None
}

/// `reg query <key>` (all values) -> value names, whatever their type.
pub fn parse_reg_query_names(output: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in output.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        // Value lines are indented; key lines (`HKEY_...`) are not.
        if !line.starts_with(char::is_whitespace) {
            continue;
        }
        let t = line.trim_start();
        let mut it = t.split_whitespace();
        let (Some(name), Some(tag)) = (it.next(), it.next()) else {
            continue;
        };
        if tag.starts_with("REG_") {
            names.push(name.to_string());
        }
    }
    names
}

// Registry value types and status codes of the Windows API (winerror.h / winnt.h).
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const ERROR_SUCCESS: u32 = 0;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;

/// UTF-16LE bytes -> text. `None` for an odd length or an unpaired surrogate: such a string cannot
/// be written back unchanged, so it is never decoded lossily.
fn utf16le_to_string(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Turns the raw answer of the registry API (`RegGetValueW`: status, value type, data) into a
/// [`RegValue`] with its exact type. `Ok(None)` is "no such value" and only the two "not found"
/// codes mean that; any other failure is an error, so a failed read is never taken for an absent
/// value (a restore would delete what it should not). `REG_SZ` / `REG_EXPAND_SZ` / `REG_DWORD`
/// are the types Zastava can write back unchanged; everything else (`REG_BINARY`, `REG_MULTI_SZ`,
/// `REG_QWORD`, ...) is `Unsupported`.
pub fn reg_read_outcome(
    status: u32,
    kind: u32,
    data: &[u8],
    op: &'static str,
) -> PResult<Option<RegValue>> {
    match status {
        ERROR_SUCCESS => {}
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => return Ok(None),
        _ => return Err(PlatformError::Failed(op)),
    }
    match kind {
        REG_SZ | REG_EXPAND_SZ => {
            let text = utf16le_to_string(data).ok_or(PlatformError::Unsupported(op))?;
            // The API terminates strings with NUL; a stored value may carry extra ones.
            let text = text.trim_end_matches('\0').to_string();
            Ok(Some(RegValue {
                kind: if kind == REG_SZ {
                    RegKind::Sz
                } else {
                    RegKind::ExpandSz
                },
                data: text,
            }))
        }
        REG_DWORD => {
            let bytes: [u8; 4] = data
                .try_into()
                .map_err(|_| PlatformError::Unsupported(op))?;
            Ok(Some(RegValue::dword(u32::from_le_bytes(bytes))))
        }
        _ => Err(PlatformError::Unsupported(op)),
    }
}

/// One value of `HKEY_CURRENT_USER\<subkey>`, read through the registry API.
#[cfg(target_os = "windows")]
fn registry_get(subkey: &str, name: &str, op: &'static str) -> PResult<Option<RegValue>> {
    let r = ffi::reg_get_hkcu(subkey, name);
    reg_read_outcome(r.status, r.kind, &r.data, op)
}

#[cfg(not(target_os = "windows"))]
fn registry_get(_subkey: &str, _name: &str, op: &'static str) -> PResult<Option<RegValue>> {
    Err(PlatformError::Unsupported(op))
}

/// Names of all values of `HKEY_CURRENT_USER\<subkey>`, whatever their type. A name that is not
/// valid UTF-16 is left out (it cannot be one of ours).
#[cfg(target_os = "windows")]
fn registry_names(subkey: &str, op: &'static str) -> PResult<Vec<String>> {
    let names = ffi::reg_names_hkcu(subkey).map_err(|_| PlatformError::Failed(op))?;
    Ok(names
        .into_iter()
        .filter_map(|n| String::from_utf16(&n).ok())
        .collect())
}

#[cfg(not(target_os = "windows"))]
fn registry_names(_subkey: &str, op: &'static str) -> PResult<Vec<String>> {
    Err(PlatformError::Unsupported(op))
}

/// Parsed `scutil` dictionary of `Setup:/Network/Service/<id>/DNS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDict {
    pub servers: Vec<String>,
    pub search_domains: Vec<String>,
    /// An unrecognised key other than `ServerAddresses` / `SearchDomains` / benign metadata was present.
    pub unknown_fields: bool,
}

fn is_benign_scutil_dns_key(key: &str) -> bool {
    matches!(
        key,
        "DomainName" | "ConfirmedServiceID" | "InterfaceName" | "SupplementalMatchDomains"
    ) || key.starts_with('_')
}

/// Parses `scutil` `show` output. Key order inside the dictionary does not matter.
/// Tolerates benign metadata keys (`DomainName`, `ConfirmedServiceID`, `InterfaceName`,
/// `SupplementalMatchDomains`, and `_`-prefixed keys).
pub fn parse_scutil_dns(output: &str) -> DnsDict {
    let mut d = DnsDict {
        servers: vec![],
        search_domains: vec![],
        unknown_fields: false,
    };
    let mut current: Option<&'static str> = None;
    let mut sub_depth: usize = 0;
    for line in output.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("<dictionary>") {
            continue;
        }
        if t == "}" {
            if sub_depth > 0 {
                sub_depth -= 1;
                if sub_depth == 0 {
                    current = None;
                }
            }
            continue;
        }
        if sub_depth > 0 {
            if t.ends_with('{') {
                sub_depth += 1;
                continue;
            }
            if sub_depth == 1
                && let Some((k, v)) = t.split_once(" : ")
            {
                let k = k.trim();
                let v = v.trim();
                if k.chars().all(|c| c.is_ascii_digit()) {
                    match current {
                        Some("servers") => d.servers.push(v.to_string()),
                        Some("domains") => d.search_domains.push(v.to_string()),
                        Some("ignored") | Some("unknown") => {}
                        _ => d.unknown_fields = true,
                    }
                } else if !matches!(current, Some("ignored") | Some("unknown")) {
                    d.unknown_fields = true;
                }
            }
            continue;
        }
        if let Some((k, v)) = t.split_once(" : ") {
            let k = k.trim();
            let v = v.trim();
            if v.starts_with("<array>") && v.ends_with('{') {
                current = match k {
                    "ServerAddresses" => Some("servers"),
                    "SearchDomains" => Some("domains"),
                    _ if is_benign_scutil_dns_key(k) => Some("ignored"),
                    _ => {
                        d.unknown_fields = true;
                        Some("unknown")
                    }
                };
                sub_depth = 1;
            } else if is_benign_scutil_dns_key(k) {
                if v.ends_with('{') {
                    current = Some("ignored");
                    sub_depth = 1;
                }
            } else {
                d.unknown_fields = true;
                if v.ends_with('{') {
                    current = Some("unknown");
                    sub_depth = 1;
                }
            }
        }
    }
    d
}

/// `networksetup -getdnsservers` -> addresses (empty when none are set).
pub fn parse_getdnsservers(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("There aren't any DNS Servers"))
        .map(str::to_string)
        .collect()
}

/// `networksetup -getsearchdomains` -> domains (empty when none are set).
pub fn parse_getsearchdomains(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("There aren't any Search Domains"))
        .map(str::to_string)
        .collect()
}

/// One `Setup:/Network/Service/<id>/DNS` entry paired with its `UserDefinedName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupDnsEntry {
    pub service_id: String,
    pub user_defined_name: Option<String>,
    pub dns: DnsDict,
}

/// Pure evaluation of temporary DNS overrides, scoped strictly to `physical_services` (services
/// Zastava actually modifies). Synthetic/VPN service IDs not matching an enabled physical service
/// are ignored.
pub fn has_physical_temp_dns_override<F>(
    physical_services: &[ServiceId],
    entries: &[SetupDnsEntry],
    mut read_saved_dns: F,
) -> PResult<bool>
where
    F: FnMut(&str) -> PResult<(Vec<String>, Vec<String>)>,
{
    if physical_services.is_empty() {
        return Ok(false);
    }
    for entry in entries {
        let Some(name) = entry.user_defined_name.as_deref() else {
            continue;
        };
        if !physical_services.iter().any(|s| s.name == name) {
            continue;
        }
        if entry.dns.unknown_fields {
            crate::diagnostics::record(
                "sysproxy:dns",
                &format!("temp_dns triggered by service={name}: unknown fields in Setup:/Network/Service/*/DNS"),
            );
            return Ok(true);
        }
        let (mut saved_servers, mut saved_domains) = read_saved_dns(name)?;
        let mut live_servers = entry.dns.servers.clone();
        live_servers.sort();
        saved_servers.sort();
        if live_servers != saved_servers {
            crate::diagnostics::record(
                "sysproxy:dns",
                &format!(
                    "temp_dns triggered by service={name}: live_servers({}) != saved_servers({})",
                    live_servers.len(),
                    saved_servers.len()
                ),
            );
            return Ok(true);
        }
        let mut live_domains = entry.dns.search_domains.clone();
        live_domains.sort();
        saved_domains.sort();
        if live_domains != saved_domains {
            crate::diagnostics::record(
                "sysproxy:dns",
                &format!(
                    "temp_dns triggered by service={name}: live_domains({}) != saved_domains({})",
                    live_domains.len(),
                    saved_domains.len()
                ),
            );
            return Ok(true);
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------------------------
// RealPlatform
// ---------------------------------------------------------------------------------------------

/// `reg add` / `reg delete` spelling of the keys (writes still go through `reg.exe`; its
/// arguments are UTF-16 on the command line, so non-ASCII values survive).
const INET_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const ENV_KEY: &str = r"HKCU\Environment";
/// The same keys below `HKEY_CURRENT_USER`, as the registry API wants them. Reads go through the
/// API: `reg.exe` prints in the OEM code page (cp866 on a Russian Windows), which turns a profile
/// path like `C:\Users\Иван` into garbage, and its exit code was never checked.
const INET_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const ENV_SUBKEY: &str = "Environment";

/// Checks the process-wide OS dry-run switch at the entry of every real call.
/// Returns `Err(DryRun)` (and counts the blocked call) when OS effects are off.
fn dry_run_gate(what: &str) -> PResult<()> {
    if super::os_effects_enabled() {
        Ok(())
    } else {
        super::note_dry_run_blocked(what);
        Err(PlatformError::DryRun)
    }
}

/// Like [`dry_run_gate`] for writes: dry-run is a counted no-op that reports success.
fn write_gate(what: &str) -> PResult<bool> {
    match dry_run_gate(what) {
        Ok(()) => Ok(true),
        Err(PlatformError::DryRun) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Returns `true` when macOS `networksetup` (or another OS tool) failed because
/// administrator authorization / authentication is required or was denied.
pub fn is_admin_auth_error(stdout: &str, stderr: &str) -> bool {
    let check = |s: &str| {
        let lower = s.to_ascii_lowercase();
        lower.contains("-60005")
            || lower.contains("-60006")
            || lower.contains("-60007")
            || lower.contains("-60008")
            || lower.contains("requires administrator")
            || lower.contains("requires admin")
            || lower.contains("requires at least admin privileges")
            || lower.contains("root privileges are required")
            || lower.contains("authorization")
            || lower.contains("errauthorizationdenied")
            || lower.contains("not authorized")
            || lower.contains("while authenticating")
            || lower.contains("operation not permitted")
            || lower.contains("permission denied")
    };
    check(stderr) || check(stdout)
}

/// Runs a program through [`super::silent_command`], capturing exit status, stdout and stderr.
fn run_detailed(
    program: &'static str,
    args: &[&str],
    op: &'static str,
) -> PResult<(bool, Option<i32>, String, String)> {
    let out = super::silent_command(program)
        .args(args)
        .output()
        .map_err(|e| {
            crate::diagnostics::record(
                "sysproxy",
                &format!("{op}: failed to spawn {program}: {}", e.kind()),
            );
            PlatformError::Failed(op)
        })?;
    Ok((
        out.status.success(),
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Runs a program through [`super::silent_command`], capturing stdout and stderr.
fn run(program: &'static str, args: &[&str], op: &'static str) -> PResult<(bool, String, String)> {
    let (ok, _code, stdout, stderr) = run_detailed(program, args, op)?;
    Ok((ok, stdout, stderr))
}

/// Runs `program` and returns stdout on success, or logs non-empty stderr/stdout to diagnostics
/// and maps macOS authorization failures to [`PlatformError::AdminAuthRequired`].
fn run_stdout(program: &'static str, args: &[&str], op: &'static str) -> PResult<String> {
    match run_detailed(program, args, op)? {
        (true, _, stdout, _) => Ok(stdout),
        (false, code, stdout, stderr) => {
            let err_trimmed = stderr.trim();
            let out_trimmed = stdout.trim();
            let subcmd = args.first().copied().unwrap_or("");
            crate::diagnostics::record(
                "sysproxy",
                &format!(
                    "{op}: {program} {subcmd} failed (code={code:?}) stderr={err_trimmed} stdout={out_trimmed}"
                ),
            );
            if is_admin_auth_error(&stdout, &stderr) {
                Err(PlatformError::AdminAuthRequired(op))
            } else {
                Err(PlatformError::Failed(op))
            }
        }
    }
}

fn run_ok(program: &'static str, args: &[&str], op: &'static str) -> PResult<()> {
    run_stdout(program, args, op).map(|_| ())
}

/// The one place that knows how a PAC URL is cleared. `networksetup` has no "unset"; clearing it
/// with an empty argument (`-setautoproxyurl <service> ""`) is the assumed way and is still to be
/// confirmed on a real macOS (manual gate S2c). If it turns out wrong, only this function changes.
fn clear_pac_url(service_name: &str) -> PResult<()> {
    run_ok(
        "networksetup",
        &["-setautoproxyurl", service_name, ""],
        "set_pac",
    )
}

/// `networksetup -setproxybypassdomains` takes the word `Empty` for "no domains".
const BYPASS_EMPTY_ARG: &str = "Empty";

/// The production implementation. Used only from non-test code in `sysproxy`.
pub struct RealPlatform;

impl RealPlatform {
    fn require_macos(op: &'static str) -> PResult<()> {
        if cfg!(target_os = "macos") {
            Ok(())
        } else {
            Err(PlatformError::Unsupported(op))
        }
    }
    fn require_windows(op: &'static str) -> PResult<()> {
        if cfg!(target_os = "windows") {
            Ok(())
        } else {
            Err(PlatformError::Unsupported(op))
        }
    }

    /// Resolves the *current* display name of a service by its stable key (handles renames).
    fn current_name(&self, svc: &ServiceId, op: &'static str) -> PResult<String> {
        self.list_services()?
            .into_iter()
            .find(|s| s.key() == svc.key())
            .map(|s| s.name)
            .ok_or(PlatformError::NotFound(op))
    }
}

impl Platform for RealPlatform {
    fn list_services(&self) -> PResult<Vec<ServiceId>> {
        Self::require_macos("list_services")?;
        dry_run_gate("networksetup:listnetworkserviceorder")?;
        let text = run_stdout(
            "networksetup",
            &["-listnetworkserviceorder"],
            "list_services",
        )?;
        Ok(parse_service_order(&text))
    }

    fn get_pac(&self, svc: &ServiceId) -> PResult<PacState> {
        Self::require_macos("get_pac")?;
        dry_run_gate("networksetup:getautoproxyurl")?;
        let name = self.current_name(svc, "get_pac")?;
        let text = run_stdout("networksetup", &["-getautoproxyurl", &name], "get_pac")?;
        Ok(parse_autoproxy(&text))
    }

    fn set_pac(&self, svc: &ServiceId, pac: &PacState) -> PResult<()> {
        Self::require_macos("set_pac")?;
        if !write_gate("networksetup:setautoproxy")? {
            return Ok(());
        }
        let name = self.current_name(svc, "set_pac")?;
        let set_state = |on: bool| {
            run_ok(
                "networksetup",
                &["-setautoproxystate", &name, if on { "on" } else { "off" }],
                "set_pac",
            )
        };
        // Switching on: the URL first, then the flag. Switching off: the flag first, so the
        // service never holds an enabled PAC without an address.
        if pac.enabled == Some(false) {
            set_state(false)?;
        }
        match pac.url.as_deref() {
            Some("") => clear_pac_url(&name)?,
            Some(url) => run_ok("networksetup", &["-setautoproxyurl", &name, url], "set_pac")?,
            None => {}
        }
        if pac.enabled == Some(true) {
            set_state(true)?;
        }
        Ok(())
    }

    fn get_chain(&self, svc: &ServiceId) -> PResult<ChainState> {
        Self::require_macos("get_chain")?;
        dry_run_gate("networksetup:getwebproxy")?;
        let name = self.current_name(svc, "get_chain")?;
        let web = run_stdout("networksetup", &["-getwebproxy", &name], "get_chain")?;
        let sec = run_stdout("networksetup", &["-getsecurewebproxy", &name], "get_chain")?;
        Ok(ChainState {
            http: parse_webproxy(&web),
            https: parse_webproxy(&sec),
        })
    }

    fn set_chain(&self, svc: &ServiceId, chain: &ChainState) -> PResult<()> {
        Self::require_macos("set_chain")?;
        if !write_gate("networksetup:setwebproxy")? {
            return Ok(());
        }
        let name = self.current_name(svc, "set_chain")?;
        for (ep, set, get, state) in [
            (
                &chain.http,
                "-setwebproxy",
                "-getwebproxy",
                "-setwebproxystate",
            ),
            (
                &chain.https,
                "-setsecurewebproxy",
                "-getsecurewebproxy",
                "-setsecurewebproxystate",
            ),
        ] {
            if let (Some(host), Some(port)) = (&ep.server, ep.port) {
                // `-setwebproxy` also switches the proxy on and resets its authentication, so it
                // runs only when the address really differs from what the service holds now.
                let (ok, text, _) = run("networksetup", &[get, &name], "set_chain")?;
                let same = ok && {
                    let cur = parse_webproxy(&text);
                    cur.server.as_deref() == Some(host.as_str()) && cur.port == Some(port)
                };
                if !same {
                    run_ok(
                        "networksetup",
                        &[set, &name, host, &port.to_string()],
                        "set_chain",
                    )?;
                }
            }
            if let Some(on) = ep.enabled {
                run_ok(
                    "networksetup",
                    &[state, &name, if on { "on" } else { "off" }],
                    "set_chain",
                )?;
            }
        }
        Ok(())
    }

    fn get_proxy_bypass_domains(&self, svc: &ServiceId) -> PResult<Vec<String>> {
        Self::require_macos("get_proxy_bypass_domains")?;
        dry_run_gate("networksetup:getproxybypassdomains")?;
        let name = self.current_name(svc, "get_proxy_bypass_domains")?;
        let text = run_stdout(
            "networksetup",
            &["-getproxybypassdomains", &name],
            "get_proxy_bypass_domains",
        )?;
        Ok(parse_bypass_domains(&text))
    }

    fn set_proxy_bypass_domains(&self, svc: &ServiceId, domains: &[String]) -> PResult<()> {
        Self::require_macos("set_proxy_bypass_domains")?;
        if !write_gate("networksetup:setproxybypassdomains")? {
            return Ok(());
        }
        if self.get_proxy_bypass_domains(svc)? == domains {
            return Ok(()); // already as wanted: no call
        }
        let name = self.current_name(svc, "set_proxy_bypass_domains")?;
        let mut args: Vec<&str> = vec!["-setproxybypassdomains", &name];
        if domains.is_empty() {
            args.push(BYPASS_EMPTY_ARG);
        } else {
            args.extend(domains.iter().map(String::as_str));
        }
        run_ok("networksetup", &args, "set_proxy_bypass_domains")
    }

    fn vpn_connections(&self) -> PResult<Vec<VpnConnection>> {
        Self::require_macos("vpn_connections")?;
        dry_run_gate("scutil:nc-list")?;
        let text = run_stdout("scutil", &["--nc", "list"], "vpn_connections")?;
        Ok(parse_nc_list(&text))
    }

    fn effective_proxy(&self) -> PResult<EffectiveProxy> {
        Self::require_macos("effective_proxy")?;
        dry_run_gate("scutil:proxy")?;
        let text = run_stdout("scutil", &["--proxy"], "effective_proxy")?;
        Ok(parse_scutil_proxy(&text))
    }

    fn temp_dns_overrides(&self) -> PResult<bool> {
        use std::io::Write;
        use std::process::Stdio;
        Self::require_macos("temp_dns_overrides")?;
        dry_run_gate("scutil:dns")?;
        // Read-only scutil session over stdin.
        let scutil = |script: &str| -> PResult<String> {
            let mut child = super::silent_command("scutil")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| PlatformError::Failed("temp_dns_overrides"))?;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(script.as_bytes());
            }
            let out = child
                .wait_with_output()
                .map_err(|_| PlatformError::Failed("temp_dns_overrides"))?;
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        };
        let services = self.list_services()?;
        let nc = self.vpn_connections()?;
        let physical: Vec<ServiceId> = services
            .into_iter()
            .filter(|s| s.enabled && classify_service(s, Some(&nc)).is_physical())
            .collect();
        if physical.is_empty() {
            return Ok(false);
        }
        let listing = scutil("list Setup:/Network/Service/[^/]+/DNS\nquit\n")?;
        let mut entries = Vec::new();
        for line in listing.lines() {
            // "  subKey [0] = Setup:/Network/Service/<ID>/DNS"
            let Some(key) = line.split(" = ").nth(1).map(str::trim) else {
                continue;
            };
            let Some(id) = key
                .strip_prefix("Setup:/Network/Service/")
                .and_then(|r| r.strip_suffix("/DNS"))
            else {
                continue;
            };
            let dns = parse_scutil_dns(&scutil(&format!("show {key}\nquit\n"))?);
            let svc_dump = scutil(&format!("show Setup:/Network/Service/{id}\nquit\n"))?;
            let user_defined_name = svc_dump.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("UserDefinedName : ")
                    .map(|v| v.trim().to_string())
            });
            entries.push(SetupDnsEntry {
                service_id: id.to_string(),
                user_defined_name,
                dns,
            });
        }
        has_physical_temp_dns_override(&physical, &entries, |name| {
            let saved_dns = run_stdout(
                "networksetup",
                &["-getdnsservers", name],
                "temp_dns_overrides",
            )?;
            let saved_search = run_stdout(
                "networksetup",
                &["-getsearchdomains", name],
                "temp_dns_overrides",
            )?;
            Ok((
                parse_getdnsservers(&saved_dns),
                parse_getsearchdomains(&saved_search),
            ))
        })
    }

    fn get_user_env(&self, key: &str) -> PResult<Option<String>> {
        dry_run_gate("user_env:get")?;
        if cfg!(target_os = "macos") {
            let text = run_stdout("launchctl", &["getenv", key], "get_user_env")?;
            // launchctl prints nothing for an unset variable; "set to empty" is indistinguishable.
            let v = text.trim_end_matches('\n');
            Ok(if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            })
        } else if cfg!(target_os = "windows") {
            match registry_get(ENV_SUBKEY, key, "get_user_env")? {
                None => Ok(None),
                Some(RegValue {
                    kind: RegKind::Sz,
                    data,
                }) => Ok(Some(data)),
                // Expand/DWORD values cannot be restored byte-exact through this API.
                Some(_) => Err(PlatformError::Unsupported("get_user_env")),
            }
        } else {
            Err(PlatformError::Unsupported("get_user_env"))
        }
    }

    fn set_user_env(&self, key: &str, value: &str) -> PResult<()> {
        if !write_gate("user_env:set")? {
            return Ok(());
        }
        if cfg!(target_os = "macos") {
            run_ok("launchctl", &["setenv", key, value], "set_user_env")
        } else if cfg!(target_os = "windows") {
            run_ok(
                "reg",
                &["add", ENV_KEY, "/v", key, "/t", "REG_SZ", "/d", value, "/f"],
                "set_user_env",
            )
        } else {
            Err(PlatformError::Unsupported("set_user_env"))
        }
    }

    fn unset_user_env(&self, key: &str) -> PResult<()> {
        if !write_gate("user_env:unset")? {
            return Ok(());
        }
        if cfg!(target_os = "macos") {
            run_ok("launchctl", &["unsetenv", key], "unset_user_env")
        } else if cfg!(target_os = "windows") {
            if self.get_user_env(key)?.is_none() {
                return Ok(());
            }
            run_ok(
                "reg",
                &["delete", ENV_KEY, "/v", key, "/f"],
                "unset_user_env",
            )
        } else {
            Err(PlatformError::Unsupported("unset_user_env"))
        }
    }

    fn list_user_env_names(&self) -> PResult<Vec<String>> {
        Self::require_windows("list_user_env_names")?;
        dry_run_gate("reg:query-env")?;
        registry_names(ENV_SUBKEY, "list_user_env_names")
    }

    fn get_inet(&self, name: &str) -> PResult<Option<RegValue>> {
        Self::require_windows("get_inet")?;
        dry_run_gate("reg:query")?;
        registry_get(INET_SUBKEY, name, "get_inet")
    }

    fn set_inet(&self, name: &str, value: &RegValue) -> PResult<()> {
        Self::require_windows("set_inet")?;
        if !write_gate("reg:add")? {
            return Ok(());
        }
        let ty = match value.kind {
            RegKind::Sz => "REG_SZ",
            RegKind::ExpandSz => "REG_EXPAND_SZ",
            RegKind::Dword => "REG_DWORD",
        };
        run_ok(
            "reg",
            &[
                "add",
                INET_KEY,
                "/v",
                name,
                "/t",
                ty,
                "/d",
                &value.data,
                "/f",
            ],
            "set_inet",
        )
    }

    fn delete_inet(&self, name: &str) -> PResult<()> {
        Self::require_windows("delete_inet")?;
        if !write_gate("reg:delete")? {
            return Ok(());
        }
        if self.get_inet(name)?.is_none() {
            return Ok(());
        }
        run_ok(
            "reg",
            &["delete", INET_KEY, "/v", name, "/f"],
            "delete_inet",
        )
    }

    fn notify_inet_refresh(&self) -> PResult<()> {
        Self::require_windows("notify_inet_refresh")?;
        if !write_gate("InternetSetOptionW")? {
            return Ok(());
        }
        #[cfg(target_os = "windows")]
        {
            ffi::inet_refresh();
        }
        Ok(())
    }

    fn broadcast_env_change(&self) -> PResult<()> {
        Self::require_windows("broadcast_env_change")?;
        if !write_gate("SendMessageTimeoutW")? {
            return Ok(());
        }
        #[cfg(target_os = "windows")]
        {
            ffi::env_broadcast();
        }
        Ok(())
    }

    fn exclude_from_backup(&self, path: &Path) -> PResult<()> {
        if !cfg!(target_os = "macos") {
            return Ok(());
        }
        if !write_gate("tmutil:addexclusion")? {
            return Ok(());
        }
        let p = path.to_string_lossy();
        run_ok("tmutil", &["addexclusion", &p], "exclude_from_backup")
    }
}

/// Windows FFI: the WinINet refresh, the environment broadcast and the registry reads.
/// Compiled and verified only by the Windows CI job.
#[cfg(target_os = "windows")]
mod ffi {
    use core::ffi::c_void;

    /// What `RegGetValueW` answered: its status code, the value type and the raw data.
    pub struct RegRead {
        pub status: u32,
        pub kind: u32,
        pub data: Vec<u8>,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegGetValueW(
            hkey: *mut c_void,
            lp_sub_key: *const u16,
            lp_value: *const u16,
            dw_flags: u32,
            pdw_type: *mut u32,
            pv_data: *mut c_void,
            pcb_data: *mut u32,
        ) -> i32;
        fn RegOpenKeyExW(
            hkey: *mut c_void,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut *mut c_void,
        ) -> i32;
        fn RegEnumValueW(
            hkey: *mut c_void,
            dw_index: u32,
            lp_value_name: *mut u16,
            lpcch_value_name: *mut u32,
            lp_reserved: *mut u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
        fn RegCloseKey(hkey: *mut c_void) -> i32;
    }

    /// `HKEY_CURRENT_USER` (0x80000001, sign-extended like the SDK does).
    const HKEY_CURRENT_USER: *mut c_void = (-2147483647_i32) as isize as *mut c_void;
    /// `RRF_RT_ANY`: accept every value type. `RRF_NOEXPAND`: leave `REG_EXPAND_SZ` unexpanded
    /// (the type stays visible and the text is the one that was stored).
    const RRF_RT_ANY: u32 = 0x0000_ffff;
    const RRF_NOEXPAND: u32 = 0x1000_0000;
    const KEY_READ: u32 = 0x0002_0019;
    const ERROR_MORE_DATA: u32 = 234;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    /// Longest value name the registry allows (16383 characters) plus the terminator.
    const MAX_VALUE_NAME: usize = 16384;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Reads one value of `HKEY_CURRENT_USER\<subkey>` with its type. The status is the Win32
    /// error code (`0` = success, `2` / `3` = not found).
    pub fn reg_get_hkcu(subkey: &str, name: &str) -> RegRead {
        let sub = wide(subkey);
        let nm = wide(name);
        let flags = RRF_RT_ANY | RRF_NOEXPAND;
        let mut kind = 0u32;
        let mut size = 0u32;
        // SAFETY: both strings are NUL-terminated and outlive the call; a null data pointer asks
        // for the size only.
        let st = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                nm.as_ptr(),
                flags,
                &mut kind,
                core::ptr::null_mut(),
                &mut size,
            )
        };
        if st != 0 {
            return RegRead {
                status: st as u32,
                kind: 0,
                data: Vec::new(),
            };
        }
        // The value can grow between the two calls: retry a few times on ERROR_MORE_DATA.
        for _ in 0..4 {
            if size == 0 {
                return RegRead {
                    status: 0,
                    kind,
                    data: Vec::new(),
                };
            }
            let mut buf = vec![0u8; size as usize];
            let mut cb = size;
            // SAFETY: `buf` holds `cb` writable bytes; the strings are NUL-terminated.
            let st = unsafe {
                RegGetValueW(
                    HKEY_CURRENT_USER,
                    sub.as_ptr(),
                    nm.as_ptr(),
                    flags,
                    &mut kind,
                    buf.as_mut_ptr().cast(),
                    &mut cb,
                )
            };
            match st as u32 {
                0 => {
                    buf.truncate(cb as usize);
                    return RegRead {
                        status: 0,
                        kind,
                        data: buf,
                    };
                }
                ERROR_MORE_DATA => size = cb.max(size.saturating_add(2)),
                other => {
                    return RegRead {
                        status: other,
                        kind: 0,
                        data: Vec::new(),
                    };
                }
            }
        }
        RegRead {
            status: ERROR_MORE_DATA,
            kind: 0,
            data: Vec::new(),
        }
    }

    /// Names of all values of `HKEY_CURRENT_USER\<subkey>` (UTF-16, without the terminator).
    pub fn reg_names_hkcu(subkey: &str) -> Result<Vec<Vec<u16>>, u32> {
        let sub = wide(subkey);
        let mut key: *mut c_void = core::ptr::null_mut();
        // SAFETY: `sub` is NUL-terminated; `key` receives the handle.
        let st = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, KEY_READ, &mut key) };
        if st != 0 {
            return Err(st as u32);
        }
        let mut names = Vec::new();
        let mut buf = vec![0u16; MAX_VALUE_NAME];
        let mut result = Ok(());
        for index in 0u32.. {
            let mut len = buf.len() as u32;
            // SAFETY: `buf` has room for `len` UTF-16 units; the other outputs are not wanted.
            let st = unsafe {
                RegEnumValueW(
                    key,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            match st as u32 {
                0 => names.push(buf[..len as usize].to_vec()),
                ERROR_NO_MORE_ITEMS => break,
                other => {
                    result = Err(other);
                    break;
                }
            }
        }
        // SAFETY: `key` was opened above and is closed exactly once.
        unsafe {
            RegCloseKey(key);
        }
        result.map(|()| names)
    }

    pub fn inet_refresh() {
        #[link(name = "wininet")]
        unsafe extern "system" {
            fn InternetSetOptionW(
                hInternet: *mut core::ffi::c_void,
                dwOption: u32,
                lpBuffer: *mut core::ffi::c_void,
                dwBufferLength: u32,
            ) -> i32;
        }
        const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
        const INTERNET_OPTION_REFRESH: u32 = 37;
        unsafe {
            let _ = InternetSetOptionW(
                core::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                core::ptr::null_mut(),
                0,
            );
            let _ = InternetSetOptionW(
                core::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                core::ptr::null_mut(),
                0,
            );
        }
    }

    pub fn env_broadcast() {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn SendMessageTimeoutW(
                hWnd: *mut core::ffi::c_void,
                Msg: u32,
                wParam: usize,
                lParam: *const u16,
                fuFlags: u32,
                uTimeout: u32,
                lpdwResult: *mut usize,
            ) -> isize;
            fn SendMessageTimeoutA(
                hWnd: *mut core::ffi::c_void,
                Msg: u32,
                wParam: usize,
                lParam: *const u8,
                fuFlags: u32,
                uTimeout: u32,
                lpdwResult: *mut usize,
            ) -> isize;
        }
        const HWND_BROADCAST: *mut core::ffi::c_void = 0xffff as *mut core::ffi::c_void;
        const WM_SETTINGCHANGE: u32 = 0x001A;
        const SMTO_ABORTIFHUNG: u32 = 0x0002;
        let env_wide: Vec<u16> = "Environment\0".encode_utf16().collect();
        let env_ansi: &[u8] = b"Environment\0";
        let mut dw_result: usize = 0;
        unsafe {
            let _ = SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                env_wide.as_ptr(),
                SMTO_ABORTIFHUNG,
                2000,
                &mut dw_result,
            );
            let _ = SendMessageTimeoutA(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                env_ansi.as_ptr(),
                SMTO_ABORTIFHUNG,
                2000,
                &mut dw_result,
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// FakePlatform
// ---------------------------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
pub use fake::{FakePlatform, PlatOp};

#[cfg(any(test, feature = "test-support"))]
mod fake {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    /// Operations that [`FakePlatform::fail_next`] can break.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum PlatOp {
        ListServices,
        GetPac,
        SetPac,
        GetChain,
        SetChain,
        GetBypass,
        SetBypass,
        TempDns,
        VpnList,
        EffectiveProxy,
        GetEnv,
        SetEnv,
        UnsetEnv,
        ListEnv,
        GetInet,
        SetInet,
        DeleteInet,
        NotifyInet,
        BroadcastEnv,
        ExcludeBackup,
    }

    #[derive(Default)]
    struct State {
        services: Vec<ServiceId>,
        pac: BTreeMap<String, PacState>,
        chain: BTreeMap<String, ChainState>,
        bypass: BTreeMap<String, Vec<String>>,
        env: BTreeMap<String, String>,
        inet: BTreeMap<String, RegValue>,
        temp_dns: bool,
        vpn: Vec<VpnConnection>,
        effective: Option<EffectiveProxy>,
        calls: Vec<String>,
        os_writes: usize,
        fail: BTreeMap<PlatOp, usize>,
        fail_auth: BTreeMap<PlatOp, usize>,
        excluded: Vec<PathBuf>,
        /// The next `set_chain` writes the HTTP side only and then fails (a process killed
        /// between the two commands).
        tear_chain: bool,
        /// How the "OS" rewrites a PAC URL it stores (case, default port, ...).
        pac_normalizer: Option<PacNormalizer>,
    }

    type PacNormalizer = Arc<dyn Fn(&str) -> String + Send + Sync>;

    /// In-memory OS. `Clone` shares the state. The call log records operation names and resource
    /// ids only, never values.
    #[derive(Clone, Default)]
    pub struct FakePlatform {
        st: Arc<Mutex<State>>,
    }

    impl FakePlatform {
        pub fn new() -> Self {
            Self::default()
        }

        /// Adds a service (initial state: PAC and chain absent).
        pub fn add_service(&self, svc: ServiceId) {
            self.st.lock().unwrap().services.push(svc);
        }

        pub fn remove_service(&self, key: &str) {
            self.st.lock().unwrap().services.retain(|s| s.key() != key);
        }

        /// Renames a service while keeping its device/port (the stable key).
        pub fn rename_service(&self, key: &str, new_name: &str) {
            for s in self.st.lock().unwrap().services.iter_mut() {
                if s.key() == key {
                    s.name = new_name.to_string();
                }
            }
        }

        // Seeding / external modification: not OS writes of ours, never counted.
        pub fn seed_pac(&self, svc: &ServiceId, pac: PacState) {
            self.st.lock().unwrap().pac.insert(svc.key(), pac);
        }
        pub fn seed_chain(&self, svc: &ServiceId, chain: ChainState) {
            self.st.lock().unwrap().chain.insert(svc.key(), chain);
        }
        pub fn seed_bypass(&self, svc: &ServiceId, domains: &[&str]) {
            self.st
                .lock()
                .unwrap()
                .bypass
                .insert(svc.key(), domains.iter().map(|d| d.to_string()).collect());
        }
        pub fn seed_env(&self, key: &str, value: &str) {
            self.st
                .lock()
                .unwrap()
                .env
                .insert(key.to_string(), value.to_string());
        }
        pub fn seed_inet(&self, name: &str, v: RegValue) {
            self.st.lock().unwrap().inet.insert(name.to_string(), v);
        }
        pub fn remove_env_externally(&self, key: &str) {
            self.st.lock().unwrap().env.remove(key);
        }
        /// Adds a VPN service: it is in the service list (without a device, like a real
        /// NetworkExtension service) and in the connection list.
        pub fn add_vpn_service(&self, name: &str, connected: bool) -> ServiceId {
            let svc = ServiceId::new("", &format!("com.vpn.{}", name.replace(' ', "")), name);
            self.add_service(svc.clone());
            self.set_vpn_connection(name, connected);
            svc
        }

        /// Sets (or adds) the state of a connection in the `scutil --nc list` of the fake.
        pub fn set_vpn_connection(&self, name: &str, connected: bool) {
            let mut s = self.st.lock().unwrap();
            match s.vpn.iter_mut().find(|c| c.name == name) {
                Some(c) => c.connected = connected,
                None => s.vpn.push(VpnConnection {
                    name: name.to_string(),
                    connected,
                }),
            }
        }

        /// What `scutil --proxy` will show: the PAC of the global proxy dictionary.
        pub fn set_effective_pac(&self, url: Option<&str>, enabled: bool) {
            self.st.lock().unwrap().effective = Some(EffectiveProxy {
                pac_enabled: Some(enabled),
                pac_url: url.map(str::to_string),
            });
        }

        pub fn set_temp_dns(&self, on: bool) {
            self.st.lock().unwrap().temp_dns = on;
        }

        pub fn pac_of(&self, svc: &ServiceId) -> PacState {
            self.st
                .lock()
                .unwrap()
                .pac
                .get(&svc.key())
                .cloned()
                .unwrap_or_default()
        }
        pub fn chain_of(&self, svc: &ServiceId) -> ChainState {
            self.st
                .lock()
                .unwrap()
                .chain
                .get(&svc.key())
                .cloned()
                .unwrap_or_default()
        }
        pub fn bypass_of(&self, svc: &ServiceId) -> Vec<String> {
            self.st
                .lock()
                .unwrap()
                .bypass
                .get(&svc.key())
                .cloned()
                .unwrap_or_default()
        }
        pub fn env_of(&self, key: &str) -> Option<String> {
            self.st.lock().unwrap().env.get(key).cloned()
        }
        pub fn inet_of(&self, name: &str) -> Option<RegValue> {
            self.st.lock().unwrap().inet.get(name).cloned()
        }

        /// Next call of `op` fails with `PlatformError::Failed` (once).
        pub fn fail_next(&self, op: PlatOp) {
            self.fail_next_n(op, 1);
        }
        pub fn fail_next_n(&self, op: PlatOp, n: usize) {
            self.st.lock().unwrap().fail.insert(op, n);
        }
        /// Next `n` calls of `op` fail with `PlatformError::AdminAuthRequired`.
        pub fn fail_next_auth(&self, op: PlatOp) {
            self.fail_next_auth_n(op, 1);
        }
        pub fn fail_next_auth_n(&self, op: PlatOp, n: usize) {
            self.st.lock().unwrap().fail_auth.insert(op, n);
        }

        /// The next `set_chain` lands its HTTP side and fails before the HTTPS side, as if the
        /// process had been killed between the two `networksetup` commands (the call after it
        /// fails as well).
        pub fn tear_next_set_chain(&self) {
            self.st.lock().unwrap().tear_chain = true;
        }

        /// From now on the (fake) OS stores every PAC URL after passing it through `f`.
        pub fn normalize_pac_urls_with(&self, f: impl Fn(&str) -> String + Send + Sync + 'static) {
            self.st.lock().unwrap().pac_normalizer = Some(Arc::new(f));
        }

        /// Number of writes of settings into the (fake) OS: set/unset/delete calls that succeeded.
        pub fn os_writes(&self) -> usize {
            self.st.lock().unwrap().os_writes
        }
        /// Operation log, e.g. `set_user_env:HTTPS_PROXY`; no values.
        pub fn calls(&self) -> Vec<String> {
            self.st.lock().unwrap().calls.clone()
        }
        pub fn clear_calls(&self) {
            self.st.lock().unwrap().calls.clear();
        }
        pub fn excluded_paths(&self) -> Vec<PathBuf> {
            self.st.lock().unwrap().excluded.clone()
        }

        fn enter(&self, op: PlatOp, name: &'static str, res: &str, write: bool) -> PResult<()> {
            let mut s = self.st.lock().unwrap();
            s.calls.push(if res.is_empty() {
                name.to_string()
            } else {
                format!("{name}:{res}")
            });
            if let Some(n) = s.fail_auth.get_mut(&op)
                && *n > 0
            {
                *n -= 1;
                if *n == 0 {
                    s.fail_auth.remove(&op);
                }
                return Err(PlatformError::AdminAuthRequired(name));
            }
            if let Some(n) = s.fail.get_mut(&op)
                && *n > 0
            {
                *n -= 1;
                if *n == 0 {
                    s.fail.remove(&op);
                }
                return Err(PlatformError::Failed(name));
            }
            if write {
                s.os_writes += 1;
            }
            Ok(())
        }

        fn has_service(&self, svc: &ServiceId) -> bool {
            self.st
                .lock()
                .unwrap()
                .services
                .iter()
                .any(|s| s.key() == svc.key())
        }
    }

    impl Platform for FakePlatform {
        fn list_services(&self) -> PResult<Vec<ServiceId>> {
            self.enter(PlatOp::ListServices, "list_services", "", false)?;
            Ok(self.st.lock().unwrap().services.clone())
        }

        fn get_pac(&self, svc: &ServiceId) -> PResult<PacState> {
            self.enter(PlatOp::GetPac, "get_pac", &svc.key(), false)?;
            if !self.has_service(svc) {
                return Err(PlatformError::NotFound("get_pac"));
            }
            Ok(self.pac_of(svc))
        }

        fn set_pac(&self, svc: &ServiceId, pac: &PacState) -> PResult<()> {
            self.enter(PlatOp::SetPac, "set_pac", &svc.key(), true)?;
            if !self.has_service(svc) {
                self.st.lock().unwrap().os_writes -= 1;
                return Err(PlatformError::NotFound("set_pac"));
            }
            let mut s = self.st.lock().unwrap();
            let norm = s.pac_normalizer.clone();
            let cur = s.pac.entry(svc.key()).or_default();
            if let Some(u) = &pac.url {
                // networksetup cannot unset a URL: an empty string reads back as absent.
                cur.url = if u.is_empty() {
                    None
                } else {
                    Some(norm.as_ref().map_or_else(|| u.clone(), |f| f(u)))
                };
            }
            if let Some(e) = pac.enabled {
                cur.enabled = Some(e);
            }
            Ok(())
        }

        fn get_chain(&self, svc: &ServiceId) -> PResult<ChainState> {
            self.enter(PlatOp::GetChain, "get_chain", &svc.key(), false)?;
            if !self.has_service(svc) {
                return Err(PlatformError::NotFound("get_chain"));
            }
            Ok(self.chain_of(svc))
        }

        fn set_chain(&self, svc: &ServiceId, chain: &ChainState) -> PResult<()> {
            self.enter(PlatOp::SetChain, "set_chain", &svc.key(), true)?;
            if !self.has_service(svc) {
                self.st.lock().unwrap().os_writes -= 1;
                return Err(PlatformError::NotFound("set_chain"));
            }
            let mut s = self.st.lock().unwrap();
            let tear = std::mem::take(&mut s.tear_chain);
            let cur = s.chain.entry(svc.key()).or_default();
            let sides = [(&mut cur.http, &chain.http), (&mut cur.https, &chain.https)];
            for (n, (dst, src)) in sides.into_iter().enumerate() {
                if tear && n == 1 {
                    break; // only the HTTP side landed
                }
                if src.server.is_some() && src.port.is_some() {
                    dst.server = src.server.clone();
                    dst.port = src.port;
                }
                if src.enabled.is_some() {
                    dst.enabled = src.enabled;
                }
            }
            if tear {
                // The process is gone: the write-back that would follow fails too.
                s.fail.insert(PlatOp::SetChain, 1);
                return Err(PlatformError::Failed("set_chain"));
            }
            Ok(())
        }

        fn get_proxy_bypass_domains(&self, svc: &ServiceId) -> PResult<Vec<String>> {
            self.enter(
                PlatOp::GetBypass,
                "get_proxy_bypass_domains",
                &svc.key(),
                false,
            )?;
            if !self.has_service(svc) {
                return Err(PlatformError::NotFound("get_proxy_bypass_domains"));
            }
            Ok(self.bypass_of(svc))
        }

        fn set_proxy_bypass_domains(&self, svc: &ServiceId, domains: &[String]) -> PResult<()> {
            // Like the real one: no call and no write when the list already is as wanted.
            if self.has_service(svc) && self.bypass_of(svc) == domains {
                self.st
                    .lock()
                    .unwrap()
                    .calls
                    .push(format!("set_proxy_bypass_domains:{}:same", svc.key()));
                return Ok(());
            }
            self.enter(
                PlatOp::SetBypass,
                "set_proxy_bypass_domains",
                &svc.key(),
                true,
            )?;
            if !self.has_service(svc) {
                self.st.lock().unwrap().os_writes -= 1;
                return Err(PlatformError::NotFound("set_proxy_bypass_domains"));
            }
            self.st
                .lock()
                .unwrap()
                .bypass
                .insert(svc.key(), domains.to_vec());
            Ok(())
        }

        fn vpn_connections(&self) -> PResult<Vec<VpnConnection>> {
            self.enter(PlatOp::VpnList, "vpn_connections", "", false)?;
            Ok(self.st.lock().unwrap().vpn.clone())
        }

        fn effective_proxy(&self) -> PResult<EffectiveProxy> {
            self.enter(PlatOp::EffectiveProxy, "effective_proxy", "", false)?;
            self.st
                .lock()
                .unwrap()
                .effective
                .clone()
                .ok_or(PlatformError::Unsupported("effective_proxy"))
        }

        fn temp_dns_overrides(&self) -> PResult<bool> {
            self.enter(PlatOp::TempDns, "temp_dns_overrides", "", false)?;
            Ok(self.st.lock().unwrap().temp_dns)
        }

        fn get_user_env(&self, key: &str) -> PResult<Option<String>> {
            self.enter(PlatOp::GetEnv, "get_user_env", key, false)?;
            Ok(self.env_of(key))
        }

        fn set_user_env(&self, key: &str, value: &str) -> PResult<()> {
            self.enter(PlatOp::SetEnv, "set_user_env", key, true)?;
            self.st
                .lock()
                .unwrap()
                .env
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn unset_user_env(&self, key: &str) -> PResult<()> {
            self.enter(PlatOp::UnsetEnv, "unset_user_env", key, true)?;
            self.st.lock().unwrap().env.remove(key);
            Ok(())
        }

        fn list_user_env_names(&self) -> PResult<Vec<String>> {
            self.enter(PlatOp::ListEnv, "list_user_env_names", "", false)?;
            Ok(self.st.lock().unwrap().env.keys().cloned().collect())
        }

        fn get_inet(&self, name: &str) -> PResult<Option<RegValue>> {
            self.enter(PlatOp::GetInet, "get_inet", name, false)?;
            Ok(self.inet_of(name))
        }

        fn set_inet(&self, name: &str, value: &RegValue) -> PResult<()> {
            self.enter(PlatOp::SetInet, "set_inet", name, true)?;
            self.st
                .lock()
                .unwrap()
                .inet
                .insert(name.to_string(), value.clone());
            Ok(())
        }

        fn delete_inet(&self, name: &str) -> PResult<()> {
            self.enter(PlatOp::DeleteInet, "delete_inet", name, true)?;
            self.st.lock().unwrap().inet.remove(name);
            Ok(())
        }

        fn notify_inet_refresh(&self) -> PResult<()> {
            self.enter(PlatOp::NotifyInet, "notify_inet_refresh", "", false)
        }

        fn broadcast_env_change(&self) -> PResult<()> {
            self.enter(PlatOp::BroadcastEnv, "broadcast_env_change", "", false)
        }

        fn exclude_from_backup(&self, path: &Path) -> PResult<()> {
            self.enter(PlatOp::ExcludeBackup, "exclude_from_backup", "", false)?;
            self.st.lock().unwrap().excluded.push(path.to_path_buf());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_key_is_device_and_port_not_the_display_name() {
        let a = ServiceId::new("en0", "Wi-Fi", "Wi-Fi");
        let renamed = ServiceId::new("en0", "Wi-Fi", "Беспроводная сеть");
        assert_eq!(a, renamed);
        assert_eq!(a.key(), "dev:en0/Wi-Fi");
        let vpn = ServiceId::new("", "com.vpn", "My VPN");
        assert_eq!(vpn.key(), "svc:com.vpn/My VPN");
    }

    #[test]
    fn debug_output_never_contains_values() {
        let secret = "http://user:hunter2@10.0.0.1:3128/proxy.pac";
        let pac = PacState {
            url: Some(secret.into()),
            enabled: Some(true),
        };
        let ep = ProxyEndpoint {
            enabled: Some(true),
            server: Some("hunter2.example".into()),
            port: Some(1),
            authenticated: None,
        };
        let reg = RegValue::sz(secret);
        let all = format!(
            "{pac:?} {ep:?} {reg:?} {:?}",
            ChainState {
                http: ep.clone(),
                https: ep.clone()
            }
        );
        assert!(!all.contains("hunter2"), "{all}");
    }

    #[test]
    fn autoproxy_distinguishes_null_empty_and_value() {
        assert_eq!(
            parse_autoproxy("URL: (null)\nEnabled: No\n"),
            PacState {
                url: None,
                enabled: Some(false)
            }
        );
        assert_eq!(
            parse_autoproxy("URL: http://x/p.pac\nEnabled: Yes\n")
                .url
                .as_deref(),
            Some("http://x/p.pac")
        );
        assert_eq!(parse_autoproxy("").enabled, None);
    }

    #[test]
    fn webproxy_absent_empty_and_zero_are_different() {
        let absent = parse_webproxy("");
        assert_eq!(absent, ProxyEndpoint::default());
        let empty = parse_webproxy("Enabled: No\nServer: \nPort: 0\n");
        assert_eq!(empty.server, Some(String::new()));
        assert_eq!(empty.port, Some(0));
        assert_ne!(absent, empty);
    }

    #[test]
    fn service_order_parses_device_port_and_disabled_flag() {
        let text = "An asterisk (*) denotes that a network service is disabled.\n\
            (1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n\
            (*) USB 10/100 LAN\n(Hardware Port: USB 10/100 LAN, Device: en5)\n\n\
            (2) My VPN\n(Hardware Port: com.vpn, Device: )\n";
        let s = parse_service_order(text);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].key(), "dev:en0/Wi-Fi");
        assert!(s[0].enabled);
        assert!(!s[1].enabled);
        assert_eq!(s[2].key(), "svc:com.vpn/My VPN");
    }

    #[test]
    fn reg_query_keeps_exact_type_and_absence() {
        let sz =
            "\r\nHKEY\\x\r\n    AutoConfigURL    REG_SZ    http://127.0.0.1:8899/proxy.pac\r\n";
        assert_eq!(
            parse_reg_query_value(sz, "AutoConfigURL"),
            Some(RegValue::sz("http://127.0.0.1:8899/proxy.pac"))
        );
        let empty = "    AutoConfigURL    REG_SZ    \n";
        assert_eq!(
            parse_reg_query_value(empty, "AutoConfigURL"),
            Some(RegValue::sz(""))
        );
        let dw = "    ProxyEnable    REG_DWORD    0x1\n";
        assert_eq!(
            parse_reg_query_value(dw, "ProxyEnable"),
            Some(RegValue::dword(1))
        );
        let ex = "    Path    REG_EXPAND_SZ    %USERPROFILE%\\bin\n";
        assert_eq!(
            parse_reg_query_value(ex, "Path").unwrap().kind,
            RegKind::ExpandSz
        );
        assert_eq!(
            parse_reg_query_value("ERROR: not found", "AutoConfigURL"),
            None
        );
        // A longer value name with the same prefix is not a match.
        assert_eq!(
            parse_reg_query_value("    AutoConfigURLX    REG_SZ    a\n", "AutoConfigURL"),
            None
        );
    }

    #[test]
    fn webproxy_reports_the_authentication_flag() {
        let ep = parse_webproxy(
            "Enabled: Yes\nServer: 10.0.0.1\nPort: 3128\nAuthenticated Proxy Enabled: 1\n",
        );
        assert_eq!(ep.authenticated, Some(true));
        let ep = parse_webproxy(
            "Enabled: Yes\nServer: 10.0.0.1\nPort: 3128\nAuthenticated Proxy Enabled: 0\n",
        );
        assert_eq!(ep.authenticated, Some(false));
        assert_eq!(parse_webproxy("Enabled: No\n").authenticated, None);
    }

    #[test]
    fn reg_query_names_lists_values_of_any_type_and_skips_key_lines() {
        let out = "\r\nHKEY_CURRENT_USER\\Environment\r\n    HTTPS_PROXY    REG_SZ    http://x\r\n    TEMP    REG_EXPAND_SZ    %X%\r\n    Flags    REG_DWORD    0x1\r\n";
        assert_eq!(
            parse_reg_query_names(out),
            vec!["HTTPS_PROXY", "TEMP", "Flags"]
        );
    }

    #[test]
    fn scutil_dns_order_independent_and_unknown_fields_flagged() {
        let a = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 1.1.1.1\n    1 : 8.8.8.8\n  }\n  SearchDomains : <array> {\n    0 : lan\n  }\n}\n";
        let b = "<dictionary> {\n  SearchDomains : <array> {\n    0 : lan\n  }\n  ServerAddresses : <array> {\n    0 : 1.1.1.1\n    1 : 8.8.8.8\n  }\n}\n";
        let (da, db) = (parse_scutil_dns(a), parse_scutil_dns(b));
        assert_eq!(da, db);
        assert_eq!(da.servers, vec!["1.1.1.1", "8.8.8.8"]);
        let benign = "<dictionary> {\n  ConfirmedServiceID : 1234-ABCD\n  DomainName : vpn.internal\n  InterfaceName : utun4\n  SupplementalMatchDomains : <array> {\n    0 : corp\n  }\n  _Reserved : <dictionary> {\n    foo : bar\n  }\n}\n";
        assert!(!parse_scutil_dns(benign).unknown_fields);
        let unknown = "<dictionary> {\n  UnexpectedCustomDnsFlag : 1\n}\n";
        assert!(parse_scutil_dns(unknown).unknown_fields);
        assert!(parse_getdnsservers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
        assert!(parse_getsearchdomains("There aren't any Search Domains set on Wi-Fi.\n").is_empty());
    }

    #[test]
    fn scutil_dns_amneziavpn_metadata_and_synthetic_services_do_not_trigger_temp_dns() {
        let amnezia_dns = parse_scutil_dns(
            "<dictionary> {\n  ConfirmedServiceID : E1A2-AMNEZIA\n  DomainName : amnezia.local\n  InterfaceName : utun4\n  ServerAddresses : <array> {\n    0 : 1.1.1.1\n  }\n  SupplementalMatchDomains : <array> {\n    0 : \n  }\n  __ORDER__ : 1\n}\n",
        );
        assert!(!amnezia_dns.unknown_fields);
        assert_eq!(amnezia_dns.servers, vec!["1.1.1.1"]);

        let wifi = svc("en0", "Wi-Fi");
        let entries = vec![
            // Synthetic / VPN Setup:/Network/Service/AmneziaWG/DNS not matching physical services.
            SetupDnsEntry {
                service_id: "E1A2-AMNEZIA".into(),
                user_defined_name: Some("AmneziaWG".into()),
                dns: amnezia_dns,
            },
            // Unmapped synthetic service with no UserDefinedName.
            SetupDnsEntry {
                service_id: "SYNTHETIC-TUN".into(),
                user_defined_name: None,
                dns: parse_scutil_dns("<dictionary> {\n  UnexpectedField : 1\n}\n"),
            },
            // Wi-Fi matches preferences.plist (192.168.1.1 + SearchDomains empty), plus benign keys.
            SetupDnsEntry {
                service_id: "WIFI-UUID".into(),
                user_defined_name: Some("Wi-Fi".into()),
                dns: parse_scutil_dns(
                    "<dictionary> {\n  ConfirmedServiceID : WIFI-UUID\n  InterfaceName : en0\n  ServerAddresses : <array> {\n    0 : 192.168.1.1\n  }\n}\n",
                ),
            },
        ];
        let triggered = has_physical_temp_dns_override(&[wifi.clone()], &entries, |name| {
            assert_eq!(name, "Wi-Fi");
            Ok((vec!["192.168.1.1".into()], Vec::new()))
        })
        .unwrap();
        assert!(!triggered, "AmneziaVPN / synthetic DNS entries must be ignored");

        // Now simulate Wi-Fi having an ephemeral DNS server override differing from preferences.
        let mut override_entries = entries.clone();
        override_entries[2].dns.servers = vec!["9.9.9.9".into()];
        assert!(
            has_physical_temp_dns_override(&[wifi.clone()], &override_entries, |_| Ok((
                vec!["192.168.1.1".into()],
                Vec::new()
            )))
            .unwrap()
        );

        // And simulate Wi-Fi having an ephemeral SearchDomains override differing from preferences.
        let mut search_entries = entries;
        search_entries[2].dns.search_domains = vec!["corp.local".into()];
        assert!(
            has_physical_temp_dns_override(&[wifi], &search_entries, |_| Ok((
                vec!["192.168.1.1".into()],
                Vec::new()
            )))
            .unwrap()
        );
    }

    #[test]
    fn dry_run_gate_blocks_and_counts() {
        // Unit tests always run in OS dry-run mode.
        let before = crate::sysproxy::dry_run_blocked_calls();
        assert_eq!(dry_run_gate("probe"), Err(PlatformError::DryRun));
        assert_eq!(write_gate("probe"), Ok(false));
        assert!(crate::sysproxy::dry_run_blocked_calls() >= before + 2);
    }

    #[test]
    fn fake_platform_counts_only_successful_writes() {
        let p = FakePlatform::new();
        p.set_user_env("A", "1").unwrap();
        p.fail_next(PlatOp::SetEnv);
        assert!(p.set_user_env("B", "2").is_err());
        assert_eq!(p.os_writes(), 1);
        assert_eq!(p.env_of("B"), None);
        assert_eq!(p.get_user_env("A").unwrap(), Some("1".into()));
        assert_eq!(p.os_writes(), 1);
        // The log names resources but carries no values.
        assert!(p.calls().iter().all(|c| !c.contains('=')));
    }

    #[test]
    fn bypass_domains_parse_the_empty_list_quirk() {
        assert!(parse_bypass_domains("There aren't any bypass domains set on Wi-Fi.\n").is_empty());
        assert!(parse_bypass_domains("").is_empty());
        assert_eq!(
            parse_bypass_domains("*.local\n169.254/16\n\n  corp.example \n"),
            vec!["*.local", "169.254/16", "corp.example"]
        );
    }

    #[test]
    fn fake_bypass_write_is_skipped_when_the_list_is_unchanged() {
        let p = FakePlatform::new();
        let svc = ServiceId::new("en0", "Wi-Fi", "Wi-Fi");
        p.add_service(svc.clone());
        p.seed_bypass(&svc, &["a", "b"]);
        let same = vec!["a".to_string(), "b".to_string()];
        p.set_proxy_bypass_domains(&svc, &same).unwrap();
        assert_eq!(p.os_writes(), 0);
        p.set_proxy_bypass_domains(&svc, &[]).unwrap();
        assert_eq!(p.os_writes(), 1);
        assert!(p.get_proxy_bypass_domains(&svc).unwrap().is_empty());
    }

    // --- WP-26: registry reads through the API (pure part, any OS) ---------------------------

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn utf16_nul(s: &str) -> Vec<u8> {
        let mut b = utf16(s);
        b.extend([0, 0]);
        b
    }

    #[test]
    fn registry_string_with_a_cyrillic_profile_path_survives_exactly() {
        let path = "file:///C:/Users/Иван/AppData/Local/zastava/proxy.pac";
        let got = reg_read_outcome(0, 1, &utf16_nul(path), "get_inet").unwrap();
        assert_eq!(got, Some(RegValue::sz(path)));
        // The same text, as the OEM-decoded `reg query` output would have damaged it.
        assert!(!got.unwrap().data.contains('\u{FFFD}'));
    }

    #[test]
    fn registry_value_types_are_kept_and_unknown_ones_are_unsupported() {
        let ok = |kind: u32, data: &[u8]| reg_read_outcome(0, kind, data, "get_inet");
        assert_eq!(ok(1, &utf16_nul("a")).unwrap(), Some(RegValue::sz("a")));
        assert_eq!(
            ok(2, &utf16_nul("%USERPROFILE%\\x")).unwrap(),
            Some(RegValue::expand_sz("%USERPROFILE%\\x")),
            "REG_EXPAND_SZ stays unexpanded and keeps its type"
        );
        assert_eq!(
            ok(4, &1u32.to_le_bytes()).unwrap(),
            Some(RegValue::dword(1))
        );
        assert_eq!(
            ok(4, &0xdead_beefu32.to_le_bytes()).unwrap(),
            Some(RegValue::dword(0xdead_beef))
        );
        for (name, kind) in [
            ("REG_BINARY", 3u32),
            ("REG_DWORD_BIG_ENDIAN", 5),
            ("REG_LINK", 6),
            ("REG_MULTI_SZ", 7),
            ("REG_QWORD", 11),
            ("REG_NONE", 0),
        ] {
            assert_eq!(
                ok(kind, &[1, 2, 3, 4]),
                Err(PlatformError::Unsupported("get_inet")),
                "{name} must be Unsupported, never `no value`"
            );
        }
    }

    #[test]
    fn a_failed_registry_read_is_an_error_and_only_not_found_means_absent() {
        let read = |status: u32| reg_read_outcome(status, 0, &[], "get_inet");
        assert_eq!(read(2).unwrap(), None, "ERROR_FILE_NOT_FOUND");
        assert_eq!(read(3).unwrap(), None, "ERROR_PATH_NOT_FOUND");
        for status in [5u32, 1450, 234, 1] {
            // ACCESS_DENIED, NO_SYSTEM_RESOURCES, MORE_DATA, INCORRECT_FUNCTION
            assert_eq!(
                read(status),
                Err(PlatformError::Failed("get_inet")),
                "status {status}"
            );
        }
    }

    #[test]
    fn registry_strings_that_cannot_round_trip_are_refused_not_repaired() {
        // Unpaired surrogate, odd length, a DWORD of the wrong size.
        let lone = [0x00, 0xD8, 0x41, 0x00];
        assert_eq!(
            reg_read_outcome(0, 1, &lone, "get_user_env"),
            Err(PlatformError::Unsupported("get_user_env"))
        );
        assert_eq!(
            reg_read_outcome(0, 1, &[0x41, 0x00, 0x42], "get_user_env"),
            Err(PlatformError::Unsupported("get_user_env"))
        );
        assert_eq!(
            reg_read_outcome(0, 4, &[1, 0, 0], "get_user_env"),
            Err(PlatformError::Unsupported("get_user_env"))
        );
    }

    #[test]
    fn an_empty_registry_string_is_a_value_and_differs_from_a_missing_one() {
        let empty = reg_read_outcome(0, 1, &utf16_nul(""), "get_inet").unwrap();
        assert_eq!(empty, Some(RegValue::sz("")));
        let no_terminator = reg_read_outcome(0, 1, &[], "get_inet").unwrap();
        assert_eq!(no_terminator, Some(RegValue::sz("")));
        assert_eq!(reg_read_outcome(2, 0, &[], "get_inet").unwrap(), None);
        // Extra trailing NULs of a stored value are dropped, inner text is kept.
        let two = [utf16("a"), vec![0, 0, 0, 0]].concat();
        assert_eq!(
            reg_read_outcome(0, 1, &two, "get_inet").unwrap(),
            Some(RegValue::sz("a"))
        );
    }

    #[test]
    fn registry_debug_output_stays_redacted() {
        let v = reg_read_outcome(0, 1, &utf16_nul("secret-path"), "get_inet")
            .unwrap()
            .unwrap();
        assert!(!format!("{v:?}").contains("secret-path"));
    }

    // --- WP-28: service kind, connection list, effective proxy ------------------------------

    /// The real shape of `scutil --nc list`, with invented names and identifiers.
    const NC_LIST: &str = "Available network connection services in the current set (*=enabled):\n\
* (Disconnected)   11111111-AAAA-4BBB-8CCC-000000000001 VPN (com.example.Alpha) \"Alpha VPN\"   [VPN:com.example.Alpha]\n\
* (Connected)      11111111-AAAA-4BBB-8CCC-000000000002 VPN (com.example.Beta.Pro) \"Beta VPN Pro\"   [VPN:com.example.Beta.Pro]\n\
  (Connecting)     11111111-AAAA-4BBB-8CCC-000000000003 VPN (com.example.Gamma) \"Gamma\"   [VPN:com.example.Gamma]\n\
* (Disconnecting)  11111111-AAAA-4BBB-8CCC-000000000004 PPP --> en0 \"Office \\\"L2TP\\\"\"   [PPP:L2TP]\n\
\n";

    #[test]
    fn nc_list_reads_state_and_the_quoted_name() {
        let list = parse_nc_list(NC_LIST);
        let seen: Vec<(&str, bool)> = list.iter().map(|c| (c.name.as_str(), c.connected)).collect();
        assert_eq!(
            seen,
            vec![
                ("Alpha VPN", false),
                ("Beta VPN Pro", true),
                ("Gamma", true),
                ("Office \\\"L2TP\\\"", true),
            ],
            "only \"Disconnected\" is not connected; the header line is skipped"
        );
        assert!(parse_nc_list("").is_empty());
        assert!(parse_nc_list("No connection services are available.\n").is_empty());
    }

    fn svc(device: &str, name: &str) -> ServiceId {
        ServiceId::new(device, name, name)
    }

    #[test]
    fn a_service_is_physical_vpn_or_unknown_by_the_connection_list_and_the_device() {
        let nc = parse_nc_list(NC_LIST);
        let kind = |s: &ServiceId, nc: Option<&[VpnConnection]>| classify_service(s, nc);
        // Listed: a VPN, whatever the device column says.
        assert_eq!(kind(&svc("", "Beta VPN Pro"), Some(&nc)), ServiceKind::Vpn { connected: true });
        assert_eq!(kind(&svc("", "Alpha VPN"), Some(&nc)), ServiceKind::Vpn { connected: false });
        assert_eq!(kind(&svc("utun4", "Gamma"), Some(&nc)), ServiceKind::Vpn { connected: true });
        // Not listed, no device: still a VPN (state unknown, so connected).
        assert_eq!(kind(&svc("", "Mystery"), Some(&nc)), ServiceKind::Vpn { connected: true });
        // Not listed, with a device: physical.
        assert_eq!(kind(&svc("en0", "Wi-Fi"), Some(&nc)), ServiceKind::Physical);
        assert_eq!(kind(&svc("bridge0", "Thunderbolt Bridge"), Some(&nc)), ServiceKind::Physical);
        // The list could not be read: a device alone does not vouch for a service.
        assert_eq!(kind(&svc("en0", "Wi-Fi"), None), ServiceKind::Unknown);
        assert_eq!(kind(&svc("", "Alpha VPN"), None), ServiceKind::Vpn { connected: true });
        assert!(ServiceKind::Physical.is_physical());
        assert!(!ServiceKind::Unknown.is_physical());
        assert!(ServiceKind::Vpn { connected: false }.is_idle_vpn());
        assert!(!ServiceKind::Vpn { connected: true }.is_idle_vpn());
        assert!(!ServiceKind::Unknown.is_idle_vpn());
    }

    #[test]
    fn service_kind_of_the_platform_follows_the_fake_connection_list() {
        let p = FakePlatform::new();
        let wifi = svc("en0", "Wi-Fi");
        p.add_service(wifi.clone());
        let vpn = p.add_vpn_service("Alpha VPN", true);
        assert_eq!(p.service_kind(&wifi), ServiceKind::Physical);
        assert_eq!(p.service_kind(&vpn), ServiceKind::Vpn { connected: true });
        p.set_vpn_connection("Alpha VPN", false);
        assert_eq!(p.service_kind(&vpn), ServiceKind::Vpn { connected: false });
        p.fail_next(PlatOp::VpnList);
        assert_eq!(p.service_kind(&wifi), ServiceKind::Unknown);
        assert_eq!(p.os_writes(), 0, "classification never writes");
    }

    #[test]
    fn scutil_proxy_gives_the_pac_part_only() {
        let text = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  ExcludeSimpleHostnames : 1\n  FTPPassive : 1\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://127.0.0.1:8899/proxy.pac\n  __SCOPED__ : <dictionary> {\n    en0 : <dictionary> {\n      ProxyAutoConfigEnable : 0\n    }\n  }\n}\n";
        let e = parse_scutil_proxy(text);
        assert_eq!(e.pac_enabled, Some(true), "the scoped block does not override it");
        assert_eq!(e.pac_url.as_deref(), Some("http://127.0.0.1:8899/proxy.pac"));
        let off = parse_scutil_proxy("<dictionary> {\n  ProxyAutoConfigEnable : 0\n}\n");
        assert_eq!(off.pac_enabled, Some(false));
        assert_eq!(off.pac_url, None);
        assert_eq!(parse_scutil_proxy("").pac_enabled, None);
        let shown = format!("{e:?}");
        assert!(!shown.contains("127.0.0.1"), "{shown}");
    }

    #[test]
    fn virtual_tunnel_devices_are_classified_as_vpn_even_without_scutil_nc() {
        let nc = parse_nc_list(NC_LIST);
        for dev in ["utun0", "utun4", "tun0", "tap1", "ppp0", "ipsec0", "UTUN7"] {
            assert_eq!(
                classify_service(&svc(dev, "AmneziaVPN Tunnel"), Some(&nc)),
                ServiceKind::Vpn { connected: true },
                "{dev} with nc list"
            );
            assert_eq!(
                classify_service(&svc(dev, "AmneziaVPN Tunnel"), None),
                ServiceKind::Vpn { connected: true },
                "{dev} without nc list"
            );
        }
        assert!(!is_virtual_tunnel_device("en0"));
        assert!(!is_virtual_tunnel_device("bridge0"));
    }

    #[test]
    fn admin_auth_error_detection_matches_macos_authorization_failures() {
        assert!(is_admin_auth_error(
            "",
            "Error: -60005 The user is not authorized."
        ));
        assert!(is_admin_auth_error(
            "",
            "This operation requires administrator privileges."
        ));
        assert!(is_admin_auth_error("", "errAuthorizationDenied"));
        assert!(is_admin_auth_error("Authorization failed.", ""));
        assert!(is_admin_auth_error("", "User is Not Authorized"));
        assert!(is_admin_auth_error("", "Command requires admin privileges."));
        assert!(is_admin_auth_error(
            "",
            "The networksetup tool requires at least admin privileges to change network settings."
        ));
        assert!(is_admin_auth_error("", "AuthorizationCreate() failed: -60007"));
        assert!(is_admin_auth_error("", "An error occurred while authenticating."));
        assert!(is_admin_auth_error("", "Operation not permitted"));
        assert!(!is_admin_auth_error("", "Wi-Fi is not a recognized network service."));
        assert!(
            PlatformError::AdminAuthRequired("set_pac")
                .to_string()
                .contains("admin")
        );
    }
}

/// Collects a sanitized, read-only OS network diagnostic snapshot (macOS only; empty on other OS
/// or when OS effects are disabled in tests).
pub fn collect_os_diagnostic_snapshot() -> Vec<String> {
    if !cfg!(target_os = "macos") || !super::os_effects_enabled() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    if let Ok((ok, code, stdout, stderr)) =
        run_detailed("networksetup", &["-listnetworkserviceorder"], "diag_services")
    {
        if ok {
            let svcs = parse_service_order(&stdout);
            let nc = run_detailed("scutil", &["--nc", "list"], "diag_nc")
                .ok()
                .filter(|(ok, _, _, _)| *ok)
                .map(|(_, _, out, _)| parse_nc_list(&out));
            let summary: Vec<String> = svcs
                .iter()
                .map(|s| {
                    let kind = classify_service(s, nc.as_deref());
                    format!(
                        "{}(dev={}, enabled={}, kind={kind:?})",
                        s.name,
                        if s.device.is_empty() { "-" } else { &s.device },
                        s.enabled
                    )
                })
                .collect();
            lines.push(format!("services: {}", summary.join("; ")));
            if let Some(connections) = nc {
                let nc_summary: Vec<String> = connections
                    .iter()
                    .map(|c| format!("{}={}", c.name, if c.connected { "connected" } else { "disconnected" }))
                    .collect();
                lines.push(format!(
                    "scutil_nc: {}",
                    if nc_summary.is_empty() {
                        "none".to_string()
                    } else {
                        nc_summary.join("; ")
                    }
                ));
            } else {
                lines.push("scutil_nc: unavailable".to_string());
            }
        } else {
            lines.push(format!(
                "services_error: code={code:?} {}",
                stderr.trim()
            ));
        }
    }
    if let Ok((ok, _, stdout, _)) = run_detailed("scutil", &["--proxy"], "diag_proxy")
        && ok
    {
        let eff = parse_scutil_proxy(&stdout);
        lines.push(format!(
            "scutil_proxy: pac_enabled={:?}, pac_url_present={}",
            eff.pac_enabled,
            eff.pac_url.is_some()
        ));
    }
    lines
}
