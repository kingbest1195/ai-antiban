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
    /// The external program or API call failed.
    Failed(&'static str),
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformError::DryRun => write!(f, "OS dry-run mode"),
            PlatformError::Unsupported(op) => write!(f, "{op}: unsupported"),
            PlatformError::NotFound(op) => write!(f, "{op}: not found"),
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
    /// Read-only: does an active VPN keep temporary DNS settings that differ from the saved ones?
    fn temp_dns_overrides(&self) -> PResult<bool>;
    /// User environment: `launchctl getenv` (macOS) / `HKCU\Environment` (Windows).
    fn get_user_env(&self, key: &str) -> PResult<Option<String>>;
    fn set_user_env(&self, key: &str, value: &str) -> PResult<()>;
    fn unset_user_env(&self, key: &str) -> PResult<()>;
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
                _ => {}
            }
        }
    }
    ep
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

/// `reg query <key> /v <name>` -> value with exact type. `None` = no such value.
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

/// Parsed `scutil` dictionary of `Setup:/Network/Service/<id>/DNS`.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsDict {
    pub servers: Vec<String>,
    pub search_domains: Vec<String>,
    /// A key other than `ServerAddresses` / `SearchDomains` was present.
    pub unknown_fields: bool,
}

/// Parses `scutil` `show` output. Key order inside the dictionary does not matter.
pub fn parse_scutil_dns(output: &str) -> DnsDict {
    let mut d = DnsDict {
        servers: vec![],
        search_domains: vec![],
        unknown_fields: false,
    };
    let mut current: Option<&'static str> = None;
    for line in output.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("<dictionary>") || t == "}" {
            if t == "}" {
                current = None;
            }
            continue;
        }
        if let Some((k, v)) = t.split_once(" : ") {
            let k = k.trim();
            let v = v.trim();
            if k.chars().all(|c| c.is_ascii_digit()) {
                match current {
                    Some("servers") => d.servers.push(v.to_string()),
                    Some("domains") => d.search_domains.push(v.to_string()),
                    _ => d.unknown_fields = true,
                }
            } else if v.starts_with("<array>") {
                current = match k {
                    "ServerAddresses" => Some("servers"),
                    "SearchDomains" => Some("domains"),
                    _ => {
                        d.unknown_fields = true;
                        None
                    }
                };
            } else {
                d.unknown_fields = true;
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

// ---------------------------------------------------------------------------------------------
// RealPlatform
// ---------------------------------------------------------------------------------------------

const INET_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const ENV_KEY: &str = r"HKCU\Environment";

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

/// Runs a program through [`super::silent_command`]; only the exit status and stdout survive.
fn run(program: &'static str, args: &[&str], op: &'static str) -> PResult<(bool, String)> {
    let out = super::silent_command(program)
        .args(args)
        .output()
        .map_err(|_| PlatformError::Failed(op))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

fn run_ok(program: &'static str, args: &[&str], op: &'static str) -> PResult<()> {
    match run(program, args, op)? {
        (true, _) => Ok(()),
        _ => Err(PlatformError::Failed(op)),
    }
}

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
        let (ok, text) = run(
            "networksetup",
            &["-listnetworkserviceorder"],
            "list_services",
        )?;
        if !ok {
            return Err(PlatformError::Failed("list_services"));
        }
        Ok(parse_service_order(&text))
    }

    fn get_pac(&self, svc: &ServiceId) -> PResult<PacState> {
        Self::require_macos("get_pac")?;
        dry_run_gate("networksetup:getautoproxyurl")?;
        let name = self.current_name(svc, "get_pac")?;
        let (ok, text) = run("networksetup", &["-getautoproxyurl", &name], "get_pac")?;
        if !ok {
            return Err(PlatformError::Failed("get_pac"));
        }
        Ok(parse_autoproxy(&text))
    }

    fn set_pac(&self, svc: &ServiceId, pac: &PacState) -> PResult<()> {
        Self::require_macos("set_pac")?;
        if !write_gate("networksetup:setautoproxy")? {
            return Ok(());
        }
        let name = self.current_name(svc, "set_pac")?;
        if let Some(url) = &pac.url {
            run_ok("networksetup", &["-setautoproxyurl", &name, url], "set_pac")?;
        }
        if let Some(on) = pac.enabled {
            let st = if on { "on" } else { "off" };
            run_ok(
                "networksetup",
                &["-setautoproxystate", &name, st],
                "set_pac",
            )?;
        }
        Ok(())
    }

    fn get_chain(&self, svc: &ServiceId) -> PResult<ChainState> {
        Self::require_macos("get_chain")?;
        dry_run_gate("networksetup:getwebproxy")?;
        let name = self.current_name(svc, "get_chain")?;
        let (ok1, web) = run("networksetup", &["-getwebproxy", &name], "get_chain")?;
        let (ok2, sec) = run("networksetup", &["-getsecurewebproxy", &name], "get_chain")?;
        if !(ok1 && ok2) {
            return Err(PlatformError::Failed("get_chain"));
        }
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
        for (ep, set, state) in [
            (&chain.http, "-setwebproxy", "-setwebproxystate"),
            (
                &chain.https,
                "-setsecurewebproxy",
                "-setsecurewebproxystate",
            ),
        ] {
            if let (Some(host), Some(port)) = (&ep.server, ep.port) {
                run_ok(
                    "networksetup",
                    &[set, &name, host, &port.to_string()],
                    "set_chain",
                )?;
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
        let listing = scutil("list Setup:/Network/Service/[^/]+/DNS\nquit\n")?;
        let services = self.list_services()?;
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
            let dict = parse_scutil_dns(&scutil(&format!("show {key}\nquit\n"))?);
            if dict.unknown_fields {
                return Ok(true); // unknown fields -> refuse, never guess
            }
            let svc_dump = scutil(&format!("show Setup:/Network/Service/{id}\nquit\n"))?;
            let name = svc_dump.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("UserDefinedName : ")
                    .map(|v| v.trim().to_string())
            });
            let Some(name) = name.filter(|n| services.iter().any(|s| &s.name == n)) else {
                return Ok(true); // cannot map to a saved service -> treat as temporary
            };
            let (ok, saved) = run(
                "networksetup",
                &["-getdnsservers", &name],
                "temp_dns_overrides",
            )?;
            if !ok {
                return Err(PlatformError::Failed("temp_dns_overrides"));
            }
            let mut live = dict.servers.clone();
            let mut saved = parse_getdnsservers(&saved);
            live.sort();
            saved.sort();
            if live != saved {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn get_user_env(&self, key: &str) -> PResult<Option<String>> {
        dry_run_gate("user_env:get")?;
        if cfg!(target_os = "macos") {
            let (ok, text) = run("launchctl", &["getenv", key], "get_user_env")?;
            if !ok {
                return Err(PlatformError::Failed("get_user_env"));
            }
            // launchctl prints nothing for an unset variable; "set to empty" is indistinguishable.
            let v = text.trim_end_matches('\n');
            Ok(if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            })
        } else if cfg!(target_os = "windows") {
            let (_, text) = run("reg", &["query", ENV_KEY, "/v", key], "get_user_env")?;
            match parse_reg_query_value(&text, key) {
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

    fn get_inet(&self, name: &str) -> PResult<Option<RegValue>> {
        Self::require_windows("get_inet")?;
        dry_run_gate("reg:query")?;
        let (_, text) = run("reg", &["query", INET_KEY, "/v", name], "get_inet")?;
        Ok(parse_reg_query_value(&text, name))
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

/// Windows FFI moved here unchanged from `sysproxy/windows.rs` (no new `unsafe`).
/// Compiled and verified only by the Windows CI job.
#[cfg(target_os = "windows")]
mod ffi {
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
        TempDns,
        GetEnv,
        SetEnv,
        UnsetEnv,
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
        env: BTreeMap<String, String>,
        inet: BTreeMap<String, RegValue>,
        temp_dns: bool,
        calls: Vec<String>,
        os_writes: usize,
        fail: BTreeMap<PlatOp, usize>,
        excluded: Vec<PathBuf>,
    }

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
            let cur = s.pac.entry(svc.key()).or_default();
            if let Some(u) = &pac.url {
                // networksetup cannot unset a URL: an empty string reads back as absent.
                cur.url = if u.is_empty() { None } else { Some(u.clone()) };
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
            let cur = s.chain.entry(svc.key()).or_default();
            for (dst, src) in [(&mut cur.http, &chain.http), (&mut cur.https, &chain.https)] {
                if src.server.is_some() && src.port.is_some() {
                    dst.server = src.server.clone();
                    dst.port = src.port;
                }
                if src.enabled.is_some() {
                    dst.enabled = src.enabled;
                }
            }
            Ok(())
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
    fn scutil_dns_order_independent_and_unknown_fields_flagged() {
        let a = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 1.1.1.1\n    1 : 8.8.8.8\n  }\n  SearchDomains : <array> {\n    0 : lan\n  }\n}\n";
        let b = "<dictionary> {\n  SearchDomains : <array> {\n    0 : lan\n  }\n  ServerAddresses : <array> {\n    0 : 1.1.1.1\n    1 : 8.8.8.8\n  }\n}\n";
        let (da, db) = (parse_scutil_dns(a), parse_scutil_dns(b));
        assert_eq!(da, db);
        assert_eq!(da.servers, vec!["1.1.1.1", "8.8.8.8"]);
        let unknown =
            "<dictionary> {\n  SupplementalMatchDomains : <array> {\n    0 : corp\n  }\n}\n";
        assert!(parse_scutil_dns(unknown).unknown_fields);
        assert!(parse_getdnsservers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
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
}
