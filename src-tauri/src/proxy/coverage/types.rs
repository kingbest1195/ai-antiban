use crate::state::CliMode;
use crate::sysproxy::FileCtx;
use crate::sysproxy::browser_policies::PolicyStore;
use crate::sysproxy::platform::Platform;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// A confirmation by live traffic is valid for 30 minutes.
pub const CONFIRM_TTL_MS: u64 = 30 * 60 * 1000;
/// Configuration facts read from the OS / files are reused for this long (a forced re-check
/// bypasses it).
pub(super) const FACTS_TTL_MS: u64 = 5_000;
/// `peer_port -> process` answers are reused for this long.
pub(super) const LOOKUP_CACHE_TTL_MS: u64 = 15_000;
/// A failed lookup is remembered for this long (no retry storm for the same port).
pub(super) const LOOKUP_NEGATIVE_TTL_MS: u64 = 5_000;
/// At most [`LOOKUP_RATE_MAX`] process lookups per [`LOOKUP_RATE_WINDOW_MS`]; the rest is
/// attributed by User-Agent only.
pub(super) const LOOKUP_RATE_WINDOW_MS: u64 = 1_000;
pub(super) const LOOKUP_RATE_MAX: usize = 8;
/// Upper bound of remembered ports (cache never grows without limit).
pub(super) const LOOKUP_CACHE_MAX: usize = 1024;
/// The "is Antigravity running" answer is reused for this long: one process listing, never a loop.
pub(super) const PROCESS_CHECK_TTL_MS: u64 = 15_000;

/// Whether the format of the JetBrains `options/proxy.settings.xml` has been confirmed on a real
/// machine. While `false`, JetBrains is always `unknown` with manual steps.
pub const JETBRAINS_XML_CONFIRMED: bool = false;

/// Keys of manual steps handed to the UI (the texts live on the front end).
pub mod steps {
    /// Enable Zastava protection with its own button.
    pub const ENABLE_PROTECTION: &str = "enable_protection";
    /// Put `http://<gateway_addr>` into the application's HTTP proxy setting.
    pub const SET_HTTP_PROXY: &str = "set_http_proxy";
    /// Put the PAC address (`pac_url`) into the application's / system proxy setting.
    pub const SET_PAC_URL: &str = "set_pac_url";
    /// Set `HTTPS_PROXY` / `HTTP_PROXY` environment variables to `http://<gateway_addr>`.
    pub const SET_ENV_PROXY: &str = "set_env_proxy";
    /// Restart the application so that it picks the setting up.
    pub const RESTART_APP: &str = "restart_app";
    /// Open a new terminal window (already running ones keep their old environment).
    pub const REOPEN_TERMINAL: &str = "reopen_terminal";
    /// Open Settings -> HTTP Proxy in a JetBrains IDE.
    pub const JETBRAINS_PROXY_SETTINGS: &str = "jetbrains_proxy_settings";
    /// Quit the app completely and start it again with `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`
    /// in its environment (Antigravity 2.x: its agent ignores the system PAC).
    pub const LAUNCH_WITH_ENV: &str = "launch_with_env";
    /// Turn the system proxy on with the switch on the overview (text only, no button: it does
    /// not cover the whole app by itself).
    pub const ENABLE_SYSTEM_PROXY: &str = "enable_system_proxy";
}

/// Protection status of an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Confirmed,
    Configured,
    Unknown,
    Off,
    NotInstalled,
}

/// Individual application status within Zastava network protection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppCoverageItem {
    pub id: String,
    pub name: String,
    pub category: String, // "browser" | "desktop" | "ide" | "cli"
    pub installed: bool,
    pub status: CoverageStatus,
    /// Same as `ai_requests` (kept for the old front end).
    pub requests_seen: u64,
    /// AI requests through the gateway since Zastava started.
    pub ai_requests: u64,
    /// How many times the app fetched `/proxy.pac`.
    pub pac_fetches: u64,
    /// Unix time (ms) of the last AI request through the gateway.
    pub last_seen_ms: Option<u64>,
    /// Keys of manual steps (see [`steps`]); empty when nothing has to be done.
    pub manual_steps: Vec<String>,
    pub detail: String,
    /// The app is running but nothing of it reached the gateway: its requests probably go
    /// around Zastava (only Antigravity 2.x is checked this way).
    #[serde(default)]
    pub bypass_suspected: bool,
}

/// Comprehensive snapshot of application protection coverage and proxy chaining.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSnapshot {
    pub sysproxy_enabled: bool,
    pub cli_protection_enabled: bool,
    /// How command-line tools are covered: `"ai_only"` (only Claude Code, Gemini CLI and the
    /// editors; `node` / `python` / `curl` are not covered) or `"global_terminal"` (the shell
    /// profiles carry the proxy too).
    pub cli_mode: CliMode,
    pub chained_proxy: Option<String>,
    /// Real address of the gateway (`127.0.0.1:<port>`).
    pub gateway_addr: Option<String>,
    /// `http://<gateway_addr>/proxy.pac`.
    pub pac_url: Option<String>,
    pub generated_at_ms: u64,
    pub apps: Vec<AppCoverageItem>,
    /// Does the system actually hand our PAC to applications (`scutil --proxy`)? `None` while the
    /// protection is off, on systems without this check, or when it could not be read. `false`
    /// with the PAC written on the physical services means something (a VPN) overrides it.
    #[serde(default)]
    pub system_proxy_effective: Option<bool>,
    /// Enabled VPN services that are connected right now. Zastava never writes into them.
    #[serde(default)]
    pub vpn_connected: Vec<String>,
    /// True when at least one installed Chromium-family browser actually has PAC enforced
    /// (profile `Preferences` JSON or `--proxy-pac-url` flag, not merely recommended plist).
    #[serde(default)]
    pub browser_pac_policy_active: bool,
    /// Display names of running supported Chromium browsers that still need a restart for PAC.
    #[serde(default)]
    pub browsers_needing_restart: Vec<String>,
    /// Display names of installed Chromium browsers where PAC is confirmed active.
    #[serde(default)]
    pub browsers_pac_active: Vec<String>,
}

/// What kind of connection reached the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficKind {
    /// A tunnel request to an AI host.
    AiRequest,
    /// `GET /proxy.pac`.
    PacFetch,
    /// Transit traffic to a non-AI host: never inspected, never counted.
    Direct,
}

#[derive(Debug, Clone)]
pub(super) struct AppTrafficStats {
    pub(super) ai_requests: u64,
    pub(super) pac_fetches: u64,
    pub(super) last_seen_ms: u64,
    pub(super) detected_name: String,
    pub(super) category: String,
}

// ---------------------------------------------------------------------------------------------
// OS seam (re-exported from `crate::sysproxy` to keep `proxy::coverage -> sysproxy` one-way)
// ---------------------------------------------------------------------------------------------

pub use crate::sysproxy::{Os, RealProbe, SystemProbe};

pub(super) type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub(super) fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    })
}

pub(super) const KNOWN_IDS: [&str; 14] = [
    "browsers",
    "claude-desktop",
    "chatgpt-desktop",
    "antigravity",
    "cursor",
    "vscode",
    "windsurf",
    "jetbrains",
    "claude-code",
    "gemini-cli",
    "opencode",
    "node-cli",
    "python-cli",
    "curl",
];

/// The PAC address the gateway serves.
pub fn pac_url_for(addr: SocketAddr) -> String {
    format!("http://{addr}/proxy.pac")
}

/// How the PAC is read from the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacSource {
    /// Per network service (`networksetup -getautoproxyurl`), macOS.
    Services,
    /// WinINet `AutoConfigURL`, Windows.
    Inet,
}

impl PacSource {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            PacSource::Inet
        } else {
            PacSource::Services
        }
    }
}

/// Everything the status computation reads from outside.
pub(crate) struct CoverageEnv<'a> {
    pub platform: &'a dyn Platform,
    pub policy_store: &'a dyn PolicyStore,
    /// `None` when the user's directories cannot be determined: file based facts are `unknown`.
    pub files: Option<&'a FileCtx>,
    pub pac_source: PacSource,
    pub sysproxy_enabled: bool,
    pub cli_protection_enabled: bool,
    pub chained_proxy: Option<String>,
    /// Whether the JetBrains settings format is trusted (see [`JETBRAINS_XML_CONFIRMED`]).
    pub jetbrains_xml_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppFact {
    pub installed: bool,
    pub status: CoverageStatus,
    pub manual_steps: Vec<String>,
    pub detail: String,
    /// Not confirmed by traffic and the app runs -> report a probable bypass of the gateway.
    pub watch_bypass: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ConfigFacts {
    pub gateway: Option<SocketAddr>,
    pub apps: HashMap<&'static str, AppFact>,
    pub system_proxy_effective: Option<bool>,
    pub vpn_connected: Vec<String>,
    pub browser_pac_policy_active: bool,
    pub browsers_needing_restart: Vec<String>,
    pub browsers_pac_active: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    Configured,
    Off,
    Unknown,
}

pub(super) fn steps_of(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|k| k.to_string()).collect()
}

/// Text when Antigravity runs but nothing of it reached the gateway.
pub const ANTIGRAVITY_BYPASS_DETAIL: &str = "Запросы Antigravity, похоже, идут мимо Заставы";
