//! Journaled browser QUIC / DoH policies so AI traffic cannot bypass the local PAC proxy.
//!
//! Browsers (Chrome, Edge, Brave, Firefox) increasingly enable HTTP/3 (QUIC over UDP 443) and
//! DNS-over-HTTPS by default, which bypasses TCP HTTP PAC proxies (`127.0.0.1:8899`). When Zastava's
//! system proxy is active, we apply minimal per-user policy overrides through the ownership
//! [`Journal`] so every prior setting (or absence) is faithfully restored on disable, quit, or
//! crash recovery.
//!
//! Host access goes strictly through [`crate::sysproxy::os_effects_enabled`] +
//! [`crate::sysproxy::note_dry_run_blocked`], and uses `crate::win_reg` on Windows (never spawning
//! `reg.exe`) or gated `defaults` on macOS (only for browsers installed or already present in
//! `~/Library/Preferences`).

mod chromium;
mod policy_apply;
mod prefs;
mod process;
mod reconcile;
mod relaunch;
mod store;

use crate::sysproxy::platform::PResult;
use serde::{Deserialize, Serialize};
use std::fmt;

#[allow(unused_imports)]
pub use chromium::{
    CHROMIUM_BROWSERS, ChromiumBrowserDef, MACOS_CHROMIUM_DOMAIN_NAMES,
    WINDOWS_CHROMIUM_POLICY_BROWSERS, policy_specs_with_pac,
};
#[allow(unused_imports)]
#[cfg(any(target_os = "macos", test))]
pub use chromium::policy_specs_for_macos;
#[allow(unused_imports)]
#[cfg(any(target_os = "windows", test))]
pub use chromium::{WINDOWS_CHROMIUM_DOMAIN_NAMES, policy_specs_for_windows};
#[allow(unused_imports)]
pub use policy_apply::{
    apply_browser_policies_with_pac, apply_browser_policies_with_pac_in, apply_policy_specs,
    is_pac_policy_active_in,
};
#[cfg(test)]
pub use policy_apply::{
    is_pac_policy_active, revert_browser_policies, revert_browser_policies_with,
};
#[allow(unused_imports)]
pub use prefs::{
    browser_prefs_files_in, browser_user_data_dirs, build_browser_proxy_json_string,
    discover_browser_prefs_files_in, extract_pac_url_from_proxy_json, find_macos_app_bundle_in,
    is_zastava_local_pac_url, read_browser_proxy_pref, same_browser_proxy_json,
    write_browser_proxy_pref,
};
#[allow(unused_imports)]
pub use process::inspect_running_browsers;
#[allow(unused_imports)]
pub use reconcile::{
    any_non_running_browser_needs_pac_sync_in, clear_stale_browser_pac_prefs_in,
    detect_browser_pac_status_in, detect_browser_pac_status_with, is_wininet_pac_active,
    reconcile_browser_pac_prefs_in,
};
#[allow(unused_imports)]
pub use relaunch::{
    BROWSER_QUIT_POLL_INTERVAL, BROWSER_QUIT_TIMEOUT, relaunch_browsers_with_pac_with,
};
pub use store::RealPolicyStore;

/// Typed policy value persisted in the ownership journal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PolicyValue {
    Bool(bool),
    Dword(u32),
    Sz(String),
}

impl fmt::Debug for PolicyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyValue::Bool(b) => write!(f, "Bool({b})"),
            PolicyValue::Dword(n) => write!(f, "Dword({n})"),
            PolicyValue::Sz(_) => write!(f, "Sz(<redacted>)"),
        }
    }
}

/// One browser policy key/value desired while Zastava system protection is active.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PolicySpec {
    pub domain: String,
    pub key: String,
    pub value: PolicyValue,
}

impl PolicySpec {
    pub fn new(domain: impl Into<String>, key: impl Into<String>, value: PolicyValue) -> Self {
        Self {
            domain: domain.into(),
            key: key.into(),
            value,
        }
    }
}

/// Abstraction over OS browser policy storage so tests run without touching real host prefs.
pub trait PolicyStore: Send + Sync {
    /// Whether this domain exists on the host (e.g. installed macOS app / existing plist).
    /// Restores bypass this check so any previously journaled entry is always cleaned up.
    fn is_domain_applicable(&self, domain: &str) -> bool;
    fn read(&self, domain: &str, key: &str) -> PResult<Option<PolicyValue>>;
    fn write(&self, domain: &str, key: &str, value: &PolicyValue) -> PResult<()>;
    fn delete(&self, domain: &str, key: &str) -> PResult<()>;
}

/// Policy key names managed by Zastava on Chromium-family browsers.
pub const KEY_QUIC_ALLOWED: &str = "QuicAllowed";
pub const KEY_DOH_MODE: &str = "DnsOverHttpsMode";
pub const KEY_PROXY_MODE: &str = "ProxyMode";
pub const KEY_PROXY_PAC_URL: &str = "ProxyPacUrl";
pub const PROXY_MODE_PAC_SCRIPT: &str = "pac_script";

/// Summary of applying browser QUIC/DoH/PAC policies through the ownership journal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyApplyReport {
    pub applied: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub failed: usize,
    #[serde(default)]
    pub pac_policy_active: bool,
}

/// Running state observed for one browser via `ps` / `tasklist`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunningBrowserInfo {
    pub running: bool,
    pub has_pac_flag: bool,
}

/// Per-browser PAC enforcement summary for installed Chromium-family browsers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BrowserPacStatus {
    pub browsers_pac_active: Vec<String>,
    pub browsers_needing_restart: Vec<String>,
}

/// Result of attempting to quit, patch `Preferences`, and relaunch Chromium browsers with PAC.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaunchSummary {
    pub restarted: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<String>,
    pub needs_automation_permission: bool,
    pub unsupported: bool,
}

#[cfg(test)]
#[path = "../browser_policies_tests/mod.rs"]
mod tests;

#[cfg(any(test, feature = "test-support"))]
mod fakes;
#[allow(unused_imports)]
#[cfg(any(test, feature = "test-support"))]
pub use fakes::FakePolicyStore;

#[cfg(test)]
use crate::sysproxy::{Os, SystemProbe};
#[cfg(test)]
use crate::sysproxy::FileCtx;
#[cfg(test)]
use crate::sysproxy::fs::Fs;
#[cfg(test)]
use crate::sysproxy::journal::{Journal, Outcome, Resource};
#[cfg(test)]
use crate::sysproxy::relaunch::{AppLauncher, QuitTiming};
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::time::Duration;
#[cfg(all(test, target_os = "macos"))]
use store::macos_app_bundles_for_domain;
