//! Journaled browser QUIC / DoH policies so AI traffic cannot bypass the local PAC proxy.
//!
//! Browsers (Chrome, Edge, Brave, Firefox) increasingly enable HTTP/3 (QUIC over UDP 443) and
//! DNS-over-HTTPS by default, which bypasses TCP HTTP PAC proxies (`127.0.0.1:8899`). When Zastava's
//! system proxy is active, we apply minimal per-user policy overrides through the ownership
//! [`Journal`] so every prior setting (or absence) is faithfully restored on disable, quit, or
//! crash recovery.
//!
//! Host access goes strictly through [`os_effects_enabled`] + [`note_dry_run_blocked`], and uses
//! `crate::win_reg` on Windows (never spawning `reg.exe`) or gated `defaults` on macOS (only for
//! browsers installed or already present in `~/Library/Preferences`).

use super::FileCtx;
use super::fs::{Fs, WriteMode};
use super::journal::{
    ApplyOutcome, Journal, JournalError, Outcome, RecoveryReport, ReportItem, Resource, Value,
};
use super::platform::{PResult, Platform, PlatformError};
use super::{note_dry_run_blocked, os_effects_enabled};
use crate::commands::restart_app::{AppLauncher, QuitTiming};
use crate::proxy::coverage::{Os, RealProbe, SystemProbe};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(any(test, feature = "test-support"))]
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// Metadata for one supported Chromium-family browser across macOS, Windows, and Linux.
#[derive(Clone, Copy, Debug)]
pub struct ChromiumBrowserDef {
    /// Canonical identifier (matches the macOS bundle identifier).
    pub id: &'static str,
    /// Human-friendly display name shown in UI / coverage lists.
    pub display_name: &'static str,
    /// macOS `.app` bundle directory names (e.g. `"Google Chrome.app"`).
    pub macos_bundles: &'static [&'static str],
    /// Relative paths under `~/Library/Application Support` holding Chromium User Data.
    pub macos_user_data_rels: &'static [&'static str],
    /// Relative paths under `%LOCALAPPDATA%` holding Chromium User Data on Windows.
    pub win_local_appdata_rels: &'static [&'static str],
    /// Relative paths under `%APPDATA%` (`AppData/Roaming`) holding Chromium User Data on Windows.
    pub win_roaming_appdata_rels: &'static [&'static str],
    /// Relative paths under `~/.config` holding Chromium User Data on Linux.
    pub linux_config_rels: &'static [&'static str],
    /// Lowercase executable names for Windows (`tasklist`) / Linux (`ps`) process matching.
    pub process_names: &'static [&'static str],
}

/// All 15 Chromium-family browsers supported by Zastava's policy + `Preferences` PAC enforcement.
pub const CHROMIUM_BROWSERS: [ChromiumBrowserDef; 15] = [
    ChromiumBrowserDef {
        id: "com.google.Chrome",
        display_name: "Google Chrome",
        macos_bundles: &["Google Chrome.app"],
        macos_user_data_rels: &["Google/Chrome"],
        win_local_appdata_rels: &["Google/Chrome/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["google-chrome"],
        process_names: &["chrome.exe", "google-chrome", "chrome"],
    },
    ChromiumBrowserDef {
        id: "com.google.Chrome.beta",
        display_name: "Google Chrome Beta",
        macos_bundles: &["Google Chrome Beta.app"],
        macos_user_data_rels: &["Google/Chrome Beta"],
        win_local_appdata_rels: &["Google/Chrome Beta/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["google-chrome-beta"],
        process_names: &["chrome.exe", "google-chrome-beta"],
    },
    ChromiumBrowserDef {
        id: "com.google.Chrome.canary",
        display_name: "Google Chrome Canary",
        macos_bundles: &["Google Chrome Canary.app"],
        macos_user_data_rels: &["Google/Chrome Canary"],
        win_local_appdata_rels: &["Google/Chrome SxS/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["google-chrome-unstable"],
        process_names: &["chrome.exe", "google-chrome-unstable"],
    },
    ChromiumBrowserDef {
        id: "ai.perplexity.comet",
        display_name: "Comet",
        macos_bundles: &["Comet.app"],
        macos_user_data_rels: &["Comet"],
        win_local_appdata_rels: &["Perplexity/Comet/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["comet"],
        process_names: &["comet.exe", "comet"],
    },
    ChromiumBrowserDef {
        id: "ru.yandex.desktop.yandex-browser",
        display_name: "Yandex Browser",
        macos_bundles: &["Yandex.app", "Yandex Browser.app"],
        macos_user_data_rels: &["Yandex/YandexBrowser"],
        win_local_appdata_rels: &["Yandex/YandexBrowser/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["yandex-browser", "yandex-browser-beta"],
        process_names: &["browser.exe", "yandex.exe", "yandex-browser"],
    },
    ChromiumBrowserDef {
        id: "com.brave.Browser",
        display_name: "Brave",
        macos_bundles: &["Brave Browser.app"],
        macos_user_data_rels: &["BraveSoftware/Brave-Browser"],
        win_local_appdata_rels: &["BraveSoftware/Brave-Browser/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["BraveSoftware/Brave-Browser"],
        process_names: &["brave.exe", "brave-browser", "brave"],
    },
    ChromiumBrowserDef {
        id: "com.brave.Browser.beta",
        display_name: "Brave Beta",
        macos_bundles: &["Brave Browser Beta.app"],
        macos_user_data_rels: &["BraveSoftware/Brave-Browser-Beta"],
        win_local_appdata_rels: &["BraveSoftware/Brave-Browser-Beta/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["BraveSoftware/Brave-Browser-Beta"],
        process_names: &["brave.exe", "brave-browser-beta"],
    },
    ChromiumBrowserDef {
        id: "com.microsoft.edgemac",
        display_name: "Microsoft Edge",
        macos_bundles: &["Microsoft Edge.app"],
        macos_user_data_rels: &["Microsoft Edge"],
        win_local_appdata_rels: &["Microsoft/Edge/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["microsoft-edge"],
        process_names: &["msedge.exe", "microsoft-edge", "msedge"],
    },
    ChromiumBrowserDef {
        id: "company.thebrowser.Browser",
        display_name: "Arc",
        macos_bundles: &["Arc.app"],
        macos_user_data_rels: &["Arc/User Data", "Arc"],
        win_local_appdata_rels: &[
            "Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data",
            "Arc/User Data",
        ],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &[],
        process_names: &["arc.exe", "arc"],
    },
    ChromiumBrowserDef {
        id: "company.thebrowser.dia",
        display_name: "Dia",
        macos_bundles: &["Dia.app"],
        macos_user_data_rels: &["Dia/User Data", "Dia"],
        win_local_appdata_rels: &["Dia/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &[],
        process_names: &["dia.exe", "dia"],
    },
    ChromiumBrowserDef {
        id: "com.operasoftware.Opera",
        display_name: "Opera",
        macos_bundles: &["Opera.app"],
        macos_user_data_rels: &["com.operasoftware.Opera", "Opera"],
        win_local_appdata_rels: &["Programs/Opera/User Data"],
        win_roaming_appdata_rels: &["Opera Software/Opera Stable"],
        linux_config_rels: &["opera"],
        process_names: &["opera.exe", "opera"],
    },
    ChromiumBrowserDef {
        id: "com.operasoftware.OperaGX",
        display_name: "Opera GX",
        macos_bundles: &["Opera GX.app"],
        macos_user_data_rels: &["com.operasoftware.OperaGX", "Opera GX"],
        win_local_appdata_rels: &["Programs/Opera GX/User Data"],
        win_roaming_appdata_rels: &["Opera Software/Opera GX Stable"],
        linux_config_rels: &["opera-gx"],
        process_names: &["opera.exe", "opera-gx"],
    },
    ChromiumBrowserDef {
        id: "com.vivaldi.Vivaldi",
        display_name: "Vivaldi",
        macos_bundles: &["Vivaldi.app"],
        macos_user_data_rels: &["Vivaldi"],
        win_local_appdata_rels: &["Vivaldi/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["vivaldi"],
        process_names: &["vivaldi.exe", "vivaldi-bin", "vivaldi"],
    },
    ChromiumBrowserDef {
        id: "org.chromium.Chromium",
        display_name: "Chromium",
        macos_bundles: &["Chromium.app"],
        macos_user_data_rels: &["Chromium"],
        win_local_appdata_rels: &["Chromium/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &["chromium", "chromium-browser"],
        process_names: &["chrome.exe", "chromium", "chromium-browser"],
    },
    ChromiumBrowserDef {
        id: "com.openai.atlas",
        display_name: "ChatGPT Atlas",
        macos_bundles: &["ChatGPT Atlas.app"],
        macos_user_data_rels: &["ChatGPT Atlas", "com.openai.atlas", "OpenAI/ChatGPT Atlas"],
        win_local_appdata_rels: &["OpenAI/ChatGPT Atlas/User Data", "ChatGPT Atlas/User Data"],
        win_roaming_appdata_rels: &[],
        linux_config_rels: &[],
        process_names: &["chatgpt atlas.exe", "atlas.exe"],
    },
];

/// Chromium-family preference domains on macOS.
pub const MACOS_CHROMIUM_DOMAIN_NAMES: [&str; 15] = [
    "com.google.Chrome",
    "com.google.Chrome.beta",
    "com.google.Chrome.canary",
    "com.brave.Browser",
    "com.brave.Browser.beta",
    "com.microsoft.edgemac",
    "org.chromium.Chromium",
    "com.vivaldi.Vivaldi",
    "com.operasoftware.Opera",
    "com.operasoftware.OperaGX",
    "ru.yandex.desktop.yandex-browser",
    "company.thebrowser.Browser",
    "company.thebrowser.dia",
    "ai.perplexity.comet",
    "com.openai.atlas",
];

/// Chromium-family HKCU policy subkeys on Windows.
pub const WINDOWS_CHROMIUM_DOMAIN_NAMES: [&str; 12] = [
    r"Software\Policies\Google\Chrome",
    r"Software\Policies\Microsoft\Edge",
    r"Software\Policies\BraveSoftware\Brave",
    r"Software\Policies\Chromium",
    r"Software\Policies\Vivaldi",
    r"Software\Policies\YandexBrowser",
    r"Software\Policies\Yandex\YandexBrowser",
    r"Software\Policies\Perplexity\Comet",
    r"Software\Policies\Opera Software\Opera Stable",
    r"Software\Policies\Opera Software\Opera GX Stable",
    r"Software\Policies\TheBrowserCompany\Arc",
    r"Software\Policies\TheBrowserCompany\Dia",
];

fn clean_pac_url(pac_url: Option<&str>) -> Option<&str> {
    pac_url.map(str::trim).filter(|u| !u.is_empty())
}

fn same_pac_url(a: &str, b: &str) -> bool {
    a.trim()
        .trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim().trim_end_matches('/'))
}

/// Builds Chromium-family (plus Firefox DoH on Windows) policy specs for Windows.
#[allow(dead_code)]
pub fn policy_specs_for_windows(pac_url: Option<&str>) -> Vec<PolicySpec> {
    let pac = clean_pac_url(pac_url);
    let mut specs = Vec::new();
    for subkey in WINDOWS_CHROMIUM_DOMAIN_NAMES {
        specs.push(PolicySpec::new(
            subkey,
            KEY_QUIC_ALLOWED,
            PolicyValue::Dword(0),
        ));
        specs.push(PolicySpec::new(
            subkey,
            KEY_DOH_MODE,
            PolicyValue::Sz("off".to_string()),
        ));
        if let Some(url) = pac {
            specs.push(PolicySpec::new(
                subkey,
                KEY_PROXY_MODE,
                PolicyValue::Sz(PROXY_MODE_PAC_SCRIPT.to_string()),
            ));
            specs.push(PolicySpec::new(
                subkey,
                KEY_PROXY_PAC_URL,
                PolicyValue::Sz(url.to_string()),
            ));
        }
    }
    specs.push(PolicySpec::new(
        r"Software\Policies\Mozilla\Firefox\DNSOverHTTPS",
        "Enabled",
        PolicyValue::Dword(0),
    ));
    specs
}

/// Builds Chromium-family policy specs for macOS.
#[allow(dead_code)]
pub fn policy_specs_for_macos(pac_url: Option<&str>) -> Vec<PolicySpec> {
    let pac = clean_pac_url(pac_url);
    let mut specs = Vec::new();
    for domain in MACOS_CHROMIUM_DOMAIN_NAMES {
        specs.push(PolicySpec::new(
            domain,
            KEY_QUIC_ALLOWED,
            PolicyValue::Bool(false),
        ));
        specs.push(PolicySpec::new(
            domain,
            KEY_DOH_MODE,
            PolicyValue::Sz("off".to_string()),
        ));
        if let Some(url) = pac {
            specs.push(PolicySpec::new(
                domain,
                KEY_PROXY_MODE,
                PolicyValue::Sz(PROXY_MODE_PAC_SCRIPT.to_string()),
            ));
            specs.push(PolicySpec::new(
                domain,
                KEY_PROXY_PAC_URL,
                PolicyValue::Sz(url.to_string()),
            ));
        }
    }
    specs
}

/// Returns the platform-appropriate Chromium/Firefox QUIC, DoH, and optional PAC policy specs.
pub fn policy_specs_with_pac(pac_url: Option<&str>) -> Vec<PolicySpec> {
    #[cfg(target_os = "windows")]
    {
        policy_specs_for_windows(pac_url)
    }
    #[cfg(target_os = "macos")]
    {
        policy_specs_for_macos(pac_url)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = pac_url;
        Vec::new()
    }
}

/// Returns the platform-appropriate Chromium/Firefox QUIC & DoH policy specs (without PAC URL).
#[allow(dead_code)]
pub fn default_policy_specs() -> Vec<PolicySpec> {
    policy_specs_with_pac(None)
}

/// Production [`PolicyStore`] backed by `crate::win_reg` on Windows and `defaults` on macOS.
pub struct RealPolicyStore;

#[cfg(target_os = "macos")]
fn macos_app_bundles_for_domain(domain: &str) -> &'static [&'static str] {
    CHROMIUM_BROWSERS
        .iter()
        .find(|b| {
            b.id == domain || (domain == "com.microsoft.Edge" && b.id == "com.microsoft.edgemac")
        })
        .map_or(&[], |b| b.macos_bundles)
}

#[cfg(target_os = "macos")]
fn macos_domain_installed(domain: &str) -> bool {
    for app_name in macos_app_bundles_for_domain(domain) {
        if std::path::Path::new("/Applications")
            .join(app_name)
            .exists()
        {
            return true;
        }
        if let Some(home) = super::user_home_dir()
            && home.join("Applications").join(app_name).exists()
        {
            return true;
        }
    }
    super::user_home_dir().is_some_and(|h| {
        h.join("Library")
            .join("Preferences")
            .join(format!("{domain}.plist"))
            .exists()
    })
}

#[cfg(target_os = "macos")]
fn is_defaults_not_found(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("does not exist") || lower.contains("not found")
}

#[cfg(target_os = "macos")]
fn parse_defaults_read(type_out: &str, val_out: &str) -> PResult<PolicyValue> {
    let t = type_out.trim().to_ascii_lowercase();
    let v = val_out.trim();
    if t.contains("boolean") {
        let b = matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        Ok(PolicyValue::Bool(b))
    } else if t.contains("integer") {
        let n = v
            .parse::<u32>()
            .map_err(|_| PlatformError::Unsupported("policy_defaults_int"))?;
        Ok(PolicyValue::Dword(n))
    } else if t.contains("string") {
        Ok(PolicyValue::Sz(v.to_string()))
    } else {
        Err(PlatformError::Unsupported("policy_defaults_type"))
    }
}

impl PolicyStore for RealPolicyStore {
    fn is_domain_applicable(&self, domain: &str) -> bool {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:check");
            return false;
        }
        #[cfg(target_os = "windows")]
        {
            let _ = domain;
            true
        }
        #[cfg(target_os = "macos")]
        {
            macos_domain_installed(domain)
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = domain;
            false
        }
    }

    fn read(&self, domain: &str, key: &str) -> PResult<Option<PolicyValue>> {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:read");
            return Err(PlatformError::DryRun);
        }
        #[cfg(target_os = "windows")]
        {
            use crate::win_reg::{
                ERROR_SUCCESS, REG_DWORD, REG_SZ, RootKey, decode_dword, decode_utf16_le_string,
                is_not_found_status, read_raw,
            };
            let raw = read_raw(RootKey::HkeyCurrentUser, domain, key);
            if is_not_found_status(raw.status) {
                return Ok(None);
            }
            if raw.status != ERROR_SUCCESS {
                return Err(PlatformError::Failed("win_reg_read_policy"));
            }
            match raw.kind {
                REG_DWORD => decode_dword(&raw.data)
                    .map(|n| Some(PolicyValue::Dword(n)))
                    .map_err(|_| PlatformError::Unsupported("policy_reg_dword")),
                REG_SZ => decode_utf16_le_string(&raw.data)
                    .map(|s| Some(PolicyValue::Sz(s)))
                    .map_err(|_| PlatformError::Unsupported("policy_reg_sz")),
                _ => Err(PlatformError::Unsupported("policy_reg_type")),
            }
        }
        #[cfg(target_os = "macos")]
        {
            let read_out = super::silent_command("defaults")
                .args(["read", domain, key])
                .output()
                .map_err(|_| PlatformError::Failed("defaults_read"))?;
            if !read_out.status.success() {
                let err = String::from_utf8_lossy(&read_out.stderr);
                if is_defaults_not_found(&err) {
                    return Ok(None);
                }
                return Err(PlatformError::Failed("defaults_read"));
            }
            let type_out = super::silent_command("defaults")
                .args(["read-type", domain, key])
                .output()
                .map_err(|_| PlatformError::Failed("defaults_read_type"))?;
            if !type_out.status.success() {
                let err = String::from_utf8_lossy(&type_out.stderr);
                if is_defaults_not_found(&err) {
                    return Ok(None);
                }
                return Err(PlatformError::Failed("defaults_read_type"));
            }
            let val_s = String::from_utf8_lossy(&read_out.stdout);
            let type_s = String::from_utf8_lossy(&type_out.stdout);
            parse_defaults_read(&type_s, &val_s).map(Some)
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (domain, key);
            Err(PlatformError::Unsupported("browser_policy"))
        }
    }

    fn write(&self, domain: &str, key: &str, value: &PolicyValue) -> PResult<()> {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:write");
            return Err(PlatformError::DryRun);
        }
        #[cfg(target_os = "windows")]
        {
            use crate::win_reg::{RootKey, set_dword, set_sz};
            match value {
                PolicyValue::Dword(n) => set_dword(RootKey::HkeyCurrentUser, domain, key, *n)
                    .map_err(|_| PlatformError::Failed("win_reg_set_dword")),
                PolicyValue::Sz(s) => set_sz(RootKey::HkeyCurrentUser, domain, key, s)
                    .map_err(|_| PlatformError::Failed("win_reg_set_sz")),
                PolicyValue::Bool(b) => {
                    set_dword(RootKey::HkeyCurrentUser, domain, key, u32::from(*b))
                        .map_err(|_| PlatformError::Failed("win_reg_set_bool"))
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            let mut cmd = super::silent_command("defaults");
            cmd.args(["write", domain, key]);
            match value {
                PolicyValue::Bool(b) => {
                    cmd.args(["-bool", if *b { "true" } else { "false" }]);
                }
                PolicyValue::Dword(n) => {
                    cmd.args(["-int", &n.to_string()]);
                }
                PolicyValue::Sz(s) => {
                    cmd.args(["-string", s]);
                }
            }
            let out = cmd
                .output()
                .map_err(|_| PlatformError::Failed("defaults_write"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(PlatformError::Failed("defaults_write"))
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (domain, key, value);
            Err(PlatformError::Unsupported("browser_policy"))
        }
    }

    fn delete(&self, domain: &str, key: &str) -> PResult<()> {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:delete");
            return Err(PlatformError::DryRun);
        }
        #[cfg(target_os = "windows")]
        {
            use crate::win_reg::{RootKey, delete_value};
            delete_value(RootKey::HkeyCurrentUser, domain, key)
                .map_err(|_| PlatformError::Failed("win_reg_delete_policy"))
        }
        #[cfg(target_os = "macos")]
        {
            let out = super::silent_command("defaults")
                .args(["delete", domain, key])
                .output()
                .map_err(|_| PlatformError::Failed("defaults_delete"))?;
            if out.status.success() {
                return Ok(());
            }
            let err = String::from_utf8_lossy(&out.stderr);
            if is_defaults_not_found(&err) {
                Ok(())
            } else {
                Err(PlatformError::Failed("defaults_delete"))
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (domain, key);
            Err(PlatformError::Unsupported("browser_policy"))
        }
    }
}

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

/// Applies the platform's default QUIC/DoH policies through `j` (without PAC URL). Non-fatal:
/// individual domain/key failures or unsupported platforms are logged and skipped.
#[allow(dead_code)]
pub fn apply_browser_policies(j: &mut Journal, p: &dyn Platform) -> PolicyApplyReport {
    apply_browser_policies_with_pac(j, p, None)
}

/// Applies browser QUIC/DoH policies and, when `pac_url` is `Some`, also sets
/// `ProxyMode = "pac_script"` and `ProxyPacUrl = <pac_url>` across Chromium-family browsers,
/// plus injects `"proxy"` into non-running Chromium profile `Preferences` files.
pub fn apply_browser_policies_with_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: Option<&str>,
) -> PolicyApplyReport {
    let ctx = if os_effects_enabled() {
        FileCtx::real_with_fs(j.fs())
    } else {
        None
    };
    apply_browser_policies_with_pac_in(j, p, pac_url, ctx.as_ref(), Os::current(), &RealProbe)
}

/// Applies browser QUIC/DoH/PAC policies and (when `ctx` is `Some` and `pac_url` is `Some`)
/// injects `"proxy"` into `Preferences` files of non-running Chromium-family browsers.
pub fn apply_browser_policies_with_pac_in(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: Option<&str>,
    ctx: Option<&FileCtx>,
    os: Os,
    probe: &dyn SystemProbe,
) -> PolicyApplyReport {
    let specs = policy_specs_with_pac(pac_url);
    let mut report = apply_policy_specs(j, p, &specs);
    if let Some(url) = clean_pac_url(pac_url)
        && let Some(file_ctx) = ctx
    {
        apply_browser_prefs_with_pac(j, p, url, file_ctx, os, probe, &mut report);
        let status = detect_browser_pac_status_in(file_ctx, os, probe, Some(url));
        report.pac_policy_active = !status.browsers_pac_active.is_empty();
    }
    report
}

/// Restores every journaled [`Resource::BrowserPolicy`] and non-running
/// [`Resource::BrowserPacPref`] entry to its pre-Zastava baseline.
#[allow(dead_code)]
pub fn revert_browser_policies(j: &mut Journal, p: &dyn Platform) -> RecoveryReport {
    if os_effects_enabled() {
        revert_browser_policies_with(j, p, Os::current(), &RealProbe)
    } else {
        j.restore_where(p, |r| {
            matches!(
                r,
                Resource::BrowserPolicy { .. } | Resource::BrowserPacPref { .. }
            )
        })
    }
}

/// Restores every journaled [`Resource::BrowserPolicy`] and every [`Resource::BrowserPacPref`]
/// whose browser is not currently running; running browsers are skipped with
/// [`Outcome::Skipped`] (`"browser_running"`) so they don't overwrite `Preferences` on exit.
pub fn revert_browser_policies_with(
    j: &mut Journal,
    p: &dyn Platform,
    os: Os,
    probe: &dyn SystemProbe,
) -> RecoveryReport {
    let has_prefs = j
        .entries()
        .iter()
        .any(|e| matches!(e.resource, Resource::BrowserPacPref { .. }));
    let running_map = if has_prefs {
        inspect_running_browsers(probe, os, None)
    } else {
        Some(BTreeMap::new())
    };
    let skipped_prefs: Vec<String> = j
        .entries()
        .iter()
        .filter_map(|e| match &e.resource {
            Resource::BrowserPacPref { domain, .. } => {
                let is_running = match &running_map {
                    Some(map) => map.get(domain.as_str()).is_some_and(|i| i.running),
                    None => true,
                };
                is_running.then(|| e.resource.id())
            }
            _ => None,
        })
        .collect();

    let mut report = j.restore_where(p, |r| match r {
        Resource::BrowserPolicy { .. } => true,
        Resource::BrowserPacPref { domain, .. } => match &running_map {
            Some(map) => !map.get(domain.as_str()).is_some_and(|i| i.running),
            None => false,
        },
        _ => false,
    });
    for id in skipped_prefs {
        report.items.push(ReportItem {
            resource: id,
            outcome: Outcome::Skipped("browser_running"),
        });
    }
    report
}

// ---------------------------------------------------------------------------------------------
// Chromium `Preferences` JSON PAC injection, inspection, reconciliation, and relaunch
// ---------------------------------------------------------------------------------------------

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

/// Builds the compact JSON string for Chromium's profile `Preferences` `"proxy"` object.
pub fn build_browser_proxy_json_string(pac_url: &str) -> String {
    serde_json::json!({
        "mode": PROXY_MODE_PAC_SCRIPT,
        "pac_url": pac_url,
        "pac_mandatory": false
    })
    .to_string()
}

/// Extracts `pac_url` from a serialized `"proxy"` JSON object when `mode == "pac_script"`.
pub fn extract_pac_url_from_proxy_json(raw_json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(raw_json).ok()?;
    let obj = val.as_object()?;
    let mode = obj.get("mode")?.as_str()?;
    if !mode.trim().eq_ignore_ascii_case(PROXY_MODE_PAC_SCRIPT) {
        return None;
    }
    obj.get("pac_url")?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Compares two serialized `"proxy"` JSON values structurally (normalizing `pac_url`).
pub fn same_browser_proxy_json(a: &str, b: &str) -> bool {
    let Ok(va) = serde_json::from_str::<serde_json::Value>(a) else {
        return false;
    };
    let Ok(vb) = serde_json::from_str::<serde_json::Value>(b) else {
        return false;
    };
    if let (Some(oa), Some(ob)) = (va.as_object(), vb.as_object()) {
        let mode_a = oa
            .get("mode")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase());
        let mode_b = ob
            .get("mode")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase());
        if mode_a.as_deref() == Some(PROXY_MODE_PAC_SCRIPT)
            && mode_b.as_deref() == Some(PROXY_MODE_PAC_SCRIPT)
        {
            let url_ok = match (
                oa.get("pac_url").and_then(|v| v.as_str()),
                ob.get("pac_url").and_then(|v| v.as_str()),
            ) {
                (Some(ua), Some(ub)) => same_pac_url(ua, ub),
                _ => false,
            };
            let mandatory_a = oa
                .get("pac_mandatory")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mandatory_b = ob
                .get("pac_mandatory")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            return url_ok && mandatory_a == mandatory_b && oa.len() == ob.len();
        }
    }
    va == vb
}

/// Returns `true` iff `url` points to `http://127.0.0.1:<port>/proxy.pac` (any non-zero port).
pub fn is_zastava_local_pac_url(url: &str) -> bool {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("http://127.0.0.1:") else {
        return false;
    };
    let Some((port_str, tail)) = rest.split_once('/') else {
        return false;
    };
    let Ok(port) = port_str.parse::<u16>() else {
        return false;
    };
    if port == 0 {
        return false;
    }
    let path_only = tail.split('?').next().unwrap_or("");
    path_only.trim_end_matches('/') == "proxy.pac"
}

/// Reads the serialized `"proxy"` key from a Chromium `Preferences` JSON file.
/// Returns `Ok(None)` when the file or key does not exist, and logs + errors on invalid JSON.
pub fn read_browser_proxy_pref(fs: &dyn Fs, path: &Path) -> PResult<Option<String>> {
    let bytes = match fs.read(path) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(None),
        Err(_) => return Err(PlatformError::Failed("prefs_read")),
    };
    let root: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "Застава: некорректный JSON в {}, пропуск: {err}",
                path.display()
            );
            return Err(PlatformError::Failed("prefs_invalid_json"));
        }
    };
    let Some(obj) = root.as_object() else {
        eprintln!(
            "Застава: корень {} не является JSON-объектом, пропуск",
            path.display()
        );
        return Err(PlatformError::Failed("prefs_invalid_json"));
    };
    match obj.get("proxy") {
        Some(val) => serde_json::to_string(val)
            .map(Some)
            .map_err(|_| PlatformError::Failed("prefs_serialize")),
        None => Ok(None),
    }
}

/// Atomically updates or removes the `"proxy"` key in a Chromium `Preferences` JSON file
/// while preserving all other JSON keys. Refuses to overwrite non-JSON or missing files.
pub fn write_browser_proxy_pref(fs: &dyn Fs, path: &Path, proxy_json: Option<&str>) -> PResult<()> {
    let bytes = match fs.read(path) {
        Ok(Some(b)) => b,
        Ok(None) => return Err(PlatformError::Failed("prefs_missing")),
        Err(_) => return Err(PlatformError::Failed("prefs_read")),
    };
    let mut root: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "Застава: некорректный JSON в {}, запись отменена: {err}",
                path.display()
            );
            return Err(PlatformError::Failed("prefs_invalid_json"));
        }
    };
    let Some(obj) = root.as_object_mut() else {
        eprintln!(
            "Застава: корень {} не является JSON-объектом, запись отменена",
            path.display()
        );
        return Err(PlatformError::Failed("prefs_invalid_json"));
    };
    match proxy_json {
        Some(raw) => {
            let val: serde_json::Value =
                serde_json::from_str(raw).map_err(|_| PlatformError::Failed("prefs_proxy_json"))?;
            obj.insert("proxy".to_string(), val);
        }
        None => {
            obj.remove("proxy");
        }
    }
    let out = serde_json::to_vec(&root).map_err(|_| PlatformError::Failed("prefs_serialize"))?;
    fs.write_atomic(path, &out, WriteMode::KeepExisting)
        .map_err(|_| PlatformError::Failed("prefs_write"))
}

/// Returns existing User Data directories for `browser` under `ctx` for `os`.
pub fn browser_user_data_dirs(browser: &ChromiumBrowserDef, ctx: &FileCtx, os: Os) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    match os {
        Os::Macos => {
            let base = ctx.home.join("Library").join("Application Support");
            for rel in browser.macos_user_data_rels {
                candidates.push(base.join(rel));
            }
        }
        Os::Windows => {
            for rel in browser.win_local_appdata_rels {
                candidates.push(ctx.local_appdata.join(rel));
            }
            let roaming = ctx.home.join("AppData").join("Roaming");
            for rel in browser.win_roaming_appdata_rels {
                candidates.push(roaming.join(rel));
            }
        }
        Os::Linux => {
            let base = ctx.home.join(".config");
            for rel in browser.linux_config_rels {
                candidates.push(base.join(rel));
            }
        }
    }
    candidates
        .into_iter()
        .filter(|dir| {
            ctx.fs.exists(dir)
                || ctx.fs.exists(&dir.join("Preferences"))
                || !ctx.fs.list_dir(dir).is_empty()
        })
        .collect()
}

/// Discovers all profile `Preferences` files inside one Chromium User Data directory
/// (direct `Preferences`, `Default`, `Profile *`, `Guest Profile`, `System Profile`, and any
/// profile key listed in `Local State`'s `profile.info_cache`).
pub fn discover_browser_prefs_files_in(fs: &dyn Fs, user_data_dir: &Path) -> Vec<PathBuf> {
    let mut found = BTreeSet::new();
    let direct = user_data_dir.join("Preferences");
    if fs.exists(&direct) {
        found.insert(direct);
    }

    for child in fs.list_dir(user_data_dir) {
        let Some(name) = child.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let is_profile_dir = name == "Default"
            || name == "Guest Profile"
            || name == "System Profile"
            || name.starts_with("Profile ");
        if is_profile_dir {
            let prefs = child.join("Preferences");
            if fs.exists(&prefs) {
                found.insert(prefs);
            }
        }
    }

    // Also inspect Chromium's `Local State` -> `profile.info_cache` for non-standard profile folders.
    let local_state = user_data_dir.join("Local State");
    if let Ok(Some(bytes)) = fs.read(&local_state)
        && let Ok(root) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(cache) = root
            .get("profile")
            .and_then(|p| p.get("info_cache"))
            .and_then(|c| c.as_object())
    {
        for key in cache.keys() {
            let prefs = user_data_dir.join(key).join("Preferences");
            if fs.exists(&prefs) {
                found.insert(prefs);
            }
        }
    }

    found.into_iter().collect()
}

/// Discovers all `Preferences` files for `browser` across all existing User Data dirs.
pub fn browser_prefs_files_in(browser: &ChromiumBrowserDef, ctx: &FileCtx, os: Os) -> Vec<PathBuf> {
    let mut found = BTreeSet::new();
    for dir in browser_user_data_dirs(browser, ctx, os) {
        for prefs in discover_browser_prefs_files_in(&*ctx.fs, &dir) {
            found.insert(prefs);
        }
    }
    found.into_iter().collect()
}

/// Finds the `.app` bundle path on macOS (`/Applications` or `~/Applications`) via `ctx.fs`.
pub fn find_macos_app_bundle_in(browser: &ChromiumBrowserDef, ctx: &FileCtx) -> Option<PathBuf> {
    for app_name in browser.macos_bundles {
        // Build the POSIX `/Applications/<app>` path directly so simulated `Os::Macos` calls on
        // Windows do not insert a `\` separator via `PathBuf::join`.
        let sys_app = PathBuf::from(format!("/Applications/{app_name}"));
        if ctx.fs.exists(&sys_app) {
            return Some(sys_app);
        }
        let user_app = ctx.home.join("Applications").join(app_name);
        if ctx.fs.exists(&user_app) {
            return Some(user_app);
        }
    }
    None
}

fn any_chromium_browser_present(ctx: &FileCtx, os: Os) -> bool {
    CHROMIUM_BROWSERS.iter().any(|b| {
        !browser_user_data_dirs(b, ctx, os).is_empty()
            || (os == Os::Macos && find_macos_app_bundle_in(b, ctx).is_some())
    })
}

fn extract_proxy_pac_url_arg(line: &str) -> Option<&str> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find("--proxy-pac-url=")?;
    let after = &line[idx + "--proxy-pac-url=".len()..];
    if let Some(quoted) = after.strip_prefix('"') {
        quoted.split('"').next()
    } else if let Some(quoted) = after.strip_prefix('\'') {
        quoted.split('\'').next()
    } else {
        after.split_whitespace().next()
    }
}

fn linux_exe_basename(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let cmd = if let Some(idx) = trimmed.find(" --") {
        trimmed[..idx].trim()
    } else {
        trimmed.split_whitespace().next().unwrap_or("")
    };
    Path::new(cmd)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
}

fn parse_tasklist_csv_image(line: &str) -> Option<String> {
    let first = line.trim().split(',').next()?;
    let unquoted = first.trim().trim_matches('"').trim().to_ascii_lowercase();
    (!unquoted.is_empty()).then_some(unquoted)
}

/// Inspects running OS processes via `probe` and returns a map keyed by [`ChromiumBrowserDef::id`].
/// Returns `None` when the process listing command itself failed.
pub fn inspect_running_browsers(
    probe: &dyn SystemProbe,
    os: Os,
    expected_pac_url: Option<&str>,
) -> Option<BTreeMap<&'static str, RunningBrowserInfo>> {
    let expected = clean_pac_url(expected_pac_url);
    let mut map = BTreeMap::<&'static str, RunningBrowserInfo>::new();

    match os {
        Os::Macos => {
            let listing = probe.run("ps", &["-axo", "args="])?;
            for line in listing.lines() {
                let lower = line.trim().to_ascii_lowercase();
                if lower.is_empty() {
                    continue;
                }
                for browser in CHROMIUM_BROWSERS {
                    let matched = browser.macos_bundles.iter().any(|bundle| {
                        let needle = format!("/{}/contents/", bundle.to_ascii_lowercase());
                        lower.contains(&needle)
                    });
                    if matched {
                        let entry = map.entry(browser.id).or_default();
                        entry.running = true;
                        if let Some(exp) = expected
                            && extract_proxy_pac_url_arg(line).is_some_and(|u| same_pac_url(u, exp))
                        {
                            entry.has_pac_flag = true;
                        }
                    }
                }
            }
        }
        Os::Linux => {
            let listing = probe.run("ps", &["-axo", "args="])?;
            for line in listing.lines() {
                let Some(exe) = linux_exe_basename(line) else {
                    continue;
                };
                for browser in CHROMIUM_BROWSERS {
                    if browser.process_names.iter().any(|p| *p == exe) {
                        let entry = map.entry(browser.id).or_default();
                        entry.running = true;
                        if let Some(exp) = expected
                            && extract_proxy_pac_url_arg(line).is_some_and(|u| same_pac_url(u, exp))
                        {
                            entry.has_pac_flag = true;
                        }
                    }
                }
            }
        }
        Os::Windows => {
            let listing = probe.run("tasklist", &["/FO", "CSV", "/NH"])?;
            for line in listing.lines() {
                let Some(image) = parse_tasklist_csv_image(line) else {
                    continue;
                };
                for browser in CHROMIUM_BROWSERS {
                    if browser.process_names.iter().any(|p| *p == image) {
                        let entry = map.entry(browser.id).or_default();
                        entry.running = true;
                    }
                }
            }
        }
    }

    Some(map)
}

fn all_prefs_match_pac(fs: &dyn Fs, prefs_files: &[PathBuf], expected_pac_url: &str) -> bool {
    if prefs_files.is_empty() {
        return false;
    }
    let mut matched = 0usize;
    for path in prefs_files {
        match read_browser_proxy_pref(fs, path) {
            Ok(Some(raw)) => {
                if extract_pac_url_from_proxy_json(&raw)
                    .is_some_and(|u| same_pac_url(&u, expected_pac_url))
                {
                    matched += 1;
                } else {
                    return false;
                }
            }
            Ok(None) | Err(_) => return false,
        }
    }
    matched == prefs_files.len()
}

/// Evaluates which installed Chromium browsers actually have PAC enforced (`Preferences` JSON or
/// `--proxy-pac-url` flag) vs which running browsers still need a restart.
pub fn detect_browser_pac_status_in(
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
    pac_url: Option<&str>,
) -> BrowserPacStatus {
    let mut status = BrowserPacStatus::default();
    let Some(expected) = clean_pac_url(pac_url) else {
        return status;
    };
    if !any_chromium_browser_present(ctx, os) {
        return status;
    }
    let running_map = inspect_running_browsers(probe, os, Some(expected)).unwrap_or_default();

    for browser in &CHROMIUM_BROWSERS {
        let prefs_files = browser_prefs_files_in(browser, ctx, os);
        let all_prefs_ok = all_prefs_match_pac(&*ctx.fs, &prefs_files, expected);
        let info = running_map.get(browser.id).copied().unwrap_or_default();

        if info.running {
            if info.has_pac_flag || all_prefs_ok {
                status
                    .browsers_pac_active
                    .push(browser.display_name.to_string());
            } else {
                status
                    .browsers_needing_restart
                    .push(browser.display_name.to_string());
            }
        } else if all_prefs_ok {
            status
                .browsers_pac_active
                .push(browser.display_name.to_string());
        }
    }

    status
}

fn apply_browser_prefs_for_browser(
    j: &mut Journal,
    p: &dyn Platform,
    browser: &ChromiumBrowserDef,
    prefs_files: &[PathBuf],
    desired_json: &str,
    report: &mut PolicyApplyReport,
) {
    for path in prefs_files {
        let res = Resource::BrowserPacPref {
            domain: browser.id.to_string(),
            file: path.to_string_lossy().into_owned(),
        };
        let val = Value::Json(Some(desired_json.to_string()));
        match j.apply(p, &res, val) {
            Ok(ApplyOutcome::Applied | ApplyOutcome::Rebased) => report.applied += 1,
            Ok(ApplyOutcome::Unchanged) => report.unchanged += 1,
            Err(JournalError::Platform(PlatformError::DryRun | PlatformError::Unsupported(_))) => {
                report.skipped += 1;
            }
            Err(err) => {
                report.failed += 1;
                eprintln!(
                    "Застава: не удалось применить proxy в {}: {err}",
                    path.display()
                );
            }
        }
    }
}

fn apply_browser_prefs_with_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
    report: &mut PolicyApplyReport,
) {
    if !any_chromium_browser_present(ctx, os) {
        return;
    }
    let Some(running_map) = inspect_running_browsers(probe, os, Some(pac_url)) else {
        eprintln!("Застава: список процессов недоступен, Preferences браузеров не изменены");
        return;
    };
    let desired = build_browser_proxy_json_string(pac_url);
    for browser in &CHROMIUM_BROWSERS {
        let prefs_files = browser_prefs_files_in(browser, ctx, os);
        if prefs_files.is_empty() {
            continue;
        }
        if running_map.get(browser.id).is_some_and(|i| i.running) {
            report.skipped += prefs_files.len();
            continue;
        }
        apply_browser_prefs_for_browser(j, p, browser, &prefs_files, &desired, report);
    }
}

/// Fast read-only check whether any non-running browser has a `Preferences` file not yet patched
/// with `pac_url`. Avoids locking the journal during periodic polling when everything is in sync.
pub fn any_non_running_browser_needs_pac_sync_in(
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
    pac_url: &str,
) -> bool {
    let Some(expected) = clean_pac_url(Some(pac_url)) else {
        return false;
    };
    if !any_chromium_browser_present(ctx, os) {
        return false;
    }
    let Some(running_map) = inspect_running_browsers(probe, os, Some(expected)) else {
        return false;
    };
    for browser in &CHROMIUM_BROWSERS {
        if running_map.get(browser.id).is_some_and(|i| i.running) {
            continue;
        }
        let prefs_files = browser_prefs_files_in(browser, ctx, os);
        if prefs_files.is_empty() {
            continue;
        }
        for path in prefs_files {
            if let Ok(existing) = read_browser_proxy_pref(&*ctx.fs, &path) {
                let matches = existing
                    .as_deref()
                    .and_then(extract_pac_url_from_proxy_json)
                    .is_some_and(|u| same_pac_url(&u, expected));
                if !matches {
                    return true;
                }
            }
        }
    }
    false
}

/// Reconciles `Preferences` JSON for browsers that have exited since protection was toggled:
/// when `pac_url` is `Some`, injects PAC into newly closed browsers; when `None`, restores any
/// deferred journaled `BrowserPacPref` entries whose browser has exited. Returns `true` if any
/// file changed.
pub fn reconcile_browser_pac_prefs_in(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: Option<&str>,
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
) -> bool {
    if let Some(url) = clean_pac_url(pac_url) {
        let mut report = PolicyApplyReport::default();
        apply_browser_prefs_with_pac(j, p, url, ctx, os, probe, &mut report);
        return report.applied > 0;
    }

    let has_prefs = j
        .entries()
        .iter()
        .any(|e| matches!(e.resource, Resource::BrowserPacPref { .. }));
    let mut changed = false;
    if has_prefs && let Some(running_map) = inspect_running_browsers(probe, os, None) {
        let rec = j.restore_where(p, |r| match r {
            Resource::BrowserPacPref { domain, .. } => {
                !running_map.get(domain.as_str()).is_some_and(|i| i.running)
            }
            _ => false,
        });
        if rec
            .items
            .iter()
            .any(|i| matches!(i.outcome, Outcome::Restored))
        {
            changed = true;
        }
    }
    if clear_stale_browser_pac_prefs_in(ctx, os, probe) > 0 {
        changed = true;
    }
    changed
}

/// Removes `"proxy"` from `Preferences` files of non-running browsers ONLY when `proxy.pac_url`
/// points to `http://127.0.0.1:<any>/proxy.pac`. Returns the count of cleaned files.
pub fn clear_stale_browser_pac_prefs_in(ctx: &FileCtx, os: Os, probe: &dyn SystemProbe) -> usize {
    if !any_chromium_browser_present(ctx, os) {
        return 0;
    }
    let Some(running_map) = inspect_running_browsers(probe, os, None) else {
        return 0;
    };
    let mut cleaned = 0usize;
    for browser in &CHROMIUM_BROWSERS {
        if running_map.get(browser.id).is_some_and(|i| i.running) {
            continue;
        }
        for path in browser_prefs_files_in(browser, ctx, os) {
            if let Ok(Some(raw)) = read_browser_proxy_pref(&*ctx.fs, &path)
                && extract_pac_url_from_proxy_json(&raw)
                    .is_some_and(|u| is_zastava_local_pac_url(&u))
                && write_browser_proxy_pref(&*ctx.fs, &path, None).is_ok()
            {
                cleaned += 1;
            }
        }
    }
    cleaned
}

fn is_osascript_permission_denied(stderr: &str) -> bool {
    stderr.contains("-1743") || stderr.to_ascii_lowercase().contains("not authorized")
}

/// Default quit wait budget for graceful browser relaunch (~3.5s).
pub const BROWSER_QUIT_TIMEOUT: Duration = Duration::from_millis(3500);
pub const BROWSER_QUIT_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Gracefully quits running Chromium browsers that still need PAC, injects `"proxy"` into all
/// their `Preferences` files (via `Journal`), and relaunches them with `--proxy-pac-url=<pac_url>`.
#[allow(clippy::too_many_arguments)]
pub fn relaunch_browsers_with_pac_with(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
    launcher: &dyn AppLauncher,
    timing: QuitTiming,
) -> RelaunchSummary {
    let mut summary = RelaunchSummary::default();
    if os != Os::Macos {
        summary.unsupported = true;
        return summary;
    }
    let Some(url) = clean_pac_url(Some(pac_url)) else {
        return summary;
    };

    let status = detect_browser_pac_status_in(ctx, os, probe, Some(url));
    if status.browsers_needing_restart.is_empty() {
        return summary;
    }

    let desired = build_browser_proxy_json_string(url);

    for browser in &CHROMIUM_BROWSERS {
        if !status
            .browsers_needing_restart
            .iter()
            .any(|name| name == browser.display_name)
        {
            continue;
        }

        let quit_args = vec![
            "-e".to_string(),
            format!("tell application id \"{}\" to quit", browser.id),
        ];
        if let Some(res) = launcher.run("osascript", &quit_args)
            && !res.success
            && is_osascript_permission_denied(&res.stderr)
        {
            summary.needs_automation_permission = true;
            summary.failed.push(browser.display_name.to_string());
            continue;
        }

        let started = Instant::now();
        let mut closed = false;
        loop {
            match inspect_running_browsers(probe, os, Some(url)) {
                Some(map) if !map.get(browser.id).is_some_and(|i| i.running) => {
                    closed = true;
                    break;
                }
                _ => {}
            }
            if started.elapsed() >= timing.timeout {
                break;
            }
            std::thread::sleep(timing.interval);
        }

        if !closed {
            summary.skipped.push(browser.display_name.to_string());
            continue;
        }

        let prefs_files = browser_prefs_files_in(browser, ctx, os);
        let mut pref_report = PolicyApplyReport::default();
        apply_browser_prefs_for_browser(j, p, browser, &prefs_files, &desired, &mut pref_report);
        if pref_report.failed > 0 {
            eprintln!(
                "Застава: частичная ошибка записи Preferences при перезапуске {}",
                browser.display_name
            );
        }

        let mut open_args = if let Some(app_path) = find_macos_app_bundle_in(browser, ctx) {
            let raw = app_path.to_string_lossy().into_owned();
            let posix = if cfg!(windows) {
                raw.replace('\\', "/")
            } else {
                raw
            };
            vec!["-a".to_string(), posix]
        } else {
            vec!["-b".to_string(), browser.id.to_string()]
        };
        open_args.push("--args".to_string());
        open_args.push(format!("--proxy-pac-url={url}"));

        match launcher.run("open", &open_args) {
            Some(res) if res.success => {
                summary.restarted.push(browser.display_name.to_string());
            }
            _ => {
                summary.failed.push(browser.display_name.to_string());
            }
        }
    }

    summary
}

/// Returns `true` when at least one installed/applicable browser domain in `domains` currently has
/// `ProxyMode = "pac_script"` and `ProxyPacUrl` pointing at `pac_url`.
#[allow(dead_code)]
pub fn is_pac_policy_active_in(store: &dyn PolicyStore, domains: &[&str], pac_url: &str) -> bool {
    let Some(expected) = clean_pac_url(Some(pac_url)) else {
        return false;
    };
    for domain in domains {
        if !store.is_domain_applicable(domain) {
            continue;
        }
        let Ok(Some(PolicyValue::Sz(actual_url))) = store.read(domain, KEY_PROXY_PAC_URL) else {
            continue;
        };
        if !same_pac_url(&actual_url, expected) {
            continue;
        }
        let Ok(Some(PolicyValue::Sz(mode))) = store.read(domain, KEY_PROXY_MODE) else {
            continue;
        };
        if mode.trim().eq_ignore_ascii_case(PROXY_MODE_PAC_SCRIPT) {
            return true;
        }
    }
    false
}

/// Checks [`is_pac_policy_active_in`] for the current platform's Chromium-family policy domains.
#[allow(dead_code)]
pub fn is_pac_policy_active(store: &dyn PolicyStore, pac_url: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        is_pac_policy_active_in(store, &WINDOWS_CHROMIUM_DOMAIN_NAMES, pac_url)
    }
    #[cfg(target_os = "macos")]
    {
        is_pac_policy_active_in(store, &MACOS_CHROMIUM_DOMAIN_NAMES, pac_url)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (store, pac_url);
        false
    }
}

/// Applies explicit `specs` through `j` using `j.policy_store()`, recording baselines first.
pub fn apply_policy_specs(
    j: &mut Journal,
    p: &dyn Platform,
    specs: &[PolicySpec],
) -> PolicyApplyReport {
    let mut report = PolicyApplyReport::default();
    let store = j.policy_store_arc();
    for spec in specs {
        if !store.is_domain_applicable(&spec.domain) {
            report.skipped += 1;
            continue;
        }
        let res = Resource::BrowserPolicy {
            domain: spec.domain.clone(),
            key: spec.key.clone(),
        };
        let val = Value::Policy(Some(spec.value.clone()));
        match j.apply(p, &res, val) {
            Ok(ApplyOutcome::Applied | ApplyOutcome::Rebased) => report.applied += 1,
            Ok(ApplyOutcome::Unchanged) => report.unchanged += 1,
            Err(JournalError::Platform(PlatformError::DryRun | PlatformError::Unsupported(_))) => {
                report.skipped += 1;
            }
            Err(err) => {
                report.failed += 1;
                eprintln!("Застава: не удалось применить политику {}: {err}", res.id());
            }
        }
    }
    report
}

/// In-memory [`PolicyStore`] for unit and integration tests.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
#[derive(Default)]
pub struct FakePolicyStore {
    inner: Mutex<FakePolicyState>,
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
#[derive(Default)]
struct FakePolicyState {
    applicable_domains: BTreeMap<String, bool>,
    values: BTreeMap<(String, String), PolicyValue>,
    fail_writes: bool,
    fail_reads: bool,
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
impl FakePolicyStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_domain_applicable(&self, domain: &str, applicable: bool) {
        self.inner
            .lock()
            .unwrap()
            .applicable_domains
            .insert(domain.to_string(), applicable);
    }

    pub fn preset(&self, domain: &str, key: &str, value: PolicyValue) {
        let mut g = self.inner.lock().unwrap();
        g.applicable_domains
            .entry(domain.to_string())
            .or_insert(true);
        g.values
            .insert((domain.to_string(), key.to_string()), value);
    }

    pub fn get(&self, domain: &str, key: &str) -> Option<PolicyValue> {
        self.inner
            .lock()
            .unwrap()
            .values
            .get(&(domain.to_string(), key.to_string()))
            .cloned()
    }

    pub fn remove_raw(&self, domain: &str, key: &str) {
        self.inner
            .lock()
            .unwrap()
            .values
            .remove(&(domain.to_string(), key.to_string()));
    }

    pub fn set_fail_writes(&self, fail: bool) {
        self.inner.lock().unwrap().fail_writes = fail;
    }

    pub fn set_fail_reads(&self, fail: bool) {
        self.inner.lock().unwrap().fail_reads = fail;
    }
}

#[cfg(any(test, feature = "test-support"))]
impl PolicyStore for FakePolicyStore {
    fn is_domain_applicable(&self, domain: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.applicable_domains.get(domain).copied().unwrap_or(true)
    }

    fn read(&self, domain: &str, key: &str) -> PResult<Option<PolicyValue>> {
        let g = self.inner.lock().unwrap();
        if g.fail_reads {
            return Err(PlatformError::Failed("fake_read"));
        }
        Ok(g.values
            .get(&(domain.to_string(), key.to_string()))
            .cloned())
    }

    fn write(&self, domain: &str, key: &str, value: &PolicyValue) -> PResult<()> {
        let mut g = self.inner.lock().unwrap();
        if g.fail_writes {
            return Err(PlatformError::Failed("fake_write"));
        }
        g.values
            .insert((domain.to_string(), key.to_string()), value.clone());
        Ok(())
    }

    fn delete(&self, domain: &str, key: &str) -> PResult<()> {
        let mut g = self.inner.lock().unwrap();
        if g.fail_writes {
            return Err(PlatformError::Failed("fake_delete"));
        }
        g.values.remove(&(domain.to_string(), key.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysproxy::fs::FakeFs;
    use crate::sysproxy::journal::{EntryState, Outcome, recover_with};
    use crate::sysproxy::platform::FakePlatform;
    use std::path::Path;

    const DIR: &str = "/data";

    fn sample_specs() -> Vec<PolicySpec> {
        vec![
            PolicySpec::new("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(false)),
            PolicySpec::new(
                "com.google.Chrome",
                "DnsOverHttpsMode",
                PolicyValue::Sz("off".to_string()),
            ),
        ]
    }

    #[test]
    fn apply_from_absent_writes_and_restore_deletes() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());

        let rep = apply_policy_specs(&mut j, &plat, &sample_specs());
        assert_eq!(rep.applied, 2);
        assert_eq!(rep.failed, 0);
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(false))
        );
        assert_eq!(
            store.get("com.google.Chrome", "DnsOverHttpsMode"),
            Some(PolicyValue::Sz("off".to_string()))
        );

        let rec = j.restore_all(&plat);
        assert_eq!(rec.items.len(), 2);
        assert!(rec.items.iter().all(|i| i.outcome == Outcome::Restored));
        assert_eq!(store.get("com.google.Chrome", "QuicAllowed"), None);
        assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
    }

    #[test]
    fn apply_over_existing_user_setting_restores_original_value() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));
        store.preset(
            "com.google.Chrome",
            "DnsOverHttpsMode",
            PolicyValue::Sz("automatic".to_string()),
        );

        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());
        let rep = apply_policy_specs(&mut j, &plat, &sample_specs());
        assert_eq!(rep.applied, 2);
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(false))
        );

        // Re-applying while active is idempotent.
        let rep2 = apply_policy_specs(&mut j, &plat, &sample_specs());
        assert_eq!(rep2.unchanged, 2);

        let rec = j.restore_all(&plat);
        assert!(rec.items.iter().all(|i| i.outcome == Outcome::Restored));
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(true))
        );
        assert_eq!(
            store.get("com.google.Chrome", "DnsOverHttpsMode"),
            Some(PolicyValue::Sz("automatic".to_string()))
        );
    }

    #[test]
    fn external_change_blocks_blind_overwrite_on_restore() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());

        apply_policy_specs(&mut j, &plat, &sample_specs());
        // Admin/MDM changed QuicAllowed while Zastava was running.
        store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));

        let rec = j.restore_all(&plat);
        let quic = rec
            .items
            .iter()
            .find(|i| i.resource.ends_with(":QuicAllowed"))
            .unwrap();
        assert_eq!(quic.outcome, Outcome::ExternalChange);
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(true)),
            "external change must not be deleted or overwritten"
        );
        // The untouched DoH key is still restored to absent.
        assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
    }

    #[test]
    fn inapplicable_domain_is_skipped_without_reading_or_writing() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        store.set_domain_applicable("com.microsoft.Edge", false);
        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());

        let specs = vec![PolicySpec::new(
            "com.microsoft.Edge",
            "QuicAllowed",
            PolicyValue::Bool(false),
        )];
        let rep = apply_policy_specs(&mut j, &plat, &specs);
        assert_eq!(rep.skipped, 1);
        assert_eq!(rep.applied, 0);
        assert!(j.entries().is_empty());
    }

    #[test]
    fn crash_recovery_from_disk_restores_baseline() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));

        {
            let mut j = Journal::open(fs.clone(), Path::new(DIR))
                .unwrap()
                .with_policy_store(store.clone());
            let rep = apply_policy_specs(&mut j, &plat, &sample_specs());
            assert_eq!(rep.applied, 2);
            assert_eq!(j.entries()[0].state, EntryState::Applied);
        }

        // Simulate restart / crash recovery via a fresh Journal open + policy store.
        let mut j2 = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());
        let rec = j2.restore_all(&plat);
        assert_eq!(rec.items.len(), 2);
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(true))
        );
        assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
        // Default recover_with uses RealPolicyStore; verify dry-run does not touch host.
        let _ = recover_with(fs, &plat, Path::new(DIR));
    }

    #[test]
    fn policy_specs_with_pac_covers_all_chromium_browsers_macos_and_windows() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let mac_no_pac = policy_specs_for_macos(None);
        assert!(
            mac_no_pac
                .iter()
                .all(|s| s.key != KEY_PROXY_MODE && s.key != KEY_PROXY_PAC_URL)
        );

        let mac_with_pac = policy_specs_for_macos(Some(pac));
        for domain in [
            "com.google.Chrome",
            "com.google.Chrome.beta",
            "com.google.Chrome.canary",
            "com.brave.Browser",
            "com.brave.Browser.beta",
            "com.microsoft.edgemac",
            "org.chromium.Chromium",
            "com.vivaldi.Vivaldi",
            "com.operasoftware.Opera",
            "com.operasoftware.OperaGX",
            "ru.yandex.desktop.yandex-browser",
            "company.thebrowser.Browser",
            "company.thebrowser.dia",
            "ai.perplexity.comet",
            "com.openai.atlas",
        ] {
            assert!(
                mac_with_pac.iter().any(|s| {
                    s.domain == domain
                        && s.key == KEY_PROXY_MODE
                        && s.value == PolicyValue::Sz("pac_script".to_string())
                }),
                "missing ProxyMode for {domain}"
            );
            assert!(
                mac_with_pac.iter().any(|s| {
                    s.domain == domain
                        && s.key == KEY_PROXY_PAC_URL
                        && s.value == PolicyValue::Sz(pac.to_string())
                }),
                "missing ProxyPacUrl for {domain}"
            );
            assert!(
                mac_with_pac.iter().any(|s| {
                    s.domain == domain
                        && s.key == KEY_QUIC_ALLOWED
                        && s.value == PolicyValue::Bool(false)
                }),
                "missing QuicAllowed for {domain}"
            );
            assert!(
                mac_with_pac.iter().any(|s| {
                    s.domain == domain
                        && s.key == KEY_DOH_MODE
                        && s.value == PolicyValue::Sz("off".to_string())
                }),
                "missing DnsOverHttpsMode for {domain}"
            );
        }

        let win_with_pac = policy_specs_for_windows(Some(pac));
        for subkey in [
            r"Software\Policies\Google\Chrome",
            r"Software\Policies\Microsoft\Edge",
            r"Software\Policies\BraveSoftware\Brave",
            r"Software\Policies\Chromium",
            r"Software\Policies\Vivaldi",
            r"Software\Policies\YandexBrowser",
            r"Software\Policies\Yandex\YandexBrowser",
            r"Software\Policies\Perplexity\Comet",
            r"Software\Policies\Opera Software\Opera Stable",
            r"Software\Policies\Opera Software\Opera GX Stable",
            r"Software\Policies\TheBrowserCompany\Arc",
            r"Software\Policies\TheBrowserCompany\Dia",
        ] {
            assert!(WINDOWS_CHROMIUM_DOMAIN_NAMES.contains(&subkey));
            assert!(
                win_with_pac.iter().any(|s| {
                    s.domain == subkey
                        && s.key == KEY_PROXY_MODE
                        && s.value == PolicyValue::Sz("pac_script".to_string())
                }),
                "missing ProxyMode for {subkey}"
            );
            assert!(
                win_with_pac.iter().any(|s| {
                    s.domain == subkey
                        && s.key == KEY_PROXY_PAC_URL
                        && s.value == PolicyValue::Sz(pac.to_string())
                }),
                "missing ProxyPacUrl for {subkey}"
            );
            assert!(
                win_with_pac.iter().any(|s| {
                    s.domain == subkey
                        && s.key == KEY_QUIC_ALLOWED
                        && s.value == PolicyValue::Dword(0)
                }),
                "missing QuicAllowed for {subkey}"
            );
            assert!(
                win_with_pac.iter().any(|s| {
                    s.domain == subkey
                        && s.key == KEY_DOH_MODE
                        && s.value == PolicyValue::Sz("off".to_string())
                }),
                "missing DnsOverHttpsMode for {subkey}"
            );
        }
    }

    #[test]
    fn pac_policies_are_journaled_and_restored_cleanly() {
        let pac = "http://127.0.0.1:9123/proxy.pac";
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        // Chrome had no proxy policy before; Arc had a corporate PAC configured by user/admin.
        store.preset(
            "company.thebrowser.Browser",
            KEY_PROXY_MODE,
            PolicyValue::Sz("fixed_servers".to_string()),
        );
        store.preset(
            "company.thebrowser.Browser",
            KEY_PROXY_PAC_URL,
            PolicyValue::Sz("https://corp.example/proxy.pac".to_string()),
        );
        for d in MACOS_CHROMIUM_DOMAIN_NAMES {
            if d != "com.google.Chrome" && d != "company.thebrowser.Browser" {
                store.set_domain_applicable(d, false);
            }
        }

        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());

        let specs = policy_specs_for_macos(Some(pac));
        let rep = apply_policy_specs(&mut j, &plat, &specs);
        assert_eq!(rep.failed, 0);
        assert!(is_pac_policy_active_in(
            &*store,
            &MACOS_CHROMIUM_DOMAIN_NAMES,
            pac
        ));
        assert_eq!(
            store.get("com.google.Chrome", KEY_PROXY_MODE),
            Some(PolicyValue::Sz("pac_script".to_string()))
        );
        assert_eq!(
            store.get("com.google.Chrome", KEY_PROXY_PAC_URL),
            Some(PolicyValue::Sz(pac.to_string()))
        );
        assert_eq!(
            store.get("company.thebrowser.Browser", KEY_PROXY_PAC_URL),
            Some(PolicyValue::Sz(pac.to_string()))
        );

        // Restore cleanly deletes keys that didn't exist and puts back pre-existing values.
        let rec = j.restore_all(&plat);
        assert!(!rec.has_failures());
        assert!(!is_pac_policy_active_in(
            &*store,
            &MACOS_CHROMIUM_DOMAIN_NAMES,
            pac
        ));
        assert_eq!(store.get("com.google.Chrome", KEY_PROXY_MODE), None);
        assert_eq!(store.get("com.google.Chrome", KEY_PROXY_PAC_URL), None);
        assert_eq!(
            store.get("company.thebrowser.Browser", KEY_PROXY_MODE),
            Some(PolicyValue::Sz("fixed_servers".to_string()))
        );
        assert_eq!(
            store.get("company.thebrowser.Browser", KEY_PROXY_PAC_URL),
            Some(PolicyValue::Sz(
                "https://corp.example/proxy.pac".to_string()
            ))
        );
    }

    #[test]
    fn is_pac_policy_active_requires_matching_mode_and_url() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let store = FakePolicyStore::new();
        for d in MACOS_CHROMIUM_DOMAIN_NAMES {
            store.set_domain_applicable(d, false);
        }
        store.set_domain_applicable("com.google.Chrome", true);

        // Missing keys -> false
        assert!(!is_pac_policy_active_in(
            &*store,
            &MACOS_CHROMIUM_DOMAIN_NAMES,
            pac
        ));

        // URL alone without ProxyMode=pac_script -> false
        store.preset(
            "com.google.Chrome",
            KEY_PROXY_PAC_URL,
            PolicyValue::Sz(pac.to_string()),
        );
        assert!(!is_pac_policy_active_in(
            &*store,
            &MACOS_CHROMIUM_DOMAIN_NAMES,
            pac
        ));

        // Wrong ProxyMode -> false
        store.preset(
            "com.google.Chrome",
            KEY_PROXY_MODE,
            PolicyValue::Sz("direct".to_string()),
        );
        assert!(!is_pac_policy_active_in(
            &*store,
            &MACOS_CHROMIUM_DOMAIN_NAMES,
            pac
        ));

        // Correct ProxyMode + matching URL -> true
        store.preset(
            "com.google.Chrome",
            KEY_PROXY_MODE,
            PolicyValue::Sz("pac_script".to_string()),
        );
        assert!(is_pac_policy_active_in(
            &*store,
            &MACOS_CHROMIUM_DOMAIN_NAMES,
            pac
        ));

        // Wrong port -> false
        assert!(!is_pac_policy_active_in(
            &*store,
            &MACOS_CHROMIUM_DOMAIN_NAMES,
            "http://127.0.0.1:9999/proxy.pac"
        ));
    }

    #[test]
    fn leftover_zastava_proxy_pac_url_is_not_adopted_as_baseline() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        // Simulate unjournaled leftover from an earlier crashed run.
        store.preset(
            "com.google.Chrome",
            KEY_PROXY_PAC_URL,
            PolicyValue::Sz(pac.to_string()),
        );

        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());
        let specs = vec![PolicySpec::new(
            "com.google.Chrome",
            KEY_PROXY_PAC_URL,
            PolicyValue::Sz(pac.to_string()),
        )];
        apply_policy_specs(&mut j, &plat, &specs);
        // On restore, Zastava's leftover PAC URL is removed rather than kept as baseline.
        j.restore_all(&plat);
        assert_eq!(store.get("com.google.Chrome", KEY_PROXY_PAC_URL), None);
    }

    #[test]
    fn apply_and_revert_browser_policies_covers_comet_yandex_opera_dia_atlas_and_betas() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();

        let target_domains = [
            "ai.perplexity.comet",
            "ru.yandex.desktop.yandex-browser",
            "com.operasoftware.Opera",
            "com.operasoftware.OperaGX",
            "company.thebrowser.dia",
            "com.google.Chrome.beta",
            "com.google.Chrome.canary",
            "com.brave.Browser.beta",
            "com.openai.atlas",
        ];

        for domain in MACOS_CHROMIUM_DOMAIN_NAMES {
            store.set_domain_applicable(domain, target_domains.contains(&domain));
        }
        // Simulate a pre-existing user setting on Yandex Browser.
        store.preset(
            "ru.yandex.desktop.yandex-browser",
            KEY_DOH_MODE,
            PolicyValue::Sz("automatic".to_string()),
        );

        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());

        let rep = apply_browser_policies_with_pac(&mut j, &plat, Some(pac));
        assert_eq!(rep.failed, 0);
        // Plist/registry policy alone without profile Preferences or running flag is not enforced.
        assert!(!rep.pac_policy_active);

        #[cfg(target_os = "macos")]
        {
            assert_eq!(rep.applied, target_domains.len() * 4);
            for domain in target_domains {
                assert_eq!(
                    store.get(domain, KEY_PROXY_MODE),
                    Some(PolicyValue::Sz("pac_script".to_string())),
                    "{domain}"
                );
                assert_eq!(
                    store.get(domain, KEY_PROXY_PAC_URL),
                    Some(PolicyValue::Sz(pac.to_string())),
                    "{domain}"
                );
                assert_eq!(
                    store.get(domain, KEY_QUIC_ALLOWED),
                    Some(PolicyValue::Bool(false)),
                    "{domain}"
                );
                assert_eq!(
                    store.get(domain, KEY_DOH_MODE),
                    Some(PolicyValue::Sz("off".to_string())),
                    "{domain}"
                );
            }
        }

        let rec = revert_browser_policies(&mut j, &plat);
        assert!(!rec.has_failures());
        assert_eq!(
            store.get("ru.yandex.desktop.yandex-browser", KEY_DOH_MODE),
            Some(PolicyValue::Sz("automatic".to_string()))
        );
        assert_eq!(store.get("ai.perplexity.comet", KEY_PROXY_PAC_URL), None);
        assert_eq!(store.get("com.openai.atlas", KEY_PROXY_MODE), None);
        assert!(!is_pac_policy_active(&*store, pac));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_app_bundle_mappings_cover_all_supported_browsers() {
        let expected = [
            ("ai.perplexity.comet", "Comet.app"),
            ("com.operasoftware.Opera", "Opera.app"),
            ("com.operasoftware.OperaGX", "Opera GX.app"),
            ("company.thebrowser.dia", "Dia.app"),
            ("com.google.Chrome.beta", "Google Chrome Beta.app"),
            ("com.google.Chrome.canary", "Google Chrome Canary.app"),
            ("com.brave.Browser.beta", "Brave Browser Beta.app"),
            ("com.openai.atlas", "ChatGPT Atlas.app"),
            ("ru.yandex.desktop.yandex-browser", "Yandex.app"),
        ];
        for (domain, app) in expected {
            assert!(
                MACOS_CHROMIUM_DOMAIN_NAMES.contains(&domain),
                "MACOS_CHROMIUM_DOMAIN_NAMES missing {domain}"
            );
            assert!(
                macos_app_bundles_for_domain(domain).contains(&app),
                "missing bundle {app} for {domain}"
            );
        }
    }

    struct StubProbe {
        outputs: Mutex<Vec<Option<String>>>,
        fallback: Mutex<Option<String>>,
    }

    impl StubProbe {
        fn fixed(output: Option<&str>) -> Self {
            Self {
                outputs: Mutex::new(Vec::new()),
                fallback: Mutex::new(output.map(str::to_string)),
            }
        }

        fn sequence(seq: Vec<Option<&str>>) -> Self {
            Self {
                outputs: Mutex::new(seq.into_iter().map(|s| s.map(str::to_string)).collect()),
                fallback: Mutex::new(None),
            }
        }
    }

    impl SystemProbe for StubProbe {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<String> {
            let mut q = self.outputs.lock().unwrap();
            if !q.is_empty() {
                return q.remove(0);
            }
            self.fallback.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct StubLauncher {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        fail_open: bool,
        permission_denied: bool,
    }

    impl AppLauncher for StubLauncher {
        fn run(
            &self,
            program: &str,
            args: &[String],
        ) -> Option<crate::commands::restart_app::RunResult> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            if program == "osascript" && self.permission_denied {
                return Some(crate::commands::restart_app::RunResult {
                    success: false,
                    stderr: "execution error: Not authorized to send Apple events (-1743)".into(),
                });
            }
            if program == "open" && self.fail_open {
                return Some(crate::commands::restart_app::RunResult {
                    success: false,
                    stderr: "LSOpenURLsWithRole failed".into(),
                });
            }
            Some(crate::commands::restart_app::RunResult {
                success: true,
                stderr: String::new(),
            })
        }
    }

    fn test_ctx(fs: &Arc<FakeFs>) -> FileCtx {
        let home = PathBuf::from("/Users/tester");
        FileCtx::new(
            fs.clone(),
            home.clone(),
            vec![home.join("Library/Application Support")],
        )
    }

    fn put_prefs(fs: &FakeFs, path: &Path, json: &str) {
        fs.put(path, json.as_bytes(), 0o600);
    }

    fn read_json(fs: &FakeFs, path: &Path) -> serde_json::Value {
        let bytes = fs.read(path).unwrap().unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn preferences_json_injection_preserves_existing_keys_and_reverts() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        let ctx = test_ctx(&fs);
        let probe = StubProbe::fixed(Some(""));

        let chrome_prefs = ctx
            .home
            .join("Library/Application Support/Google/Chrome/Default/Preferences");
        let comet_prefs = ctx
            .home
            .join("Library/Application Support/Comet/Profile 1/Preferences");

        put_prefs(
            &fs,
            &chrome_prefs,
            r#"{"browser":{"show_home_button":true},"extensions":{"theme":{"id":"abc"}}}"#,
        );
        put_prefs(
            &fs,
            &comet_prefs,
            r#"{"proxy":{"mode":"fixed_servers","server":"10.0.0.1:8080"},"profile":{"name":"Work"}}"#,
        );

        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());

        let rep = apply_browser_policies_with_pac_in(
            &mut j,
            &plat,
            Some(pac),
            Some(&ctx),
            Os::Macos,
            &probe,
        );
        assert_eq!(rep.failed, 0);
        assert!(rep.pac_policy_active);

        let chrome_after = read_json(&fs, &chrome_prefs);
        assert_eq!(chrome_after["browser"]["show_home_button"], true);
        assert_eq!(chrome_after["extensions"]["theme"]["id"], "abc");
        assert_eq!(chrome_after["proxy"]["mode"], "pac_script");
        assert_eq!(chrome_after["proxy"]["pac_url"], pac);
        assert_eq!(chrome_after["proxy"]["pac_mandatory"], false);

        let comet_after = read_json(&fs, &comet_prefs);
        assert_eq!(comet_after["profile"]["name"], "Work");
        assert_eq!(comet_after["proxy"]["mode"], "pac_script");
        assert_eq!(comet_after["proxy"]["pac_url"], pac);

        let rec = revert_browser_policies_with(&mut j, &plat, Os::Macos, &probe);
        assert!(!rec.has_failures());

        let chrome_reverted = read_json(&fs, &chrome_prefs);
        assert!(chrome_reverted.get("proxy").is_none());
        assert_eq!(chrome_reverted["browser"]["show_home_button"], true);

        let comet_reverted = read_json(&fs, &comet_prefs);
        assert_eq!(comet_reverted["proxy"]["mode"], "fixed_servers");
        assert_eq!(comet_reverted["proxy"]["server"], "10.0.0.1:8080");
        assert_eq!(comet_reverted["profile"]["name"], "Work");
    }

    #[test]
    fn multi_profile_discovery_includes_local_state_and_opera_single_profile() {
        let fs = Arc::new(FakeFs::new());
        let ctx = test_ctx(&fs);
        let comet_dir = ctx.home.join("Library/Application Support/Comet");
        let opera_dir = ctx
            .home
            .join("Library/Application Support/com.operasoftware.Opera");

        put_prefs(&fs, &comet_dir.join("Default/Preferences"), "{}");
        put_prefs(&fs, &comet_dir.join("Profile 2/Preferences"), "{}");
        put_prefs(&fs, &comet_dir.join("CustomWork/Preferences"), "{}");
        fs.put(
            &comet_dir.join("Local State"),
            br#"{"profile":{"info_cache":{"Default":{},"CustomWork":{}}}}"#,
            0o600,
        );
        put_prefs(&fs, &opera_dir.join("Preferences"), "{}");

        let comet_def = CHROMIUM_BROWSERS
            .iter()
            .find(|b| b.id == "ai.perplexity.comet")
            .unwrap();
        let opera_def = CHROMIUM_BROWSERS
            .iter()
            .find(|b| b.id == "com.operasoftware.Opera")
            .unwrap();

        let comet_files = browser_prefs_files_in(comet_def, &ctx, Os::Macos);
        assert_eq!(comet_files.len(), 3);
        assert!(comet_files.contains(&comet_dir.join("Default/Preferences")));
        assert!(comet_files.contains(&comet_dir.join("Profile 2/Preferences")));
        assert!(comet_files.contains(&comet_dir.join("CustomWork/Preferences")));

        let opera_files = browser_prefs_files_in(opera_def, &ctx, Os::Macos);
        assert_eq!(opera_files, vec![opera_dir.join("Preferences")]);
    }

    #[test]
    fn corrupt_or_non_object_preferences_are_skipped_without_overwrite() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        let ctx = test_ctx(&fs);
        let probe = StubProbe::fixed(Some(""));

        let bad_prefs = ctx
            .home
            .join("Library/Application Support/Google/Chrome/Default/Preferences");
        let raw_bad = b"{not valid json";
        fs.put(&bad_prefs, raw_bad, 0o600);

        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store);
        let rep = apply_browser_policies_with_pac_in(
            &mut j,
            &plat,
            Some(pac),
            Some(&ctx),
            Os::Macos,
            &probe,
        );
        assert_eq!(rep.failed, 1);
        assert!(!rep.pac_policy_active);
        assert_eq!(fs.read(&bad_prefs).unwrap().unwrap(), raw_bad);
    }

    #[test]
    fn running_browser_skips_preferences_injection_and_revert_until_exited() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        let ctx = test_ctx(&fs);

        let chrome_prefs = ctx
            .home
            .join("Library/Application Support/Google/Chrome/Default/Preferences");
        let yandex_prefs = ctx
            .home
            .join("Library/Application Support/Yandex/YandexBrowser/Default/Preferences");
        put_prefs(&fs, &chrome_prefs, r#"{"profile":{"name":"Main"}}"#);
        put_prefs(&fs, &yandex_prefs, r#"{"profile":{"name":"Ya"}}"#);

        // Chrome is running without PAC flag; Yandex is closed.
        let running_chrome = StubProbe::fixed(Some(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n",
        ));

        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store);

        let rep = apply_browser_policies_with_pac_in(
            &mut j,
            &plat,
            Some(pac),
            Some(&ctx),
            Os::Macos,
            &running_chrome,
        );
        assert!(rep.applied >= 1);
        assert!(rep.skipped >= 1);
        assert!(read_json(&fs, &chrome_prefs).get("proxy").is_none());
        assert_eq!(read_json(&fs, &yandex_prefs)["proxy"]["pac_url"], pac);

        // Chrome exits -> reconciler injects Chrome's Preferences.
        let all_closed = StubProbe::fixed(Some(""));
        assert!(reconcile_browser_pac_prefs_in(
            &mut j,
            &plat,
            Some(pac),
            &ctx,
            Os::Macos,
            &all_closed
        ));
        assert_eq!(read_json(&fs, &chrome_prefs)["proxy"]["pac_url"], pac);

        // Now Yandex is running at revert time -> Yandex revert is skipped, Chrome reverts.
        let running_yandex =
            StubProbe::fixed(Some("/Applications/Yandex.app/Contents/MacOS/Yandex\n"));
        let rec = revert_browser_policies_with(&mut j, &plat, Os::Macos, &running_yandex);
        assert!(!rec.has_failures());
        assert!(read_json(&fs, &chrome_prefs).get("proxy").is_none());
        assert_eq!(read_json(&fs, &yandex_prefs)["proxy"]["pac_url"], pac);

        // Yandex closes -> reconcile(None) restores Yandex's baseline.
        assert!(reconcile_browser_pac_prefs_in(
            &mut j,
            &plat,
            None,
            &ctx,
            Os::Macos,
            &all_closed
        ));
        assert!(read_json(&fs, &yandex_prefs).get("proxy").is_none());
    }

    #[test]
    fn clear_stale_browser_pac_prefs_removes_only_zastava_local_pac_urls() {
        let fs = Arc::new(FakeFs::new());
        let ctx = test_ctx(&fs);
        let chrome_prefs = ctx
            .home
            .join("Library/Application Support/Google/Chrome/Default/Preferences");
        let brave_prefs = ctx
            .home
            .join("Library/Application Support/BraveSoftware/Brave-Browser/Default/Preferences");
        let comet_prefs = ctx
            .home
            .join("Library/Application Support/Comet/Default/Preferences");

        put_prefs(
            &fs,
            &chrome_prefs,
            r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:54321/proxy.pac","pac_mandatory":false},"keep":1}"#,
        );
        put_prefs(
            &fs,
            &brave_prefs,
            r#"{"proxy":{"mode":"pac_script","pac_url":"https://corp.example/wpad.dat"}}"#,
        );
        put_prefs(
            &fs,
            &comet_prefs,
            r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac"}}"#,
        );

        // Comet is still running, Chrome & Brave are closed.
        let probe = StubProbe::fixed(Some("/Applications/Comet.app/Contents/MacOS/Comet\n"));
        let cleaned = clear_stale_browser_pac_prefs_in(&ctx, Os::Macos, &probe);
        assert_eq!(cleaned, 1);

        let chrome = read_json(&fs, &chrome_prefs);
        assert!(chrome.get("proxy").is_none());
        assert_eq!(chrome["keep"], 1);
        assert_eq!(
            read_json(&fs, &brave_prefs)["proxy"]["pac_url"],
            "https://corp.example/wpad.dat"
        );
        assert_eq!(
            read_json(&fs, &comet_prefs)["proxy"]["pac_url"],
            "http://127.0.0.1:8899/proxy.pac"
        );
    }

    #[test]
    fn detect_browser_pac_status_distinguishes_active_and_needing_restart() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let fs = Arc::new(FakeFs::new());
        let ctx = test_ctx(&fs);

        let chrome_prefs = ctx
            .home
            .join("Library/Application Support/Google/Chrome/Default/Preferences");
        let comet_prefs = ctx
            .home
            .join("Library/Application Support/Comet/Default/Preferences");
        let dia_prefs = ctx
            .home
            .join("Library/Application Support/Dia/User Data/Default/Preferences");
        let arc_prefs = ctx
            .home
            .join("Library/Application Support/Arc/User Data/Default/Preferences");

        // Chrome: running WITHOUT flag and WITHOUT Preferences -> needs restart.
        put_prefs(&fs, &chrome_prefs, "{}");
        // Comet: running WITH --proxy-pac-url=<pac> -> active even without Preferences.
        put_prefs(&fs, &comet_prefs, "{}");
        // Dia: running WITHOUT flag, but Preferences ALREADY has our PAC -> active.
        put_prefs(
            &fs,
            &dia_prefs,
            r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac","pac_mandatory":false}}"#,
        );
        // Arc: closed, Preferences has our PAC -> active.
        put_prefs(
            &fs,
            &arc_prefs,
            r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac","pac_mandatory":false}}"#,
        );

        let ps = format!(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n\
             /Applications/Comet.app/Contents/MacOS/Comet --proxy-pac-url={pac}\n\
             /Applications/Dia.app/Contents/MacOS/Dia\n"
        );
        let probe = StubProbe::fixed(Some(&ps));
        let status = detect_browser_pac_status_in(&ctx, Os::Macos, &probe, Some(pac));

        assert_eq!(
            status.browsers_needing_restart,
            vec!["Google Chrome".to_string()]
        );
        assert_eq!(
            status.browsers_pac_active,
            vec!["Comet".to_string(), "Arc".to_string(), "Dia".to_string()]
        );
    }

    #[test]
    fn relaunch_browsers_with_pac_quits_patches_and_reopens_with_flag() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        let ctx = test_ctx(&fs);

        fs.create_private_dir_all(&PathBuf::from("/Applications/Google Chrome.app"))
            .unwrap();
        let chrome_prefs = ctx
            .home
            .join("Library/Application Support/Google/Chrome/Default/Preferences");
        put_prefs(&fs, &chrome_prefs, r#"{"keep":"yes"}"#);

        // First call (detect status): Chrome running; second call (wait after osascript): exited.
        let probe = StubProbe::sequence(vec![
            Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n"),
            Some(""),
        ]);
        let launcher = StubLauncher::default();
        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store);
        let timing = QuitTiming {
            timeout: Duration::from_millis(50),
            interval: Duration::from_millis(5),
        };

        let summary = relaunch_browsers_with_pac_with(
            &mut j,
            &plat,
            pac,
            &ctx,
            Os::Macos,
            &probe,
            &launcher,
            timing,
        );

        assert_eq!(summary.restarted, vec!["Google Chrome".to_string()]);
        assert!(summary.skipped.is_empty());
        assert!(summary.failed.is_empty());
        assert_eq!(read_json(&fs, &chrome_prefs)["proxy"]["pac_url"], pac);
        assert_eq!(read_json(&fs, &chrome_prefs)["keep"], "yes");

        let calls = launcher.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "osascript");
        assert!(calls[0].1[1].contains("com.google.Chrome"));
        assert_eq!(calls[1].0, "open");
        assert_eq!(
            calls[1].1,
            vec![
                "-a".to_string(),
                "/Applications/Google Chrome.app".to_string(),
                "--args".to_string(),
                format!("--proxy-pac-url={pac}"),
            ]
        );
    }

    #[test]
    fn relaunch_browsers_with_pac_returns_unsupported_on_windows() {
        let pac = "http://127.0.0.1:8899/proxy.pac";
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        let ctx = test_ctx(&fs);
        let probe = StubProbe::fixed(Some(""));
        let launcher = StubLauncher::default();
        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store);
        let timing = QuitTiming {
            timeout: Duration::from_millis(10),
            interval: Duration::from_millis(5),
        };

        let summary = relaunch_browsers_with_pac_with(
            &mut j,
            &plat,
            pac,
            &ctx,
            Os::Windows,
            &probe,
            &launcher,
            timing,
        );

        assert!(summary.unsupported);
        assert!(summary.restarted.is_empty());
        assert!(summary.skipped.is_empty());
        assert!(summary.failed.is_empty());
        assert!(launcher.calls.lock().unwrap().is_empty());
    }
}
