//! Production [`PolicyStore`] backed by `crate::win_reg` on Windows and `defaults` on macOS.

#[cfg(target_os = "macos")]
use super::chromium::CHROMIUM_BROWSERS;
use super::{PolicyStore, PolicyValue};
use crate::sysproxy::platform::{PResult, PlatformError};
use crate::sysproxy::{note_dry_run_blocked, os_effects_enabled};
#[cfg(any(target_os = "windows", test))]
use std::path::{Path, PathBuf};

/// Production [`PolicyStore`] backed by `crate::win_reg` on Windows and `defaults` on macOS.
pub struct RealPolicyStore;

#[cfg(any(target_os = "windows", test))]
struct WindowsBrowserInstallSpec {
    domain: &'static str,
    /// `(exe_name, required_path_substr, forbidden_path_substr)` checked under `App Paths`.
    app_paths: &'static [(&'static str, Option<&'static str>, Option<&'static str>)],
    /// `ENV_KEY/relative/path/to/browser.exe` fallbacks (never touches Chromium `User Data`).
    fallback_paths: &'static [&'static str],
}

#[cfg(any(target_os = "windows", test))]
const WINDOWS_BROWSER_INSTALL_SPECS: &[WindowsBrowserInstallSpec] = &[
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\Google\Chrome",
        app_paths: &[("chrome.exe", Some("google"), Some("chromium"))],
        fallback_paths: &[
            "ProgramFiles/Google/Chrome/Application/chrome.exe",
            "ProgramFiles(x86)/Google/Chrome/Application/chrome.exe",
            "LOCALAPPDATA/Google/Chrome/Application/chrome.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\Microsoft\Edge",
        app_paths: &[("msedge.exe", None, None)],
        fallback_paths: &[
            "ProgramFiles(x86)/Microsoft/Edge/Application/msedge.exe",
            "ProgramFiles/Microsoft/Edge/Application/msedge.exe",
            "LOCALAPPDATA/Microsoft/Edge/Application/msedge.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\BraveSoftware\Brave",
        app_paths: &[("brave.exe", None, None)],
        fallback_paths: &[
            "ProgramFiles/BraveSoftware/Brave-Browser/Application/brave.exe",
            "ProgramFiles(x86)/BraveSoftware/Brave-Browser/Application/brave.exe",
            "LOCALAPPDATA/BraveSoftware/Brave-Browser/Application/brave.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\Chromium",
        app_paths: &[("chrome.exe", Some("chromium"), None)],
        fallback_paths: &[
            "ProgramFiles/Chromium/Application/chrome.exe",
            "ProgramFiles(x86)/Chromium/Application/chrome.exe",
            "LOCALAPPDATA/Chromium/Application/chrome.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\Vivaldi",
        app_paths: &[("vivaldi.exe", None, None)],
        fallback_paths: &[
            "ProgramFiles/Vivaldi/Application/vivaldi.exe",
            "ProgramFiles(x86)/Vivaldi/Application/vivaldi.exe",
            "LOCALAPPDATA/Vivaldi/Application/vivaldi.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\YandexBrowser",
        app_paths: &[("browser.exe", Some("yandex"), None)],
        fallback_paths: &[
            "LOCALAPPDATA/Yandex/YandexBrowser/Application/browser.exe",
            "ProgramFiles/Yandex/YandexBrowser/Application/browser.exe",
            "ProgramFiles(x86)/Yandex/YandexBrowser/Application/browser.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\Yandex\YandexBrowser",
        app_paths: &[("browser.exe", Some("yandex"), None)],
        fallback_paths: &[
            "LOCALAPPDATA/Yandex/YandexBrowser/Application/browser.exe",
            "ProgramFiles/Yandex/YandexBrowser/Application/browser.exe",
            "ProgramFiles(x86)/Yandex/YandexBrowser/Application/browser.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\Perplexity\Comet",
        app_paths: &[("comet.exe", None, None)],
        fallback_paths: &[
            "LOCALAPPDATA/Perplexity/Comet/Application/comet.exe",
            "ProgramFiles/Perplexity/Comet/Application/comet.exe",
            "ProgramFiles(x86)/Perplexity/Comet/Application/comet.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\Opera Software\Opera Stable",
        app_paths: &[
            ("opera.exe", None, Some("opera gx")),
            ("launcher.exe", Some("opera"), Some("opera gx")),
        ],
        fallback_paths: &[
            "LOCALAPPDATA/Programs/Opera/opera.exe",
            "LOCALAPPDATA/Programs/Opera/launcher.exe",
            "ProgramFiles/Opera/opera.exe",
            "ProgramFiles/Opera/launcher.exe",
            "ProgramFiles(x86)/Opera/opera.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\Opera Software\Opera GX Stable",
        app_paths: &[
            ("opera.exe", Some("opera gx"), None),
            ("launcher.exe", Some("opera gx"), None),
        ],
        fallback_paths: &[
            "LOCALAPPDATA/Programs/Opera GX/opera.exe",
            "LOCALAPPDATA/Programs/Opera GX/launcher.exe",
            "ProgramFiles/Opera GX/opera.exe",
            "ProgramFiles/Opera GX/launcher.exe",
            "ProgramFiles(x86)/Opera GX/opera.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\TheBrowserCompany\Arc",
        app_paths: &[("Arc.exe", None, None)],
        fallback_paths: &[
            "LOCALAPPDATA/Programs/Arc/Arc.exe",
            "ProgramFiles/Arc/Arc.exe",
            "LOCALAPPDATA/Microsoft/WindowsApps/Arc.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\TheBrowserCompany\Dia",
        app_paths: &[("Dia.exe", None, None)],
        fallback_paths: &[
            "LOCALAPPDATA/Programs/Dia/Dia.exe",
            "ProgramFiles/Dia/Dia.exe",
            "LOCALAPPDATA/Microsoft/WindowsApps/Dia.exe",
        ],
    },
    WindowsBrowserInstallSpec {
        domain: r"Software\Policies\Mozilla\Firefox\DNSOverHTTPS",
        app_paths: &[("firefox.exe", None, None)],
        fallback_paths: &[
            "ProgramFiles/Mozilla Firefox/firefox.exe",
            "ProgramFiles(x86)/Mozilla Firefox/firefox.exe",
            "LOCALAPPDATA/Mozilla Firefox/firefox.exe",
        ],
    },
];

#[cfg(any(target_os = "windows", test))]
pub(super) fn windows_domain_installed_with<E, R, F>(
    domain: &str,
    env_var: &E,
    reg_app_path: &R,
    file_exists: &F,
) -> bool
where
    E: Fn(&str) -> Option<String>,
    R: Fn(&str) -> Option<String>,
    F: Fn(&Path) -> bool,
{
    let Some(spec) = WINDOWS_BROWSER_INSTALL_SPECS
        .iter()
        .find(|s| s.domain == domain)
    else {
        return false;
    };

    for &(exe_name, required, forbidden) in spec.app_paths {
        if let Some(raw_path) = reg_app_path(exe_name) {
            let trimmed = raw_path.trim().trim_matches('"');
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase().replace('\\', "/");
            if let Some(req) = required
                && !lower.contains(req)
            {
                continue;
            }
            if let Some(forb) = forbidden
                && lower.contains(forb)
            {
                continue;
            }
            if file_exists(Path::new(trimmed)) {
                return true;
            }
        }
    }

    for template in spec.fallback_paths {
        let Some((root_key, suffix)) = template.split_once('/') else {
            continue;
        };
        let Some(root_val) = env_var(root_key) else {
            continue;
        };
        if root_val.trim().is_empty() {
            continue;
        }
        let mut candidate = PathBuf::from(root_val);
        for part in suffix.split('/') {
            candidate.push(part);
        }
        if file_exists(&candidate) {
            return true;
        }
    }

    false
}

#[cfg(target_os = "windows")]
fn read_windows_app_path(exe_name: &str) -> Option<String> {
    use crate::win_reg::{RootKey, get_string};
    let subkey = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}");
    if let Ok(Some(val)) = get_string(RootKey::HkeyLocalMachine, &subkey, "") {
        return Some(val);
    }
    if let Ok(Some(val)) = get_string(RootKey::HkeyCurrentUser, &subkey, "") {
        return Some(val);
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_domain_installed(domain: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    const CACHE_TTL: Duration = Duration::from_secs(30);
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, bool)>>> = OnceLock::new();

    let now = Instant::now();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock()
        && let Some(&(ts, installed)) = guard.get(domain)
        && now.saturating_duration_since(ts) < CACHE_TTL
    {
        return installed;
    }

    let env_fn = |key: &str| std::env::var(key).ok();
    let reg_fn = |exe: &str| read_windows_app_path(exe);
    let exists_fn = |p: &Path| p.is_file();
    let installed = windows_domain_installed_with(domain, &env_fn, &reg_fn, &exists_fn);

    if let Ok(mut guard) = cache.lock() {
        guard.insert(domain.to_string(), (now, installed));
    }
    installed
}

#[cfg(target_os = "macos")]
pub(super) fn macos_app_bundles_for_domain(domain: &str) -> &'static [&'static str] {
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
        if let Some(home) = crate::sysproxy::user_home_dir()
            && home.join("Applications").join(app_name).exists()
        {
            return true;
        }
    }
    crate::sysproxy::user_home_dir().is_some_and(|h| {
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
            windows_domain_installed(domain)
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
            let read_out = crate::sysproxy::silent_command("defaults")
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
            let type_out = crate::sysproxy::silent_command("defaults")
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
            let mut cmd = crate::sysproxy::silent_command("defaults");
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
            let out = crate::sysproxy::silent_command("defaults")
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
