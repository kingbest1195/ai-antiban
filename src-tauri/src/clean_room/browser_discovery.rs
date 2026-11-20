//! Chromium-family browser discovery (Chrome > Edge > Brave) on Windows and macOS.

use std::path::{Path, PathBuf};

use super::DetectedBrowser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryPlatform {
    Windows,
    Macos,
    Other,
}

impl DiscoveryPlatform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrowserSpec {
    pub engine: &'static str,
    pub display_name: &'static str,
    pub win_exe: &'static str,
    pub win_fallbacks: &'static [&'static str],
    pub mac_rel_path: &'static str,
}

pub const SUPPORTED_BROWSERS: &[BrowserSpec] = &[
    BrowserSpec {
        engine: "chrome",
        display_name: "Google Chrome",
        win_exe: "chrome.exe",
        win_fallbacks: &[
            "ProgramFiles/Google/Chrome/Application/chrome.exe",
            "ProgramFiles(x86)/Google/Chrome/Application/chrome.exe",
            "LOCALAPPDATA/Google/Chrome/Application/chrome.exe",
        ],
        mac_rel_path: "Google Chrome.app/Contents/MacOS/Google Chrome",
    },
    BrowserSpec {
        engine: "edge",
        display_name: "Microsoft Edge",
        win_exe: "msedge.exe",
        win_fallbacks: &[
            "ProgramFiles(x86)/Microsoft/Edge/Application/msedge.exe",
            "ProgramFiles/Microsoft/Edge/Application/msedge.exe",
            "LOCALAPPDATA/Microsoft/Edge/Application/msedge.exe",
        ],
        mac_rel_path: "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    },
    BrowserSpec {
        engine: "brave",
        display_name: "Brave Browser",
        win_exe: "brave.exe",
        win_fallbacks: &[
            "ProgramFiles/BraveSoftware/Brave-Browser/Application/brave.exe",
            "ProgramFiles(x86)/BraveSoftware/Brave-Browser/Application/brave.exe",
            "LOCALAPPDATA/BraveSoftware/Brave-Browser/Application/brave.exe",
        ],
        mac_rel_path: "Brave Browser.app/Contents/MacOS/Brave Browser",
    },
];

/// Discovers installed supported browsers in priority order (`chrome` > `edge` > `brave`).
pub fn discover_clean_browsers() -> Vec<DetectedBrowser> {
    let platform = DiscoveryPlatform::current();
    let env_fn = |key: &str| std::env::var(key).ok();
    let reg_fn = |exe: &str| read_windows_app_path(exe);
    let exists_fn = |p: &Path| p.is_file();
    discover_browsers_with(platform, &env_fn, &reg_fn, &exists_fn)
}

/// Pure, testable browser discovery helper with injected environment, registry, and fs checks.
pub fn discover_browsers_with<E, R, F>(
    platform: DiscoveryPlatform,
    env_var: &E,
    reg_app_path: &R,
    file_exists: &F,
) -> Vec<DetectedBrowser>
where
    E: Fn(&str) -> Option<String>,
    R: Fn(&str) -> Option<String>,
    F: Fn(&Path) -> bool,
{
    let mut out = Vec::with_capacity(SUPPORTED_BROWSERS.len());
    for spec in SUPPORTED_BROWSERS {
        let found = match platform {
            DiscoveryPlatform::Windows => {
                find_windows_browser(spec, env_var, reg_app_path, file_exists)
            }
            DiscoveryPlatform::Macos => find_macos_browser(spec, env_var, file_exists),
            DiscoveryPlatform::Other => None,
        };
        out.push(DetectedBrowser {
            engine: spec.engine.to_string(),
            display_name: spec.display_name.to_string(),
            executable_path: found.clone().unwrap_or_default(),
            available: found.is_some(),
        });
    }
    out
}

/// Resolves the executable path for a requested engine (`"chrome"`, `"edge"`, `"brave"`),
/// falling back to the highest-priority available browser if `engine` is empty.
pub fn resolve_browser_executable(engine: &str) -> Result<(String, String), String> {
    let browsers = discover_clean_browsers();
    resolve_browser_executable_from(&browsers, engine)
}

pub fn resolve_browser_executable_from(
    browsers: &[DetectedBrowser],
    engine: &str,
) -> Result<(String, String), String> {
    let normalized = engine.trim().to_ascii_lowercase();
    if !normalized.is_empty()
        && let Some(found) = browsers
            .iter()
            .find(|b| b.available && b.engine == normalized)
    {
        return Ok((found.engine.clone(), found.executable_path.clone()));
    }
    if normalized.is_empty()
        && let Some(first) = browsers.iter().find(|b| b.available)
    {
        return Ok((first.engine.clone(), first.executable_path.clone()));
    }
    if !normalized.is_empty() {
        return Err(format!(
            "Requested browser engine '{normalized}' is not installed or unavailable"
        ));
    }
    Err("No supported Chromium browser (Chrome, Edge, Brave) was found".to_string())
}

fn find_windows_browser<E, R, F>(
    spec: &BrowserSpec,
    env_var: &E,
    reg_app_path: &R,
    file_exists: &F,
) -> Option<String>
where
    E: Fn(&str) -> Option<String>,
    R: Fn(&str) -> Option<String>,
    F: Fn(&Path) -> bool,
{
    if let Some(reg_path) = reg_app_path(spec.win_exe) {
        let trimmed = reg_path.trim().trim_matches('"');
        if !trimmed.is_empty() && file_exists(Path::new(trimmed)) {
            return Some(trimmed.to_string());
        }
    }
    for template in spec.win_fallbacks {
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
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn find_macos_browser<E, F>(spec: &BrowserSpec, env_var: &E, file_exists: &F) -> Option<String>
where
    E: Fn(&str) -> Option<String>,
    F: Fn(&Path) -> bool,
{
    let mut system_path = PathBuf::from("/Applications");
    for part in spec.mac_rel_path.split('/') {
        system_path.push(part);
    }
    if file_exists(&system_path) {
        return Some(system_path.to_string_lossy().into_owned());
    }

    if let Some(home) = env_var("HOME")
        && !home.trim().is_empty()
    {
        let mut user_path = PathBuf::from(home).join("Applications");
        for part in spec.mac_rel_path.split('/') {
            user_path.push(part);
        }
        if file_exists(&user_path) {
            return Some(user_path.to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn read_windows_app_path(exe_name: &str) -> Option<String> {
    use crate::win_reg::{RootKey, get_string};
    let subkey = format!(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{}",
        exe_name
    );
    if let Ok(Some(val)) = get_string(RootKey::HkeyLocalMachine, &subkey, "") {
        return Some(val);
    }
    if let Ok(Some(val)) = get_string(RootKey::HkeyCurrentUser, &subkey, "") {
        return Some(val);
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn read_windows_app_path(_exe_name: &str) -> Option<String> {
    None
}
