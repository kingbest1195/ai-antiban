//! Host OS metadata & process probes for the Clean Room trace detector.
//!
//! Strictly read-only (`exists()`, `tasklist`, `pgrep`) — never reads secrets,
//! Keychain, DPAPI, Credential Manager, or SQLite Cookies contents.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::auditor::cache_cleaner::is_windows_claude_desktop_exe;
use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::profile_switcher::resolve_ai_app_data_dirs;

/// Abstracted host probe for deterministic unit testing without touching the real OS.
pub trait DetectorEnv {
    fn path_exists(&self, path: &Path) -> bool;
    fn running_ai_processes(&self) -> Vec<String>;
    fn browser_profile_dirs(&self) -> Vec<(&'static str, PathBuf)>;
    fn claude_data_dirs(&self) -> Vec<PathBuf>;
    fn chatgpt_data_dirs(&self) -> Vec<PathBuf>;
    fn cursor_data_dirs(&self) -> Vec<PathBuf>;
    fn is_windows(&self) -> bool;
}

pub struct RealDetectorEnv;

impl DetectorEnv for RealDetectorEnv {
    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn running_ai_processes(&self) -> Vec<String> {
        query_running_ai_processes()
    }

    fn browser_profile_dirs(&self) -> Vec<(&'static str, PathBuf)> {
        default_browser_profile_dirs()
    }

    fn claude_data_dirs(&self) -> Vec<PathBuf> {
        resolve_ai_app_data_dirs(ProviderId::Anthropic)
    }

    fn chatgpt_data_dirs(&self) -> Vec<PathBuf> {
        resolve_ai_app_data_dirs(ProviderId::Openai)
    }

    fn cursor_data_dirs(&self) -> Vec<PathBuf> {
        default_cursor_data_dirs()
    }

    fn is_windows(&self) -> bool {
        cfg!(target_os = "windows")
    }
}

fn default_browser_profile_dirs() -> Vec<(&'static str, PathBuf)> {
    let mut dirs = Vec::new();
    #[cfg(target_os = "windows")]
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let base = PathBuf::from(local);
        dirs.push(("Chrome", base.join("Google/Chrome/User Data")));
        dirs.push(("Edge", base.join("Microsoft/Edge/User Data")));
        dirs.push(("Brave", base.join("BraveSoftware/Brave-Browser/User Data")));
        dirs.push(("Yandex", base.join("Yandex/YandexBrowser/User Data")));
    }
    #[cfg(target_os = "macos")]
    if let Ok(home) = std::env::var("HOME") {
        let base = PathBuf::from(home).join("Library/Application Support");
        dirs.push(("Chrome", base.join("Google/Chrome")));
        dirs.push(("Edge", base.join("Microsoft Edge")));
        dirs.push(("Brave", base.join("BraveSoftware/Brave-Browser")));
        dirs.push(("Yandex", base.join("Yandex/YandexBrowser")));
    }
    dirs
}

fn default_cursor_data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    #[cfg(target_os = "windows")]
    if let Ok(appdata) = std::env::var("APPDATA") {
        dirs.push(PathBuf::from(appdata).join("Cursor"));
    }
    #[cfg(target_os = "macos")]
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join("Library/Application Support/Cursor"));
    }
    dirs
}

/// Parses `PID|Name|ExecutablePath` lines (from Win32_Process) and flags only Claude Desktop
/// (never native Claude Code CLI `claude.exe`), plus `ChatGPT.exe` and `Cursor.exe`.
pub fn parse_windows_running_ai_processes(process_lines: &str) -> Vec<String> {
    let mut found = BTreeSet::new();
    for line in process_lines.lines() {
        let mut parts = line.trim().splitn(3, '|');
        let Some(pid_raw) = parts.next() else {
            continue;
        };
        let Some(name_raw) = parts.next() else {
            continue;
        };
        let exe_path = parts.next().unwrap_or("");
        if pid_raw.trim().parse::<u32>().ok().is_none_or(|p| p == 0) {
            continue;
        }
        match name_raw.trim().to_ascii_lowercase().as_str() {
            "claude.exe" if is_windows_claude_desktop_exe(exe_path) => {
                found.insert("claude.exe".to_string());
            }
            "chatgpt.exe" => {
                found.insert("ChatGPT.exe".to_string());
            }
            "cursor.exe" => {
                found.insert("Cursor.exe".to_string());
            }
            _ => {}
        }
    }
    found.into_iter().collect()
}

fn query_running_ai_processes() -> Vec<String> {
    if !crate::sysproxy::os_effects_enabled() {
        return Vec::new();
    }
    #[cfg(target_os = "windows")]
    {
        let script = r#"Get-CimInstance Win32_Process -Filter "Name='claude.exe' OR Name='ChatGPT.exe' OR Name='Cursor.exe'" | ForEach-Object { "$($_.ProcessId)|$($_.Name)|$($_.ExecutablePath)" }"#;
        if let Ok(out) = crate::sysproxy::silent_command("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            && out.status.success()
        {
            return parse_windows_running_ai_processes(&String::from_utf8_lossy(&out.stdout));
        }

        // Fallback without PowerShell: only match ChatGPT.exe and Cursor.exe by image name,
        // never claude.exe (which would falsely match native Claude Code CLI).
        let Ok(out) = crate::sysproxy::silent_command("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
        else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut found = BTreeSet::new();
        for target in ["ChatGPT.exe", "Cursor.exe"] {
            if text.lines().any(|l| {
                l.to_ascii_lowercase()
                    .contains(&format!("\"{}\"", target.to_ascii_lowercase()))
            }) {
                found.insert(target.to_string());
            }
        }
        found.into_iter().collect()
    }
    #[cfg(target_os = "macos")]
    {
        let mut found = Vec::new();
        for (proc_name, pattern) in [
            ("Claude", "Claude.app/Contents/MacOS/Claude"),
            ("ChatGPT", "ChatGPT.app/Contents/MacOS/ChatGPT"),
            ("Cursor", "Cursor.app/Contents/MacOS/Cursor"),
        ] {
            if let Ok(status) = std::process::Command::new("pgrep")
                .args(["-f", pattern])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                && status.success()
            {
                found.push(proc_name.to_string());
            }
        }
        found
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Vec::new()
    }
}
