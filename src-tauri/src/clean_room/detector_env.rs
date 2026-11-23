//! Host OS metadata & process probes for the Clean Room trace detector.
//!
//! Strictly read-only (`exists()`, native Win32 ToolHelp32/QueryFullProcessImageNameW, `pgrep`) —
//! never reads secrets, Keychain, DPAPI, Credential Manager, or SQLite Cookies contents.

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
    fn windsurf_data_dirs(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    fn read_text_limited(&self, _path: &Path) -> Option<String> {
        None
    }
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

    fn windsurf_data_dirs(&self) -> Vec<PathBuf> {
        default_windsurf_data_dirs()
    }

    fn read_text_limited(&self, path: &Path) -> Option<String> {
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() > 512 * 1024 {
            return None;
        }
        std::fs::read_to_string(path).ok()
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
    default_ide_data_dirs("Cursor")
}

fn default_windsurf_data_dirs() -> Vec<PathBuf> {
    default_ide_data_dirs("Windsurf")
}

fn default_ide_data_dirs(app_name: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    #[cfg(target_os = "windows")]
    if let Ok(appdata) = std::env::var("APPDATA") {
        dirs.push(PathBuf::from(appdata).join(app_name));
    }
    #[cfg(target_os = "macos")]
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(
            PathBuf::from(home)
                .join("Library/Application Support")
                .join(app_name),
        );
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".config").join(app_name));
    }
    dirs
}

/// Strictly read-only inspection for Cursor / Windsurf `storage.json` device IDs
/// (`telemetry.machineId` / `devDeviceId`). Never modifies any third-party files.
pub fn detect_ide_machine_id_storage<E: DetectorEnv + ?Sized>(
    env: &E,
) -> Option<(&'static str, PathBuf)> {
    let candidates = env
        .cursor_data_dirs()
        .into_iter()
        .map(|d| ("Cursor", d))
        .chain(
            env.windsurf_data_dirs()
                .into_iter()
                .map(|d| ("Windsurf", d)),
        );

    for (ide_name, base_dir) in candidates {
        for rel in [
            "User/globalStorage/storage.json",
            "globalStorage/storage.json",
            "storage.json",
        ] {
            let p = base_dir.join(rel);
            if !env.path_exists(&p) {
                continue;
            }
            if let Some(raw) = env.read_text_limited(&p)
                && (raw.contains("telemetry.machineId")
                    || raw.contains("devDeviceId")
                    || raw.contains("machineId"))
            {
                return Some((ide_name, p));
            }
        }
    }
    None
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

/// Classifies native Win32 `ProcessEntry` rows using `resolve_image_path` so only Claude Desktop
/// (never native Claude Code CLI `claude.exe`), plus `ChatGPT.exe` and `Cursor.exe` are flagged.
pub fn classify_windows_process_entries<F>(
    entries: &[crate::win_native::process::ProcessEntry],
    resolve_image_path: F,
) -> Vec<String>
where
    F: Fn(u32) -> Option<String>,
{
    let mut found = BTreeSet::new();
    for entry in entries {
        if entry.pid == 0 {
            continue;
        }
        let base = crate::win_native::extract_exe_basename(&entry.exe_name);
        match base.to_ascii_lowercase().as_str() {
            "claude.exe" => {
                if let Some(exe_path) = resolve_image_path(entry.pid)
                    && is_windows_claude_desktop_exe(&exe_path)
                {
                    found.insert("claude.exe".to_string());
                }
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
        let Ok(entries) = crate::win_native::process::list_processes() else {
            return Vec::new();
        };
        classify_windows_process_entries(&entries, |pid| {
            crate::win_native::process::query_process_image_path(pid).ok()
        })
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
