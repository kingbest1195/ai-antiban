//! OS-level autostart management (macOS LaunchAgent + Windows Registry Run).
//!
//! All real OS mutations respect [`crate::sysproxy::os_effects_enabled`] (`ZASTAVA_OS_DRY_RUN=1`),
//! so unit and integration tests never touch the user's real `~/Library/LaunchAgents` or Registry.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const LAUNCH_AGENT_LABEL: &str = "io.zastava.desktop";
pub const LAUNCH_AGENT_PLIST_NAME: &str = "io.zastava.desktop.plist";
pub const WINDOWS_RUN_REG_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
pub const WINDOWS_RUN_VALUE_NAME: &str = "Zastava";
pub const MINIMIZED_ARG: &str = "--minimized";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutostartStatus {
    pub supported: bool,
    pub enabled: bool,
    pub active_in_os: bool,
    pub platform: String,
    pub detail: String,
}

pub fn current_platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

pub fn is_supported_platform() -> bool {
    cfg!(any(target_os = "macos", target_os = "windows"))
}

fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Builds the macOS LaunchAgent `.plist` XML launching `exe_path` with `--minimized` at login.
pub fn build_launch_agent_plist(exe_path: &Path) -> String {
    let exe_escaped = xml_escape(&exe_path.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe_escaped}</string>
        <string>{MINIMIZED_ARG}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#
    )
}

/// Formats the Windows `HKCU\...\Run` command value (`"<exe>" --minimized`).
pub fn windows_run_value(exe_path: &Path) -> String {
    format!("\"{}\" {}", exe_path.to_string_lossy(), MINIMIZED_ARG)
}

pub fn launch_agent_plist_path_in(home_dir: &Path) -> PathBuf {
    home_dir
        .join("Library")
        .join("LaunchAgents")
        .join(LAUNCH_AGENT_PLIST_NAME)
}

pub fn is_launch_agent_installed_in(home_dir: &Path) -> bool {
    launch_agent_plist_path_in(home_dir).is_file()
}

pub fn set_launch_agent_in(
    home_dir: &Path,
    exe_path: &Path,
    enabled: bool,
) -> Result<bool, String> {
    let plist_path = launch_agent_plist_path_in(home_dir);
    if enabled {
        let Some(parent) = plist_path.parent() else {
            return Err("Не удалось определить папку LaunchAgents".to_string());
        };
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Не удалось создать папку LaunchAgents: {e}"))?;
        let content = build_launch_agent_plist(exe_path);
        std::fs::write(&plist_path, content)
            .map_err(|e| format!("Не удалось записать LaunchAgent {plist_path:?}: {e}"))?;
        Ok(true)
    } else {
        if plist_path.exists() {
            std::fs::remove_file(&plist_path)
                .map_err(|e| format!("Не удалось удалить LaunchAgent {plist_path:?}: {e}"))?;
        }
        Ok(false)
    }
}

fn user_home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

#[cfg(target_os = "windows")]
fn run_reg_command(args: &[&str]) -> Result<std::process::Output, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    std::process::Command::new("reg.exe")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Не удалось запустить reg.exe: {e}"))
}

#[cfg(target_os = "windows")]
fn is_windows_run_installed() -> bool {
    run_reg_command(&["query", WINDOWS_RUN_REG_KEY, "/v", WINDOWS_RUN_VALUE_NAME])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn set_windows_run_entry(exe_path: &Path, enabled: bool) -> Result<bool, String> {
    if enabled {
        let value = windows_run_value(exe_path);
        let out = run_reg_command(&[
            "add",
            WINDOWS_RUN_REG_KEY,
            "/v",
            WINDOWS_RUN_VALUE_NAME,
            "/t",
            "REG_SZ",
            "/d",
            &value,
            "/f",
        ])?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(if err.is_empty() {
                "Не удалось записать ключ автозапуска в реестр Windows".to_string()
            } else {
                format!("Не удалось записать ключ автозапуска: {err}")
            });
        }
        Ok(true)
    } else {
        let out = run_reg_command(&[
            "delete",
            WINDOWS_RUN_REG_KEY,
            "/v",
            WINDOWS_RUN_VALUE_NAME,
            "/f",
        ])?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
            // Absence of the key when disabling is fine.
            if !err.contains("unable to find") && !err.contains("не удалось найти") {
                return Err(format!(
                    "Не удалось удалить ключ автозапуска: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        Ok(false)
    }
}

/// Checks OS autostart presence without mutating anything.
pub fn query_os_autostart_active() -> bool {
    if !crate::sysproxy::os_effects_enabled() {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        return user_home_dir()
            .map(|h| is_launch_agent_installed_in(&h))
            .unwrap_or(false);
    }
    #[cfg(target_os = "windows")]
    {
        return is_windows_run_installed();
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

/// Applies or removes OS autostart. Respects `os_effects_enabled()` (dry-run skips OS writes).
pub fn apply_os_autostart(enabled: bool) -> Result<bool, String> {
    if !crate::sysproxy::os_effects_enabled() {
        return Ok(enabled && is_supported_platform());
    }
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к исполняемому файлу: {e}"))?;

    #[cfg(target_os = "macos")]
    {
        let home = user_home_dir()
            .ok_or_else(|| "Не удалось определить домашнюю папку пользователя".to_string())?;
        set_launch_agent_in(&home, &exe_path, enabled)
    }
    #[cfg(target_os = "windows")]
    {
        set_windows_run_entry(&exe_path, enabled)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (exe_path, enabled);
        Err("Автозапуск поддерживается только на macOS и Windows".to_string())
    }
}

pub fn build_status(saved_enabled: bool, active_in_os: bool) -> AutostartStatus {
    let supported = is_supported_platform();
    let platform = current_platform_name().to_string();
    let detail = if !supported {
        "Автозапуск через настройки поддерживается на macOS и Windows.".to_string()
    } else if cfg!(target_os = "macos") {
        if active_in_os || (!crate::sysproxy::os_effects_enabled() && saved_enabled) {
            format!("LaunchAgent ({LAUNCH_AGENT_PLIST_NAME}) запускает Заставу в трей при входе.")
        } else {
            "LaunchAgent не установлен — Застава запускается только вручную.".to_string()
        }
    } else if active_in_os || (!crate::sysproxy::os_effects_enabled() && saved_enabled) {
        "Автозапуск в реестре Windows (HKCU\\...\\Run) запускает Заставу в трей при входе."
            .to_string()
    } else {
        "Автозапуск в реестре Windows выключен.".to_string()
    };

    AutostartStatus {
        supported,
        enabled: saved_enabled,
        active_in_os: if crate::sysproxy::os_effects_enabled() {
            active_in_os
        } else {
            saved_enabled && supported
        },
        platform,
        detail,
    }
}

pub fn get_status(saved_enabled: bool) -> AutostartStatus {
    let active_in_os = query_os_autostart_active();
    build_status(saved_enabled, active_in_os)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn plist_contains_label_minimized_and_run_at_load() {
        let plist = build_launch_agent_plist(Path::new("/Applications/Zastava & Co.app/Contents/MacOS/zastava"));
        assert!(plist.contains("<string>io.zastava.desktop</string>"));
        assert!(plist.contains("<string>/Applications/Zastava &amp; Co.app/Contents/MacOS/zastava</string>"));
        assert!(plist.contains("<string>--minimized</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n    <true/>"));
    }

    #[test]
    fn windows_run_value_quotes_exe_and_passes_minimized() {
        let val = windows_run_value(Path::new(r"C:\Program Files\Zastava\zastava.exe"));
        assert_eq!(val, r#""C:\Program Files\Zastava\zastava.exe" --minimized"#);
    }

    #[test]
    fn launch_agent_install_and_remove_in_tempdir() {
        let dir = tempdir().unwrap();
        let exe = Path::new("/Applications/Zastava.app/Contents/MacOS/zastava");
        assert!(!is_launch_agent_installed_in(dir.path()));

        assert!(set_launch_agent_in(dir.path(), exe, true).unwrap());
        let plist_path = launch_agent_plist_path_in(dir.path());
        assert!(plist_path.is_file());
        let body = std::fs::read_to_string(&plist_path).unwrap();
        assert!(body.contains("--minimized"));

        assert!(!set_launch_agent_in(dir.path(), exe, false).unwrap());
        assert!(!plist_path.exists());
        // Removing again is idempotent.
        assert!(!set_launch_agent_in(dir.path(), exe, false).unwrap());
    }

    #[test]
    fn dry_run_apply_does_not_touch_real_os() {
        crate::sysproxy::force_os_dry_run();
        assert!(!query_os_autostart_active());
        let res = apply_os_autostart(true).unwrap();
        assert_eq!(res, is_supported_platform());
        let off = apply_os_autostart(false).unwrap();
        assert!(!off);
    }
}
