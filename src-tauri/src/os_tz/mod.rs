//! OS system timezone synchronization and automatic baseline restore.
//!
//! Browsers (Chrome, Safari, Edge, Firefox) and Electron apps (Claude Desktop) ignore `TZ` env
//! vars in shell/IDE settings and read the OS system timezone directly. This module allows users
//! to sync the OS timezone to the VPN/exit IP timezone (via UAC on Windows or administrator
//! privileges on macOS), while durably persisting the original timezone in `os_tz_baseline.json`
//! so it can be restored manually, when disabling protection, on app quit, or after a crash.

mod baseline;
#[cfg(target_os = "macos")]
mod macos;
mod mapping;
mod sync;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(test)]
#[allow(unused_imports)]
use crate::sysproxy::fs::{Fs, RealFs};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Mutex, OnceLock};

pub use baseline::{baseline_path, read_baseline, remove_baseline, write_baseline_atomic};
pub use mapping::{
    allowlisted_windows_tz_id, canonicalize_iana_tz, iana_to_windows_tz, validate_iana_tz,
    windows_to_iana_tz,
};
pub use sync::{
    get_os_timezone_sync_status, get_os_timezone_sync_status_with, recover_baseline_on_start,
    recover_baseline_on_start_with, restore_if_synced_on_disable,
    restore_if_synced_on_disable_with, restore_on_exit_once, restore_os_timezone,
    restore_os_timezone_with, sync_os_timezone, sync_os_timezone_with,
};

pub const BASELINE_FILE_NAME: &str = "os_tz_baseline.json";

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
static OS_TZ_OPS: Mutex<()> = Mutex::new(());
static EXIT_RESTORE_RAN: AtomicBool = AtomicBool::new(false);

/// Pins the app data directory where `os_tz_baseline.json` lives.
pub fn set_data_dir(dir: PathBuf) {
    let _ = DATA_DIR.set(dir);
}

/// Resolves the app data directory from an optional `AppHandle`, pinned `DATA_DIR`, or OS default.
pub fn resolve_app_data_dir(app: Option<&tauri::AppHandle>) -> Option<PathBuf> {
    if let Some(handle) = app {
        use tauri::Manager;
        if let Ok(dir) = handle.path().app_data_dir() {
            return Some(dir);
        }
    }
    DATA_DIR
        .get()
        .cloned()
        .or_else(crate::sysproxy::default_app_data_dir)
}

/// Whether real OS timezone reads/writes via external tools (`tzutil`, `systemsetup`, `osascript`)
/// are allowed. Always `false` in tests (`cfg!(test)`, `test-support`), dry-run mode, or when
/// `ZASTAVA_TEST_MODE=1`/`true`.
pub fn os_tz_effects_enabled() -> bool {
    if !crate::sysproxy::os_effects_enabled() {
        return false;
    }
    !std::env::var("ZASTAVA_TEST_MODE")
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// Durable backup of the user's pre-Zastava OS timezone state (`os_tz_baseline.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsTzBaseline {
    pub original_iana: String,
    pub original_windows_id: Option<String>,
    pub original_auto_tz: Option<bool>,
    pub synced_iana: String,
    pub synced_at_utc: String,
}

/// Status returned to the frontend / callers describing current OS timezone sync state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsTzSyncStatus {
    pub synced: bool,
    pub current_os_tz: Option<String>,
    pub original_os_tz: Option<String>,
    pub synced_target_tz: Option<String>,
    pub auto_restore_pending: bool,
}

/// Platform abstraction for reading/setting the OS system timezone without running real OS
/// commands during tests.
pub trait OsTzPlatform: Send + Sync {
    /// Returns the current OS system timezone as an IANA identifier (e.g. `"Europe/Moscow"`).
    fn current_iana_timezone(&self) -> Result<String, String>;

    /// Returns the current Windows time zone ID (e.g. `"Russian Standard Time"`), or `None` on
    /// non-Windows systems.
    fn current_windows_tz_id(&self) -> Result<Option<String>, String>;

    /// Returns whether OS automatic timezone detection (`tzautoupdate` on Windows,
    /// `com.apple.timezone.auto` on macOS) is currently enabled (`Some(true)`), disabled
    /// (`Some(false)`), or unknown (`None`).
    fn is_auto_tz_enabled(&self) -> Result<Option<bool>, String>;

    /// Applies `target_iana` to the OS system timezone and optionally disables automatic timezone.
    fn apply_timezone(&self, target_iana: &str, disable_auto_tz: bool) -> Result<(), String>;

    /// Restores `orig_iana` (or `orig_win_id` on Windows) and restores automatic timezone if
    /// `restore_auto_tz == Some(true)`.
    fn restore_timezone(
        &self,
        orig_iana: &str,
        orig_win_id: Option<&str>,
        restore_auto_tz: Option<bool>,
    ) -> Result<(), String>;
}

/// Real OS implementation (macOS `systemsetup`/`osascript` + `defaults`; Windows `tzutil`/Win32
/// registry + PowerShell `RunAs`). Every mutation respects [`os_tz_effects_enabled`].
pub struct RealOsTzPlatform;

impl OsTzPlatform for RealOsTzPlatform {
    fn current_iana_timezone(&self) -> Result<String, String> {
        #[cfg(target_os = "macos")]
        {
            macos::current_iana_timezone()
        }
        #[cfg(target_os = "windows")]
        {
            windows::current_iana_timezone()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            iana_time_zone::get_timezone().map_err(|e| e.to_string())
        }
    }

    fn current_windows_tz_id(&self) -> Result<Option<String>, String> {
        #[cfg(target_os = "windows")]
        {
            windows::current_windows_tz_id()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(None)
        }
    }

    fn is_auto_tz_enabled(&self) -> Result<Option<bool>, String> {
        #[cfg(target_os = "macos")]
        {
            macos::is_auto_tz_enabled()
        }
        #[cfg(target_os = "windows")]
        {
            windows::is_auto_tz_enabled()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Ok(None)
        }
    }

    fn apply_timezone(&self, target_iana: &str, disable_auto_tz: bool) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            macos::apply_timezone(target_iana, disable_auto_tz)
        }
        #[cfg(target_os = "windows")]
        {
            windows::apply_timezone(target_iana, disable_auto_tz)
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = (target_iana, disable_auto_tz);
            Err(
                "Синхронизация системного часового пояса поддерживается только на Windows и macOS."
                    .to_string(),
            )
        }
    }

    fn restore_timezone(
        &self,
        orig_iana: &str,
        orig_win_id: Option<&str>,
        restore_auto_tz: Option<bool>,
    ) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            macos::restore_timezone(orig_iana, orig_win_id, restore_auto_tz)
        }
        #[cfg(target_os = "windows")]
        {
            windows::restore_timezone(orig_iana, orig_win_id, restore_auto_tz)
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = (orig_iana, orig_win_id, restore_auto_tz);
            Err("Восстановление системного часового пояса поддерживается только на Windows и macOS.".to_string())
        }
    }
}

#[cfg(test)]
#[path = "../os_tz_tests.rs"]
mod tests;
