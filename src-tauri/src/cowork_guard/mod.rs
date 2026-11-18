//! Protection against background AI service auto-start before Zastava:
//! - Windows: `CoworkVMService` (Microsoft Store Claude Desktop) boot-time Task Scheduler guard
//!   (`Start = 3` Manual, NEVER `4` Disabled) without executing any user-writable binaries.
//! - macOS: non-destructive inspection of running AI apps/helpers/LoginItems/LaunchAgents.
//!
//! All real OS probes/mutations respect [`crate::sysproxy::os_effects_enabled`] (`ZASTAVA_OS_DRY_RUN=1`).

mod elevate;
mod macos;
mod task_xml;
#[cfg(target_os = "windows")]
mod windows;

#[cfg_attr(not(any(target_os = "windows", test)), allow(unused_imports))]
use elevate::write_install_error_file;
#[cfg(test)]
#[allow(unused_imports)]
use elevate::read_install_error_file;
use serde::{Deserialize, Serialize};

pub use elevate::{build_elevated_cli_params, parse_install_cli_args};
pub use macos::{parse_launchctl_output, parse_macos_ps_output};
pub use task_xml::{
    build_schtasks_create_args, build_windows_summary, build_windows_task_xml,
    build_windows_task_xml_with_system_root, cowork_guard_inline_ps, decode_windows_cmd_text,
    encode_utf16_le_with_bom, is_task_xml_healthy, parse_reg_start_dword, parse_sc_running,
    parse_tasklist_has_claude, validate_windows_task_xml,
};

pub const COWORK_SERVICE_NAME: &str = "CoworkVMService";
pub const COWORK_SERVICE_REG_PATH: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\CoworkVMService";
#[cfg(target_os = "windows")]
pub(super) const COWORK_SERVICE_REG_SUBKEY: &str =
    r"SYSTEM\CurrentControlSet\Services\CoworkVMService";
pub const COWORK_TASK_PATH: &str = r"\Zastava\";
pub const COWORK_TASK_NAME: &str = "CoworkVMServiceManualGuard";
pub const COWORK_TASK_FULL_NAME: &str = r"Zastava\CoworkVMServiceManualGuard";
pub const INSTALL_COWORK_GUARD_ARG: &str = "--install-cowork-guard";
pub const COWORK_ERROR_FILE_ARG: &str = "--error-file";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectedAiProcess {
    pub name: String,
    pub kind: String,
    pub running: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoworkGuardStatus {
    pub platform: String,
    pub supported: bool,
    pub service_present: bool,
    pub start_type: Option<u32>,
    pub service_running: bool,
    pub task_installed: bool,
    pub task_healthy: bool,
    pub needs_repair: bool,
    pub summary: String,
    #[serde(default)]
    pub detected_ai_apps: Vec<DetectedAiProcess>,
}

pub fn trigger_cowork_guard_task() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows::trigger_cowork_guard_task()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

pub fn get_cowork_guard_status() -> CoworkGuardStatus {
    if !crate::sysproxy::os_effects_enabled() {
        let platform = crate::autostart::current_platform_name().to_string();
        return CoworkGuardStatus {
            platform,
            supported: cfg!(any(target_os = "windows", target_os = "macos")),
            service_present: false,
            start_type: None,
            service_running: false,
            task_installed: false,
            task_healthy: false,
            needs_repair: false,
            summary: "Проверка фоновых ИИ-служб (dry-run).".to_string(),
            detected_ai_apps: Vec::new(),
        };
    }

    #[cfg(target_os = "windows")]
    {
        windows::query_windows_status()
    }
    #[cfg(target_os = "macos")]
    {
        macos::query_macos_status()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        CoworkGuardStatus {
            platform: "linux".to_string(),
            supported: false,
            service_present: false,
            start_type: None,
            service_running: false,
            task_installed: false,
            task_healthy: false,
            needs_repair: false,
            summary: "Защита от фонового запуска CoworkVMService требуется только на Windows."
                .to_string(),
            detected_ai_apps: Vec::new(),
        }
    }
}

/// Runs the CoworkGuard installation logic and optionally writes fatal errors to `error_file`
/// so an un-elevated parent process can surface exact Win32/`schtasks` diagnostics.
pub fn run_install_cowork_guard_cli_with_error_file(error_file: Option<&std::path::Path>) -> i32 {
    if !crate::sysproxy::os_effects_enabled() {
        return 0;
    }
    #[cfg(target_os = "windows")]
    {
        if let Err(err) = windows::install_cowork_guard_direct() {
            crate::diagnostics::record("cowork_guard", &err);
            eprintln!("Застава cowork_guard: {err}");
            write_install_error_file(error_file, &err);
            return 1;
        }
        0
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = error_file;
        0
    }
}

/// Elevated helper entrypoint (`--install-cowork-guard`) launched via `ShellExecuteExW` (`runas`).
/// Registers `\Zastava\CoworkVMServiceManualGuard` via `schtasks.exe /Create`, enforces `Start = 3`
/// via `win_reg` on HKLM (falling back to the SYSTEM scheduled task on ACL denial), and stops
/// `CoworkVMService` via `sc.exe stop` when `claude.exe` is closed.
pub fn run_install_cowork_guard_cli() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let error_file = parse_install_cli_args(&args).flatten();
    run_install_cowork_guard_cli_with_error_file(error_file.as_deref())
}

/// User-triggered install/repair of `\Zastava\CoworkVMServiceManualGuard` on Windows.
/// Runs directly when already elevated; otherwise requests UAC once via Win32 `ShellExecuteExW`
/// (`lpVerb = "runas"`, `nShow = SW_HIDE`) with `--error-file` diagnostics forwarding.
pub fn install_or_repair_cowork_guard() -> Result<CoworkGuardStatus, String> {
    if !crate::sysproxy::os_effects_enabled() {
        return Ok(get_cowork_guard_status());
    }

    #[cfg(target_os = "windows")]
    {
        if elevate::win_elevate::is_current_process_elevated() {
            if let Err(err) = windows::install_cowork_guard_direct() {
                crate::diagnostics::record("cowork_guard", &err);
                return Err(format!("Ошибка настройки задачи планировщика: {err}"));
            }
        } else {
            let exe = std::env::current_exe()
                .map_err(|e| format!("Не удалось определить путь к приложению: {e}"))?;
            elevate::win_elevate::run_elevated_install(&exe)?;
        }
        Ok(windows::query_windows_status())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(get_cowork_guard_status())
    }
}

#[cfg(test)]
#[path = "../cowork_guard_tests.rs"]
mod tests;
