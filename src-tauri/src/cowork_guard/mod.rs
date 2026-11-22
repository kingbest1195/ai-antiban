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

#[cfg(test)]
#[allow(unused_imports)]
use elevate::read_install_error_file;
#[cfg_attr(not(any(target_os = "windows", test)), allow(unused_imports))]
use elevate::write_install_error_file;
use serde::{Deserialize, Serialize};

pub use crate::win_native::COWORK_TASK_SDDL;
pub use elevate::{build_elevated_cli_params, parse_install_cli_args};
pub use macos::{parse_launchctl_output, parse_macos_ps_output};
pub use task_xml::{
    SchtasksQueryError, build_schtasks_create_args, build_windows_summary, build_windows_task_xml,
    build_windows_task_xml_with_exe, classify_schtasks_query_error, decode_windows_cmd_text,
    encode_utf16_le_with_bom, is_task_list_healthy, is_task_xml_healthy, parse_reg_start_dword,
    parse_sc_running, parse_tasklist_has_claude, validate_windows_task_xml,
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
pub const APPLY_COWORK_GUARD_ONCE_ARG: &str = "--apply-cowork-guard-once";
pub const UNINSTALL_COWORK_GUARD_ARG: &str = "--uninstall-cowork-guard";
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
            summary: "Защита от автозапуска фоновой службы Claude требуется только на Windows."
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
/// Registers `\Zastava\CoworkVMServiceManualGuard` via COM Task Scheduler 2.0 with `(A;;GRGX;;;AU)`,
/// enforces `Start = 3` via `win_reg` + SCM, and stops `CoworkVMService` when `claude.exe` is closed.
pub fn run_install_cowork_guard_cli() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let error_file = parse_install_cli_args(&args).flatten();
    run_install_cowork_guard_cli_with_error_file(error_file.as_deref())
}

/// Boot-trigger / SYSTEM helper entrypoint (`--apply-cowork-guard-once`):
/// enforces `Start = 3` (Manual) and stops `CoworkVMService` if `claude.exe` is not running.
pub fn run_apply_cowork_guard_once_cli() -> i32 {
    if !crate::sysproxy::os_effects_enabled() {
        return 0;
    }
    #[cfg(target_os = "windows")]
    {
        if let Err(err) = windows::apply_cowork_guard_once_direct() {
            crate::diagnostics::record("cowork_guard", &err);
            eprintln!("Застава cowork_guard: {err}");
            return 1;
        }
        0
    }
    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}

/// Uninstaller helper entrypoint (`--uninstall-cowork-guard`):
/// deletes `\Zastava\CoworkVMServiceManualGuard` via in-process COM Task Scheduler 2.0.
pub fn run_uninstall_cowork_guard_cli() -> i32 {
    if !crate::sysproxy::os_effects_enabled() {
        return 0;
    }
    #[cfg(target_os = "windows")]
    {
        if let Err(err) = windows::uninstall_cowork_guard_task() {
            crate::diagnostics::record("cowork_guard", &err);
            eprintln!("Застава cowork_guard: {err}");
            return 1;
        }
        0
    }
    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}

/// Post-install verification for [`install_or_repair_cowork_guard`]: refuses to return `Ok`
/// when the task is still missing, unhealthy, or requires repair, surfacing exact diagnostics.
pub fn verify_post_install_status(
    status: CoworkGuardStatus,
    last_diag: Option<&str>,
) -> Result<CoworkGuardStatus, String> {
    if !status.task_installed || !status.task_healthy || status.needs_repair {
        let start_desc = status
            .start_type
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string());
        let diag_suffix = last_diag
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|d| format!("; диагностика: {d}"))
            .unwrap_or_default();
        let msg = format!(
            "Защита службы Claude не подтверждена после настройки (task_installed={}, task_healthy={}, start_type={}, needs_repair={}): {}{}",
            status.task_installed,
            status.task_healthy,
            start_desc,
            status.needs_repair,
            status.summary,
            diag_suffix
        );
        crate::diagnostics::record("cowork_guard", &msg);
        return Err(msg);
    }
    Ok(status)
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub(crate) fn install_or_repair_cowork_guard_with<FInstall, FQuery>(
    install_fn: FInstall,
    query_fn: FQuery,
) -> Result<CoworkGuardStatus, String>
where
    FInstall: FnOnce() -> Result<(), String>,
    FQuery: FnOnce() -> CoworkGuardStatus,
{
    install_fn()?;
    let status = query_fn();
    let last_diag = crate::diagnostics::dump()
        .into_iter()
        .rev()
        .find(|line| line.contains("[cowork_guard]"));
    verify_post_install_status(status, last_diag.as_deref())
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
        install_or_repair_cowork_guard_with(
            || {
                if elevate::win_elevate::is_current_process_elevated() {
                    windows::install_cowork_guard_direct().map_err(|err| {
                        crate::diagnostics::record("cowork_guard", &err);
                        format!("Ошибка настройки задачи планировщика: {err}")
                    })
                } else {
                    let exe = std::env::current_exe()
                        .map_err(|e| format!("Не удалось определить путь к приложению: {e}"))?;
                    elevate::win_elevate::run_elevated_install(&exe)
                }
            },
            windows::query_windows_status,
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(get_cowork_guard_status())
    }
}

#[cfg(test)]
#[path = "../cowork_guard_tests.rs"]
mod tests;
