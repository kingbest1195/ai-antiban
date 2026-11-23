//! Windows CoworkVMService status querying, COM Task Scheduler registration, and enforcement.

use super::task_xml::{
    build_windows_summary, build_windows_task_xml, diagnose_task_xml, validate_windows_task_xml,
};
use super::{
    COWORK_SERVICE_NAME, COWORK_SERVICE_REG_SUBKEY, COWORK_TASK_NAME, COWORK_TASK_PATH,
    CoworkGuardStatus,
};
use crate::win_native::{COWORK_TASK_SDDL, process, service, task_scheduler};

fn query_task_via_registry_taskcache() -> bool {
    const TASKCACHE_SUBKEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Zastava\CoworkVMServiceManualGuard";
    matches!(
        crate::win_reg::get_string(
            crate::win_reg::RootKey::HkeyLocalMachine,
            TASKCACHE_SUBKEY,
            "Id"
        ),
        Ok(Some(id)) if !id.trim().is_empty()
    )
}

pub(super) fn query_windows_status() -> CoworkGuardStatus {
    let (service_present, start_type) = match crate::win_reg::get_dword(
        crate::win_reg::RootKey::HkeyLocalMachine,
        COWORK_SERVICE_REG_SUBKEY,
        "Start",
    ) {
        Ok(Some(v)) => (true, Some(v)),
        _ => (false, None),
    };

    // Fast path: do NOT poll Task Scheduler or SCM every 60s when CoworkVMService is absent.
    if !service_present {
        return CoworkGuardStatus {
            platform: "windows".to_string(),
            supported: true,
            service_present: false,
            start_type: None,
            service_running: false,
            task_installed: false,
            task_healthy: false,
            needs_repair: false,
            summary:
                "Фоновая служба Claude не обнаружена — приложение из Microsoft Store не установлено."
                    .to_string(),
            detected_ai_apps: Vec::new(),
        };
    }

    let service_running = service::query_service_status(COWORK_SERVICE_NAME)
        .map(|st| st.running)
        .unwrap_or(false);

    let (task_installed, task_healthy, query_diag) =
        match task_scheduler::query_task_xml(COWORK_TASK_PATH, COWORK_TASK_NAME) {
            Ok(Some(xml)) => match diagnose_task_xml(&xml) {
                Ok(()) => (true, true, None),
                Err(reason) => (true, false, Some(format!("Task XML unhealthy: {reason}"))),
            },
            Ok(None) => {
                if query_task_via_registry_taskcache() {
                    (
                        true,
                        false,
                        Some("TaskCache entry present, but COM query returned None".to_string()),
                    )
                } else {
                    (false, false, None)
                }
            }
            Err(err) => {
                if query_task_via_registry_taskcache() || err.starts_with("ACCESS_DENIED:") {
                    (true, false, Some(err))
                } else {
                    (false, false, Some(err))
                }
            }
        };

    if let Some(ref diag) = query_diag
        && (!task_installed || !task_healthy)
    {
        crate::diagnostics::record("cowork_guard", diag);
    }

    let (needs_repair, summary) = build_windows_summary(
        service_present,
        start_type,
        service_running,
        task_installed,
        task_healthy,
    );

    CoworkGuardStatus {
        platform: "windows".to_string(),
        supported: true,
        service_present,
        start_type,
        service_running,
        task_installed,
        task_healthy,
        needs_repair,
        summary,
        detected_ai_apps: Vec::new(),
    }
}

pub(super) fn trigger_cowork_guard_task() -> bool {
    if !crate::sysproxy::os_effects_enabled() {
        return false;
    }
    match task_scheduler::run_task(COWORK_TASK_PATH, COWORK_TASK_NAME) {
        Ok(()) => true,
        Err(err) => {
            crate::diagnostics::record("cowork_guard", &format!("COM Run failed: {err}"));
            false
        }
    }
}

pub(super) fn uninstall_cowork_guard_task() -> Result<(), String> {
    if !crate::sysproxy::os_effects_enabled() {
        return Ok(());
    }
    task_scheduler::delete_task(COWORK_TASK_PATH, COWORK_TASK_NAME)
}

fn is_claude_process_running() -> bool {
    process::is_process_running_by_name("claude.exe")
}

fn register_cowork_guard_task() -> Result<(), String> {
    let xml = build_windows_task_xml();
    validate_windows_task_xml(&xml)?;
    task_scheduler::register_task_xml(COWORK_TASK_PATH, COWORK_TASK_NAME, &xml, COWORK_TASK_SDDL)
}

/// Applies `Start = 3` (Manual) and stops `CoworkVMService` when `claude.exe` is not running.
pub(super) fn apply_cowork_guard_once_direct() -> Result<(), String> {
    use crate::win_reg::{RootKey, get_dword, set_dword};

    match get_dword(
        RootKey::HkeyLocalMachine,
        COWORK_SERVICE_REG_SUBKEY,
        "Start",
    ) {
        Ok(None) => return Ok(()),
        Ok(Some(cur)) if cur != 3 => {
            set_dword(
                RootKey::HkeyLocalMachine,
                COWORK_SERVICE_REG_SUBKEY,
                "Start",
                3,
            )?;
            service::set_service_start_type(COWORK_SERVICE_NAME, 3)?;
        }
        Ok(Some(_)) => {}
        Err(err) => return Err(err),
    }

    let running = service::query_service_status(COWORK_SERVICE_NAME)
        .map(|st| st.running)
        .unwrap_or(false);
    if running && !is_claude_process_running() {
        service::stop_service(COWORK_SERVICE_NAME)?;
    }
    Ok(())
}

/// Applies `Start = 3` (Manual) and stops `CoworkVMService` when `claude.exe` is not running,
/// delegating to the `NT AUTHORITY\SYSTEM` task when Admin token lacks ACL on `CoworkVMService`.
fn enforce_cowork_service_manual_and_stop() -> Result<(), String> {
    let mut need_system_task = false;
    if let Err(err) = apply_cowork_guard_once_direct() {
        crate::diagnostics::record(
            "cowork_guard",
            &format!("Admin enforcement fallback to SYSTEM task: {err}"),
        );
        need_system_task = true;
    }

    if need_system_task {
        if trigger_cowork_guard_task() {
            std::thread::sleep(std::time::Duration::from_millis(800));
            if let Ok(Some(cur)) = crate::win_reg::get_dword(
                crate::win_reg::RootKey::HkeyLocalMachine,
                COWORK_SERVICE_REG_SUBKEY,
                "Start",
            ) && cur != 3
            {
                let msg = format!(
                    "SYSTEM task ran, but CoworkVMService Start is still {cur} instead of 3"
                );
                crate::diagnostics::record("cowork_guard", &msg);
                eprintln!("Застава cowork_guard: {msg}");
            }
        } else {
            let msg = "Registry/SCM fallback required SYSTEM task, but trigger_cowork_guard_task() failed";
            crate::diagnostics::record("cowork_guard", msg);
            eprintln!("Застава cowork_guard: {msg}");
        }
    }
    Ok(())
}

pub(super) fn install_cowork_guard_direct() -> Result<(), String> {
    register_cowork_guard_task()?;
    enforce_cowork_service_manual_and_stop()
}
