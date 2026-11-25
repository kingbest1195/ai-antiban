//! Windows `CoworkVMService` guard watcher.
//!
//! Gates `CreateToolhelp32Snapshot` (`list_processes`) behind both the lightweight
//! `CoworkGuardStatus` check and an explicit SCM check so process enumeration never runs
//! unless `CoworkVMService` is actually installed and running.

use crate::cowork_guard;
use std::time::Duration;
use tauri::Emitter;

/// Pure trigger predicate for the Windows `CoworkVMService` guard watcher.
///
/// Triggers `\Zastava\CoworkVMServiceManualGuard` only when OS effects are enabled, the
/// platform supports the guard, the Task Scheduler task is installed, and either:
/// - `start_type == Some(2)` (Store update reset service startup back to Automatic), OR
/// - `service_running && !claude_process_running` (service is running while Claude is closed).
pub(crate) fn should_trigger_cowork_guard(
    status: &cowork_guard::CoworkGuardStatus,
    claude_process_running: bool,
    os_effects_enabled: bool,
) -> bool {
    if !os_effects_enabled || !status.supported || !status.task_installed {
        return false;
    }
    status.start_type == Some(2) || (status.service_running && !claude_process_running)
}

/// Pure gate deciding whether `CreateToolhelp32Snapshot` (`claude.exe` lookup) may run.
///
/// Skips process enumeration whenever OS effects are disabled, the guard is unsupported or
/// uninstalled, `start_type == Some(2)` already forces a trigger, or `CoworkVMService` is
/// not installed and running.
pub(crate) fn should_probe_claude_process(
    status: &cowork_guard::CoworkGuardStatus,
    os_effects_enabled: bool,
) -> bool {
    os_effects_enabled
        && status.supported
        && status.service_present
        && status.service_running
        && status.task_installed
        && status.start_type != Some(2)
}

fn is_cowork_service_installed_and_running() -> bool {
    if !crate::sysproxy::os_effects_enabled() {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        crate::win_native::service::query_service_status(cowork_guard::COWORK_SERVICE_NAME)
            .is_ok_and(|st| st.exists && st.running)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

pub(super) fn is_claude_process_running() -> bool {
    if !is_cowork_service_installed_and_running() {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        crate::win_native::process::is_process_running_by_name("claude.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

pub(crate) struct CoworkTickOutcome {
    pub(crate) status: cowork_guard::CoworkGuardStatus,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) triggered: bool,
}

pub(crate) async fn evaluate_cowork_guard_tick<
    FStatus,
    FStatusFut,
    FClaude,
    FClaudeFut,
    FTrigger,
    FTriggerFut,
    FSleep,
    FSleepFut,
>(
    os_effects: bool,
    mut query_status: FStatus,
    probe_claude_running: FClaude,
    trigger_task: FTrigger,
    sleep_after_trigger: FSleep,
) -> Option<CoworkTickOutcome>
where
    FStatus: FnMut() -> FStatusFut,
    FStatusFut: std::future::Future<Output = Option<cowork_guard::CoworkGuardStatus>>,
    FClaude: FnOnce() -> FClaudeFut,
    FClaudeFut: std::future::Future<Output = bool>,
    FTrigger: FnOnce() -> FTriggerFut,
    FTriggerFut: std::future::Future<Output = bool>,
    FSleep: FnOnce() -> FSleepFut,
    FSleepFut: std::future::Future<Output = ()>,
{
    let mut status = query_status().await?;
    let claude_running = if should_probe_claude_process(&status, os_effects) {
        probe_claude_running().await
    } else {
        false
    };
    let mut triggered = false;
    if should_trigger_cowork_guard(&status, claude_running, os_effects) {
        triggered = trigger_task().await;
        if triggered {
            sleep_after_trigger().await;
            if let Some(refreshed) = query_status().await {
                status = refreshed;
            }
        }
    }
    Some(CoworkTickOutcome { status, triggered })
}

/// Periodically verifies Windows `CoworkVMService` Start type / macOS AI helpers every 60s.
/// If a Windows Store update resets `CoworkVMService\Start` back to `2` (Automatic) or the
/// service is left running with Claude closed while the Task Scheduler guard is installed,
/// triggers the guard task automatically and notifies the UI.
pub(super) fn spawn_cowork_guard_watcher(app: &tauri::App) {
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            let os_effects = crate::sysproxy::os_effects_enabled();
            if let Some(outcome) = evaluate_cowork_guard_tick(
                os_effects,
                || async {
                    tokio::task::spawn_blocking(cowork_guard::get_cowork_guard_status)
                        .await
                        .ok()
                },
                || async {
                    tokio::task::spawn_blocking(is_claude_process_running)
                        .await
                        .unwrap_or(false)
                },
                || async {
                    tokio::task::spawn_blocking(cowork_guard::trigger_cowork_guard_task)
                        .await
                        .unwrap_or(false)
                },
                || tokio::time::sleep(Duration::from_secs(2)),
            )
            .await
            {
                let _ = handle.emit("cowork-guard://status", &outcome.status);
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

#[cfg(test)]
#[path = "cowork_watcher_tests.rs"]
mod tests;
