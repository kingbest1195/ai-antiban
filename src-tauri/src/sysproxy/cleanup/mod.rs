//! Process-exit safety net and cleanup entry points: panic flag, OS signal watcher, restore of
//! the ownership journal and the one-time, signature-based cleanup of 1.3.x leftovers.

mod migration;
mod restore;
mod shutdown;
mod signatures;

pub(super) use restore::{cleanup_cli_files, restore_and_migrate_with, restore_user_env};
pub use shutdown::{
    SHUTDOWN_PROGRESS_EVENT, SHUTDOWN_PROGRESS_TOTAL, ShutdownCleanupGuard,
    ShutdownProgressPayload, is_shutdown_cleanup_completed, reset_shutdown_cleanup_guard,
    try_claim_async_shutdown,
};
#[allow(unused_imports)]
pub(super) use signatures::{
    is_zastava_env_signature, is_zastava_pac_signature, is_zastava_proxy_json,
};
pub use signatures::{legacy_env_plan, legacy_env_plan_with_gateway};

use super::journal::{self, RecoveryReport};
use super::{Run, state, with_journal};
use restore::{cleanup_cli_files as restore_cleanup_cli_files, restore_and_migrate};
use shutdown::SHUTDOWN_GUARD;
use std::sync::Once;
use tauri::{Emitter, Manager};

static CLEAN_HOOK_INIT: Once = Once::new();

/// Registers the panic hook once per process. The hook only raises a flag: no I/O and no system
/// call from inside a panic. Everything Zastava changed is in the journal, so the restore
/// happens at the next start (the release build aborts on panic; SIGKILL is the same case).
pub fn register_clean_exit_guard() {
    CLEAN_HOOK_INIT.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            journal::note_panic();
            default_hook(panic_info);
        }));
    });
}

/// Spawns an asynchronous OS signal watcher (`SIGINT` / `SIGTERM` / `SIGHUP`) that restores the
/// system settings Zastava changed before the process terminates.
pub fn spawn_signal_cleanup_watcher() {
    tauri::async_runtime::spawn(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate()).ok();
            let mut sighup = signal(SignalKind::hangup()).ok();

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = async {
                    match &mut sigterm {
                        Some(s) => { let _ = s.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {},
                _ = async {
                    match &mut sighup {
                        Some(s) => { let _ = s.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {},
            }
        }

        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }

        eprintln!("Termination signal received! Restoring system settings...");
        let _ = cleanup_on_shutdown_once(None, "quit");
        std::process::exit(0);
    });
}


fn cleanup_os_and_policies_pass() -> RecoveryReport {
    match with_journal("ownership_cleanup", |j, p| {
        // The PAC flag goes down before the restore, under the same lock (see `restore_pass`).
        super::restore_pass(state(), j, p, restore_and_migrate)
    }) {
        Run::Done(r) => r,
        Run::Blocked => RecoveryReport {
            skipped_dry_run: true,
            ..Default::default()
        },
        Run::Failed(_) => RecoveryReport {
            journal_write_failed: true,
            ..Default::default()
        },
    }
}

fn cleanup_cli_and_reset_state() -> RecoveryReport {
    let files = restore_cleanup_cli_files();
    state().reset();
    files
}

fn run_shutdown_cleanup_inner(
    app: Option<&tauri::AppHandle>,
    mode: &str,
    emit_step1: bool,
) -> Option<RecoveryReport> {
    SHUTDOWN_GUARD.run_once_with(
        mode,
        emit_step1,
        |payload| {
            if let Some(handle) = app {
                let _ = handle.emit(SHUTDOWN_PROGRESS_EVENT, payload);
            }
        },
        || {
            if let Some(handle) = app {
                if mode != "update" {
                    crate::core::shutdown::notify_shutdown();
                }
                if let Some(guard) =
                    handle.try_state::<std::sync::Arc<crate::proxy::NetworkGuard>>()
                {
                    guard.abort_active_tunnels();
                }
            }
            state().set_sys_proxy_active(false);
        },
        cleanup_os_and_policies_pass,
        cleanup_cli_and_reset_state,
        || {
            crate::os_tz::restore_on_exit_once(app);
        },
    )
}

/// Runs the deduplicated 4-step shutdown/update cleanup once per process exit, emitting
/// `"app://shutdown-progress"` events for steps 1..4 and completion.
pub fn cleanup_on_shutdown_once(
    app: Option<&tauri::AppHandle>,
    mode: &str,
) -> Option<RecoveryReport> {
    run_shutdown_cleanup_inner(app, mode, true)
}

/// Completes the deduplicated shutdown cleanup after step 1 was already emitted synchronously
/// on the main thread (used by the async tray-quit flow).
pub fn cleanup_on_shutdown_after_step1(
    app: Option<&tauri::AppHandle>,
    mode: &str,
) -> Option<RecoveryReport> {
    run_shutdown_cleanup_inner(app, mode, false)
}

/// Restores everything Zastava changed in the system from the ownership journal (PAC, chained
/// proxy, WinINet, user environment, browser policies), runs the one-time legacy migration and
/// cleans the CLI/IDE files. Intended for runtime toggle-off / manual cleanups (unguarded by the
/// process-exit guard).
pub fn cleanup_all_persistent_settings() -> RecoveryReport {
    let mut report = cleanup_os_and_policies_pass();
    let files = cleanup_cli_and_reset_state();
    report.items.extend(files.items);
    report.journal_write_failed |= files.journal_write_failed;
    report
}

/// Forcefully restores all system settings Zastava owns and cleans CLI/IDE files, returning a
/// human-readable list of the cleaned components. Foreign settings are never touched.
pub fn force_clean_all_os_proxy_traces() -> Vec<String> {
    let _ = cleanup_all_persistent_settings();
    cleaned_components()
}

/// Names of the components a full cleanup covers (for the user-facing result list).
pub fn cleaned_components() -> Vec<String> {
    vec![
        "Системный PAC-прокси".to_string(),
        "Конфигурации VS Code / Cursor / Claude".to_string(),
        "Профили терминала и переменные среды ОС".to_string(),
    ]
}

#[cfg(test)]
#[path = "../cleanup_tests/mod.rs"]
mod tests;

#[cfg(test)]
pub(super) use migration::{
    LAUNCHD_MIGRATION_MARK, LEGACY_MIGRATION_MARK, VPN_PAC_MIGRATION_MARK, migrate_legacy,
    migrate_legacy_pac,
};
#[cfg(test)]
pub(super) use restore::{Scope, restore_with, restore_with_probe};
#[cfg(test)]
#[allow(unused_imports)]
use crate::sysproxy::{Os, SystemProbe};
#[cfg(test)]
#[allow(unused_imports)]
use crate::sysproxy::browser_policies;
#[cfg(test)]
#[allow(unused_imports)]
use crate::sysproxy::fs::Fs;
#[cfg(test)]
#[allow(unused_imports)]
use crate::sysproxy::journal::{EntryState, Journal, Outcome, Resource, Value};
#[cfg(test)]
#[allow(unused_imports)]
use crate::sysproxy::platform::{FakePlatform, PacState, PlatOp, Platform, RegKind, RegValue};
#[cfg(test)]
#[allow(unused_imports)]
use crate::sysproxy::FileCtx;
#[cfg(test)]
#[allow(unused_imports)]
use std::collections::BTreeMap;
#[cfg(test)]
#[allow(unused_imports)]
use std::sync::Arc;
#[cfg(test)]
#[allow(unused_imports)]
use std::sync::atomic::Ordering;
