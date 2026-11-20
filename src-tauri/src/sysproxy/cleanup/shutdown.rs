use super::super::journal::RecoveryReport;
use serde::Serialize;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Event emitted during shutdown or update cleanup so the UI can show live phase progress.
pub const SHUTDOWN_PROGRESS_EVENT: &str = "app://shutdown-progress";
/// Total number of numbered shutdown cleanup phases before completion.
pub const SHUTDOWN_PROGRESS_TOTAL: u8 = 4;

/// Payload for [`SHUTDOWN_PROGRESS_EVENT`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ShutdownProgressPayload {
    pub mode: String,
    pub step: u8,
    pub total: u8,
    pub label: String,
    pub done: bool,
}

impl ShutdownProgressPayload {
    pub fn step(mode: &str, step: u8) -> Self {
        let label = match step {
            1 => "Остановка защиты и локального шлюза...",
            2 => "Восстановление системного прокси и политик браузеров...",
            3 => "Очистка настроек терминала и IDE...",
            _ => "Восстановление системного часового пояса...",
        };
        Self {
            mode: mode.to_string(),
            step,
            total: SHUTDOWN_PROGRESS_TOTAL,
            label: label.to_string(),
            done: false,
        }
    }

    pub fn done(mode: &str) -> Self {
        let label = if mode == "update" {
            "Перезапуск после обновления..."
        } else {
            "Готово, закрываем приложение..."
        };
        Self {
            mode: mode.to_string(),
            step: SHUTDOWN_PROGRESS_TOTAL,
            total: SHUTDOWN_PROGRESS_TOTAL,
            label: label.to_string(),
            done: true,
        }
    }
}

/// Process-wide idempotency guard for final shutdown / update cleanup so quit hooks and tray
/// handlers cannot run the full OS restore more than once.
pub struct ShutdownCleanupGuard {
    lock: Mutex<()>,
    in_progress: AtomicBool,
    completed: AtomicBool,
}

impl Default for ShutdownCleanupGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownCleanupGuard {
    pub const fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            in_progress: AtomicBool::new(false),
            completed: AtomicBool::new(false),
        }
    }

    /// Claims the async tray-quit slot before spawning a background cleanup worker. Returns
    /// `false` if shutdown cleanup has already started or completed.
    pub fn try_claim_async_start(&self) -> bool {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.in_progress.load(Ordering::SeqCst) || self.completed.load(Ordering::SeqCst) {
            return false;
        }
        self.in_progress.store(true, Ordering::SeqCst);
        true
    }

    /// Clears the guard when the process is NOT exiting after all (e.g. a failed update install
    /// that restored protection).
    pub fn reset(&self) {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.in_progress.store(false, Ordering::SeqCst);
        self.completed.store(false, Ordering::SeqCst);
    }

    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    /// Executes the 4-phase shutdown cleanup at most once, serializing concurrent callers.
    /// Returns `None` if cleanup already completed earlier.
    #[allow(clippy::too_many_arguments)]
    pub fn run_once_with(
        &self,
        mode: &str,
        emit_step1: bool,
        mut sink: impl FnMut(ShutdownProgressPayload),
        stop_gateway: impl FnOnce(),
        os_cleanup: impl FnOnce() -> RecoveryReport,
        cli_cleanup: impl FnOnce() -> RecoveryReport,
        tz_restore: impl FnOnce(),
    ) -> Option<RecoveryReport> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.completed.load(Ordering::SeqCst) {
            return None;
        }
        self.in_progress.store(true, Ordering::SeqCst);

        if emit_step1 {
            sink(ShutdownProgressPayload::step(mode, 1));
        }
        stop_gateway();

        sink(ShutdownProgressPayload::step(mode, 2));
        let mut report = os_cleanup();

        sink(ShutdownProgressPayload::step(mode, 3));
        let files = cli_cleanup();
        report.items.extend(files.items);
        report.journal_write_failed |= files.journal_write_failed;

        sink(ShutdownProgressPayload::step(mode, 4));
        tz_restore();

        sink(ShutdownProgressPayload::done(mode));
        self.completed.store(true, Ordering::SeqCst);
        self.in_progress.store(false, Ordering::SeqCst);
        Some(report)
    }
}

pub(super) static SHUTDOWN_GUARD: ShutdownCleanupGuard = ShutdownCleanupGuard::new();

/// Claims the async shutdown slot on the main thread before spawning background cleanup.
pub fn try_claim_async_shutdown() -> bool {
    SHUTDOWN_GUARD.try_claim_async_start()
}

/// Resets the shutdown cleanup guard (used if an update install fails and the app stays running).
pub fn reset_shutdown_cleanup_guard() {
    SHUTDOWN_GUARD.reset();
}

/// Returns `true` once shutdown cleanup has completed in this process.
pub fn is_shutdown_cleanup_completed() -> bool {
    SHUTDOWN_GUARD.is_completed()
}
