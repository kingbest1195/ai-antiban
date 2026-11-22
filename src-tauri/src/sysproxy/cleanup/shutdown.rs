use super::super::journal::RecoveryReport;
use super::super::{Os, RealProbe, SystemProbe};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Event emitted during shutdown or update cleanup so the UI can show live phase progress.
pub const SHUTDOWN_PROGRESS_EVENT: &str = "app://shutdown-progress";
/// Total number of numbered shutdown cleanup phases before completion.
pub const SHUTDOWN_PROGRESS_TOTAL: u8 = 4;

static GATEWAY_LAUNCHED_APPS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Records an application explicitly restarted through Zastava's gateway (e.g. `"Antigravity"`)
/// so shutdown can warn the user if that process is still bound to the closing gateway port.
pub fn record_gateway_launched_app(app_name: &str) {
    let trimmed = app_name.trim();
    if trimmed.is_empty() {
        return;
    }
    let mut g = GATEWAY_LAUNCHED_APPS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    g.insert(trimmed.to_string());
}

fn snapshot_gateway_launched_apps() -> Vec<String> {
    GATEWAY_LAUNCHED_APPS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect()
}

struct SupportedEditor {
    name: &'static str,
    mac_bundles: &'static [&'static str],
    win_exes: &'static [&'static str],
    linux_bins: &'static [&'static str],
}

const SUPPORTED_EDITORS: &[SupportedEditor] = &[
    SupportedEditor {
        name: "Antigravity",
        mac_bundles: &["antigravity.app/contents/"],
        win_exes: &["antigravity.exe"],
        linux_bins: &["antigravity"],
    },
    SupportedEditor {
        name: "Cursor",
        mac_bundles: &["cursor.app/contents/"],
        win_exes: &["cursor.exe"],
        linux_bins: &["cursor"],
    },
    SupportedEditor {
        name: "Visual Studio Code",
        mac_bundles: &["visual studio code.app/contents/", "vscodium.app/contents/"],
        win_exes: &["code.exe", "vscodium.exe"],
        linux_bins: &["code", "codium"],
    },
    SupportedEditor {
        name: "Windsurf",
        mac_bundles: &["windsurf.app/contents/"],
        win_exes: &["windsurf.exe"],
        linux_bins: &["windsurf"],
    },
];

fn editor_matches_listing(name: &str, os: Os, listing_lower: &str) -> bool {
    let Some(ed) = SUPPORTED_EDITORS.iter().find(|e| e.name == name) else {
        return true;
    };
    listing_lower.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return false;
        }
        match os {
            Os::Macos => ed.mac_bundles.iter().any(|b| trimmed.contains(b)),
            Os::Windows => {
                let first = trimmed.split(',').next().unwrap_or("");
                let image = first.trim().trim_matches('"');
                ed.win_exes.contains(&image)
            }
            Os::Linux => {
                let exe = std::path::Path::new(trimmed)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                ed.linux_bins.contains(&exe)
            }
        }
    })
}

/// Pure collection of Windows apps/IDEs from native `ProcessEntry` list.
pub(crate) fn collect_gateway_bound_apps_from_win_entries(
    launched: &[String],
    cli_active: bool,
    entries: &[crate::win_native::process::ProcessEntry],
) -> Vec<String> {
    if launched.is_empty() && !cli_active {
        return Vec::new();
    }
    let listing_lower: Vec<String> = entries
        .iter()
        .map(|p| {
            crate::win_native::extract_exe_basename(&p.exe_name)
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty())
        .collect();
    let matches_editor = |name: &str| -> bool {
        let Some(ed) = SUPPORTED_EDITORS.iter().find(|e| e.name == name) else {
            return true;
        };
        listing_lower
            .iter()
            .any(|img| ed.win_exes.contains(&img.as_str()))
    };
    let mut out = BTreeSet::new();
    for app in launched {
        if matches_editor(app) {
            out.insert(app.clone());
        }
    }
    if cli_active {
        for ed in SUPPORTED_EDITORS {
            if matches_editor(ed.name) {
                out.insert(ed.name.to_string());
            }
        }
    }
    out.into_iter().collect()
}

/// Pure collection of apps/IDEs that may still hold gateway proxy settings in memory.
pub(crate) fn collect_gateway_bound_apps_with(
    launched: &[String],
    cli_active: bool,
    os: Os,
    probe: &dyn SystemProbe,
) -> Vec<String> {
    if launched.is_empty() && !cli_active {
        return Vec::new();
    }
    if os == Os::Windows {
        if !crate::sysproxy::os_effects_enabled() {
            return Vec::new();
        }
        return match crate::win_native::process::list_processes() {
            Ok(entries) => {
                collect_gateway_bound_apps_from_win_entries(launched, cli_active, &entries)
            }
            Err(_) => launched.to_vec(),
        };
    }
    let listing = probe.run("ps", &["-axo", "comm="]);
    let mut out = BTreeSet::new();
    match listing {
        Some(text) => {
            let lower = text.to_ascii_lowercase();
            for app in launched {
                if editor_matches_listing(app, os, &lower) {
                    out.insert(app.clone());
                }
            }
            if cli_active {
                for ed in SUPPORTED_EDITORS {
                    if editor_matches_listing(ed.name, os, &lower) {
                        out.insert(ed.name.to_string());
                    }
                }
            }
        }
        None => {
            for app in launched {
                out.insert(app.clone());
            }
        }
    }
    out.into_iter().collect()
}

pub(crate) fn collect_gateway_bound_apps(cli_active: bool) -> Vec<String> {
    let launched = snapshot_gateway_launched_apps();
    collect_gateway_bound_apps_with(&launched, cli_active, Os::current(), &RealProbe)
}

/// Payload for [`SHUTDOWN_PROGRESS_EVENT`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownProgressPayload {
    pub mode: String,
    pub step: u8,
    pub total: u8,
    pub label: String,
    pub done: bool,
    #[serde(default)]
    pub gateway_bound_apps: Vec<String>,
}

impl ShutdownProgressPayload {
    pub fn step(mode: &str, step: u8) -> Self {
        Self::step_with_keep_tz(mode, step, false)
    }

    pub fn step_with_keep_tz(mode: &str, step: u8, keep_tz: bool) -> Self {
        let label = match step {
            1 => "Остановка защиты и локального шлюза...",
            2 => "Восстановление системного прокси и политик браузеров...",
            3 => "Очистка настроек терминала и IDE...",
            _ if keep_tz => "Сохранение системного часового пояса ОС...",
            _ => "Восстановление системного часового пояса...",
        };
        Self {
            mode: mode.to_string(),
            step,
            total: SHUTDOWN_PROGRESS_TOTAL,
            label: label.to_string(),
            done: false,
            gateway_bound_apps: Vec::new(),
        }
    }

    pub fn done(mode: &str) -> Self {
        Self::done_with_apps(mode, Vec::new())
    }

    pub fn done_with_apps(mode: &str, gateway_bound_apps: Vec<String>) -> Self {
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
            gateway_bound_apps,
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
        sink: impl FnMut(ShutdownProgressPayload),
        stop_gateway: impl FnOnce(),
        os_cleanup: impl FnOnce() -> RecoveryReport,
        cli_cleanup: impl FnOnce() -> RecoveryReport,
        tz_restore: impl FnOnce(),
    ) -> Option<RecoveryReport> {
        self.run_once_with_tz_keep(
            mode,
            emit_step1,
            crate::os_tz::keep_system_tz_on_exit(),
            sink,
            stop_gateway,
            os_cleanup,
            cli_cleanup,
            tz_restore,
        )
    }

    /// Executes the 4-phase shutdown cleanup with an explicit `keep_tz` flag for step 4.
    #[allow(clippy::too_many_arguments)]
    pub fn run_once_with_tz_keep(
        &self,
        mode: &str,
        emit_step1: bool,
        keep_tz: bool,
        sink: impl FnMut(ShutdownProgressPayload),
        stop_gateway: impl FnOnce(),
        os_cleanup: impl FnOnce() -> RecoveryReport,
        cli_cleanup: impl FnOnce() -> RecoveryReport,
        tz_restore: impl FnOnce(),
    ) -> Option<RecoveryReport> {
        self.run_once_full(
            mode,
            emit_step1,
            keep_tz,
            sink,
            stop_gateway,
            os_cleanup,
            cli_cleanup,
            tz_restore,
            Vec::new,
        )
    }

    /// Executes the 4-phase shutdown cleanup and collects `gateway_bound_apps` before CLI state
    /// is reset so the final completion event reports any editors still bound to the gateway.
    #[allow(clippy::too_many_arguments)]
    pub fn run_once_full(
        &self,
        mode: &str,
        emit_step1: bool,
        keep_tz: bool,
        mut sink: impl FnMut(ShutdownProgressPayload),
        stop_gateway: impl FnOnce(),
        os_cleanup: impl FnOnce() -> RecoveryReport,
        cli_cleanup: impl FnOnce() -> RecoveryReport,
        tz_restore: impl FnOnce(),
        collect_apps: impl FnOnce() -> Vec<String>,
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

        let gateway_bound_apps = collect_apps();
        sink(ShutdownProgressPayload::step(mode, 3));
        let files = cli_cleanup();
        report.items.extend(files.items);
        report.journal_write_failed |= files.journal_write_failed;

        sink(ShutdownProgressPayload::step_with_keep_tz(mode, 4, keep_tz));
        if !keep_tz {
            tz_restore();
        }

        sink(ShutdownProgressPayload::done_with_apps(
            mode,
            gateway_bound_apps,
        ));
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
