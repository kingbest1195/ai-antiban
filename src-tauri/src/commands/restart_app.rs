//! "Restart Antigravity with protection": closes the app politely and starts it again with the
//! gateway address in its environment (its agent ignores the system PAC and reads only
//! `HTTPS_PROXY` / `HTTP_PROXY`).
//!
//! Safety rules: the front end sends only an id from a whitelist; the app path, bundle id and the
//! gateway address are decided here. The app is never killed: it is asked to quit (it may ask the
//! user about unsaved work) and, if it does not go away in time, nothing is started or touched.
//! Programs run with separate arguments, never through a shell. The OS is reached only through
//! the [`SystemProbe`] (process list) and [`AppLauncher`] (`osascript`, `open`) seams.

use crate::proxy::ProxyManager;
use crate::proxy::coverage::{Os, RealProbe, SystemProbe, antigravity_app_path};
use crate::state::AppState;
use crate::sysproxy::FileCtx;
pub use crate::sysproxy::relaunch::{
    AppLauncher, QUIT_POLL_INTERVAL, QUIT_TIMEOUT, QuitTiming, RealLauncher, RunResult,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Bundle id of Antigravity; `osascript` addresses the app by it, not by a name.
const ANTIGRAVITY_BUNDLE_ID: &str = "com.google.antigravity";
/// Addresses of the machine itself never go through the gateway (the UI talks to its local agent).
const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// The only app this command is allowed to restart.
pub const APP_ID_ANTIGRAVITY: &str = "antigravity";

/// What happened. The front end maps each value to its own text and advice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartOutcome {
    /// Started with the gateway address in its environment.
    Restarted,
    /// Still running after [`QUIT_TIMEOUT`]; nothing was started or touched.
    NotClosed,
    /// macOS refused the Apple event ("Automation" permission).
    NeedsAutomationPermission,
    /// `open` did not start the app.
    LaunchFailed,
    /// The app is not installed (no `.app` bundle found).
    NotInstalled,
    /// Not macOS: only the manual command exists.
    Unsupported,
}

/// Does the process list contain a process from the Antigravity bundle? `ps -axo comm=` prints
/// full executable paths, and every helper of the app lives inside `Antigravity.app/Contents/`.
/// (A command-line tool of the same name elsewhere is not the app and must not block a restart.)
fn bundle_running(listing: &str) -> bool {
    listing
        .lines()
        .any(|l| l.to_ascii_lowercase().contains("antigravity.app/contents/"))
}

/// `Some(running)`, or `None` when the process list could not be read.
fn is_running(probe: &dyn SystemProbe) -> Option<bool> {
    probe
        .run("ps", &["-axo", "comm="])
        .map(|t| bundle_running(&t))
}

fn is_permission_denied(stderr: &str) -> bool {
    stderr.contains("-1743") || stderr.to_ascii_lowercase().contains("not authorized")
}

/// `osascript -e 'tell application id "<bundle id>" to quit'`: the argument list, one item each.
fn quit_args() -> Vec<String> {
    vec![
        "-e".to_string(),
        format!("tell application id \"{ANTIGRAVITY_BUNDLE_ID}\" to quit"),
    ]
}

/// `open -a <app> --env ...`: the address comes from the gateway, never from the caller.
fn open_args(app: &Path, gateway: SocketAddr) -> Vec<String> {
    let url = format!("http://{gateway}");
    vec![
        "-a".to_string(),
        app.to_string_lossy().into_owned(),
        "--env".to_string(),
        format!("HTTPS_PROXY={url}"),
        "--env".to_string(),
        format!("HTTP_PROXY={url}"),
        "--env".to_string(),
        format!("NO_PROXY={NO_PROXY}"),
    ]
}

/// The whole sequence; blocking (polls the process list), so callers run it off the async pool.
/// `Err` is for a refused request (not in the whitelist) or an unreadable process list.
pub(crate) fn restart_with_gateway(
    app_id: &str,
    os: Os,
    ctx: &FileCtx,
    gateway: SocketAddr,
    probe: &dyn SystemProbe,
    launcher: &dyn AppLauncher,
    timing: QuitTiming,
) -> Result<RestartOutcome, String> {
    if app_id != APP_ID_ANTIGRAVITY {
        return Err("Перезапуск этого приложения не поддерживается".to_string());
    }
    if os != Os::Macos {
        return Ok(RestartOutcome::Unsupported);
    }
    let Some(app_path) = antigravity_app_path(ctx) else {
        return Ok(RestartOutcome::NotInstalled);
    };

    let running =
        is_running(probe).ok_or_else(|| "Не удалось прочитать список процессов".to_string())?;
    if running {
        // A soft quit only: the app may ask about unsaved work, and that is the user's call.
        let quit = launcher.run("osascript", &quit_args());
        if quit
            .as_ref()
            .is_some_and(|r| !r.success && is_permission_denied(&r.stderr))
        {
            return Ok(RestartOutcome::NeedsAutomationPermission);
        }
        // Any other osascript failure is not final: the user may close the app themselves
        // within the same time limit, so the wait below still applies.
        let started = Instant::now();
        loop {
            if is_running(probe) == Some(false) {
                break;
            }
            if started.elapsed() >= timing.timeout {
                return Ok(RestartOutcome::NotClosed);
            }
            std::thread::sleep(timing.interval);
        }
    }

    match launcher.run("open", &open_args(&app_path, gateway)) {
        Some(r) if r.success => Ok(RestartOutcome::Restarted),
        _ => Ok(RestartOutcome::LaunchFailed),
    }
}

/// Only one restart at a time (a second click while the first one waits is refused).
static IN_PROGRESS: AtomicBool = AtomicBool::new(false);

struct Busy;

impl Busy {
    fn enter() -> Option<Self> {
        (!IN_PROGRESS.swap(true, Ordering::SeqCst)).then_some(Busy)
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        IN_PROGRESS.store(false, Ordering::SeqCst);
    }
}

/// Closes Antigravity (politely) and starts it again with the gateway address. The caller passes
/// only the id; see the module docs. After a successful start the coverage snapshot is re-read.
#[tauri::command]
pub async fn restart_app_with_gateway(
    app_id: String,
    proxy_manager: tauri::State<'_, ProxyManager>,
    state: tauri::State<'_, AppState>,
) -> Result<RestartOutcome, String> {
    if app_id != APP_ID_ANTIGRAVITY {
        return Err("Перезапуск этого приложения не поддерживается".to_string());
    }
    let Some(_busy) = Busy::enter() else {
        return Err("Перезапуск уже выполняется".to_string());
    };
    let gateway = proxy_manager.server.bound_addr;
    let outcome = tokio::task::spawn_blocking(move || {
        let ctx =
            FileCtx::real().ok_or_else(|| "Не удалось определить домашний каталог".to_string())?;
        restart_with_gateway(
            &app_id,
            Os::current(),
            &ctx,
            gateway,
            &RealProbe,
            &RealLauncher,
            QuitTiming::DEFAULT,
        )
    })
    .await
    .map_err(|e| format!("restart task failed: {e}"))??;
    if outcome == RestartOutcome::Restarted {
        // The status should follow the new process; a failed re-read is not a failed restart.
        let _ =
            super::coverage::build_snapshot(&proxy_manager, state.get_cli_mode().await, true).await;
    }
    Ok(outcome)
}

#[cfg(test)]
#[path = "restart_app_tests.rs"]
mod tests;
