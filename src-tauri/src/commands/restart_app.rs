//! "Restart Antigravity with protection": closes the app politely and starts it again with the
//! gateway address in its environment (its agent ignores the system PAC and reads only
//! `HTTPS_PROXY` / `HTTP_PROXY`).
//!
//! Safety rules: the front end sends only an id from a whitelist; the app path, bundle id and the
//! gateway address are decided here. The app is never killed: it is asked to quit (it may ask the
//! user about unsaved work) and, if it does not go away in time, nothing is started or touched.
//! Programs run with separate arguments, never through a shell. The OS is reached only through
//! the [`SystemProbe`] (process list) and [`AppLauncher`] (`osascript`, `open`) seams.

use crate::proxy::coverage::{Os, RealProbe, SystemProbe, antigravity_app_path};
use crate::proxy::ProxyManager;
use crate::state::AppState;
use crate::sysproxy::FileCtx;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long the app gets to quit (the user may be answering a "save changes?" window).
pub const QUIT_TIMEOUT: Duration = Duration::from_secs(15);
/// How often the process list is read while waiting.
pub const QUIT_POLL_INTERVAL: Duration = Duration::from_millis(500);

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

/// How long to wait for the app to quit (a parameter so tests do not wait 15 s).
#[derive(Debug, Clone, Copy)]
pub struct QuitTiming {
    pub timeout: Duration,
    pub interval: Duration,
}

impl QuitTiming {
    pub const DEFAULT: Self = Self {
        timeout: QUIT_TIMEOUT,
        interval: QUIT_POLL_INTERVAL,
    };
}

/// Result of one external program run.
pub struct RunResult {
    pub success: bool,
    pub stderr: String,
}

/// Runs a program with separate arguments (no shell). `None` — it could not be started.
pub trait AppLauncher: Send + Sync {
    fn run(&self, program: &str, args: &[String]) -> Option<RunResult>;
}

/// The real thing; in OS dry-run mode `silent_command` starts nothing.
pub struct RealLauncher;

impl AppLauncher for RealLauncher {
    fn run(&self, program: &str, args: &[String]) -> Option<RunResult> {
        let out = crate::sysproxy::silent_command(program)
            .args(args)
            .output()
            .ok()?;
        Some(RunResult {
            success: out.status.success(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
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

    let running = is_running(probe)
        .ok_or_else(|| "Не удалось прочитать список процессов".to_string())?;
    if running {
        // A soft quit only: the app may ask about unsaved work, and that is the user's call.
        let quit = launcher.run("osascript", &quit_args());
        if quit.as_ref().is_some_and(|r| !r.success && is_permission_denied(&r.stderr)) {
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
        let ctx = FileCtx::real().ok_or_else(|| "Не удалось определить домашний каталог".to_string())?;
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
        let _ = super::coverage::build_snapshot(&proxy_manager, state.get_cli_mode().await, true).await;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysproxy::fs::{FakeFs, Fs};
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    const BUNDLE_LINE: &str = "/Applications/Antigravity.app/Contents/MacOS/Electron";
    const AGENT_LINE: &str = "/Applications/Antigravity.app/Contents/Resources/app/bin/language_server_macos_arm";
    const OTHER_LINES: &str = "/usr/sbin/cfprefsd\n/Applications/Safari.app/Contents/MacOS/Safari\n";

    /// Process list answers in order; the last one repeats. `None` — the listing failed.
    struct FakeProbe {
        answers: Mutex<VecDeque<Option<String>>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeProbe {
        fn new(answers: &[Option<&str>]) -> Self {
            Self {
                answers: Mutex::new(answers.iter().map(|a| a.map(str::to_string)).collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl SystemProbe for FakeProbe {
        fn run(&self, program: &str, args: &[&str]) -> Option<String> {
            self.calls.lock().unwrap().push(format!("{program} {}", args.join(" ")));
            let mut a = self.answers.lock().unwrap();
            if a.len() > 1 { a.pop_front().unwrap() } else { a.front().cloned().flatten() }
        }
    }

    /// Records every program and its argument list; answers per program.
    struct FakeLauncher {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        osascript: Mutex<Option<RunResult>>,
        open_ok: bool,
    }

    impl FakeLauncher {
        fn new(osascript: Option<RunResult>, open_ok: bool) -> Self {
            Self { calls: Mutex::new(Vec::new()), osascript: Mutex::new(osascript), open_ok }
        }
        fn ok() -> Self {
            Self::new(Some(RunResult { success: true, stderr: String::new() }), true)
        }
        fn programs(&self) -> Vec<String> {
            self.calls.lock().unwrap().iter().map(|(p, _)| p.clone()).collect()
        }
    }

    impl AppLauncher for FakeLauncher {
        fn run(&self, program: &str, args: &[String]) -> Option<RunResult> {
            self.calls.lock().unwrap().push((program.to_string(), args.to_vec()));
            match program {
                "osascript" => self.osascript.lock().unwrap().take(),
                "open" => Some(RunResult { success: self.open_ok, stderr: String::new() }),
                _ => None,
            }
        }
    }

    fn gw() -> SocketAddr {
        "127.0.0.1:40111".parse().unwrap()
    }

    fn ctx(installed: bool) -> FileCtx {
        let fs = FakeFs::default();
        if installed {
            fs.create_private_dir_all(Path::new("/Applications/Antigravity.app")).unwrap();
        }
        FileCtx::new(Arc::new(fs), PathBuf::from("home").join("user"), vec![])
    }

    const FAST: QuitTiming = QuitTiming {
        timeout: Duration::from_millis(60),
        interval: Duration::from_millis(5),
    };

    fn run(
        app_id: &str,
        os: Os,
        installed: bool,
        probe: &FakeProbe,
        launcher: &FakeLauncher,
    ) -> Result<RestartOutcome, String> {
        restart_with_gateway(app_id, os, &ctx(installed), gw(), probe, launcher, FAST)
    }

    fn expected_open() -> Vec<String> {
        [
            "-a",
            "/Applications/Antigravity.app",
            "--env",
            "HTTPS_PROXY=http://127.0.0.1:40111",
            "--env",
            "HTTP_PROXY=http://127.0.0.1:40111",
            "--env",
            "NO_PROXY=localhost,127.0.0.1,::1",
        ]
        .map(String::from)
        .to_vec()
    }

    #[test]
    fn not_running_opens_once_with_exact_arguments() {
        let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
        let launcher = FakeLauncher::ok();
        assert_eq!(run("antigravity", Os::Macos, true, &probe, &launcher), Ok(RestartOutcome::Restarted));
        let calls = launcher.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "no osascript for a closed app: it would launch it");
        assert_eq!(calls[0], ("open".to_string(), expected_open()));
    }

    #[test]
    fn running_is_asked_to_quit_then_waited_for_then_opened() {
        // Running (initial), still running (1st poll), gone (2nd poll).
        let both = format!("{OTHER_LINES}{BUNDLE_LINE}\n{AGENT_LINE}\n");
        let probe = FakeProbe::new(&[Some(&both), Some(&both), Some(OTHER_LINES)]);
        let launcher = FakeLauncher::ok();
        assert_eq!(run("antigravity", Os::Macos, true, &probe, &launcher), Ok(RestartOutcome::Restarted));
        let calls = launcher.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0],
            (
                "osascript".to_string(),
                vec!["-e".to_string(), "tell application id \"com.google.antigravity\" to quit".to_string()]
            )
        );
        assert_eq!(calls[1], ("open".to_string(), expected_open()));
        assert_eq!(probe.calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn not_closed_in_time_starts_and_touches_nothing_more() {
        let running = format!("{BUNDLE_LINE}\n");
        let probe = FakeProbe::new(&[Some(&running)]);
        let launcher = FakeLauncher::ok();
        assert_eq!(run("antigravity", Os::Macos, true, &probe, &launcher), Ok(RestartOutcome::NotClosed));
        // Only the polite quit request: no `open`, and nothing that kills (no kill/pkill/killall).
        assert_eq!(launcher.programs(), vec!["osascript".to_string()]);
        assert!(probe.calls.lock().unwrap().iter().all(|c| c.starts_with("ps ")));
    }

    #[test]
    fn automation_denied_reports_permission_and_does_not_wait_or_open() {
        let running = format!("{BUNDLE_LINE}\n");
        let probe = FakeProbe::new(&[Some(&running)]);
        let denied = RunResult {
            success: false,
            stderr: "execution error: Not authorized to send Apple events to Antigravity. (-1743)".into(),
        };
        let launcher = FakeLauncher::new(Some(denied), true);
        assert_eq!(
            run("antigravity", Os::Macos, true, &probe, &launcher),
            Ok(RestartOutcome::NeedsAutomationPermission)
        );
        assert_eq!(launcher.programs(), vec!["osascript".to_string()]);
        assert_eq!(probe.calls.lock().unwrap().len(), 1, "no polling after a refusal");
    }

    #[test]
    fn other_osascript_failure_still_lets_the_user_close_the_app() {
        let running = format!("{BUNDLE_LINE}\n");
        let probe = FakeProbe::new(&[Some(&running), Some(OTHER_LINES)]);
        let failed = RunResult { success: false, stderr: "some other error (-600)".into() };
        let launcher = FakeLauncher::new(Some(failed), true);
        assert_eq!(run("antigravity", Os::Macos, true, &probe, &launcher), Ok(RestartOutcome::Restarted));
        assert_eq!(launcher.programs(), vec!["osascript".to_string(), "open".to_string()]);
    }

    #[test]
    fn open_failure_is_launch_failed() {
        let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
        let launcher = FakeLauncher::new(None, false);
        assert_eq!(run("antigravity", Os::Macos, true, &probe, &launcher), Ok(RestartOutcome::LaunchFailed));
        // `open` that could not even start is the same outcome.
        struct NoStart;
        impl AppLauncher for NoStart {
            fn run(&self, _: &str, _: &[String]) -> Option<RunResult> {
                None
            }
        }
        let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
        assert_eq!(
            restart_with_gateway("antigravity", Os::Macos, &ctx(true), gw(), &probe, &NoStart, FAST),
            Ok(RestartOutcome::LaunchFailed)
        );
    }

    #[test]
    fn unknown_app_id_is_refused_before_anything_runs() {
        for id in ["", "Antigravity", "claude", "antigravity ", "../antigravity", "antigravity; rm -rf /"] {
            let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
            let launcher = FakeLauncher::ok();
            assert!(run(id, Os::Macos, true, &probe, &launcher).is_err(), "{id:?}");
            assert!(launcher.calls.lock().unwrap().is_empty());
            assert!(probe.calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn other_systems_are_unsupported_and_untouched() {
        for os in [Os::Windows, Os::Linux] {
            let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
            let launcher = FakeLauncher::ok();
            assert_eq!(run("antigravity", os, true, &probe, &launcher), Ok(RestartOutcome::Unsupported));
            assert!(launcher.calls.lock().unwrap().is_empty());
            assert!(probe.calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn not_installed_starts_nothing() {
        let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
        let launcher = FakeLauncher::ok();
        assert_eq!(run("antigravity", Os::Macos, false, &probe, &launcher), Ok(RestartOutcome::NotInstalled));
        assert!(launcher.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn unreadable_process_list_is_an_error_not_a_guess() {
        let probe = FakeProbe::new(&[None]);
        let launcher = FakeLauncher::ok();
        assert!(run("antigravity", Os::Macos, true, &probe, &launcher).is_err());
        assert!(launcher.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_cli_with_the_same_name_is_not_the_app() {
        assert!(!bundle_running("/Users/x/.gemini/antigravity-cli/bin/agy\n"));
        assert!(bundle_running(BUNDLE_LINE));
        assert!(bundle_running("/Users/x/Applications/Antigravity.app/Contents/Frameworks/Antigravity Helper.app/Contents/MacOS/Antigravity Helper"));
    }

    #[test]
    fn arguments_are_separate_items_and_the_address_is_the_gateways() {
        let args = open_args(Path::new("/Applications/Antigravity.app"), "127.0.0.1:9".parse().unwrap());
        assert_eq!(args.len(), 8);
        assert_eq!(args[3], "HTTPS_PROXY=http://127.0.0.1:9");
        assert_eq!(args[5], "HTTP_PROXY=http://127.0.0.1:9");
        // No argument carries more than one `--env` pair or a shell separator.
        assert!(args.iter().all(|a| !a.contains(';') && !a.contains('&') && !a.contains('|') && !a.contains(' ')));
    }
}
