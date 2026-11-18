use super::*;
use crate::sysproxy::fs::{FakeFs, Fs};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BUNDLE_LINE: &str = "/Applications/Antigravity.app/Contents/MacOS/Electron";
const AGENT_LINE: &str =
    "/Applications/Antigravity.app/Contents/Resources/app/bin/language_server_macos_arm";
const OTHER_LINES: &str =
    "/usr/sbin/cfprefsd\n/Applications/Safari.app/Contents/MacOS/Safari\n";

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
        self.calls
            .lock()
            .unwrap()
            .push(format!("{program} {}", args.join(" ")));
        let mut a = self.answers.lock().unwrap();
        if a.len() > 1 {
            a.pop_front().unwrap()
        } else {
            a.front().cloned().flatten()
        }
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
        Self {
            calls: Mutex::new(Vec::new()),
            osascript: Mutex::new(osascript),
            open_ok,
        }
    }
    fn ok() -> Self {
        Self::new(
            Some(RunResult {
                success: true,
                stderr: String::new(),
            }),
            true,
        )
    }
    fn programs(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| p.clone())
            .collect()
    }
}

impl AppLauncher for FakeLauncher {
    fn run(&self, program: &str, args: &[String]) -> Option<RunResult> {
        self.calls
            .lock()
            .unwrap()
            .push((program.to_string(), args.to_vec()));
        match program {
            "osascript" => self.osascript.lock().unwrap().take(),
            "open" => Some(RunResult {
                success: self.open_ok,
                stderr: String::new(),
            }),
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
        fs.create_private_dir_all(Path::new("/Applications/Antigravity.app"))
            .unwrap();
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
    assert_eq!(
        run("antigravity", Os::Macos, true, &probe, &launcher),
        Ok(RestartOutcome::Restarted)
    );
    let calls = launcher.calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        1,
        "no osascript for a closed app: it would launch it"
    );
    assert_eq!(calls[0], ("open".to_string(), expected_open()));
}

#[test]
fn running_is_asked_to_quit_then_waited_for_then_opened() {
    // Running (initial), still running (1st poll), gone (2nd poll).
    let both = format!("{OTHER_LINES}{BUNDLE_LINE}\n{AGENT_LINE}\n");
    let probe = FakeProbe::new(&[Some(&both), Some(&both), Some(OTHER_LINES)]);
    let launcher = FakeLauncher::ok();
    assert_eq!(
        run("antigravity", Os::Macos, true, &probe, &launcher),
        Ok(RestartOutcome::Restarted)
    );
    let calls = launcher.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0],
        (
            "osascript".to_string(),
            vec![
                "-e".to_string(),
                "tell application id \"com.google.antigravity\" to quit".to_string()
            ]
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
    assert_eq!(
        run("antigravity", Os::Macos, true, &probe, &launcher),
        Ok(RestartOutcome::NotClosed)
    );
    // Only the polite quit request: no `open`, and nothing that kills (no kill/pkill/killall).
    assert_eq!(launcher.programs(), vec!["osascript".to_string()]);
    assert!(
        probe
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|c| c.starts_with("ps "))
    );
}

#[test]
fn automation_denied_reports_permission_and_does_not_wait_or_open() {
    let running = format!("{BUNDLE_LINE}\n");
    let probe = FakeProbe::new(&[Some(&running)]);
    let denied = RunResult {
        success: false,
        stderr: "execution error: Not authorized to send Apple events to Antigravity. (-1743)"
            .into(),
    };
    let launcher = FakeLauncher::new(Some(denied), true);
    assert_eq!(
        run("antigravity", Os::Macos, true, &probe, &launcher),
        Ok(RestartOutcome::NeedsAutomationPermission)
    );
    assert_eq!(launcher.programs(), vec!["osascript".to_string()]);
    assert_eq!(
        probe.calls.lock().unwrap().len(),
        1,
        "no polling after a refusal"
    );
}

#[test]
fn other_osascript_failure_still_lets_the_user_close_the_app() {
    let running = format!("{BUNDLE_LINE}\n");
    let probe = FakeProbe::new(&[Some(&running), Some(OTHER_LINES)]);
    let failed = RunResult {
        success: false,
        stderr: "some other error (-600)".into(),
    };
    let launcher = FakeLauncher::new(Some(failed), true);
    assert_eq!(
        run("antigravity", Os::Macos, true, &probe, &launcher),
        Ok(RestartOutcome::Restarted)
    );
    assert_eq!(
        launcher.programs(),
        vec!["osascript".to_string(), "open".to_string()]
    );
}

#[test]
fn open_failure_is_launch_failed() {
    let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
    let launcher = FakeLauncher::new(None, false);
    assert_eq!(
        run("antigravity", Os::Macos, true, &probe, &launcher),
        Ok(RestartOutcome::LaunchFailed)
    );
    // `open` that could not even start is the same outcome.
    struct NoStart;
    impl AppLauncher for NoStart {
        fn run(&self, _: &str, _: &[String]) -> Option<RunResult> {
            None
        }
    }
    let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
    assert_eq!(
        restart_with_gateway(
            "antigravity",
            Os::Macos,
            &ctx(true),
            gw(),
            &probe,
            &NoStart,
            FAST
        ),
        Ok(RestartOutcome::LaunchFailed)
    );
}

#[test]
fn unknown_app_id_is_refused_before_anything_runs() {
    for id in [
        "",
        "Antigravity",
        "claude",
        "antigravity ",
        "../antigravity",
        "antigravity; rm -rf /",
    ] {
        let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
        let launcher = FakeLauncher::ok();
        assert!(
            run(id, Os::Macos, true, &probe, &launcher).is_err(),
            "{id:?}"
        );
        assert!(launcher.calls.lock().unwrap().is_empty());
        assert!(probe.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn other_systems_are_unsupported_and_untouched() {
    for os in [Os::Windows, Os::Linux] {
        let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
        let launcher = FakeLauncher::ok();
        assert_eq!(
            run("antigravity", os, true, &probe, &launcher),
            Ok(RestartOutcome::Unsupported)
        );
        assert!(launcher.calls.lock().unwrap().is_empty());
        assert!(probe.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn not_installed_starts_nothing() {
    let probe = FakeProbe::new(&[Some(OTHER_LINES)]);
    let launcher = FakeLauncher::ok();
    assert_eq!(
        run("antigravity", Os::Macos, false, &probe, &launcher),
        Ok(RestartOutcome::NotInstalled)
    );
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
    assert!(!bundle_running(
        "/Users/x/.gemini/antigravity-cli/bin/agy\n"
    ));
    assert!(bundle_running(BUNDLE_LINE));
    assert!(bundle_running(
        "/Users/x/Applications/Antigravity.app/Contents/Frameworks/Antigravity Helper.app/Contents/MacOS/Antigravity Helper"
    ));
}

#[test]
fn arguments_are_separate_items_and_the_address_is_the_gateways() {
    let args = open_args(
        Path::new("/Applications/Antigravity.app"),
        "127.0.0.1:9".parse().unwrap(),
    );
    assert_eq!(args.len(), 8);
    assert_eq!(args[3], "HTTPS_PROXY=http://127.0.0.1:9");
    assert_eq!(args[5], "HTTP_PROXY=http://127.0.0.1:9");
    // No argument carries more than one `--env` pair or a shell separator.
    assert!(
        args.iter().all(|a| !a.contains(';')
            && !a.contains('&')
            && !a.contains('|')
            && !a.contains(' '))
    );
}
