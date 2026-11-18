//! Process launcher seam and polite quit timing shared by `sysproxy` browser relaunch and
//! `commands::restart_app`.

use std::time::Duration;

/// How long an app gets to quit politely (the user may be answering a "save changes?" window).
pub const QUIT_TIMEOUT: Duration = Duration::from_secs(15);
/// How often the process list is polled while waiting for quit.
pub const QUIT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How long to wait for an application to quit (injectable so tests do not wait 15 s).
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

/// Runs a program with separate arguments (no shell). `None` means it could not be started.
pub trait AppLauncher: Send + Sync {
    fn run(&self, program: &str, args: &[String]) -> Option<RunResult>;
}

/// Production launcher; in OS dry-run mode `silent_command` starts nothing.
pub struct RealLauncher;

impl AppLauncher for RealLauncher {
    fn run(&self, program: &str, args: &[String]) -> Option<RunResult> {
        let out = super::silent_command(program).args(args).output().ok()?;
        Some(RunResult {
            success: out.status.success(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}
