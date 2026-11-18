//! OS / process-probe seam shared by `sysproxy` and `proxy::coverage`.

/// Runs a system program and returns its stdout when it exited successfully.
pub trait SystemProbe: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> Option<String>;
}

/// The real thing: starts the program (nothing is started in OS dry-run mode).
pub struct RealProbe;

impl SystemProbe for RealProbe {
    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        let output = crate::sysproxy::silent_command(program)
            .args(args)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Which OS tools to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Macos,
    Windows,
    Linux,
}

impl Os {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Os::Macos
        } else if cfg!(target_os = "windows") {
            Os::Windows
        } else {
            Os::Linux
        }
    }
}
