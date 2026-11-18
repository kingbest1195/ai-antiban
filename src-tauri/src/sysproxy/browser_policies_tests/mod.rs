use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::journal::{EntryState, recover_with};
use crate::sysproxy::platform::FakePlatform;
use std::path::Path;

use std::sync::{Arc, Mutex};

pub(super) const DIR: &str = "/data";


pub(super) struct StubProbe {
    outputs: Mutex<Vec<Option<String>>>,
    fallback: Mutex<Option<String>>,
}

impl StubProbe {
    pub(super) fn fixed(output: Option<&str>) -> Self {
        Self {
            outputs: Mutex::new(Vec::new()),
            fallback: Mutex::new(output.map(str::to_string)),
        }
    }

    pub(super) fn sequence(seq: Vec<Option<&str>>) -> Self {
        Self {
            outputs: Mutex::new(seq.into_iter().map(|s| s.map(str::to_string)).collect()),
            fallback: Mutex::new(None),
        }
    }
}

impl SystemProbe for StubProbe {
    fn run(&self, _program: &str, _args: &[&str]) -> Option<String> {
        let mut q = self.outputs.lock().unwrap();
        if !q.is_empty() {
            return q.remove(0);
        }
        self.fallback.lock().unwrap().clone()
    }
}

#[derive(Default)]
pub(super) struct StubLauncher {
    pub(super) calls: Mutex<Vec<(String, Vec<String>)>>,
    pub(super) fail_open: bool,
    pub(super) permission_denied: bool,
}

impl AppLauncher for StubLauncher {
    fn run(
        &self,
        program: &str,
        args: &[String],
    ) -> Option<crate::sysproxy::relaunch::RunResult> {
        self.calls
            .lock()
            .unwrap()
            .push((program.to_string(), args.to_vec()));
        if program == "osascript" && self.permission_denied {
            return Some(crate::sysproxy::relaunch::RunResult {
                success: false,
                stderr: "execution error: Not authorized to send Apple events (-1743)".into(),
            });
        }
        if program == "open" && self.fail_open {
            return Some(crate::sysproxy::relaunch::RunResult {
                success: false,
                stderr: "LSOpenURLsWithRole failed".into(),
            });
        }
        Some(crate::sysproxy::relaunch::RunResult {
            success: true,
            stderr: String::new(),
        })
    }
}

pub(super) fn test_ctx(fs: &Arc<FakeFs>) -> FileCtx {
    let home = PathBuf::from("/Users/tester");
    FileCtx::new(
        fs.clone(),
        home.clone(),
        vec![home.join("Library/Application Support")],
    )
}

pub(super) fn put_prefs(fs: &FakeFs, path: &Path, json: &str) {
    fs.put(path, json.as_bytes(), 0o600);
}

pub(super) fn read_json(fs: &FakeFs, path: &Path) -> serde_json::Value {
    let bytes = fs.read(path).unwrap().unwrap();
    serde_json::from_slice(&bytes).unwrap()
}


mod policy_tests;
mod prefs_tests;
mod windows_tests;
