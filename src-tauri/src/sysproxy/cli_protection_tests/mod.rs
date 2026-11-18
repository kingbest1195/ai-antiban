//! The file side on `FakeFs`: no test reads or writes a real home directory.
use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::platform::FakePlatform;
use crate::sysproxy::shell_rc::build_shell_rc_guard_block_with_tz;
use std::path::PathBuf;
use std::sync::Arc;


pub(super) const URL: &str = "http://127.0.0.1:8899";
pub(super) const HOME: &str = "/home/u";
pub(super) const ROOT: &str = "/home/u/AppSup";
pub(super) const IDE_DIR: &str = "/home/u/AppSup/Code/User";
pub(super) const IDE_FILE: &str = "/home/u/AppSup/Code/User/settings.json";

pub(super) struct Env {
    fs: FakeFs,
    p: FakePlatform,
    ctx: FileCtx,
}

pub(super) fn env() -> Env {
    let fs = FakeFs::new();
    fs.create_private_dir_all(Path::new(HOME)).unwrap();
    let ctx = FileCtx::new(
        Arc::new(fs.clone()),
        PathBuf::from(HOME),
        vec![PathBuf::from(ROOT)],
    );
    Env {
        fs,
        p: FakePlatform::new(),
        ctx,
    }
}

impl Env {
    pub(super) fn journal(&self) -> Journal {
        Journal::open(Arc::new(self.fs.clone()), Path::new("/data")).unwrap()
    }
    /// Proxy protection on, `global_terminal` (the shell profiles are written), Unix.
    pub(super) fn enable(&self, tz: Option<&str>) -> Vec<String> {
        self.apply(Some(URL), tz, CliMode::GlobalTerminal, HostOs::Unix)
            .targets
    }
    pub(super) fn apply(
        &self,
        proxy: Option<&str>,
        tz: Option<&str>,
        mode: CliMode,
        os: HostOs,
    ) -> FilesApplied {
        let mut j = self.journal();
        let plan = FilePlan {
            proxy_url: proxy,
            port: 8899,
            tz,
            mode,
            os,
            strip_unjournaled_blocks: false,
        };
        apply_files(&mut j, &self.p, &self.ctx, &plan)
    }
    pub(super) fn disable(&self) -> RecoveryReport {
        let mut j = self.journal();
        disable_files(&mut j, &self.p, Some(&self.ctx), CliMode::GlobalTerminal)
    }
    /// An installed editor: its `User` directory exists, the settings file holds `text`.
    pub(super) fn ide_with(&self, text: &str, mode: u32) -> PathBuf {
        self.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
        self.fs.put(Path::new(IDE_FILE), text.as_bytes(), mode);
        PathBuf::from(IDE_FILE)
    }
    pub(super) fn text(&self, p: &Path) -> String {
        String::from_utf8(self.fs.get(p).unwrap()).unwrap()
    }
    /// Edits the file as the user's editor would: same permissions, new content.
    pub(super) fn user_writes(&self, p: &Path, text: &str) {
        let mode = self.fs.mode(p).unwrap().unwrap();
        self.fs.put(p, text.as_bytes(), mode);
    }
    pub(super) fn journal_is_empty(&self) -> bool {
        self.journal().is_empty()
    }
}

pub(super) fn raw(text: &str, path: &[&str]) -> Option<String> {
    jsonc::get(text, path).unwrap().map(|f| f.raw.to_string())
}

pub(super) const COMMENTED: &str = "\u{feff}{\r\n\t// my theme\r\n\t\"workbench.colorTheme\": \"Default Dark+\",\r\n\t\"editor.fontSize\": 14 /* px */\r\n}\r\n";


pub(super) const ZONE: &str = "Europe/Berlin";
pub(super) const USER_ZSHRC: &str = "export PATH=\"$HOME/bin:$PATH\"\nalias g=git\n";

pub(super) fn json_of(e: &Env, file: &Path) -> String {
    e.fs.get(file)
        .map(|b| String::from_utf8(b).unwrap())
        .unwrap_or_else(|| "{}".to_string())
}

/// The block of 2.0.0: both parts, `LC_ALL` and the short `NO_PROXY`.
pub(super) fn block_2_0_0() -> String {
    build_shell_rc_guard_block_with_tz(URL, 8899, Some(ZONE))
        .replace(
            "  export LC_TIME=\"en_US.UTF-8\"",
            "  export LC_TIME=\"en_US.UTF-8\"\n  export LC_ALL=\"en_US.UTF-8\"",
        )
        .replace(NO_PROXY_VALUE, crate::sysproxy::NO_PROXY_VALUE_2_0)
}

pub(super) fn with_block(user: &str, block: &str) -> String {
    crate::sysproxy::shell_rc::upsert_block(user, block).unwrap()
}

pub(super) fn shell_block() -> String {
    build_shell_rc_guard_block_with_tz(URL, 8899, None)
}


mod ide_tests;
mod shell_tests;
mod mode_tests;
mod signature_tests;
