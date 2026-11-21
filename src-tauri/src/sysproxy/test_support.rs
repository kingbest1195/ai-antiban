#![cfg(any(test, feature = "test-support"))]

use super::browser_policies::{self, FakePolicyStore, PolicyApplyReport};
use super::fs::Fs;
use super::journal::{Journal, JournalError};
use super::macos::{self, HEAL_WINDOW, HealGuard};
use super::platform::Platform;
use super::state::state;
use super::windows;
use super::{EnableReport, FileCtx, Os, SystemProbe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

struct EmptyProcessProbe;

impl SystemProbe for EmptyProcessProbe {
    fn run(&self, _program: &str, _args: &[&str]) -> Option<String> {
        Some(String::new())
    }
}

pub const HEAL_WINDOW_SECS: u64 = HEAL_WINDOW.as_secs();

pub struct TestHealGuard(HealGuard);

impl Default for TestHealGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl TestHealGuard {
    pub fn new() -> Self {
        Self(HealGuard::new())
    }

    pub fn reset(&self) {
        self.0.reset();
    }

    pub fn is_suspended_at(&self, key: &str, now: Instant) -> bool {
        self.0.is_suspended_at(key, now)
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestEnableReport {
    pub configured: Vec<String>,
    pub changed: bool,
    pub skipped_vpn: Vec<String>,
    pub os_pac_deferred: bool,
}

impl From<EnableReport> for TestEnableReport {
    fn from(r: EnableReport) -> Self {
        Self {
            configured: r.configured,
            changed: r.changed,
            skipped_vpn: r.skipped_vpn,
            os_pac_deferred: r.os_pac_deferred,
        }
    }
}

/// Runs macOS PAC enable against a [`Platform`] (e.g. `FakePlatform`) and updates `os_pac_deferred`.
pub fn enable_macos_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
) -> Result<TestEnableReport, String> {
    let r = macos::enable_pac(j, p, pac_url)?;
    state().set_os_pac_deferred(r.os_pac_deferred);
    state().set_sys_proxy_active(true);
    state().set_last_pac_url(Some(pac_url.to_string()));
    Ok(r.into())
}

/// Runs macOS PAC self-heal refresh against a [`Platform`] with explicit `TestHealGuard` & clock.
pub fn refresh_macos_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: &TestHealGuard,
    now: Instant,
) -> Result<TestEnableReport, String> {
    let r = macos::refresh_pac(j, p, pac_url, &heal.0, now)?;
    state().set_os_pac_deferred(r.os_pac_deferred);
    Ok(r.into())
}

/// Runs Windows WinINet PAC enable/refresh against a [`Platform`] with optional `TestHealGuard`.
pub fn enable_windows_inet(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: Option<(&TestHealGuard, Instant)>,
) -> Result<TestEnableReport, String> {
    let r = windows::enable_inet_with_heal(j, p, pac_url, heal.map(|(g, t)| (&g.0, t)))?;
    state().set_os_pac_deferred(r.os_pac_deferred);
    state().set_sys_proxy_active(true);
    state().set_last_pac_url(Some(pac_url.to_string()));
    Ok(r.into())
}

/// Applies browser policies using the journal's policy store for the specified target OS.
pub fn apply_browser_policies_for_os(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: Option<&str>,
    is_macos: bool,
) -> PolicyApplyReport {
    let os = if is_macos { Os::Macos } else { Os::Windows };
    let file_ctx = FileCtx::new(j.fs(), PathBuf::from("/fake-home"), Vec::new());
    let rep = browser_policies::apply_browser_policies_with_pac_in(
        j,
        p,
        pac_url,
        Some(&file_ctx),
        os,
        &EmptyProcessProbe,
    );
    state().set_browser_pac_policy_active(rep.pac_policy_active);
    rep
}

/// Resets global sysproxy protection flags in tests.
pub fn reset_sysproxy_state_for_test() {
    state().reset();
}

/// Opens a [`Journal`] backed by an in-memory [`FakePolicyStore`] for deterministic E2E tests.
pub fn open_journal_with_fake_policies(
    fs: Arc<dyn Fs>,
    data_dir: &Path,
) -> Result<Journal, JournalError> {
    Ok(Journal::open(fs, data_dir)?.with_policy_store(FakePolicyStore::new()))
}
