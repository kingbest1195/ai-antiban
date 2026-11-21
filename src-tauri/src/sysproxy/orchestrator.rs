use super::browser_policies::{self, PolicyApplyReport};
use super::cleanup;
use super::fs;
use super::journal;
use super::macos;
use super::platform;
use super::state::{
    APP_IDENTIFIER, FileCtx, SysState, default_app_data_dir, note_dry_run_blocked,
    os_effects_enabled, state,
};
use super::windows;
use super::{SysproxyStatus, register_clean_exit_guard};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// What the platform side of an enable reports back.
#[derive(Debug, Default)]
pub(crate) struct EnableReport {
    /// Display names of the services (or the Windows store) that now carry the PAC.
    pub configured: Vec<String>,
    /// Something was written (not just verified).
    pub changed: bool,
    /// Connected (or unclassifiable) VPN services that were left alone, by display name.
    pub skipped_vpn: Vec<String>,
    /// macOS `networksetup` PAC writes were skipped because temporary VPN DNS overrides are
    /// present (or DNS state could not be verified); browser policies and CLI protection still ran.
    pub os_pac_deferred: bool,
}

/// Outcome of a journal-backed operation against the real OS.
pub(crate) enum Run<T> {
    /// OS dry-run mode: nothing was examined or written.
    Blocked,
    Done(T),
    /// The journal could not be opened (locked, corrupt, unknown schema, no data directory).
    /// Fail closed: the OS was not touched.
    Failed(journal::JournalError),
}

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
/// Serialises journal-backed operations inside this process (the journal lock is per process).
static OS_OPS: Mutex<()> = Mutex::new(());

/// Pins the app data directory the journal lives in (the one Tauri resolved at start).
pub fn set_data_dir(dir: PathBuf) {
    let _ = DATA_DIR.set(dir);
}

/// Where the journal and its locks live. Windows: `%LOCALAPPDATA%\<identifier>`, not the roaming
/// `%APPDATA%` (the journal holds values that must not follow the user to other machines, and
/// the local profile is private by default). Everywhere else: the app data directory itself.
/// A journal still in the old place is carried over on open ([`journal::Journal::open_migrating`]).
pub(crate) fn journal_base_dir(app_data: &std::path::Path) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        local_journal_base(
            std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
            app_data,
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        app_data.to_path_buf()
    }
}

/// The Windows rule of [`journal_base_dir`] without the environment (testable on any OS).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn local_journal_base(
    local_app_data: Option<PathBuf>,
    app_data: &std::path::Path,
) -> PathBuf {
    match local_app_data.filter(|p| !p.as_os_str().is_empty()) {
        Some(local) => local.join(APP_IDENTIFIER),
        None => app_data.to_path_buf(),
    }
}

pub(super) fn data_dir() -> Option<PathBuf> {
    DATA_DIR.get().cloned().or_else(default_app_data_dir)
}

/// Runs `f` on the journal in `dir` with the real OS behind it. The one place where the journal
/// meets the real file system and the real platform; dry-run is checked first.
fn with_journal_in<T>(
    dir: &std::path::Path,
    what: &str,
    f: impl FnOnce(&mut journal::Journal, &dyn platform::Platform) -> T,
) -> Run<T> {
    if !os_effects_enabled() {
        note_dry_run_blocked(what);
        return Run::Blocked;
    }
    let _guard = OS_OPS.lock().unwrap_or_else(|e| e.into_inner());
    let base = journal_base_dir(dir);
    match journal::Journal::open_migrating(std::sync::Arc::new(fs::RealFs), &base, Some(dir)) {
        Ok(mut j) => Run::Done(f(&mut j, &platform::RealPlatform)),
        Err(e) => Run::Failed(e),
    }
}

pub(crate) fn with_journal<T>(
    what: &str,
    f: impl FnOnce(&mut journal::Journal, &dyn platform::Platform) -> T,
) -> Run<T> {
    if !os_effects_enabled() {
        note_dry_run_blocked(what);
        return Run::Blocked;
    }
    match data_dir() {
        Some(dir) => with_journal_in(&dir, what, f),
        None => Run::Failed(journal::JournalError::Io(
            "data_dir",
            std::io::ErrorKind::NotFound,
        )),
    }
}

/// A user environment value read through the real platform (Windows registry), `None` in dry-run.
#[cfg(target_os = "windows")]
pub(crate) fn real_user_env(name: &str) -> Option<String> {
    use platform::Platform;
    if !os_effects_enabled() {
        note_dry_run_blocked("user_env:get");
        return None;
    }
    platform::RealPlatform.get_user_env(name).ok().flatten()
}

/// Runs `f` on the journal and the user's files (real home). Same gates as [`with_journal`].
pub(crate) fn with_files<T>(
    what: &str,
    f: impl FnOnce(&mut journal::Journal, &dyn platform::Platform, &FileCtx) -> T,
) -> Run<T> {
    let mut f = Some(f);
    let r = with_journal(what, |j, p| {
        let ctx = FileCtx::real_with_fs(j.fs())?;
        f.take().map(|f| f(j, p, &ctx))
    });
    match r {
        Run::Blocked => Run::Blocked,
        Run::Failed(e) => Run::Failed(e),
        Run::Done(Some(v)) => Run::Done(v),
        Run::Done(None) => Run::Failed(journal::JournalError::Io(
            "home_dir",
            std::io::ErrorKind::NotFound,
        )),
    }
}

/// Russian text for the toast when the journal blocks an enable. Contains no values.
pub(crate) fn journal_failure_text(e: &journal::JournalError) -> String {
    let why = match e {
        journal::JournalError::Locked => "журнал настроек занят другим экземпляром Заставы",
        journal::JournalError::Corrupt | journal::JournalError::UnknownSchema(_) => {
            "журнал настроек повреждён или создан более новой версией Заставы"
        }
        journal::JournalError::Io(..) | journal::JournalError::Platform(_) => {
            "не удалось открыть журнал настроек"
        }
        journal::JournalError::KindMismatch => "внутренняя ошибка журнала настроек",
    };
    format!("Защита не включена: {why}. Системные настройки не менялись.")
}

/// Recovery pass of the ownership journal: puts back what Zastava changed in a previous run and
/// nothing else, then runs the one-time legacy migration. Runs before protection is enabled and
/// from `--cleanup`.
/// Fail closed: a corrupt/unknown journal or a lock held by another process is an `Err` and no
/// OS call is made. In OS dry-run mode nothing is examined.
pub fn recover_ownership_on_start(
    data_dir: &std::path::Path,
) -> Result<journal::RecoveryReport, journal::JournalError> {
    if os_effects_enabled() {
        hold_app_lock(&fs::RealFs, &journal_base_dir(data_dir))?;
    }
    // The app enables the protection right after this: a leftover PAC on a physical service is
    // adopted by that pass instead of being cleared and written again.
    recover_in_mode(data_dir, true)
}

pub(super) fn recover_in(
    data_dir: &std::path::Path,
) -> Result<journal::RecoveryReport, journal::JournalError> {
    recover_in_mode(data_dir, false)
}

fn recover_in_mode(
    data_dir: &std::path::Path,
    at_app_start: bool,
) -> Result<journal::RecoveryReport, journal::JournalError> {
    match with_journal_in(data_dir, "ownership_recovery", |j, p| {
        cleanup::restore_and_migrate_with(j, p, at_app_start)
    }) {
        Run::Blocked => Ok(journal::RecoveryReport {
            skipped_dry_run: true,
            ..Default::default()
        }),
        Run::Done(report) => Ok(report),
        Run::Failed(e) => Err(e),
    }
}

/// The app lock of this process (held until it exits; the OS drops it with the process).
static APP_LOCK: Mutex<Option<fs::FsLock>> = Mutex::new(None);

/// Takes the lock that marks "a Zastava is running on this data directory" and keeps it for the
/// life of the process. Unlike the journal lock (held for one operation) it is long-lived, so a
/// `--cleanup` started while the app runs can tell and leaves the app's PAC alone. A second call
/// in the same process does nothing. `Locked` when another process holds it.
pub(crate) fn hold_app_lock(
    fs: &dyn fs::Fs,
    data_dir: &std::path::Path,
) -> Result<(), journal::JournalError> {
    let mut slot = APP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        return Ok(());
    }
    *slot = Some(take_app_lock(fs, data_dir)?);
    Ok(())
}

pub(super) fn take_app_lock(
    fs: &dyn fs::Fs,
    data_dir: &std::path::Path,
) -> Result<fs::FsLock, journal::JournalError> {
    fs.create_private_dir_all(&journal::ownership_dir(data_dir))
        .map_err(|e| journal::JournalError::Io("create_dir", e.kind()))?;
    fs.try_lock(&journal::app_lock_path(data_dir))
        .map_err(|e| match e {
            fs::LockError::Held => journal::JournalError::Locked,
            fs::LockError::Io(k) => journal::JournalError::Io("app_lock", k),
        })
}

/// What `--cleanup` may do on `data_dir`: `Ok(Some(lock))` - no app is running, go on (the lock
/// keeps an app from starting in the middle of it); `Ok(None)` - a running app holds the app lock
/// and restores its own settings, so nothing is touched.
pub(crate) fn cleanup_cli_gate(
    fs: &dyn fs::Fs,
    data_dir: &std::path::Path,
) -> Result<Option<fs::FsLock>, journal::JournalError> {
    match take_app_lock(fs, data_dir) {
        Ok(lock) => Ok(Some(lock)),
        Err(journal::JournalError::Locked) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `--cleanup`: journal recovery, then the IDE/shell files. If the journal is unusable (corrupt,
/// unknown schema, locked by another instance) nothing is guessed and nothing is changed. A
/// running app (it holds the app lock) is left alone: exit 0, nothing written. Exit codes: 0 ok
/// (or the app is running), 1 some resources could not be restored (kept for retry), 2
/// fail-closed. The uninstaller repeats the call on a non-zero code for about ten seconds, so no
/// retry loop lives here.
pub fn run_cleanup_cli() -> i32 {
    let Some(dir) = data_dir() else {
        eprintln!("Zastava --cleanup: data directory is unknown; nothing was changed");
        return 2;
    };
    // Held until this function returns.
    let _app_guard = if os_effects_enabled() {
        match cleanup_cli_gate(&fs::RealFs, &journal_base_dir(&dir)) {
            Ok(guard) if guard.is_some() => guard,
            Ok(_) => {
                eprintln!(
                    "Zastava --cleanup: the app is running and restores its own settings; nothing was changed"
                );
                return 0;
            }
            Err(e) => {
                eprintln!("Zastava --cleanup: {e}; nothing was changed");
                return 2;
            }
        }
    } else {
        None
    };
    match recover_in(&dir) {
        Err(e) => {
            eprintln!("Zastava --cleanup: {e}; nothing was changed");
            2
        }
        Ok(report) => {
            eprintln!("Zastava --cleanup: {}", report.summary());
            let files = cleanup::cleanup_cli_files();
            i32::from(report.has_failures() || files.has_failures())
        }
    }
}

/// Enables systemic PAC proxy with the given PAC URL (e.g. "http://127.0.0.1:8899/proxy.pac").
/// Every touched setting is recorded in the journal first; when a VPN holds temporary DNS on
/// macOS, `networksetup` PAC writes are gracefully deferred (`os_pac_deferred = true`) while
/// browser PAC policies still apply. Incompatible upstreams or unusable journals fail closed
/// before any write and return Russian text for the user.
pub fn enable_sysproxy(pac_url: &str) -> Result<SysproxyStatus, String> {
    enable_sysproxy_inner(pac_url, false)
}

/// Enables the system PAC proxy using macOS administrator privileges (`osascript`) when
/// `enable_sysproxy` previously failed with `ADMIN_AUTH_REQUIRED:`. On non-macOS systems this is
/// equivalent to [`enable_sysproxy`].
pub fn enable_sysproxy_privileged(pac_url: &str) -> Result<SysproxyStatus, String> {
    enable_sysproxy_inner(pac_url, true)
}

fn enable_sysproxy_inner(pac_url: &str, privileged: bool) -> Result<SysproxyStatus, String> {
    register_clean_exit_guard();

    let (configured, vpn_untouched, os_pac_deferred) =
        match with_journal("enable_sysproxy", |j, p| {
            enable_with_mode(state(), j, p, pac_url, privileged)
        }) {
            Run::Blocked => {
                // Dry-run: nothing was written, the flags still follow the call.
                mark_active(state(), pac_url);
                (Vec::new(), Vec::new(), false)
            }
            Run::Failed(e) => return Err(journal_failure_text(&e)),
            Run::Done(r) => {
                let r = r?;
                (r.configured, r.skipped_vpn, r.os_pac_deferred)
            }
        };

    Ok(SysproxyStatus {
        enabled: true,
        pac_url: Some(pac_url.to_string()),
        services_configured: configured,
        vpn_untouched,
        os_pac_deferred,
    })
}

fn mark_active(st: &SysState, pac_url: &str) {
    st.set_sys_proxy_active(true);
    st.set_last_pac_url(Some(pac_url.to_string()));
}

/// The enable pass, run inside the `OS_OPS` lock. The "PAC is on" flag is raised here, after the
/// write and under the same lock, so a switch-off that runs next ([`restore_pass`]) cannot be
/// overtaken by a late `set_sys_proxy_active(true)`.
#[cfg(test)]
pub(super) fn enable_with(
    st: &SysState,
    j: &mut journal::Journal,
    p: &dyn platform::Platform,
    pac_url: &str,
) -> Result<EnableReport, String> {
    enable_with_mode(st, j, p, pac_url, false)
}

fn enable_with_mode(
    st: &SysState,
    j: &mut journal::Journal,
    p: &dyn platform::Platform,
    pac_url: &str,
    privileged: bool,
) -> Result<EnableReport, String> {
    let report = if privileged {
        if cfg!(target_os = "macos") {
            HEAL.reset();
            macos::enable_pac_privileged(j, p, pac_url)?
        } else {
            enable_system_proxy(j, p, pac_url, false)?
        }
    } else {
        enable_system_proxy(j, p, pac_url, false)?
    };
    let policy_rep = browser_policies::apply_browser_policies_with_pac(j, p, Some(pac_url));
    st.set_os_pac_deferred(report.os_pac_deferred);
    st.set_browser_pac_policy_active(policy_rep.pac_policy_active);
    mark_active(st, pac_url);
    Ok(report)
}

/// Re-applies and verifies browser policies (QUIC, DoH, and PAC URL) through the ownership
/// journal without re-running `networksetup` (useful when a VPN overrides `scutil --proxy`).
pub fn reapply_browser_policies(pac_url: Option<&str>) -> Result<PolicyApplyReport, String> {
    let resolved_pac = pac_url
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_string)
        .or_else(|| state().last_pac_url());
    match with_journal("reapply_browser_policies", |j, p| {
        browser_policies::apply_browser_policies_with_pac(j, p, resolved_pac.as_deref())
    }) {
        Run::Blocked => Ok(PolicyApplyReport::default()),
        Run::Failed(e) => Err(journal_failure_text(&e)),
        Run::Done(rep) => Ok(rep),
    }
}

/// The refresh pass, run inside the `OS_OPS` lock. The flag is read here, under the lock: a
/// switch-off that already cleared it (before its restore) wins, and the PAC is not put back.
pub(super) fn refresh_with(
    st: &SysState,
    j: &mut journal::Journal,
    p: &dyn platform::Platform,
) -> Result<EnableReport, String> {
    if !st.sys_proxy_active() {
        return Ok(EnableReport::default());
    }
    let Some(pac) = st.last_pac_url() else {
        return Ok(EnableReport::default());
    };
    let report = enable_system_proxy(j, p, &pac, true)?;
    let policy_rep = browser_policies::apply_browser_policies_with_pac(j, p, Some(&pac));
    st.set_os_pac_deferred(report.os_pac_deferred);
    st.set_browser_pac_policy_active(policy_rep.pac_policy_active);
    Ok(report)
}

/// Switch-off pass, run inside the `OS_OPS` lock: the flag goes down BEFORE anything is restored,
/// so a refresh that was waiting for the lock sees "off" and leaves the PAC alone.
pub(crate) fn restore_pass(
    st: &SysState,
    j: &mut journal::Journal,
    p: &dyn platform::Platform,
    restore: impl FnOnce(&mut journal::Journal, &dyn platform::Platform) -> journal::RecoveryReport,
) -> journal::RecoveryReport {
    st.set_sys_proxy_active(false);
    st.set_os_pac_deferred(false);
    st.set_browser_pac_policy_active(false);
    restore(j, p)
}

/// Self-heal bookkeeping of the macOS PAC (which service something else keeps rewriting).
static HEAL: macos::HealGuard = macos::HealGuard::new();
/// Self-heal bookkeeping of Windows WinINet (`AutoConfigURL` / `ProxyEnable` overrides).
static WIN_HEAL: macos::HealGuard = macos::HealGuard::new();

fn enable_system_proxy(
    j: &mut journal::Journal,
    p: &dyn platform::Platform,
    pac_url: &str,
    self_heal: bool,
) -> Result<EnableReport, String> {
    if cfg!(target_os = "macos") {
        if self_heal {
            macos::refresh_pac(j, p, pac_url, &HEAL, std::time::Instant::now())
        } else {
            HEAL.reset(); // an explicit enable starts a fresh account
            macos::enable_pac(j, p, pac_url)
        }
    } else if cfg!(target_os = "windows") {
        if self_heal {
            let heal = Some((&WIN_HEAL, std::time::Instant::now()));
            windows::enable_inet_with_heal(j, p, pac_url, heal)
        } else {
            WIN_HEAL.reset();
            windows::enable_inet(j, p, pac_url)
        }
    } else {
        Ok(EnableReport::default())
    }
}

/// Returns whether systemic PAC proxy is currently active.
pub fn is_sysproxy_active() -> bool {
    state().sys_proxy_active()
}

/// Returns whether OS PAC writes were deferred due to temporary VPN DNS (`os_pac_deferred`).
pub fn is_os_pac_deferred() -> bool {
    state().os_pac_deferred()
}

/// Returns whether Chromium managed PAC policies are active for the current session.
pub fn is_browser_pac_policy_active() -> bool {
    state().browser_pac_policy_active()
}

/// Re-applies the PAC configuration when a new network service appeared (e.g. a VPN client
/// added its own service) or when an external network tool / OS sleep-wake cycle disabled
/// or overwrote the PAC on a service (self-healing). A foreign value found there is adopted as
/// the baseline to restore, never lost. Returns `true` when something was re-applied.
pub fn refresh_if_services_changed() -> bool {
    // Cheap early exit; the real decision is taken again under the lock (`refresh_with`).
    if !is_sysproxy_active() {
        return false;
    }
    match with_journal("refresh_sysproxy", |j, p| refresh_with(state(), j, p)) {
        Run::Done(Ok(report)) => report.changed,
        Run::Done(Err(e)) => {
            // Same refusal as at enable (e.g. temporary VPN DNS): nothing was written. Say it once.
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::SeqCst) {
                eprintln!("Застава: {e}");
            }
            false
        }
        Run::Failed(_) | Run::Blocked => false,
    }
}
