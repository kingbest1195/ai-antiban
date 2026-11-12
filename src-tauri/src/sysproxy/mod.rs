//! System proxy and CLI/IDE protection.
//!
//! Layout: `platform` (the only code that talks to `networksetup` / `launchctl` / `reg` / `scutil`),
//! `journal` + `fs` (ownership journal: what Zastava changed and what was there before),
//! `macos` / `windows` (PAC, chained proxy and WinINet through the journal), `shell_rc`
//! (zsh/bash/PowerShell blocks), `ide` (editor settings.json), `ai_cli` (Claude Code / Gemini CLI
//! settings), `jsonc` (point editor for JSONC), `cli_protection` (enable/disable/status
//! orchestration), `cleanup` (exit guard, signals, restore of the journal, one-time legacy
//! migration).
//! Zastava restores only what it changed itself: every system setting and every key / block in a
//! user file goes through the journal. Files are reached through [`FileCtx`] (file system, home,
//! editor roots), runtime flags live in [`SysState`]; the no-argument public functions use the
//! process-wide instances of both.

mod ai_cli;
mod cleanup;
mod cli_protection;
pub mod fs;
mod ide;
pub mod journal;
mod jsonc;
mod macos;
pub mod platform;
mod shell_rc;
mod windows;

pub use cleanup::{
    cleaned_components, cleanup_all_persistent_settings, force_clean_all_os_proxy_traces,
    legacy_env_plan, legacy_env_plan_with_gateway, register_clean_exit_guard,
    spawn_signal_cleanup_watcher,
};
pub use cli_protection::{
    CliApplied, apply_cli_settings, disable_cli_and_ide_runtime_settings, disable_cli_protection,
    enable_cli_and_ide_protection, enable_cli_and_ide_protection_with, is_cli_protection_enabled,
    sync_ai_tz_active,
};
pub use ide::{candidate_ide_settings_paths, sanitize_jsonc};
pub use shell_rc::{
    build_powershell_guard_block_with_tz, build_shell_rc_guard_block,
    build_shell_rc_guard_block_with_tz, get_windows_powershell_profile_paths,
    remove_shell_rc_block, sanitize_timezone, upsert_powershell_profile_content_with_tz,
    upsert_shell_rc_content, upsert_shell_rc_content_with_tz,
};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Runtime state of the protection: what this process switched on. The durable facts (what was
/// changed and what was there before) are in the ownership journal, not here.
pub(crate) struct SysState {
    sys_proxy_active: AtomicBool,
    cli_protection_active: AtomicBool,
    last_pac_url: Mutex<Option<String>>,
    chained_proxy: Mutex<Option<String>>,
    /// Proxy address (`http://127.0.0.1:<port>`, port) written into the CLI / IDE files, `None`
    /// while the CLI / IDE protection is off.
    cli_proxy: Mutex<Option<(String, u16)>>,
    /// Time zone written into the CLI / IDE files, `None` while the time zone switch is off or no
    /// zone is known. Independent of `cli_proxy`.
    cli_tz: Mutex<Option<String>>,
    /// The CLI mode the files were last written for (`0` = `ai_only`, `1` = `global_terminal`).
    cli_mode: AtomicU8,
}

impl SysState {
    pub(crate) const fn new() -> Self {
        Self {
            sys_proxy_active: AtomicBool::new(false),
            cli_protection_active: AtomicBool::new(false),
            last_pac_url: Mutex::new(None),
            chained_proxy: Mutex::new(None),
            cli_proxy: Mutex::new(None),
            cli_tz: Mutex::new(None),
            cli_mode: AtomicU8::new(0),
        }
    }

    pub(crate) fn cli_proxy(&self) -> Option<(String, u16)> {
        self.cli_proxy.lock().ok().and_then(|g| g.clone())
    }

    pub(crate) fn set_cli_proxy(&self, proxy: Option<(String, u16)>) {
        if let Ok(mut g) = self.cli_proxy.lock() {
            *g = proxy;
        }
    }

    pub(crate) fn cli_tz(&self) -> Option<String> {
        self.cli_tz.lock().ok().and_then(|g| g.clone())
    }

    pub(crate) fn set_cli_tz(&self, tz: Option<String>) {
        if let Ok(mut g) = self.cli_tz.lock() {
            *g = tz;
        }
    }

    pub(crate) fn cli_mode(&self) -> crate::state::CliMode {
        match self.cli_mode.load(Ordering::SeqCst) {
            1 => crate::state::CliMode::GlobalTerminal,
            _ => crate::state::CliMode::AiOnly,
        }
    }

    pub(crate) fn set_cli_mode(&self, mode: crate::state::CliMode) {
        let v = match mode {
            crate::state::CliMode::AiOnly => 0,
            crate::state::CliMode::GlobalTerminal => 1,
        };
        self.cli_mode.store(v, Ordering::SeqCst);
    }

    pub(crate) fn sys_proxy_active(&self) -> bool {
        self.sys_proxy_active.load(Ordering::SeqCst)
    }

    pub(crate) fn set_sys_proxy_active(&self, on: bool) {
        self.sys_proxy_active.store(on, Ordering::SeqCst);
    }

    pub(crate) fn cli_protection_active(&self) -> bool {
        self.cli_protection_active.load(Ordering::SeqCst)
    }

    pub(crate) fn set_cli_protection_active(&self, on: bool) {
        self.cli_protection_active.store(on, Ordering::SeqCst);
    }

    pub(crate) fn last_pac_url(&self) -> Option<String> {
        self.last_pac_url.lock().ok().and_then(|g| g.clone())
    }

    pub(crate) fn set_last_pac_url(&self, url: Option<String>) {
        if let Ok(mut g) = self.last_pac_url.lock() {
            *g = url;
        }
    }

    /// Port of Zastava's own gateway, from the PAC URL last enabled.
    pub(crate) fn gateway_port(&self) -> Option<u16> {
        self.last_pac_url()
            .as_deref()
            .and_then(parse_gateway_port_from_pac_url)
    }

    pub(crate) fn chained_proxy(&self) -> Option<String> {
        self.chained_proxy.lock().ok().and_then(|g| g.clone())
    }

    /// Sets or clears the upstream proxy; Zastava's own gateway is refused (loop protection).
    pub(crate) fn set_chained_proxy(&self, proxy: Option<String>) {
        if let Some(ref p) = proxy
            && is_gateway_host_port(p, self.gateway_port())
        {
            return;
        }
        if let Ok(mut g) = self.chained_proxy.lock() {
            *g = proxy;
        }
    }

    /// Everything off: protection switched off, nothing remembered. The CLI mode is a setting,
    /// not a runtime fact, and stays.
    pub(crate) fn reset(&self) {
        self.set_sys_proxy_active(false);
        self.set_cli_protection_active(false);
        self.set_cli_proxy(None);
        self.set_cli_tz(None);
        self.set_last_pac_url(None);
        self.set_chained_proxy(None);
    }
}

static STATE: SysState = SysState::new();

/// The process-wide runtime state used by the no-argument public functions.
pub(crate) fn state() -> &'static SysState {
    &STATE
}

const ZASTAVA_RC_START: &str = "# >>> Zastava AI CLI & IDE Guard >>>";
const ZASTAVA_RC_END: &str = "# <<< Zastava AI CLI & IDE Guard <<<";
/// `NO_PROXY` Zastava writes: loopback, `.local` (Bonjour, AirPrint / IPP printers) and every
/// private range, so local-network traffic never goes through a proxy. One constant for every
/// place (shell profiles, IDE and agent `settings.json`, Windows environment, PAC bypass list).
/// Note: not every client understands CIDR (`10.0.0.0/8`); the ones that do not simply ignore it.
pub(crate) const NO_PROXY_VALUE: &str =
    "localhost,127.0.0.1,::1,.local,*.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16";

/// The `NO_PROXY` that Zastava 2.0.0 wrote. Still recognised as "ours", otherwise what 2.0.0
/// left in a profile, a settings file or the user environment would never be rolled back.
pub(crate) const NO_PROXY_VALUE_2_0: &str = "localhost,127.0.0.1,::1,.local";

/// Every `NO_PROXY` value a Zastava build ever wrote (old and new).
pub(crate) const KNOWN_NO_PROXY_VALUES: [&str; 2] = [NO_PROXY_VALUE, NO_PROXY_VALUE_2_0];

/// Whether `value` is a `NO_PROXY` written by some Zastava version.
pub(crate) fn is_known_no_proxy_value(value: &str) -> bool {
    let v = value.trim();
    KNOWN_NO_PROXY_VALUES.contains(&v)
}

/// Returns the currently discovered/configured upstream chained proxy (e.g. "127.0.0.1:10808"), if any.
pub fn get_chained_proxy() -> Option<String> {
    state().chained_proxy()
}

/// Sets or clears the upstream chained proxy with loop protection against Zastava's gateway.
pub fn set_chained_proxy(proxy: Option<String>) {
    state().set_chained_proxy(proxy);
}

/// Extracts gateway port from a PAC URL (e.g. "http://127.0.0.1:8899/proxy.pac" -> 8899).
pub fn parse_gateway_port_from_pac_url(pac_url: &str) -> Option<u16> {
    let without_scheme = pac_url
        .strip_prefix("http://")
        .or_else(|| pac_url.strip_prefix("https://"))
        .unwrap_or(pac_url);
    let host_port = without_scheme.split('/').next().unwrap_or("");
    host_port
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
}

/// Checks whether `server:port` points to Zastava's own gateway port or default loopback ports,
/// preventing recursive proxy loops.
pub fn is_gateway_target(server: &str, port: u16, gateway_port: Option<u16>) -> bool {
    if port == 0 {
        return true;
    }
    if gateway_port.is_some_and(|gp| gp > 0 && port == gp) {
        return true;
    }
    let s = server
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let is_loopback = s == "127.0.0.1" || s == "localhost" || s == "::1";
    if is_loopback && (port == 8899 || port == 8900) {
        return true;
    }
    false
}

/// Helper that checks `host:port` string against gateway loop.
pub fn is_gateway_host_port(host_port: &str, gateway_port: Option<u16>) -> bool {
    let trimmed = host_port.trim();
    if let Some((host, port_str)) = trimmed.rsplit_once(':') {
        match port_str.parse::<u16>() {
            Ok(port) => is_gateway_target(host, port, gateway_port),
            Err(_) => true,
        }
    } else {
        true
    }
}

/// Parses the output of macOS `networksetup -getwebproxy <service>` or `-getsecurewebproxy <service>`.
/// Returns `Some((server, port))` only when enabled is "Yes", server is non-empty, and port > 0.
pub fn parse_networksetup_webproxy_output(output: &str) -> Option<(String, u16)> {
    let mut enabled = false;
    let mut server = String::new();
    let mut port: u16 = 0;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "enabled" => {
                    enabled = val.eq_ignore_ascii_case("yes");
                }
                "server" => {
                    server = val.to_string();
                }
                "port" => {
                    port = val.parse::<u16>().unwrap_or(0);
                }
                _ => {}
            }
        }
    }

    if enabled && !server.is_empty() && port > 0 {
        Some((server, port))
    } else {
        None
    }
}

/// Parses Windows registry ProxyServer value into a `host:port` string.
/// Supports both plain format "127.0.0.1:10808" and protocol format "http=127.0.0.1:10808;https=127.0.0.1:10808".
/// Returns `None` if the proxy points to Zastava's gateway (loop prevention) or is invalid.
pub fn parse_windows_proxy_server(raw: &str, gateway_port: Option<u16>) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let candidate = if raw.contains('=') {
        let parts: Vec<&str> = raw
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let find_proto = |proto: &str| -> Option<&str> {
            parts.iter().find_map(|p| {
                let (k, v) = p.split_once('=')?;
                if k.trim().eq_ignore_ascii_case(proto) {
                    Some(v.trim())
                } else {
                    None
                }
            })
        };

        find_proto("https")
            .or_else(|| find_proto("http"))
            .or_else(|| find_proto("socks"))
            .or_else(|| {
                parts
                    .first()
                    .and_then(|p| p.split_once('=').map(|(_, v)| v.trim()).or(Some(p)))
            })
    } else {
        Some(raw)
    };

    let target = candidate?.trim();
    if target.is_empty() {
        return None;
    }

    let clean_target = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .or_else(|| target.strip_prefix("socks://"))
        .unwrap_or(target);

    let (host, port_str) = clean_target.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }

    let clean_host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if clean_host.is_empty() {
        return None;
    }

    if is_gateway_target(&clean_host, port, gateway_port) {
        return None;
    }

    Some(format!("{clean_host}:{port}"))
}

/// Parses a REG_DWORD integer value from Windows `reg query` output.
pub fn parse_reg_dword(output: &str, value_name: &str) -> Option<u32> {
    for line in output.lines() {
        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 3
            && parts[0].eq_ignore_ascii_case(value_name)
            && parts[1].eq_ignore_ascii_case("REG_DWORD")
        {
            let v = parts[2].trim_start_matches("0x").trim_start_matches("0X");
            return u32::from_str_radix(v, 16)
                .or_else(|_| parts[2].parse::<u32>())
                .ok();
        }
    }
    None
}

/// Parses a REG_SZ string value from Windows `reg query` output.
pub fn parse_reg_sz(output: &str, value_name: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2
            && parts[0].eq_ignore_ascii_case(value_name)
            && parts[1].eq_ignore_ascii_case("REG_SZ")
        {
            let idx = trimmed.find("REG_SZ")?;
            let rest = trimmed[idx + 6..].trim();
            return Some(rest.to_string());
        }
    }
    None
}

/// Environment variable that switches every OS side effect off (`1` or `true`).
pub const OS_DRY_RUN_ENV: &str = "ZASTAVA_OS_DRY_RUN";

static FORCE_DRY_RUN: AtomicBool = AtomicBool::new(false);
static DRY_RUN_BLOCKED: AtomicUsize = AtomicUsize::new(0);
static DRY_RUN_PROGRAMS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static DRY_RUN_HOME: OnceLock<PathBuf> = OnceLock::new();

/// Whether this process may touch the operating system (network services, launchd, registry,
/// the real home directory). Always `false` inside unit tests (`cfg!(test)`), after
/// [`force_os_dry_run`], or when `ZASTAVA_OS_DRY_RUN` is `1`/`true`.
pub fn os_effects_enabled() -> bool {
    if cfg!(test) || FORCE_DRY_RUN.load(Ordering::SeqCst) {
        return false;
    }
    !std::env::var(OS_DRY_RUN_ENV)
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// Switches the process into OS dry-run mode. Integration tests (`tests/*.rs`) link the library
/// without `cfg(test)`, so each of them calls this first (feature `test-support`).
#[cfg(any(test, feature = "test-support"))]
pub fn force_os_dry_run() {
    FORCE_DRY_RUN.store(true, Ordering::SeqCst);
}

/// Number of OS-facing commands that were replaced by a no-op because of dry-run mode.
pub fn dry_run_blocked_calls() -> usize {
    DRY_RUN_BLOCKED.load(Ordering::SeqCst)
}

/// Program names of the commands blocked so far in dry-run mode (diagnostics for tests).
pub fn dry_run_blocked_programs() -> Vec<String> {
    DRY_RUN_PROGRAMS
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default()
}

pub(crate) fn note_dry_run_blocked(what: &str) {
    DRY_RUN_BLOCKED.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut g) = DRY_RUN_PROGRAMS.lock()
        && g.len() < 512
    {
        g.push(what.to_string());
    }
}

/// Process-wide scratch directory that stands in for the user's home in dry-run mode.
fn dry_run_home_dir() -> PathBuf {
    DRY_RUN_HOME
        .get_or_init(|| {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "zastava-dry-run-home-{}-{nanos}",
                std::process::id()
            ));
            let _ = std::fs::create_dir_all(&dir);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            dir
        })
        .clone()
}

/// Bundle identifier of the app; the app data directory is `<OS data dir>/<identifier>`.
/// Must equal `identifier` in `tauri.conf.json` (checked by a unit test).
pub const APP_IDENTIFIER: &str = "io.zastava.desktop";

/// The directory Tauri's `app_data_dir()` resolves to, computed without an `AppHandle`
/// (needed by `--cleanup`). `None` when the OS data directory cannot be determined.
pub fn default_app_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Library").join("Application Support"));
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
        });
    base.map(|b| b.join(APP_IDENTIFIER))
}

/// What the platform side of an enable reports back.
#[derive(Debug, Default)]
pub(crate) struct EnableReport {
    /// Display names of the services (or the Windows store) that now carry the PAC.
    pub configured: Vec<String>,
    /// Something was written (not just verified).
    pub changed: bool,
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

fn data_dir() -> Option<PathBuf> {
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
    match journal::Journal::open(std::sync::Arc::new(fs::RealFs), dir) {
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
pub(super) fn real_user_env(name: &str) -> Option<String> {
    use platform::Platform;
    if !os_effects_enabled() {
        note_dry_run_blocked("user_env:get");
        return None;
    }
    platform::RealPlatform.get_user_env(name).ok().flatten()
}

/// Where the user's files are: the file system to use, the home directory and the roots under
/// which editors keep their per-user data (`<root>/<Editor>/User/settings.json`). Production code
/// builds it with [`FileCtx::real`]; tests hand in a `FakeFs` and a scratch home, so nothing in
/// the file layer reads `$HOME` / `%APPDATA%` on its own.
pub(crate) struct FileCtx {
    pub fs: Arc<dyn fs::Fs>,
    pub home: PathBuf,
    pub ide_roots: Vec<PathBuf>,
}

impl FileCtx {
    pub(crate) fn new(fs: Arc<dyn fs::Fs>, home: PathBuf, ide_roots: Vec<PathBuf>) -> Self {
        Self {
            fs,
            home,
            ide_roots,
        }
    }

    /// The real file system with the real per-user locations (the scratch home in dry-run).
    pub(crate) fn real() -> Option<Self> {
        Self::real_with_fs(Arc::new(fs::RealFs))
    }

    /// The real per-user locations on a given file system (the one the journal uses).
    pub(crate) fn real_with_fs(fs: Arc<dyn fs::Fs>) -> Option<Self> {
        let home = user_home_dir()?;
        #[cfg(target_os = "macos")]
        let roots = vec![home.join("Library").join("Application Support")];
        #[cfg(target_os = "windows")]
        let roots: Vec<PathBuf> = user_appdata_dir().into_iter().collect();
        #[cfg(all(unix, not(target_os = "macos")))]
        let roots = vec![home.join(".config")];
        Some(Self::new(fs, home, roots))
    }

    pub(crate) fn claude_settings(&self) -> PathBuf {
        self.home.join(".claude").join("settings.json")
    }

    pub(crate) fn gemini_settings(&self) -> PathBuf {
        self.home.join(".gemini").join("settings.json")
    }

    pub(crate) fn powershell_profiles(&self) -> Vec<PathBuf> {
        shell_rc::powershell_profile_paths(&self.home)
    }
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
fn journal_failure_text(e: &journal::JournalError) -> String {
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
    match with_journal_in(data_dir, "ownership_recovery", cleanup::restore_and_migrate) {
        Run::Blocked => Ok(journal::RecoveryReport {
            skipped_dry_run: true,
            ..Default::default()
        }),
        Run::Done(report) => Ok(report),
        Run::Failed(e) => Err(e),
    }
}

/// `--cleanup`: journal recovery, then the IDE/shell files. If the journal is unusable (corrupt,
/// unknown schema, locked by another instance) nothing is guessed and nothing is changed. Exit
/// codes: 0 ok, 1 some resources could not be restored (kept for retry), 2 fail-closed.
pub fn run_cleanup_cli() -> i32 {
    let Some(dir) = data_dir() else {
        eprintln!("Zastava --cleanup: data directory is unknown; nothing was changed");
        return 2;
    };
    match recover_ownership_on_start(&dir) {
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

/// Spawns a Command configured on Windows with `CREATE_NO_WINDOW` (0x08000000)
/// to completely prevent cmd.exe / PowerShell / Terminal console windows flashing.
/// In dry-run mode (see [`os_effects_enabled`]) the real program is never started: the command
/// becomes `true` (`cmd /c exit 0` on Windows) and the call is counted.
pub fn silent_command<S: AsRef<std::ffi::OsStr>>(program: S) -> std::process::Command {
    if !os_effects_enabled() {
        note_dry_run_blocked(&program.as_ref().to_string_lossy());
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            let mut cmd = std::process::Command::new("cmd");
            cmd.args(["/c", "exit", "0"])
                .creation_flags(CREATE_NO_WINDOW);
            return cmd;
        }
        #[cfg(not(target_os = "windows"))]
        return std::process::Command::new("true");
    }
    #[allow(unused_mut)]
    let mut cmd = std::process::Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysproxyStatus {
    pub enabled: bool,
    pub pac_url: Option<String>,
    pub services_configured: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliProtectionReport {
    /// `false` when nothing was switched on (e.g. the ownership journal could not be opened).
    pub enabled: bool,
    pub proxy_url: String,
    pub configured_targets: Vec<String>,
    pub shell_command: String,
    /// Notes for the user, Russian, no values (e.g. an old block that could not be removed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Why `enabled` is `false`, Russian, no values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Restores everything Zastava changed in the system (PAC, chained proxy, WinINet, user
/// environment) from the ownership journal and cleans the CLI/IDE files. Kept under its
/// historical name for existing callers; it is [`cleanup_all_persistent_settings`].
pub fn disable_all_sysproxy() {
    let _ = cleanup_all_persistent_settings();
}

/// Enables systemic PAC proxy with the given PAC URL (e.g. "http://127.0.0.1:8899/proxy.pac").
/// Every touched setting is recorded in the journal first; a refusal (temporary VPN DNS,
/// incompatible upstream, unusable journal) happens before any system write and returns the
/// Russian text for the user.
pub fn enable_sysproxy(pac_url: &str) -> Result<SysproxyStatus, String> {
    register_clean_exit_guard();

    let configured =
        match with_journal("enable_sysproxy", |j, p| enable_system_proxy(j, p, pac_url)) {
            Run::Blocked => Vec::new(),
            Run::Failed(e) => return Err(journal_failure_text(&e)),
            Run::Done(r) => r?.configured,
        };

    state().set_sys_proxy_active(true);
    state().set_last_pac_url(Some(pac_url.to_string()));

    Ok(SysproxyStatus {
        enabled: true,
        pac_url: Some(pac_url.to_string()),
        services_configured: configured,
    })
}

fn enable_system_proxy(
    j: &mut journal::Journal,
    p: &dyn platform::Platform,
    pac_url: &str,
) -> Result<EnableReport, String> {
    if cfg!(target_os = "macos") {
        macos::enable_pac(j, p, pac_url)
    } else if cfg!(target_os = "windows") {
        windows::enable_inet(j, p, pac_url)
    } else {
        Ok(EnableReport::default())
    }
}

/// Returns whether systemic PAC proxy is currently active.
pub fn is_sysproxy_active() -> bool {
    state().sys_proxy_active()
}

/// Re-applies the PAC configuration when a new network service appeared (e.g. a VPN client
/// added its own service) or when an external network tool / OS sleep-wake cycle disabled
/// or overwrote the PAC on a service (self-healing). A foreign value found there is adopted as
/// the baseline to restore, never lost. Returns `true` when something was re-applied.
pub fn refresh_if_services_changed() -> bool {
    if !is_sysproxy_active() {
        return false;
    }
    let Some(pac) = state().last_pac_url() else {
        return false;
    };
    match with_journal("refresh_sysproxy", |j, p| enable_system_proxy(j, p, &pac)) {
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

pub struct SysProxy;

impl SysProxy {
    pub fn enable(pac_url: &str) -> Result<SysproxyStatus, String> {
        enable_sysproxy(pac_url)
    }

    pub fn disable() {
        let _ = cleanup_all_persistent_settings();
    }

    pub fn is_active() -> bool {
        is_sysproxy_active()
    }
}

pub(super) fn user_home_dir() -> Option<PathBuf> {
    if !os_effects_enabled() {
        return Some(dry_run_home_dir());
    }
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
}

/// `%APPDATA%`; inside the dry-run home in dry-run mode so tests never see real editor settings.
#[cfg(target_os = "windows")]
pub(super) fn user_appdata_dir() -> Option<PathBuf> {
    if !os_effects_enabled() {
        return Some(dry_run_home_dir().join("AppData").join("Roaming"));
    }
    std::env::var_os("APPDATA").map(PathBuf::from)
}

/// Spawns the native OS date and time settings panel.
pub fn open_os_datetime_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        silent_command("open")
            .arg("x-apple.systempreferences:com.apple.preference.datetime")
            .spawn()
            .map_err(|e| format!("Failed to open macOS date & time settings: {e}"))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        silent_command("cmd")
            .args(["/C", "start", "ms-settings:dateandtime"])
            .spawn()
            .map_err(|e| format!("Failed to open Windows date & time settings: {e}"))?;
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_covers_loopback_bonjour_and_every_private_range() {
        assert_eq!(
            NO_PROXY_VALUE,
            "localhost,127.0.0.1,::1,.local,*.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
        );
        let items: Vec<&str> = NO_PROXY_VALUE.split(',').collect();
        for must in [
            "localhost",
            "127.0.0.1",
            "::1",
            ".local",
            "*.local",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
        ] {
            assert!(items.contains(&must), "{must}");
        }
    }

    #[test]
    fn both_generations_of_no_proxy_are_known_and_nothing_else() {
        assert!(is_known_no_proxy_value(NO_PROXY_VALUE));
        assert!(is_known_no_proxy_value(NO_PROXY_VALUE_2_0));
        assert!(is_known_no_proxy_value(
            "  localhost,127.0.0.1,::1,.local \n"
        ));
        assert_eq!(NO_PROXY_VALUE_2_0, "localhost,127.0.0.1,::1,.local");
        assert!(!is_known_no_proxy_value("localhost,corp.example"));
        assert!(!is_known_no_proxy_value(""));
    }

    #[test]
    fn app_identifier_matches_tauri_conf() {
        let conf = include_str!("../../tauri.conf.json");
        assert!(conf.contains(&format!("\"identifier\": \"{APP_IDENTIFIER}\"")));
    }

    #[test]
    fn recovery_entry_point_is_a_no_op_in_dry_run() {
        let before = dry_run_blocked_calls();
        let dir = std::env::temp_dir().join("zastava-never-created-by-dry-run");
        let r = recover_ownership_on_start(&dir).unwrap();
        assert!(r.skipped_dry_run && r.items.is_empty());
        assert!(
            !dir.exists(),
            "dry-run recovery must not even create the directory"
        );
        assert!(dry_run_blocked_calls() > before);
    }

    #[test]
    fn enable_in_dry_run_changes_no_system_setting_and_reports_no_service() {
        let before = dry_run_blocked_calls();
        let st = enable_sysproxy("http://127.0.0.1:8899/proxy.pac").unwrap();
        assert!(st.enabled && st.services_configured.is_empty());
        assert!(is_sysproxy_active());
        assert!(!refresh_if_services_changed(), "nothing to heal in dry-run");
        assert!(dry_run_blocked_calls() > before);
        let _ = cleanup_all_persistent_settings();
        assert!(!is_sysproxy_active());
    }

    #[test]
    fn journal_failure_texts_are_russian_and_carry_no_values() {
        use journal::JournalError as E;
        for e in [
            E::Locked,
            E::Corrupt,
            E::UnknownSchema(7),
            E::Io("write", std::io::ErrorKind::PermissionDenied),
            E::KindMismatch,
        ] {
            let t = journal_failure_text(&e);
            assert!(t.starts_with("Защита не включена"), "{t}");
            assert!(t.contains("Системные настройки не менялись"));
        }
    }

    #[test]
    fn dry_run_is_always_on_in_unit_tests() {
        assert!(!os_effects_enabled());
    }

    #[test]
    fn dry_run_silent_command_never_starts_the_requested_program() {
        let before = dry_run_blocked_calls();
        let marker = "zastava-definitely-not-a-real-program";
        // A real spawn of this name would fail with NotFound; the no-op replacement succeeds.
        let status = silent_command(marker)
            .arg("--whatever")
            .status()
            .expect("no-op spawn");
        assert!(status.success());
        assert!(dry_run_blocked_calls() > before);
        assert!(dry_run_blocked_programs().iter().any(|p| p == marker));
    }

    #[test]
    fn dry_run_home_is_a_scratch_dir_not_the_real_home() {
        let home = user_home_dir().expect("dry-run home");
        assert!(home.is_dir());
        assert!(home.starts_with(std::env::temp_dir()));
        assert_eq!(
            user_home_dir(),
            Some(home),
            "the dry-run home is stable per process"
        );
    }

    #[test]
    fn dry_run_cli_protection_changes_no_file_and_reports_no_target() {
        let before = dry_run_blocked_calls();
        let report = enable_cli_and_ide_protection("127.0.0.1:8899");
        assert!(report.enabled);
        assert!(
            report.configured_targets.is_empty(),
            "nothing is written in dry-run, so nothing is configured"
        );
        // The journal gate blocked the file layer: the scratch home stays empty.
        let home = user_home_dir().unwrap();
        assert!(!home.join(".zshrc").exists());
        assert!(!home.join(".claude").exists());
        assert!(dry_run_blocked_calls() > before);
        // No `launchctl setenv` for the GUI session, with or without a timezone sync.
        let with_tz = enable_cli_and_ide_protection_with(
            "127.0.0.1:8899",
            crate::state::CliMode::AiOnly,
            Some("Europe/Berlin"),
        );
        assert!(with_tz.enabled);
        assert!(
            !dry_run_blocked_programs()
                .iter()
                .any(|w| w.contains("launchctl") || w.contains("user_env")),
            "the GUI session stays clean: {:?}",
            dry_run_blocked_programs()
        );
        let report = disable_cli_protection();
        assert!(report.skipped_dry_run || !report.has_failures());
        assert!(!state().cli_protection_active());
        state().set_cli_tz(None);
    }

    #[test]
    fn test_parse_networksetup_webproxy_output() {
        let active_output =
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 10808\nAuthenticated Proxy Enabled: 0\n";
        let parsed = parse_networksetup_webproxy_output(active_output);
        assert_eq!(parsed, Some(("127.0.0.1".to_string(), 10808)));

        // Test loop prevention on Zastava's gateway
        assert!(!is_gateway_target("127.0.0.1", 10808, Some(8899)));
        assert!(is_gateway_target("127.0.0.1", 8899, Some(8899)));
        assert!(is_gateway_target("localhost", 8899, None));
        assert!(is_gateway_target("127.0.0.1", 8900, None));
        assert!(is_gateway_target("127.0.0.1", 0, None));

        let disabled_output = "Enabled: No\nServer: amrika-panel.nomadnocode.com\nPort: 11443\nAuthenticated Proxy Enabled: 0\n";
        assert_eq!(parse_networksetup_webproxy_output(disabled_output), None);

        let empty_output = "";
        assert_eq!(parse_networksetup_webproxy_output(empty_output), None);
    }

    #[test]
    fn test_parse_windows_proxy_server_and_loop_prevention() {
        // Plain format
        assert_eq!(
            parse_windows_proxy_server("127.0.0.1:10808", Some(8899)),
            Some("127.0.0.1:10808".to_string())
        );

        // Protocol formats
        assert_eq!(
            parse_windows_proxy_server("http=127.0.0.1:10808;https=127.0.0.1:10808", Some(8899)),
            Some("127.0.0.1:10808".to_string())
        );
        assert_eq!(
            parse_windows_proxy_server("http=127.0.0.1:10808;https=127.0.0.1:2080", Some(8899)),
            Some("127.0.0.1:2080".to_string())
        );
        assert_eq!(
            parse_windows_proxy_server("socks=127.0.0.1:10808", Some(8899)),
            Some("127.0.0.1:10808".to_string())
        );

        // Loop prevention: Zastava's active gateway port or default ports
        assert_eq!(
            parse_windows_proxy_server("127.0.0.1:8899", Some(8899)),
            None
        );
        assert_eq!(
            parse_windows_proxy_server("http=127.0.0.1:8899;https=127.0.0.1:8899", Some(8899)),
            None
        );
        assert_eq!(parse_windows_proxy_server("localhost:8900", None), None);
        assert_eq!(parse_windows_proxy_server("", Some(8899)), None);
    }

    #[test]
    fn test_parse_reg_dword_and_sz() {
        let dword_sample = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\n    ProxyEnable    REG_DWORD    0x1\n";
        assert_eq!(parse_reg_dword(dword_sample, "ProxyEnable"), Some(1));

        let sz_sample = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\n    ProxyServer    REG_SZ    http=127.0.0.1:10808;https=127.0.0.1:10808\n";
        assert_eq!(
            parse_reg_sz(sz_sample, "ProxyServer"),
            Some("http=127.0.0.1:10808;https=127.0.0.1:10808".to_string())
        );
    }

    #[test]
    fn test_get_set_chained_proxy_loop_guard() {
        // A context of its own: no other test can change it.
        let st = SysState::new();
        st.set_chained_proxy(Some("127.0.0.1:10808".to_string()));
        assert_eq!(st.chained_proxy(), Some("127.0.0.1:10808".to_string()));

        // Setting Zastava default port should be rejected by loop guard
        st.set_chained_proxy(Some("127.0.0.1:8899".to_string()));
        assert_eq!(st.chained_proxy(), Some("127.0.0.1:10808".to_string()));

        // The gateway port of the PAC last enabled is refused too.
        st.set_last_pac_url(Some("http://127.0.0.1:9123/proxy.pac".to_string()));
        assert_eq!(st.gateway_port(), Some(9123));
        st.set_chained_proxy(Some("127.0.0.1:9123".to_string()));
        assert_eq!(st.chained_proxy(), Some("127.0.0.1:10808".to_string()));

        st.set_chained_proxy(None);
        assert_eq!(st.chained_proxy(), None);
    }

    #[test]
    fn sys_state_instances_are_independent_and_reset_clears_everything() {
        let a = SysState::new();
        let b = SysState::new();
        a.set_sys_proxy_active(true);
        a.set_cli_protection_active(true);
        a.set_last_pac_url(Some("http://127.0.0.1:8899/proxy.pac".into()));
        a.set_chained_proxy(Some("127.0.0.1:10808".into()));
        assert!(!b.sys_proxy_active() && !b.cli_protection_active());
        assert_eq!(b.last_pac_url(), None);
        a.reset();
        assert!(!a.sys_proxy_active() && !a.cli_protection_active());
        assert_eq!((a.last_pac_url(), a.chained_proxy()), (None, None));
    }

    #[test]
    fn file_context_is_built_from_what_it_is_given_not_from_the_environment() {
        let fs = fs::FakeFs::new();
        let ctx = FileCtx::new(
            Arc::new(fs),
            PathBuf::from("/h"),
            vec![PathBuf::from("/h/root")],
        );
        assert_eq!(
            ctx.claude_settings(),
            PathBuf::from("/h/.claude/settings.json")
        );
        assert_eq!(
            ctx.gemini_settings(),
            PathBuf::from("/h/.gemini/settings.json")
        );
        assert!(
            ctx.powershell_profiles()
                .iter()
                .all(|p| p.starts_with("/h/Documents"))
        );
    }

    #[test]
    fn test_parse_gateway_port_from_pac_url() {
        assert_eq!(
            parse_gateway_port_from_pac_url("http://127.0.0.1:8899/proxy.pac"),
            Some(8899)
        );
        assert_eq!(
            parse_gateway_port_from_pac_url("http://127.0.0.1:8900/pac.js"),
            Some(8900)
        );
        assert_eq!(
            parse_gateway_port_from_pac_url("127.0.0.1:8899"),
            Some(8899)
        );
    }
}
