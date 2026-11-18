use super::fs;
use super::parsing::{is_gateway_host_port, parse_gateway_port_from_pac_url};
use super::shell_rc;
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

pub(crate) const ZASTAVA_RC_START: &str = "# >>> Zastava AI CLI & IDE Guard >>>";
pub(crate) const ZASTAVA_RC_END: &str = "# <<< Zastava AI CLI & IDE Guard <<<";
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


/// Environment variable that switches every OS side effect off (`1` or `true`).
pub const OS_DRY_RUN_ENV: &str = "ZASTAVA_OS_DRY_RUN";

static FORCE_DRY_RUN: AtomicBool = AtomicBool::new(false);
static DRY_RUN_BLOCKED: AtomicUsize = AtomicUsize::new(0);
static DRY_RUN_PROGRAMS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static DRY_RUN_HOME: OnceLock<PathBuf> = OnceLock::new();

/// Whether this process may touch the operating system (network services, launchd, registry,
/// the real home directory). Default-deny in every test build: always `false` inside unit tests
/// (`cfg!(test)`) and in integration tests (`tests/*.rs` link the library with the `test-support`
/// feature), whether or not a test remembered to call [`force_os_dry_run`]. In a normal build it
/// is `false` after [`force_os_dry_run`] or when `ZASTAVA_OS_DRY_RUN` is `1`/`true`.
pub fn os_effects_enabled() -> bool {
    if cfg!(any(test, feature = "test-support")) || FORCE_DRY_RUN.load(Ordering::SeqCst) {
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


/// Where the user's files are: the file system to use, the home directory and the roots under
/// which editors keep their per-user data (`<root>/<Editor>/User/settings.json`). Production code
/// builds it with [`FileCtx::real`]; tests hand in a `FakeFs` and a scratch home, so nothing in
/// the file layer reads `$HOME` / `%APPDATA%` on its own.
pub(crate) struct FileCtx {
    pub fs: Arc<dyn fs::Fs>,
    pub home: PathBuf,
    pub ide_roots: Vec<PathBuf>,
    #[cfg(test)]
    pub local_appdata: PathBuf,
}

impl FileCtx {
    pub(crate) fn new(fs: Arc<dyn fs::Fs>, home: PathBuf, ide_roots: Vec<PathBuf>) -> Self {
        #[cfg(test)]
        let local_appdata = home.join("AppData").join("Local");
        Self {
            fs,
            home,
            ide_roots,
            #[cfg(test)]
            local_appdata,
        }
    }

    #[cfg(all(test, target_os = "windows"))]
    fn with_local_appdata(mut self, local_appdata: PathBuf) -> Self {
        self.local_appdata = local_appdata;
        self
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
        let ctx = Self::new(fs, home, roots);
        #[cfg(all(test, target_os = "windows"))]
        let ctx = if let Some(local) = std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
        {
            ctx.with_local_appdata(local)
        } else {
            ctx
        };
        Some(ctx)
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


pub(crate) fn user_home_dir() -> Option<PathBuf> {
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
pub(crate) fn user_appdata_dir() -> Option<PathBuf> {
    if !os_effects_enabled() {
        return Some(dry_run_home_dir().join("AppData").join("Roaming"));
    }
    std::env::var_os("APPDATA").map(PathBuf::from)
}

