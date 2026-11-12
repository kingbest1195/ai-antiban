//! Application network coverage and incoming socket process auditing.
//!
//! A status is never guessed from an in-memory flag:
//! * `confirmed`  - the app made an AI request through the gateway within [`CONFIRM_TTL_MS`];
//! * `configured` - a fact read from the system says so (the PAC the OS hands out equals ours,
//!   `http.proxy` in the editor's `settings.json` points at the gateway port);
//! * `off`        - the fact was read and it says "not configured";
//! * `unknown`    - the app is there but there is nothing reliable to read (or reading failed);
//! * `not_installed`.
//!
//! Everything that touches the OS (`lsof` / `netstat` / `tasklist` / `ss`, `Platform`, files)
//! goes through a seam, so the tests feed canned output and fakes instead of starting processes.

use crate::state::CliMode;
use crate::sysproxy::FileCtx;
use crate::sysproxy::fs::Fs;
use crate::sysproxy::platform::{Platform, PlatformError, ServiceKind, classify_services};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A confirmation by live traffic is valid for 30 minutes.
pub const CONFIRM_TTL_MS: u64 = 30 * 60 * 1000;
/// Configuration facts read from the OS / files are reused for this long (a forced re-check
/// bypasses it).
const FACTS_TTL_MS: u64 = 5_000;
/// `peer_port -> process` answers are reused for this long.
const LOOKUP_CACHE_TTL_MS: u64 = 15_000;
/// A failed lookup is remembered for this long (no retry storm for the same port).
const LOOKUP_NEGATIVE_TTL_MS: u64 = 5_000;
/// At most [`LOOKUP_RATE_MAX`] process lookups per [`LOOKUP_RATE_WINDOW_MS`]; the rest is
/// attributed by User-Agent only.
const LOOKUP_RATE_WINDOW_MS: u64 = 1_000;
const LOOKUP_RATE_MAX: usize = 8;
/// Upper bound of remembered ports (cache never grows without limit).
const LOOKUP_CACHE_MAX: usize = 1024;

/// Whether the format of the JetBrains `options/proxy.settings.xml` has been confirmed on a real
/// machine. While `false`, JetBrains is always `unknown` with manual steps.
pub const JETBRAINS_XML_CONFIRMED: bool = false;

/// Keys of manual steps handed to the UI (the texts live on the front end).
pub mod steps {
    /// Enable Zastava protection with its own button.
    pub const ENABLE_PROTECTION: &str = "enable_protection";
    /// Put `http://<gateway_addr>` into the application's HTTP proxy setting.
    pub const SET_HTTP_PROXY: &str = "set_http_proxy";
    /// Put the PAC address (`pac_url`) into the application's / system proxy setting.
    pub const SET_PAC_URL: &str = "set_pac_url";
    /// Set `HTTPS_PROXY` / `HTTP_PROXY` environment variables to `http://<gateway_addr>`.
    pub const SET_ENV_PROXY: &str = "set_env_proxy";
    /// Restart the application so that it picks the setting up.
    pub const RESTART_APP: &str = "restart_app";
    /// Open a new terminal window (already running ones keep their old environment).
    pub const REOPEN_TERMINAL: &str = "reopen_terminal";
    /// Open Settings -> HTTP Proxy in a JetBrains IDE.
    pub const JETBRAINS_PROXY_SETTINGS: &str = "jetbrains_proxy_settings";
}

/// Protection status of an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Confirmed,
    Configured,
    Unknown,
    Off,
    NotInstalled,
}

/// Individual application status within Zastava network protection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppCoverageItem {
    pub id: String,
    pub name: String,
    pub category: String, // "browser" | "desktop" | "ide" | "cli"
    pub installed: bool,
    pub status: CoverageStatus,
    /// Same as `ai_requests` (kept for the old front end).
    pub requests_seen: u64,
    /// AI requests through the gateway since Zastava started.
    pub ai_requests: u64,
    /// How many times the app fetched `/proxy.pac`.
    pub pac_fetches: u64,
    /// Unix time (ms) of the last AI request through the gateway.
    pub last_seen_ms: Option<u64>,
    /// Keys of manual steps (see [`steps`]); empty when nothing has to be done.
    pub manual_steps: Vec<String>,
    pub detail: String,
}

/// Comprehensive snapshot of application protection coverage and proxy chaining.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSnapshot {
    pub sysproxy_enabled: bool,
    pub cli_protection_enabled: bool,
    /// How command-line tools are covered: `"ai_only"` (only Claude Code, Gemini CLI and the
    /// editors; `node` / `python` / `curl` are not covered) or `"global_terminal"` (the shell
    /// profiles carry the proxy too).
    pub cli_mode: CliMode,
    pub chained_proxy: Option<String>,
    /// Real address of the gateway (`127.0.0.1:<port>`).
    pub gateway_addr: Option<String>,
    /// `http://<gateway_addr>/proxy.pac`.
    pub pac_url: Option<String>,
    pub generated_at_ms: u64,
    pub apps: Vec<AppCoverageItem>,
    /// Does the system actually hand our PAC to applications (`scutil --proxy`)? `None` while the
    /// protection is off, on systems without this check, or when it could not be read. `false`
    /// with the PAC written on the physical services means something (a VPN) overrides it.
    #[serde(default)]
    pub system_proxy_effective: Option<bool>,
    /// Enabled VPN services that are connected right now. Zastava never writes into them.
    #[serde(default)]
    pub vpn_connected: Vec<String>,
}

/// What kind of connection reached the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficKind {
    /// A tunnel request to an AI host.
    AiRequest,
    /// `GET /proxy.pac`.
    PacFetch,
    /// Transit traffic to a non-AI host: never inspected, never counted.
    Direct,
}

#[derive(Debug, Clone)]
struct AppTrafficStats {
    ai_requests: u64,
    pac_fetches: u64,
    last_seen_ms: u64,
    detected_name: String,
    category: String,
}

// ---------------------------------------------------------------------------------------------
// OS seam
// ---------------------------------------------------------------------------------------------

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

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    })
}

// ---------------------------------------------------------------------------------------------
// Tracker
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct LookupState {
    /// `peer_port -> (process or None for "not found", time of the answer)`.
    cache: HashMap<u16, (Option<String>, u64)>,
    inflight: HashSet<u16>,
    recent: VecDeque<u64>,
}

/// Live process accounting engine tracking incoming local gateway sockets.
pub struct CoverageTracker {
    stats: Mutex<HashMap<String, AppTrafficStats>>,
    lookups: Mutex<LookupState>,
    gateway: Mutex<Option<SocketAddr>>,
    facts: Mutex<Option<(u64, ConfigFacts)>>,
    /// The CLI mode the facts are computed for (see [`CoverageSnapshot::cli_mode`]).
    cli_mode: Mutex<CliMode>,
    clock: Clock,
    probe: Arc<dyn SystemProbe>,
    os: Os,
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// What must happen after the cheap part of an incoming connection was handled.
enum Step {
    Done,
    Lookup,
}

impl CoverageTracker {
    pub fn new() -> Self {
        Self::with_parts(system_clock(), Arc::new(RealProbe), Os::current())
    }

    /// A tracker with its own clock (Unix ms), OS probe and OS flavour (tests).
    pub fn with_parts(clock: Clock, probe: Arc<dyn SystemProbe>, os: Os) -> Self {
        Self {
            stats: Mutex::new(HashMap::new()),
            lookups: Mutex::new(LookupState::default()),
            gateway: Mutex::new(None),
            facts: Mutex::new(None),
            cli_mode: Mutex::new(CliMode::default()),
            clock,
            probe,
            os,
        }
    }

    fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    /// The address the gateway really listens on.
    pub fn set_gateway_addr(&self, addr: SocketAddr) {
        if let Ok(mut g) = self.gateway.lock() {
            *g = Some(addr);
        }
        if let Ok(mut f) = self.facts.lock() {
            *f = None;
        }
    }

    pub fn gateway_addr(&self) -> Option<SocketAddr> {
        self.gateway.lock().ok().and_then(|g| *g)
    }

    /// Tells the tracker how command-line tools are covered right now; a change drops the cached
    /// facts so the next snapshot reads them again.
    pub fn set_cli_mode(&self, mode: CliMode) {
        let changed = match self.cli_mode.lock() {
            Ok(mut g) => {
                let changed = *g != mode;
                *g = mode;
                changed
            }
            Err(_) => false,
        };
        if changed && let Ok(mut f) = self.facts.lock() {
            *f = None;
        }
    }

    pub fn cli_mode(&self) -> CliMode {
        self.cli_mode.lock().map(|g| *g).unwrap_or_default()
    }

    /// Records an incoming connection from `peer_port`. Never blocks the tunnel: the OS lookup
    /// (when needed at all) runs on the blocking pool.
    ///
    /// [`TrafficKind::Direct`] is ignored: transit traffic to non-AI hosts must not cost a single
    /// process lookup.
    pub fn record_incoming(
        self: &Arc<Self>,
        peer_port: u16,
        user_agent: Option<String>,
        kind: TrafficKind,
    ) {
        if let Step::Lookup = self.prepare(peer_port, user_agent.as_deref(), kind) {
            let tracker = Arc::clone(self);
            tokio::task::spawn_blocking(move || {
                tracker.run_lookup(peer_port, user_agent.as_deref(), kind);
            });
        }
    }

    /// Same as [`Self::record_incoming`] but the lookup (if any) runs on the calling thread.
    pub fn record_incoming_blocking(
        &self,
        peer_port: u16,
        user_agent: Option<&str>,
        kind: TrafficKind,
    ) {
        if let Step::Lookup = self.prepare(peer_port, user_agent, kind) {
            self.run_lookup(peer_port, user_agent, kind);
        }
    }

    /// Cheap part: cache, User-Agent, debounce and rate limit. Decides whether an OS lookup is due.
    fn prepare(&self, peer_port: u16, user_agent: Option<&str>, kind: TrafficKind) -> Step {
        if kind == TrafficKind::Direct {
            return Step::Done;
        }
        let now = self.now_ms();

        // 1. Recent answer for this port (found or not found).
        let cached = self.lookups.lock().ok().and_then(|l| {
            l.cache.get(&peer_port).and_then(|(name, at)| {
                let ttl = if name.is_some() {
                    LOOKUP_CACHE_TTL_MS
                } else {
                    LOOKUP_NEGATIVE_TTL_MS
                };
                (now.saturating_sub(*at) < ttl).then(|| name.clone())
            })
        });
        if let Some(answer) = cached {
            match answer {
                Some(name) => self.record(kind, &name, user_agent),
                None => self.record_by_user_agent(kind, user_agent),
            }
            return Step::Done;
        }

        // 2. The User-Agent names the client directly.
        if let Some(ua) = user_agent
            && let Some(name) = identify_by_user_agent(ua)
        {
            self.cache_answer(peer_port, Some(name.to_string()), now);
            self.record(kind, name, user_agent);
            return Step::Done;
        }

        // 3. Debounce and rate limit: a lookup for this port is already running / too many
        //    lookups lately -> no new process, attribute by User-Agent only.
        let Ok(mut l) = self.lookups.lock() else {
            return Step::Done;
        };
        if l.inflight.contains(&peer_port) {
            return Step::Done;
        }
        while let Some(front) = l.recent.front() {
            if now.saturating_sub(*front) >= LOOKUP_RATE_WINDOW_MS {
                l.recent.pop_front();
            } else {
                break;
            }
        }
        if l.recent.len() >= LOOKUP_RATE_MAX {
            drop(l);
            self.record_by_user_agent(kind, user_agent);
            return Step::Done;
        }
        l.recent.push_back(now);
        l.inflight.insert(peer_port);
        Step::Lookup
    }

    fn run_lookup(&self, peer_port: u16, user_agent: Option<&str>, kind: TrafficKind) {
        let found = lookup_process_with(&*self.probe, self.os, peer_port, std::process::id());
        let now = self.now_ms();
        if let Ok(mut l) = self.lookups.lock() {
            l.inflight.remove(&peer_port);
        }
        self.cache_answer(peer_port, found.clone(), now);
        match found {
            Some(name) => self.record(kind, &name, user_agent),
            None => self.record_by_user_agent(kind, user_agent),
        }
    }

    fn cache_answer(&self, port: u16, name: Option<String>, now: u64) {
        if let Ok(mut l) = self.lookups.lock() {
            if l.cache.len() >= LOOKUP_CACHE_MAX {
                l.cache
                    .retain(|_, (_, at)| now.saturating_sub(*at) < LOOKUP_CACHE_TTL_MS);
                if l.cache.len() >= LOOKUP_CACHE_MAX {
                    l.cache.clear();
                }
            }
            l.cache.insert(port, (name, now));
        }
    }

    fn record_by_user_agent(&self, kind: TrafficKind, user_agent: Option<&str>) {
        if let Some(ua) = user_agent {
            self.record(kind, ua, None);
        }
    }

    /// Records one AI request from a discovered process name or user-agent.
    pub fn record_hit(&self, raw_process_name: &str, user_agent: Option<&str>) {
        self.record(TrafficKind::AiRequest, raw_process_name, user_agent);
    }

    fn record(&self, kind: TrafficKind, raw_process_name: &str, user_agent: Option<&str>) {
        if kind == TrafficKind::Direct {
            return;
        }
        let (id, display_name, category) = resolve_app_identity(raw_process_name, user_agent);
        let now_ms = self.now_ms();
        let Ok(mut lock) = self.stats.lock() else {
            return;
        };
        match kind {
            TrafficKind::AiRequest => {
                let entry = lock.entry(id).or_insert_with(|| AppTrafficStats {
                    ai_requests: 0,
                    pac_fetches: 0,
                    last_seen_ms: now_ms,
                    detected_name: display_name,
                    category,
                });
                entry.ai_requests = entry.ai_requests.saturating_add(1);
                entry.last_seen_ms = now_ms;
            }
            TrafficKind::PacFetch => {
                // A PAC fetch only counts for apps of the catalog: it must not create an entry
                // for the system's own PAC helper.
                if get_known_app_info(&id).is_none() {
                    return;
                }
                let entry = lock.entry(id).or_insert_with(|| AppTrafficStats {
                    ai_requests: 0,
                    pac_fetches: 0,
                    last_seen_ms: 0,
                    detected_name: display_name,
                    category,
                });
                entry.pac_fetches = entry.pac_fetches.saturating_add(1);
            }
            TrafficKind::Direct => {}
        }
    }

    /// Builds the snapshot. `force` ignores the cache of configuration facts (re-reads the OS
    /// and the files right now).
    pub(crate) fn snapshot(&self, env: &CoverageEnv<'_>, force: bool) -> CoverageSnapshot {
        let now = self.now_ms();
        let gateway = self.gateway_addr();
        let cli_mode = self.cli_mode();

        let facts = {
            let mut guard = self.facts.lock().unwrap_or_else(|e| e.into_inner());
            let fresh = match &*guard {
                Some((at, f)) => {
                    !force && now.saturating_sub(*at) < FACTS_TTL_MS && f.gateway == gateway
                }
                None => false,
            };
            if !fresh {
                *guard = Some((now, compute_config_facts(env, gateway, cli_mode)));
            }
            guard.as_ref().map(|(_, f)| f.clone()).unwrap_or_default()
        };

        let stats_map = self.stats.lock().map(|l| l.clone()).unwrap_or_default();
        let mut apps = Vec::new();

        for app_id in KNOWN_IDS {
            let info = get_known_app_info(app_id).unwrap_or(KnownAppInfo {
                id: app_id,
                name: app_id,
                category: "desktop",
            });
            let traffic = stats_map.get(app_id);
            let ai_requests = traffic.map(|t| t.ai_requests).unwrap_or(0);
            let pac_fetches = traffic.map(|t| t.pac_fetches).unwrap_or(0);
            let last_seen_ms = traffic
                .filter(|t| t.ai_requests > 0)
                .map(|t| t.last_seen_ms);
            let fact = facts.apps.get(app_id);
            let installed = fact.map(|f| f.installed).unwrap_or(false) || ai_requests > 0;
            let fresh = last_seen_ms.is_some_and(|t| now.saturating_sub(t) < CONFIRM_TTL_MS);

            let (status, manual_steps, detail) = if fresh {
                (
                    CoverageStatus::Confirmed,
                    Vec::new(),
                    format!("Подтверждено трафиком ({} запр.)", ai_requests),
                )
            } else if !installed {
                (
                    CoverageStatus::NotInstalled,
                    Vec::new(),
                    "Не установлено".to_string(),
                )
            } else if let Some(f) = fact.filter(|f| f.installed) {
                (f.status, f.manual_steps.clone(), f.detail.clone())
            } else {
                // Seen on traffic earlier, but nothing to read now.
                (
                    CoverageStatus::Unknown,
                    Vec::new(),
                    "Подтверждение устарело".to_string(),
                )
            };

            apps.push(AppCoverageItem {
                id: info.id.to_string(),
                name: info.name.to_string(),
                category: info.category.to_string(),
                installed,
                status,
                requests_seen: ai_requests,
                ai_requests,
                pac_fetches,
                last_seen_ms,
                manual_steps,
                detail,
            });
        }

        // Processes seen on AI traffic that are not in the catalog.
        let mut dynamic: Vec<_> = stats_map
            .iter()
            .filter(|(id, t)| !KNOWN_IDS.contains(&id.as_str()) && t.ai_requests > 0)
            .collect();
        dynamic.sort_by(|a, b| a.0.cmp(b.0));
        for (id, t) in dynamic {
            let fresh = now.saturating_sub(t.last_seen_ms) < CONFIRM_TTL_MS;
            apps.push(AppCoverageItem {
                id: id.clone(),
                name: t.detected_name.clone(),
                category: t.category.clone(),
                installed: true,
                status: if fresh {
                    CoverageStatus::Confirmed
                } else {
                    CoverageStatus::Unknown
                },
                requests_seen: t.ai_requests,
                ai_requests: t.ai_requests,
                pac_fetches: t.pac_fetches,
                last_seen_ms: Some(t.last_seen_ms),
                manual_steps: Vec::new(),
                detail: format!("Подтверждено трафиком ({} запр.)", t.ai_requests),
            });
        }

        CoverageSnapshot {
            sysproxy_enabled: env.sysproxy_enabled,
            cli_protection_enabled: env.cli_protection_enabled,
            cli_mode,
            chained_proxy: env.chained_proxy.clone(),
            gateway_addr: facts.gateway.map(|g| g.to_string()),
            pac_url: facts.gateway.map(pac_url_for),
            generated_at_ms: now,
            apps,
            system_proxy_effective: if env.sysproxy_enabled {
                facts.system_proxy_effective
            } else {
                None
            },
            vpn_connected: facts.vpn_connected.clone(),
        }
    }
}

const KNOWN_IDS: [&str; 13] = [
    "browsers",
    "claude-desktop",
    "chatgpt-desktop",
    "antigravity",
    "cursor",
    "vscode",
    "windsurf",
    "jetbrains",
    "claude-code",
    "gemini-cli",
    "node-cli",
    "python-cli",
    "curl",
];

/// The PAC address the gateway serves.
pub fn pac_url_for(addr: SocketAddr) -> String {
    format!("http://{addr}/proxy.pac")
}

fn identify_by_user_agent(ua: &str) -> Option<&'static str> {
    let ua_lower = ua.to_lowercase();
    if ua_lower.starts_with("curl/") {
        return Some("curl");
    }
    if ua_lower.contains("claude-code") || ua_lower.contains("claude_code") {
        return Some("claude-code");
    }
    if ua_lower.contains("python-requests") || ua_lower.contains("aiohttp") {
        return Some("python");
    }
    if ua_lower.contains("node-fetch") || ua_lower.contains("undici") {
        return Some("node");
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Configuration facts
// ---------------------------------------------------------------------------------------------

/// How the PAC is read from the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacSource {
    /// Per network service (`networksetup -getautoproxyurl`), macOS.
    Services,
    /// WinINet `AutoConfigURL`, Windows.
    Inet,
}

impl PacSource {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            PacSource::Inet
        } else {
            PacSource::Services
        }
    }
}

/// Everything the status computation reads from outside.
pub(crate) struct CoverageEnv<'a> {
    pub platform: &'a dyn Platform,
    /// `None` when the user's directories cannot be determined: file based facts are `unknown`.
    pub files: Option<&'a FileCtx>,
    pub pac_source: PacSource,
    pub sysproxy_enabled: bool,
    pub cli_protection_enabled: bool,
    pub chained_proxy: Option<String>,
    /// Whether the JetBrains settings format is trusted (see [`JETBRAINS_XML_CONFIRMED`]).
    pub jetbrains_xml_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppFact {
    pub installed: bool,
    pub status: CoverageStatus,
    pub manual_steps: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ConfigFacts {
    pub gateway: Option<SocketAddr>,
    pub apps: HashMap<&'static str, AppFact>,
    pub system_proxy_effective: Option<bool>,
    pub vpn_connected: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Configured,
    Off,
    Unknown,
}

fn steps_of(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|k| k.to_string()).collect()
}

fn compute_config_facts(
    env: &CoverageEnv<'_>,
    gateway: Option<SocketAddr>,
    cli_mode: CliMode,
) -> ConfigFacts {
    let mut facts = ConfigFacts {
        gateway,
        apps: HashMap::new(),
        system_proxy_effective: None,
        vpn_connected: Vec::new(),
    };

    // One PAC read serves browsers and desktop apps.
    let pac_verdict = match gateway {
        Some(g) => read_os_pac(env.platform, env.pac_source, &pac_url_for(g)),
        None => Verdict::Unknown,
    };

    if env.pac_source == PacSource::Services {
        facts.vpn_connected = connected_vpn_names(env.platform);
        facts.system_proxy_effective = gateway.and_then(|g| read_effective_pac(env.platform, g));
    }

    for id in KNOWN_IDS {
        let Some(info) = get_known_app_info(id) else {
            continue;
        };
        let installed = match env.files {
            Some(ctx) => check_app_installed_in(id, ctx),
            None => matches!(id, "browsers" | "curl"),
        };
        if !installed {
            facts.apps.insert(
                id,
                AppFact {
                    installed: false,
                    status: CoverageStatus::NotInstalled,
                    manual_steps: Vec::new(),
                    detail: "Не установлено".to_string(),
                },
            );
            continue;
        }

        let (status, manual_steps, detail) = match info.category {
            "browser" | "desktop" => match pac_verdict {
                Verdict::Configured => (
                    CoverageStatus::Configured,
                    Vec::new(),
                    "Системный PAC указывает на Заставу, ждём первый запрос".to_string(),
                ),
                Verdict::Off => (
                    CoverageStatus::Off,
                    steps_of(&[steps::ENABLE_PROTECTION]),
                    "Системный PAC не указывает на Заставу".to_string(),
                ),
                Verdict::Unknown => (
                    CoverageStatus::Unknown,
                    steps_of(&[steps::ENABLE_PROTECTION, steps::SET_PAC_URL]),
                    "Не удалось прочитать системный PAC".to_string(),
                ),
            },
            "ide" if id == "jetbrains" => {
                jetbrains_fact(env.files, gateway, env.jetbrains_xml_confirmed)
            }
            "ide" => {
                let verdict = match (env.files, gateway) {
                    (Some(ctx), Some(g)) => ide_verdict(ctx, ide_folders(id), g.port()),
                    _ => Verdict::Unknown,
                };
                match verdict {
                    Verdict::Configured => (
                        CoverageStatus::Configured,
                        Vec::new(),
                        "В settings.json http.proxy указывает на Заставу".to_string(),
                    ),
                    Verdict::Off => (
                        CoverageStatus::Off,
                        steps_of(&[steps::ENABLE_PROTECTION, steps::SET_HTTP_PROXY]),
                        "В settings.json нет http.proxy с портом Заставы".to_string(),
                    ),
                    Verdict::Unknown => (
                        CoverageStatus::Unknown,
                        steps_of(&[steps::SET_HTTP_PROXY]),
                        "Не удалось прочитать settings.json".to_string(),
                    ),
                }
            }
            "cli" => cli_fact(id, env, gateway, cli_mode),
            _ => (
                CoverageStatus::Unknown,
                Vec::new(),
                "Не удалось проверить".to_string(),
            ),
        };

        facts.apps.insert(
            id,
            AppFact {
                installed: true,
                status,
                manual_steps,
                detail,
            },
        );
    }
    facts
}

/// Settings file of the AI command-line clients that Zastava configures (`ai_only`).
fn agent_settings_path(ctx: &FileCtx, id: &str) -> Option<PathBuf> {
    match id {
        "claude-code" => Some(ctx.claude_settings()),
        "gemini-cli" => Some(ctx.gemini_settings()),
        _ => None,
    }
}

/// `env.HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` of a Claude Code / Gemini CLI `settings.json`
/// against the gateway port. A missing file is `Off`; an unreadable one is `Unknown`.
fn agent_verdict(ctx: &FileCtx, path: &Path, gateway_port: u16) -> Verdict {
    let text = match ctx.fs.read(path) {
        Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
        Ok(None) => return Verdict::Off,
        Err(_) => return Verdict::Unknown,
    };
    let text = text.trim_start_matches('\u{feff}');
    if text.trim().is_empty() {
        return Verdict::Off;
    }
    let cleaned = crate::sysproxy::sanitize_jsonc(text);
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&cleaned) else {
        return Verdict::Unknown;
    };
    let env = v.get("env");
    let targets = ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"].iter().any(|k| {
        env.and_then(|e| e.get(*k))
            .and_then(|p| p.as_str())
            .is_some_and(|p| proxy_value_targets_gateway(p, gateway_port))
    });
    if targets {
        Verdict::Configured
    } else {
        Verdict::Off
    }
}

/// Status of a command-line application (`category == "cli"`) in the given CLI mode.
///
/// * `ai_only`: Claude Code and Gemini CLI are `Configured` only when their own `settings.json`
///   carries the Zastava proxy; the general tools (`node`, `python`, `curl`) are not covered at all
///   (`Off`, no "enable protection" step: it would not change anything).
/// * `global_terminal`: the shell profiles carry the proxy, so every CLI follows the protection
///   flag; a terminal opened before needs reopening.
fn cli_fact(
    id: &str,
    env: &CoverageEnv<'_>,
    gateway: Option<SocketAddr>,
    mode: CliMode,
) -> (CoverageStatus, Vec<String>, String) {
    if mode == CliMode::GlobalTerminal {
        return if env.cli_protection_enabled {
            (
                CoverageStatus::Configured,
                steps_of(&[steps::REOPEN_TERMINAL]),
                "Защита терминала включена (действует в новых терминалах)".to_string(),
            )
        } else {
            (
                CoverageStatus::Off,
                steps_of(&[steps::ENABLE_PROTECTION, steps::SET_ENV_PROXY]),
                "Защита терминала не включена".to_string(),
            )
        };
    }
    let verdict = match (env.files, gateway) {
        (Some(ctx), Some(g)) => {
            agent_settings_path(ctx, id).map(|path| agent_verdict(ctx, &path, g.port()))
        }
        _ if agent_settings_path_known(id) => Some(Verdict::Unknown),
        _ => None,
    };
    match verdict {
        Some(Verdict::Configured) => (
            CoverageStatus::Configured,
            Vec::new(),
            "В settings.json прописан прокси Заставы (действует для новых сессий)".to_string(),
        ),
        Some(Verdict::Off) => (
            CoverageStatus::Off,
            steps_of(&[steps::ENABLE_PROTECTION, steps::SET_ENV_PROXY]),
            "В settings.json нет прокси Заставы".to_string(),
        ),
        Some(Verdict::Unknown) => (
            CoverageStatus::Unknown,
            steps_of(&[steps::SET_ENV_PROXY]),
            "Не удалось прочитать settings.json".to_string(),
        ),
        None => (
            CoverageStatus::Off,
            steps_of(&[steps::SET_ENV_PROXY]),
            "Не покрывается в режиме «Только ИИ-клиенты и IDE»".to_string(),
        ),
    }
}

fn agent_settings_path_known(id: &str) -> bool {
    matches!(id, "claude-code" | "gemini-cli")
}

fn same_pac(a: &str, b: &str) -> bool {
    a.trim()
        .trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim().trim_end_matches('/'))
}

/// Names of the enabled VPN services that are connected now (macOS). Read-only.
fn connected_vpn_names(platform: &dyn Platform) -> Vec<String> {
    let Ok(services) = platform.list_services() else {
        return Vec::new();
    };
    let enabled: Vec<_> = services.into_iter().filter(|s| s.enabled).collect();
    classify_services(platform, &enabled)
        .into_iter()
        .filter(|(_, k)| *k == ServiceKind::Vpn { connected: true })
        .map(|(s, _)| s.name)
        .collect()
}

/// `scutil --proxy` against our PAC: the proxy the system really applies, which follows the
/// primary service (so a VPN that took over shows up here although Wi-Fi carries our PAC).
/// `None` when it cannot be read.
fn read_effective_pac(platform: &dyn Platform, gateway: SocketAddr) -> Option<bool> {
    let eff = platform.effective_proxy().ok()?;
    Some(
        eff.pac_enabled == Some(true)
            && eff
                .pac_url
                .as_deref()
                .is_some_and(|u| same_pac(u, &pac_url_for(gateway))),
    )
}

/// Reads the PAC the OS hands out and compares it with ours. A failed read is `Unknown`,
/// never `Configured`.
fn read_os_pac(platform: &dyn Platform, source: PacSource, ours: &str) -> Verdict {
    match source {
        PacSource::Inet => match platform.get_inet("AutoConfigURL") {
            Ok(Some(v)) if same_pac(&v.data, ours) => Verdict::Configured,
            Ok(_) => Verdict::Off,
            Err(_) => Verdict::Unknown,
        },
        PacSource::Services => {
            let services = match platform.list_services() {
                Ok(s) => s,
                Err(_) => return Verdict::Unknown,
            };
            let mut readable = 0usize;
            let mut failed = 0usize;
            let enabled: Vec<_> = services.into_iter().filter(|s| s.enabled).collect();
            // A PAC in a VPN service is not Zastava's (it never writes there): not a verdict.
            for (svc, kind) in classify_services(platform, &enabled) {
                if !kind.is_physical() {
                    continue;
                }
                let svc = &svc;
                match platform.get_pac(svc) {
                    Ok(st) => {
                        readable += 1;
                        if st.enabled == Some(true)
                            && st.url.as_deref().is_some_and(|u| same_pac(u, ours))
                        {
                            return Verdict::Configured;
                        }
                    }
                    Err(PlatformError::NotFound(_)) => {}
                    Err(_) => failed += 1,
                }
            }
            if failed > 0 || readable == 0 {
                Verdict::Unknown
            } else {
                Verdict::Off
            }
        }
    }
}

/// Folder names under the editors' per-user data root.
fn ide_folders(id: &str) -> &'static [&'static str] {
    match id {
        "antigravity" => &["Antigravity"],
        "cursor" => &["Cursor"],
        "vscode" => &["Code", "VSCodium"],
        "windsurf" => &["Windsurf"],
        _ => &[],
    }
}

/// Does an `http.proxy` value point at the local gateway on `port`?
pub fn proxy_value_targets_gateway(raw: &str, port: u16) -> bool {
    let raw = raw.trim();
    if raw.is_empty() {
        return false;
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let Ok(url) = url::Url::parse(&with_scheme) else {
        return false;
    };
    let host_ok = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    host_ok && url.port_or_known_default() == Some(port)
}

/// `http.proxy` of the editor's `settings.json` against the gateway port.
fn ide_verdict(ctx: &FileCtx, folders: &[&str], gateway_port: u16) -> Verdict {
    let mut unreadable = false;
    for root in &ctx.ide_roots {
        for folder in folders {
            let path = root.join(folder).join("User").join("settings.json");
            match ctx.fs.read(&path) {
                Ok(Some(bytes)) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let text = text.trim_start_matches('\u{feff}');
                    let cleaned = crate::sysproxy::sanitize_jsonc(text);
                    match serde_json::from_str::<serde_json::Value>(&cleaned) {
                        Ok(v) => {
                            if v.get("http.proxy")
                                .and_then(|p| p.as_str())
                                .is_some_and(|p| proxy_value_targets_gateway(p, gateway_port))
                            {
                                return Verdict::Configured;
                            }
                        }
                        Err(_) => unreadable = true,
                    }
                }
                Ok(None) => {}
                Err(_) => unreadable = true,
            }
        }
    }
    if unreadable {
        Verdict::Unknown
    } else {
        Verdict::Off
    }
}

// ----- JetBrains -------------------------------------------------------------------------------

/// Value of `<option name="X" value="Y" />` in a JetBrains settings XML (the format is not
/// confirmed: see [`JETBRAINS_XML_CONFIRMED`]).
fn xml_option(xml: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\"");
    let at = xml.find(&needle)?;
    let tag_start = xml[..at].rfind('<')?;
    let tag_end = at + xml[at..].find('>')?;
    let tag = &xml[tag_start..=tag_end];
    let v_at = tag.find("value=\"")? + "value=\"".len();
    let rest = &tag[v_at..];
    Some(rest[..rest.find('"')?].to_string())
}

fn jetbrains_xml_verdict(xml: &str, gateway: SocketAddr) -> Verdict {
    let flag = |n: &str| xml_option(xml, n).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if flag("USE_HTTP_PROXY") {
        let host_ok = xml_option(xml, "PROXY_HOST")
            .is_some_and(|h| matches!(h.trim(), "127.0.0.1" | "localhost"));
        let port_ok = xml_option(xml, "PROXY_PORT")
            .and_then(|p| p.trim().parse::<u16>().ok())
            .is_some_and(|p| p == gateway.port());
        return if host_ok && port_ok {
            Verdict::Configured
        } else {
            Verdict::Off
        };
    }
    if flag("USE_PROXY_PAC") {
        return match xml_option(xml, "PAC_URL") {
            Some(u) if same_pac(&u, &pac_url_for(gateway)) => Verdict::Configured,
            Some(_) => Verdict::Off,
            None => Verdict::Unknown,
        };
    }
    Verdict::Unknown
}

/// `<root>/JetBrains/<Product>/options/proxy.settings.xml` for every product directory.
fn jetbrains_xml_candidates(ctx: &FileCtx) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in &ctx.ide_roots {
        if let Ok(rd) = std::fs::read_dir(root.join("JetBrains")) {
            for entry in rd.flatten() {
                out.push(entry.path().join("options").join("proxy.settings.xml"));
            }
        }
    }
    out.sort();
    out
}

fn jetbrains_fact(
    files: Option<&FileCtx>,
    gateway: Option<SocketAddr>,
    confirmed: bool,
) -> (CoverageStatus, Vec<String>, String) {
    let manual = steps_of(&[
        steps::JETBRAINS_PROXY_SETTINGS,
        steps::SET_PAC_URL,
        steps::SET_HTTP_PROXY,
    ]);
    let unknown = (
        CoverageStatus::Unknown,
        manual.clone(),
        "Настройки прокси JetBrains проверить нельзя: смотрим по трафику".to_string(),
    );
    if !confirmed {
        return unknown;
    }
    let (Some(ctx), Some(g)) = (files, gateway) else {
        return unknown;
    };
    let mut seen_configured = false;
    let mut seen_off = false;
    for path in jetbrains_xml_candidates(ctx) {
        if let Ok(Some(bytes)) = ctx.fs.read(&path) {
            match jetbrains_xml_verdict(&String::from_utf8_lossy(&bytes), g) {
                Verdict::Configured => seen_configured = true,
                Verdict::Off => seen_off = true,
                Verdict::Unknown => {}
            }
        }
    }
    if seen_configured {
        (
            CoverageStatus::Configured,
            Vec::new(),
            "Прокси JetBrains указывает на Заставу, ждём первый запрос".to_string(),
        )
    } else if seen_off {
        (
            CoverageStatus::Off,
            manual,
            "Прокси JetBrains настроен не на Заставу".to_string(),
        )
    } else {
        unknown
    }
}

// ---------------------------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------------------------

pub struct KnownAppInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
}

pub fn get_known_app_info(id: &str) -> Option<KnownAppInfo> {
    let (id, name, category) = match id {
        "browsers" => (
            "browsers",
            "Браузеры (Chrome, Safari, Arc, Edge...)",
            "browser",
        ),
        "claude-desktop" => ("claude-desktop", "Claude Desktop", "desktop"),
        "chatgpt-desktop" => ("chatgpt-desktop", "ChatGPT Desktop", "desktop"),
        "antigravity" => ("antigravity", "Antigravity", "ide"),
        "cursor" => ("cursor", "Cursor", "ide"),
        "vscode" => ("vscode", "VS Code", "ide"),
        "windsurf" => ("windsurf", "Windsurf", "ide"),
        "jetbrains" => ("jetbrains", "JetBrains IDE (PyCharm, IntelliJ...)", "ide"),
        "claude-code" => ("claude-code", "Claude Code", "cli"),
        "gemini-cli" => ("gemini-cli", "Gemini CLI", "cli"),
        "node-cli" => ("node-cli", "Node.js / CLI", "cli"),
        "python-cli" => ("python-cli", "Python / CLI", "cli"),
        "curl" => ("curl", "curl", "cli"),
        _ => return None,
    };
    Some(KnownAppInfo { id, name, category })
}

/// Splits a process name into lower-case words (non-alphanumeric characters separate words;
/// trailing digits of a word are dropped: `idea64` -> `idea`).
fn name_words(lower: &str) -> Vec<String> {
    lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| {
            let t = w.trim_end_matches(|c: char| c.is_ascii_digit());
            if t.is_empty() { w } else { t }.to_string()
        })
        .collect()
}

/// Normalizes raw OS process names to canonical Zastava app identifiers. Names are compared as
/// whole words / exact binary names, never as substrings (`provider` is not `rider`,
/// `knowledge` is not `edge`).
pub fn classify_process_name(name: &str) -> &'static str {
    let lower_buf = name.to_lowercase();
    let lower = lower_buf.trim().trim_end_matches(".exe");
    let words = name_words(lower);
    let has = |w: &str| words.iter().any(|x| x == w);
    let first = words.first().map(String::as_str).unwrap_or("");

    if lower.contains("claude-code") || lower.contains("claude_code") {
        return "claude-code";
    }
    if first == "claude" {
        return "claude-desktop";
    }
    if has("chatgpt") {
        return "chatgpt-desktop";
    }
    if has("antigravity") {
        return "antigravity";
    }
    if has("cursor") {
        return "cursor";
    }
    if first == "code"
        || has("vscode")
        || has("vscodium")
        || (has("visual") && has("studio") && has("code"))
    {
        return "vscode";
    }
    if has("windsurf") {
        return "windsurf";
    }
    if has("chrome")
        || has("chromium")
        || has("safari")
        || has("firefox")
        || has("brave")
        || has("msedge")
        || has("edge")
        || first == "arc"
        || words
            .iter()
            .any(|w| w.starts_with("yandex") || w.starts_with("яндекс"))
    {
        return "browsers";
    }
    const JETBRAINS_WORDS: [&str; 11] = [
        "idea", "pycharm", "webstorm", "datagrip", "clion", "rider", "goland", "rubymine",
        "phpstorm", "fleet", "appcode",
    ];
    if JETBRAINS_WORDS.iter().any(|w| has(w))
        || (has("android") && has("studio"))
        || lower == "studio64"
    {
        return "jetbrains";
    }
    if lower == "gemini" || lower.contains("gemini-cli") {
        return "gemini-cli";
    }
    if lower == "node" || lower.starts_with("node ") {
        return "node-cli";
    }
    if first == "python" {
        return "python-cli";
    }
    if lower == "curl" {
        return "curl";
    }

    "other"
}

/// Resolves an app identifier, human-readable name, and category from process info.
pub fn resolve_app_identity(
    raw_process_name: &str,
    user_agent: Option<&str>,
) -> (String, String, String) {
    if let Some(ua) = user_agent {
        let ua_lower = ua.to_lowercase();
        if ua_lower.starts_with("curl/") {
            return ("curl".to_string(), "curl".to_string(), "cli".to_string());
        }
        if ua_lower.contains("claude-code") {
            return (
                "claude-code".to_string(),
                "Claude Code".to_string(),
                "cli".to_string(),
            );
        }
    }

    let classified = classify_process_name(raw_process_name);
    if classified != "other"
        && let Some(info) = get_known_app_info(classified)
    {
        return (
            info.id.to_string(),
            info.name.to_string(),
            info.category.to_string(),
        );
    }

    let clean_id = raw_process_name
        .to_lowercase()
        .replace([' ', '_', '/'], "-");
    (clean_id, raw_process_name.to_string(), "cli".to_string())
}

// ---------------------------------------------------------------------------------------------
// Installed?
// ---------------------------------------------------------------------------------------------

/// Checks whether an application is installed on this machine (real home).
pub fn check_app_installed(id: &str) -> bool {
    FileCtx::real()
        .map(|ctx| check_app_installed_in(id, &ctx))
        .unwrap_or(matches!(id, "browsers" | "curl"))
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

/// Whether the application is installed or its config / settings directory exists, looking
/// only through `ctx` (its file system, home and editor roots).
pub(crate) fn check_app_installed_in(id: &str, ctx: &FileCtx) -> bool {
    let fs: &dyn Fs = &*ctx.fs;
    let ex = |p: &Path| fs.exists(p);
    let in_roots = |folder: &str| ctx.ide_roots.iter().any(|r| ex(&r.join(folder)));
    let windows_local = |sub: &[&str]| {
        cfg!(target_os = "windows")
            && env_dir("LOCALAPPDATA").is_some_and(|l| {
                let mut p = l;
                for s in sub {
                    p = p.join(s);
                }
                ex(&p)
            })
    };
    let has_ide_folder = |folder: &str| {
        ctx.ide_roots
            .iter()
            .any(|r| ex(&r.join(folder).join("User")))
    };

    match id {
        "browsers" | "curl" => true,
        "claude-desktop" => {
            ex(Path::new("/Applications/Claude.app"))
                || ex(&ctx.home.join("Applications").join("Claude.app"))
                || in_roots("Claude")
                || windows_local(&["Programs", "Claude"])
        }
        "chatgpt-desktop" => {
            ex(Path::new("/Applications/ChatGPT.app"))
                || ex(&ctx.home.join("Applications").join("ChatGPT.app"))
                || in_roots("ChatGPT")
                || windows_local(&["Programs", "ChatGPT"])
        }
        "antigravity" => {
            has_ide_folder("Antigravity")
                || ex(Path::new("/Applications/Antigravity.app"))
                || ex(&ctx.home.join(".gemini").join("antigravity-cli"))
        }
        "cursor" => has_ide_folder("Cursor") || ex(Path::new("/Applications/Cursor.app")),
        "vscode" => {
            has_ide_folder("Code")
                || has_ide_folder("VSCodium")
                || ex(Path::new("/Applications/Visual Studio Code.app"))
        }
        "windsurf" => has_ide_folder("Windsurf") || ex(Path::new("/Applications/Windsurf.app")),
        "jetbrains" => {
            in_roots("JetBrains")
                || windows_local(&["JetBrains"])
                || ex(Path::new("/Applications/IntelliJ IDEA.app"))
                || ex(Path::new("/Applications/PyCharm.app"))
                || ex(Path::new("/Applications/WebStorm.app"))
        }
        "claude-code" => ex(&ctx.home.join(".claude")),
        "gemini-cli" => ex(&ctx.home.join(".gemini")),
        "node-cli" => {
            ex(&ctx.home.join(".nvm"))
                || ex(&ctx.home.join(".fnm"))
                || ex(Path::new("/usr/local/bin/node"))
                || ex(Path::new("/opt/homebrew/bin/node"))
                || env_dir("ProgramFiles").is_some_and(|p| ex(&p.join("nodejs")))
        }
        "python-cli" => {
            ex(Path::new("/usr/bin/python3"))
                || ex(Path::new("/usr/local/bin/python3"))
                || ex(Path::new("/opt/homebrew/bin/python3"))
                || windows_local(&["Programs", "Python"])
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------
// Process owner of a local port
// ---------------------------------------------------------------------------------------------

/// Asynchronously resolves process name owning `peer_port`.
pub async fn lookup_process_name_by_port(port: u16) -> Option<String> {
    tokio::task::spawn_blocking(move || lookup_process_name_by_port_sync(port))
        .await
        .ok()
        .flatten()
}

/// Synchronous OS-level process resolution for an established TCP port.
pub fn lookup_process_name_by_port_sync(port: u16) -> Option<String> {
    lookup_process_with(&RealProbe, Os::current(), port, std::process::id())
}

/// Resolves the process that owns `port` using `probe` (`lsof` on macOS, `netstat` + `tasklist`
/// on Windows, `ss` on Linux). `my_pid` (the gateway itself) is never returned.
pub fn lookup_process_with(
    probe: &dyn SystemProbe,
    os: Os,
    port: u16,
    my_pid: u32,
) -> Option<String> {
    match os {
        Os::Macos => {
            let filter = format!("-iTCP:{port}");
            let text = probe.run("lsof", &["-nP", "+c", "0", "-Fpcn", &filter])?;
            parse_lsof_owner(&text, my_pid)
        }
        Os::Windows => {
            let text = probe.run("netstat", &["-ano", "-p", "tcp"])?;
            let pid = parse_netstat_pid(&text, port, my_pid)?;
            let filter = format!("PID eq {pid}");
            let tasks = probe.run("tasklist", &["/FI", &filter, "/FO", "CSV", "/NH"])?;
            parse_tasklist_name(&tasks)
        }
        Os::Linux => {
            let text = probe.run("ss", &["-t", "-p", "-H"])?;
            parse_ss_owner(&text, port, my_pid)
        }
    }
}

fn unescape_lsof(s: &str) -> String {
    s.replace("\\x20", " ")
}

/// `lsof -Fpcn` output -> first command that is not the gateway itself.
pub fn parse_lsof_owner(text: &str, my_pid: u32) -> Option<String> {
    let mut current_pid: Option<u32> = None;
    let mut current_cmd: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('p') {
            current_pid = rest.trim().parse::<u32>().ok();
            current_cmd = None;
        } else if let Some(rest) = line.strip_prefix('c') {
            current_cmd = Some(unescape_lsof(rest.trim()));
        } else if line.starts_with('n')
            && let Some(cmd) = &current_cmd
        {
            let own =
                cmd.eq_ignore_ascii_case("zastava") || cmd.eq_ignore_ascii_case("zastava_lib");
            if current_pid != Some(my_pid) && !own && !cmd.is_empty() {
                return Some(cmd.clone());
            }
        }
    }
    None
}

/// Port of `host:port` / `[::1]:port`.
fn addr_port(addr: &str) -> Option<u16> {
    addr.rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
}

/// `netstat -ano -p tcp` -> PID of the process on `port`. The port must match exactly
/// (8899 is not 18899 / 88990); the gateway's own rows and PID 0 are skipped.
pub fn parse_netstat_pid(text: &str, port: u16, my_pid: u32) -> Option<u32> {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || !parts[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        let local = addr_port(parts[1]);
        let remote = addr_port(parts[2]);
        if local != Some(port) && remote != Some(port) {
            continue;
        }
        if let Ok(pid) = parts[parts.len() - 1].parse::<u32>()
            && pid != my_pid
            && pid != 0
        {
            return Some(pid);
        }
    }
    None
}

/// `tasklist /FO CSV /NH` -> image name.
pub fn parse_tasklist_name(text: &str) -> Option<String> {
    for line in text.lines() {
        let clean = line.trim();
        if clean.starts_with('"') {
            let name = clean.trim_start_matches('"').split('"').next()?;
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// `ss -t -p -H` -> process name of the socket on `port` (exact port, not the gateway itself).
pub fn parse_ss_owner(text: &str, port: u16, my_pid: u32) -> Option<String> {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let (local, peer) = (addr_port(parts[3]), addr_port(parts[4]));
        if local != Some(port) && peer != Some(port) {
            continue;
        }
        let Some(after) = line.split("users:((\"").nth(1) else {
            continue;
        };
        let Some(name) = after.split('"').next() else {
            continue;
        };
        let pid = after
            .split("pid=")
            .nth(1)
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|p| p.parse::<u32>().ok());
        if pid == Some(my_pid) || name.is_empty() {
            continue;
        }
        return Some(name.to_string());
    }
    None
}

#[cfg(test)]
mod tests;
