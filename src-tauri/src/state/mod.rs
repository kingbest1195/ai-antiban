use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{watch, RwLock};

use crate::routing::{select_route, select_route_id, Route, RouteHealthRegistry, RouteSelection};

pub const PROVIDER_ANTHROPIC: &str = "anthropic";
pub const PROVIDER_OPENAI: &str = "openai";
pub const PROVIDER_GEMINI: &str = "gemini";
pub const KNOWN_PROVIDERS: [&str; 3] = [PROVIDER_ANTHROPIC, PROVIDER_OPENAI, PROVIDER_GEMINI];
pub const MAX_HISTORY_ENTRIES_PER_PROVIDER: usize = 10;
pub const STATE_FILE_NAME: &str = "state.json";
/// Copy of the original v1.3.x `state.json`, written once before the v1 -> v2 migration.
pub const STATE_V1_BACKUP_NAME: &str = "state.v1.bak.json";
/// `state.json` schema: 0/1 = v1.3.x (single `upstream_proxy`), 2 = routes.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Storage path error: {0}")]
    PathError(String),
}

/// Single connection/audit history record for an AI provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpHistoryEntry {
    pub ip: String,
    pub country_code: String,
    #[serde(default, deserialize_with = "deserialize_asn")]
    pub asn: Option<u32>,
    pub timestamp: u64,
}

impl IpHistoryEntry {
    pub fn new(
        ip: impl Into<String>,
        country_code: impl Into<String>,
        asn: Option<u32>,
        timestamp: u64,
    ) -> Self {
        Self {
            ip: ip.into(),
            country_code: country_code.into().to_ascii_uppercase(),
            asn,
            timestamp,
        }
    }
}

/// Helper deserializer to tolerate integer, string (e.g. "AS20473" or "20473"), or null ASN values.
fn deserialize_asn<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AsnVisitor;

    impl<'de> serde::de::Visitor<'de> for AsnVisitor {
        type Value = Option<u32>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an integer ASN, a string with optional 'AS' prefix, or null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v as u32))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
            if v >= 0 {
                Ok(Some(v as u32))
            } else {
                Ok(None)
            }
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let cleaned = v.trim().trim_start_matches("AS").trim_start_matches("as");
            match cleaned.parse::<u32>() {
                Ok(num) => Ok(Some(num)),
                Err(_) => Ok(None),
            }
        }
    }

    deserializer.deserialize_any(AsnVisitor)
}

fn default_true() -> bool {
    true
}

/// Preset behavior rules when risk or VPN drop is detected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum InterceptionBehavior {
    /// Show the top-right non-focus-stealing alert popup and wait for user choice (default)
    #[default]
    AskPopup,
    /// Automatically lock/freeze AI traffic on VPN drop or risk WITHOUT showing any popup ("Тихий лок без попапа")
    AutoLockSilent,
    /// Automatically allow session if the new country is not in global_blocked_countries (RU/BY/CN/HK/IR/KP/SY/CU)
    AutoAllowTrusted,
}

/// Where the protection of command-line tools goes (`cli_mode` in `state.json`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CliMode {
    /// Only the AI clients and the editors: `~/.claude/settings.json`, `~/.gemini/settings.json`
    /// and the editors' `settings.json`. Nothing is written into shell profiles, so `npm`, `brew`
    /// and `git` in a plain terminal go directly (default).
    #[default]
    AiOnly,
    /// Additionally a marked block in the interactive shell profiles (`~/.zshrc`,
    /// `~/.bash_profile`; on Windows the PowerShell profile).
    GlobalTerminal,
}

/// Alert popup screen placement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PopupPosition {
    /// Top-right corner of the primary screen (default per user request #8)
    #[default]
    TopRight,
    /// Top-center under the notch
    TopCenter,
}

/// Legacy (v1.3.x) single upstream proxy. Since schema v2 this is a read-only mirror of the
/// legacy/default route, kept for the existing commands, `get_state` and downgrade safety.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamProxyConfig {
    pub enabled: bool,
    pub raw_key: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub label: Option<String>,
}

impl UpstreamProxyConfig {
    /// Copy without secrets (no password, masked username, display-safe `raw_key`) for command
    /// results.
    pub fn without_secrets(&self) -> UpstreamProxyConfig {
        UpstreamProxyConfig {
            raw_key: crate::routing::mask_raw_key(&self.raw_key),
            username: self.username.as_deref().map(crate::routing::mask_secret),
            password: None,
            ..self.clone()
        }
    }
}

impl std::fmt::Debug for UpstreamProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamProxyConfig")
            .field("enabled", &self.enabled)
            .field("raw_key", &"***")
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username.as_deref().map(crate::routing::mask_secret))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("label", &self.label)
            .finish()
    }
}

/// Persistent state data structure serialized to `state.json`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppStateData {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub pinned_ip: Option<String>,
    #[serde(default)]
    pub strict_pinning_enabled: bool,
    #[serde(default)]
    pub ip_history: HashMap<String, Vec<IpHistoryEntry>>,
    #[serde(default)]
    pub session_allowed_providers: HashSet<String>,
    #[serde(default)]
    pub blocked_providers: HashSet<String>,
    #[serde(default)]
    pub upstream_proxy: Option<UpstreamProxyConfig>,
    #[serde(default)]
    pub warmup_started_at: Option<u64>,
    #[serde(default)]
    pub synced_ai_timezone: Option<String>,
    /// Independent switch "replace the time zone and locale for the AI tools in the terminal /
    /// editors". Applied only while a time zone is known; has nothing to do with the CLI / IDE
    /// protection switch. State files of 2.0.0 and older have no such field: on.
    #[serde(default = "default_true")]
    pub sync_ai_tz_enabled: bool,
    /// Coverage of command-line tools (see [`CliMode`]). Older state files: `ai_only`.
    #[serde(default)]
    pub cli_mode: CliMode,
    #[serde(default = "default_true")]
    pub auto_update_enabled: bool,
    #[serde(default)]
    pub autostart_enabled: bool,
    #[serde(default)]
    pub cowork_guard_enabled: bool,
    #[serde(default)]
    pub interception_behavior: InterceptionBehavior,
    #[serde(default)]
    pub popup_position: PopupPosition,
    #[serde(default)]
    pub custom_ai_domains: Vec<String>,
    /// Imported keys.
    #[serde(default)]
    pub routes: Vec<Route>,
    /// provider id -> route id.
    #[serde(default)]
    pub provider_routes: HashMap<String, String>,
    /// Route for AI providers without an explicit binding (`None` = direct / user's VPN).
    #[serde(default)]
    pub default_route_id: Option<String>,
    /// Route of the active Claude profile (`bound_upstream_key`); highest priority for anthropic.
    #[serde(default)]
    pub profile_route_id: Option<String>,
    /// Route managed by the legacy `*_upstream_proxy` commands.
    #[serde(default)]
    pub legacy_route_id: Option<String>,
    /// Set while the key of the active Claude profile failed validation: the profile route is then
    /// "invalid" and Claude is blocked (fail-closed) instead of keeping the previous profile's route.
    #[serde(default)]
    pub profile_route_invalid: Option<String>,
    /// Manual kill-switch ("СТОП СЕТИ"). Restored at launch: a restart must not lift it silently.
    #[serde(default)]
    pub manual_killswitch: bool,
    /// Routes of `state.json` this version does not understand (e.g. a future `proto`). They are
    /// skipped (their bindings become `Missing`, i.e. blocked) but written back unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_routes: Vec<serde_json::Value>,
}

impl std::fmt::Debug for AppStateData {
    /// Secrets (passwords, raw keys, unknown route payloads) are masked.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStateData")
            .field("schema_version", &self.schema_version)
            .field("pinned_ip", &self.pinned_ip)
            .field("strict_pinning_enabled", &self.strict_pinning_enabled)
            .field("ip_history", &self.ip_history)
            .field("session_allowed_providers", &self.session_allowed_providers)
            .field("blocked_providers", &self.blocked_providers)
            .field("upstream_proxy", &self.upstream_proxy)
            .field("warmup_started_at", &self.warmup_started_at)
            .field("synced_ai_timezone", &self.synced_ai_timezone)
            .field("sync_ai_tz_enabled", &self.sync_ai_tz_enabled)
            .field("cli_mode", &self.cli_mode)
            .field("auto_update_enabled", &self.auto_update_enabled)
            .field("autostart_enabled", &self.autostart_enabled)
            .field("cowork_guard_enabled", &self.cowork_guard_enabled)
            .field("interception_behavior", &self.interception_behavior)
            .field("popup_position", &self.popup_position)
            .field("custom_ai_domains", &self.custom_ai_domains)
            .field("routes", &self.routes)
            .field("provider_routes", &self.provider_routes)
            .field("default_route_id", &self.default_route_id)
            .field("profile_route_id", &self.profile_route_id)
            .field("legacy_route_id", &self.legacy_route_id)
            .field("profile_route_invalid", &self.profile_route_invalid)
            .field("manual_killswitch", &self.manual_killswitch)
            .field("skipped_routes", &format_args!("<{} not shown>", self.skipped_routes.len()))
            .finish()
    }
}

impl AppStateData {
    /// Upgrades data loaded from an older `state.json`. Returns true if anything changed.
    pub fn migrate(&mut self, now: u64) -> bool {
        let before = self.clone();
        if self.schema_version < 2 {
            if let Some(cfg) = self.upstream_proxy.clone() {
                if let Some(route) = Route::from_legacy(&cfg, now) {
                    let id = route.id.clone();
                    if !self.routes.iter().any(|r| r.id == id) {
                        self.routes.push(route);
                    }
                    self.legacy_route_id = Some(id.clone());
                    if cfg.enabled {
                        self.default_route_id = Some(id);
                    }
                }
            }
        }
        self.schema_version = self.schema_version.max(CURRENT_SCHEMA_VERSION);
        // Dangling references are deliberately kept: a binding to a missing route is `Missing`
        // (blocked), never silently "direct".
        self.sync_legacy_mirror();
        *self != before
    }

    fn has_route(&self, id: &str) -> bool {
        self.routes.iter().any(|r| r.id == id)
    }

    /// True when a provider binding, the default or the profile slot points to `id`.
    fn is_route_referenced(&self, id: &str) -> bool {
        self.provider_routes.values().any(|v| v == id)
            || self.default_route_id.as_deref() == Some(id)
            || self.profile_route_id.as_deref() == Some(id)
    }

    /// Id of the route the legacy commands act on: the legacy slot, else the default route.
    pub fn legacy_target_id(&self) -> Option<String> {
        self.legacy_route_id
            .clone()
            .or_else(|| self.default_route_id.clone())
    }

    /// Recomputes `upstream_proxy` from the routes. `enabled` there means "carries default traffic".
    pub fn sync_legacy_mirror(&mut self) {
        let mirror = self.legacy_target_id().and_then(|id| {
            let r = self.routes.iter().find(|r| r.id == id)?;
            let active = r.enabled && self.default_route_id.as_deref() == Some(id.as_str());
            r.to_legacy(active)
        });
        self.upstream_proxy = mirror;
    }

    /// The time zone to put into the AI tools' environment: the stored one, and only while the
    /// switch is on and the value is a well-formed zone name.
    pub fn effective_sync_tz(&self) -> Option<String> {
        if !self.sync_ai_tz_enabled {
            return None;
        }
        self.synced_ai_timezone
            .as_deref()
            .and_then(crate::sysproxy::sanitize_timezone)
    }

    /// Copy safe to hand to the UI via `get_state`: route secrets are blanked
    /// (`list_routes` is the route API). `upstream_proxy` stays as in v1.3.x.
    pub fn redacted_for_ui(&self) -> AppStateData {
        let mut d = self.clone();
        d.skipped_routes.clear();
        // `upstream_proxy.password` / `.username` are not read by the interface. `raw_key` is still
        // passed around by it (AppShell -> BackupTab props), so it is left as in v1.3.x for now.
        if let Some(u) = d.upstream_proxy.as_mut() {
            u.password = None;
            u.username = u.username.as_deref().map(crate::routing::mask_secret);
        }
        for r in &mut d.routes {
            r.raw_key = String::new();
            for e in &mut r.entries {
                e.password = None;
                e.username = e.username.as_deref().map(crate::routing::mask_secret);
            }
        }
        d
    }

    /// Known providers whose traffic currently goes through a route (fixed exit).
    pub fn routed_providers(&self) -> Vec<&'static str> {
        KNOWN_PROVIDERS
            .into_iter()
            .filter(|p| select_route_id(self, p).is_some())
            .collect()
    }

    /// Known providers whose traffic goes directly through the local network / VPN.
    pub fn unrouted_providers(&self) -> Vec<&'static str> {
        KNOWN_PROVIDERS
            .into_iter()
            .filter(|p| select_route_id(self, p).is_none())
            .collect()
    }

    /// Removes the route itself. Bindings that point to it stay (and become `Missing`, i.e. the
    /// providers are blocked until the user rebinds or unbinds them); only the legacy slot, which
    /// is not a routing reference, is cleared.
    fn remove_route_locked(&mut self, id: &str) -> bool {
        let before = self.routes.len();
        self.routes.retain(|r| r.id != id);
        let removed = self.routes.len() != before;
        if self.legacy_route_id.as_deref() == Some(id) {
            self.legacy_route_id = None;
        }
        removed
    }

    /// Removes the legacy route `id` if nothing else references it.
    fn gc_legacy_route(&mut self, id: &str) -> bool {
        if self.is_route_referenced(id) || self.legacy_route_id.as_deref() == Some(id) {
            return false;
        }
        self.remove_route_locked(id)
    }
}

impl Default for AppStateData {
    fn default() -> Self {
        let mut ip_history = HashMap::new();
        for &provider in &KNOWN_PROVIDERS {
            ip_history.insert(provider.to_string(), Vec::new());
        }

        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            pinned_ip: None,
            strict_pinning_enabled: false,
            ip_history,
            session_allowed_providers: HashSet::new(),
            blocked_providers: HashSet::new(),
            upstream_proxy: None,
            warmup_started_at: None,
            synced_ai_timezone: None,
            sync_ai_tz_enabled: true,
            cli_mode: CliMode::AiOnly,
            auto_update_enabled: true,
            autostart_enabled: false,
            cowork_guard_enabled: false,
            interception_behavior: InterceptionBehavior::AskPopup,
            popup_position: PopupPosition::TopRight,
            custom_ai_domains: Vec::new(),
            routes: Vec::new(),
            provider_routes: HashMap::new(),
            default_route_id: None,
            profile_route_id: None,
            legacy_route_id: None,
            profile_route_invalid: None,
            manual_killswitch: false,
            skipped_routes: Vec::new(),
        }
    }
}

/// Thread-safe wrapper for persistent application state.
pub type AppContext = AppState;

/// Single live event recorded by the gateway interceptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentGatewayEvent {
    pub timestamp: u64,
    pub host: String,
    pub provider: String,
    pub action: String, // "PROTECTED" | "HELD" | "BLOCKED" | "DIRECT"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub country: String,
}

/// Instant snapshot of live traffic counters for the UI and system tray.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GatewayStatsSnapshot {
    pub protected_ai_requests: u64,
    pub intercepted_leaks: u64,
    pub direct_bypassed_requests: u64,
    pub active_ai_tunnels: u64,
    pub uptime_seconds: u64,
    pub last_protected_host: Option<String>,
    pub recent_events: Vec<RecentGatewayEvent>,
}

/// Thread-safe lock-free atomic tracker for live gateway traffic counters.
#[derive(Debug)]
pub struct GatewayStatsTracker {
    pub start_time: std::time::Instant,
    pub protected_ai_requests: AtomicU64,
    pub intercepted_leaks: AtomicU64,
    pub direct_bypassed_requests: AtomicU64,
    pub active_ai_tunnels: AtomicU64,
    pub last_protected_host: std::sync::RwLock<Option<String>>,
    pub recent_events: std::sync::RwLock<VecDeque<RecentGatewayEvent>>,
}

/// RAII guard that tracks the active AI tunnel count.
pub struct TunnelGuard {
    tracker: Arc<GatewayStatsTracker>,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        self.tracker.active_ai_tunnels.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Default for GatewayStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayStatsTracker {
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            protected_ai_requests: AtomicU64::new(0),
            intercepted_leaks: AtomicU64::new(0),
            direct_bypassed_requests: AtomicU64::new(0),
            active_ai_tunnels: AtomicU64::new(0),
            last_protected_host: std::sync::RwLock::new(None),
            recent_events: std::sync::RwLock::new(VecDeque::with_capacity(20)),
        }
    }

    pub fn record_protected(&self, host: &str, provider: &str, country: &str) {
        // Crash-test canary probes must never inflate real user counters.
        if host.starts_with("canary-test.") {
            return;
        }
        self.protected_ai_requests.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut l) = self.last_protected_host.write() {
            *l = Some(host.to_string());
        }
        let event = RecentGatewayEvent {
            timestamp: crate::auditor::network::current_timestamp(),
            host: host.to_string(),
            provider: provider.to_string(),
            action: "PROTECTED".to_string(),
            kind: None,
            country: country.to_string(),
        };
        self.push_event(event);
    }

    pub fn record_intercepted(&self, host: &str, provider: &str, action: &str, country: &str) {
        // Crash-test canary probes must never inflate real user counters.
        if host.starts_with("canary-test.") {
            return;
        }
        self.intercepted_leaks.fetch_add(1, Ordering::SeqCst);
        let event = RecentGatewayEvent {
            timestamp: crate::auditor::network::current_timestamp(),
            host: host.to_string(),
            provider: provider.to_string(),
            action: action.to_string(),
            kind: None,
            country: country.to_string(),
        };
        self.push_event(event);
    }

    pub fn record_direct_bypassed(&self) {
        self.direct_bypassed_requests.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_direct_bypassed_host(&self, host: &str) {
        self.direct_bypassed_requests.fetch_add(1, Ordering::SeqCst);
        let now = crate::auditor::network::current_timestamp();
        if let Ok(mut g) = self.recent_events.write() {
            if let Some(last) = g.back_mut() {
                let is_direct = last.action.eq_ignore_ascii_case("direct")
                    || last.kind.as_deref().map(|k| k.eq_ignore_ascii_case("direct")).unwrap_or(false);
                if is_direct && last.host == host {
                    last.timestamp = now;
                    return;
                }
            }
            if g.len() >= 20 {
                g.pop_front();
            }
            g.push_back(RecentGatewayEvent {
                timestamp: now,
                host: host.to_string(),
                provider: "Non-AI".to_string(),
                action: "DIRECT".to_string(),
                kind: Some("direct".to_string()),
                country: "DIRECT".to_string(),
            });
        }
    }

    pub fn record_direct_bypassed_with_host(&self, host: &str) {
        self.record_direct_bypassed_host(host);
    }

    pub fn enter_tunnel(self: &Arc<Self>) -> TunnelGuard {
        self.active_ai_tunnels.fetch_add(1, Ordering::SeqCst);
        TunnelGuard {
            tracker: Arc::clone(self),
        }
    }

    fn push_event(&self, event: RecentGatewayEvent) {
        if let Ok(mut g) = self.recent_events.write() {
            if g.len() >= 20 {
                g.pop_front();
            }
            g.push_back(event);
        }
    }

    pub async fn snapshot(&self) -> GatewayStatsSnapshot {
        self.snapshot_sync()
    }

    pub fn snapshot_sync(&self) -> GatewayStatsSnapshot {
        let events = self
            .recent_events
            .read()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default();
        let last_host = self.last_protected_host.read().ok().and_then(|h| h.clone());
        GatewayStatsSnapshot {
            protected_ai_requests: self.protected_ai_requests.load(Ordering::SeqCst),
            intercepted_leaks: self.intercepted_leaks.load(Ordering::SeqCst),
            direct_bypassed_requests: self.direct_bypassed_requests.load(Ordering::SeqCst),
            active_ai_tunnels: self.active_ai_tunnels.load(Ordering::SeqCst),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            last_protected_host: last_host,
            recent_events: events,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppStateData>>,
    storage_path: Option<PathBuf>,
    save_lock: Arc<tokio::sync::Mutex<()>>,
    stats: Arc<GatewayStatsTracker>,
    route_health: Arc<RouteHealthRegistry>,
    /// Routing generation: bumped by every change that can alter which route a provider uses (or
    /// the route itself). Established tunnels watch it and re-check their provider's selection.
    routing_gen: Arc<watch::Sender<u64>>,
}

impl AppState {
    /// Creates a new in-memory `AppState` with optional persistence file path.
    pub fn new(data: AppStateData, storage_path: Option<PathBuf>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(data)),
            storage_path,
            save_lock: Arc::new(tokio::sync::Mutex::new(())),
            stats: Arc::new(GatewayStatsTracker::new()),
            route_health: Arc::new(RouteHealthRegistry::default()),
            routing_gen: Arc::new(watch::channel(0u64).0),
        }
    }

    /// Receiver that fires after every routing-relevant change (see `routing_gen`).
    pub fn subscribe_routing(&self) -> watch::Receiver<u64> {
        self.routing_gen.subscribe()
    }

    /// Current routing generation.
    pub fn routing_generation(&self) -> u64 {
        *self.routing_gen.borrow()
    }

    fn bump_routing(&self) {
        self.routing_gen.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Runtime (not persisted) health of routes.
    pub fn route_health(&self) -> &Arc<RouteHealthRegistry> {
        &self.route_health
    }

    /// Access the live gateway statistics tracker.
    pub fn stats(&self) -> &Arc<GatewayStatsTracker> {
        &self.stats
    }

    /// Returns a live snapshot of gateway statistics.
    pub async fn get_gateway_stats(&self) -> GatewayStatsSnapshot {
        self.stats.snapshot().await
    }

    /// Creates an in-memory `AppState` initialized with default values.
    pub fn new_in_memory() -> Self {
        Self::new(AppStateData::default(), None)
    }

    /// Loads state from `state.json` at `storage_path`. A missing file yields the defaults. A file
    /// that cannot be read at all is first copied to `state.corrupt-<ts>.json` and then replaced by
    /// the defaults; a single unrecognised route never resets the rest of the state.
    pub fn load_or_default(storage_path: PathBuf) -> Self {
        let mut needs_save = false;
        let mut data = if storage_path.exists() {
            Self::restrict_to_owner(&storage_path);
            match Self::read_state_lenient(&storage_path) {
                Ok(mut loaded) => {
                    let now = crate::auditor::network::current_timestamp();
                    if loaded.schema_version < 2 {
                        Self::backup_v1_state_once(&storage_path);
                    }
                    needs_save = loaded.migrate(now);
                    loaded
                }
                Err(err) => {
                    let kept = Self::keep_corrupt_copy(&storage_path);
                    eprintln!(
                        "Warning: Failed to load state from {}: {}. {} Self-healing to default state.",
                        storage_path.display(),
                        err,
                        match kept {
                            Some(p) => format!("The original file was kept as {}.", p.display()),
                            None => "The original file could not be copied.".to_string(),
                        }
                    );
                    needs_save = true;
                    AppStateData::default()
                }
            }
        } else {
            AppStateData::default()
        };

        // Session allowances are ephemeral per app launch and must not carry over across restarts
        data.session_allowed_providers.clear();

        if needs_save {
            if let Err(e) = Self::save_data_to_file(&data, &storage_path) {
                eprintln!("Warning: could not rewrite {}: {e}", storage_path.display());
            }
        }

        Self::new(data, Some(storage_path))
    }

    /// Loads `AppStateData` from a file path, migrated to the current schema.
    pub fn load_from_file(path: &Path) -> Result<AppStateData, StateError> {
        let mut data = Self::read_state_lenient(path)?;
        data.migrate(crate::auditor::network::current_timestamp());
        Ok(data)
    }

    /// Reads `state.json`; routes that this version cannot parse are moved to `skipped_routes`
    /// instead of failing the whole file.
    fn read_state_lenient(path: &Path) -> Result<AppStateData, StateError> {
        let content = std::fs::read_to_string(path)?;
        let mut value: serde_json::Value = serde_json::from_str(&content)?;
        let obj = value
            .as_object_mut()
            .ok_or_else(|| StateError::PathError("state.json is not a JSON object".to_string()))?;
        let routes_value = obj.remove("routes");
        let mut data: AppStateData = serde_json::from_value(value)?;

        let mut candidates: Vec<serde_json::Value> = std::mem::take(&mut data.skipped_routes);
        match routes_value {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(items)) => {
                // Previously skipped routes go last: a newer build may understand them now.
                candidates = items.into_iter().chain(candidates).collect();
            }
            Some(_) => {
                return Err(StateError::PathError("`routes` is not an array".to_string()));
            }
        }
        for (i, item) in candidates.into_iter().enumerate() {
            match serde_json::from_value::<Route>(item.clone()) {
                Ok(r) => {
                    if !data.routes.iter().any(|x| x.id == r.id) {
                        data.routes.push(r);
                    }
                }
                Err(_) => {
                    // The error is not printed: serde may quote values of the key.
                    eprintln!(
                        "Warning: route #{i} of state.json is not understood by this version and was skipped"
                    );
                    data.skipped_routes.push(item);
                }
            }
        }
        Ok(data)
    }

    /// Copies the original v1.3.x file next to it, once.
    fn backup_v1_state_once(path: &Path) {
        let backup = path.with_file_name(STATE_V1_BACKUP_NAME);
        if backup.exists() {
            return;
        }
        if let Err(e) = Self::copy_private(path, &backup) {
            eprintln!("Warning: could not back up the v1 state file: {e}");
        }
    }

    /// Creates (truncating) a file that only the owner can read: mode 0600 on unix, default ACLs
    /// on Windows.
    fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    }

    /// Tightens an existing file to 0600 on unix (no-op on Windows and on errors).
    fn restrict_to_owner(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    /// Copies `src` to `dest` as an owner-only file (unlike `fs::copy`, which keeps the source mode).
    fn copy_private(src: &Path, dest: &Path) -> std::io::Result<()> {
        let mut input = std::fs::File::open(src)?;
        let mut out = Self::create_private_file(dest)?;
        // An existing destination keeps its old mode through `create`, so tighten it explicitly.
        Self::restrict_to_owner(dest);
        std::io::copy(&mut input, &mut out)?;
        out.sync_all()
    }

    /// Copies an unreadable state file to `state.corrupt-<ts>.json` before it is replaced.
    fn keep_corrupt_copy(path: &Path) -> Option<PathBuf> {
        let ts = crate::auditor::network::current_timestamp();
        let mut dest = path.with_file_name(format!("state.corrupt-{ts}.json"));
        let mut n = 1;
        while dest.exists() {
            dest = path.with_file_name(format!("state.corrupt-{ts}-{n}.json"));
            n += 1;
        }
        Self::copy_private(path, &dest).ok().map(|_| dest)
    }

    /// Saves `AppStateData` atomically: temp file + fsync + rename (+ fsync of the directory).
    pub fn save_data_to_file(data: &AppStateData, path: &Path) -> Result<(), StateError> {
        use std::io::Write;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(data)?;
        let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
        {
            let mut f = Self::create_private_file(&tmp_path)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            // Fallback to direct write if cross-device or Windows file lock prevents rename
            let mut f = Self::create_private_file(path).map_err(|_| StateError::Io(e))?;
            Self::restrict_to_owner(path);
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Synchronously saves the current state to the configured storage path.
    pub fn save_sync(&self) -> Result<(), StateError> {
        if let Some(path) = &self.storage_path {
            let data = self.inner.blocking_read().clone();
            Self::save_data_to_file(&data, path)?;
        }
        Ok(())
    }

    /// Asynchronously saves the current state to the configured storage path.
    pub async fn save_async(&self) -> Result<(), StateError> {
        if let Some(path) = &self.storage_path {
            let _guard = self.save_lock.lock().await;
            let data = self.inner.read().await.clone();
            let path_clone = path.clone();
            tokio::task::spawn_blocking(move || Self::save_data_to_file(&data, &path_clone))
                .await
                .map_err(|e| StateError::PathError(e.to_string()))??;
        }
        Ok(())
    }

    /// Returns a cloned snapshot of current `AppStateData`.
    pub async fn get_data(&self) -> AppStateData {
        self.inner.read().await.clone()
    }

    /// Direct async read lock.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, AppStateData> {
        self.inner.read().await
    }

    /// Direct async write lock.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, AppStateData> {
        self.inner.write().await
    }

    // --- Pinned IP & Strict Pinning ---

    pub async fn get_pinned_ip(&self) -> Option<String> {
        self.inner.read().await.pinned_ip.clone()
    }

    pub async fn set_pinned_ip(&self, ip: Option<String>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.pinned_ip = ip;
        }
        self.save_async().await
    }

    pub async fn is_strict_pinning_enabled(&self) -> bool {
        self.inner.read().await.strict_pinning_enabled
    }

    pub async fn set_strict_pinning_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.strict_pinning_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn is_auto_update_enabled(&self) -> bool {
        self.inner.read().await.auto_update_enabled
    }

    pub async fn set_auto_update_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.auto_update_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn is_autostart_enabled(&self) -> bool {
        self.inner.read().await.autostart_enabled
    }

    pub async fn set_autostart_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.autostart_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn is_cowork_guard_enabled(&self) -> bool {
        self.inner.read().await.cowork_guard_enabled
    }

    pub async fn set_cowork_guard_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.cowork_guard_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn set_sysproxy_enabled(&self, _enabled: bool) -> Result<(), StateError> {
        Ok(())
    }

    pub async fn set_cli_protection_enabled(&self, _enabled: bool) -> Result<(), StateError> {
        Ok(())
    }

    // --- Upstream Proxy Gateway ---

    pub async fn get_upstream_proxy(&self) -> Option<UpstreamProxyConfig> {
        self.inner.read().await.upstream_proxy.clone()
    }

    /// Legacy single-proxy setter, implemented on top of routes: `Some` installs the config as the
    /// legacy route (default route when `enabled`), `None` is the legacy "clear" (see
    /// [`Self::clear_legacy_route`]).
    pub async fn set_upstream_proxy(
        &self,
        proxy: Option<UpstreamProxyConfig>,
    ) -> Result<(), StateError> {
        match proxy.as_ref().and_then(|cfg| {
            Route::from_legacy(cfg, crate::auditor::network::current_timestamp())
        }) {
            Some(route) => self.install_legacy_route(route).await,
            None => self.clear_legacy_route().await,
        }
    }

    /// Installs `route` as the legacy route; it becomes the default route when enabled. Only the
    /// explicit legacy slot is ever replaced, never a route that merely serves as the default; a
    /// replaced legacy route nothing else uses is dropped, as the single slot used to be.
    pub async fn install_legacy_route(&self, route: Route) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            let previous = w.legacy_route_id.clone();
            let id = route.id.clone();
            let enabled = route.enabled;
            Self::upsert_route_locked(&mut w, route, false);
            w.legacy_route_id = Some(id.clone());
            if enabled {
                w.default_route_id = Some(id.clone());
            } else if w.default_route_id.as_deref() == Some(id.as_str()) {
                w.default_route_id = None;
            }
            self.route_health.remove(&id);
            if let Some(prev) = previous.filter(|p| *p != id) {
                if w.default_route_id.as_deref() == Some(prev.as_str()) {
                    w.default_route_id = if enabled { Some(id.clone()) } else { None };
                }
                if w.gc_legacy_route(&prev) {
                    self.route_health.remove(&prev);
                }
            }
            w.sync_legacy_mirror();
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Legacy "clear key": the key stops being the default for unbound providers and its legacy
    /// route is dropped, but ONLY the legacy role goes away. The profile route and explicit
    /// provider bindings are never touched; a route they still use is kept as an ordinary route.
    pub async fn clear_legacy_route(&self) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            match w.legacy_route_id.take() {
                Some(prev) => {
                    if w.default_route_id.as_deref() == Some(prev.as_str()) {
                        w.default_route_id = None;
                    }
                    if w.gc_legacy_route(&prev) {
                        self.route_health.remove(&prev);
                    }
                }
                None => {
                    // Legacy UI showed the default route: detach it, keep the route itself.
                    w.default_route_id = None;
                }
            }
            w.sync_legacy_mirror();
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Legacy toggle: enables the legacy route and makes it the default, or detaches it from the
    /// default slot (so unbound providers go direct, as in v1.3.x). Disabling never changes
    /// anything the profile route or an explicit binding uses.
    pub async fn toggle_legacy_upstream(
        &self,
        enabled: bool,
    ) -> Result<Option<UpstreamProxyConfig>, StateError> {
        let out = {
            let mut w = self.inner.write().await;
            let Some(id) = w.legacy_target_id().filter(|id| w.has_route(id)) else {
                return Ok(None);
            };
            // Used by the profile or an explicit binding: those must not be affected.
            let shared = w.provider_routes.values().any(|v| *v == id)
                || w.profile_route_id.as_deref() == Some(id.as_str());
            if enabled {
                if let Some(r) = w.routes.iter_mut().find(|r| r.id == id) {
                    r.enabled = true;
                }
                w.default_route_id = Some(id.clone());
            } else {
                if w.default_route_id.as_deref() == Some(id.as_str()) {
                    w.default_route_id = None;
                }
                if !shared {
                    if let Some(r) = w.routes.iter_mut().find(|r| r.id == id) {
                        r.enabled = false;
                    }
                }
            }
            w.legacy_route_id = Some(id);
            w.sync_legacy_mirror();
            self.bump_routing();
            w.upstream_proxy.clone()
        };
        self.save_async().await?;
        Ok(out)
    }

    // --- Routes ---

    /// Inserts or replaces (same id) a route. `preserve_enabled`: a re-import of an existing key
    /// must not silently re-enable a route the user disabled.
    fn upsert_route_locked(w: &mut AppStateData, mut route: Route, preserve_enabled: bool) {
        if let Some(existing) = w.routes.iter_mut().find(|r| r.id == route.id) {
            route.added_at = existing.added_at;
            if preserve_enabled {
                route.enabled = existing.enabled;
            }
            *existing = route;
        } else {
            w.routes.push(route);
        }
    }

    pub async fn get_routes(&self) -> Vec<Route> {
        self.inner.read().await.routes.clone()
    }

    pub async fn get_route(&self, id: &str) -> Option<Route> {
        self.inner.read().await.routes.iter().find(|r| r.id == id).cloned()
    }

    /// Adds or replaces (same id) a route; an existing route keeps its `enabled` flag. No
    /// validation here: keys are validated by the parser.
    pub async fn upsert_route(&self, route: Route) -> Result<String, StateError> {
        let id = route.id.clone();
        {
            let mut w = self.inner.write().await;
            Self::upsert_route_locked(&mut w, route, true);
            w.sync_legacy_mirror();
            self.route_health.remove(&id);
            self.bump_routing();
        }
        self.save_async().await?;
        Ok(id)
    }

    /// Removes a route. Bindings that point to it are NOT cleaned up: they become `Missing` and the
    /// providers stay blocked until the user binds another key or unbinds explicitly
    /// (`bind_provider_route(provider, null)` / `set_default_route(null)`).
    pub async fn remove_route(&self, id: &str) -> Result<bool, StateError> {
        let removed = {
            let mut w = self.inner.write().await;
            let removed = w.remove_route_locked(id);
            w.sync_legacy_mirror();
            self.route_health.remove(id);
            self.bump_routing();
            removed
        };
        self.save_async().await?;
        Ok(removed)
    }

    pub async fn set_route_enabled(&self, id: &str, enabled: bool) -> Result<bool, StateError> {
        let found = {
            let mut w = self.inner.write().await;
            let found = match w.routes.iter_mut().find(|r| r.id == id) {
                Some(r) => {
                    r.enabled = enabled;
                    true
                }
                None => false,
            };
            w.sync_legacy_mirror();
            self.bump_routing();
            found
        };
        self.save_async().await?;
        Ok(found)
    }

    /// Binds a provider (canonical id) to a route, or unbinds it with `None`.
    pub async fn bind_provider_route(
        &self,
        provider: &str,
        route_id: Option<&str>,
    ) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            match route_id {
                Some(id) => {
                    if !w.has_route(id) {
                        return Err(StateError::PathError(format!("unknown route id: {id}")));
                    }
                    w.provider_routes.insert(provider.to_string(), id.to_string());
                }
                None => {
                    w.provider_routes.remove(provider);
                }
            }
            self.bump_routing();
        }
        self.save_async().await
    }

    pub async fn set_default_route(&self, route_id: Option<&str>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            if let Some(id) = route_id {
                if !w.has_route(id) {
                    return Err(StateError::PathError(format!("unknown route id: {id}")));
                }
            }
            w.default_route_id = route_id.map(str::to_string);
            w.sync_legacy_mirror();
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Sets (or with `None` clears) the route of the active Claude profile; clears any "invalid".
    pub async fn set_profile_route(&self, route_id: Option<String>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            if route_id.as_deref().map(|id| !w.has_route(id)).unwrap_or(false) {
                return Err(StateError::PathError("unknown route id".to_string()));
            }
            w.profile_route_id = route_id;
            w.profile_route_invalid = None;
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Imports the key of the active Claude profile as a route and makes it the profile route, in
    /// one step (the previous profile's route is never left in place).
    pub async fn apply_profile_route(&self, route: Route) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            let id = route.id.clone();
            Self::upsert_route_locked(&mut w, route, true);
            w.profile_route_id = Some(id.clone());
            w.profile_route_invalid = None;
            w.sync_legacy_mirror();
            self.route_health.remove(&id);
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Fail-closed state for a profile whose key does not pass validation: no profile route, and
    /// Claude is blocked with `reason` until a valid key (or no key) is applied.
    pub async fn invalidate_profile_route(&self, reason: String) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.profile_route_id = None;
            w.profile_route_invalid = Some(reason.chars().take(300).collect());
            self.bump_routing();
        }
        self.save_async().await
    }

    // --- Manual kill-switch persistence ---

    pub async fn is_manual_killswitch_saved(&self) -> bool {
        self.inner.read().await.manual_killswitch
    }

    pub async fn set_manual_killswitch_saved(&self, on: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.manual_killswitch = on;
        }
        self.save_async().await
    }

    /// Effective routing decision for `provider` (see `crate::routing` for priorities).
    pub async fn route_selection(&self, provider: &str) -> RouteSelection {
        select_route(&*self.inner.read().await, provider)
    }

    pub async fn routed_providers(&self) -> Vec<&'static str> {
        self.inner.read().await.routed_providers()
    }

    pub async fn unrouted_providers(&self) -> Vec<&'static str> {
        self.inner.read().await.unrouted_providers()
    }

    /// Effective route id for a provider without cloning the route.
    pub async fn route_id_for_provider(&self, provider: &str) -> Option<String> {
        select_route_id(&*self.inner.read().await, provider)
    }

    // --- Warmup Timer ---

    pub async fn get_warmup_started_at(&self) -> Option<u64> {
        self.inner.read().await.warmup_started_at
    }

    pub async fn set_warmup_started_at(&self, started_at: Option<u64>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.warmup_started_at = started_at;
        }
        self.save_async().await
    }

    // --- Synced AI Timezone (CLI / IDE AI Agent TZ) ---

    pub async fn get_synced_ai_timezone(&self) -> Option<String> {
        self.inner.read().await.synced_ai_timezone.clone()
    }

    pub async fn set_synced_ai_timezone(&self, tz: Option<String>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.synced_ai_timezone = tz;
        }
        self.save_async().await
    }

    // --- Time zone / locale switch and CLI coverage mode ---

    pub async fn get_sync_ai_tz_enabled(&self) -> bool {
        self.inner.read().await.sync_ai_tz_enabled
    }

    pub async fn set_sync_ai_tz_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.sync_ai_tz_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn get_cli_mode(&self) -> CliMode {
        self.inner.read().await.cli_mode
    }

    pub async fn set_cli_mode(&self, mode: CliMode) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.cli_mode = mode;
        }
        self.save_async().await
    }

    /// The zone to apply now (see [`AppStateData::effective_sync_tz`]).
    pub async fn effective_sync_tz(&self) -> Option<String> {
        self.inner.read().await.effective_sync_tz()
    }

    // --- Preset Interception Behavior & Popup Position ---

    pub async fn get_interception_behavior(&self) -> InterceptionBehavior {
        self.inner.read().await.interception_behavior
    }

    pub async fn set_interception_behavior(&self, b: InterceptionBehavior) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.interception_behavior = b;
        }
        self.save_async().await
    }

    pub async fn get_popup_position(&self) -> PopupPosition {
        self.inner.read().await.popup_position
    }

    pub fn get_popup_position_sync(&self) -> PopupPosition {
        self.inner.try_read().map(|d| d.popup_position).unwrap_or_default()
    }

    pub async fn set_popup_position(&self, p: PopupPosition) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.popup_position = p;
        }
        self.save_async().await
    }

    // --- Custom AI Domains ---

    pub async fn get_custom_ai_domains(&self) -> Vec<String> {
        self.inner.read().await.custom_ai_domains.clone()
    }

    pub async fn add_custom_ai_domain(&self, domain: String) -> Result<Vec<String>, StateError> {
        let clean = domain.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
        let updated = {
            let mut w = self.inner.write().await;
            if !clean.is_empty() && !w.custom_ai_domains.iter().any(|d| d == &clean) {
                w.custom_ai_domains.push(clean);
            }
            w.custom_ai_domains.clone()
        };
        self.save_async().await?;
        Ok(updated)
    }

    pub async fn remove_custom_ai_domain(&self, domain: &str) -> Result<Vec<String>, StateError> {
        let clean = domain.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
        let updated = {
            let mut w = self.inner.write().await;
            w.custom_ai_domains.retain(|d| d != &clean);
            w.custom_ai_domains.clone()
        };
        self.save_async().await?;
        Ok(updated)
    }

    // --- IP History ---

    /// Appends a new IP history entry for the given provider, keeping at most 10 recent entries.
    /// Repeated sightings of the same IP/country only refresh the timestamp of the last entry
    /// (and are persisted at most once per minute) so busy sessions don't flood the disk.
    pub async fn record_ip_history(
        &self,
        provider: &str,
        entry: IpHistoryEntry,
    ) -> Result<(), StateError> {
        let mut should_save = true;
        {
            let mut w = self.inner.write().await;
            let history = w.ip_history.entry(provider.to_string()).or_default();

            let same_as_last = history
                .last()
                .map(|l| l.ip == entry.ip && l.country_code == entry.country_code)
                .unwrap_or(false);

            if same_as_last {
                if let Some(last) = history.last_mut() {
                    should_save = entry.timestamp.saturating_sub(last.timestamp) >= 60;
                    last.timestamp = last.timestamp.max(entry.timestamp);
                }
            } else {
                history.push(entry);
                if history.len() > MAX_HISTORY_ENTRIES_PER_PROVIDER {
                    let overflow = history.len() - MAX_HISTORY_ENTRIES_PER_PROVIDER;
                    history.drain(0..overflow);
                }
            }
        }
        if should_save {
            self.save_async().await
        } else {
            Ok(())
        }
    }

    pub async fn get_ip_history(&self, provider: &str) -> Vec<IpHistoryEntry> {
        self.inner
            .read()
            .await
            .ip_history
            .get(provider)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn get_last_ip_history(&self, provider: &str) -> Option<IpHistoryEntry> {
        self.inner
            .read()
            .await
            .ip_history
            .get(provider)
            .and_then(|h| h.last().cloned())
    }

    // --- Session Allowed Providers ("Accept risk & proceed") ---

    pub async fn allow_provider_for_session(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.session_allowed_providers.insert(provider.to_string());
            // An allowed provider is unblocked if previously marked blocked
            w.blocked_providers.remove(provider);
        }
        self.save_async().await
    }

    pub async fn is_provider_session_allowed(&self, provider: &str) -> bool {
        self.inner
            .read()
            .await
            .session_allowed_providers
            .contains(provider)
    }

    pub async fn revoke_session_allowed_provider(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.session_allowed_providers.remove(provider);
        }
        self.save_async().await
    }

    pub async fn clear_session_allowed_providers(&self) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.session_allowed_providers.clear();
        }
        self.save_async().await
    }

    // --- Blocked Providers ("Block requests until network change") ---

    pub async fn block_provider(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.blocked_providers.insert(provider.to_string());
            // When blocked, remove from session allowed
            w.session_allowed_providers.remove(provider);
        }
        self.save_async().await
    }

    pub async fn unblock_provider(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.blocked_providers.remove(provider);
        }
        self.save_async().await
    }

    pub async fn is_provider_blocked(&self, provider: &str) -> bool {
        self.inner.read().await.blocked_providers.contains(provider)
    }

    pub async fn clear_blocked_providers(&self) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.blocked_providers.clear();
        }
        self.save_async().await
    }

    pub async fn clear_ip_history_for_provider(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            if let Some(h) = w.ip_history.get_mut(provider) {
                h.clear();
            }
        }
        self.save_async().await
    }
}

/// Initializes `AppState` from the standard Tauri app data directory.
pub fn init_app_state<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<AppState, StateError> {
    use tauri::Manager;
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| StateError::PathError(e.to_string()))?;
    std::fs::create_dir_all(&app_data_dir)?;
    let state_file = app_data_dir.join(STATE_FILE_NAME);
    let state = AppState::load_or_default(state_file);
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_state_serialization_deserialization() {
        let mut original = AppStateData::default();
        original.pinned_ip = Some("185.220.101.5".to_string());
        original.strict_pinning_enabled = true;
        original
            .session_allowed_providers
            .insert("anthropic".to_string());
        original.blocked_providers.insert("gemini".to_string());

        let entry = IpHistoryEntry::new("185.220.101.5", "nl", Some(20473), 1730745600);
        original
            .ip_history
            .get_mut("anthropic")
            .unwrap()
            .push(entry.clone());

        let json = serde_json::to_string_pretty(&original).expect("serialize failed");
        let deserialized: AppStateData =
            serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(original, deserialized);
        assert_eq!(deserialized.pinned_ip.as_deref(), Some("185.220.101.5"));
        assert!(deserialized.strict_pinning_enabled);
        assert!(deserialized.session_allowed_providers.contains("anthropic"));
        assert!(deserialized.blocked_providers.contains("gemini"));

        let history = deserialized.ip_history.get("anthropic").unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].country_code, "NL");
        assert_eq!(history[0].asn, Some(20473));
    }

    #[test]
    fn test_asn_deserializer_variants() {
        let json_num = r#"{"ip":"1.1.1.1","country_code":"US","asn":13335,"timestamp":100}"#;
        let entry1: IpHistoryEntry = serde_json::from_str(json_num).unwrap();
        assert_eq!(entry1.asn, Some(13335));

        let json_str = r#"{"ip":"1.1.1.1","country_code":"US","asn":"AS13335","timestamp":100}"#;
        let entry2: IpHistoryEntry = serde_json::from_str(json_str).unwrap();
        assert_eq!(entry2.asn, Some(13335));

        let json_null = r#"{"ip":"1.1.1.1","country_code":"US","asn":null,"timestamp":100}"#;
        let entry3: IpHistoryEntry = serde_json::from_str(json_null).unwrap();
        assert_eq!(entry3.asn, None);

        let json_missing = r#"{"ip":"1.1.1.1","country_code":"US","timestamp":100}"#;
        let entry4: IpHistoryEntry = serde_json::from_str(json_missing).unwrap();
        assert_eq!(entry4.asn, None);
    }

    #[tokio::test]
    async fn test_persistence_save_load() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("state.json");

        let state = AppState::load_or_default(file_path.clone());
        assert_eq!(state.get_pinned_ip().await, None);
        assert!(!state.is_strict_pinning_enabled().await);

        // Mutate and verify auto-save
        state
            .set_pinned_ip(Some("95.217.1.1".to_string()))
            .await
            .expect("set pinned ip");
        state
            .set_strict_pinning_enabled(true)
            .await
            .expect("set strict pinning");

        // Reload fresh instance from disk
        let reloaded = AppState::load_or_default(file_path);
        assert_eq!(
            reloaded.get_pinned_ip().await,
            Some("95.217.1.1".to_string())
        );
        assert!(reloaded.is_strict_pinning_enabled().await);
    }

    #[tokio::test]
    async fn test_ip_history_max_10_entries() {
        let state = AppState::new_in_memory();

        // Push 15 entries
        for i in 1..=15 {
            let entry = IpHistoryEntry::new(
                format!("185.10.10.{}", i),
                "NL",
                Some(12345),
                1000 + i as u64,
            );
            state
                .record_ip_history("anthropic", entry)
                .await
                .expect("record history");
        }

        let history = state.get_ip_history("anthropic").await;
        assert_eq!(history.len(), 10);
        // Oldest entry kept should be i = 6
        assert_eq!(history[0].ip, "185.10.10.6");
        // Latest entry kept should be i = 15
        assert_eq!(history[9].ip, "185.10.10.15");

        let last = state.get_last_ip_history("anthropic").await.unwrap();
        assert_eq!(last.ip, "185.10.10.15");
    }

    #[tokio::test]
    async fn test_session_allowance_logic() {
        let state = AppState::new_in_memory();

        assert!(!state.is_provider_session_allowed("anthropic").await);

        state
            .allow_provider_for_session("anthropic")
            .await
            .expect("allow session");
        assert!(state.is_provider_session_allowed("anthropic").await);
        assert!(!state.is_provider_session_allowed("openai").await);

        state
            .revoke_session_allowed_provider("anthropic")
            .await
            .expect("revoke session");
        assert!(!state.is_provider_session_allowed("anthropic").await);

        state
            .allow_provider_for_session("anthropic")
            .await
            .expect("allow session");
        state
            .allow_provider_for_session("openai")
            .await
            .expect("allow session");
        state
            .clear_session_allowed_providers()
            .await
            .expect("clear all");
        assert!(!state.is_provider_session_allowed("anthropic").await);
        assert!(!state.is_provider_session_allowed("openai").await);
    }

    #[tokio::test]
    async fn test_provider_blocking_logic() {
        let state = AppState::new_in_memory();

        assert!(!state.is_provider_blocked("gemini").await);

        state.block_provider("gemini").await.expect("block provider");
        assert!(state.is_provider_blocked("gemini").await);

        // Blocking should revoke session allowed status if present
        state
            .allow_provider_for_session("openai")
            .await
            .expect("allow openai");
        assert!(state.is_provider_session_allowed("openai").await);
        state.block_provider("openai").await.expect("block openai");
        assert!(state.is_provider_blocked("openai").await);
        assert!(!state.is_provider_session_allowed("openai").await);

        // Allowing session should unblock provider
        state
            .allow_provider_for_session("openai")
            .await
            .expect("allow openai again");
        assert!(!state.is_provider_blocked("openai").await);
        assert!(state.is_provider_session_allowed("openai").await);

        state.unblock_provider("gemini").await.expect("unblock gemini");
        assert!(!state.is_provider_blocked("gemini").await);

        state.block_provider("anthropic").await.unwrap();
        state.clear_blocked_providers().await.unwrap();
        assert!(!state.is_provider_blocked("anthropic").await);
    }

    #[tokio::test]
    async fn test_upstream_proxy_and_warmup_timer_state() {
        let state = AppState::new_in_memory();

        assert_eq!(state.get_upstream_proxy().await, None);
        assert_eq!(state.get_warmup_started_at().await, None);

        let cfg = UpstreamProxyConfig {
            enabled: true,
            raw_key: "socks5://user:pass@127.0.0.1:1080#Custom".to_string(),
            protocol: "socks5".to_string(),
            host: "127.0.0.1".to_string(),
            port: 1080,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            label: Some("Custom".to_string()),
        };

        state.set_upstream_proxy(Some(cfg.clone())).await.expect("set upstream proxy");
        assert_eq!(state.get_upstream_proxy().await, Some(cfg));

        state.set_warmup_started_at(Some(1730000000)).await.expect("set warmup timer");
        assert_eq!(state.get_warmup_started_at().await, Some(1730000000));

        state.set_upstream_proxy(None).await.expect("clear upstream proxy");
        assert_eq!(state.get_upstream_proxy().await, None);

        state.set_warmup_started_at(None).await.expect("clear warmup timer");
        assert_eq!(state.get_warmup_started_at().await, None);

        // Synced AI timezone
        assert_eq!(state.get_synced_ai_timezone().await, None);
        state
            .set_synced_ai_timezone(Some("Europe/Amsterdam".to_string()))
            .await
            .expect("set synced ai tz");
        assert_eq!(
            state.get_synced_ai_timezone().await,
            Some("Europe/Amsterdam".to_string())
        );
        state
            .set_synced_ai_timezone(None)
            .await
            .expect("clear synced ai tz");
        assert_eq!(state.get_synced_ai_timezone().await, None);
    }

    #[tokio::test]
    async fn test_gateway_stats_tracker() {
        let state = AppState::new_in_memory();
        let tracker = state.stats();

        let initial = state.get_gateway_stats().await;
        assert_eq!(initial.protected_ai_requests, 0);
        assert_eq!(initial.intercepted_leaks, 0);
        assert_eq!(initial.direct_bypassed_requests, 0);
        assert_eq!(initial.active_ai_tunnels, 0);
        assert!(initial.recent_events.is_empty());

        // Increment direct bypass
        tracker.record_direct_bypassed();
        assert_eq!(state.get_gateway_stats().await.direct_bypassed_requests, 1);

        // Record protected events
        tracker.record_protected("api.anthropic.com", "anthropic", "GB");
        let snap1 = state.get_gateway_stats().await;
        assert_eq!(snap1.protected_ai_requests, 1);
        assert_eq!(snap1.last_protected_host.as_deref(), Some("api.anthropic.com"));
        assert_eq!(snap1.recent_events.len(), 1);
        assert_eq!(snap1.recent_events[0].action, "PROTECTED");
        assert_eq!(snap1.recent_events[0].host, "api.anthropic.com");

        // Record intercepted leak
        tracker.record_intercepted("api.openai.com", "openai", "HELD", "TR");
        let snap2 = state.get_gateway_stats().await;
        assert_eq!(snap2.intercepted_leaks, 1);
        assert_eq!(snap2.recent_events.len(), 2);
        assert_eq!(snap2.recent_events[1].action, "HELD");

        // Test active tunnel RAII guard
        {
            let guard = tracker.enter_tunnel();
            assert_eq!(state.get_gateway_stats().await.active_ai_tunnels, 1);
            drop(guard);
        }
        assert_eq!(state.get_gateway_stats().await.active_ai_tunnels, 0);

        // Test ring buffer caps at 20 events
        for i in 0..25 {
            tracker.record_protected(&format!("host-{i}.ai"), "gemini", "US");
        }
        let snap3 = state.get_gateway_stats().await;
        assert_eq!(snap3.recent_events.len(), 20);
        assert_eq!(snap3.recent_events.last().unwrap().host, "host-24.ai");

        // Test direct bypass recording and deduplication
        let prev_direct = snap3.direct_bypassed_requests;
        tracker.record_direct_bypassed_host("api.github.com");
        let snap4 = state.get_gateway_stats().await;
        assert_eq!(snap4.direct_bypassed_requests, prev_direct + 1);
        let last_ev = snap4.recent_events.last().unwrap();
        assert_eq!(last_ev.host, "api.github.com");
        assert_eq!(last_ev.provider, "Non-AI");
        assert_eq!(last_ev.action, "DIRECT");
        assert_eq!(last_ev.country, "DIRECT");
        assert_eq!(last_ev.kind.as_deref(), Some("direct"));
        let count_events = snap4.recent_events.len();

        // Same host called again -> deduplication updates timestamp without increasing queue length
        tracker.record_direct_bypassed_host("api.github.com");
        let snap5 = state.get_gateway_stats().await;
        assert_eq!(snap5.direct_bypassed_requests, prev_direct + 2);
        assert_eq!(snap5.recent_events.len(), count_events);
        assert_eq!(snap5.recent_events.last().unwrap().host, "api.github.com");

        // Different non-AI host -> appends new event
        tracker.record_direct_bypassed_host("registry.npmjs.org");
        let snap6 = state.get_gateway_stats().await;
        assert_eq!(snap6.direct_bypassed_requests, prev_direct + 3);
        assert_eq!(snap6.recent_events.last().unwrap().host, "registry.npmjs.org");
    }

    #[tokio::test]
    async fn test_interception_behavior_popup_position_and_custom_domains() {
        let state = AppState::new_in_memory();

        // Defaults
        assert_eq!(state.get_interception_behavior().await, InterceptionBehavior::AskPopup);
        assert_eq!(state.get_popup_position().await, PopupPosition::TopRight);
        assert!(state.get_custom_ai_domains().await.is_empty());

        // Update interception behavior
        state.set_interception_behavior(InterceptionBehavior::AutoLockSilent).await.unwrap();
        assert_eq!(state.get_interception_behavior().await, InterceptionBehavior::AutoLockSilent);

        state.set_interception_behavior(InterceptionBehavior::AutoAllowTrusted).await.unwrap();
        assert_eq!(state.get_interception_behavior().await, InterceptionBehavior::AutoAllowTrusted);

        // Update popup position
        state.set_popup_position(PopupPosition::TopCenter).await.unwrap();
        assert_eq!(state.get_popup_position().await, PopupPosition::TopCenter);

        // Custom AI domains management
        let domains = state.add_custom_ai_domain("my-local-llm.internal".to_string()).await.unwrap();
        assert_eq!(domains, vec!["my-local-llm.internal".to_string()]);
        assert_eq!(state.get_custom_ai_domains().await, vec!["my-local-llm.internal".to_string()]);

        // Trimming, leading wildcard normalization, and deduplication
        let domains = state.add_custom_ai_domain(" *.Custom-Model.ai ".to_string()).await.unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[1], "custom-model.ai");

        // Duplicate addition is idempotent
        let domains = state.add_custom_ai_domain("custom-model.ai".to_string()).await.unwrap();
        assert_eq!(domains.len(), 2);

        // Removal
        let domains = state.remove_custom_ai_domain("my-local-llm.internal").await.unwrap();
        assert_eq!(domains, vec!["custom-model.ai".to_string()]);
        assert_eq!(state.get_custom_ai_domains().await, vec!["custom-model.ai".to_string()]);
    }

    /// state.json exactly as written by v1.3.1 (no schema_version, single upstream_proxy).
    const V131_STATE_JSON: &str = r#"{
  "pinned_ip": "185.10.10.1",
  "strict_pinning_enabled": false,
  "ip_history": {"anthropic": [{"ip":"185.10.10.1","country_code":"NL","asn":20473,"timestamp":1730745600}], "openai": [], "gemini": []},
  "session_allowed_providers": ["anthropic"],
  "blocked_providers": [],
  "upstream_proxy": {
    "enabled": true,
    "raw_key": "socks5://alice:s3cret@185.10.10.2:1080#NL Gate",
    "protocol": "socks5",
    "host": "185.10.10.2",
    "port": 1080,
    "username": "alice",
    "password": "s3cret",
    "label": "NL Gate"
  },
  "warmup_started_at": null,
  "synced_ai_timezone": "Europe/Amsterdam",
  "auto_update_enabled": true,
  "interception_behavior": "ask_popup",
  "popup_position": "top_right",
  "custom_ai_domains": []
}"#;

    #[tokio::test]
    async fn test_migration_from_v131_state_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, V131_STATE_JSON).unwrap();

        let state = AppState::load_or_default(path.clone());
        let data = state.get_data().await;
        let expected_id =
            crate::routing::route_id_for_raw_key("socks5://alice:s3cret@185.10.10.2:1080#NL Gate");

        assert_eq!(data.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(data.routes.len(), 1);
        let r = &data.routes[0];
        assert_eq!(r.id, expected_id);
        assert_eq!(r.label, "NL Gate");
        assert!(r.enabled);
        assert_eq!(r.entries[0].proto, crate::routing::EntryProto::Socks5);
        assert_eq!(r.entries[0].host, "185.10.10.2");
        assert_eq!(r.entries[0].password.as_deref(), Some("s3cret"));
        assert_eq!(data.default_route_id.as_deref(), Some(expected_id.as_str()));
        assert_eq!(data.legacy_route_id.as_deref(), Some(expected_id.as_str()));
        // Untouched v1.3.1 fields survive.
        assert_eq!(data.pinned_ip.as_deref(), Some("185.10.10.1"));
        assert_eq!(data.synced_ai_timezone.as_deref(), Some("Europe/Amsterdam"));
        assert_eq!(data.ip_history["anthropic"].len(), 1);

        // Legacy mirror keeps the v1.3.1 shape for the current frontend.
        let mirror = state.get_upstream_proxy().await.expect("mirror");
        assert!(mirror.enabled);
        assert_eq!(mirror.raw_key, "socks5://alice:s3cret@185.10.10.2:1080#NL Gate");
        assert_eq!(mirror.protocol, "socks5");
        assert_eq!(mirror.port, 1080);
        assert_eq!(mirror.label.as_deref(), Some("NL Gate"));

        // Every AI provider without a binding now uses the migrated route.
        for p in KNOWN_PROVIDERS {
            assert!(matches!(state.route_selection(p).await, RouteSelection::Route(ref r) if r.id == expected_id));
        }

        // Migrated file was rewritten; a second load is stable (id does not change).
        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(on_disk["schema_version"], 2);
        let again = AppState::load_or_default(path).get_data().await;
        assert_eq!(again.routes, data.routes);
        assert_eq!(again.default_route_id, data.default_route_id);
    }

    #[test]
    fn test_migration_of_disabled_upstream_goes_direct() {
        let json = V131_STATE_JSON.replace("\"enabled\": true", "\"enabled\": false");
        let mut data: AppStateData = serde_json::from_str(&json).unwrap();
        assert_eq!(data.schema_version, 0);
        assert!(data.migrate(1));
        assert_eq!(data.routes.len(), 1);
        assert!(!data.routes[0].enabled);
        assert_eq!(data.default_route_id, None);
        assert_eq!(select_route(&data, "openai"), RouteSelection::Direct);
        assert_eq!(data.upstream_proxy.as_ref().map(|c| c.enabled), Some(false));
        // Idempotent.
        assert!(!data.migrate(2));
    }

    #[test]
    fn test_state_without_upstream_and_new_fields_loads() {
        let json = r#"{"pinned_ip": null, "auto_update_enabled": false}"#;
        let mut data: AppStateData = serde_json::from_str(json).unwrap();
        data.migrate(1);
        assert!(data.routes.is_empty());
        assert_eq!(data.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(data.upstream_proxy, None);
    }

    #[tokio::test]
    async fn test_legacy_commands_on_top_of_routes() {
        let state = AppState::new_in_memory();
        let cfg = UpstreamProxyConfig {
            enabled: true,
            raw_key: "socks5://185.1.1.1:1080".into(),
            protocol: "socks5".into(),
            host: "185.1.1.1".into(),
            port: 1080,
            username: None,
            password: None,
            label: Some("A".into()),
        };
        state.set_upstream_proxy(Some(cfg.clone())).await.unwrap();
        let id = state.get_data().await.default_route_id.clone().unwrap();

        // Toggle off: route kept, default detached -> unbound providers go direct (v1.3.x semantics).
        let off = state.toggle_legacy_upstream(false).await.unwrap().unwrap();
        assert!(!off.enabled);
        assert_eq!(state.route_selection("openai").await, RouteSelection::Direct);
        assert_eq!(state.get_routes().await.len(), 1);

        let on = state.toggle_legacy_upstream(true).await.unwrap().unwrap();
        assert!(on.enabled);
        assert!(matches!(state.route_selection("openai").await, RouteSelection::Route(_)));

        // Explicit binding survives replacing the legacy key, and is fail-closed when disabled.
        state.bind_provider_route("gemini", Some(&id)).await.unwrap();
        let mut cfg2 = cfg.clone();
        cfg2.raw_key = "socks5://185.2.2.2:1080".into();
        cfg2.host = "185.2.2.2".into();
        state.set_upstream_proxy(Some(cfg2)).await.unwrap();
        let data = state.get_data().await;
        assert_eq!(data.routes.len(), 2, "bound old route is kept");
        assert_ne!(data.default_route_id.as_deref(), Some(id.as_str()));
        state.set_route_enabled(&id, false).await.unwrap();
        match state.route_selection("gemini").await {
            RouteSelection::Route(r) => assert!(r.check_usable(0).is_err()),
            other => panic!("gemini must stay on its (disabled) route, got {other:?}"),
        }

        // Removing a route preserves provider bindings (fail-closed dangling route -> RouteSelection::Missing).
        state.remove_route(&id).await.unwrap();
        assert_eq!(
            state.get_data().await.provider_routes.get("gemini"),
            Some(&id)
        );
        assert_eq!(
            state.route_selection("gemini").await,
            RouteSelection::Missing(id.clone())
        );

        // clear_upstream_proxy removes the legacy route.
        state.set_upstream_proxy(None).await.unwrap();
        assert!(state.get_routes().await.is_empty());
        assert_eq!(state.get_upstream_proxy().await, None);
    }

    #[test]
    fn test_redacted_for_ui_hides_route_secrets() {
        let mut data: AppStateData = serde_json::from_str(V131_STATE_JSON).unwrap();
        data.migrate(1);
        let ui = serde_json::to_string(&data.redacted_for_ui().routes).unwrap();
        assert!(!ui.contains("s3cret"));
        assert!(!ui.contains("alice"));
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_json_and_copies_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");

        // A fresh state.json is created 0600.
        let state = AppState::load_or_default(path.clone());
        state.set_pinned_ip(Some("95.217.1.1".to_string())).await.unwrap();
        assert_eq!(mode_of(&path), 0o600, "new state.json");

        // An existing world-readable v1 file is tightened on load, and its backup is 0600 too.
        std::fs::write(&path, V131_STATE_JSON).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = AppState::load_or_default(path.clone());
        assert_eq!(mode_of(&path), 0o600, "loaded state.json");
        assert_eq!(mode_of(&dir.path().join(STATE_V1_BACKUP_NAME)), 0o600, "backup_v1");

        // An unreadable file leaves a 0600 corrupt copy.
        std::fs::write(&path, "{ not json").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = AppState::load_or_default(path.clone());
        let corrupt: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("state.corrupt-"))
            .collect();
        assert_eq!(corrupt.len(), 1);
        assert_eq!(mode_of(&corrupt[0].path()), 0o600, "state.corrupt copy");
        assert_eq!(mode_of(&path), 0o600, "rewritten state.json");
    }

    // --- time zone switch and CLI mode (2.1) ---

    #[test]
    fn state_json_of_2_0_0_without_the_new_fields_reads_with_the_defaults() {
        let data: AppStateData = serde_json::from_str(
            r#"{"schema_version": 2, "synced_ai_timezone": "Europe/Amsterdam", "auto_update_enabled": true}"#,
        )
        .unwrap();
        assert!(
            data.sync_ai_tz_enabled,
            "the switch is on unless the user turned it off"
        );
        assert!(!data.autostart_enabled);
        assert!(!data.cowork_guard_enabled);
        assert_eq!(data.cli_mode, CliMode::AiOnly);
        assert_eq!(data.synced_ai_timezone.as_deref(), Some("Europe/Amsterdam"));
        // The v1.3.1 file has neither field either.
        let old: AppStateData = serde_json::from_str(V131_STATE_JSON).unwrap();
        assert!(old.sync_ai_tz_enabled);
        assert_eq!(old.cli_mode, CliMode::AiOnly);
        assert_eq!(AppStateData::default().cli_mode, CliMode::AiOnly);
        assert!(AppStateData::default().sync_ai_tz_enabled);
    }

    #[test]
    fn cli_mode_is_snake_case_in_state_json() {
        assert_eq!(
            serde_json::to_string(&CliMode::AiOnly).unwrap(),
            "\"ai_only\""
        );
        assert_eq!(
            serde_json::to_string(&CliMode::GlobalTerminal).unwrap(),
            "\"global_terminal\""
        );
        let data: AppStateData =
            serde_json::from_str(r#"{"cli_mode": "global_terminal", "sync_ai_tz_enabled": false}"#)
                .unwrap();
        assert_eq!(data.cli_mode, CliMode::GlobalTerminal);
        assert!(!data.sync_ai_tz_enabled);
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["cli_mode"], "global_terminal");
        assert_eq!(json["sync_ai_tz_enabled"], false);
    }

    #[tokio::test]
    async fn the_switch_and_the_mode_are_saved_and_reloaded() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = AppState::load_or_default(path.clone());
        assert_eq!(state.get_cli_mode().await, CliMode::AiOnly);
        assert!(state.get_sync_ai_tz_enabled().await);
        state.set_cli_mode(CliMode::GlobalTerminal).await.unwrap();
        state.set_sync_ai_tz_enabled(false).await.unwrap();
        let reloaded = AppState::load_or_default(path.clone());
        assert_eq!(reloaded.get_cli_mode().await, CliMode::GlobalTerminal);
        assert!(!reloaded.get_sync_ai_tz_enabled().await);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "state.json stays private");
        }
    }

    #[tokio::test]
    async fn the_zone_to_apply_needs_the_switch_and_a_well_formed_name() {
        let state = AppState::new_in_memory();
        assert_eq!(state.effective_sync_tz().await, None, "no zone known");
        state
            .set_synced_ai_timezone(Some("Europe/Amsterdam".into()))
            .await
            .unwrap();
        assert_eq!(
            state.effective_sync_tz().await.as_deref(),
            Some("Europe/Amsterdam")
        );
        state.set_sync_ai_tz_enabled(false).await.unwrap();
        assert_eq!(
            state.effective_sync_tz().await,
            None,
            "switch off: nothing to apply"
        );
        // The zone stays remembered while the switch is off.
        assert_eq!(
            state.get_synced_ai_timezone().await.as_deref(),
            Some("Europe/Amsterdam")
        );
        state.set_sync_ai_tz_enabled(true).await.unwrap();
        state
            .set_synced_ai_timezone(Some("Europe/Berlin; rm -rf /".into()))
            .await
            .unwrap();
        assert_eq!(
            state.effective_sync_tz().await,
            None,
            "malformed name is never applied"
        );
    }
}
