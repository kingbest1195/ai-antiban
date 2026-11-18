//! Persistent state schema types, constants, secret-redacting Debug impls, and UI redaction.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;

pub const PROVIDER_ANTHROPIC: &str = "anthropic";
pub const PROVIDER_OPENAI: &str = "openai";
pub const PROVIDER_GEMINI: &str = "gemini";
pub const KNOWN_PROVIDERS: [&str; 3] = [PROVIDER_ANTHROPIC, PROVIDER_OPENAI, PROVIDER_GEMINI];
pub const MAX_HISTORY_ENTRIES_PER_PROVIDER: usize = 10;
pub const DEFAULT_IP_CHANGE_COOLDOWN_SECS: u64 = 4 * 3600;
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
            if v >= 0 { Ok(Some(v as u32)) } else { Ok(None) }
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
            .field(
                "username",
                &self.username.as_deref().map(crate::routing::mask_secret),
            )
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
    /// Per-provider pinned exit IPs (`"anthropic"`, `"openai"`, `"gemini"`, and `"default"` for
    /// the Direct/VPN path). Keeps `pinned_ip` synchronized with `"default"` for backwards compat.
    #[serde(default)]
    pub pinned_ips: HashMap<String, String>,
    #[serde(default)]
    pub strict_pinning_enabled: bool,
    #[serde(default)]
    pub onboarding_v2_2_done: bool,
    #[serde(default)]
    pub hide_ip_mode: bool,
    #[serde(default)]
    pub ip_history: HashMap<String, Vec<IpHistoryEntry>>,
    #[serde(default)]
    pub session_allowed_providers: HashSet<String>,
    #[serde(default)]
    pub blocked_providers: HashSet<String>,
    /// Persistent per-(provider, exit_ip) forced-allow exceptions that survive restarts and network changes.
    #[serde(default)]
    pub trusted_exceptions: BTreeMap<String, Vec<String>>,
    /// Providers for which monitoring, PAC routing, auditing, blocking, and alerts are disabled.
    #[serde(default)]
    pub disabled_providers: HashSet<String>,
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
    pub routes: Vec<crate::routing::Route>,
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
    /// When true, split-tunnel/PAC routing is expected: IPv6 direct checks and NetworkGuard's
    /// general-interface exit IP jitter checks do not trigger false leak warnings or locks.
    #[serde(default)]
    pub split_tunnel_mode: bool,
    /// Routes of `state.json` this version does not understand (e.g. a future `proto`). They are
    /// skipped (their bindings become `Missing`, i.e. blocked) but written back unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_routes: Vec<serde_json::Value>,
    /// Unix timestamp (seconds) until which sudden IP/ASN changes require explicit user confirmation.
    #[serde(default)]
    pub ip_change_cooldown_until: Option<i64>,
    /// Unix timestamp (seconds) of the last Safe Logout of Claude Desktop/CLI.
    #[serde(default)]
    pub last_safe_logout_at: Option<i64>,
}

impl std::fmt::Debug for AppStateData {
    /// Secrets (passwords, raw keys, unknown route payloads) are masked.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStateData")
            .field("schema_version", &self.schema_version)
            .field("pinned_ip", &self.pinned_ip)
            .field("pinned_ips", &self.pinned_ips)
            .field("strict_pinning_enabled", &self.strict_pinning_enabled)
            .field("onboarding_v2_2_done", &self.onboarding_v2_2_done)
            .field("hide_ip_mode", &self.hide_ip_mode)
            .field("ip_history", &self.ip_history)
            .field("session_allowed_providers", &self.session_allowed_providers)
            .field("blocked_providers", &self.blocked_providers)
            .field("trusted_exceptions", &self.trusted_exceptions)
            .field("disabled_providers", &self.disabled_providers)
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
            .field("ip_change_cooldown_until", &self.ip_change_cooldown_until)
            .field("last_safe_logout_at", &self.last_safe_logout_at)
            .field(
                "skipped_routes",
                &format_args!("<{} not shown>", self.skipped_routes.len()),
            )
            .finish()
    }
}

impl AppStateData {
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
            pinned_ips: HashMap::new(),
            strict_pinning_enabled: false,
            onboarding_v2_2_done: false,
            hide_ip_mode: false,
            ip_history,
            session_allowed_providers: HashSet::new(),
            blocked_providers: HashSet::new(),
            trusted_exceptions: BTreeMap::new(),
            disabled_providers: HashSet::new(),
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
            split_tunnel_mode: false,
            skipped_routes: Vec::new(),
            ip_change_cooldown_until: None,
            last_safe_logout_at: None,
        }
    }
}
