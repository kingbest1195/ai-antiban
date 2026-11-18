//! Routes: per-provider egress through the entry nodes of an imported key.
//!
//! A [`Route`] is the parsed form of a key (`zastava://…`, `socks5://…`, `https://…`). Providers are
//! bound to routes in [`crate::state::AppStateData`]; the gateway resolves the effective route of a
//! provider with [`select_route_id`]:
//!
//! * `anthropic`: route of the active Claude profile (`profile_route_id`) -> explicit
//!   `provider_routes[provider]` -> `default_route_id` -> direct;
//! * every other provider: explicit `provider_routes[provider]` -> `default_route_id` -> direct
//!   (through whatever network / VPN the user has). A route bound to a Claude profile never
//!   leaks to other providers when `default_route_id` is `None`.
//!
//! Once a route is selected it is fail-closed: if it is disabled, expired, missing, invalid or
//! unreachable the connection is refused and never falls back to a direct connection.

pub mod key;
pub mod net;
mod select;
mod view;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::state::AppStateData;
use crate::state::UpstreamProxyConfig;

pub use key::parse_route_key;
pub use select::{
    RouteSelection, apply_profile_binding, apply_profile_key, mask_raw_key, route_fingerprint,
    select_route, select_route_id,
};
pub use view::{
    DanglingBinding, EntryView, RouteHealth, RouteHealthRegistry, RouteStatus, RouteView,
    RoutesSnapshot, compute_status, ip_equal, route_view, snapshot,
};

/// Maximum number of entry nodes in one key.
pub const MAX_ENTRIES: usize = 8;

/// Pseudo route id selected for the providers that follow the Claude profile while the profile's
/// key failed validation (see [`RouteSelection::Invalid`]). It never exists in `routes`.
pub const INVALID_PROFILE_ROUTE_ID: &str = "profile:invalid";

/// Sentinel stored in `provider_routes[provider]` to force direct (system/VPN) routing even when
/// `default_route_id` is configured. Unbinding (`None` / deleting the key) inherits `default_route_id`.
pub const DIRECT_ROUTE_ID: &str = "__direct__";

fn default_true() -> bool {
    true
}

/// Transport used to reach an entry node.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EntryProto {
    /// HTTP CONNECT proxy wrapped in TLS (certificate is always verified).
    Https,
    /// SOCKS5 (domain names are resolved by the node).
    Socks5,
    /// Plain-text HTTP CONNECT proxy.
    Http,
}

impl EntryProto {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryProto::Https => "https",
            EntryProto::Socks5 => "socks5",
            EntryProto::Http => "http",
        }
    }

    pub fn from_scheme(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "https" => Some(EntryProto::Https),
            "socks5" | "socks5h" => Some(EntryProto::Socks5),
            "http" => Some(EntryProto::Http),
            _ => None,
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            EntryProto::Https => 443,
            EntryProto::Socks5 => 1080,
            EntryProto::Http => 80,
        }
    }
}

/// One entry node of a route.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub proto: EntryProto,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// TLS server name for `https` entries (defaults to `host`).
    #[serde(default)]
    pub sni: Option<String>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("proto", &self.proto)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username.as_deref().map(mask_secret))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("sni", &self.sni)
            .finish()
    }
}

impl Entry {
    /// `host:port` with IPv6 literals bracketed (no credentials).
    pub fn endpoint(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn tls_server_name(&self) -> &str {
        self.sni
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.host)
    }
}

/// An imported key: where the traffic of the bound providers leaves to the Internet.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub country: Option<String>,
    /// Exit IP promised by the key (checked against the observed one, see [`RouteStatus::ExitIpMismatch`]).
    #[serde(default)]
    pub exit_ip: Option<String>,
    /// Unix seconds; the route is fail-closed once this moment has passed.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Entry nodes tried in order.
    pub entries: Vec<Entry>,
    pub raw_key: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub added_at: u64,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("country", &self.country)
            .field("exit_ip", &self.exit_ip)
            .field("expires_at", &self.expires_at)
            .field("entries", &self.entries)
            .field("raw_key", &"***")
            .field("enabled", &self.enabled)
            .field("added_at", &self.added_at)
            .finish()
    }
}

/// Why a selected route cannot carry traffic right now.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteDownReason {
    Disabled,
    Expired,
    NoEntries,
    /// The binding points to a route id that no longer exists.
    Missing,
    /// Every entry node failed.
    Unreachable,
    /// The key of the active Claude profile failed validation.
    Invalid,
}

impl RouteDownReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RouteDownReason::Disabled => "disabled",
            RouteDownReason::Expired => "expired",
            RouteDownReason::NoEntries => "no_entries",
            RouteDownReason::Missing => "missing",
            RouteDownReason::Unreachable => "unreachable",
            RouteDownReason::Invalid => "invalid",
        }
    }

    /// Generic reason for the client of the gateway (never names entry nodes).
    pub fn message(&self) -> &'static str {
        match self {
            RouteDownReason::Disabled => "route is disabled",
            RouteDownReason::Expired => "route key has expired",
            RouteDownReason::NoEntries => "route has no entry nodes",
            RouteDownReason::Missing => {
                "route key was removed: choose another key or allow a direct connection"
            }
            RouteDownReason::Unreachable => "the route's entry nodes are unreachable",
            RouteDownReason::Invalid => "the key of the active Claude profile is not valid",
        }
    }

    /// Same reason for the Zastava UI (Russian).
    pub fn message_ru(&self) -> &'static str {
        match self {
            RouteDownReason::Disabled => "маршрут отключён",
            RouteDownReason::Expired => "срок действия ключа истёк",
            RouteDownReason::NoEntries => "в маршруте нет входных нод",
            RouteDownReason::Missing => {
                "ключ удалён, выберите другой или разрешите прямое соединение"
            }
            RouteDownReason::Unreachable => "входные ноды маршрута недоступны",
            RouteDownReason::Invalid => "ключ активного профиля Claude не прошёл проверку",
        }
    }
}

impl Route {
    /// Keys typed by the user in URL form may point to the user's own local proxy; keys that come
    /// from outside (`zastava://…`) may not. See [`net`].
    pub fn allows_local_entries(&self) -> bool {
        !self
            .raw_key
            .trim_start()
            .to_ascii_lowercase()
            .starts_with(key::ZASTAVA_SCHEME)
    }

    pub fn is_expired_at(&self, now: u64) -> bool {
        self.expires_at.map(|e| e <= now).unwrap_or(false)
    }

    /// Static checks (no network): enabled, not expired, has entries.
    pub fn check_usable(&self, now: u64) -> Result<(), RouteDownReason> {
        if !self.enabled {
            return Err(RouteDownReason::Disabled);
        }
        if self.is_expired_at(now) {
            return Err(RouteDownReason::Expired);
        }
        if self.entries.is_empty() {
            return Err(RouteDownReason::NoEntries);
        }
        Ok(())
    }

    /// Converts a v1.3.x single upstream config. No validation: the user already accepted it.
    pub fn from_legacy(cfg: &UpstreamProxyConfig, now: u64) -> Option<Route> {
        let proto = EntryProto::from_scheme(&cfg.protocol)?;
        let host = cfg
            .host
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        if host.is_empty() || cfg.port == 0 {
            return None;
        }
        Some(Route {
            id: route_id_for_raw_key(&cfg.raw_key),
            label: cfg
                .label
                .clone()
                .filter(|l| !l.trim().is_empty())
                .unwrap_or_else(|| host.clone()),
            country: None,
            exit_ip: None,
            expires_at: None,
            entries: vec![Entry {
                proto,
                host,
                port: cfg.port,
                username: cfg.username.clone().filter(|u| !u.is_empty()),
                password: cfg.password.clone().filter(|p| !p.is_empty()),
                sni: None,
            }],
            raw_key: cfg.raw_key.clone(),
            enabled: cfg.enabled,
            added_at: now,
        })
    }

    /// Legacy single-proxy view (first entry) for the v1.3.x commands and `get_state`.
    pub fn to_legacy(&self, enabled: bool) -> Option<UpstreamProxyConfig> {
        let e = self.entries.first()?;
        Some(UpstreamProxyConfig {
            enabled,
            raw_key: self.raw_key.clone(),
            protocol: e.proto.as_str().to_string(),
            host: e.host.clone(),
            port: e.port,
            username: e.username.clone(),
            password: e.password.clone(),
            label: Some(self.label.clone()),
        })
    }
}

/// Stable id for keys that do not carry their own: `r-` + 24 hex chars of SHA-256(raw key).
pub fn route_id_for_raw_key(raw_key: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, raw_key.trim().as_bytes());
    let hex: String = digest.as_ref()[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("r-{hex}")
}

/// Masks a credential for display: `ab***`.
pub fn mask_secret(s: &str) -> String {
    let prefix: String = s.chars().take(2).collect();
    if s.chars().count() <= 2 {
        "***".to_string()
    } else {
        format!("{prefix}***")
    }
}
