//! Runtime route health registry and secret-free UI snapshot views.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use super::select::select_route_id;
use super::{DIRECT_ROUTE_ID, EntryProto, Route, mask_secret};
use crate::state::AppStateData;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RouteHealth {
    /// `None` until the route was used or tested.
    pub reachable: Option<bool>,
    pub last_error: Option<String>,
    pub observed_exit_ip: Option<String>,
    pub observed_country: Option<String>,
    /// `None` when the key does not declare `exit_ip` or no exit was observed yet.
    pub exit_ip_matches: Option<bool>,
    pub latency_ms: Option<u64>,
    pub checked_at: u64,
}

#[derive(Debug, Default)]
pub struct RouteHealthRegistry {
    inner: RwLock<HashMap<String, RouteHealth>>,
}

pub fn ip_equal(a: &str, b: &str) -> bool {
    match (a.trim().parse::<IpAddr>(), b.trim().parse::<IpAddr>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a.trim().eq_ignore_ascii_case(b.trim()),
    }
}

impl RouteHealthRegistry {
    pub fn get(&self, id: &str) -> Option<RouteHealth> {
        self.inner.read().ok().and_then(|m| m.get(id).cloned())
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut RouteHealth)) {
        if let Ok(mut m) = self.inner.write() {
            let h = m.entry(id.to_string()).or_default();
            f(h);
            h.checked_at = crate::auditor::network::current_timestamp();
        }
    }

    pub fn mark_reachable(&self, id: &str) {
        self.update(id, |h| {
            h.reachable = Some(true);
            h.last_error = None;
        });
    }

    pub fn mark_unreachable(&self, id: &str, error: &str) {
        let err: String = error.chars().take(300).collect();
        self.update(id, |h| {
            h.reachable = Some(false);
            h.last_error = Some(err);
        });
    }

    pub fn record_latency(&self, id: &str, latency_ms: u64) {
        self.update(id, |h| h.latency_ms = Some(latency_ms));
    }

    /// Records the observed exit; returns whether it matches the key's declared `exit_ip`.
    pub fn record_exit(
        &self,
        id: &str,
        observed_ip: &str,
        observed_country: &str,
        expected_ip: Option<&str>,
    ) -> Option<bool> {
        let matches = expected_ip.map(|e| ip_equal(e, observed_ip));
        let ip = observed_ip.to_string();
        let cc = observed_country.to_string();
        self.update(id, |h| {
            h.reachable = Some(true);
            h.last_error = None;
            h.observed_exit_ip = Some(ip);
            h.observed_country = Some(cc);
            h.exit_ip_matches = matches;
        });
        matches
    }

    pub fn remove(&self, id: &str) {
        if let Ok(mut m) = self.inner.write() {
            m.remove(id);
        }
    }
}

// --- UI views (no secrets) ---

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Active,
    Disabled,
    Expired,
    Unreachable,
    ExitIpMismatch,
}

pub fn compute_status(route: &Route, health: Option<&RouteHealth>, now: u64) -> RouteStatus {
    if !route.enabled {
        return RouteStatus::Disabled;
    }
    if route.is_expired_at(now) {
        return RouteStatus::Expired;
    }
    if route.entries.is_empty() {
        return RouteStatus::Unreachable;
    }
    if let Some(h) = health {
        if h.reachable == Some(false) {
            return RouteStatus::Unreachable;
        }
        if h.exit_ip_matches == Some(false) {
            return RouteStatus::ExitIpMismatch;
        }
    }
    RouteStatus::Active
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryView {
    pub proto: EntryProto,
    pub host: String,
    pub port: u16,
    /// Masked (`ab***`), never the real value.
    pub username: Option<String>,
    pub has_password: bool,
    pub sni: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteView {
    pub id: String,
    pub label: String,
    pub country: Option<String>,
    pub exit_ip: Option<String>,
    pub expires_at: Option<u64>,
    pub enabled: bool,
    pub added_at: u64,
    pub entries: Vec<EntryView>,
    pub status: RouteStatus,
    pub is_default: bool,
    /// Providers explicitly bound via `bind_provider_route`.
    pub bound_providers: Vec<String>,
    /// Route of the active Claude profile (overrides the `anthropic` binding).
    pub is_profile_route: bool,
    pub health: Option<RouteHealth>,
}

/// A binding that points to a route which no longer exists. The provider stays blocked
/// (fail-closed) until the user picks another key or explicitly unbinds it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DanglingBinding {
    /// `provider` | `default` | `profile`
    pub kind: String,
    /// Set for `kind == "provider"`.
    pub provider: Option<String>,
    pub route_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutesSnapshot {
    pub routes: Vec<RouteView>,
    pub provider_routes: HashMap<String, String>,
    pub default_route_id: Option<String>,
    pub profile_route_id: Option<String>,
    /// Effective route id per known provider after applying priorities (`null` = direct). A
    /// provider that is blocked because its key is invalid maps to [`super::INVALID_PROFILE_ROUTE_ID`].
    pub effective: HashMap<String, Option<String>>,
    /// Why the active Claude profile's key cannot be used (`null` = fine). Claude is blocked.
    #[serde(default)]
    pub profile_route_error: Option<String>,
    /// Bindings whose route was removed (their providers are blocked, not direct).
    #[serde(default)]
    pub dangling: Vec<DanglingBinding>,
}

fn dangling_bindings(data: &AppStateData) -> Vec<DanglingBinding> {
    let mut out = Vec::new();
    let mut providers: Vec<(&String, &String)> = data.provider_routes.iter().collect();
    providers.sort();
    for (p, id) in providers {
        if id == DIRECT_ROUTE_ID {
            continue;
        }
        if !data.routes.iter().any(|r| r.id == *id) {
            out.push(DanglingBinding {
                kind: "provider".into(),
                provider: Some(p.clone()),
                route_id: id.clone(),
            });
        }
    }
    if let Some(id) = data.default_route_id.as_ref()
        && !data.routes.iter().any(|r| r.id == *id)
    {
        out.push(DanglingBinding {
            kind: "default".into(),
            provider: None,
            route_id: id.clone(),
        });
    }
    if let Some(id) = data.profile_route_id.as_ref()
        && !data.routes.iter().any(|r| r.id == *id)
    {
        out.push(DanglingBinding {
            kind: "profile".into(),
            provider: None,
            route_id: id.clone(),
        });
    }
    out
}

pub fn route_view(
    route: &Route,
    data: &AppStateData,
    health: Option<RouteHealth>,
    now: u64,
) -> RouteView {
    let mut bound: Vec<String> = data
        .provider_routes
        .iter()
        .filter(|(_, rid)| **rid == route.id)
        .map(|(p, _)| p.clone())
        .collect();
    bound.sort();
    RouteView {
        id: route.id.clone(),
        label: route.label.clone(),
        country: route.country.clone(),
        exit_ip: route.exit_ip.clone(),
        expires_at: route.expires_at,
        enabled: route.enabled,
        added_at: route.added_at,
        entries: route
            .entries
            .iter()
            .map(|e| EntryView {
                proto: e.proto,
                host: e.host.clone(),
                port: e.port,
                username: e.username.as_deref().map(mask_secret),
                has_password: e
                    .password
                    .as_deref()
                    .map(|p| !p.is_empty())
                    .unwrap_or(false),
                sni: e.sni.clone(),
            })
            .collect(),
        status: compute_status(route, health.as_ref(), now),
        is_default: data.default_route_id.as_deref() == Some(route.id.as_str()),
        bound_providers: bound,
        is_profile_route: data.profile_route_id.as_deref() == Some(route.id.as_str()),
        health,
    }
}

pub fn snapshot(data: &AppStateData, health: &RouteHealthRegistry, now: u64) -> RoutesSnapshot {
    let effective = crate::state::KNOWN_PROVIDERS
        .iter()
        .map(|p| (p.to_string(), select_route_id(data, p)))
        .collect();
    RoutesSnapshot {
        routes: data
            .routes
            .iter()
            .map(|r| route_view(r, data, health.get(&r.id), now))
            .collect(),
        provider_routes: data.provider_routes.clone(),
        default_route_id: data.default_route_id.clone(),
        profile_route_id: data.profile_route_id.clone(),
        effective,
        profile_route_error: data.profile_route_invalid.clone(),
        dangling: dangling_bindings(data),
    }
}
