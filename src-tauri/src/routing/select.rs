//! Route selection, fingerprinting, raw-key masking, and profile route binding.

use std::hash::{Hash, Hasher};

use super::key::parse_route_key;
use super::{DIRECT_ROUTE_ID, INVALID_PROFILE_ROUTE_ID, Route, key};
use crate::state::{AppState, AppStateData, PROVIDER_ANTHROPIC};

/// The route id that should carry `provider` traffic, `None` = direct. While the profile key is
/// invalid, [`INVALID_PROFILE_ROUTE_ID`] is returned wherever the profile route would apply.
pub fn select_route_id(data: &AppStateData, provider: &str) -> Option<String> {
    let profile: Option<String> = if data.profile_route_invalid.is_some() {
        Some(INVALID_PROFILE_ROUTE_ID.to_string())
    } else {
        data.profile_route_id.clone()
    };
    let is_claude = provider == PROVIDER_ANTHROPIC;
    if is_claude && let Some(id) = profile.as_ref() {
        return Some(id.clone());
    }
    if let Some(id) = data.provider_routes.get(provider) {
        if id == DIRECT_ROUTE_ID {
            return None;
        }
        return Some(id.clone());
    }
    if let Some(id) = data.default_route_id.as_ref()
        && id != DIRECT_ROUTE_ID
    {
        return Some(id.clone());
    }
    None
}

/// Effective routing decision for a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteSelection {
    Direct,
    Route(Route),
    /// Bound to an id that does not exist (treated as down, never as direct).
    Missing(String),
    /// The key of the active Claude profile failed validation (treated as down, never as direct).
    Invalid(String),
}

pub fn select_route(data: &AppStateData, provider: &str) -> RouteSelection {
    match select_route_id(data, provider) {
        None => RouteSelection::Direct,
        Some(id) if id == INVALID_PROFILE_ROUTE_ID => {
            RouteSelection::Invalid(data.profile_route_invalid.clone().unwrap_or_default())
        }
        Some(id) => match data.routes.iter().find(|r| r.id == id) {
            Some(r) => RouteSelection::Route(r.clone()),
            None => RouteSelection::Missing(id),
        },
    }
}

/// Fingerprint of the nodes (and credentials) of a route: a route re-imported under the same id
/// with different nodes must not reuse the telemetry cached for the old ones.
pub fn route_fingerprint(route: &Route) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for e in &route.entries {
        e.proto.as_str().hash(&mut h);
        e.host.hash(&mut h);
        e.port.hash(&mut h);
        e.username.hash(&mut h);
        e.password.hash(&mut h);
        e.sni.hash(&mut h);
    }
    h.finish()
}

/// Display-safe form of a raw key: no credentials, no label (`socks5://host:port`).
pub fn mask_raw_key(raw: &str) -> String {
    let t = raw.trim();
    if t.to_ascii_lowercase().starts_with(key::ZASTAVA_SCHEME) {
        return "zastava://***".to_string();
    }
    let base = t.split('#').next().unwrap_or("");
    match url::Url::parse(base) {
        Ok(u) => match (u.host_str(), u.port()) {
            (Some(h), Some(p)) => format!("{}://{h}:{p}", u.scheme()),
            (Some(h), None) => format!("{}://{h}", u.scheme()),
            _ => "***".to_string(),
        },
        Err(_) => "***".to_string(),
    }
}

/// Applies the `bound_upstream_key` of the active Claude profile: the key becomes a route and the
/// highest-priority route for `anthropic`. `None` removes the override.
///
/// Fail-closed: when the key does not pass validation the previous profile's route is NOT kept
/// (that would send this account's traffic through another account's IP). The profile route is
/// marked invalid instead, Claude is blocked with that reason, and the error is returned.
pub async fn apply_profile_key(state: &AppState, key: Option<&str>) -> Result<(), String> {
    match key.map(str::trim).filter(|k| !k.is_empty()) {
        Some(k) => match parse_route_key(k, crate::auditor::network::current_timestamp()) {
            Ok(route) => state
                .apply_profile_route(route)
                .await
                .map_err(|e| e.to_string()),
            Err(msg) => {
                state
                    .invalidate_profile_route(msg.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                Err(msg)
            }
        },
        None => state
            .set_profile_route(None)
            .await
            .map_err(|e| e.to_string()),
    }
}

/// Applies the active Claude profile's route binding: if `key` is `Some(...)`, delegates to
/// [`apply_profile_key`]; if `key` is `None` while `expected_route_id` is `Some(rid)` (a route
/// that was removed while bound to this profile), retains `profile_route_id = Some(rid)` so
/// `anthropic` stays fail-closed as `RouteSelection::Missing` / `DanglingBinding`.
pub async fn apply_profile_binding(
    state: &AppState,
    key: Option<&str>,
    expected_route_id: Option<&str>,
) -> Result<(), String> {
    if key.map(str::trim).filter(|k| !k.is_empty()).is_some() {
        return apply_profile_key(state, key).await;
    }
    if let Some(rid) = expected_route_id.map(str::trim).filter(|s| !s.is_empty()) {
        return state
            .set_profile_route_dangling(rid.to_string())
            .await
            .map_err(|e| e.to_string());
    }
    state
        .set_profile_route(None)
        .await
        .map_err(|e| e.to_string())
}
