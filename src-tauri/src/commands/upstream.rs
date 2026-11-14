//! Legacy (v1.3.x) single upstream proxy commands, implemented on top of routes:
//! the key becomes the legacy route and the default route for unbound AI providers.
//!
//! Results carry no secrets (the interface ignores them). `clear_upstream_proxy` and
//! `toggle_upstream_proxy(false)` only end the legacy "default key" role; they never touch the
//! route of the Claude profile or explicit provider bindings.

use super::AppContext;
use crate::{routing, state};

#[tauri::command]
pub async fn set_upstream_proxy(
    key: String,
    state: tauri::State<'_, AppContext>,
) -> Result<state::UpstreamProxyConfig, String> {
    let route = routing::parse_route_key(&key, crate::auditor::network::current_timestamp())?;
    let cfg = route
        .to_legacy(true)
        .ok_or_else(|| "Key has no entry nodes".to_string())?;
    state
        .install_legacy_route(route)
        .await
        .map_err(|e| e.to_string())?;
    Ok(cfg.without_secrets())
}

#[tauri::command]
pub async fn toggle_upstream_proxy(
    enabled: bool,
    state: tauri::State<'_, AppContext>,
) -> Result<Option<state::UpstreamProxyConfig>, String> {
    state
        .toggle_legacy_upstream(enabled)
        .await
        .map(|c| c.map(|c| c.without_secrets()))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_upstream_proxy(state: tauri::State<'_, AppContext>) -> Result<bool, String> {
    state
        .clear_legacy_route()
        .await
        .map_err(|e| e.to_string())?;
    Ok(true)
}
