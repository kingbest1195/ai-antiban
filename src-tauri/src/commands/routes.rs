//! Route (key) management commands. Responses never contain passwords or raw keys.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::AppContext;
use crate::auditor::network::current_timestamp;
use crate::routing::{self, RouteView, RoutesSnapshot};
use crate::{auditor, proxy};

/// Target used by `test_route` to measure the tunnel setup latency.
const TEST_TARGET_HOST: &str = "1.1.1.1";
const TEST_TARGET_PORT: u16 = 443;
const TEST_ENTRY_TIMEOUT_SECS: u64 = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteTestResult {
    pub ok: bool,
    pub exit_ip: Option<String>,
    pub country: Option<String>,
    pub latency_ms: Option<u64>,
    /// `None` when the key declares no `exit_ip`.
    pub exit_ip_matches: Option<bool>,
    pub error: Option<String>,
}

async fn snapshot(state: &AppContext) -> RoutesSnapshot {
    let data = state.get_data().await;
    routing::snapshot(&data, state.route_health(), current_timestamp())
}

/// Providers that just got a fixed exit no longer need blocks left by the network guard
/// ("until network change"). The manual kill-switch is never lifted here.
async fn release_routed_blocks(state: &AppContext, guard: &proxy::NetworkGuard) {
    if guard.is_manual_killswitch() || state.is_manual_killswitch_saved().await {
        return;
    }
    let routed = state.routed_providers().await;
    for p in &routed {
        let _ = state.unblock_provider(p).await;
    }
    guard.open_routed_providers(&routed);
}

fn canonical_provider(provider: &str) -> Result<&'static str, String> {
    auditor::ProviderId::from_id(provider)
        .map(|p| p.as_str())
        .ok_or_else(|| format!("Неизвестный провайдер: {provider}"))
}

#[tauri::command]
pub async fn list_routes(state: tauri::State<'_, AppContext>) -> Result<RoutesSnapshot, String> {
    Ok(snapshot(&state).await)
}

#[tauri::command]
pub async fn add_route(
    key: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, auditor::Auditor>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<RouteView, String> {
    let route = routing::parse_route_key(&key, current_timestamp())?;
    let _runtime_lock = super::claude::lock_profile_runtime().await;
    let raw_key = route.raw_key.clone();
    let id = state.upsert_route(route).await.map_err(|e| e.to_string())?;
    auditor.resolver.invalidate_route(&id).await;
    match auditor::profile_switcher::sync_profiles_for_route_update(&id, Some(&raw_key)) {
        Ok(Some(active_key)) => {
            crate::commands::claude::sync_active_profile_route_to_runtime(
                &state,
                &guard,
                active_key.as_deref(),
            )
            .await?;
            crate::tray::menu::refresh_profiles_submenu(&app);
        }
        Ok(None) => {
            crate::tray::menu::refresh_profiles_submenu(&app);
        }
        Err(err) => {
            crate::diagnostics::record("routes", &err);
        }
    }
    let data = state.get_data().await;
    let route = data
        .routes
        .iter()
        .find(|r| r.id == id)
        .ok_or("Маршрут не сохранён")?;
    Ok(routing::route_view(
        route,
        &data,
        state.route_health().get(&id),
        current_timestamp(),
    ))
}

#[tauri::command]
pub async fn remove_route(
    id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, auditor::Auditor>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<RoutesSnapshot, String> {
    let _runtime_lock = super::claude::lock_profile_runtime().await;
    let was_active_profile_route =
        state.get_data().await.profile_route_id.as_deref() == Some(id.as_str());
    if !state.remove_route(&id).await.map_err(|e| e.to_string())? {
        return Err(format!("Маршрут не найден: {id}"));
    }
    auditor.resolver.invalidate_route(&id).await;

    let profile_sync = auditor::profile_switcher::mark_profiles_route_removed(&id);
    let active_profile_affected = match &profile_sync {
        Ok(affected) => *affected || was_active_profile_route,
        Err(err) => {
            crate::diagnostics::record("routes", err);
            was_active_profile_route
        }
    };
    if active_profile_affected {
        // Fail-closed: preserve `profile_route_id = Some(id)` so `select_route("anthropic")`
        // returns `RouteSelection::Missing(id)` (`DanglingBinding`, 403) instead of falling back
        // to Direct / `default_route_id`.
        state
            .set_profile_route_dangling(id.clone())
            .await
            .map_err(|e| e.to_string())?;
    }
    if profile_sync.is_ok() {
        crate::tray::menu::refresh_profiles_submenu(&app);
    }

    let anthropic_routed = matches!(
        state.route_selection(crate::state::PROVIDER_ANTHROPIC).await,
        routing::RouteSelection::Route(_)
    );
    guard.sync_provider_route_change(crate::state::PROVIDER_ANTHROPIC, anthropic_routed);
    Ok(snapshot(&state).await)
}

#[tauri::command]
pub async fn set_route_enabled(
    id: String,
    enabled: bool,
    state: tauri::State<'_, AppContext>,
) -> Result<RoutesSnapshot, String> {
    if !state
        .set_route_enabled(&id, enabled)
        .await
        .map_err(|e| e.to_string())?
    {
        return Err(format!("Маршрут не найден: {id}"));
    }
    Ok(snapshot(&state).await)
}

#[tauri::command]
pub async fn bind_provider_route(
    provider: String,
    route_id: Option<String>,
    state: tauri::State<'_, AppContext>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<RoutesSnapshot, String> {
    let provider = canonical_provider(&provider)?;
    state
        .bind_provider_route(provider, route_id.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    release_routed_blocks(&state, &guard).await;
    let is_routed = matches!(
        state.route_selection(provider).await,
        routing::RouteSelection::Route(_)
    );
    guard.sync_provider_route_change(provider, is_routed);
    Ok(snapshot(&state).await)
}

#[tauri::command]
pub async fn set_default_route(
    route_id: Option<String>,
    state: tauri::State<'_, AppContext>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<RoutesSnapshot, String> {
    state
        .set_default_route(route_id.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    release_routed_blocks(&state, &guard).await;
    for provider in crate::state::KNOWN_PROVIDERS {
        let is_routed = matches!(
            state.route_selection(provider).await,
            routing::RouteSelection::Route(_)
        );
        guard.sync_provider_route_change(provider, is_routed);
    }
    Ok(snapshot(&state).await)
}

#[tauri::command]
pub async fn test_route(
    id: String,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, auditor::Auditor>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<RouteTestResult, String> {
    // The manual kill-switch stops everything: a test must not open a tunnel either.
    if guard.is_manual_killswitch() {
        return Err(
            "Включён «СТОП СЕТИ»: проверка маршрута отключена, пока блокировка не снята"
                .to_string(),
        );
    }
    let route = state
        .get_route(&id)
        .await
        .ok_or_else(|| format!("Маршрут не найден: {id}"))?;

    let started = Instant::now();
    let tunnel = proxy::upstream::connect_via_route(
        &route,
        TEST_TARGET_HOST,
        TEST_TARGET_PORT,
        Duration::from_secs(TEST_ENTRY_TIMEOUT_SECS),
        auditor.resolver.gateway_port(),
    )
    .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    if let Err(e) = tunnel {
        let msg = e.to_string();
        state.route_health().mark_unreachable(&id, &msg);
        return Ok(RouteTestResult {
            ok: false,
            exit_ip: None,
            country: None,
            latency_ms: None,
            exit_ip_matches: None,
            error: Some(msg),
        });
    }
    drop(tunnel);
    state.route_health().mark_reachable(&id);
    state.route_health().record_latency(&id, latency_ms);

    match auditor.resolve_route(&route, &state, true).await {
        Ok(tel) => Ok(RouteTestResult {
            ok: true,
            exit_ip_matches: route
                .exit_ip
                .as_deref()
                .map(|expected| routing::ip_equal(expected, &tel.ip)),
            exit_ip: Some(tel.ip),
            country: Some(tel.country_code),
            latency_ms: Some(latency_ms),
            error: None,
        }),
        // The tunnel works but the geo lookup through it failed: report it, keep the route reachable.
        Err(e) => Ok(RouteTestResult {
            ok: false,
            exit_ip: None,
            country: None,
            latency_ms: Some(latency_ms),
            exit_ip_matches: None,
            error: Some(e),
        }),
    }
}
