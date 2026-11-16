//! Claude-specific commands: app cache cleaning, local data scan/export, multi-account profiles.

use crate::{auditor, proxy, routing, state, tray};
use std::sync::OnceLock;

static PROFILE_RUNTIME_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

pub(crate) async fn lock_profile_runtime() -> tokio::sync::MutexGuard<'static, ()> {
    PROFILE_RUNTIME_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

pub async fn sync_active_profile_binding_to_runtime(
    state: &state::AppState,
    guard: &proxy::NetworkGuard,
    pinned_ip: Option<String>,
    upstream_key: Option<&str>,
    expected_route_id: Option<&str>,
) -> Result<(), String> {
    if let Err(err) = state
        .set_pinned_ip_for(state::PROVIDER_ANTHROPIC, pinned_ip)
        .await
    {
        let msg = err.to_string();
        crate::diagnostics::record("profile", &msg);
        return Err(msg);
    }
    if let Err(err) = routing::apply_profile_binding(state, upstream_key, expected_route_id).await {
        crate::diagnostics::record("profile", &err);
        return Err(err);
    }
    if let Err(err) = state
        .clear_provider_blocks_and_session(state::PROVIDER_ANTHROPIC)
        .await
    {
        let msg = err.to_string();
        crate::diagnostics::record("profile", &msg);
        return Err(msg);
    }
    let is_routed = matches!(
        state.route_selection(state::PROVIDER_ANTHROPIC).await,
        routing::RouteSelection::Route(_)
    );
    guard.sync_provider_route_change(state::PROVIDER_ANTHROPIC, is_routed);
    Ok(())
}

pub async fn sync_active_profile_route_to_runtime(
    state: &state::AppState,
    guard: &proxy::NetworkGuard,
    upstream_key: Option<&str>,
) -> Result<(), String> {
    if let Err(err) = routing::apply_profile_key(state, upstream_key).await {
        crate::diagnostics::record("profile", &err);
        return Err(err);
    }
    if let Err(err) = state
        .clear_provider_blocks_and_session(state::PROVIDER_ANTHROPIC)
        .await
    {
        let msg = err.to_string();
        crate::diagnostics::record("profile", &msg);
        return Err(msg);
    }
    let is_routed = matches!(
        state.route_selection(state::PROVIDER_ANTHROPIC).await,
        routing::RouteSelection::Route(_)
    );
    guard.sync_provider_route_change(state::PROVIDER_ANTHROPIC, is_routed);
    Ok(())
}

pub async fn sync_active_profile_to_runtime(
    state: &state::AppState,
    guard: &proxy::NetworkGuard,
    pinned_ip: Option<String>,
    upstream_key: Option<&str>,
) -> Result<(), String> {
    let route_id = auditor::profile_switcher::resolve_route_id_for_key(upstream_key);
    sync_active_profile_binding_to_runtime(state, guard, pinned_ip, upstream_key, route_id.as_deref())
        .await
}

#[tauri::command]
pub async fn clean_app_cache(
    provider: String,
) -> Result<auditor::cache_cleaner::CleanResult, String> {
    let provider_id = auditor::ProviderId::from_id(&provider)
        .ok_or_else(|| format!("Неизвестный провайдер: {provider}"))?;
    Ok(auditor::clean_ai_app_cache(provider_id))
}

#[tauri::command]
pub fn scan_claude_data_cmd() -> Result<auditor::claude_exporter::ClaudeLocalDataSummary, String> {
    Ok(auditor::claude_exporter::scan_claude_local_data())
}

#[tauri::command]
pub async fn export_claude_data_cmd() -> Result<auditor::claude_exporter::ClaudeExportResult, String>
{
    tokio::task::spawn_blocking(auditor::claude_exporter::export_claude_local_data)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn list_claude_profiles_cmd(
    state: tauri::State<'_, state::AppState>,
) -> Result<auditor::profile_switcher::ClaudeProfileListResponse, String> {
    let pinned_ips = state.get_pinned_ips().await;
    let pinned_ip = pinned_ips
        .get(state::PROVIDER_ANTHROPIC)
        .or_else(|| pinned_ips.get("default"))
        .cloned();
    auditor::profile_switcher::list_claude_profiles(pinned_ip.as_deref())
}

#[tauri::command]
pub async fn create_claude_profile_cmd(
    name: String,
    bind_ip: Option<String>,
    bind_country: Option<String>,
    bind_upstream_key: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
) -> Result<auditor::profile_switcher::ClaudeProfileListResponse, String> {
    let bind_upstream_key = bind_upstream_key.filter(|k| !k.trim().is_empty());
    if let Some(ref k) = bind_upstream_key {
        let route = routing::parse_route_key(k, crate::auditor::network::current_timestamp())?;
        state.upsert_route(route).await.map_err(|e| e.to_string())?;
    }
    let resp = auditor::profile_switcher::create_claude_profile(
        &name,
        bind_ip,
        bind_country,
        bind_upstream_key,
    )?;
    tray::menu::refresh_profiles_submenu(&app);
    Ok(resp)
}

#[tauri::command]
pub async fn switch_claude_profile_cmd(
    target_id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<auditor::profile_switcher::ProfileSwitchResult, String> {
    let _runtime_lock = lock_profile_runtime().await;
    let res = auditor::profile_switcher::switch_claude_profile(&target_id)?;
    tray::menu::refresh_profiles_submenu(&app);
    sync_active_profile_binding_to_runtime(
        &state,
        &guard,
        res.pinned_ip_updated.clone(),
        res.bound_upstream_key_updated.as_deref(),
        res.active_profile.bound_route_id.as_deref(),
    )
    .await?;
    Ok(res)
}

#[tauri::command]
pub async fn delete_claude_profile_cmd(
    profile_id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<auditor::profile_switcher::ClaudeProfileListResponse, String> {
    let _runtime_lock = lock_profile_runtime().await;
    let prev_active_id = auditor::profile_switcher::active_profile_binding_state()
        .ok()
        .flatten()
        .map(|s| s.profile_id);
    let resp = auditor::profile_switcher::delete_claude_profile(&profile_id)?;
    tray::menu::refresh_profiles_submenu(&app);
    if prev_active_id.as_deref() != Some(resp.active_profile_id.as_str()) {
        // Deleting the active profile activated another one: apply its IP and route bindings.
        let active = resp
            .profiles
            .iter()
            .find(|p| p.id == resp.active_profile_id);
        sync_active_profile_binding_to_runtime(
            &state,
            &guard,
            active.and_then(|p| p.bound_ip.clone()),
            active.and_then(|p| p.bound_upstream_key.as_deref()),
            active.and_then(|p| p.bound_route_id.as_deref()),
        )
        .await?;
    }
    Ok(resp)
}

#[tauri::command]
pub async fn bind_ip_to_claude_profile_cmd(
    profile_id: String,
    bind_ip: Option<String>,
    bind_country: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
) -> Result<auditor::profile_switcher::ClaudeProfileListResponse, String> {
    let _runtime_lock = lock_profile_runtime().await;
    let resp =
        auditor::profile_switcher::update_profile_bound_ip(&profile_id, bind_ip.clone(), bind_country)?;
    tray::menu::refresh_profiles_submenu(&app);
    if resp.active_profile_id == profile_id
        && let Err(err) = state
            .set_pinned_ip_for(state::PROVIDER_ANTHROPIC, bind_ip)
            .await
    {
        let msg = err.to_string();
        crate::diagnostics::record("profile", &msg);
        return Err(msg);
    }
    Ok(resp)
}

#[tauri::command]
pub async fn bind_upstream_to_claude_profile_cmd(
    profile_id: String,
    upstream_key: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<auditor::profile_switcher::ClaudeProfileListResponse, String> {
    let _runtime_lock = lock_profile_runtime().await;
    let upstream_key = upstream_key.filter(|k| !k.trim().is_empty());
    // Validate before persisting so a profile never carries an unusable key.
    if let Some(ref k) = upstream_key {
        let route = routing::parse_route_key(k, crate::auditor::network::current_timestamp())?;
        state.upsert_route(route).await.map_err(|e| e.to_string())?;
    }
    let resp = auditor::profile_switcher::update_profile_bound_upstream(
        &profile_id,
        upstream_key.clone(),
    )?;
    tray::menu::refresh_profiles_submenu(&app);
    if resp.active_profile_id == profile_id {
        sync_active_profile_route_to_runtime(&state, &guard, upstream_key.as_deref()).await?;
    }
    Ok(resp)
}

#[tauri::command]
pub async fn bind_route_to_claude_profile(
    profile_id: String,
    route_id: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<auditor::profile_switcher::ClaudeProfileListResponse, String> {
    let _runtime_lock = lock_profile_runtime().await;
    let upstream_key = match route_id.filter(|id| !id.trim().is_empty()) {
        Some(rid) => {
            let data = state.get_data().await;
            let route = data
                .routes
                .iter()
                .find(|r| r.id == rid)
                .ok_or_else(|| format!("Маршрут не найден: {rid}"))?;
            let raw_key = route.raw_key.clone();
            routing::parse_route_key(&raw_key, crate::auditor::network::current_timestamp())?;
            Some(raw_key)
        }
        None => None,
    };

    let resp = auditor::profile_switcher::update_profile_bound_upstream(
        &profile_id,
        upstream_key.clone(),
    )?;
    tray::menu::refresh_profiles_submenu(&app);
    if resp.active_profile_id == profile_id {
        sync_active_profile_route_to_runtime(&state, &guard, upstream_key.as_deref()).await?;
    }
    Ok(resp)
}
