//! Tauri commands for Clean Room audit, browser discovery, sandbox lifecycle, and tainted IP tracking.

pub mod profiles;

pub use profiles::{
    create_clean_profile, create_clean_profile_in, delete_clean_profile, delete_clean_profile_in,
    launch_clean_browser, list_clean_profiles, mark_clean_profile_tainted,
    prepare_clean_browser_launch_with_env, start_clean_profile_warmup, update_clean_profile_route,
    update_clean_profile_route_in, update_clean_profile_route_with_sandbox,
    update_clean_profile_step,
};

use std::path::{Path, PathBuf};

use tauri::Manager;

use super::AppContext;
use crate::auditor::Auditor;
use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::network::current_timestamp;
use crate::auditor::profile_switcher::list_claude_profiles;
use crate::clean_room::browser_discovery::discover_clean_browsers as discover_browsers_impl;
use crate::clean_room::detector::{
    DetectorEnv, DetectorInput, RealDetectorEnv, run_clean_room_audit_with,
};
use crate::clean_room::{CleanRoomAuditReport, CleanRoomProfile, CleanRoomState, DetectedBrowser};
use crate::routing::{DIRECT_ROUTE_ID, RouteSelection, select_route_id};
use crate::state::AppStateData;

pub(super) fn resolve_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("Не удалось определить папку данных приложения: {e}"))
}

pub fn normalize_alias_route_id(bound_route_id: Option<&str>) -> Option<String> {
    let route_id = bound_route_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DIRECT_ROUTE_ID);
    Some(route_id.to_string())
}

pub fn resolve_audit_provider(provider: Option<&str>) -> ProviderId {
    provider
        .and_then(|raw| {
            let trimmed = raw.trim();
            if trimmed.eq_ignore_ascii_case("custom") {
                None
            } else {
                ProviderId::from_id(trimmed)
            }
        })
        .unwrap_or(ProviderId::Anthropic)
}

fn route_selection_for_clean_profile(
    data: &AppStateData,
    bound_route_id: Option<&str>,
) -> RouteSelection {
    match bound_route_id {
        Some(id) if id == DIRECT_ROUTE_ID => RouteSelection::Direct,
        Some(id) => match data.routes.iter().find(|r| r.id == id) {
            Some(r) => RouteSelection::Route(r.clone()),
            None => RouteSelection::Missing(id.to_string()),
        },
        None => RouteSelection::Direct,
    }
}

pub(super) fn is_direct_route_arg(trimmed: &str) -> bool {
    trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("direct")
        || trimmed.eq_ignore_ascii_case(DIRECT_ROUTE_ID)
}

pub(super) fn resolve_clean_audit_route_selection(
    data: &AppStateData,
    provider: ProviderId,
    profile: Option<&CleanRoomProfile>,
    route_id: Option<&str>,
) -> RouteSelection {
    if let Some(explicit) = route_id {
        let trimmed = explicit.trim();
        if is_direct_route_arg(trimmed) {
            return RouteSelection::Direct;
        }
        return match data.routes.iter().find(|r| r.id == trimmed) {
            Some(r) => RouteSelection::Route(r.clone()),
            None => RouteSelection::Missing(trimmed.to_string()),
        };
    }

    if let Some(p) = profile {
        return route_selection_for_clean_profile(data, p.bound_route_id.as_deref());
    }

    if let Some(selected_id) = select_route_id(data, provider.as_str())
        && let Some(route) = data
            .routes
            .iter()
            .find(|r| r.id == selected_id && r.enabled)
    {
        return RouteSelection::Route(route.clone());
    }
    if let Some(default_id) = data.default_route_id.as_deref()
        && let Some(route) = data.routes.iter().find(|r| r.id == default_id && r.enabled)
    {
        return RouteSelection::Route(route.clone());
    }
    if let Some(first_enabled) = data.routes.iter().find(|r| r.enabled) {
        return RouteSelection::Route(first_enabled.clone());
    }
    RouteSelection::Direct
}

pub async fn run_clean_room_audit_with_env<E: DetectorEnv>(
    env: &E,
    data_dir: &Path,
    state: &AppContext,
    auditor: &Auditor,
    profile_id: Option<&str>,
) -> Result<CleanRoomAuditReport, String> {
    run_clean_room_audit_with_route_env(env, data_dir, state, auditor, profile_id, None).await
}

pub async fn run_clean_room_audit_with_route_env<E: DetectorEnv>(
    env: &E,
    data_dir: &Path,
    state: &AppContext,
    auditor: &Auditor,
    profile_id: Option<&str>,
    route_id: Option<&str>,
) -> Result<CleanRoomAuditReport, String> {
    let data = state.get_data().await;
    let profile = profile_id.and_then(|pid| data.clean_room.profiles.iter().find(|p| p.id == pid));

    let provider = resolve_audit_provider(profile.map(|p| p.provider.as_str()));
    let selection = resolve_clean_audit_route_selection(&data, provider, profile, route_id);

    let protection = crate::commands::audit::read_runtime_protection_flags().await;
    let (risk_report, audit_error) = match auditor
        .evaluate_all_with_selection_protection(provider, state, &selection, false, protection)
        .await
    {
        Ok(report) => (Some(report), None),
        Err(err) => (None, Some(err)),
    };

    let os_tz = crate::os_tz::get_os_timezone_sync_status(data_dir)
        .ok()
        .and_then(|s| s.current_os_tz);
    let claude_profiles = list_claude_profiles(None)
        .map(|r| r.profiles)
        .unwrap_or_default();

    Ok(run_clean_room_audit_with(
        env,
        &DetectorInput {
            target_provider: provider,
            target_profile_id: profile_id,
            risk_report: risk_report.as_ref(),
            audit_error: audit_error.as_deref(),
            state_data: &data,
            claude_profiles: &claude_profiles,
            os_tz: os_tz.as_deref(),
            now_secs: current_timestamp(),
        },
    ))
}

#[tauri::command]
pub async fn run_clean_room_audit(
    profile_id: Option<String>,
    route_id: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, Auditor>,
) -> Result<CleanRoomAuditReport, String> {
    let data_dir = resolve_data_dir(&app)?;
    run_clean_room_audit_with_route_env(
        &RealDetectorEnv,
        &data_dir,
        &state,
        &auditor,
        profile_id.as_deref(),
        route_id.as_deref(),
    )
    .await
}

#[tauri::command]
pub async fn discover_clean_browsers() -> Result<Vec<DetectedBrowser>, String> {
    Ok(discover_browsers_impl())
}

#[tauri::command]
pub async fn mark_ip_tainted(
    ip: Option<String>,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, Auditor>,
) -> Result<CleanRoomState, String> {
    let target_ip = match ip.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(explicit) => explicit,
        None => {
            let telemetry = auditor.resolver.resolve(false).await?;
            telemetry.ip
        }
    };
    let now = current_timestamp();
    let new_state = {
        let mut w = state.write().await;
        w.clean_room.tainted_ips.insert(target_ip, now);
        w.clean_room.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(new_state)
}

pub async fn untaint_clean_room_ip_in(
    ip: &str,
    state: &AppContext,
) -> Result<CleanRoomState, String> {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return Err("Укажите IP-адрес для снятия отметки.".to_string());
    }
    let parsed_target = trimmed.parse::<std::net::IpAddr>().ok();
    let new_state = {
        let mut w = state.write().await;
        w.clean_room.tainted_ips.retain(|key, _| {
            let k_trimmed = key.trim();
            if k_trimmed == trimmed {
                return false;
            }
            if let Some(target_ip) = parsed_target
                && let Ok(key_ip) = k_trimmed.parse::<std::net::IpAddr>()
            {
                return key_ip != target_ip;
            }
            true
        });
        w.clean_room.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(new_state)
}

#[tauri::command]
pub async fn untaint_clean_room_ip(
    ip: String,
    state: tauri::State<'_, AppContext>,
) -> Result<CleanRoomState, String> {
    untaint_clean_room_ip_in(&ip, &state).await
}
