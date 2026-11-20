//! Tauri commands for Clean Room audit, browser discovery, sandbox lifecycle, and tainted IP tracking.

use std::path::{Path, PathBuf};

use tauri::Manager;

use super::AppContext;
use crate::auditor::Auditor;
use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::network::current_timestamp;
use crate::auditor::profile_switcher::list_claude_profiles;
use crate::clean_room::browser_discovery::{
    discover_clean_browsers as discover_browsers_impl, resolve_browser_executable,
};
use crate::clean_room::browser_sandbox::{
    SandboxProcessRegistry, clean_profile_dir, launch_hardened_sandbox, terminate_sandbox_pid,
};
use crate::clean_room::detector::{
    DetectorEnv, DetectorInput, RealDetectorEnv, run_clean_room_audit_with,
};
use crate::clean_room::tz_guard::resolve_target_tz_for_spawn;
use crate::clean_room::{
    CleanProfileId, CleanProfileStatus, CleanRoomAuditReport, CleanRoomProfile, CleanRoomState,
    CreateCleanProfileInput, DetectedBrowser, LaunchCleanBrowserResult,
};
use crate::proxy::ProxyManager;
use crate::routing::{DIRECT_ROUTE_ID, RouteSelection};
use crate::state::AppStateData;

fn resolve_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))
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

pub async fn run_clean_room_audit_with_env<E: DetectorEnv>(
    env: &E,
    data_dir: &Path,
    state: &AppContext,
    auditor: &Auditor,
    profile_id: Option<&str>,
) -> Result<CleanRoomAuditReport, String> {
    let data = state.get_data().await;
    let profile = profile_id.and_then(|pid| data.clean_room.profiles.iter().find(|p| p.id == pid));

    let provider = resolve_audit_provider(profile.map(|p| p.provider.as_str()));
    let selection =
        route_selection_for_clean_profile(&data, profile.and_then(|p| p.bound_route_id.as_deref()));

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

async fn run_audit_internal(
    app: &tauri::AppHandle,
    state: &AppContext,
    auditor: &Auditor,
    profile_id: Option<&str>,
) -> Result<CleanRoomAuditReport, String> {
    let data_dir = resolve_data_dir(app)?;
    run_clean_room_audit_with_env(&RealDetectorEnv, &data_dir, state, auditor, profile_id).await
}

#[tauri::command]
pub async fn run_clean_room_audit(
    profile_id: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, Auditor>,
) -> Result<CleanRoomAuditReport, String> {
    run_audit_internal(&app, &state, &auditor, profile_id.as_deref()).await
}

#[tauri::command]
pub async fn discover_clean_browsers() -> Result<Vec<DetectedBrowser>, String> {
    Ok(discover_browsers_impl())
}

#[tauri::command]
pub async fn list_clean_profiles(
    state: tauri::State<'_, AppContext>,
) -> Result<CleanRoomState, String> {
    Ok(state.get_data().await.clean_room)
}

pub async fn create_clean_profile_in(
    input: CreateCleanProfileInput,
    state: &AppContext,
) -> Result<CleanRoomProfile, String> {
    let label = input.label.trim().to_string();
    if label.is_empty() {
        return Err("Profile label cannot be empty".to_string());
    }
    let trimmed_provider = input.provider.trim();
    let provider = if trimmed_provider.eq_ignore_ascii_case("custom") {
        "custom".to_string()
    } else {
        ProviderId::from_id(trimmed_provider)
            .map(|p| p.as_str().to_string())
            .ok_or_else(|| format!("Unknown provider: {}", input.provider))?
    };

    let raw_id = format!("cr-{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let profile_id = CleanProfileId::parse(&raw_id)?;

    let profile = CleanRoomProfile {
        id: profile_id.as_str().to_string(),
        label,
        provider,
        browser_engine: input.browser_engine.trim().to_ascii_lowercase(),
        bound_route_id: input.bound_route_id.filter(|s| !s.trim().is_empty()),
        last_exit_ip: None,
        last_exit_country: None,
        status: CleanProfileStatus::Active,
        created_at: current_timestamp(),
        last_opened_at: None,
        warmup_started_at: None,
        launchpad_step: 1,
        completed_checklist: Vec::new(),
    };

    {
        let mut w = state.write().await;
        w.clean_room.active_profile_id = Some(profile.id.clone());
        w.clean_room.profiles.push(profile.clone());
    }
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(profile)
}

#[tauri::command]
pub async fn create_clean_profile(
    input: CreateCleanProfileInput,
    state: tauri::State<'_, AppContext>,
) -> Result<CleanRoomProfile, String> {
    create_clean_profile_in(input, &state).await
}

#[tauri::command]
pub async fn update_clean_profile_step(
    profile_id: String,
    step: u8,
    completed_checklist: Option<Vec<String>>,
    state: tauri::State<'_, AppContext>,
) -> Result<CleanRoomProfile, String> {
    let id = CleanProfileId::parse(&profile_id)?;
    let clamped_step = step.clamp(1, 4);
    let updated = {
        let mut w = state.write().await;
        let profile = w
            .clean_room
            .profiles
            .iter_mut()
            .find(|p| p.id == id.as_str())
            .ok_or_else(|| format!("Clean Room profile not found: {}", id.as_str()))?;
        profile.launchpad_step = clamped_step;
        if let Some(list) = completed_checklist {
            profile.completed_checklist = list;
        }
        profile.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(updated)
}

#[tauri::command]
pub async fn start_clean_profile_warmup(
    profile_id: String,
    state: tauri::State<'_, AppContext>,
) -> Result<CleanRoomProfile, String> {
    let id = CleanProfileId::parse(&profile_id)?;
    let now = current_timestamp();
    let updated = {
        let mut w = state.write().await;
        let profile = w
            .clean_room
            .profiles
            .iter_mut()
            .find(|p| p.id == id.as_str())
            .ok_or_else(|| format!("Clean Room profile not found: {}", id.as_str()))?;
        let started_at = profile.warmup_started_at.unwrap_or(now);
        profile.warmup_started_at = Some(started_at);
        if profile.status == CleanProfileStatus::Active {
            profile.status = CleanProfileStatus::WarmingUp;
        }
        let cloned = profile.clone();
        w.warmup_started_at = Some(started_at);
        cloned
    };
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(updated)
}

pub async fn prepare_clean_browser_launch_with_env<E: DetectorEnv>(
    env: &E,
    data_dir: &Path,
    profile_id: &str,
    state: &AppContext,
    auditor: &Auditor,
    proxy_mgr: &ProxyManager,
) -> Result<(CleanProfileId, CleanRoomProfile, CleanRoomAuditReport, u16), String> {
    let id = CleanProfileId::parse(profile_id)?;
    let data = state.get_data().await;
    if data.manual_killswitch {
        return Err("Manual kill-switch is active: Clean Room launch is blocked".to_string());
    }
    let profile = data
        .clean_room
        .profiles
        .iter()
        .find(|p| p.id == id.as_str())
        .cloned()
        .ok_or_else(|| format!("Clean Room profile not found: {}", id.as_str()))?;

    if profile.status == CleanProfileStatus::Tainted {
        return Err(format!(
            "Clean Room profile '{}' is tainted and permanently locked",
            profile.label
        ));
    }

    let audit =
        run_clean_room_audit_with_env(env, data_dir, state, auditor, Some(id.as_str())).await?;
    if !audit.ready_to_launch {
        return Err(format!(
            "Hard Readiness Gate blocked launch ({} critical findings)",
            audit.critical_count
        ));
    }

    let normalized_route_id = normalize_alias_route_id(profile.bound_route_id.as_deref());
    let alias_port = proxy_mgr
        .ensure_profile_alias(id.as_str(), normalized_route_id)
        .await?;
    Ok((id, profile, audit, alias_port))
}

#[tauri::command]
pub async fn launch_clean_browser(
    profile_id: String,
    target_url: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, Auditor>,
    proxy_mgr: tauri::State<'_, ProxyManager>,
    sandbox_registry: tauri::State<'_, SandboxProcessRegistry>,
) -> Result<LaunchCleanBrowserResult, String> {
    let data_dir = resolve_data_dir(&app)?;
    let (id, profile, audit, alias_port) = prepare_clean_browser_launch_with_env(
        &RealDetectorEnv,
        &data_dir,
        &profile_id,
        &state,
        &auditor,
        &proxy_mgr,
    )
    .await?;
    let (engine, exe_path) = resolve_browser_executable(&profile.browser_engine)?;
    let tz_for_spawn =
        resolve_target_tz_for_spawn(cfg!(target_os = "macos"), audit.exit_timezone.as_deref());

    let result = launch_hardened_sandbox(
        &sandbox_registry,
        &data_dir,
        &id,
        &engine,
        &exe_path,
        alias_port,
        target_url.as_deref(),
        tz_for_spawn.as_deref(),
    )?;

    let now = current_timestamp();
    {
        let mut w = state.write().await;
        w.clean_room.active_profile_id = Some(id.as_str().to_string());
        if let Some(p) = w
            .clean_room
            .profiles
            .iter_mut()
            .find(|p| p.id == id.as_str())
        {
            p.last_opened_at = Some(now);
            if audit.exit_ip.is_some() {
                p.last_exit_ip = audit.exit_ip;
            }
            if audit.exit_country.is_some() {
                p.last_exit_country = audit.exit_country;
            }
        }
    }
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(result)
}

#[tauri::command]
pub async fn mark_clean_profile_tainted(
    profile_id: String,
    reason: Option<String>,
    state: tauri::State<'_, AppContext>,
    proxy_mgr: tauri::State<'_, ProxyManager>,
    sandbox_registry: tauri::State<'_, SandboxProcessRegistry>,
) -> Result<CleanRoomProfile, String> {
    let id = CleanProfileId::parse(&profile_id)?;
    let now = current_timestamp();
    let updated = {
        let mut w = state.write().await;
        let idx = w
            .clean_room
            .profiles
            .iter()
            .position(|p| p.id == id.as_str())
            .ok_or_else(|| format!("Clean Room profile not found: {}", id.as_str()))?;
        w.clean_room.profiles[idx].status = CleanProfileStatus::Tainted;
        if let Some(ip) = w.clean_room.profiles[idx].last_exit_ip.clone() {
            w.clean_room.tainted_ips.insert(ip, now);
        }
        w.clean_room.profiles[idx].clone()
    };
    if let Some(reason_text) = reason.as_deref() {
        crate::diagnostics::record(
            "clean_room",
            &format!("tainted {}: {reason_text}", id.as_str()),
        );
    }
    proxy_mgr.stop_profile_alias(id.as_str()).await;
    if let Some(proc_info) = sandbox_registry.remove(id.as_str()) {
        terminate_sandbox_pid(proc_info.pid);
    }
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(updated)
}

#[tauri::command]
pub async fn delete_clean_profile(
    profile_id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    proxy_mgr: tauri::State<'_, ProxyManager>,
    sandbox_registry: tauri::State<'_, SandboxProcessRegistry>,
) -> Result<CleanRoomState, String> {
    let id = CleanProfileId::parse(&profile_id)?;
    let now = current_timestamp();
    let new_state = {
        let mut w = state.write().await;
        let Some(pos) = w
            .clean_room
            .profiles
            .iter()
            .position(|p| p.id == id.as_str())
        else {
            return Err(format!("Clean Room profile not found: {}", id.as_str()));
        };
        let removed = w.clean_room.profiles.remove(pos);
        if let Some(ip) = removed.last_exit_ip {
            w.clean_room.tainted_ips.insert(ip, now);
        }
        if w.clean_room.active_profile_id.as_deref() == Some(id.as_str()) {
            w.clean_room.active_profile_id = None;
        }
        w.clean_room.clone()
    };

    proxy_mgr.stop_profile_alias(id.as_str()).await;
    if let Some(proc_info) = sandbox_registry.remove(id.as_str()) {
        terminate_sandbox_pid(proc_info.pid);
    }
    if let Ok(data_dir) = resolve_data_dir(&app) {
        let dir = clean_profile_dir(&data_dir, &id);
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(new_state)
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
