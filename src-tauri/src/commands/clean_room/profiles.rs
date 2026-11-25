//! Clean Room profile CRUD, route rebinding, sandbox browser launch, and tainted IP controls.

use std::path::Path;

use super::super::AppContext;
use super::{
    is_direct_route_arg, normalize_alias_route_id, resolve_data_dir, run_clean_room_audit_with_env,
};
use crate::auditor::Auditor;
use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::network::current_timestamp;
use crate::clean_room::browser_discovery::resolve_browser_executable;
use crate::clean_room::browser_sandbox::{
    SandboxProcessRegistry, clean_profile_dir, launch_hardened_sandbox_with_country,
    read_sandbox_meta, terminate_sandbox_for_profile,
};
use crate::clean_room::detector::{DetectorEnv, RealDetectorEnv};
use crate::clean_room::tz_guard::resolve_target_tz_for_spawn;
use crate::clean_room::{
    CleanProfileId, CleanProfileStatus, CleanRoomAuditReport, CleanRoomProfile, CleanRoomState,
    CreateCleanProfileInput, LaunchCleanBrowserResult,
};
use crate::proxy::ProxyManager;

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
        return Err("Название профиля не может быть пустым.".to_string());
    }
    let trimmed_provider = input.provider.trim();
    let provider = if trimmed_provider.eq_ignore_ascii_case("custom") {
        "custom".to_string()
    } else {
        ProviderId::from_id(trimmed_provider)
            .map(|p| p.as_str().to_string())
            .ok_or_else(|| format!("Неизвестный ИИ-провайдер: {}", input.provider))?
    };

    let raw_id = format!("cr-{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let profile_id = CleanProfileId::parse(&raw_id)?;

    let profile = CleanRoomProfile {
        id: profile_id.as_str().to_string(),
        label,
        provider,
        browser_engine: input.browser_engine.trim().to_ascii_lowercase(),
        bound_route_id: input
            .bound_route_id
            .map(|s| s.trim().to_string())
            .filter(|s| !is_direct_route_arg(s)),
        last_exit_ip: None,
        last_exit_country: None,
        status: CleanProfileStatus::Active,
        created_at: current_timestamp(),
        last_opened_at: None,
        warmup_started_at: None,
        launchpad_step: 1,
        completed_checklist: Vec::new(),
        post_payment_quarantine: None,
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
            .ok_or_else(|| format!("Профиль «Чистой комнаты» не найден: {}", id.as_str()))?;
        profile.launchpad_step = clamped_step;
        if let Some(list) = completed_checklist {
            profile.completed_checklist = list;
        }
        profile.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(updated)
}

pub async fn update_clean_profile_route_in(
    profile_id: &str,
    route_id: Option<&str>,
    state: &AppContext,
    proxy_mgr: &ProxyManager,
) -> Result<CleanRoomProfile, String> {
    let id = CleanProfileId::parse(profile_id)?;
    let clean_route_id = route_id
        .map(str::trim)
        .filter(|s| !is_direct_route_arg(s))
        .map(str::to_string);

    let updated = {
        let mut w = state.write().await;
        if let Some(ref rid) = clean_route_id
            && !w.routes.iter().any(|r| r.id == *rid)
        {
            return Err(format!("Выбранный маршрут «{rid}» не найден."));
        }
        let profile = w
            .clean_room
            .profiles
            .iter_mut()
            .find(|p| p.id == id.as_str())
            .ok_or_else(|| format!("Профиль «Чистой комнаты» не найден: {}", id.as_str()))?;
        profile.bound_route_id = clean_route_id.clone();
        profile.clone()
    };

    state.save_async().await.map_err(|e| e.to_string())?;
    if proxy_mgr
        .get_profile_alias_port(id.as_str())
        .await
        .is_some()
    {
        let normalized_route_id = normalize_alias_route_id(clean_route_id.as_deref());
        let alias_provider = ProviderId::from_id(&updated.provider);
        proxy_mgr
            .ensure_profile_alias_with_provider(
                id.as_str(),
                normalized_route_id,
                alias_provider,
                None,
            )
            .await?;
    }
    Ok(updated)
}

pub async fn update_clean_profile_route_with_sandbox(
    profile_id: &str,
    route_id: Option<&str>,
    data_dir: Option<&Path>,
    state: &AppContext,
    proxy_mgr: &ProxyManager,
    sandbox_registry: &SandboxProcessRegistry,
) -> Result<CleanRoomProfile, String> {
    let updated = update_clean_profile_route_in(profile_id, route_id, state, proxy_mgr).await?;
    if let Some(new_port) = proxy_mgr.get_profile_alias_port(updated.id.as_str()).await {
        let profile_dir = data_dir
            .map(|d| d.join("clean-profiles").join(&updated.id))
            .unwrap_or_default();
        let saved_port = if !profile_dir.as_os_str().is_empty() {
            read_sandbox_meta(&profile_dir).map(|m| m.alias_port)
        } else {
            None
        };
        let tracked_port = sandbox_registry
            .get(updated.id.as_str())
            .map(|p| p.alias_port);
        let stale_port = saved_port.is_some_and(|p| p != new_port)
            || tracked_port.is_some_and(|p| p != new_port);
        if stale_port {
            terminate_sandbox_for_profile(sandbox_registry, &profile_dir, updated.id.as_str());
        }
    }
    Ok(updated)
}

#[tauri::command]
pub async fn update_clean_profile_route(
    profile_id: String,
    route_id: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    proxy_mgr: tauri::State<'_, ProxyManager>,
    sandbox_registry: tauri::State<'_, SandboxProcessRegistry>,
) -> Result<CleanRoomProfile, String> {
    let data_dir = resolve_data_dir(&app).ok();
    update_clean_profile_route_with_sandbox(
        &profile_id,
        route_id.as_deref(),
        data_dir.as_deref(),
        &state,
        &proxy_mgr,
        &sandbox_registry,
    )
    .await
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
            .ok_or_else(|| format!("Профиль «Чистой комнаты» не найден: {}", id.as_str()))?;
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
        return Err("Включена ручная блокировка сети: запуск песочницы остановлен.".to_string());
    }
    let profile = data
        .clean_room
        .profiles
        .iter()
        .find(|p| p.id == id.as_str())
        .cloned()
        .ok_or_else(|| format!("Профиль «Чистой комнаты» не найден: {}", id.as_str()))?;

    if profile.status == CleanProfileStatus::Tainted {
        return Err(format!(
            "Профиль «{}» отмечен после блокировки и заблокирован для запуска.",
            profile.label
        ));
    }

    let audit =
        run_clean_room_audit_with_env(env, data_dir, state, auditor, Some(id.as_str())).await?;
    if !audit.ready_to_launch {
        return Err(format!(
            "Запуск песочницы заблокирован проверкой безопасности (критических замечаний: {}).",
            audit.critical_count
        ));
    }

    let normalized_route_id = normalize_alias_route_id(profile.bound_route_id.as_deref());
    let alias_provider = ProviderId::from_id(&profile.provider);
    let profile_dir = clean_profile_dir(data_dir, &id);
    let preferred_port = read_sandbox_meta(&profile_dir).map(|m| m.alias_port);
    let alias_port = proxy_mgr
        .ensure_profile_alias_with_provider(
            id.as_str(),
            normalized_route_id,
            alias_provider,
            preferred_port,
        )
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

    let result = launch_hardened_sandbox_with_country(
        &sandbox_registry,
        &data_dir,
        &id,
        &engine,
        &exe_path,
        alias_port,
        target_url.as_deref(),
        tz_for_spawn.as_deref(),
        audit.exit_country.as_deref(),
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
    app: tauri::AppHandle,
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
            .ok_or_else(|| format!("Профиль «Чистой комнаты» не найден: {}", id.as_str()))?;
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
    if let Ok(data_dir) = resolve_data_dir(&app) {
        let profile_dir = clean_profile_dir(&data_dir, &id);
        terminate_sandbox_for_profile(&sandbox_registry, &profile_dir, id.as_str());
    } else {
        terminate_sandbox_for_profile(&sandbox_registry, Path::new(""), id.as_str());
    }
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(updated)
}

pub async fn delete_clean_profile_in(
    profile_id: &str,
    taint_exit_ip: Option<bool>,
    data_dir: Option<&Path>,
    state: &AppContext,
    proxy_mgr: &ProxyManager,
    sandbox_registry: &SandboxProcessRegistry,
) -> Result<CleanRoomState, String> {
    let id = CleanProfileId::parse(profile_id)?;
    let now = current_timestamp();
    let should_taint = taint_exit_ip == Some(true);
    let new_state = {
        let mut w = state.write().await;
        let Some(pos) = w
            .clean_room
            .profiles
            .iter()
            .position(|p| p.id == id.as_str())
        else {
            return Err(format!(
                "Профиль «Чистой комнаты» не найден: {}",
                id.as_str()
            ));
        };
        let removed = w.clean_room.profiles.remove(pos);
        if should_taint && let Some(ip) = removed.last_exit_ip {
            w.clean_room.tainted_ips.insert(ip, now);
        }
        if w.clean_room.active_profile_id.as_deref() == Some(id.as_str()) {
            w.clean_room.active_profile_id = None;
        }
        w.clean_room.clone()
    };

    proxy_mgr.stop_profile_alias(id.as_str()).await;
    if let Some(dir_root) = data_dir {
        let dir = clean_profile_dir(dir_root, &id);
        terminate_sandbox_for_profile(sandbox_registry, &dir, id.as_str());
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
    } else {
        terminate_sandbox_for_profile(sandbox_registry, Path::new(""), id.as_str());
    }
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(new_state)
}

#[tauri::command]
pub async fn delete_clean_profile(
    profile_id: String,
    taint_exit_ip: Option<bool>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    proxy_mgr: tauri::State<'_, ProxyManager>,
    sandbox_registry: tauri::State<'_, SandboxProcessRegistry>,
) -> Result<CleanRoomState, String> {
    let data_dir = resolve_data_dir(&app).ok();
    delete_clean_profile_in(
        &profile_id,
        taint_exit_ip,
        data_dir.as_deref(),
        &state,
        &proxy_mgr,
        &sandbox_registry,
    )
    .await
}

pub use super::{mark_ip_tainted, untaint_clean_room_ip, untaint_clean_room_ip_in};
