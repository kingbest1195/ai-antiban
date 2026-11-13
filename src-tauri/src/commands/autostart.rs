//! Tauri commands for OS autostart and background AI service guard (`CoworkVMService` / macOS).

use crate::{autostart, cowork_guard, state};

#[tauri::command]
pub async fn get_autostart_status(
    state: tauri::State<'_, state::AppState>,
) -> Result<autostart::AutostartStatus, String> {
    let saved = state.is_autostart_enabled().await;
    Ok(tokio::task::spawn_blocking(move || autostart::get_status(saved))
        .await
        .map_err(|e| e.to_string())?)
}

#[tauri::command]
pub async fn set_autostart_enabled(
    enabled: bool,
    state: tauri::State<'_, state::AppState>,
) -> Result<autostart::AutostartStatus, String> {
    let active_in_os = tokio::task::spawn_blocking(move || autostart::apply_os_autostart(enabled))
        .await
        .map_err(|e| e.to_string())??;
    state
        .set_autostart_enabled(enabled)
        .await
        .map_err(|e| e.to_string())?;
    Ok(autostart::build_status(enabled, active_in_os))
}

#[tauri::command]
pub async fn get_cowork_guard_status() -> Result<cowork_guard::CoworkGuardStatus, String> {
    tokio::task::spawn_blocking(cowork_guard::get_cowork_guard_status)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn install_or_repair_cowork_guard(
    state: tauri::State<'_, state::AppState>,
) -> Result<cowork_guard::CoworkGuardStatus, String> {
    let status = tokio::task::spawn_blocking(cowork_guard::install_or_repair_cowork_guard)
        .await
        .map_err(|e| e.to_string())??;
    let enabled = status.task_installed && status.task_healthy;
    let _ = state.set_cowork_guard_enabled(enabled).await;
    Ok(status)
}
