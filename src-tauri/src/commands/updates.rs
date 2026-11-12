//! Application update commands.

use crate::{state, updater};

#[tauri::command]
pub async fn check_for_updates(
    app: tauri::AppHandle,
) -> Result<updater::UpdateCheckResult, updater::UpdateFailure> {
    updater::check_for_updates(&app).await
}

/// Installs the update announced by the pinned, signed endpoint. Takes nothing from the frontend.
#[tauri::command]
pub async fn install_update(
    app: tauri::AppHandle,
) -> Result<updater::InstallUpdateResult, updater::UpdateFailure> {
    updater::install_update(&app).await
}

#[tauri::command]
pub async fn toggle_auto_update(
    enabled: bool,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    state
        .set_auto_update_enabled(enabled)
        .await
        .map_err(|e| e.to_string())
}
