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

/// Lists signed GitHub releases strictly older than the running version that have a `latest.json` manifest.
#[tauri::command]
pub async fn list_rollback_versions()
-> Result<Vec<updater::RollbackReleaseInfo>, updater::UpdateFailure> {
    updater::list_rollback_versions().await
}

/// Downloads, verifies (minisign), and installs a signed older release for rollback.
#[tauri::command]
pub async fn install_rollback_version(
    app: tauri::AppHandle,
    version: String,
) -> Result<updater::InstallUpdateResult, updater::UpdateFailure> {
    updater::install_rollback_version(&app, &version).await
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
