//! Tauri commands for v3.0 onboarding, "What's New" sheet, and dismissible HintCard flags.

use super::AppContext;
use crate::state::AppStateData;

#[tauri::command]
pub async fn complete_onboarding_v3(
    state: tauri::State<'_, AppContext>,
) -> Result<AppStateData, String> {
    let snapshot = {
        let mut w = state.write().await;
        w.onboarding_v3_done = true;
        w.whats_new_v3_seen = true;
        w.onboarding_v2_2_done = true;
        w.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(snapshot)
}

#[tauri::command]
pub async fn mark_whats_new_v3_seen(
    state: tauri::State<'_, AppContext>,
) -> Result<AppStateData, String> {
    let snapshot = {
        let mut w = state.write().await;
        w.whats_new_v3_seen = true;
        w.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(snapshot)
}

#[tauri::command]
pub async fn dismiss_hint(
    hint_id: String,
    state: tauri::State<'_, AppContext>,
) -> Result<AppStateData, String> {
    let clean = hint_id.trim().to_string();
    if clean.is_empty() {
        return Err("Hint ID cannot be empty".to_string());
    }
    let snapshot = {
        let mut w = state.write().await;
        if !w.dismissed_hints.iter().any(|h| h == &clean) {
            w.dismissed_hints.push(clean);
        }
        w.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(snapshot)
}

#[tauri::command]
pub async fn reset_dismissed_hints(
    state: tauri::State<'_, AppContext>,
) -> Result<AppStateData, String> {
    let snapshot = {
        let mut w = state.write().await;
        w.dismissed_hints.clear();
        w.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(snapshot)
}
