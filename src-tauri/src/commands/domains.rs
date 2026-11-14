//! Custom AI domain list commands.

use crate::state;

#[tauri::command]
pub async fn get_custom_ai_domains_cmd(
    state: tauri::State<'_, state::AppState>,
) -> Result<Vec<String>, String> {
    Ok(state.get_custom_ai_domains().await)
}

#[tauri::command]
pub async fn add_custom_ai_domain_cmd(
    domain: String,
    state: tauri::State<'_, state::AppState>,
) -> Result<Vec<String>, String> {
    state
        .add_custom_ai_domain(domain)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_custom_ai_domain_cmd(
    domain: String,
    state: tauri::State<'_, state::AppState>,
) -> Result<Vec<String>, String> {
    state
        .remove_custom_ai_domain(&domain)
        .await
        .map_err(|e| e.to_string())
}
