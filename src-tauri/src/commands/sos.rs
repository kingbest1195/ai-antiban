//! Tauri commands for the proactive Persona Risk Index and behavioral self-check toggles.

use tauri::Manager;

use super::AppContext;
use crate::auditor::Auditor;
use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::network::current_timestamp;
use crate::auditor::persona_risk::{
    PersonaRiskInput, PersonaRiskReport, PersonaSelfCheckPatch, evaluate_persona_risk,
};
use crate::clean_room::detector_env::{DetectorEnv, RealDetectorEnv};

async fn build_persona_risk_report(
    app: &tauri::AppHandle,
    state: &AppContext,
    auditor: &Auditor,
) -> PersonaRiskReport {
    let state_data = state.get_data().await;
    let risk_report = auditor
        .evaluate_all(ProviderId::Anthropic, state, false)
        .await
        .ok();
    let data_dir = app.path().app_data_dir().ok();

    let (sysproxy_active, os_tz, has_personal_browser_traces, has_desktop_traces) =
        tokio::task::spawn_blocking(move || {
            let sysproxy_active = crate::sysproxy::is_sysproxy_active();
            let os_tz = data_dir
                .as_deref()
                .and_then(|d| crate::os_tz::get_os_timezone_sync_status(d).ok())
                .and_then(|s| s.current_os_tz);
            let env = RealDetectorEnv;
            let browser_traces = env
                .browser_profile_dirs()
                .into_iter()
                .any(|(_, p)| env.path_exists(&p));
            let desktop_traces = env
                .claude_data_dirs()
                .into_iter()
                .chain(env.chatgpt_data_dirs())
                .any(|d| {
                    env.path_exists(&d.join("Cookies")) || env.path_exists(&d.join("Local Storage"))
                });
            (sysproxy_active, os_tz, browser_traces, desktop_traces)
        })
        .await
        .unwrap_or((false, None, false, false));

    evaluate_persona_risk(&PersonaRiskInput {
        state_data: &state_data,
        risk_report: risk_report.as_ref(),
        sysproxy_active,
        os_tz: os_tz.as_deref(),
        has_personal_browser_traces,
        has_desktop_traces,
        now_secs: current_timestamp(),
    })
}

#[tauri::command]
pub async fn get_persona_risk_report(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, Auditor>,
) -> Result<PersonaRiskReport, String> {
    Ok(build_persona_risk_report(&app, &state, &auditor).await)
}

#[tauri::command]
pub async fn update_persona_self_check(
    patch: PersonaSelfCheckPatch,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, Auditor>,
) -> Result<PersonaRiskReport, String> {
    {
        let mut w = state.write().await;
        patch.apply_to(&mut w.persona_self_check);
    }
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(build_persona_risk_report(&app, &state, &auditor).await)
}

#[tauri::command]
pub async fn clean_antigravity_auth_cache()
-> Result<crate::auditor::cache_cleaner::CleanResult, String> {
    tokio::task::spawn_blocking(crate::auditor::cache_cleaner::clean_antigravity_auth_cache)
        .await
        .map_err(|e| format!("Clean Antigravity auth cache task failed: {e}"))
}
