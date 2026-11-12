//! Audit, IP pinning, provider allow/unblock and state/stats read commands.

use crate::tray::update_tray_from_report;
use crate::{auditor, proxy, state};

#[tauri::command]
pub async fn get_state(state: tauri::State<'_, state::AppState>) -> Result<state::AppStateData, String> {
    // Route secrets are blanked; `upstream_proxy` keeps its v1.3.x shape (legacy/default route).
    Ok(state.get_data().await.redacted_for_ui())
}

#[tauri::command]
pub async fn audit_connection(
    provider: String,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
    app: tauri::AppHandle,
    force_refresh: Option<bool>,
) -> Result<auditor::RiskReport, String> {
    let provider_id = auditor::ProviderId::from_id(&provider)
        .ok_or_else(|| format!("Неизвестный провайдер: {provider}"))?;
    let report = match auditor
        .evaluate_all(provider_id, &state, force_refresh.unwrap_or(false))
        .await
    {
        Ok(report) => report,
        Err(e) => {
            // A failed primary audit must not leave the previous (possibly green) tray state;
            // a stop/block state stays as it is.
            if provider_id == auditor::ProviderId::Anthropic {
                let st = state.get_data().await;
                let has_blocked =
                    !st.blocked_providers.is_empty() || guard.gate() != proxy::Gate::Open;
                if !has_blocked {
                    crate::tray::update_tray_no_data(&app, None);
                }
            }
            return Err(e);
        }
    };

    // Sync system tray status whenever Anthropic or primary audit runs
    if provider_id == auditor::ProviderId::Anthropic || force_refresh.unwrap_or(false) {
        let st = state.get_data().await;
        let is_pinned = st
            .pinned_ip
            .as_ref()
            .map(|p| p.trim() == report.telemetry.ip.trim())
            .unwrap_or(false);
        let has_blocked =
            !st.blocked_providers.is_empty() || guard.gate() != proxy::Gate::Open;
        update_tray_from_report(&app, &report, is_pinned, has_blocked);
    }

    Ok(report)
}

#[tauri::command]
pub async fn pin_current_ip(
    ip: String,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    state
        .set_pinned_ip(Some(ip))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn unpin_ip(state: tauri::State<'_, state::AppState>) -> Result<(), String> {
    state.set_pinned_ip(None).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn toggle_strict_pinning(
    enabled: bool,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    state
        .set_strict_pinning_enabled(enabled)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn allow_provider_session(
    provider: String,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<(), String> {
    state
        .allow_provider_for_session(&provider)
        .await
        .map_err(|e| e.to_string())?;

    // Record current IP in history so Impossible Travel is acknowledged and cleared
    if let Some(provider_id) = auditor::ProviderId::from_id(&provider) {
        if let Ok(tel) = auditor.resolve_for_provider(provider_id, &state, false).await {
            let entry = state::IpHistoryEntry::new(
                tel.ip,
                tel.country_code,
                tel.asn,
                tel.resolved_at,
            );
            let _ = state.record_ip_history(provider_id.as_str(), entry).await;
        }
    }

    proxy_manager
        .hold_queue
        .resolve_all_for_provider(&provider, proxy::HoldResolution::Allow)
        .await;

    // If traffic was frozen after a network change, the user's manual confirmation resumes it
    proxy_manager.guard.accept_current().await;

    Ok(())
}

#[tauri::command]
pub async fn unblock_provider_cmd(
    provider: String,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
) -> Result<(), String> {
    state
        .unblock_provider(&provider)
        .await
        .map_err(|e| e.to_string())?;

    // Also update IP history to current IP so a stale Impossible Travel doesn't immediately re-flag
    if let Some(provider_id) = auditor::ProviderId::from_id(&provider) {
        if let Ok(tel) = auditor.resolve_for_provider(provider_id, &state, false).await {
            let entry = state::IpHistoryEntry::new(
                tel.ip,
                tel.country_code,
                tel.asn,
                tel.resolved_at,
            );
            let _ = state.record_ip_history(provider_id.as_str(), entry).await;
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn get_gateway_stats(
    state: tauri::State<'_, state::AppState>,
) -> Result<state::GatewayStatsSnapshot, String> {
    Ok(state.get_gateway_stats().await)
}
