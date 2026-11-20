//! Audit, IP pinning, provider allow/unblock and state/stats read commands.

mod helpers;

use crate::tray::update_tray_from_report;
use crate::{auditor, proxy, state};
use helpers::resolve_exit_ip_for_provider;
use std::sync::Arc;
use tauri::{Emitter, Manager};

pub(crate) use helpers::{
    AuditProgressEvent, clear_trusted_exceptions_inner, finalize_audit_report_for_state,
    is_ip_pinned_for_state, remove_trusted_exception_inner, set_provider_monitoring_inner,
    should_verify_unblock,
};

fn read_os_pac_deferred() -> bool {
    #[cfg(target_os = "macos")]
    {
        if !crate::sysproxy::os_effects_enabled() || !crate::sysproxy::is_sysproxy_active() {
            return false;
        }
        use crate::sysproxy::platform::{Platform, RealPlatform};
        !matches!(RealPlatform.temp_dns_overrides(), Ok(false))
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

pub(crate) async fn read_runtime_protection_flags() -> auditor::AuditProtectionFlags {
    tokio::task::spawn_blocking(|| auditor::AuditProtectionFlags {
        sysproxy_active: crate::sysproxy::is_sysproxy_active(),
        cli_or_sandbox_protection_active: crate::sysproxy::is_cli_protection_enabled(),
        os_pac_deferred: read_os_pac_deferred(),
    })
    .await
    .unwrap_or_default()
}

#[cfg(test)]
pub(crate) use helpers::{allow_provider_session_inner, pin_ip_inner, unpin_ip_inner};

/// Event with the pieces of a running audit (see `audit_connection`, argument `run_id`).
pub const AUDIT_PROGRESS_EVENT: &str = "audit://progress";

#[tauri::command]
pub async fn get_state(
    state: tauri::State<'_, state::AppState>,
) -> Result<state::AppStateData, String> {
    // Route secrets are blanked; `upstream_proxy` keeps its v1.3.x shape (legacy/default route).
    Ok(state.get_data().await.redacted_for_ui())
}

/// Where the background start is: the interface shows "checking" while it is `starting`.
#[tauri::command]
pub fn get_startup_state(
    startup: tauri::State<'_, Arc<crate::startup::StartupState>>,
) -> crate::startup::StartupSnapshot {
    startup.snapshot()
}

#[tauri::command]
pub async fn audit_connection(
    provider: String,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
    app: tauri::AppHandle,
    force_refresh: Option<bool>,
    run_id: Option<String>,
) -> Result<auditor::RiskReport, String> {
    let provider_id = auditor::ProviderId::from_id(&provider)
        .ok_or_else(|| format!("Неизвестный провайдер: {provider}"))?;
    // With a `run_id` every check is sent to the interface as soon as it is done, so the rows
    // fill in one by one instead of staying empty until the slowest check ends.
    let sink: Option<auditor::ProgressSink> = run_id.map(|run_id| {
        let app = app.clone();
        let provider = provider.clone();
        Arc::new(move |progress: auditor::AuditProgress| {
            let _ = app.emit(
                AUDIT_PROGRESS_EVENT,
                AuditProgressEvent {
                    run_id: &run_id,
                    provider: &provider,
                    progress,
                },
            );
        }) as auditor::ProgressSink
    });
    let protection = read_runtime_protection_flags().await;
    let mut report = match auditor
        .evaluate_all_progress_with_protection(
            provider_id,
            &state,
            force_refresh.unwrap_or(false),
            sink,
            protection,
        )
        .await
    {
        Ok(report) => report,
        Err(e) => {
            // A failed primary audit must not leave the previous (possibly green) tray state;
            // a stop/block state stays as it is.
            if provider_id == auditor::ProviderId::Anthropic && !guard.any_provider_gate_pending() {
                let st = state.get_data().await;
                let has_blocked =
                    !st.blocked_providers.is_empty() || guard.any_provider_gate_closed();
                if !has_blocked {
                    crate::tray::update_tray_no_data(&app, None);
                }
            }
            return Err(e);
        }
    };

    let st = state.get_data().await;
    let is_pinned = finalize_audit_report_for_state(&st, provider_id, &mut report);

    // Sync system tray status whenever Anthropic or primary audit runs (unless guard is pending)
    if (provider_id == auditor::ProviderId::Anthropic || force_refresh.unwrap_or(false))
        && !guard.any_provider_gate_pending()
    {
        let has_blocked = !st.blocked_providers.is_empty() || guard.any_provider_gate_closed();
        let tray_report = proxy::guard::effective_tray_report(&report, has_blocked, &st);
        update_tray_from_report(&app, &tray_report, is_pinned, has_blocked);
    }

    Ok(report)
}

/// Pins `ip` for the routed `provider` key, or for `"default"` when the provider is Direct or omitted.
#[tauri::command]
pub async fn pin_current_ip(
    ip: String,
    provider: Option<String>,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    helpers::pin_ip_inner(&state, ip, provider).await
}

/// Unpins the IP for `provider` (or clears all pinned IPs when `provider` is omitted).
#[tauri::command]
pub async fn unpin_ip(
    provider: Option<String>,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    helpers::unpin_ip_inner(&state, provider).await
}

#[tauri::command]
pub async fn get_pinned_ips(
    state: tauri::State<'_, state::AppState>,
) -> Result<std::collections::HashMap<String, String>, String> {
    Ok(state.get_pinned_ips().await)
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
    helpers::allow_provider_session_inner(&provider, &state, &auditor, &proxy_manager).await
}

#[tauri::command]
pub async fn unblock_provider_cmd(
    provider: String,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<(), String> {
    let canonical = auditor::ProviderId::from_id(&provider)
        .map(|p| p.as_str())
        .unwrap_or(&provider);
    state
        .unblock_provider(canonical)
        .await
        .map_err(|e| e.to_string())?;

    // Also update IP history to current IP so a stale Impossible Travel doesn't immediately re-flag
    let (tel_opt, _ip_opt) =
        resolve_exit_ip_for_provider(canonical, &state, &auditor, &proxy_manager).await;

    if !proxy_manager.guard.is_manual_killswitch() {
        proxy_manager
            .guard
            .confirm_provider_session(canonical, tel_opt.as_ref())
            .await;
    }

    Ok(())
}

#[tauri::command]
pub async fn set_provider_monitoring(
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
    guard: tauri::State<'_, Arc<proxy::NetworkGuard>>,
    provider: String,
    enabled: bool,
) -> Result<state::AppStateData, String> {
    let updated = set_provider_monitoring_inner(&state, &guard, &provider, enabled).await?;
    if let Some(pm) = app.try_state::<proxy::ProxyManager>() {
        pm.coverage.invalidate_facts();
        let _ = pm.server.build_pac_script().await;
    }
    if crate::sysproxy::SysProxy::is_active() {
        tokio::task::spawn_blocking(|| {
            let _ = crate::sysproxy::refresh_if_services_changed();
            crate::sysproxy::reconcile_browser_pac_prefs(None);
        });
    }
    let _ = app.emit("network://changed", &());
    Ok(updated)
}

#[tauri::command]
pub async fn remove_trusted_exception(
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
    guard: tauri::State<'_, Arc<proxy::NetworkGuard>>,
    provider: String,
    ip: String,
) -> Result<state::AppStateData, String> {
    let updated = remove_trusted_exception_inner(&state, &guard, &provider, &ip).await?;
    let _ = app.emit("network://changed", &());
    Ok(updated)
}

#[tauri::command]
pub async fn clear_trusted_exceptions(
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
    guard: tauri::State<'_, Arc<proxy::NetworkGuard>>,
    provider: Option<String>,
) -> Result<state::AppStateData, String> {
    let updated = clear_trusted_exceptions_inner(&state, &guard, provider.as_deref()).await?;
    let _ = app.emit("network://changed", &());
    Ok(updated)
}

/// Runs a fresh forced audit for `provider` and unblocks it if traffic is no longer under a
/// manual kill-switch and the audit confirms traffic is allowed for the current state.
#[tauri::command]
pub async fn verify_and_unblock_provider(
    provider: String,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let provider_id = auditor::ProviderId::from_id(&provider)
        .ok_or_else(|| format!("Неизвестный провайдер: {provider}"))?;
    let protection = read_runtime_protection_flags().await;
    let mut report = auditor
        .evaluate_all_with_protection(provider_id, &state, true, protection)
        .await?;

    let st_before = state.get_data().await;
    let manual_ks = guard.is_manual_killswitch();
    let is_pinned = finalize_audit_report_for_state(&st_before, provider_id, &mut report);
    let selection = crate::routing::select_route(&st_before, provider_id.as_str());
    let is_routed = matches!(selection, crate::routing::RouteSelection::Route(_));

    if !should_verify_unblock(manual_ks, &report, &st_before, is_routed) {
        let has_blocked =
            !st_before.blocked_providers.is_empty() || guard.any_provider_gate_closed();
        update_tray_from_report(&app, &report, is_pinned, has_blocked);
        return Ok(false);
    }
    state
        .unblock_provider(provider_id.as_str())
        .await
        .map_err(|e| e.to_string())?;
    let entry = state::IpHistoryEntry::new(
        report.telemetry.ip.clone(),
        report.telemetry.country_code.clone(),
        report.telemetry.asn,
        report.telemetry.resolved_at,
    );
    let _ = state
        .record_ip_history_for_selection(provider_id.as_str(), &selection, entry)
        .await;
    if matches!(selection, crate::routing::RouteSelection::Direct) {
        guard.ensure_open_for_verified(&report.telemetry).await;
    }

    let st_after = state.get_data().await;
    let has_blocked = !st_after.blocked_providers.is_empty() || guard.any_provider_gate_closed();
    update_tray_from_report(&app, &report, is_pinned, has_blocked);
    let _ = app.emit("network://changed", &report);
    Ok(true)
}

#[tauri::command]
pub async fn get_gateway_stats(
    state: tauri::State<'_, state::AppState>,
) -> Result<state::GatewayStatsSnapshot, String> {
    Ok(state.get_gateway_stats().await)
}

#[tauri::command]
pub async fn get_split_tunnel_mode(
    state: tauri::State<'_, state::AppState>,
) -> Result<bool, String> {
    Ok(state.is_split_tunnel_mode().await)
}

#[tauri::command]
pub async fn set_split_tunnel_mode(
    enabled: bool,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    state
        .set_split_tunnel_mode(enabled)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_onboarding_v2_2_done(
    state: tauri::State<'_, state::AppState>,
) -> Result<bool, String> {
    Ok(state.is_onboarding_v2_2_done().await)
}

#[tauri::command]
pub async fn set_onboarding_v2_2_done(
    done: bool,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    state
        .set_onboarding_v2_2_done(done)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_hide_ip_mode(state: tauri::State<'_, state::AppState>) -> Result<bool, String> {
    Ok(state.is_hide_ip_mode().await)
}

#[tauri::command]
pub async fn set_hide_ip_mode(
    enabled: bool,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    state
        .set_hide_ip_mode(enabled)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
#[path = "../audit_tests.rs"]
mod tests;
