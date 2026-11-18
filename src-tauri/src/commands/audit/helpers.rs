//! Internal pinning, session allow/unblock, and provider monitoring helpers for audit commands.

use crate::{auditor, proxy, state};
use std::sync::Arc;

/// Payload of [`super::AUDIT_PROGRESS_EVENT`]: `run_id` tells the interface which call it belongs to.
#[derive(serde::Serialize, Clone)]
pub(crate) struct AuditProgressEvent<'a> {
    pub(crate) run_id: &'a str,
    pub(crate) provider: &'a str,
    #[serde(flatten)]
    pub(crate) progress: auditor::AuditProgress,
}

pub(crate) fn finalize_audit_report_for_state(
    st: &state::AppStateData,
    provider_id: auditor::ProviderId,
    report: &mut auditor::RiskReport,
) -> bool {
    let is_pinned = is_ip_pinned_for_state(st, provider_id, &report.telemetry.ip);
    auditor::history::apply_pinned_travel_grace(report, is_pinned);
    is_pinned
}

pub(crate) fn is_ip_pinned_for_state(
    st: &state::AppStateData,
    provider_id: auditor::ProviderId,
    exit_ip: &str,
) -> bool {
    let is_routed = matches!(
        crate::routing::select_route(st, provider_id.as_str()),
        crate::routing::RouteSelection::Route(_)
    );
    if is_routed {
        if let Some(pin) = st.pinned_ip_for_provider(provider_id.as_str(), true) {
            return pin == exit_ip.trim();
        }
        // A bound Zastava key already locks this provider to the key endpoint IP.
        return true;
    }
    st.pinned_ip_for_provider(provider_id.as_str(), false)
        .map(|p| p == exit_ip.trim())
        .unwrap_or(false)
}

async fn resolve_pin_scope(
    state: &state::AppState,
    provider: Option<&str>,
) -> Result<String, String> {
    let Some(raw) = provider.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok("default".to_string());
    };
    if raw.eq_ignore_ascii_case("default") {
        return Ok("default".to_string());
    }
    let pid =
        auditor::ProviderId::from_id(raw).ok_or_else(|| format!("Неизвестный провайдер: {raw}"))?;
    let st = state.get_data().await;
    let is_routed = matches!(
        crate::routing::select_route(&st, pid.as_str()),
        crate::routing::RouteSelection::Route(_)
    );
    if is_routed || st.has_explicit_pinned_ip(pid.as_str()) {
        Ok(pid.as_str().to_string())
    } else {
        Ok("default".to_string())
    }
}

pub(crate) async fn pin_ip_inner(
    state: &state::AppState,
    ip: String,
    provider: Option<String>,
) -> Result<(), String> {
    let scope = resolve_pin_scope(state, provider.as_deref()).await?;
    state
        .set_pinned_ip_for(&scope, Some(ip))
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn unpin_ip_inner(
    state: &state::AppState,
    provider: Option<String>,
) -> Result<(), String> {
    match provider.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => state
            .clear_all_pinned_ips()
            .await
            .map_err(|e| e.to_string()),
        Some(_) => {
            let scope = resolve_pin_scope(state, provider.as_deref()).await?;
            state
                .set_pinned_ip_for(&scope, None)
                .await
                .map_err(|e| e.to_string())
        }
    }
}

pub(super) async fn resolve_exit_ip_for_provider(
    provider: &str,
    state: &state::AppState,
    auditor: &auditor::Auditor,
    proxy_manager: &proxy::ProxyManager,
) -> (Option<auditor::NetworkTelemetry>, Option<String>) {
    let mut tel_opt = None;
    let mut ip_opt = None;
    let mut is_direct = true;
    if let Some(provider_id) = auditor::ProviderId::from_id(provider) {
        let data = state.get_data().await;
        let selection = crate::routing::select_route(&data, provider_id.as_str());
        is_direct = matches!(selection, crate::routing::RouteSelection::Direct);
        if let Ok(tel) = auditor
            .resolve_for_provider(provider_id, state, false)
            .await
        {
            let entry = state::IpHistoryEntry::new(
                tel.ip.clone(),
                tel.country_code.clone(),
                tel.asn,
                tel.resolved_at,
            );
            let _ = state
                .record_ip_history_for_selection(provider_id.as_str(), &selection, entry)
                .await;
            ip_opt = Some(tel.ip.clone());
            if is_direct {
                tel_opt = Some(tel);
            }
        }
    }
    if ip_opt.is_none() {
        if is_direct {
            ip_opt = proxy_manager.guard.current_observed_ip().await;
        }
        if ip_opt.is_none() {
            ip_opt = proxy_manager
                .hold_queue
                .current_alert()
                .and_then(|alert| alert.report.map(|r| r.telemetry.ip));
        }
    }
    (tel_opt, ip_opt)
}

pub(crate) async fn allow_provider_session_inner(
    provider: &str,
    state: &state::AppState,
    auditor: &auditor::Auditor,
    proxy_manager: &proxy::ProxyManager,
) -> Result<(), String> {
    let canonical = auditor::ProviderId::from_id(provider)
        .map(|p| p.as_str())
        .unwrap_or(provider);
    let (tel_opt, ip_opt) =
        resolve_exit_ip_for_provider(canonical, state, auditor, proxy_manager).await;

    state
        .allow_provider_for_session(canonical)
        .await
        .map_err(|e| e.to_string())?;
    if !proxy_manager.guard.is_manual_killswitch() {
        state
            .unblock_provider(canonical)
            .await
            .map_err(|e| e.to_string())?;
    }
    if let Some(ip) = ip_opt
        && !ip.trim().is_empty()
    {
        state
            .add_trusted_exception(canonical, &ip)
            .await
            .map_err(|e| e.to_string())?;
    }

    proxy_manager
        .hold_queue
        .resolve_all_for_provider(canonical, proxy::HoldResolution::Allow)
        .await;

    // Scoped per-provider session confirmation: never clears unrelated providers' blocks and sets
    // `baseline.trusted = true` even when telemetry could not be resolved.
    proxy_manager
        .guard
        .confirm_provider_session(canonical, tel_opt.as_ref())
        .await;

    Ok(())
}

pub(crate) async fn set_provider_monitoring_inner(
    state: &state::AppState,
    guard: &Arc<proxy::NetworkGuard>,
    provider: &str,
    enabled: bool,
) -> Result<state::AppStateData, String> {
    let provider_id = auditor::ProviderId::from_id(provider)
        .ok_or_else(|| format!("Неизвестный провайдер: {provider}"))?;
    state
        .set_provider_monitoring(provider_id.as_str(), enabled)
        .await
        .map_err(|e| e.to_string())?;
    if enabled {
        guard
            .sync_provider_monitoring_enabled(provider_id.as_str())
            .await;
    } else {
        guard
            .sync_provider_disabled(provider_id.as_str(), state)
            .await;
    }
    Ok(state.get_data().await.redacted_for_ui())
}

pub(crate) async fn remove_trusted_exception_inner(
    state: &state::AppState,
    guard: &Arc<proxy::NetworkGuard>,
    provider: &str,
    ip: &str,
) -> Result<state::AppStateData, String> {
    let provider_id = auditor::ProviderId::from_id(provider)
        .ok_or_else(|| format!("Неизвестный провайдер: {provider}"))?;
    state
        .remove_trusted_exception(provider_id.as_str(), ip)
        .await
        .map_err(|e| e.to_string())?;
    let _ = state
        .revoke_provider_session_allowance(Some(provider_id.as_str()))
        .await;
    guard.kick_reaudit();
    Ok(state.get_data().await.redacted_for_ui())
}

pub(crate) async fn clear_trusted_exceptions_inner(
    state: &state::AppState,
    guard: &Arc<proxy::NetworkGuard>,
    provider: Option<&str>,
) -> Result<state::AppStateData, String> {
    let canonical = match provider {
        Some(p) => Some(
            auditor::ProviderId::from_id(p)
                .ok_or_else(|| format!("Неизвестный провайдер: {p}"))?
                .as_str(),
        ),
        None => None,
    };
    state
        .clear_trusted_exceptions(canonical)
        .await
        .map_err(|e| e.to_string())?;
    let _ = state.revoke_provider_session_allowance(canonical).await;
    guard.kick_reaudit();
    Ok(state.get_data().await.redacted_for_ui())
}

pub(crate) fn should_verify_unblock(
    manual_killswitch: bool,
    report: &auditor::RiskReport,
    st: &state::AppStateData,
    routed: bool,
) -> bool {
    if manual_killswitch {
        return false;
    }
    proxy::guard::report_allowed_for_state(report, st, routed)
}
