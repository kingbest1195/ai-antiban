//! Interception resolution/simulation, behavior & popup position settings, network kill-switch.

mod helpers;
mod sim;

use super::AppContext;
use crate::popup::show_and_position_alert_popup;
use crate::{auditor, proxy, state};
use helpers::{ResolveInterceptionParams, resolve_interception_with_params};
use sim::build_simulated_risk_report;
use tauri::{Emitter, Manager};

#[cfg(test)]
pub(crate) use helpers::{resolve_interception_core, resolve_interception_core_with};
pub(crate) use helpers::toggle_or_clear_stop_core;
pub(crate) use sim::build_simulation_network_change;

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn resolve_interception(
    id: String,
    action: proxy::InterceptionAction,
    provider: String,
    scope: Option<String>,
    persist_exception: Option<bool>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    app: tauri::AppHandle,
) -> Result<bool, proxy::AllowError> {
    let is_simulation = scope.as_deref() == Some("simulation") || id.starts_with("sim-");
    if is_simulation {
        let resolution = match action {
            proxy::InterceptionAction::AllowSession => proxy::HoldResolution::Allow,
            proxy::InterceptionAction::BlockUntilNetworkChange
            | proxy::InterceptionAction::OpenGuideAndBlock => proxy::HoldResolution::Block,
        };
        proxy_manager.hold_queue.resolve(&id, resolution).await;
        if matches!(action, proxy::InterceptionAction::OpenGuideAndBlock)
            && let Some(main_win) = app.get_webview_window("main")
        {
            let _ = main_win.show();
            let _ = main_win.set_focus();
            let _ = app.emit("interceptor://open-guide", "01-personal-vpn-15min");
        }
        crate::popup::hide_alert_popup(&app);
        let _ = app.emit("interceptor://resolved", "");
        return Ok(true);
    }

    let outcome = resolve_interception_with_params(ResolveInterceptionParams {
        id: &id,
        action,
        provider: &provider,
        scope: scope.as_deref(),
        persist_exception: persist_exception.unwrap_or(false),
        proxy_manager: &proxy_manager,
        state: &state,
        auditor: &auditor,
    })
    .await?;

    if let Some(ref status) = outcome.pause_status {
        emit_guard_pause_status(&app, status);
    }
    if outcome.open_guide
        && let Some(main_win) = app.get_webview_window("main")
    {
        let _ = main_win.show();
        let _ = main_win.set_focus();
        let _ = app.emit("interceptor://open-guide", "01-personal-vpn-15min");
    }

    crate::popup::hide_alert_popup(&app);
    let _ = app.emit("interceptor://resolved", "");

    Ok(outcome.applied)
}

#[tauri::command]
pub async fn simulate_interception(
    provider: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<(), String> {
    let prov = provider.unwrap_or_else(|| "anthropic".to_string());
    let provider_id = auditor::ProviderId::from_id(&prov).unwrap_or(auditor::ProviderId::Anthropic);
    let report = build_simulated_risk_report(provider_id, &auditor).await;

    let hold_id = format!("sim-{}", uuid::Uuid::new_v4());
    let _rx = proxy_manager
        .hold_queue
        .register(hold_id.clone(), provider_id.as_str())
        .await;

    let data = state.get_data().await;
    let network_change = Some(build_simulation_network_change(&data, provider_id.as_str()));
    let gate_reason = Some(proxy::hold_queue::build_gate_reason(
        Some(&report),
        network_change.as_ref(),
        true,
    ));

    let payload = proxy::RiskInterceptPayload {
        id: hold_id,
        provider: provider_id,
        host: "ДЕМО-ТЕСТ: api.anthropic.com:443".to_string(),
        report: Some(report),
        ttl_seconds: proxy::hold_queue::DEFAULT_HOLD_TTL_SECS,
        scope: "simulation".to_string(),
        network_change,
        is_simulation: true,
        detected_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        phase: proxy::hold_queue::PHASE_READY.to_string(),
        gate_reason,
        checkout_risk: None,
    };

    // Emit first, then show: the hidden window must not display its placeholder content.
    proxy_manager.hold_queue.set_alert(payload.clone());
    let _ = app.emit("interceptor://risk-detected", &payload);
    show_and_position_alert_popup(&app);

    Ok(())
}

/// Snapshot of the alert that is waiting for a decision (or `None`). The alert popup calls it
/// after its event listeners are registered: a hidden window can miss the first
/// `interceptor://risk-detected`. The snapshot carries everything known so far (`phase`,
/// `report`, `network_change`); it is not consumed and disappears once the hold is resolved.
#[tauri::command]
pub fn take_pending_alert(
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Option<proxy::RiskInterceptPayload> {
    proxy_manager.hold_queue.current_alert()
}

#[tauri::command]
pub async fn get_interception_behavior_cmd(
    state: tauri::State<'_, state::AppState>,
) -> Result<state::InterceptionBehavior, String> {
    Ok(state.get_interception_behavior().await)
}

#[tauri::command]
pub async fn set_interception_behavior_cmd(
    behavior: state::InterceptionBehavior,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    state
        .set_interception_behavior(behavior)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_popup_position_cmd(
    state: tauri::State<'_, state::AppState>,
) -> Result<state::PopupPosition, String> {
    Ok(state.get_popup_position().await)
}

#[tauri::command]
pub async fn set_popup_position_cmd(
    position: state::PopupPosition,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    state
        .set_popup_position(position)
        .await
        .map_err(|e| e.to_string())
}

fn emit_guard_pause_status(app: &tauri::AppHandle, status: &proxy::guard::GuardPauseStatus) {
    let _ = app.emit("guard://pause-status-changed", status);
}

pub(crate) async fn toggle_killswitch_shared(
    freeze: Option<bool>,
    guard: &std::sync::Arc<proxy::NetworkGuard>,
    state: &state::AppState,
    app: &tauri::AppHandle,
) -> bool {
    let (now_frozen, should_emit_network_changed) =
        toggle_or_clear_stop_core(freeze, guard, state).await;
    crate::tray::update_tray_killswitch(app, now_frozen);
    let _ = app.emit("tray://killswitch-toggled", now_frozen);
    emit_guard_pause_status(app, &guard.pause_status());
    if should_emit_network_changed {
        let _ = app.emit("network://changed", &());
    }
    now_frozen
}

#[tauri::command]
pub async fn toggle_network_killswitch_cmd(
    freeze: Option<bool>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
    state: tauri::State<'_, AppContext>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    Ok(toggle_killswitch_shared(freeze, &guard, &state, &app).await)
}

#[tauri::command]
pub async fn get_network_killswitch_status_cmd(
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<bool, String> {
    Ok(guard.is_manual_killswitch())
}

#[tauri::command]
pub async fn pause_until_network_change_cmd(
    reason: Option<String>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
    state: tauri::State<'_, AppContext>,
    app: tauri::AppHandle,
) -> Result<proxy::guard::GuardPauseStatus, String> {
    let status = guard.pause_until_network_change(&state, reason).await;
    emit_guard_pause_status(&app, &status);
    Ok(status)
}

#[tauri::command]
pub async fn set_guard_pause_mode_cmd(
    mode: proxy::guard::PauseMode,
    reason: Option<String>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
    state: tauri::State<'_, AppContext>,
    app: tauri::AppHandle,
) -> Result<proxy::guard::GuardPauseStatus, String> {
    let was_manual = guard.is_manual_killswitch();
    let status = match mode {
        proxy::guard::PauseMode::None => {
            if was_manual {
                guard.set_manual_killswitch(false, &state).await;
            }
            guard
                .clear_pause_on_network_change(Some(&state), true)
                .await;
            guard.pause_status()
        }
        proxy::guard::PauseMode::UntilNetworkChange => {
            guard.pause_until_network_change(&state, reason).await
        }
        proxy::guard::PauseMode::Manual => {
            guard.set_manual_killswitch(true, &state).await;
            guard.pause_status()
        }
    };
    if status.manual_killswitch != was_manual {
        crate::tray::update_tray_killswitch(&app, status.manual_killswitch);
        let _ = app.emit("tray://killswitch-toggled", status.manual_killswitch);
    }
    emit_guard_pause_status(&app, &status);
    Ok(status)
}

#[tauri::command]
pub async fn get_guard_pause_status_cmd(
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<proxy::guard::GuardPauseStatus, String> {
    Ok(guard.pause_status())
}

#[cfg(test)]
#[path = "../interception_tests.rs"]
mod tests;
