//! Interception resolution/simulation, behavior & popup position settings, network kill-switch.

use super::AppContext;
use crate::popup::show_and_position_alert_popup;
use crate::{auditor, proxy, state};
use tauri::{Emitter, Manager};

/// `measured_via` of the canned results in the demo simulation.
const SIMULATED_VIA: &str = "simulation";

async fn resolve_provider_telemetry_for_allow(
    id: &str,
    provider: &str,
    state: &state::AppState,
    auditor: &auditor::Auditor,
    proxy_manager: &proxy::ProxyManager,
) -> (Option<auditor::NetworkTelemetry>, Option<String>) {
    let alert_tel = proxy_manager
        .hold_queue
        .current_alert()
        .filter(|a| a.id == id)
        .and_then(|a| a.report.map(|r| r.telemetry));

    let pid_opt = auditor::ProviderId::from_id(provider);
    let data = state.get_data().await;
    let selection = pid_opt
        .map(|p| crate::routing::select_route(&data, p.as_str()))
        .unwrap_or(crate::routing::RouteSelection::Direct);
    let is_direct = matches!(selection, crate::routing::RouteSelection::Direct);

    let resolved_tel = if let Some(tel) = alert_tel {
        Some(tel)
    } else if let Some(pid) = pid_opt {
        auditor.resolve_for_provider(pid, state, false).await.ok()
    } else {
        None
    };

    if let Some(ref tel) = resolved_tel {
        if let Some(pid) = pid_opt {
            let entry = state::IpHistoryEntry::new(
                tel.ip.clone(),
                tel.country_code.clone(),
                tel.asn,
                tel.resolved_at,
            );
            let _ = state
                .record_ip_history_for_selection(pid.as_str(), &selection, entry)
                .await;
        }
        let ip = Some(tel.ip.clone());
        let direct_tel = is_direct.then(|| tel.clone());
        return (direct_tel, ip);
    }

    let fallback_ip = if is_direct {
        proxy_manager.guard.current_observed_ip().await
    } else {
        None
    };
    (None, fallback_ip)
}

struct ResolveInterceptionOutcome {
    applied: bool,
    open_guide: bool,
    pause_status: Option<proxy::guard::GuardPauseStatus>,
}

impl ResolveInterceptionOutcome {
    fn noop() -> Self {
        Self {
            applied: false,
            open_guide: false,
            pause_status: None,
        }
    }
}

async fn claim_and_block_targets_if_active(
    id: &str,
    targets: &[String],
    is_network_scope: bool,
    network_alert_active: bool,
    epoch_before: u64,
    proxy_manager: &proxy::ProxyManager,
    state: &state::AppState,
) -> Result<bool, proxy::AllowError> {
    let network_alert_stale =
        is_network_scope && proxy_manager.guard.is_env_installed() && !network_alert_active;
    if network_alert_stale || proxy_manager.guard.restore_epoch() != epoch_before {
        return Ok(false);
    }
    let was_active = proxy_manager
        .hold_queue
        .resolve(id, proxy::HoldResolution::Block)
        .await;
    if !was_active || proxy_manager.guard.restore_epoch() != epoch_before {
        return Ok(false);
    }
    for p in targets {
        state.block_provider(p).await.map_err(|e| e.to_string())?;
    }
    if proxy_manager.guard.restore_epoch() != epoch_before {
        if !proxy_manager.guard.is_manual_killswitch() {
            for p in targets {
                let _ = state.unblock_provider(p).await;
            }
        }
        proxy_manager.guard.sync_gates_with_state(state).await;
        return Ok(false);
    }
    proxy_manager.guard.sync_gates_with_state(state).await;
    Ok(true)
}

async fn resolve_interception_core(
    id: &str,
    action: proxy::InterceptionAction,
    provider: &str,
    scope: Option<&str>,
    proxy_manager: &proxy::ProxyManager,
    state: &state::AppState,
    auditor: &auditor::Auditor,
) -> Result<ResolveInterceptionOutcome, proxy::AllowError> {
    let epoch_before = proxy_manager.guard.restore_epoch();
    // `all` or scope "network" = network-wide hold created by the network guard after a sudden IP change
    let is_network_scope = scope == Some("network") || provider == proxy::ALL_PROVIDERS;
    let network_targets = if is_network_scope {
        proxy_manager.guard.affected_providers_for_alert(id).await
    } else {
        None
    };
    let network_alert_active = network_targets.is_some();
    let targets: Vec<String> = if is_network_scope {
        match network_targets {
            Some(list) if !list.is_empty() => list,
            _ => state
                .enabled_unrouted_providers()
                .await
                .into_iter()
                .map(|p| p.to_string())
                .collect(),
        }
    } else {
        let canonical = auditor::ProviderId::from_id(provider)
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| provider.to_string());
        vec![canonical]
    };

    let mut open_guide = false;
    let mut pause_status = None;

    match action {
        proxy::InterceptionAction::AllowSession => {
            if is_network_scope {
                // Network-wide allow: only for the alert that is still current and fully audited
                // (checked and applied by the guard under its lock). Persists trusted_exceptions
                // and opens ONLY `targets`, preserving unrelated `already_blocked_providers`.
                proxy_manager
                    .guard
                    .allow_network_alert(id, &targets)
                    .await?;
            } else {
                for p in &targets {
                    let (tel_opt, ip_opt) = resolve_provider_telemetry_for_allow(
                        id,
                        p,
                        state,
                        auditor,
                        proxy_manager,
                    )
                    .await;
                    state
                        .allow_provider_for_session(p)
                        .await
                        .map_err(|e| e.to_string())?;
                    if !proxy_manager.guard.is_manual_killswitch() {
                        state
                            .unblock_provider(p)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    if let Some(ip) = ip_opt
                        && !ip.trim().is_empty()
                    {
                        state
                            .add_trusted_exception(p, &ip)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    proxy_manager
                        .hold_queue
                        .resolve(id, proxy::HoldResolution::Allow)
                        .await;
                    proxy_manager
                        .guard
                        .confirm_provider_session(p, tel_opt.as_ref())
                        .await;
                }
            }
            // Provider holds only: an allow never reaches the network-wide `all` hold.
            for p in targets.iter().map(String::as_str) {
                proxy_manager
                    .hold_queue
                    .resolve_all_for_provider(p, proxy::HoldResolution::Allow)
                    .await;
            }
        }
        proxy::InterceptionAction::BlockUntilNetworkChange => {
            let pause_reason = if is_network_scope {
                proxy_manager.guard.gate_reason().or_else(|| {
                    proxy_manager
                        .hold_queue
                        .current_alert()
                        .and_then(|alert| alert.gate_reason)
                })
            } else {
                None
            };
            if !claim_and_block_targets_if_active(
                id,
                &targets,
                is_network_scope,
                network_alert_active,
                epoch_before,
                proxy_manager,
                state,
            )
            .await?
            {
                return Ok(ResolveInterceptionOutcome::noop());
            }
            if is_network_scope {
                let st_after = state.get_data().await;
                let all_enabled_unrouted_blocked = st_after
                    .enabled_unrouted_providers()
                    .iter()
                    .all(|p| st_after.blocked_providers.contains(*p));
                if all_enabled_unrouted_blocked && !targets.is_empty() {
                    proxy_manager
                        .guard
                        .mark_paused_until_network_change(pause_reason)
                        .await;
                    proxy_manager.guard.sync_gates_with_state(state).await;
                    pause_status = Some(proxy_manager.guard.pause_status());
                }
            }
            for p in targets
                .iter()
                .map(String::as_str)
                .chain([proxy::ALL_PROVIDERS])
            {
                proxy_manager
                    .hold_queue
                    .resolve_all_for_provider(p, proxy::HoldResolution::Block)
                    .await;
            }
        }
        proxy::InterceptionAction::OpenGuideAndBlock => {
            if !claim_and_block_targets_if_active(
                id,
                &targets,
                is_network_scope,
                network_alert_active,
                epoch_before,
                proxy_manager,
                state,
            )
            .await?
            {
                return Ok(ResolveInterceptionOutcome::noop());
            }
            for p in targets
                .iter()
                .map(String::as_str)
                .chain([proxy::ALL_PROVIDERS])
            {
                proxy_manager
                    .hold_queue
                    .resolve_all_for_provider(p, proxy::HoldResolution::Block)
                    .await;
            }
            open_guide = true;
        }
    }

    Ok(ResolveInterceptionOutcome {
        applied: true,
        open_guide,
        pause_status,
    })
}

#[tauri::command]
pub async fn resolve_interception(
    id: String,
    action: proxy::InterceptionAction,
    provider: String,
    scope: Option<String>,
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

    let outcome = resolve_interception_core(
        &id,
        action,
        &provider,
        scope.as_deref(),
        &proxy_manager,
        &state,
        &auditor,
    )
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

fn build_simulation_network_change(
    data: &state::AppStateData,
    provider_key: &str,
) -> proxy::hold_queue::NetworkChange {
    let scoped_key = data.ip_history_key_for_provider(provider_key);
    let last_entry = data
        .ip_history
        .get(&scoped_key)
        .and_then(|v| v.last())
        .or_else(|| data.ip_history.get(provider_key).and_then(|v| v.last()))
        .or_else(|| data.ip_history.values().filter_map(|v| v.last()).next());

    let old_ip = data
        .pinned_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| last_entry.map(|e| e.ip.clone()))
        .unwrap_or_else(|| "185.212.102.40".to_string());

    let old_country = last_entry
        .and_then(|e| {
            if e.ip.trim() == old_ip.trim() {
                Some(e.country_code.clone())
            } else {
                None
            }
        })
        .or_else(|| last_entry.map(|e| e.country_code.clone()))
        .filter(|c| !c.trim().is_empty())
        .unwrap_or_else(|| "NL".to_string());

    proxy::hold_queue::NetworkChange {
        old_ip: Some(old_ip),
        old_country: Some(old_country),
        new_ip: Some("185.220.101.5".to_string()),
        new_country: Some("TR".to_string()),
    }
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

    let matrix = auditor.rules.provider_matrix.read().await;
    let dangerous_asns = auditor.rules.dangerous_asns.read().await;

    let telemetry = auditor::NetworkTelemetry {
        ip: "185.220.101.5".to_string(),
        country_code: "TR".to_string(),
        hostname: Some("tor-exit-01.relays.net".to_string()),
        asn: Some(9009),
        org: Some("M247 Europe SRL".to_string()),
        isp: Some("M247 Europe SRL".to_string()),
        timezone: Some("Europe/Istanbul".to_string()),
        resolved_at: auditor::network::current_timestamp(),
    };

    let geo_result = auditor::evaluate_provider_geo(&matrix, provider_id, &telemetry.country_code);
    let pinning_result = auditor::CheckResult::warning(
        "PINNED_IP_NOT_CONFIGURED",
        "Строгая привязка IP отключена. Трафик идет через публичный коммерческий VPN-пул.",
        Some(auditor::geo_matrix::GUIDE_PERSONAL_VPN.to_string()),
    );
    let travel_result =
        auditor::CheckResult::ok("TRAVEL_NORMAL", "Конфликтов перемещения за 12ч нет.");
    let dnsbl_report = auditor::check_all_dnsbl(&telemetry.ip, &dangerous_asns).await;
    let dnsbl_result = auditor::evaluate_dnsbl_report(&dnsbl_report);
    // SIMULATION ONLY: the Tor list is not downloaded here; the demo address is a mass-VPN pool.
    let asn_result = auditor::evaluate_ip_reputation(
        &auditor::ExitIdentity {
            ip: &telemetry.ip,
            country_code: &telemetry.country_code,
            asn: telemetry.asn,
            isp: telemetry.isp.as_deref(),
            org: telemetry.org.as_deref(),
        },
        &dangerous_asns,
        auditor::TorLookup::NotListed,
        false,
    )
    .with_measured_via(SIMULATED_VIA);
    // SIMULATION ONLY: these two verdicts are canned demo values, not the outcome of a probe.
    // They are marked (`measured_via = "simulation"`) so that they never pass for a real check.
    let ipv6_result =
        auditor::CheckResult::ok("IPV6_SAFE", "Утечек по протоколу IPv6 не обнаружено.")
            .with_measured_via(SIMULATED_VIA);
    let dns_result = auditor::CheckResult::ok(
        "DNS_CLEAN",
        "Утечек через локальные DNS-резолверы РФ не обнаружено.",
    )
    .with_measured_via(SIMULATED_VIA);
    let timezone_result = auditor::evaluate_system_timezone(telemetry.timezone.as_deref(), None);
    let location_result = auditor::check_os_location_services();
    let reverse_dns_result = auditor::evaluate_reverse_dns_ptr(&telemetry);
    let dns_country_result = auditor::evaluate_dns_country_consistency(&telemetry, None);
    let locale_result = auditor::evaluate_locale_env_hygiene(None);
    // SIMULATION ONLY: the 13th check (UDP/STUN) is a canned demo value as well.
    let udp_stun_result = auditor::CheckResult::ok(
        "UDP_STUN_MATCH",
        "Внешний адрес по UDP совпадает с адресом HTTP-выхода.",
    )
    .with_measured_via(SIMULATED_VIA);

    let checks = vec![
        geo_result.clone(),
        pinning_result.clone(),
        travel_result.clone(),
        dnsbl_result.clone(),
        asn_result.clone(),
        ipv6_result.clone(),
        dns_result,
        timezone_result.clone(),
        location_result,
        reverse_dns_result,
        dns_country_result,
        locale_result,
        udp_stun_result,
    ];

    let (unknown_count, applicable_count) = auditor::count_checks(&checks);
    let report = auditor::RiskReport {
        provider: provider_id,
        overall_status: auditor::OverallStatus::Red,
        trust_score: 28,
        telemetry,
        geo_result,
        pinning_result,
        travel_result,
        dnsbl_result,
        dnsbl_clean_count: dnsbl_report.summary_label,
        asn_result,
        ipv6_result,
        timezone_result,
        ipv6_exit: false,
        checks,
        unknown_count,
        applicable_count,
        incomplete: unknown_count > 0,
    };

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

pub(crate) async fn toggle_or_clear_stop_core(
    freeze: Option<bool>,
    guard: &std::sync::Arc<proxy::NetworkGuard>,
    state: &state::AppState,
) -> (bool, bool) {
    let is_manual = guard.is_manual_killswitch();
    match freeze {
        Some(true) => (guard.set_manual_killswitch(true, state).await, false),
        Some(false) => {
            if is_manual {
                let frozen = guard.set_manual_killswitch(false, state).await;
                guard.kick_reaudit();
                (frozen, true)
            } else {
                guard.clear_stop_and_reaudit(state).await;
                (false, true)
            }
        }
        None => {
            let st = state.get_data().await;
            let has_any_stop = is_manual
                || guard.any_provider_gate_closed()
                || !st.blocked_providers.is_empty();
            if has_any_stop {
                if is_manual {
                    let frozen = guard.set_manual_killswitch(false, state).await;
                    guard.kick_reaudit();
                    (frozen, true)
                } else {
                    guard.clear_stop_and_reaudit(state).await;
                    (false, true)
                }
            } else {
                (guard.set_manual_killswitch(true, state).await, false)
            }
        }
    }
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
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn simulation_network_change_uses_pinned_history_or_defaults() {
        let mut data = state::AppStateData::default();
        let nc = build_simulation_network_change(&data, "anthropic");
        assert_eq!(nc.old_ip.as_deref(), Some("185.212.102.40"));
        assert_eq!(nc.old_country.as_deref(), Some("NL"));
        assert_eq!(nc.new_ip.as_deref(), Some("185.220.101.5"));
        assert_eq!(nc.new_country.as_deref(), Some("TR"));

        data.ip_history.insert(
            "anthropic".to_string(),
            vec![state::IpHistoryEntry::new(
                "45.83.220.10".to_string(),
                "DE".to_string(),
                Some(24940),
                1,
            )],
        );
        let nc_hist = build_simulation_network_change(&data, "anthropic");
        assert_eq!(nc_hist.old_ip.as_deref(), Some("45.83.220.10"));
        assert_eq!(nc_hist.old_country.as_deref(), Some("DE"));

        data.pinned_ip = Some("91.199.10.20".to_string());
        let nc_pinned = build_simulation_network_change(&data, "anthropic");
        assert_eq!(nc_pinned.old_ip.as_deref(), Some("91.199.10.20"));
        assert_eq!(nc_pinned.old_country.as_deref(), Some("DE"));
    }

    #[test]
    fn simulation_gate_reason_and_pause_mode_serde_work() {
        let data = state::AppStateData::default();
        let nc = build_simulation_network_change(&data, "anthropic");
        let sim_reason = proxy::hold_queue::build_gate_reason(None, Some(&nc), true);
        assert!(!sim_reason.trim().is_empty());
        assert!(sim_reason.contains("185.212.102.40"));
        assert!(sim_reason.contains("185.220.101.5"));

        let parsed: proxy::guard::PauseMode =
            serde_json::from_str("\"until_network_change\"").expect("parse PauseMode");
        assert_eq!(parsed, proxy::guard::PauseMode::UntilNetworkChange);
    }

    #[tokio::test]
    async fn resolve_interception_single_provider_allow_persists_exception_and_keeps_unrelated_block()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = state::AppState::load_or_default(path.clone());
        state.block_provider("anthropic").await.unwrap();
        state.block_provider("openai").await.unwrap();

        let auditor = auditor::Auditor::new().unwrap();
        let tel = auditor::NetworkTelemetry {
            ip: "5.5.5.5".to_string(),
            country_code: "RU".to_string(),
            hostname: None,
            asn: Some(1),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: crate::auditor::network::current_timestamp(),
        };
        auditor.resolver.set_cached(tel).await;

        let hq = Arc::new(proxy::HoldQueue::new());
        let server = Arc::new(
            proxy::ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), hq, None)
                .await
                .unwrap(),
        );
        let pm = proxy::ProxyManager {
            hold_queue: Arc::clone(&server.hold_queue),
            guard: Arc::clone(&server.guard),
            coverage: Arc::clone(&server.coverage),
            server,
        };
        pm.guard.sync_gates_with_state(&state).await;
        let rx = pm.hold_queue.register("hold-1".to_string(), "anthropic").await;

        resolve_interception_core(
            "hold-1",
            proxy::InterceptionAction::AllowSession,
            "anthropic",
            Some("provider"),
            &pm,
            &state,
            &auditor,
        )
        .await
        .unwrap();

        assert_eq!(rx.await.unwrap(), proxy::HoldResolution::Allow);
        assert!(!state.is_provider_blocked("anthropic").await);
        assert!(state.is_ip_trusted_for_provider("anthropic", "5.5.5.5").await);
        assert_eq!(pm.guard.gate_for(auditor::ProviderId::Anthropic), proxy::Gate::Open);
        // Unrelated openai remains blocked and un-excepted.
        assert!(state.is_provider_blocked("openai").await);
        assert!(!state.is_ip_trusted_for_provider("openai", "5.5.5.5").await);
        assert_eq!(pm.guard.gate_for(auditor::ProviderId::Openai), proxy::Gate::Blocked);

        // Reloading clears session_allowed but keeps trusted_exceptions.
        drop(state);
        let reloaded = state::AppState::load_or_default(path);
        assert!(!reloaded.is_provider_session_allowed("anthropic").await);
        assert!(reloaded.is_ip_trusted_for_provider("anthropic", "5.5.5.5").await);
    }

    #[tokio::test]
    async fn resolve_interception_network_block_skips_disabled_and_routed_providers() {
        let state = state::AppState::new_in_memory();
        state.set_provider_monitoring("gemini", false).await.unwrap();
        let route =
            crate::routing::parse_route_key("socks5://1.2.3.4:1080#nl", 1).unwrap();
        let route_id = state.upsert_route(route).await.unwrap();
        state
            .bind_provider_route("openai", Some(&route_id))
            .await
            .unwrap();

        let auditor = auditor::Auditor::new().unwrap();
        let hq = std::sync::Arc::new(proxy::HoldQueue::new());
        let server = std::sync::Arc::new(
            proxy::ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), hq, None)
                .await
                .unwrap(),
        );
        let pm = proxy::ProxyManager {
            hold_queue: std::sync::Arc::clone(&server.hold_queue),
            guard: std::sync::Arc::clone(&server.guard),
            coverage: std::sync::Arc::clone(&server.coverage),
            server,
        };
        let _rx = pm.hold_queue.register("net-1".to_string(), proxy::ALL_PROVIDERS).await;

        resolve_interception_core(
            "net-1",
            proxy::InterceptionAction::BlockUntilNetworkChange,
            proxy::ALL_PROVIDERS,
            Some("network"),
            &pm,
            &state,
            &auditor,
        )
        .await
        .unwrap();

        // Only enabled unrouted provider `anthropic` was blocked; disabled `gemini` & routed `openai` stay open.
        assert!(state.is_provider_blocked("anthropic").await);
        assert!(!state.is_provider_blocked("openai").await);
        assert!(!state.is_provider_blocked("gemini").await);
        assert_eq!(pm.guard.gate_for(auditor::ProviderId::Anthropic), proxy::Gate::Blocked);
        assert_eq!(pm.guard.gate_for(auditor::ProviderId::Openai), proxy::Gate::Open);
        assert_eq!(pm.guard.gate_for(auditor::ProviderId::Gemini), proxy::Gate::Open);
    }

    #[tokio::test]
    async fn toggle_or_clear_stop_unblocks_automatic_pause_without_engaging_manual_killswitch() {
        let state = state::AppState::new_in_memory();
        state.block_provider("anthropic").await.unwrap();
        let auditor = auditor::Auditor::new().unwrap();
        let hq = std::sync::Arc::new(proxy::HoldQueue::new());
        let server = std::sync::Arc::new(
            proxy::ProxyServer::bind_ephemeral(auditor, state.clone(), hq, None)
                .await
                .unwrap(),
        );
        server.guard.sync_gates_with_state(&state).await;
        assert!(!server.guard.is_manual_killswitch());
        assert!(server.guard.any_provider_gate_closed());
        assert_eq!(
            server.guard.gate_for(auditor::ProviderId::Anthropic),
            proxy::Gate::Blocked
        );

        let (now_manual, should_emit_changed) =
            toggle_or_clear_stop_core(None, &server.guard, &state).await;
        assert!(
            !now_manual,
            "clearing automatic provider blocks must NOT engage manual_killswitch"
        );
        assert!(should_emit_changed);
        assert!(!server.guard.is_manual_killswitch());
        assert!(!server.guard.any_provider_gate_closed());
        assert!(state.get_data().await.blocked_providers.is_empty());
    }

    #[tokio::test]
    async fn resolve_interception_superseded_block_and_open_guide_are_noops_and_never_reblock() {
        let state = state::AppState::new_in_memory();
        let auditor = auditor::Auditor::new().unwrap();
        let hq = Arc::new(proxy::HoldQueue::new());
        let server = Arc::new(
            proxy::ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), hq, None)
                .await
                .unwrap(),
        );
        let pm = proxy::ProxyManager {
            hold_queue: Arc::clone(&server.hold_queue),
            guard: Arc::clone(&server.guard),
            coverage: Arc::clone(&server.coverage),
            server,
        };

        // Provider hold superseded by network recovery must NOT re-block on BlockUntilNetworkChange or OpenGuideAndBlock.
        let _rx_prov = pm
            .hold_queue
            .register("hold-prov-1".to_string(), "anthropic")
            .await;
        pm.hold_queue.cancel_all_superseded().await;

        let out_block = resolve_interception_core(
            "hold-prov-1",
            proxy::InterceptionAction::BlockUntilNetworkChange,
            "anthropic",
            Some("provider"),
            &pm,
            &state,
            &auditor,
        )
        .await
        .unwrap();
        assert!(!out_block.applied);
        assert!(out_block.pause_status.is_none());
        assert!(!state.is_provider_blocked("anthropic").await);
        assert_eq!(pm.guard.gate_for(auditor::ProviderId::Anthropic), proxy::Gate::Open);

        let out_guide = resolve_interception_core(
            "hold-prov-1",
            proxy::InterceptionAction::OpenGuideAndBlock,
            "anthropic",
            Some("provider"),
            &pm,
            &state,
            &auditor,
        )
        .await
        .unwrap();
        assert!(!out_guide.applied);
        assert!(!out_guide.open_guide);
        assert!(!state.is_provider_blocked("anthropic").await);
        assert_eq!(pm.guard.gate_for(auditor::ProviderId::Anthropic), proxy::Gate::Open);

        // Network-scoped alert superseded before UI click must NOT block or enter PauseMode.
        let _rx_net = pm
            .hold_queue
            .register("net-stale-1".to_string(), proxy::ALL_PROVIDERS)
            .await;
        pm.hold_queue.cancel_all_superseded().await;
        let out_net = resolve_interception_core(
            "net-stale-1",
            proxy::InterceptionAction::BlockUntilNetworkChange,
            proxy::ALL_PROVIDERS,
            Some("network"),
            &pm,
            &state,
            &auditor,
        )
        .await
        .unwrap();
        assert!(!out_net.applied);
        assert!(!pm.guard.pause_status().paused);
        assert!(state.get_data().await.blocked_providers.is_empty());

        // Active provider hold still blocks as expected.
        let rx_active = pm
            .hold_queue
            .register("hold-active-1".to_string(), "anthropic")
            .await;
        let out_active = resolve_interception_core(
            "hold-active-1",
            proxy::InterceptionAction::BlockUntilNetworkChange,
            "anthropic",
            Some("provider"),
            &pm,
            &state,
            &auditor,
        )
        .await
        .unwrap();
        assert!(out_active.applied);
        assert_eq!(rx_active.await.unwrap(), proxy::HoldResolution::Block);
        assert!(state.is_provider_blocked("anthropic").await);
        assert_eq!(
            pm.guard.gate_for(auditor::ProviderId::Anthropic),
            proxy::Gate::Blocked
        );
    }
}
