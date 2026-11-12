//! Interception resolution/simulation, behavior & popup position settings, network kill-switch.

use super::AppContext;
use crate::popup::show_and_position_alert_popup;
use crate::{auditor, proxy, state};
use tauri::{Emitter, Manager};

/// `measured_via` of the canned results in the demo simulation.
const SIMULATED_VIA: &str = "simulation";

#[tauri::command]
pub async fn resolve_interception(
    id: String,
    action: proxy::InterceptionAction,
    provider: String,
    scope: Option<String>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
    state: tauri::State<'_, state::AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let is_simulation = scope.as_deref() == Some("simulation") || id.starts_with("sim-");
    if is_simulation {
        let resolution = match action {
            proxy::InterceptionAction::AllowSession => proxy::HoldResolution::Allow,
            proxy::InterceptionAction::BlockUntilNetworkChange
            | proxy::InterceptionAction::OpenGuideAndBlock => proxy::HoldResolution::Block,
        };
        proxy_manager.hold_queue.resolve(&id, resolution).await;
        if matches!(action, proxy::InterceptionAction::OpenGuideAndBlock) {
            if let Some(main_win) = app.get_webview_window("main") {
                let _ = main_win.show();
                let _ = main_win.set_focus();
                let _ = app.emit("interceptor://open-guide", "01-personal-vpn-15min");
            }
        }
        if let Some(popup) = app.get_webview_window("alert-popup") {
            let _ = popup.hide();
        }
        let _ = app.emit("interceptor://resolved", "");
        return Ok(());
    }

    // `all` or scope "network" = network-wide hold created by the network guard after a sudden IP change
    let is_network_scope = scope.as_deref() == Some("network") || provider == proxy::ALL_PROVIDERS;
    let targets: Vec<String> = if is_network_scope {
        state::KNOWN_PROVIDERS.iter().map(|p| p.to_string()).collect()
    } else {
        vec![provider.clone()]
    };

    match action {
        proxy::InterceptionAction::AllowSession => {
            if is_network_scope {
                // Network-wide allow: only for the alert that is still current and fully audited
                // (checked and applied by the guard under its lock). A stale / premature allow
                // opens nothing and writes nothing.
                proxy_manager
                    .guard
                    .allow_network_alert(&id, &targets)
                    .await?;
            } else {
                for p in &targets {
                    state
                        .allow_provider_for_session(p)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                proxy_manager
                    .hold_queue
                    .resolve(&id, proxy::HoldResolution::Allow)
                    .await;
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
            for p in &targets {
                state.block_provider(p).await.map_err(|e| e.to_string())?;
            }
            proxy_manager
                .hold_queue
                .resolve(&id, proxy::HoldResolution::Block)
                .await;
            for p in targets.iter().map(String::as_str).chain([proxy::ALL_PROVIDERS]) {
                proxy_manager
                    .hold_queue
                    .resolve_all_for_provider(p, proxy::HoldResolution::Block)
                    .await;
            }
        }
        proxy::InterceptionAction::OpenGuideAndBlock => {
            for p in &targets {
                state.block_provider(p).await.map_err(|e| e.to_string())?;
            }
            proxy_manager
                .hold_queue
                .resolve(&id, proxy::HoldResolution::Block)
                .await;
            for p in targets.iter().map(String::as_str).chain([proxy::ALL_PROVIDERS]) {
                proxy_manager
                    .hold_queue
                    .resolve_all_for_provider(p, proxy::HoldResolution::Block)
                    .await;
            }
            if let Some(main_win) = app.get_webview_window("main") {
                let _ = main_win.show();
                let _ = main_win.set_focus();
                let _ = app.emit("interceptor://open-guide", "01-personal-vpn-15min");
            }
        }
    }

    if let Some(popup) = app.get_webview_window("alert-popup") {
        let _ = popup.hide();
    }
    let _ = app.emit("interceptor://resolved", "");

    Ok(())
}

#[tauri::command]
pub async fn simulate_interception(
    provider: Option<String>,
    app: tauri::AppHandle,
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
    let travel_result = auditor::CheckResult::ok("TRAVEL_NORMAL", "Конфликтов перемещения за 12ч нет.");
    let dnsbl_report = auditor::check_all_dnsbl(&telemetry.ip, &dangerous_asns).await;
    let dnsbl_result = auditor::evaluate_dnsbl_report(&dnsbl_report);
    let asn_result = auditor::evaluate_asn_reputation(
        telemetry.asn,
        telemetry.isp.as_deref(),
        telemetry.org.as_deref(),
        &dangerous_asns,
        false,
    );
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

    let payload = proxy::RiskInterceptPayload {
        id: hold_id,
        provider: provider_id,
        host: "ДЕМО-ТЕСТ: api.anthropic.com:443".to_string(),
        report: Some(report),
        ttl_seconds: proxy::hold_queue::DEFAULT_HOLD_TTL_SECS,
        scope: "simulation".to_string(),
        network_change: None,
        is_simulation: true,
        detected_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        phase: proxy::hold_queue::PHASE_READY.to_string(),
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
    state.set_interception_behavior(behavior).await.map_err(|e| e.to_string())
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
    state.set_popup_position(position).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn toggle_network_killswitch_cmd(
    freeze: Option<bool>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
    state: tauri::State<'_, AppContext>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let target_freeze = freeze.unwrap_or(!guard.is_gate_blocked());
    let now_frozen = guard.set_manual_killswitch(target_freeze, &state).await;
    crate::tray::update_tray_killswitch(&app, now_frozen);
    let _ = app.emit("tray://killswitch-toggled", now_frozen);
    Ok(now_frozen)
}

#[tauri::command]
pub async fn get_network_killswitch_status_cmd(
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<bool, String> {
    Ok(guard.is_gate_blocked())
}
