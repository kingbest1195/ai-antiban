//! Audit, IP pinning, provider allow/unblock and state/stats read commands.

use crate::tray::update_tray_from_report;
use crate::{auditor, proxy, state};
use std::sync::Arc;
use tauri::Emitter;

/// Event with the pieces of a running audit (see `audit_connection`, argument `run_id`).
pub const AUDIT_PROGRESS_EVENT: &str = "audit://progress";

/// Payload of [`AUDIT_PROGRESS_EVENT`]: `run_id` tells the interface which call it belongs to.
#[derive(serde::Serialize, Clone)]
struct AuditProgressEvent<'a> {
    run_id: &'a str,
    provider: &'a str,
    #[serde(flatten)]
    progress: auditor::AuditProgress,
}

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
    let report = match auditor
        .evaluate_all_progress(provider_id, &state, force_refresh.unwrap_or(false), sink)
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
        let is_pinned = is_ip_pinned_for_state(&st, provider_id, &report.telemetry.ip);
        let has_blocked = !st.blocked_providers.is_empty() || guard.gate() != proxy::Gate::Open;
        let tray_report = proxy::guard::effective_tray_report(&report, has_blocked, &st);
        update_tray_from_report(&app, &tray_report, is_pinned, has_blocked);
    }

    Ok(report)
}

fn is_ip_pinned_for_state(
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
    let is_routed = matches!(
        state.route_selection(pid.as_str()).await,
        crate::routing::RouteSelection::Route(_)
    );
    if is_routed {
        Ok(pid.as_str().to_string())
    } else {
        Ok("default".to_string())
    }
}

async fn pin_ip_inner(
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

async fn unpin_ip_inner(state: &state::AppState, provider: Option<String>) -> Result<(), String> {
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

/// Pins `ip` for the routed `provider` key, or for `"default"` when the provider is Direct or omitted.
#[tauri::command]
pub async fn pin_current_ip(
    ip: String,
    provider: Option<String>,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    pin_ip_inner(&state, ip, provider).await
}

/// Unpins the IP for `provider` (or clears all pinned IPs when `provider` is omitted).
#[tauri::command]
pub async fn unpin_ip(
    provider: Option<String>,
    state: tauri::State<'_, state::AppState>,
) -> Result<(), String> {
    unpin_ip_inner(&state, provider).await
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
    state
        .allow_provider_for_session(&provider)
        .await
        .map_err(|e| e.to_string())?;

    // Record current IP in history so Impossible Travel is acknowledged and cleared
    let mut tel_opt = None;
    if let Some(provider_id) = auditor::ProviderId::from_id(&provider)
        && let Ok(tel) = auditor
            .resolve_for_provider(provider_id, &state, false)
            .await
    {
        let data = state.get_data().await;
        let selection = crate::routing::select_route(&data, provider_id.as_str());
        let entry = state::IpHistoryEntry::new(
            tel.ip.clone(),
            tel.country_code.clone(),
            tel.asn,
            tel.resolved_at,
        );
        let _ = state
            .record_ip_history_for_selection(provider_id.as_str(), &selection, entry)
            .await;
        if matches!(selection, crate::routing::RouteSelection::Direct) {
            tel_opt = Some(tel);
        }
    }

    proxy_manager
        .hold_queue
        .resolve_all_for_provider(&provider, proxy::HoldResolution::Allow)
        .await;

    // Confirm current baseline as trusted and resume traffic if frozen (no-op under manual kill-switch)
    proxy_manager
        .guard
        .confirm_current_session(tel_opt.as_ref())
        .await;

    Ok(())
}

#[tauri::command]
pub async fn unblock_provider_cmd(
    provider: String,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<(), String> {
    state
        .unblock_provider(&provider)
        .await
        .map_err(|e| e.to_string())?;

    // Also update IP history to current IP so a stale Impossible Travel doesn't immediately re-flag
    let mut tel_opt = None;
    if let Some(provider_id) = auditor::ProviderId::from_id(&provider)
        && let Ok(tel) = auditor
            .resolve_for_provider(provider_id, &state, false)
            .await
    {
        let data = state.get_data().await;
        let selection = crate::routing::select_route(&data, provider_id.as_str());
        let entry = state::IpHistoryEntry::new(
            tel.ip.clone(),
            tel.country_code.clone(),
            tel.asn,
            tel.resolved_at,
        );
        let _ = state
            .record_ip_history_for_selection(provider_id.as_str(), &selection, entry)
            .await;
        if matches!(selection, crate::routing::RouteSelection::Direct) {
            tel_opt = Some(tel);
        }
    }

    if state.get_data().await.blocked_providers.is_empty()
        && !proxy_manager.guard.is_manual_killswitch()
    {
        proxy_manager
            .guard
            .confirm_current_session(tel_opt.as_ref())
            .await;
    }

    Ok(())
}

fn should_verify_unblock(
    manual_killswitch: bool,
    report: &auditor::RiskReport,
    _pinned_ip: Option<&str>,
) -> bool {
    if manual_killswitch {
        return false;
    }
    proxy::guard::report_no_critical_and_geo_ok(report)
}

/// Runs a fresh forced audit for `provider` and unblocks it if traffic is no longer under a
/// manual kill-switch and the audit confirms an allowed geo with no critical failures.
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
    let report = auditor.evaluate_all(provider_id, &state, true).await?;

    let st_before = state.get_data().await;
    let manual_ks = guard.is_manual_killswitch();
    let is_pinned = is_ip_pinned_for_state(&st_before, provider_id, &report.telemetry.ip);

    if !should_verify_unblock(manual_ks, &report, st_before.pinned_ip.as_deref()) {
        let has_blocked =
            !st_before.blocked_providers.is_empty() || guard.gate() != proxy::Gate::Open;
        update_tray_from_report(&app, &report, is_pinned, has_blocked);
        return Ok(false);
    }

    let selection = crate::routing::select_route(&st_before, provider_id.as_str());
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
    let has_blocked = !st_after.blocked_providers.is_empty() || guard.gate() != proxy::Gate::Open;
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
mod pin_tests {
    use super::*;
    use crate::routing::{Entry, EntryProto, Route};

    #[tokio::test]
    async fn pin_ip_isolates_routed_provider_from_default_vpn_and_preserves_route_lock() {
        let state = state::AppState::new_in_memory();
        let route = Route {
            id: "fr-1".to_string(),
            label: "France".to_string(),
            country: Some("FR".to_string()),
            exit_ip: Some("136.244.114.42".to_string()),
            expires_at: None,
            entries: vec![Entry {
                proto: EntryProto::Http,
                host: "136.244.114.42".to_string(),
                port: 8443,
                username: None,
                password: None,
                sni: None,
            }],
            raw_key: String::new(),
            enabled: true,
            added_at: 0,
        };
        state.upsert_route(route).await.unwrap();
        state
            .bind_provider_route("gemini", Some("fr-1"))
            .await
            .unwrap();

        // Direct provider (anthropic) pins under "default".
        pin_ip_inner(
            &state,
            "145.241.193.245".to_string(),
            Some("anthropic".to_string()),
        )
        .await
        .unwrap();

        let st = state.get_data().await;
        assert_eq!(st.pinned_ip.as_deref(), Some("145.241.193.245"));
        assert_eq!(
            st.pinned_ips.get("default").map(String::as_str),
            Some("145.241.193.245")
        );
        assert!(!st.pinned_ips.contains_key("gemini"));

        // Routed Gemini is pinned by its Zastava key even when its exit differs from global VPN.
        assert!(is_ip_pinned_for_state(
            &st,
            auditor::ProviderId::Gemini,
            "136.244.114.42"
        ));
        assert!(is_ip_pinned_for_state(
            &st,
            auditor::ProviderId::Anthropic,
            "145.241.193.245"
        ));
        assert!(!is_ip_pinned_for_state(
            &st,
            auditor::ProviderId::Anthropic,
            "1.2.3.4"
        ));

        // Explicit pin on routed Gemini goes into pinned_ips["gemini"] without touching "default".
        pin_ip_inner(
            &state,
            "136.244.114.42".to_string(),
            Some("gemini".to_string()),
        )
        .await
        .unwrap();
        let st2 = state.get_data().await;
        assert_eq!(
            st2.pinned_ips.get("gemini").map(String::as_str),
            Some("136.244.114.42")
        );
        assert_eq!(
            st2.pinned_ips.get("default").map(String::as_str),
            Some("145.241.193.245")
        );
        assert!(!is_ip_pinned_for_state(
            &st2,
            auditor::ProviderId::Gemini,
            "99.99.99.99"
        ));

        // Unpinning Gemini only removes Gemini's explicit pin, keeping "default" intact.
        unpin_ip_inner(&state, Some("gemini".to_string()))
            .await
            .unwrap();
        let st3 = state.get_data().await;
        assert!(!st3.pinned_ips.contains_key("gemini"));
        assert_eq!(
            st3.pinned_ips.get("default").map(String::as_str),
            Some("145.241.193.245")
        );

        // Unpinning with None clears all pinned IPs.
        unpin_ip_inner(&state, None).await.unwrap();
        let st4 = state.get_data().await;
        assert!(st4.pinned_ip.is_none());
        assert!(st4.pinned_ips.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_event_is_one_flat_object_the_interface_reads() {
        let event = AuditProgressEvent {
            run_id: "r1",
            provider: "anthropic",
            progress: auditor::AuditProgress::Check {
                index: 6,
                result: auditor::CheckResult::ok("DNS_PUBLIC_RESOLVER", "ok"),
            },
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["run_id"], "r1");
        assert_eq!(json["provider"], "anthropic");
        assert_eq!(json["kind"], "check");
        assert_eq!(json["index"], 6);
        assert_eq!(json["result"]["code"], "DNS_PUBLIC_RESOLVER");
    }

    #[test]
    fn verify_unblock_decision_respects_killswitch_geo_and_critical_checks() {
        let ok = auditor::CheckResult::ok("T", "t");
        let base_report = |status: auditor::OverallStatus, cc: &str| auditor::RiskReport {
            provider: auditor::ProviderId::Openai,
            overall_status: status,
            trust_score: 90,
            telemetry: auditor::NetworkTelemetry {
                ip: "1.1.1.1".into(),
                country_code: cc.into(),
                hostname: None,
                asn: Some(1),
                org: None,
                isp: None,
                timezone: None,
                resolved_at: 0,
            },
            geo_result: ok.clone(),
            pinning_result: ok.clone(),
            travel_result: ok.clone(),
            dnsbl_result: ok.clone(),
            dnsbl_clean_count: "0/0".into(),
            asn_result: ok.clone(),
            ipv6_result: ok.clone(),
            timezone_result: ok.clone(),
            ipv6_exit: false,
            checks: vec![ok.clone()],
            unknown_count: 0,
            applicable_count: 14,
            incomplete: false,
        };

        let green = base_report(auditor::OverallStatus::Green, "NL");
        assert!(should_verify_unblock(false, &green, None));
        assert!(!should_verify_unblock(true, &green, None));

        // Non-critical Yellow warning on allowed geo / pinned IP succeeds.
        let mut yellow = base_report(auditor::OverallStatus::Yellow, "NL");
        yellow.checks = vec![
            ok.clone(),
            auditor::CheckResult::warning("TZ", "diff", None),
        ];
        assert!(should_verify_unblock(false, &yellow, Some("1.1.1.1")));

        // Sanctioned country stays blocked even if checks weren't flagged.
        let ru = base_report(auditor::OverallStatus::Green, "RU");
        assert!(!should_verify_unblock(false, &ru, None));

        // Red status stays blocked.
        let red = base_report(auditor::OverallStatus::Red, "NL");
        assert!(!should_verify_unblock(false, &red, Some("1.1.1.1")));
    }
}
