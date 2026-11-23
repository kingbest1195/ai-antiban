//! Payment BIN checker (Zero PCI-DSS Scope, 6..=8 digits), 4-axis Payment Readiness audit,
//! Zero-MITM checkout guard actions, 72h post-payment quarantine, and warm-up timer commands.

use super::AppContext;
use crate::auditor::Auditor;
use crate::auditor::bin_radar_verify::submit_local_bin_radar_report;
use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::payment_advisor::{
    evaluate_advisor_plan, get_bin_radar_stats_for, get_evaluated_providers_manifest,
};
use crate::auditor::payment_readiness::{
    PaymentChannel, PaymentReadinessInput, PaymentReadinessReport, SubscriptionPlan,
    evaluate_payment_readiness as eval_payment_readiness_core,
};
use crate::bin_checker::{self, BinAuditResult, BinReport, validate_strict_bin_prefix};
use crate::clean_room::quarantine::{
    PostPaymentQuarantineStatus, QuarantineActivationInput, activate_quarantine_in,
    get_quarantine_status_in, override_quarantine_in,
};
use crate::core::bin_radar::{AiPaymentService, BinRadarLookupStats, BinRadarReport};
use crate::core::payment_advisor::{AdvisorPlan, AdvisorQuery};
use crate::core::providers_manifest::EvaluatedProvidersManifest;
use crate::proxy::server::checkout_guard::checkout_provider_key;
use crate::proxy::{HoldResolution, ProxyManager};
use crate::routing::RouteSelection;
use serde::Deserialize;
use std::path::Path;
use tauri::{Emitter, Manager};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EvaluatePaymentReadinessParams {
    #[serde(default)]
    pub bin: Option<String>,
    #[serde(default)]
    pub billing_country: Option<String>,
    #[serde(default)]
    pub google_profile_country: Option<String>,
    #[serde(default)]
    pub apple_id_country: Option<String>,
    #[serde(default)]
    pub channel: PaymentChannel,
    #[serde(default)]
    pub in_clean_room: bool,
    #[serde(default)]
    pub account_age_confirmed_96h: Option<bool>,
    #[serde(default)]
    pub plan: SubscriptionPlan,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub target_service: Option<AiPaymentService>,
}

fn sanitize_country_code(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim)
        .filter(|cc| cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_alphabetic()))
}

#[tauri::command]
pub async fn check_payment_bin(
    bin: String,
    vpn_country: Option<String>,
    app: tauri::AppHandle,
    checker: tauri::State<'_, bin_checker::BinChecker>,
) -> Result<BinAuditResult, String> {
    let clean_bin = bin_checker::BinChecker::sanitize_bin(&bin)?;
    let data_dir = app.path().app_data_dir().ok();
    let vpn_cc = sanitize_country_code(vpn_country.as_deref());
    let report = checker
        .check_bin_report_with_cache_dir(&clean_bin, vpn_cc, data_dir.as_deref())
        .await?;
    let guide_ref = if report.status == crate::auditor::geo_matrix::CheckStatus::Ok {
        None
    } else {
        Some(crate::auditor::geo_matrix::GUIDE_PAYMENT_CARDS.to_string())
    };
    Ok(BinAuditResult::from_report(report, guide_ref))
}

async fn check_card_bin_with(
    bin: &str,
    vpn_country: Option<&str>,
    data_dir: Option<&Path>,
    checker: &bin_checker::BinChecker,
) -> Result<BinReport, String> {
    let strict_bin = validate_strict_bin_prefix(bin)?;
    let vpn_cc = sanitize_country_code(vpn_country);
    checker
        .check_bin_report_with_cache_dir(&strict_bin, vpn_cc, data_dir)
        .await
}

#[tauri::command]
pub async fn check_card_bin(
    bin: String,
    vpn_country: Option<String>,
    app: tauri::AppHandle,
    checker: tauri::State<'_, bin_checker::BinChecker>,
) -> Result<BinReport, String> {
    let data_dir = app.path().app_data_dir().ok();
    check_card_bin_with(&bin, vpn_country.as_deref(), data_dir.as_deref(), &checker).await
}

#[tauri::command]
pub async fn evaluate_payment_readiness(
    params: EvaluatePaymentReadinessParams,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, Auditor>,
    checker: tauri::State<'_, bin_checker::BinChecker>,
    proxy_mgr: tauri::State<'_, ProxyManager>,
) -> Result<PaymentReadinessReport, String> {
    let state_data = state.get_data().await;
    let provider_id = params
        .provider
        .as_deref()
        .and_then(ProviderId::from_id)
        .unwrap_or(match params.target_service {
            Some(AiPaymentService::Gemini) => ProviderId::Gemini,
            Some(AiPaymentService::Chatgpt) => ProviderId::Openai,
            _ => ProviderId::Anthropic,
        });

    let active_profile = params
        .profile_id
        .as_deref()
        .or(state_data.clean_room.active_profile_id.as_deref())
        .and_then(|pid| state_data.clean_room.profiles.iter().find(|p| p.id == pid));

    let risk_report = if let Some(route_id) =
        active_profile.and_then(|p| p.bound_route_id.as_deref())
        && let Some(route) = state_data.routes.iter().find(|r| r.id == route_id)
    {
        auditor
            .evaluate_all_with(
                provider_id,
                &state,
                &RouteSelection::Route(route.clone()),
                false,
            )
            .await
            .ok()
    } else {
        auditor.evaluate_all(provider_id, &state, false).await.ok()
    };

    let exit_country = risk_report
        .as_ref()
        .and_then(|r| sanitize_country_code(Some(r.telemetry.country_code.as_str())));
    let data_dir = app.path().app_data_dir().ok();
    let bin_report = match params
        .bin
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            let strict_bin = validate_strict_bin_prefix(raw)?;
            Some(
                checker
                    .check_bin_report_with_cache_dir(&strict_bin, exit_country, data_dir.as_deref())
                    .await?,
            )
        }
        None => None,
    };

    let sysproxy_active = tokio::task::spawn_blocking(crate::sysproxy::is_sysproxy_active)
        .await
        .unwrap_or(false);
    let split_ip_checkout_risk = !params.in_clean_room && !sysproxy_active;

    let mut eval_input = PaymentReadinessInput::from_runtime(
        &state_data,
        risk_report.as_ref(),
        bin_report,
        params.billing_country,
        params.google_profile_country,
        params.apple_id_country,
        params.channel,
        params.in_clean_room,
        params.plan,
        split_ip_checkout_risk,
        params.profile_id.as_deref(),
    );
    eval_input.account_age_confirmed_96h = params.account_age_confirmed_96h;
    eval_input.target_service = params.target_service;
    let report = eval_payment_readiness_core(&eval_input);
    proxy_mgr
        .server
        .checkout_guard
        .set_cached_report(report.clone())
        .await;
    Ok(report)
}

#[tauri::command]
pub async fn cancel_and_inspect(
    id: String,
    domain: String,
    proxy_manager: tauri::State<'_, ProxyManager>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let resolved_id = proxy_manager
        .hold_queue
        .resolve(&id, HoldResolution::Block)
        .await;
    let resolved_domain = proxy_manager
        .hold_queue
        .resolve_all_for_provider(&checkout_provider_key(&domain), HoldResolution::Block)
        .await;
    crate::popup::hide_alert_popup(&app);
    let _ = app.emit("interceptor://resolved", "");
    if let Some(main_win) = app.get_webview_window("main") {
        let _ = main_win.show();
        let _ = main_win.set_focus();
    }
    let _ = app.emit("payshield://open-payment-check", &domain);
    Ok(resolved_id || resolved_domain > 0)
}

#[tauri::command]
pub async fn allow_checkout_15m(
    id: String,
    domain: String,
    proxy_manager: tauri::State<'_, ProxyManager>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    proxy_manager
        .server
        .checkout_guard
        .allow_domain_15m(&domain)
        .await;
    let resolved_id = proxy_manager
        .hold_queue
        .resolve(&id, HoldResolution::Allow)
        .await;
    let resolved_domain = proxy_manager
        .hold_queue
        .resolve_all_for_provider(&checkout_provider_key(&domain), HoldResolution::Allow)
        .await;
    crate::popup::hide_alert_popup(&app);
    let _ = app.emit("interceptor://resolved", "");
    Ok(resolved_id || resolved_domain > 0)
}

#[tauri::command]
pub async fn activate_post_payment_quarantine(
    profile_id: Option<String>,
    route_id: Option<String>,
    exit_ip: Option<String>,
    exit_asn: Option<u32>,
    exit_country: Option<String>,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, Auditor>,
) -> Result<PostPaymentQuarantineStatus, String> {
    let (resolved_ip, resolved_asn, resolved_country) =
        if exit_ip.is_none() || exit_country.is_none() {
            match auditor
                .resolve_for_provider(ProviderId::Anthropic, &state, false)
                .await
            {
                Ok(tel) => (
                    exit_ip.or(Some(tel.ip)),
                    exit_asn.or(tel.asn),
                    exit_country.or(Some(tel.country_code)),
                ),
                Err(_) => (exit_ip, exit_asn, exit_country),
            }
        } else {
            (exit_ip, exit_asn, exit_country)
        };

    activate_quarantine_in(
        &state,
        QuarantineActivationInput {
            profile_id,
            route_id,
            exit_ip: resolved_ip,
            exit_asn: resolved_asn,
            exit_country: resolved_country,
        },
    )
    .await
}

#[tauri::command]
pub async fn get_post_payment_quarantine_status(
    profile_id: Option<String>,
    state: tauri::State<'_, AppContext>,
) -> Result<PostPaymentQuarantineStatus, String> {
    get_quarantine_status_in(&state, profile_id.as_deref()).await
}

#[tauri::command]
pub async fn override_post_payment_quarantine(
    profile_id: Option<String>,
    reason: Option<String>,
    state: tauri::State<'_, AppContext>,
) -> Result<PostPaymentQuarantineStatus, String> {
    override_quarantine_in(&state, profile_id.as_deref(), reason.as_deref()).await
}

#[tauri::command]
pub async fn set_warmup_timer(
    timestamp: Option<u64>,
    state: tauri::State<'_, AppContext>,
) -> Result<Option<u64>, String> {
    state
        .set_warmup_started_at(timestamp)
        .await
        .map_err(|e| e.to_string())?;
    Ok(timestamp)
}

#[tauri::command]
pub async fn get_payment_advice(
    query: AdvisorQuery,
    app: tauri::AppHandle,
) -> Result<AdvisorPlan, String> {
    let data_dir = app.path().app_data_dir().ok();
    Ok(evaluate_advisor_plan(&query, data_dir.as_deref()))
}

#[tauri::command]
pub async fn get_bin_radar_stats(
    bin_prefix: String,
    service: Option<AiPaymentService>,
    app: tauri::AppHandle,
) -> Result<BinRadarLookupStats, String> {
    let clean = validate_strict_bin_prefix(bin_prefix.trim())?;
    let data_dir = app.path().app_data_dir().ok();
    let svc = service.unwrap_or(AiPaymentService::ClaudePro);
    Ok(get_bin_radar_stats_for(data_dir.as_deref(), &clean, svc))
}

#[tauri::command]
pub async fn get_providers_manifest(
    app: tauri::AppHandle,
) -> Result<EvaluatedProvidersManifest, String> {
    let data_dir = app.path().app_data_dir().ok();
    Ok(get_evaluated_providers_manifest(data_dir.as_deref()))
}

#[tauri::command]
pub async fn submit_bin_radar_report(
    report: serde_json::Value,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
) -> Result<BinRadarReport, String> {
    let opt_in = state.is_bin_radar_opt_in().await;
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Не удалось определить папку данных: {e}"))?;
    let raw =
        serde_json::to_string(&report).map_err(|e| format!("Некорректный формат отчёта: {e}"))?;
    submit_local_bin_radar_report(&data_dir, opt_in, &raw)
}

#[tauri::command]
pub async fn set_bin_radar_opt_in(
    enabled: bool,
    state: tauri::State<'_, AppContext>,
) -> Result<bool, String> {
    state
        .set_bin_radar_opt_in(enabled)
        .await
        .map_err(|e| e.to_string())?;
    Ok(enabled)
}

#[cfg(test)]
#[path = "payment_tests.rs"]
mod tests;
