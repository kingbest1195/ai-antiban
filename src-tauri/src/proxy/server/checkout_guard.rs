//! Zero-MITM Checkout Interceptor (`checkout_guard.rs`).
//!
//! Inspects ONLY the target host/port of `CONNECT` tunnels (never decrypting TLS or reading
//! payment form payloads). When a checkout/KYC host is contacted while `PaymentReadinessReport`
//! indicates high risk (`score < 70` or any blocker / `Red` tier), pauses the tunnel in
//! `HoldQueue` and opens `alert-popup` (`440x470`) with the checkout risk card.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tauri::Emitter;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::network::current_timestamp;
use crate::auditor::payment_readiness::{
    PaymentChannel, PaymentReadinessInput, PaymentReadinessReport, ReadinessTier, SubscriptionPlan,
    evaluate_payment_readiness,
};
use crate::clean_room::quarantine::PostPaymentQuarantineStatus;
use crate::proxy::hold_queue::{
    CheckoutRiskAlert, HoldResolution, PHASE_READY, RiskInterceptPayload,
};
use crate::state::{AppStateData, CleanProfileStatus};

use super::ProxyServer;
use super::responses::send_forbidden;

pub const CHECKOUT_ALLOW_TTL_SECS: u64 = 15 * 60;
pub const CHECKOUT_SCORE_THRESHOLD: u8 = 70;

pub const CHECKOUT_TRIGGER_DOMAINS: &[&str] = &[
    "checkout.stripe.com",
    "billing.stripe.com",
    "withpersona.com",
    "inquiry.withpersona.com",
    "pay.google.com",
];

pub fn normalize_checkout_host(raw: &str) -> String {
    let without_port = if let Some(bracketed) = raw.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or(raw)
    } else {
        raw.split(':').next().unwrap_or(raw)
    };
    without_port
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn host_matches(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

pub fn is_checkout_trigger_host(raw_host: &str) -> bool {
    let host = normalize_checkout_host(raw_host);
    !host.is_empty()
        && CHECKOUT_TRIGGER_DOMAINS
            .iter()
            .any(|d| host_matches(&host, d))
}

pub fn checkout_provider_key(raw_host: &str) -> String {
    format!("checkout:{}", normalize_checkout_host(raw_host))
}

pub fn should_intercept_report(report: &PaymentReadinessReport) -> bool {
    report.score < CHECKOUT_SCORE_THRESHOLD
        || !report.blockers.is_empty()
        || report.tier == ReadinessTier::Red
}

#[derive(Default)]
pub struct CheckoutGuardState {
    cached_report: RwLock<Option<PaymentReadinessReport>>,
    domain_allowances: RwLock<HashMap<String, Instant>>,
}

impl CheckoutGuardState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set_cached_report(&self, report: PaymentReadinessReport) {
        *self.cached_report.write().await = Some(report);
    }

    pub async fn cached_report(&self) -> Option<PaymentReadinessReport> {
        self.cached_report.read().await.clone()
    }

    pub async fn clear_cached_report(&self) {
        *self.cached_report.write().await = None;
    }

    pub async fn allow_domain_15m(&self, domain: &str) {
        self.allow_domain_for(domain, Duration::from_secs(CHECKOUT_ALLOW_TTL_SECS))
            .await;
    }

    pub async fn allow_domain_for(&self, domain: &str, ttl: Duration) {
        let key = normalize_checkout_host(domain);
        if key.is_empty() {
            return;
        }
        let deadline = Instant::now() + ttl;
        self.domain_allowances.write().await.insert(key, deadline);
    }

    pub async fn is_domain_allowed(&self, raw_host: &str) -> bool {
        let host = normalize_checkout_host(raw_host);
        if host.is_empty() {
            return false;
        }
        let now = Instant::now();
        let mut w = self.domain_allowances.write().await;
        w.retain(|_, exp| *exp > now);
        w.keys().any(|allowed| host_matches(&host, allowed))
    }

    pub async fn evaluate_risk_for_host(
        &self,
        raw_host: &str,
        state_data: &AppStateData,
    ) -> Option<CheckoutRiskAlert> {
        self.evaluate_risk_for_host_with_context(raw_host, state_data, false, false)
            .await
    }

    pub async fn evaluate_risk_for_host_with_context(
        &self,
        raw_host: &str,
        state_data: &AppStateData,
        is_alias: bool,
        has_app_handle: bool,
    ) -> Option<CheckoutRiskAlert> {
        let host = normalize_checkout_host(raw_host);
        if !is_checkout_trigger_host(&host) || self.is_domain_allowed(&host).await {
            return None;
        }

        if let Some(report) = self.cached_report().await {
            if !should_intercept_report(&report) {
                return None;
            }
            return Some(alert_from_report(host, report));
        }

        evaluate_unassessed_risk(host, state_data, is_alias, has_app_handle)
    }
}

fn alert_from_report(host: String, report: PaymentReadinessReport) -> CheckoutRiskAlert {
    let reason = report
        .blockers
        .first()
        .cloned()
        .or_else(|| report.warnings.first().cloned())
        .unwrap_or_else(|| {
            format!(
                "Проверка оплаты показала {}/100 (ниже безопасного уровня {CHECKOUT_SCORE_THRESHOLD}).",
                report.score
            )
        });
    CheckoutRiskAlert {
        domain: host,
        score: report.score,
        tier: report.tier,
        reason,
        blockers: report.blockers,
        warnings: report.warnings,
        recommended_action: report.recommended_action,
    }
}

fn has_payshield_state(state_data: &AppStateData) -> bool {
    !state_data.clean_room.profiles.is_empty()
        || state_data.clean_room.active_profile_id.is_some()
        || state_data
            .clean_room
            .global_post_payment_quarantine
            .is_some()
        || !state_data.clean_room.tainted_ips.is_empty()
        || state_data.warmup_started_at.is_some()
        || state_data.onboarding_v3_done
        || state_data.last_safe_logout_at.is_some()
}

fn evaluate_unassessed_risk(
    host: String,
    state_data: &AppStateData,
    is_alias: bool,
    has_app_handle: bool,
) -> Option<CheckoutRiskAlert> {
    let now_u64 = current_timestamp();
    let now = now_u64 as i64;
    if let Some(rem) = state_data.ip_change_cooldown_remaining_secs(now) {
        let mins = rem.div_ceil(60);
        let reason = format!(
            "Недавно сменился IP или страна выхода (подождите ещё {mins} мин) — переход на страницу оплаты сейчас несёт высокий риск запроса паспорта и селфи."
        );
        return Some(CheckoutRiskAlert {
            domain: host,
            score: 35,
            tier: ReadinessTier::Red,
            reason: reason.clone(),
            blockers: vec![reason],
            warnings: vec![],
            recommended_action: Some(
                "Отложите оплату до завершения 4-часовой паузы или откройте проверку оплаты в Заставе."
                    .to_string(),
            ),
        });
    }

    let active_profile = state_data
        .clean_room
        .active_profile_id
        .as_deref()
        .and_then(|pid| state_data.clean_room.profiles.iter().find(|p| p.id == pid));

    let quarantine_rec = active_profile
        .and_then(|p| p.post_payment_quarantine.clone())
        .or_else(|| state_data.clean_room.global_post_payment_quarantine.clone());
    let quarantine_status = PostPaymentQuarantineStatus::from_record(quarantine_rec, now_u64);
    if quarantine_status.active {
        let reason = quarantine_status.warning.unwrap_or_else(|| {
            "Активна защита маршрута на 3 дня (72 ч) после прошлой оплаты — проверьте параметры в Заставе перед новой покупкой."
                .to_string()
        });
        return Some(CheckoutRiskAlert {
            domain: host,
            score: 40,
            tier: ReadinessTier::Red,
            reason: reason.clone(),
            blockers: vec![reason],
            warnings: vec![],
            recommended_action: Some(
                "Дождитесь окончания 3-дневной защиты маршрута или откройте проверку оплаты в Заставе."
                    .to_string(),
            ),
        });
    }

    if let Some(prof) = active_profile
        && (prof.status == CleanProfileStatus::Tainted
            || prof
                .last_exit_ip
                .as_deref()
                .is_some_and(|ip| state_data.clean_room.tainted_ips.contains_key(ip)))
    {
        let reason = format!(
            "Профиль «{}» или его адрес подключения помечен как ненадёжный — оплата заблокирована для вашей безопасности.",
            prof.label
        );
        return Some(CheckoutRiskAlert {
            domain: host,
            score: 20,
            tier: ReadinessTier::Red,
            reason: reason.clone(),
            blockers: vec![reason],
            warnings: vec![],
            recommended_action: Some(
                "Создайте новый профиль «Чистой комнаты» с чистым выделенным ключом.".to_string(),
            ),
        });
    }

    // Preserve isolated alias-routing tests that have no PayShield/CleanRoom state and no Tauri app.
    if is_alias && !has_app_handle && !has_payshield_state(state_data) {
        return None;
    }

    let split_ip_risk = !is_alias;
    let eval_input = PaymentReadinessInput::from_runtime(
        state_data,
        None,
        None,
        None,
        None,
        None,
        PaymentChannel::DirectCard,
        is_alias,
        SubscriptionPlan::Pro,
        split_ip_risk,
        None,
    );
    let report = evaluate_payment_readiness(&eval_input);
    if should_intercept_report(&report) {
        Some(alert_from_report(host, report))
    } else {
        None
    }
}

impl ProxyServer {
    /// Runs Zero-MITM checkout guard for `CONNECT` targets. Returns `Ok(true)` if the tunnel may
    /// proceed, or `Ok(false)` after sending `403 Forbidden` to the client.
    pub(super) async fn check_checkout_guard(
        &self,
        client: &mut TcpStream,
        raw_host: &str,
    ) -> Result<bool, std::io::Error> {
        let host = normalize_checkout_host(raw_host);
        if !is_checkout_trigger_host(&host) {
            return Ok(true);
        }

        let state_data = self.state.get_data().await;
        let Some(alert) = self
            .checkout_guard
            .evaluate_risk_for_host_with_context(
                &host,
                &state_data,
                self.is_alias,
                self.app_handle.is_some(),
            )
            .await
        else {
            return Ok(true);
        };

        self.state
            .stats()
            .record_intercepted(&host, "anthropic", "HELD", "??");

        let provider_key = checkout_provider_key(&host);
        let (hold_id, rx, is_leader) = self
            .hold_queue
            .register_or_coalesce_provider(Uuid::new_v4().to_string(), &provider_key)
            .await;

        if is_leader {
            let detected_at_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let payload = RiskInterceptPayload {
                id: hold_id.clone(),
                provider: ProviderId::Anthropic,
                host: host.clone(),
                report: None,
                ttl_seconds: self.hold_ttl.as_secs().max(1),
                scope: "checkout".to_string(),
                network_change: None,
                is_simulation: false,
                detected_at_ms,
                phase: PHASE_READY.to_string(),
                gate_reason: Some(alert.reason.clone()),
                checkout_risk: Some(alert),
            };
            self.hold_queue.set_alert(payload.clone());
            if let Some(app) = &self.app_handle {
                let _ = app.emit("interceptor://risk-detected", &payload);
                crate::proxy::popup_port::show_alert_popup(app, None);
            }
        }

        let resolution = tokio::time::timeout(self.hold_ttl, rx).await;
        self.hold_queue.remove(&hold_id).await;

        match resolution {
            Ok(Ok(HoldResolution::Allow)) => Ok(true),
            Ok(Ok(HoldResolution::Block)) | Ok(Ok(HoldResolution::Superseded)) | Ok(Err(_)) => {
                send_forbidden(
                    client,
                    "Payment blocked by Zastava: review payment readiness first.",
                )
                .await?;
                Ok(false)
            }
            Err(_) => {
                self.hold_queue
                    .resolve(&hold_id, HoldResolution::Block)
                    .await;
                if let Some(app) = &self.app_handle
                    && self.hold_queue.current_alert().is_none()
                {
                    crate::proxy::popup_port::hide_alert_popup(app);
                    let _ = app.emit("interceptor://resolved", "");
                }
                send_forbidden(
                    client,
                    "Payment request timed out waiting for Zastava confirmation.",
                )
                .await?;
                Ok(false)
            }
        }
    }
}
