//! 72-hour Post-Payment Quarantine Lock (`PostPaymentQuarantine`).
//!
//! Switching countries/routes/exit IPs during the first 72 hours after a payment
//! is one of the primary triggers for delayed Persona KYC verification.

use serde::{Deserialize, Serialize};

use crate::auditor::network::current_timestamp;
use crate::clean_room::CleanProfileId;
use crate::state::AppState;

pub use crate::state::PostPaymentQuarantine;

pub const POST_PAYMENT_QUARANTINE_SECS: u64 = 72 * 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostPaymentQuarantineStatus {
    pub active: bool,
    pub remaining_hours: u64,
    pub remaining_secs: u64,
    pub quarantine: Option<PostPaymentQuarantine>,
    pub warning: Option<String>,
}

impl PostPaymentQuarantineStatus {
    pub fn from_record(q: Option<PostPaymentQuarantine>, now: u64) -> Self {
        let Some(ref rec) = q else {
            return Self {
                active: false,
                remaining_hours: 0,
                remaining_secs: 0,
                quarantine: None,
                warning: None,
            };
        };
        if rec.overridden_at.is_some() || now >= rec.expires_at {
            return Self {
                active: false,
                remaining_hours: 0,
                remaining_secs: 0,
                quarantine: q,
                warning: None,
            };
        }
        let remaining_secs = rec.expires_at.saturating_sub(now);
        let remaining_hours = remaining_secs.div_ceil(3600);
        let warning = Some(format!(
            "Защита маршрута после оплаты: осталось {remaining_hours} ч из 72 ч. Смена страны, сервера или ключа сейчас повышает риск последующей проверки по паспорту и селфи."
        ));
        Self {
            active: true,
            remaining_hours,
            remaining_secs,
            quarantine: q,
            warning,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct QuarantineActivationInput {
    pub profile_id: Option<String>,
    pub route_id: Option<String>,
    pub exit_ip: Option<String>,
    pub exit_asn: Option<u32>,
    pub exit_country: Option<String>,
}

fn clean_opt(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Activates a 72-hour post-payment quarantine lock on the target Clean Room profile
/// (or global Clean Room quarantine when `profile_id` is omitted) and persists to disk.
pub async fn activate_quarantine_in(
    state: &AppState,
    input: QuarantineActivationInput,
) -> Result<PostPaymentQuarantineStatus, String> {
    activate_quarantine_at(state, input, current_timestamp()).await
}

pub async fn activate_quarantine_at(
    state: &AppState,
    input: QuarantineActivationInput,
    now: u64,
) -> Result<PostPaymentQuarantineStatus, String> {
    let parsed_profile = input
        .profile_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(CleanProfileId::parse)
        .transpose()?;

    let record = {
        let mut w = state.write().await;
        let target_id = parsed_profile
            .as_ref()
            .map(|id| id.as_str().to_string())
            .or_else(|| w.clean_room.active_profile_id.clone());

        let mut pinned_route_id = clean_opt(input.route_id);
        let mut pinned_exit_ip = clean_opt(input.exit_ip);
        let mut pinned_country = clean_opt(input.exit_country).map(|c| c.to_ascii_uppercase());

        if let Some(ref pid) = target_id {
            if let Some(profile) = w.clean_room.profiles.iter_mut().find(|p| p.id == *pid) {
                if pinned_route_id.is_none() {
                    pinned_route_id = profile.bound_route_id.clone();
                }
                if pinned_exit_ip.is_none() {
                    pinned_exit_ip = profile.last_exit_ip.clone();
                }
                if pinned_country.is_none() {
                    pinned_country = profile.last_exit_country.clone();
                }
                let q = PostPaymentQuarantine {
                    started_at: now,
                    expires_at: now.saturating_add(POST_PAYMENT_QUARANTINE_SECS),
                    pinned_route_id: pinned_route_id.clone(),
                    pinned_exit_ip: pinned_exit_ip.clone(),
                    pinned_asn: input.exit_asn,
                    pinned_country: pinned_country.clone(),
                    overridden_at: None,
                };
                profile.post_payment_quarantine = Some(q.clone());
                q
            } else if parsed_profile.is_some() {
                return Err(format!("Профиль «Чистой комнаты» не найден: {pid}"));
            } else {
                let q = PostPaymentQuarantine {
                    started_at: now,
                    expires_at: now.saturating_add(POST_PAYMENT_QUARANTINE_SECS),
                    pinned_route_id,
                    pinned_exit_ip,
                    pinned_asn: input.exit_asn,
                    pinned_country,
                    overridden_at: None,
                };
                w.clean_room.global_post_payment_quarantine = Some(q.clone());
                q
            }
        } else {
            let q = PostPaymentQuarantine {
                started_at: now,
                expires_at: now.saturating_add(POST_PAYMENT_QUARANTINE_SECS),
                pinned_route_id,
                pinned_exit_ip,
                pinned_asn: input.exit_asn,
                pinned_country,
                overridden_at: None,
            };
            w.clean_room.global_post_payment_quarantine = Some(q.clone());
            q
        }
    };

    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(PostPaymentQuarantineStatus::from_record(Some(record), now))
}

/// Reads current post-payment quarantine status for `profile_id` (or active/global fallback).
pub async fn get_quarantine_status_in(
    state: &AppState,
    profile_id: Option<&str>,
) -> Result<PostPaymentQuarantineStatus, String> {
    get_quarantine_status_at(state, profile_id, current_timestamp()).await
}

pub async fn get_quarantine_status_at(
    state: &AppState,
    profile_id: Option<&str>,
    now: u64,
) -> Result<PostPaymentQuarantineStatus, String> {
    let parsed_profile = profile_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(CleanProfileId::parse)
        .transpose()?;

    let data = state.get_data().await;
    let q = if let Some(ref pid) = parsed_profile {
        let profile = data
            .clean_room
            .profiles
            .iter()
            .find(|p| p.id == pid.as_str())
            .ok_or_else(|| format!("Профиль «Чистой комнаты» не найден: {}", pid.as_str()))?;
        profile.post_payment_quarantine.clone()
    } else if let Some(active_id) = data.clean_room.active_profile_id.as_deref()
        && let Some(profile) = data.clean_room.profiles.iter().find(|p| p.id == active_id)
        && profile.post_payment_quarantine.is_some()
    {
        profile.post_payment_quarantine.clone()
    } else {
        data.clean_room.global_post_payment_quarantine.clone()
    };

    Ok(PostPaymentQuarantineStatus::from_record(q, now))
}

/// Explicitly overrides an active post-payment quarantine ("Сменить всё равно") and persists.
pub async fn override_quarantine_in(
    state: &AppState,
    profile_id: Option<&str>,
    reason: Option<&str>,
) -> Result<PostPaymentQuarantineStatus, String> {
    override_quarantine_at(state, profile_id, reason, current_timestamp()).await
}

pub async fn override_quarantine_at(
    state: &AppState,
    profile_id: Option<&str>,
    reason: Option<&str>,
    now: u64,
) -> Result<PostPaymentQuarantineStatus, String> {
    let parsed_profile = profile_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(CleanProfileId::parse)
        .transpose()?;

    let updated = {
        let mut w = state.write().await;
        if let Some(ref pid) = parsed_profile {
            let profile = w
                .clean_room
                .profiles
                .iter_mut()
                .find(|p| p.id == pid.as_str())
                .ok_or_else(|| format!("Профиль «Чистой комнаты» не найден: {}", pid.as_str()))?;
            if let Some(q) = profile.post_payment_quarantine.as_mut() {
                q.overridden_at = Some(now);
            }
            profile.post_payment_quarantine.clone()
        } else if let Some(active_id) = w.clean_room.active_profile_id.clone()
            && let Some(profile) = w.clean_room.profiles.iter_mut().find(|p| p.id == active_id)
            && profile.post_payment_quarantine.is_some()
        {
            if let Some(q) = profile.post_payment_quarantine.as_mut() {
                q.overridden_at = Some(now);
            }
            profile.post_payment_quarantine.clone()
        } else {
            if let Some(q) = w.clean_room.global_post_payment_quarantine.as_mut() {
                q.overridden_at = Some(now);
            }
            w.clean_room.global_post_payment_quarantine.clone()
        }
    };

    let note = reason
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("explicit_user_override");
    crate::diagnostics::record("clean_room:quarantine", &format!("override: {note}"));
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(PostPaymentQuarantineStatus::from_record(updated, now))
}
