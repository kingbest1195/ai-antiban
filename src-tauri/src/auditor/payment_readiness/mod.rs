//! 4-axis Payment Readiness Score (0..=100) and Google Pay / Apple Pay trap detector.
//!
//! Strictly separated from `auditor/scoring.rs` (`trust_score` measures network hygiene only).

mod axes_geo_channel;
mod axes_network_bin;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

use crate::auditor::RiskReport;
use crate::auditor::geo_matrix::CheckStatus;
use crate::auditor::ip_type::IpType;
use crate::auditor::network::current_timestamp;
use crate::bin_checker::BinReport;
use crate::state::AppStateData;

pub use axes_geo_channel::evaluate_payment_readiness;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReadinessTier {
    Green,
    Yellow,
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum PaymentChannel {
    #[default]
    #[serde(alias = "DirectCard", alias = "direct_card")]
    DirectCard,
    #[serde(alias = "GooglePayWeb", alias = "google_pay_web")]
    GooglePayWeb,
    #[serde(alias = "ApplePayWeb", alias = "apple_pay_web")]
    ApplePayWeb,
    #[serde(alias = "AppleIAP", alias = "apple_iap", alias = "appleIap")]
    AppleIAP,
    #[serde(alias = "Api", alias = "API")]
    Api,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionPlan {
    #[default]
    #[serde(alias = "Pro")]
    Pro,
    #[serde(alias = "Max")]
    Max,
    #[serde(alias = "Api", alias = "API")]
    Api,
    #[serde(alias = "Unknown")]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AxisScore {
    pub id: String,
    pub label: String,
    pub score: u8,
    pub max_score: u8,
    pub status: CheckStatus,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentReadinessAxes {
    pub network_base: AxisScore,
    pub card_bin: AxisScore,
    pub geo_billing_parity: AxisScore,
    pub channel_env_warmup: AxisScore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentReadinessReport {
    pub score: u8,
    pub tier: ReadinessTier,
    pub axes: PaymentReadinessAxes,
    pub warnings: Vec<String>,
    pub blockers: Vec<String>,
    pub recommended_action: Option<String>,
    pub requires_matching_billing: bool,
    pub fail_closed_bin: bool,
    pub channel: PaymentChannel,
    pub evaluated_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct PaymentReadinessInput {
    pub exit_ip: Option<String>,
    pub exit_country: Option<String>,
    pub exit_asn: Option<u32>,
    pub is_pinned: bool,
    pub is_datacenter_or_vpn: bool,
    pub is_tor_or_mass_vpn: bool,
    pub has_network_leaks: bool,
    pub has_recent_jump_lt_4h: bool,
    pub split_ip_checkout_risk: bool,
    pub bin_report: Option<BinReport>,
    pub billing_country: Option<String>,
    pub google_profile_country: Option<String>,
    pub apple_id_country: Option<String>,
    pub channel: PaymentChannel,
    pub in_clean_room: bool,
    pub warmup_hours: Option<u64>,
    pub account_age_confirmed_96h: Option<bool>,
    pub plan: SubscriptionPlan,
    pub evaluated_at: u64,
}

impl PaymentReadinessInput {
    /// Builds an audit input from live Zastava state, optional network `RiskReport`,
    /// optional `BinReport`, and user-selected checkout parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn from_runtime(
        state_data: &AppStateData,
        risk_report: Option<&RiskReport>,
        bin_report: Option<BinReport>,
        billing_country: Option<String>,
        google_profile_country: Option<String>,
        apple_id_country: Option<String>,
        channel: PaymentChannel,
        in_clean_room: bool,
        plan: SubscriptionPlan,
        split_ip_checkout_risk: bool,
        profile_id: Option<&str>,
    ) -> Self {
        let now = current_timestamp();
        let exit_ip = risk_report.map(|r| r.telemetry.ip.trim().to_string());
        let exit_country = risk_report
            .map(|r| crate::core::country::normalize_country_code(&r.telemetry.country_code))
            .filter(|cc| cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_alphabetic()));
        let exit_asn = risk_report.and_then(|r| r.telemetry.asn);

        let is_pinned = risk_report.is_some_and(|r| {
            let ip = r.telemetry.ip.trim();
            matches!(
                r.pinning_result.code.as_str(),
                "PINNED_BY_ZASTAVA_KEY" | "PINNED_IP_MATCH"
            ) || (!ip.is_empty()
                && (state_data.pinned_ips.values().any(|p| p.trim() == ip)
                    || state_data
                        .pinned_ip
                        .as_deref()
                        .is_some_and(|p| p.trim() == ip)))
        });

        let ip_type = risk_report
            .and_then(|r| r.asn_result.detail.as_ref())
            .and_then(|d| d.ip_type)
            .unwrap_or(IpType::Unknown);
        let asn_code = risk_report
            .map(|r| r.asn_result.code.as_str())
            .unwrap_or("");
        let is_tor_or_mass_vpn = matches!(ip_type, IpType::Tor | IpType::Vpn)
            || matches!(asn_code, "IP_TYPE_TOR" | "HIGH_RISK_MASS_VPN_ASN");
        let is_datacenter_or_vpn = is_tor_or_mass_vpn
            || ip_type == IpType::Hosting
            || asn_code == "IP_TYPE_HOSTING"
            || risk_report.is_some_and(|r| r.dnsbl_result.status.is_critical());

        let has_network_leaks = risk_report.is_some_and(|r| {
            matches!(
                r.ipv6_result.status,
                CheckStatus::Critical | CheckStatus::Warning
            ) || (r.timezone_result.code == "TIMEZONE_LEAK_RU"
                && r.timezone_result.status != CheckStatus::Ok)
                || r.checks.iter().any(|c| {
                    matches!(c.status, CheckStatus::Critical | CheckStatus::Warning)
                        && (c.code.contains("DNS") || c.code.contains("UDP_STUN"))
                })
        });

        let cooldown_active = state_data
            .ip_change_cooldown_remaining_secs(now as i64)
            .is_some();
        let travel_jump = risk_report.is_some_and(|r| {
            r.travel_result.status != CheckStatus::Ok
                && matches!(
                    r.travel_result.code.as_str(),
                    "TRAVEL_ASN_JUMP_SAME_COUNTRY"
                        | "IMPOSSIBLE_TRAVEL_CRITICAL"
                        | "IMPOSSIBLE_TRAVEL_WARNING"
                )
        });

        let active_profile = profile_id
            .or(state_data.clean_room.active_profile_id.as_deref())
            .and_then(|pid| state_data.clean_room.profiles.iter().find(|p| p.id == pid));
        let warmup_started_at = active_profile
            .and_then(|p| p.warmup_started_at)
            .or(state_data.warmup_started_at);
        let warmup_hours = warmup_started_at.map(|started| now.saturating_sub(started) / 3600);

        Self {
            exit_ip,
            exit_country,
            exit_asn,
            is_pinned,
            is_datacenter_or_vpn,
            is_tor_or_mass_vpn,
            has_network_leaks,
            has_recent_jump_lt_4h: cooldown_active || travel_jump,
            split_ip_checkout_risk,
            bin_report,
            billing_country,
            google_profile_country,
            apple_id_country,
            channel,
            in_clean_room,
            warmup_hours,
            account_age_confirmed_96h: None,
            plan,
            evaluated_at: now,
        }
    }
}
