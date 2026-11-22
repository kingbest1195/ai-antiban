//! Domain models and strict Zero-PCI-DSS BIN prefix validation (6..=8 ASCII digits).

use crate::auditor::geo_matrix::CheckStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CardFunding {
    Credit,
    Debit,
    Prepaid,
    Charge,
    #[serde(other)]
    Unknown,
}

impl CardFunding {
    pub fn as_display_str(self) -> &'static str {
        match self {
            CardFunding::Credit => "CREDIT",
            CardFunding::Debit => "DEBIT",
            CardFunding::Prepaid => "PREPAID",
            CardFunding::Charge => "CHARGE",
            CardFunding::Unknown => "UNKNOWN",
        }
    }

    pub fn parse_loose(raw: &str) -> Self {
        match raw.trim().to_ascii_uppercase().as_str() {
            "CREDIT" => CardFunding::Credit,
            "DEBIT" => CardFunding::Debit,
            "PREPAID" => CardFunding::Prepaid,
            "CHARGE" | "CHARGE CARD" => CardFunding::Charge,
            _ => CardFunding::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BinSource {
    LocalOverlay,
    Cache,
    ProxyApi,
    FallbackPublicApi,
    FallbackUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClaudeWebVerdict {
    SafeAligned,
    NeedsMatchingIpBilling,
    HighKycRisk,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BinReport {
    pub bin_prefix: String,
    pub status: CheckStatus,
    pub scheme: Option<String>,
    pub funding: CardFunding,
    pub is_prepaid: Option<bool>,
    pub is_commercial: Option<bool>,
    pub is_reloadable: Option<bool>,
    pub card_category: Option<String>,
    pub country_code: Option<String>,
    pub issuer_name: Option<String>,
    pub known_fintech_label: Option<String>,
    pub source: BinSource,
    pub claude_web_verdict: ClaudeWebVerdict,
    pub warnings: Vec<String>,
}

/// Backward-compatible IPC payload for `check_payment_bin`, carrying the full `BinReport`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinAuditResult {
    pub bin: String,
    pub country_code: Option<String>,
    pub card_type: Option<String>,
    pub bank_name: Option<String>,
    pub is_prepaid: bool,
    pub status: CheckStatus,
    pub advisory: String,
    pub guide_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<BinReport>,
}

impl BinAuditResult {
    pub fn from_report(report: BinReport, guide_ref: Option<String>) -> Self {
        let advisory = if report.warnings.is_empty() {
            "Карта успешно проверена и подходит для оплаты подписки.".to_string()
        } else {
            report.warnings.join(" ")
        };
        let card_type = if report.funding != CardFunding::Unknown {
            Some(report.funding.as_display_str().to_string())
        } else {
            report.card_category.clone()
        };
        Self {
            bin: report.bin_prefix.clone(),
            country_code: report.country_code.clone(),
            card_type,
            bank_name: report
                .known_fintech_label
                .clone()
                .or_else(|| report.issuer_name.clone()),
            is_prepaid: report.is_prepaid.unwrap_or(false)
                || report.funding == CardFunding::Prepaid,
            status: report.status,
            advisory,
            guide_ref,
            report: Some(report),
        }
    }
}

/// Strict `^\d{6,8}$` validation (ASCII digits only, no separators, no logging of input).
pub fn validate_strict_bin_prefix(raw_input: &str) -> Result<String, String> {
    if !raw_input.bytes().all(|b| b.is_ascii_digit()) {
        return Err(
            "Допускаются только первые 6–8 цифр карты (без букв и спецсимволов).".to_string(),
        );
    }
    if raw_input.len() < 6 {
        return Err("Введите минимум 6 первых цифр карты.".to_string());
    }
    if raw_input.len() > 8 {
        return Err(
            "Для безопасности введите только первые 6–8 цифр карты без остального номера."
                .to_string(),
        );
    }
    Ok(raw_input.to_string())
}

/// Sanitizes user-formatted BIN input (allows spaces/`-` separators only), rejecting any
/// non-ASCII-digit characters and enforcing 6..=8 digits without logging raw input.
pub fn sanitize_bin_input(raw_input: &str) -> Result<String, String> {
    let mut cleaned = String::with_capacity(8);
    for ch in raw_input.chars() {
        if ch == ' ' || ch == '-' {
            continue;
        }
        if !ch.is_ascii_digit() {
            return Err(
                "Вводите только первые 6–8 цифр карты (без букв и спецсимволов).".to_string(),
            );
        }
        if cleaned.len() >= 8 {
            return Err(
                "Для безопасности введите только первые 6–8 цифр карты без остального номера."
                    .to_string(),
            );
        }
        cleaned.push(ch);
    }
    validate_strict_bin_prefix(&cleaned)
}
