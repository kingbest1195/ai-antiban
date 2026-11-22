//! Zero-PAN `PaymentPassport` stored in Local Data Bunker for renewal consistency checks.
//!
//! Security invariant: `PaymentPassport` NEVER accepts or stores full PAN, last-4 digits,
//! CVV, or card expiration dates. `bin_prefix` is strictly validated as `^\d{6,8}$`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::auditor::network::current_timestamp;
use crate::bin_checker::validate_strict_bin_prefix;
use crate::bunker::sanitize::{ensure_private_dir, write_private_file};
use crate::clean_room::CleanProfileId;
use crate::core::country::format_country_ru;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PassportChannel {
    #[serde(alias = "DirectCard", alias = "direct_card")]
    DirectCard,
    #[serde(alias = "AppleIAP", alias = "apple_iap", alias = "appleIap")]
    AppleIAP,
    #[serde(alias = "Api", alias = "API")]
    Api,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentPassport {
    pub profile_id: String,
    pub bin_prefix: String,
    pub card_country: String,
    pub channel: PassportChannel,
    pub billing_country: String,
    pub exit_ip: String,
    #[serde(default)]
    pub exit_asn: Option<u32>,
    pub paid_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RenewalCheckInput {
    #[serde(default)]
    pub bin_prefix: Option<String>,
    #[serde(default)]
    pub card_country: Option<String>,
    #[serde(default)]
    pub channel: Option<PassportChannel>,
    #[serde(default)]
    pub billing_country: Option<String>,
    #[serde(default)]
    pub exit_ip: Option<String>,
    #[serde(default)]
    pub exit_asn: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportVerificationResult {
    pub matched: bool,
    pub mismatches: Vec<String>,
    pub warnings: Vec<String>,
    pub passport: PaymentPassport,
}

pub fn bunker_passports_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("bunker").join("passports")
}

fn validate_passport_profile_id(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed == "default" {
        return Ok("default".to_string());
    }
    Ok(CleanProfileId::parse(trimmed)?.as_str().to_string())
}

fn normalize_country_code(raw: &str, field_label_ru: &str) -> Result<String, String> {
    let upper = raw.trim().to_ascii_uppercase();
    if upper.len() != 2 || !upper.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(format!(
            "Укажите {field_label_ru}: выберите страну из списка."
        ));
    }
    Ok(upper)
}

/// Validates Zero-PAN invariants and normalizes fields before saving.
pub fn validate_and_normalize_passport(
    mut passport: PaymentPassport,
) -> Result<PaymentPassport, String> {
    passport.profile_id = validate_passport_profile_id(&passport.profile_id)?;
    let trimmed_bin = passport.bin_prefix.trim();
    if trimmed_bin.is_empty()
        && matches!(
            passport.channel,
            PassportChannel::AppleIAP | PassportChannel::Api
        )
    {
        passport.bin_prefix = String::new();
    } else {
        passport.bin_prefix = validate_strict_bin_prefix(trimmed_bin)?;
    }
    passport.card_country = normalize_country_code(&passport.card_country, "страну карты")?;
    passport.billing_country =
        normalize_country_code(&passport.billing_country, "страну адреса оплаты")?;
    passport.exit_ip = passport.exit_ip.trim().to_string();
    if passport.exit_ip.is_empty() {
        return Err("Укажите выходной IP для привязки платёжного паспорта.".to_string());
    }
    if passport.paid_at == 0 {
        passport.paid_at = current_timestamp();
    }
    Ok(passport)
}

pub fn save_payment_passport_in(
    app_data_dir: &Path,
    passport: PaymentPassport,
) -> Result<PaymentPassport, String> {
    let normalized = validate_and_normalize_passport(passport)?;
    let dir = bunker_passports_dir(app_data_dir);
    ensure_private_dir(&dir)?;
    let path = dir.join(format!("{}.json", normalized.profile_id));
    let json = serde_json::to_string_pretty(&normalized)
        .map_err(|e| format!("Failed to serialize PaymentPassport: {e}"))?;
    write_private_file(&path, json.as_bytes())?;
    Ok(normalized)
}

pub fn load_payment_passport_in(
    app_data_dir: &Path,
    profile_id: &str,
) -> Result<Option<PaymentPassport>, String> {
    let clean_id = validate_passport_profile_id(profile_id)?;
    let path = bunker_passports_dir(app_data_dir).join(format!("{clean_id}.json"));
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read PaymentPassport {}: {e}", path.display()))?;
    let parsed: PaymentPassport = serde_json::from_str(&raw)
        .map_err(|e| format!("Invalid PaymentPassport {}: {e}", path.display()))?;
    let validated = validate_and_normalize_passport(parsed)?;
    Ok(Some(validated))
}

fn passport_channel_label_ru(ch: PassportChannel) -> &'static str {
    match ch {
        PassportChannel::DirectCard => "Картой на сайте",
        PassportChannel::AppleIAP => "Через App Store",
        PassportChannel::Api => "Оплата API-баланса",
    }
}

/// Compares a renewal attempt against the stored `PaymentPassport` to prevent accidental
/// payment from a different country, card prefix, channel, or exit network.
pub fn verify_renewal_against_passport(
    passport: &PaymentPassport,
    current: &RenewalCheckInput,
) -> PassportVerificationResult {
    let mut mismatches = Vec::new();
    let mut warnings = Vec::new();

    if let Some(raw_bin) = current
        .bin_prefix
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match validate_strict_bin_prefix(raw_bin) {
            Ok(clean_bin) => {
                let prefix_len = clean_bin.len().min(passport.bin_prefix.len());
                if clean_bin[..prefix_len] != passport.bin_prefix[..prefix_len] {
                    mismatches.push(format!(
                        "Первые цифры карты ({clean_bin}) не совпадают с сохранёнными в памятке ({}).",
                        passport.bin_prefix
                    ));
                }
            }
            Err(err) => {
                mismatches.push(err);
            }
        }
    }

    if let Some(card_cc) = current
        .card_country
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && !card_cc.eq_ignore_ascii_case(&passport.card_country)
    {
        mismatches.push(format!(
            "Страна карты ({}) не совпадает с памяткой ({}).",
            format_country_ru(card_cc),
            format_country_ru(&passport.card_country)
        ));
    }

    if let Some(bill_cc) = current
        .billing_country
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && !bill_cc.eq_ignore_ascii_case(&passport.billing_country)
    {
        mismatches.push(format!(
            "Страна адреса оплаты ({}) не совпадает с памяткой ({}).",
            format_country_ru(bill_cc),
            format_country_ru(&passport.billing_country)
        ));
    }

    if let Some(ch) = current.channel
        && ch != passport.channel
    {
        mismatches.push(format!(
            "Способ оплаты ({}) отличается от первичной оплаты ({}).",
            passport_channel_label_ru(ch),
            passport_channel_label_ru(passport.channel)
        ));
    }

    if let Some(ip) = current
        .exit_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && ip != passport.exit_ip
    {
        warnings.push(format!(
            "Адрес подключения изменился ({ip} вместо {}): при продлении желательно использовать тот же маршрут.",
            passport.exit_ip
        ));
    }

    if let (Some(saved_asn), Some(curr_asn)) = (passport.exit_asn, current.exit_asn)
        && saved_asn != curr_asn
    {
        mismatches.push(format!(
            "Сеть провайдера маршрута изменилась ({curr_asn} вместо {saved_asn}) — высокий риск проверки при продлении."
        ));
    }

    PassportVerificationResult {
        matched: mismatches.is_empty(),
        mismatches,
        warnings,
        passport: passport.clone(),
    }
}
