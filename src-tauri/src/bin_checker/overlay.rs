//! Compile-time curated BIN overlay (`rules/bin_overlay.json`), priority #1 over remote APIs.

use super::model::{BinReport, BinSource, CardFunding, ClaudeWebVerdict};
use crate::auditor::geo_matrix::CheckStatus;
use serde::Deserialize;
use std::collections::HashMap;

pub const DEFAULT_BIN_OVERLAY_JSON: &str = include_str!("../../../rules/bin_overlay.json");

#[derive(Debug, Clone, Deserialize)]
pub struct OverlayEntry {
    pub prefix: String,
    pub scheme: Option<String>,
    pub funding: CardFunding,
    pub is_prepaid: Option<bool>,
    pub is_commercial: Option<bool>,
    pub is_reloadable: Option<bool>,
    pub card_category: Option<String>,
    pub country_code: Option<String>,
    pub issuer_name: Option<String>,
    pub known_fintech_label: Option<String>,
    #[serde(default)]
    pub high_kyc_risk: bool,
    pub claude_web_verdict: ClaudeWebVerdict,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OverlayRange {
    pub start: String,
    pub end: String,
    pub scheme: Option<String>,
    pub funding: CardFunding,
    pub is_prepaid: Option<bool>,
    pub is_commercial: Option<bool>,
    pub is_reloadable: Option<bool>,
    pub card_category: Option<String>,
    pub country_code: Option<String>,
    pub issuer_name: Option<String>,
    pub known_fintech_label: Option<String>,
    #[serde(default)]
    pub high_kyc_risk: bool,
    pub claude_web_verdict: ClaudeWebVerdict,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OverlayFile {
    #[serde(default)]
    high_risk_issuer_keywords: Vec<String>,
    #[serde(default)]
    prefixes: Vec<OverlayEntry>,
    #[serde(default)]
    ranges: Vec<OverlayRange>,
}

#[derive(Debug, Clone)]
pub struct OverlayMatch {
    pub report: BinReport,
    pub high_kyc_risk: bool,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct BinOverlay {
    exact_8: HashMap<String, OverlayEntry>,
    exact_6: HashMap<String, OverlayEntry>,
    short_prefixes: Vec<OverlayEntry>,
    ranges: Vec<OverlayRange>,
    high_risk_keywords: Vec<String>,
}

impl BinOverlay {
    pub fn load_bundled() -> Result<Self, serde_json::Error> {
        Self::from_json(DEFAULT_BIN_OVERLAY_JSON)
    }

    pub fn from_json(raw: &str) -> Result<Self, serde_json::Error> {
        let parsed: OverlayFile = serde_json::from_str(raw)?;
        let mut exact_8 = HashMap::new();
        let mut exact_6 = HashMap::new();
        let mut short_prefixes = Vec::new();
        for entry in parsed.prefixes {
            match entry.prefix.len() {
                8 => {
                    exact_8.insert(entry.prefix.clone(), entry);
                }
                6 => {
                    exact_6.insert(entry.prefix.clone(), entry);
                }
                _ => short_prefixes.push(entry),
            }
        }
        short_prefixes.sort_by_key(|a| std::cmp::Reverse(a.prefix.len()));
        Ok(Self {
            exact_8,
            exact_6,
            short_prefixes,
            ranges: parsed.ranges,
            high_risk_keywords: parsed
                .high_risk_issuer_keywords
                .into_iter()
                .map(|k| k.to_ascii_uppercase())
                .collect(),
        })
    }

    /// Resolves a validated 6..=8 digit BIN with strict priority:
    /// 8-digit prefix -> 6-digit prefix -> shorter prefix -> range (e.g. `2200..=2204`).
    pub fn lookup(&self, bin_prefix: &str) -> Option<OverlayMatch> {
        if bin_prefix.len() == 8
            && let Some(entry) = self.exact_8.get(bin_prefix)
        {
            return Some(entry_to_match(bin_prefix, entry));
        }
        if bin_prefix.len() >= 6
            && let Some(entry) = self.exact_6.get(&bin_prefix[..6])
        {
            return Some(entry_to_match(bin_prefix, entry));
        }
        for entry in &self.short_prefixes {
            if bin_prefix.starts_with(&entry.prefix) {
                return Some(entry_to_match(bin_prefix, entry));
            }
        }
        for range in &self.ranges {
            let len = range.start.len();
            if len > 0
                && range.end.len() == len
                && bin_prefix.len() >= len
                && let Some(slice) = bin_prefix.get(..len)
                && slice >= range.start.as_str()
                && slice <= range.end.as_str()
            {
                return Some(range_to_match(bin_prefix, range));
            }
        }
        None
    }

    pub fn is_high_risk_issuer(&self, issuer: Option<&str>) -> bool {
        let Some(name) = issuer else {
            return false;
        };
        let upper = name.to_ascii_uppercase();
        self.high_risk_keywords.iter().any(|k| upper.contains(k))
    }
}

fn humanize_overlay_note(prefix_or_start: &str, raw_note: &str) -> String {
    match prefix_or_start {
        "220441" => "Карта Antarctic Wallet («Мир»): российские и связанные с ними виртуальные карты не принимаются для оплаты подписки."
            .to_string(),
        "404038" => "Виртуальная предоплаченная карта RedotPay, Гонконг (HK). Карты этого региона не принимаются для оплаты подписки."
            .to_string(),
        "474447" => "Предоплаченная карта RedotPay, Гонконг (HK). Карты этого региона не принимаются для оплаты подписки."
            .to_string(),
        "493724" => "Виртуальная предоплаченная корпоративная карта Сингапура (SG) — используется в RedotPay и Wayment. Высокий риск запроса паспорта и селфи при оплате."
            .to_string(),
        "446614" => "Тариф «Для подписок» сервиса «Плати по миру» (США (US), корпоративная карта). Требует подключения через США (US) и американский адрес оплаты."
            .to_string(),
        "485953" => "Дебетовая карта Bybit, Великобритания (GB). Требует подключения через Великобританию (GB) и адреса оплаты в этой стране."
            .to_string(),
        "537872" => "Дебетовая карта Bybit (Европейская экономическая зона). Требует европейского подключения и совпадающего адреса оплаты."
            .to_string(),
        "454924" => "Кредитная карта ether.fi Cash, Пуэрто-Рико (PR). Требует совпадающей страны подключения и адреса оплаты."
            .to_string(),
        "537349" => "Дебетовая карта MetaMask, Великобритания (GB). Требует подключения через Великобританию (GB) и совпадающего адреса оплаты."
            .to_string(),
        "440043" => "Карта банка Казахстана (KZ). Указывайте реальный адрес оплаты в Казахстане (KZ); при оплате через другую страну возможна дополнительная проверка."
            .to_string(),
        "439087" => "Карта Halyk Bank, Казахстан (KZ). Указывайте реальный адрес оплаты в Казахстане (KZ) и не меняйте страну подключения перед оплатой."
            .to_string(),
        "422970" => "Карта Bakai Bank, Кыргызстан (KG). Указывайте реальный адрес оплаты в Кыргызстане (KG), а не адрес в США (US) или Германии (DE)."
            .to_string(),
        "416958" => "Карта MBank, Кыргызстан (KG). Указывайте реальный адрес оплаты в Кыргызстане (KG) и используйте подключение из той же страны."
            .to_string(),
        "409986" => "Карта IDBank, Армения (AM). Указывайте реальный адрес оплаты в Армении (AM)."
            .to_string(),
        "426696" => "Карта TBC Bank, Грузия (GE). Указывайте реальный адрес оплаты в Грузии (GE)."
            .to_string(),
        "424290" => "Карта Bank of Georgia, Грузия (GE). Указывайте реальный адрес оплаты в Грузии (GE)."
            .to_string(),
        "406218" => "Карта Kapitalbank, Узбекистан (UZ). Указывайте реальный адрес оплаты в Узбекистане (UZ)."
            .to_string(),
        _ => raw_note
            .replace("Stripe Radar", "антифрод оплаты")
            .replace("Stripe", "платёжная система сайта")
            .replace("Persona KYC", "проверка по паспорту и селфи")
            .replace("KYC", "проверка по паспорту и селфи")
            .replace("биллинг-адреса", "адреса оплаты")
            .replace("биллинг-адрес", "адрес оплаты")
            .replace("биллинга", "адреса оплаты")
            .replace("биллинг", "адрес оплаты"),
    }
}

fn entry_to_match(bin_prefix: &str, e: &OverlayEntry) -> OverlayMatch {
    OverlayMatch {
        report: BinReport {
            bin_prefix: bin_prefix.to_string(),
            status: CheckStatus::Ok,
            scheme: e.scheme.clone(),
            funding: e.funding,
            is_prepaid: e.is_prepaid,
            is_commercial: e.is_commercial,
            is_reloadable: e.is_reloadable,
            card_category: e.card_category.clone(),
            country_code: e.country_code.clone(),
            issuer_name: e.issuer_name.clone(),
            known_fintech_label: e.known_fintech_label.clone(),
            source: BinSource::LocalOverlay,
            claude_web_verdict: e.claude_web_verdict,
            warnings: Vec::new(),
        },
        high_kyc_risk: e.high_kyc_risk,
        note: humanize_overlay_note(&e.prefix, &e.note),
    }
}

fn range_to_match(bin_prefix: &str, r: &OverlayRange) -> OverlayMatch {
    OverlayMatch {
        report: BinReport {
            bin_prefix: bin_prefix.to_string(),
            status: CheckStatus::Ok,
            scheme: r.scheme.clone(),
            funding: r.funding,
            is_prepaid: r.is_prepaid,
            is_commercial: r.is_commercial,
            is_reloadable: r.is_reloadable,
            card_category: r.card_category.clone(),
            country_code: r.country_code.clone(),
            issuer_name: r.issuer_name.clone(),
            known_fintech_label: r.known_fintech_label.clone(),
            source: BinSource::LocalOverlay,
            claude_web_verdict: r.claude_web_verdict,
            warnings: Vec::new(),
        },
        high_kyc_risk: r.high_kyc_risk,
        note: humanize_overlay_note(&r.start, &r.note),
    }
}
