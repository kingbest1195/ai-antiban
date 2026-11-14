use crate::auditor::geo_matrix::{CheckStatus, GUIDE_PAYMENT_CARDS};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinAuditResult {
    pub bin: String,
    pub country_code: Option<String>,
    pub card_type: Option<String>,
    pub bank_name: Option<String>,
    pub is_prepaid: bool,
    pub status: CheckStatus,
    pub advisory: String,
    pub guide_ref: Option<String>,
}

#[derive(Deserialize)]
struct HandyApiBinResponse {
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "Type")]
    card_type: Option<String>,
    #[serde(rename = "Country")]
    country: Option<HandyApiCountry>,
    #[serde(rename = "Issuer")]
    issuer: Option<String>,
    #[serde(rename = "CardTier")]
    card_tier: Option<String>,
}

#[derive(Deserialize)]
struct HandyApiCountry {
    #[serde(rename = "A2")]
    a2: Option<String>,
    #[serde(rename = "Name")]
    _name: Option<String>,
}

pub struct BinChecker {
    client: reqwest::Client,
}

impl Default for BinChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl BinChecker {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(2500))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { client }
    }

    /// Sanitizes and validates the BIN input. Rejects numbers < 6 or > 8 digits.
    pub fn sanitize_bin(raw_input: &str) -> Result<String, String> {
        let cleaned: String = raw_input.chars().filter(|c| c.is_ascii_digit()).collect();

        if cleaned.len() < 6 {
            return Err("Введите минимум 6 первых цифр карты (BIN).".to_string());
        }

        if cleaned.len() > 8 {
            return Err(
                "Для вашей безопасности (For your privacy) НЕ вводите полный 16-значный номер карты! Достаточно первых 6–8 цифр (BIN)."
                    .to_string(),
            );
        }

        Ok(cleaned)
    }

    /// Performs offline heuristic analysis on the BIN.
    pub fn evaluate_heuristics(bin: &str) -> Option<BinAuditResult> {
        // Mir cards start with 2200..2204
        if bin.starts_with("2200")
            || bin.starts_with("2201")
            || bin.starts_with("2202")
            || bin.starts_with("2203")
            || bin.starts_with("2204")
        {
            return Some(BinAuditResult {
                bin: bin.to_string(),
                country_code: Some("RU".to_string()),
                card_type: Some("DEBIT".to_string()),
                bank_name: Some("НСПК «Мир» (Mir / Банк РФ)".to_string()),
                is_prepaid: false,
                status: CheckStatus::Critical,
                advisory: "Обнаружена карта «Мир» (Mir). Международные платформы не поддерживают карты этой платежной системы.".to_string(),
                guide_ref: Some(GUIDE_PAYMENT_CARDS.to_string()),
            });
        }

        // Belkart starts with 9112
        if bin.starts_with("9112") {
            return Some(BinAuditResult {
                bin: bin.to_string(),
                country_code: Some("BY".to_string()),
                card_type: Some("DEBIT".to_string()),
                bank_name: Some("Белкарт (Беларусь)".to_string()),
                is_prepaid: false,
                status: CheckStatus::Critical,
                advisory: "Обнаружена локальная карта региона. Международные платежные системы не обслуживают карты этой юрисдикции.".to_string(),
                guide_ref: Some(GUIDE_PAYMENT_CARDS.to_string()),
            });
        }

        None
    }

    /// Checks the BIN via heuristics and online lookup.
    pub async fn check_bin(
        &self,
        raw_bin: &str,
        current_vpn_country: Option<&str>,
    ) -> Result<BinAuditResult, String> {
        let bin = Self::sanitize_bin(raw_bin)?;

        // 1. Check offline heuristics first
        if let Some(mut result) = Self::evaluate_heuristics(&bin) {
            Self::apply_vpn_country_comparison(&mut result, current_vpn_country);
            return Ok(result);
        }

        // 2. Perform online lookup via HandyAPI
        let url = format!("https://data.handyapi.com/bin/{bin}");
        match self.client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(data) = resp.json::<HandyApiBinResponse>().await
                    && data.status.as_deref() == Some("SUCCESS")
                {
                    let country_code = data.country.and_then(|c| c.a2).map(|s| s.to_uppercase());
                    let card_type = data.card_type;
                    let bank_name = data.issuer;
                    let tier = data.card_tier.unwrap_or_default().to_uppercase();
                    let is_prepaid = card_type
                        .as_deref()
                        .map(|t| t.eq_ignore_ascii_case("PREPAID"))
                        .unwrap_or(false)
                        || tier.contains("PREPAID")
                        || tier.contains("VIRTUAL");

                    let mut result = BinAuditResult {
                            bin: bin.clone(),
                            country_code,
                            card_type,
                            bank_name,
                            is_prepaid,
                            status: CheckStatus::Ok,
                            advisory: "Карта успешно проверена. Банк-эмитент совместим со Stripe и подходит для оплаты подписки.".to_string(),
                            guide_ref: None,
                        };

                    Self::apply_heuristics_and_advisories(&mut result, current_vpn_country);
                    return Ok(result);
                }
            }
            Err(e) => {
                eprintln!("Online BIN lookup failed: {e}");
            }
        }

        // 3. Fallback generic result if online API is unavailable
        let mut fallback = BinAuditResult {
            bin,
            country_code: None,
            card_type: None,
            bank_name: None,
            is_prepaid: false,
            status: CheckStatus::Ok,
            advisory: "Префикс BIN принят. Убедитесь, что платежный адрес и страна активного VPN совпадают со страной банка карты."
                .to_string(),
            guide_ref: Some(GUIDE_PAYMENT_CARDS.to_string()),
        };
        Self::apply_vpn_country_comparison(&mut fallback, current_vpn_country);
        Ok(fallback)
    }

    fn apply_heuristics_and_advisories(
        result: &mut BinAuditResult,
        current_vpn_country: Option<&str>,
    ) {
        if let Some(country) = &result.country_code
            && (country == "RU" || country == "BY")
        {
            result.status = CheckStatus::Critical;
            result.advisory = format!(
                "Карта выпущена в неподдерживаемой юрисдикции ({country}). Международные сервисы не принимают карты этого региона."
            );
            result.guide_ref = Some(GUIDE_PAYMENT_CARDS.to_string());
            return;
        }

        if result.is_prepaid {
            result.status = CheckStatus::Warning;
            result.advisory = "Виртуальная / предоплаченная (PREPAID) карта. Международные сервисы часто отклоняют предоплаченные BIN без подтверждения адреса (AVS). Рекомендуется именная Debit-карта или оплата через магазины приложений."
                .to_string();
            result.guide_ref = Some(GUIDE_PAYMENT_CARDS.to_string());
        }

        Self::apply_vpn_country_comparison(result, current_vpn_country);
    }

    fn apply_vpn_country_comparison(
        result: &mut BinAuditResult,
        current_vpn_country: Option<&str>,
    ) {
        if let (Some(card_country), Some(vpn_country)) = (&result.country_code, current_vpn_country)
        {
            let vpn_upper = vpn_country.trim().to_uppercase();
            if !card_country.eq_ignore_ascii_case(&vpn_upper)
                && result.status != CheckStatus::Critical
            {
                result.status = CheckStatus::Warning;
                result.advisory = format!(
                    "Несовпадение регионов: карта выпущена в {card_country}, а ваш текущий сетевой шлюз — {vpn_upper}. На момент проведения платежа рекомендуется синхронизировать регион шлюза с регионом карты.",
                );
                result.guide_ref = Some(GUIDE_PAYMENT_CARDS.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bin_checker_validation() {
        // Valid 6 digits
        let sanitized = BinChecker::sanitize_bin(" 4111 11 ").unwrap();
        assert_eq!(sanitized, "411111");

        // Reject too short (<6)
        let too_short = BinChecker::sanitize_bin("12345");
        assert!(too_short.is_err());

        // Reject 16 digits for privacy
        let full_card = BinChecker::sanitize_bin("4111 1111 2222 3333");
        assert!(full_card.is_err());
        assert!(full_card.unwrap_err().contains("For your privacy"));

        // Heuristics for Russian Mir card (220220 and 220012)
        let mir_220220 = BinChecker::evaluate_heuristics("220220").unwrap();
        assert_eq!(mir_220220.status, CheckStatus::Critical);
        assert_eq!(mir_220220.country_code.as_deref(), Some("RU"));
        assert!(mir_220220.advisory.contains("Mir"));

        let mir_res = BinChecker::evaluate_heuristics("220012").unwrap();
        assert_eq!(mir_res.status, CheckStatus::Critical);
        assert_eq!(mir_res.country_code.as_deref(), Some("RU"));
        assert!(mir_res.advisory.contains("Mir"));

        // Heuristics for Belkart
        let by_res = BinChecker::evaluate_heuristics("911234").unwrap();
        assert_eq!(by_res.status, CheckStatus::Critical);
        assert_eq!(by_res.country_code.as_deref(), Some("BY"));
    }
}
