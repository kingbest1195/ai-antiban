//! 8-digit BIN X-Ray (Zero PCI-DSS Scope, Fail-Closed) with curated overlay and 7-day cache.

pub mod cache;
pub mod http_adapter;
pub mod model;
pub mod overlay;
pub mod port;

#[cfg(test)]
mod tests;

pub use model::{
    BinAuditResult, BinReport, BinSource, CardFunding, ClaudeWebVerdict, sanitize_bin_input,
    validate_strict_bin_prefix,
};
pub use overlay::BinOverlay;
pub use port::{BinLookupError, BinLookupPort, RawBinInfo};

use crate::auditor::geo_matrix::{CheckStatus, GUIDE_PAYMENT_CARDS};
use crate::core::country::format_country_ru;
use cache::BinCache;
use http_adapter::HttpBinLookupAdapter;
use std::path::Path;
use std::sync::Arc;

const SANCTIONED_CARD_COUNTRIES: &[&str] = &[
    "RU", "BY", "CN", "HK", "MO", "IR", "KP", "SY", "CU", "VE", "AF", "MM", "SD", "YE",
];

pub struct BinChecker {
    overlay: BinOverlay,
    lookup_port: Arc<dyn BinLookupPort>,
}

impl Default for BinChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl BinChecker {
    pub fn new() -> Self {
        Self::with_port(Arc::new(HttpBinLookupAdapter::from_env()))
    }

    pub fn with_port(lookup_port: Arc<dyn BinLookupPort>) -> Self {
        let overlay = BinOverlay::load_bundled().expect("bundled bin_overlay.json must be valid");
        Self {
            overlay,
            lookup_port,
        }
    }

    pub fn sanitize_bin(raw_input: &str) -> Result<String, String> {
        sanitize_bin_input(raw_input)
    }

    pub fn evaluate_heuristics(bin: &str) -> Option<BinAuditResult> {
        let overlay = BinOverlay::load_bundled().ok()?;
        let mut matched = overlay.lookup(bin)?;
        evaluate_report(
            &mut matched.report,
            matched.high_kyc_risk,
            &matched.note,
            None,
        );
        Some(BinAuditResult::from_report(
            matched.report,
            Some(GUIDE_PAYMENT_CARDS.to_string()),
        ))
    }

    pub async fn check_bin(
        &self,
        raw_bin: &str,
        current_vpn_country: Option<&str>,
    ) -> Result<BinAuditResult, String> {
        let report = self
            .check_bin_report_with_cache_dir(raw_bin, current_vpn_country, None)
            .await?;
        let guide_ref = if report.status == CheckStatus::Ok {
            None
        } else {
            Some(GUIDE_PAYMENT_CARDS.to_string())
        };
        Ok(BinAuditResult::from_report(report, guide_ref))
    }

    pub async fn check_bin_report_with_cache_dir(
        &self,
        raw_bin: &str,
        current_vpn_country: Option<&str>,
        cache_dir: Option<&Path>,
    ) -> Result<BinReport, String> {
        let bin_prefix = sanitize_bin_input(raw_bin)?;

        // 1. Curated local overlay (compile-time, priority #1 over any external API or cache)
        if let Some(mut matched) = self.overlay.lookup(&bin_prefix) {
            evaluate_report(
                &mut matched.report,
                matched.high_kyc_risk,
                &matched.note,
                current_vpn_country,
            );
            return Ok(matched.report);
        }

        // 2. 7-day local TTL cache
        let cache = cache_dir.map(BinCache::in_dir);
        if let Some(ref c) = cache
            && let Some(mut cached) = c.get(&bin_prefix)
        {
            let high_risk = self
                .overlay
                .is_high_risk_issuer(cached.issuer_name.as_deref());
            evaluate_report(&mut cached, high_risk, "", current_vpn_country);
            return Ok(cached);
        }

        // 3. Remote lookup via BinLookupPort (ProxyApi -> FallbackPublicApi)
        match self.lookup_port.lookup(&bin_prefix).await {
            Ok(info) => {
                let mut report = raw_info_to_report(&bin_prefix, info);
                let high_risk = self
                    .overlay
                    .is_high_risk_issuer(report.issuer_name.as_deref());
                evaluate_report(&mut report, high_risk, "", current_vpn_country);
                if let Some(ref c) = cache
                    && report.country_code.is_some()
                    && report.status != CheckStatus::Unknown
                {
                    c.put(&report);
                }
                Ok(report)
            }
            // 4. Fail-Closed: NEVER return CheckStatus::Ok on lookup failure
            Err(err) => Ok(fail_closed_report(bin_prefix, err)),
        }
    }
}

fn raw_info_to_report(bin_prefix: &str, info: RawBinInfo) -> BinReport {
    BinReport {
        bin_prefix: bin_prefix.to_string(),
        status: CheckStatus::Ok,
        scheme: info.scheme,
        funding: info.funding,
        is_prepaid: info.is_prepaid,
        is_commercial: info.is_commercial,
        is_reloadable: info.is_reloadable,
        card_category: info.card_category,
        country_code: info.country_code,
        issuer_name: info.issuer_name,
        known_fintech_label: None,
        source: info.source,
        claude_web_verdict: ClaudeWebVerdict::SafeAligned,
        warnings: Vec::new(),
    }
}

fn fail_closed_report(bin_prefix: String, err: BinLookupError) -> BinReport {
    let warnings = vec![
        "Не удалось проверить первые цифры карты — оплата вслепую несёт риск запроса паспорта и селфи. Проверьте карту позже или оплатите через App Store."
            .to_string(),
        err.user_reason_ru(),
    ];
    BinReport {
        bin_prefix,
        status: CheckStatus::Unknown,
        scheme: None,
        funding: CardFunding::Unknown,
        is_prepaid: None,
        is_commercial: None,
        is_reloadable: None,
        card_category: None,
        country_code: None,
        issuer_name: None,
        known_fintech_label: None,
        source: BinSource::FallbackUnknown,
        claude_web_verdict: ClaudeWebVerdict::HighKycRisk,
        warnings,
    }
}

fn evaluate_report(
    report: &mut BinReport,
    high_kyc_risk: bool,
    overlay_note: &str,
    current_vpn_country: Option<&str>,
) {
    report.warnings.clear();
    if !overlay_note.is_empty() {
        report.warnings.push(overlay_note.to_string());
    }

    let country = report.country_code.as_deref().unwrap_or("");
    if !country.is_empty() && SANCTIONED_CARD_COUNTRIES.contains(&country) {
        report.status = CheckStatus::Critical;
        report.claude_web_verdict = ClaudeWebVerdict::Blocked;
        let country_label = format_country_ru(country);
        report.warnings.push(format!(
            "Карта выпущена в неподдерживаемой стране: {country_label}. Платёжная система сайта отклоняет карты этого региона."
        ));
        return;
    }

    if high_kyc_risk {
        report.status = CheckStatus::Critical;
        report.claude_web_verdict = ClaudeWebVerdict::HighKycRisk;
        report.warnings.push(
            "Высокий риск мгновенного запроса паспорта и селфи на claude.ai для этой карты."
                .to_string(),
        );
        return;
    }

    let is_prepaid = report.is_prepaid == Some(true) || report.funding == CardFunding::Prepaid;
    let is_commercial = report.is_commercial == Some(true);

    if is_prepaid {
        report.status = CheckStatus::Warning;
        report.claude_web_verdict = if is_commercial {
            ClaudeWebVerdict::HighKycRisk
        } else {
            ClaudeWebVerdict::NeedsMatchingIpBilling
        };
        report.warnings.push(
            "Предоплаченная (виртуальная) карта: антифрод оплаты часто отправляет такие карты на дополнительную проверку по паспорту и селфи."
                .to_string(),
        );
    } else if is_commercial {
        report.status = CheckStatus::Warning;
        report.claude_web_verdict = ClaudeWebVerdict::NeedsMatchingIpBilling;
        report.warnings.push(
            "Корпоративная карта: требуется строгое совпадение страны карты, страны подключения и адреса оплаты."
                .to_string(),
        );
    }

    if country.is_empty() {
        if report.status != CheckStatus::Critical {
            report.status = CheckStatus::Unknown;
        }
        if !matches!(
            report.claude_web_verdict,
            ClaudeWebVerdict::Blocked | ClaudeWebVerdict::HighKycRisk
        ) {
            report.claude_web_verdict = ClaudeWebVerdict::HighKycRisk;
        }
        report.warnings.push(
            "Страна выпуска карты не определена — такая проверка не может считаться безопасной."
                .to_string(),
        );
    } else if let (Some(card_cc), Some(vpn_raw)) = (&report.country_code, current_vpn_country) {
        let vpn_cc = crate::core::country::normalize_country_code(vpn_raw);
        if vpn_cc.len() == 2
            && vpn_cc.bytes().all(|b| b.is_ascii_alphabetic())
            && !card_cc.eq_ignore_ascii_case(&vpn_cc)
        {
            if report.status != CheckStatus::Critical {
                report.status = CheckStatus::Warning;
            }
            if !matches!(
                report.claude_web_verdict,
                ClaudeWebVerdict::Blocked | ClaudeWebVerdict::HighKycRisk
            ) {
                report.claude_web_verdict = ClaudeWebVerdict::NeedsMatchingIpBilling;
            }
            let card_label = format_country_ru(card_cc);
            let vpn_label = format_country_ru(&vpn_cc);
            report.warnings.push(format!(
                "Несовпадение стран: карта из страны {card_label}, а текущее подключение — {vpn_label}. Выберите подключение и адрес оплаты в стране карты."
            ));
        } else if !is_prepaid && !is_commercial {
            report.status = CheckStatus::Ok;
            report.claude_web_verdict = ClaudeWebVerdict::SafeAligned;
        }
    } else if !is_prepaid && !is_commercial {
        report.status = CheckStatus::Ok;
        report.claude_web_verdict = ClaudeWebVerdict::SafeAligned;
    }
}
