mod cascade;
mod exit_probe;
mod resolver;

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auditor::geo_matrix::{CheckResult, UnknownReason};
#[cfg(test)]
use crate::auditor::geo_matrix::{CheckStatus, ProviderId};
#[cfg(test)]
use crate::auditor::rules::ProviderMatrix;
#[cfg(test)]
use crate::auditor::seams::{HttpProbeOutcome, IpProbe};
#[cfg(test)]
use crate::routing::{Entry, EntryProto, Route};
#[cfg(test)]
use crate::state::UpstreamProxyConfig;
#[cfg(test)]
use cascade::{build_entry_client_with_root, format_checked_entry_error};
#[cfg(test)]
use exit_probe::default_exit_probe_url;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::Ordering;
#[cfg(test)]
use std::time::Duration;

pub use cascade::{build_entry_client, build_upstream_client};
pub use exit_probe::{CloudflareTrace, parse_cloudflare_trace};
pub use resolver::NetworkResolver;

pub const CACHE_TTL_SECONDS: u64 = 15;
pub const REQUEST_TIMEOUT_MS: u64 = 3500;

/// Neutral browser-like User-Agent for telemetry and exit probes (never identifies Zastava).
pub const NEUTRAL_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

pub const SUSPICIOUS_ANONYMIZER_MARKERS: &[&str] = &[
    "tor-exit",
    "anonymizer",
    "openproxy",
    "public-vpn",
    "socks-proxy",
    "vpn-exit",
    "exit-node",
    "torproject",
    "tor-node",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkTelemetry {
    pub ip: String,
    pub country_code: String,
    #[serde(default)]
    pub hostname: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub timezone: Option<String>,
    pub resolved_at: u64,
}

impl NetworkTelemetry {
    pub fn is_fresh(&self, ttl_seconds: u64) -> bool {
        let now = current_timestamp();
        now.saturating_sub(self.resolved_at) < ttl_seconds
    }

    pub fn has_provider_metadata(&self) -> bool {
        self.asn.is_some() || self.isp.is_some() || self.org.is_some()
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Gate 10: Evaluates reverse DNS / hostname / ISP / org for suspicious proxy and anonymizer markers.
pub fn evaluate_reverse_dns_ptr(telemetry: &NetworkTelemetry) -> CheckResult {
    evaluate_reverse_dns_ptr_with_ptr(telemetry, None)
}

/// Gate 10 with a real (or faked) PTR hostname resolved via [`crate::auditor::seams::DnsLookup::reverse_ptr`].
pub async fn evaluate_reverse_dns_ptr_with_dns(
    telemetry: &NetworkTelemetry,
    dns: &dyn crate::auditor::seams::DnsLookup,
) -> CheckResult {
    let ptr = match telemetry.ip.trim().parse::<std::net::IpAddr>() {
        Ok(ip) => dns.reverse_ptr(ip).await,
        Err(_) => None,
    };
    evaluate_reverse_dns_ptr_with_ptr(telemetry, ptr.as_deref())
}

/// Gate 10 evaluator taking an optional resolved PTR record alongside geo telemetry.
pub fn evaluate_reverse_dns_ptr_with_ptr(
    telemetry: &NetworkTelemetry,
    ptr_hostname: Option<&str>,
) -> CheckResult {
    let ptr_clean = ptr_hostname.map(str::trim).filter(|t| !t.is_empty());
    let mut examined = Vec::new();
    if let Some(ptr) = ptr_clean {
        examined.push(ptr);
    }
    if let Some(h) = &telemetry.hostname {
        examined.push(h.as_str());
    }
    if let Some(isp) = &telemetry.isp {
        examined.push(isp.as_str());
    }
    if let Some(org) = &telemetry.org {
        examined.push(org.as_str());
    }

    for text in examined {
        let lower = text.to_lowercase();
        for &marker in SUSPICIOUS_ANONYMIZER_MARKERS {
            if lower.contains(marker) {
                let res = CheckResult::warning(
                    "REVERSE_DNS_ANONYMIZER_MARKER",
                    format!(
                        "В данных узла ({text}) обнаружен маркер публичного анонимайзера «{marker}». Антифрод-системы ИИ блокируют такие адреса. Рекомендуется сменить сервер на чистый VPS."
                    ),
                    Some(crate::auditor::geo_matrix::GUIDE_PERSONAL_VPN.to_string()),
                );
                return if ptr_clean.is_some() {
                    res.with_measured_via("rdns:ptr")
                } else {
                    res
                };
            }
        }
    }

    if let Some(ptr) = ptr_clean {
        return CheckResult::ok(
            "REVERSE_DNS_CLEAN",
            format!(
                "PTR-запись выходного IP ({ptr}) проверена: маркеров публичных анонимайзеров из встроенного списка не обнаружено."
            ),
        )
        .with_measured_via("rdns:ptr");
    }

    fn non_empty(v: &Option<String>) -> Option<&str> {
        v.as_deref().filter(|t| !t.trim().is_empty())
    }
    let Some(detail) = non_empty(&telemetry.hostname)
        .or(non_empty(&telemetry.isp))
        .or(non_empty(&telemetry.org))
    else {
        return CheckResult::unknown(
            "REVERSE_DNS_NO_DATA",
            "Reverse DNS не проверен: PTR-запись недоступна, а источник геолокации не передал имя узла, провайдера и организацию.",
            UnknownReason::NoData,
        );
    };

    CheckResult::ok(
        "REVERSE_DNS_CLEAN",
        format!(
            "PTR-запись недоступна; по данным узла/провайдера ({detail}) маркеров публичных анонимайзеров из встроенного списка не обнаружено."
        ),
    )
}

/// Gate 11: Verifies whether the exit IP geolocation across independent telemetry endpoints
/// and DNS resolution is consistent (detects cross-country DNS splits or transparent DNS hijacking).
pub fn evaluate_dns_country_consistency(
    telemetry: &NetworkTelemetry,
    secondary_country: Option<&str>,
) -> CheckResult {
    let exit_country = telemetry.country_code.trim().to_uppercase();

    // 1. Check if a secondary independent telemetry source reports a mismatched country
    if let Some(sec_country) = secondary_country {
        let sec = sec_country.trim().to_uppercase();
        if !sec.is_empty() && sec != exit_country {
            return CheckResult::warning(
                "DNS_COUNTRY_SPLIT",
                format!(
                    "Обнаружен рассинхрон юрисдикций: выходной IP находится в {exit_country}, а вторичный резолвер сообщает о локации {sec}. Это может указывать на утечку DNS или прозрачный DNS-прокси."
                ),
                Some(crate::auditor::geo_matrix::GUIDE_OS_PRIVACY.to_string()),
            );
        }
    }

    if secondary_country.is_none_or(|c| c.trim().is_empty()) {
        // No independent source to compare with: nothing was verified.
        return CheckResult::unknown(
            "DNS_COUNTRY_NO_SOURCE",
            "Согласованность страны DNS и выходного узла не проверена: нет независимого источника для сравнения.",
            UnknownReason::NoData,
        );
    }

    CheckResult::ok(
        "DNS_COUNTRY_CONSISTENT",
        format!(
            "Географическая юрисдикция DNS и выходного узла ({exit_country}) полностью согласованы."
        ),
    )
}

#[cfg(test)]
#[path = "../network_tests/mod.rs"]
mod tests;
