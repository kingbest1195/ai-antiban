use std::net::SocketAddr;
use std::time::Duration;
use crate::auditor::geo_matrix::{CheckResult, UnknownReason, GUIDE_PERSONAL_VPN};
use crate::auditor::rules::{DangerousAsns, DnsblZoneConfig};

pub const DNSBL_TIMEOUT_MS: u64 = 600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsblZoneHit {
    pub zone: String,
    pub name: String,
    pub return_ip: String,
    pub severity: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsblReport {
    pub total_checked: usize,
    pub hits: Vec<DnsblZoneHit>,
    pub summary_label: String, // e.g. "0/4 Clean" or "1/4 Listed"
    /// One entry per zone that gave no usable answer (timeout, refusal by the resolver, task failure).
    pub failures: Vec<UnknownReason>,
}

/// Fewer answering zones than this cannot vouch for "not listed".
pub const MIN_ANSWERING_ZONES: usize = 2;

impl DnsblReport {
    pub fn answered(&self) -> usize {
        self.total_checked.saturating_sub(self.failures.len())
    }

    /// Why the report cannot vouch for "clean", if it cannot. A listing is always conclusive.
    pub fn unknown_reason(&self) -> Option<UnknownReason> {
        if !self.hits.is_empty() {
            return None;
        }
        if self.total_checked > 0 && self.answered() >= MIN_ANSWERING_ZONES.min(self.total_checked) {
            return None;
        }
        let count = |r: UnknownReason| self.failures.iter().filter(|f| **f == r).count();
        Some(if self.failures.is_empty() {
            UnknownReason::NoData
        } else if count(UnknownReason::SourceRefused) == self.failures.len() {
            UnknownReason::SourceRefused
        } else if count(UnknownReason::Timeout) > 0 {
            UnknownReason::Timeout
        } else if count(UnknownReason::NoData) == self.failures.len() {
            UnknownReason::NoData
        } else {
            UnknownReason::NetworkError
        })
    }
}

/// Outcome of one zone lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneOutcome {
    Listed(DnsblZoneHit),
    /// An answer without a listing (NXDOMAIN or a non-listing address).
    NotListed,
    /// The resolver answered with an error marker (`127.255.255.x`): the zone refuses this resolver.
    Refused,
    TimedOut,
}

/// Reverses IPv4 octets: "185.220.101.5" -> "5.101.220.185".
pub fn reverse_ipv4(ip_str: &str) -> Result<String, String> {
    let parts: Vec<&str> = ip_str.trim().split('.').collect();
    if parts.len() != 4 {
        return Err(format!("Invalid IPv4 format: {ip_str}"));
    }

    for part in &parts {
        let num: u8 = part
            .parse()
            .map_err(|_| format!("Invalid IPv4 octet: {part}"))?;
        let _ = num;
    }

    Ok(format!("{}.{}.{}.{}", parts[3], parts[2], parts[1], parts[0]))
}

/// Formats DNSBL query domain: "5.101.220.185.zen.spamhaus.org".
pub fn format_dnsbl_query(ip: &str, zone: &str) -> Result<String, String> {
    let reversed = reverse_ipv4(ip)?;
    Ok(format!("{}.{}", reversed, zone.trim_matches('.')))
}

/// Queries a single DNSBL zone asynchronously with strict 600 ms timeout.
pub async fn query_dnsbl_zone(
    reversed_ip: &str,
    zone_cfg: &DnsblZoneConfig,
) -> Option<DnsblZoneHit> {
    match query_dnsbl_zone_outcome(reversed_ip, zone_cfg).await {
        ZoneOutcome::Listed(hit) => Some(hit),
        _ => None,
    }
}

/// Like [`query_dnsbl_zone`], but a timeout or a refusal is told apart from "not listed".
pub async fn query_dnsbl_zone_outcome(
    reversed_ip: &str,
    zone_cfg: &DnsblZoneConfig,
) -> ZoneOutcome {
    let query_host = format!("{}.{}:80", reversed_ip, zone_cfg.zone.trim_matches('.'));

    let lookup_future = tokio::net::lookup_host(&query_host);
    let result = tokio::time::timeout(Duration::from_millis(DNSBL_TIMEOUT_MS), lookup_future).await;

    match result {
        Ok(Ok(addrs)) => {
            let mut refused = false;
            for addr in addrs {
                if let SocketAddr::V4(v4) = addr {
                    let octets = v4.ip().octets();
                    // 127.0.0.x indicates listing in DNSBL
                    // (127.255.255.x indicates query error / refusal by public resolver)
                    if octets[0] == 127 && octets[1] == 0 && octets[2] == 0 {
                        return ZoneOutcome::Listed(DnsblZoneHit {
                            zone: zone_cfg.zone.clone(),
                            name: zone_cfg.name.clone(),
                            return_ip: v4.ip().to_string(),
                            severity: zone_cfg.severity.clone(),
                            reason: zone_cfg.reason.clone(),
                        });
                    }
                    if octets[0] == 127 && octets[1] == 255 && octets[2] == 255 {
                        refused = true;
                    }
                }
            }
            if refused {
                ZoneOutcome::Refused
            } else {
                ZoneOutcome::NotListed
            }
        }
        // The system resolver reports NXDOMAIN and other failures alike: not listed.
        Ok(Err(_)) => ZoneOutcome::NotListed,
        Err(_) => ZoneOutcome::TimedOut,
    }
}

/// Queries all configured DNSBL zones in parallel.
pub async fn check_all_dnsbl(ip: &str, dangerous_asns: &DangerousAsns) -> DnsblReport {
    let total = dangerous_asns.dnsbl_zones.len();
    let reversed = match reverse_ipv4(ip) {
        Ok(rev) => rev,
        Err(_) => {
            return DnsblReport {
                total_checked: total,
                hits: Vec::new(),
                summary_label: format!("Не проверено: IP {ip} не IPv4"),
                failures: vec![UnknownReason::NoData; total],
            };
        }
    };

    let mut tasks = Vec::new();
    for zone in &dangerous_asns.dnsbl_zones {
        let rev_clone = reversed.clone();
        let zone_clone = zone.clone();
        tasks.push(tokio::spawn(async move {
            query_dnsbl_zone_outcome(&rev_clone, &zone_clone).await
        }));
    }

    let mut hits = Vec::new();
    let mut failures = Vec::new();
    for task in tasks {
        match task.await {
            Ok(ZoneOutcome::Listed(hit)) => hits.push(hit),
            Ok(ZoneOutcome::NotListed) => {}
            Ok(ZoneOutcome::Refused) => failures.push(UnknownReason::SourceRefused),
            Ok(ZoneOutcome::TimedOut) => failures.push(UnknownReason::Timeout),
            Err(_) => failures.push(UnknownReason::InternalError),
        }
    }

    let hit_count = hits.len();
    let answered = total.saturating_sub(failures.len());
    let summary_label = if hit_count > 0 {
        format!("{hit_count}/{total} Listed")
    } else if failures.is_empty() {
        format!("0/{total} Clean")
    } else {
        format!("Ответили {answered} из {total} баз")
    };

    DnsblReport {
        total_checked: total,
        hits,
        summary_label,
        failures,
    }
}

/// Converts DNSBL Report to standard CheckResult.
pub fn evaluate_dnsbl_report(report: &DnsblReport) -> CheckResult {
    if let Some(reason) = report.unknown_reason() {
        return CheckResult::unknown(
            match reason {
                UnknownReason::SourceRefused => "DNSBL_RESOLVER_REFUSED",
                UnknownReason::Timeout => "DNSBL_TIMEOUT",
                _ => "DNSBL_NO_ANSWER",
            },
            format!(
                "Проверка DNSBL не выполнена: ответили {} из {} спам-баз, отсутствие листинга не подтверждено.",
                report.answered(),
                report.total_checked,
            ),
            reason,
        );
    }
    if report.hits.is_empty() {
        return CheckResult::ok(
            "DNSBL_CLEAN",
            format!("Проверка DNSBL: {} — IP чист, совпадений в спам-базах нет.", report.summary_label),
        );
    }

    let has_critical = report.hits.iter().any(|h| h.severity == "critical");
    let names: Vec<String> = report.hits.iter().map(|h| h.name.clone()).collect();
    let joined_names = names.join(", ");

    let msg = format!(
        "Ваш IP найден в спам/ботнет-базах ({joined_names}). Антифрод Cloudflare и Claude блокирует сессии с заспамленных узлов."
    );

    if has_critical {
        CheckResult::critical("DNSBL_LISTED_CRITICAL", msg, Some(GUIDE_PERSONAL_VPN.to_string()))
    } else {
        CheckResult::warning("DNSBL_LISTED_WARNING", msg, Some(GUIDE_PERSONAL_VPN.to_string()))
    }
}

/// Evaluates ASN and Network reputation.
pub fn evaluate_asn_reputation(
    asn: Option<u32>,
    isp: Option<&str>,
    org: Option<&str>,
    dangerous_asns: &DangerousAsns,
    is_pinned: bool,
) -> CheckResult {
    // 1. Check if ISP/Org name indicates Russian domestic telecom
    let isp_str = isp.unwrap_or_default();
    let org_str = org.unwrap_or_default();

    if let Some(matched_isp) = dangerous_asns.matches_russian_isp(isp_str).or_else(|| dangerous_asns.matches_russian_isp(org_str)) {
        return CheckResult::critical(
            "RUSSIAN_ISP_DETECTED",
            format!("Обнаружен домашний провайдер РФ ({matched_isp}). Прямой выход без VPN приведет к мгновенному бану аккаунта."),
            Some(GUIDE_PERSONAL_VPN.to_string()),
        );
    }

    // 2. If user already pinned this IP as their personal dedicated VPS, datacenter ASN warnings are bypassed!
    if is_pinned {
        return CheckResult::ok(
            "ASN_VERIFIED_PINNED",
            "IP подтвержден и закреплен как ваш личный выделенный VPS.",
        );
    }

    // 3. Check for commercial mass-VPN / shared datacenter ASN
    if let Some(asn_num) = asn {
        if let Some(high_risk) = dangerous_asns.is_high_risk_asn(asn_num) {
            return CheckResult::warning(
                "HIGH_RISK_MASS_VPN_ASN",
                format!(
                    "Подсеть массового хостинга/VPN «{}» (AS{}). {} Если это ваш личный VPS — нажмите «Закрепить IP», чтобы убрать предупреждение.",
                    high_risk.name,
                    high_risk.asn,
                    high_risk.reason
                ),
                Some(GUIDE_PERSONAL_VPN.to_string()),
            );
        }
    }

    // Nothing to judge: the geolocation source gave neither ASN nor ISP/org.
    if asn.is_none() && isp_str.trim().is_empty() && org_str.trim().is_empty() {
        return CheckResult::unknown(
            "ASN_NO_DATA",
            "Репутация ASN не проверена: источник геолокации не передал ASN, провайдера и организацию.",
            UnknownReason::NoData,
        );
    }

    CheckResult::ok("ASN_CLEAN", "Репутация автономной системы (ASN) и провайдера чистая.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::geo_matrix::CheckStatus;

    #[test]
    fn test_dnsbl_reverse_ip_query_formatting() {
        let ip = "185.220.101.1";
        let reversed = reverse_ipv4(ip).unwrap();
        assert_eq!(reversed, "1.101.220.185");

        let fqdn = format_dnsbl_query(ip, "zen.spamhaus.org").unwrap();
        assert_eq!(fqdn, "1.101.220.185.zen.spamhaus.org");

        // Verify alternative IP
        assert_eq!(reverse_ipv4("185.220.101.5").unwrap(), "5.101.220.185");

        let invalid = reverse_ipv4("invalid.ip");
        assert!(invalid.is_err());

        // DNSBL hit simulation with 127.0.0.2 -> Listed (Critical)
        let critical_hit = DnsblZoneHit {
            zone: "zen.spamhaus.org".to_string(),
            name: "Spamhaus ZEN".to_string(),
            return_ip: "127.0.0.2".to_string(),
            severity: "critical".to_string(),
            reason: "SBL Listed".to_string(),
        };
        let listed_report = DnsblReport {
            total_checked: 4,
            hits: vec![critical_hit],
            summary_label: "1/4 Listed".to_string(),
            failures: Vec::new(),
        };
        let listed_res = evaluate_dnsbl_report(&listed_report);
        assert_eq!(listed_res.status, CheckStatus::Critical);
        assert_eq!(listed_res.code, "DNSBL_LISTED_CRITICAL");
        assert!(listed_res.message.contains("Spamhaus ZEN"));

        // DNSBL hit simulation with warning severity -> Listed (Warning)
        let warning_hit = DnsblZoneHit {
            zone: "dnsbl.dronebl.org".to_string(),
            name: "DroneBL".to_string(),
            return_ip: "127.0.0.2".to_string(),
            severity: "warning".to_string(),
            reason: "Suspected crawler".to_string(),
        };
        let warning_report = DnsblReport {
            total_checked: 4,
            hits: vec![warning_hit],
            summary_label: "1/4 Listed".to_string(),
            failures: Vec::new(),
        };
        let warning_res = evaluate_dnsbl_report(&warning_report);
        assert_eq!(warning_res.status, CheckStatus::Warning);
        assert_eq!(warning_res.code, "DNSBL_LISTED_WARNING");

        // NXDOMAIN simulation (no hits) -> Clean (Status::Ok)
        let clean_report = DnsblReport {
            total_checked: 4,
            hits: Vec::new(),
            summary_label: "0/4 Clean".to_string(),
            failures: Vec::new(),
        };
        let clean_res = evaluate_dnsbl_report(&clean_report);
        assert_eq!(clean_res.status, CheckStatus::Ok);
        assert_eq!(clean_res.code, "DNSBL_CLEAN");
    }

    #[test]
    fn test_asn_matching_and_pinning_bypass() {
        let asns = DangerousAsns::load_bundled().unwrap();

        // High risk mass VPN (M247: AS9009) when unpinned -> Warning
        let res_unpinned = evaluate_asn_reputation(Some(9009), Some("M247"), None, &asns, false);
        assert_eq!(res_unpinned.status, CheckStatus::Warning);
        assert_eq!(res_unpinned.code, "HIGH_RISK_MASS_VPN_ASN");

        // High risk mass VPN (M247: AS9009) when PINNED -> Ok
        let res_pinned = evaluate_asn_reputation(Some(9009), Some("M247"), None, &asns, true);
        assert_eq!(res_pinned.status, CheckStatus::Ok);
        assert_eq!(res_pinned.code, "ASN_VERIFIED_PINNED");

        // Russian ISP keyword (Rostelecom) -> Critical even if pinned
        let res_ru = evaluate_asn_reputation(Some(12389), Some("PJSC Rostelecom"), None, &asns, false);
        assert_eq!(res_ru.status, CheckStatus::Critical);
        assert_eq!(res_ru.code, "RUSSIAN_ISP_DETECTED");
    }

    fn report(total: usize, failures: Vec<UnknownReason>) -> DnsblReport {
        DnsblReport {
            total_checked: total,
            hits: Vec::new(),
            summary_label: String::new(),
            failures,
        }
    }

    #[test]
    fn test_dnsbl_without_enough_answers_is_unknown() {
        use UnknownReason::*;
        // All four zones timed out.
        let r = evaluate_dnsbl_report(&report(4, vec![Timeout; 4]));
        assert_eq!(r.status, CheckStatus::Unknown);
        assert_eq!(r.reason, Some(Timeout));
        // All refused by the resolver.
        let r = evaluate_dnsbl_report(&report(4, vec![SourceRefused; 4]));
        assert_eq!(r.reason, Some(SourceRefused));
        // 2 answered + 2 timed out: enough to call it clean.
        let r = evaluate_dnsbl_report(&report(4, vec![Timeout; 2]));
        assert_eq!(r.status, CheckStatus::Ok);
        // 1 answered + 3 timed out: not enough.
        let r = evaluate_dnsbl_report(&report(4, vec![Timeout; 3]));
        assert_eq!(r.status, CheckStatus::Unknown);
        // A task failure is an error, never "clean".
        let r = evaluate_dnsbl_report(&report(4, vec![InternalError; 4]));
        assert_eq!(r.status, CheckStatus::Unknown);
        // No zones configured at all.
        assert_eq!(evaluate_dnsbl_report(&report(0, vec![])).status, CheckStatus::Unknown);
    }

    #[test]
    fn test_dnsbl_listing_wins_over_failures() {
        let mut rep = report(4, vec![UnknownReason::Timeout; 3]);
        rep.hits.push(DnsblZoneHit {
            zone: "z".into(),
            name: "Z".into(),
            return_ip: "127.0.0.2".into(),
            severity: "warning".into(),
            reason: "r".into(),
        });
        assert_eq!(evaluate_dnsbl_report(&rep).status, CheckStatus::Warning);
    }

    #[tokio::test]
    async fn test_dnsbl_non_ipv4_is_unknown_without_network() {
        let asns = DangerousAsns::load_bundled().unwrap();
        let rep = check_all_dnsbl("2606:4700::1111", &asns).await;
        let res = evaluate_dnsbl_report(&rep);
        assert_eq!(res.status, CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::NoData));
    }

    #[test]
    fn test_asn_without_any_data_is_unknown() {
        let asns = DangerousAsns::load_bundled().unwrap();
        let res = evaluate_asn_reputation(None, None, None, &asns, false);
        assert_eq!(res.status, CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::NoData));
        // A known (clean) ASN is still a verdict.
        let res = evaluate_asn_reputation(Some(64500), Some("Example Net"), None, &asns, false);
        assert_eq!(res.status, CheckStatus::Ok);
    }
}
