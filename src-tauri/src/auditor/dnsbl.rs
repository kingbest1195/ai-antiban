use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::auditor::geo_matrix::{CheckResult, GUIDE_PERSONAL_VPN, UnknownReason};
use crate::auditor::rules::{DangerousAsns, DnsblZoneConfig};
use crate::auditor::seams::{DnsLookup, LookupOutcome, SystemDns};

/// Time limit of one lookup (the zone's real query and its control query run side by side).
pub const DNSBL_TIMEOUT_MS: u64 = 1500;

/// Control address: every working DNSBL zone lists `127.0.0.2` (RFC 5782, section 5).
const CONTROL_REVERSED_IP: &str = "2.0.0.127";

/// Spamhaus ZEN answers `127.0.0.10` / `127.0.0.11` for the Policy Block List: the address range
/// is dynamic or residential, which is not a reputation problem of this IP.
const SPAMHAUS_ZEN_ZONE: &str = "zen.spamhaus.org";
const SPAMHAUS_PBL_CODES: [u8; 2] = [10, 11];

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
    /// Number of zones actually queried.
    pub total_checked: usize,
    pub hits: Vec<DnsblZoneHit>,
    /// E.g. "Ответили 3 из 3 баз" or "1/3 Listed".
    pub summary_label: String,
    /// One entry per zone that gave no usable answer (timeout, refusal by the resolver, task failure).
    pub failures: Vec<UnknownReason>,
    /// The IP is not IPv4: the zones list IPv4 addresses only, so nothing was queried.
    pub unsupported_ip: bool,
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
        if self.unsupported_ip {
            return Some(UnknownReason::NoData);
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
        } else if count(UnknownReason::InternalError) == self.failures.len() {
            UnknownReason::InternalError
        } else {
            UnknownReason::NetworkError
        })
    }
}

/// Outcome of one zone query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneAnswer {
    Listed(DnsblZoneHit),
    /// The zone proved itself (the control address is listed) and has no record for this IP.
    NotListed,
    /// The zone does not serve this resolver: `127.255.255.x`, or no listing for the control
    /// address (a dead zone or a resolver the zone turns away).
    Refused,
    Timeout,
    /// Unusable answer (resolver failure, an address outside `127.0.0.0/8` such as a fake-IP
    /// DNS interceptor or a captive portal gives).
    Error,
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

/// How one lookup reads for a DNSBL zone.
#[derive(Debug, PartialEq, Eq)]
enum Reading {
    /// `127.0.0.x` answers.
    Listing(Vec<Ipv4Addr>),
    /// `127.255.255.x`: the zone turns this resolver away.
    Refusal,
    /// NXDOMAIN or an empty answer.
    Empty,
    Timeout,
    Failed,
    /// Addresses that mean nothing for a DNSBL (fake-IP DNS, captive portal, IPv6 only...).
    Unexpected,
}

fn read_lookup(outcome: LookupOutcome) -> Reading {
    match outcome {
        LookupOutcome::Timeout => Reading::Timeout,
        LookupOutcome::Failed => Reading::Failed,
        LookupOutcome::NotFound => Reading::Empty,
        LookupOutcome::Addrs(addrs) => {
            let v4: Vec<Ipv4Addr> = addrs
                .into_iter()
                .filter_map(|a| match a {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                })
                .collect();
            let listing: Vec<Ipv4Addr> = v4
                .iter()
                .copied()
                .filter(|a| a.octets()[..3] == [127, 0, 0])
                .collect();
            if !listing.is_empty() {
                Reading::Listing(listing)
            } else if v4.iter().any(|a| a.octets()[..3] == [127, 255, 255]) {
                Reading::Refusal
            } else {
                Reading::Unexpected
            }
        }
    }
}

/// Spamhaus PBL: an answer that says nothing about the reputation of the IP.
fn is_policy_only(zone: &str, addr: &Ipv4Addr) -> bool {
    zone.trim_matches('.').eq_ignore_ascii_case(SPAMHAUS_ZEN_ZONE)
        && SPAMHAUS_PBL_CODES.contains(&addr.octets()[3])
}

/// Queries one zone: the control address first proves the zone answers this resolver, then the
/// IP itself. A zone counts as "not listed" only when the control query came back as a listing.
pub async fn query_zone(
    dns: &dyn DnsLookup,
    reversed_ip: &str,
    zone_cfg: &DnsblZoneConfig,
    limit: Duration,
) -> ZoneAnswer {
    let zone = zone_cfg.zone.trim_matches('.');
    let control_host = format!("{CONTROL_REVERSED_IP}.{zone}");
    let ip_host = format!("{reversed_ip}.{zone}");
    let (control, real) = tokio::join!(
        dns.lookup(&control_host, limit),
        dns.lookup(&ip_host, limit)
    );

    match read_lookup(control) {
        Reading::Listing(_) => {}
        Reading::Refusal | Reading::Empty => return ZoneAnswer::Refused,
        Reading::Timeout => return ZoneAnswer::Timeout,
        Reading::Failed | Reading::Unexpected => return ZoneAnswer::Error,
    }

    match read_lookup(real) {
        Reading::Listing(addrs) => {
            let meaningful: Vec<Ipv4Addr> = addrs
                .into_iter()
                .filter(|a| !is_policy_only(zone, a))
                .collect();
            match meaningful.first() {
                Some(first) => ZoneAnswer::Listed(DnsblZoneHit {
                    zone: zone_cfg.zone.clone(),
                    name: zone_cfg.name.clone(),
                    return_ip: first.to_string(),
                    severity: zone_cfg.severity.clone(),
                    reason: zone_cfg.reason.clone(),
                }),
                None => ZoneAnswer::NotListed,
            }
        }
        Reading::Empty => ZoneAnswer::NotListed,
        Reading::Refusal => ZoneAnswer::Refused,
        Reading::Timeout => ZoneAnswer::Timeout,
        Reading::Failed | Reading::Unexpected => ZoneAnswer::Error,
    }
}

/// Queries all configured DNSBL zones in parallel through the OS resolver.
pub async fn check_all_dnsbl(ip: &str, dangerous_asns: &DangerousAsns) -> DnsblReport {
    check_all_dnsbl_with(Arc::new(SystemDns), ip, dangerous_asns).await
}

/// [`check_all_dnsbl`] through `dns` (injectable for tests).
pub async fn check_all_dnsbl_with(
    dns: Arc<dyn DnsLookup>,
    ip: &str,
    dangerous_asns: &DangerousAsns,
) -> DnsblReport {
    let total = dangerous_asns.dnsbl_zones.len();
    let reversed = match reverse_ipv4(ip) {
        Ok(rev) => rev,
        Err(_) => {
            return DnsblReport {
                total_checked: total,
                hits: Vec::new(),
                summary_label: format!("Не проверено: IP {ip} не IPv4"),
                failures: vec![UnknownReason::NoData; total],
                unsupported_ip: true,
            };
        }
    };

    let limit = Duration::from_millis(DNSBL_TIMEOUT_MS);
    let mut tasks = Vec::new();
    for zone in &dangerous_asns.dnsbl_zones {
        let (dns, reversed, zone) = (dns.clone(), reversed.clone(), zone.clone());
        tasks.push(tokio::spawn(async move {
            query_zone(&*dns, &reversed, &zone, limit).await
        }));
    }

    let mut hits = Vec::new();
    let mut failures = Vec::new();
    for task in tasks {
        match task.await {
            Ok(ZoneAnswer::Listed(hit)) => hits.push(hit),
            Ok(ZoneAnswer::NotListed) => {}
            Ok(ZoneAnswer::Refused) => failures.push(UnknownReason::SourceRefused),
            Ok(ZoneAnswer::Timeout) => failures.push(UnknownReason::Timeout),
            Ok(ZoneAnswer::Error) => failures.push(UnknownReason::NetworkError),
            // A zone task that died is an error of that zone, never a clean answer.
            Err(_) => failures.push(UnknownReason::InternalError),
        }
    }

    let hit_count = hits.len();
    let answered = total.saturating_sub(failures.len());
    let summary_label = if hit_count > 0 {
        format!("{hit_count}/{total} Listed")
    } else {
        format!("Ответили {answered} из {total} баз")
    };

    DnsblReport {
        total_checked: total,
        hits,
        summary_label,
        failures,
        unsupported_ip: false,
    }
}

/// Converts DNSBL Report to standard CheckResult.
pub fn evaluate_dnsbl_report(report: &DnsblReport) -> CheckResult {
    if let Some(reason) = report.unknown_reason() {
        if report.unsupported_ip {
            return CheckResult::unknown(
                "DNSBL_IPV6_UNSUPPORTED",
                "Проверка DNSBL не выполнена: выходной адрес не IPv4, а спам-базы проверяют только IPv4.",
                reason,
            );
        }
        return CheckResult::unknown(
            match reason {
                UnknownReason::SourceRefused => "DNSBL_RESOLVER_REFUSED",
                UnknownReason::Timeout => "DNSBL_TIMEOUT",
                _ => "DNSBL_NO_ANSWER",
            },
            format!(
                "Проверка DNSBL не выполнена: подтвердили ответ {} из {} спам-баз (нужно не меньше {}), отсутствие листинга не доказано.",
                report.answered(),
                report.total_checked,
                MIN_ANSWERING_ZONES.min(report.total_checked).max(1),
            ),
            reason,
        );
    }
    if report.hits.is_empty() {
        return CheckResult::ok(
            "DNSBL_CLEAN",
            format!(
                "Ответили {} из {} спам-баз DNSBL, ваш IP в них не числится.",
                report.answered(),
                report.total_checked
            ),
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

    let who = match (asn, [isp_str.trim(), org_str.trim()].into_iter().find(|t| !t.is_empty())) {
        (Some(n), Some(name)) => format!("AS{n} ({name})"),
        (Some(n), None) => format!("AS{n}"),
        (None, Some(name)) => name.to_string(),
        (None, None) => unreachable!("handled above: no ASN and no name is Unknown"),
    };
    CheckResult::ok(
        "ASN_CLEAN",
        format!(
            "{who} не найден среди {} известных сетей массовых VPN/хостинга и домашних провайдеров РФ из встроенного списка.",
            dangerous_asns.high_risk_asns.len() + dangerous_asns.russian_isp_keywords.len()
        ),
    )
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::geo_matrix::CheckStatus;
    use crate::auditor::seams::fakes::{FakeDns, addr};
    use std::sync::atomic::Ordering;

    const TEST_IP: &str = "203.0.113.9"; // TEST-NET-3, never a real address
    const REVERSED: &str = "9.113.0.203";

    fn zone(name: &str, severity: &str) -> DnsblZoneConfig {
        DnsblZoneConfig {
            zone: name.to_string(),
            name: name.to_uppercase(),
            severity: severity.to_string(),
            reason: "r".to_string(),
        }
    }

    /// The bundled rules with the zone list replaced by `z1.test` .. `zN.test`.
    fn asns_with_zones(n: usize, severity: &str) -> DangerousAsns {
        let mut asns = DangerousAsns::load_bundled().unwrap();
        asns.dnsbl_zones = (1..=n).map(|i| zone(&format!("z{i}.test"), severity)).collect();
        asns
    }

    /// A zone that works: the control address is listed, the IP is not.
    fn healthy(dns: FakeDns, z: &str) -> FakeDns {
        dns.with(&format!("2.0.0.127.{z}"), addr("127.0.0.2"))
            .with(&format!("{REVERSED}.{z}"), LookupOutcome::NotFound)
    }

    async fn run(dns: FakeDns, asns: &DangerousAsns) -> (DnsblReport, CheckResult) {
        let rep = check_all_dnsbl_with(Arc::new(dns), TEST_IP, asns).await;
        let res = evaluate_dnsbl_report(&rep);
        (rep, res)
    }

    #[test]
    fn test_dnsbl_reverse_ip_query_formatting() {
        assert_eq!(reverse_ipv4("185.220.101.1").unwrap(), "1.101.220.185");
        assert_eq!(
            format_dnsbl_query("185.220.101.1", "zen.spamhaus.org").unwrap(),
            "1.101.220.185.zen.spamhaus.org"
        );
        assert_eq!(reverse_ipv4("185.220.101.5").unwrap(), "5.101.220.185");
        assert!(reverse_ipv4("invalid.ip").is_err());
    }

    #[test]
    fn bundled_zone_list_has_no_dead_zones() {
        let asns = DangerousAsns::load_bundled().unwrap();
        let zones: Vec<&str> = asns.dnsbl_zones.iter().map(|z| z.zone.as_str()).collect();
        assert!(!zones.iter().any(|z| z.contains("sorbs")), "SORBS is shut down");
        assert!(zones.contains(&"zen.spamhaus.org"));
        assert!(asns.dnsbl_zones.len() >= MIN_ANSWERING_ZONES);
    }

    // (1) every zone times out
    #[tokio::test]
    async fn all_zones_timing_out_is_unknown_timeout() {
        let (rep, res) = run(FakeDns::new(LookupOutcome::Timeout), &asns_with_zones(4, "warning")).await;
        assert_eq!(rep.total_checked, 4);
        assert_eq!(res.status, CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::Timeout));
    }

    // (2) every zone answers 127.255.255.254: the resolver is turned away
    #[tokio::test]
    async fn all_zones_refusing_is_unknown_source_refused() {
        let (_, res) = run(
            FakeDns::new(addr("127.255.255.254")),
            &asns_with_zones(4, "warning"),
        )
        .await;
        assert_eq!(res.status, CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::SourceRefused));
        assert_eq!(res.code, "DNSBL_RESOLVER_REFUSED");
    }

    // (3) the threshold of two answering zones
    #[tokio::test]
    async fn two_answering_zones_are_enough_one_is_not() {
        let asns = asns_with_zones(4, "warning");
        let two = healthy(healthy(FakeDns::new(LookupOutcome::Timeout), "z1.test"), "z2.test");
        let (rep, res) = run(two, &asns).await;
        assert_eq!(res.status, CheckStatus::Ok);
        assert_eq!(res.code, "DNSBL_CLEAN");
        assert!(res.message.contains("Ответили 2 из 4"), "{}", res.message);
        assert_eq!(rep.summary_label, "Ответили 2 из 4 баз");

        let one = healthy(FakeDns::new(LookupOutcome::Timeout), "z1.test");
        let (_, res) = run(one, &asns).await;
        assert_eq!(res.status, CheckStatus::Unknown);
    }

    #[tokio::test]
    async fn the_denominator_is_the_real_number_of_zones() {
        let asns = asns_with_zones(3, "warning");
        let all = ["z1.test", "z2.test", "z3.test"]
            .iter()
            .fold(FakeDns::new(LookupOutcome::Timeout), |d, z| healthy(d, z));
        let (_, res) = run(all, &asns).await;
        assert!(res.message.contains("Ответили 3 из 3"), "{}", res.message);
    }

    // (4) a listing wins over zones that did not answer
    #[tokio::test]
    async fn a_listing_wins_over_timeouts() {
        let dns = FakeDns::new(LookupOutcome::Timeout)
            .with("2.0.0.127.z1.test", addr("127.0.0.2"))
            .with(&format!("{REVERSED}.z1.test"), addr("127.0.0.2"));
        let (_, res) = run(dns, &asns_with_zones(4, "warning")).await;
        assert_eq!(res.status, CheckStatus::Warning);
        let dns = FakeDns::new(LookupOutcome::Timeout)
            .with("2.0.0.127.z1.test", addr("127.0.0.2"))
            .with(&format!("{REVERSED}.z1.test"), addr("127.0.0.4"));
        let (_, res) = run(dns, &asns_with_zones(4, "critical")).await;
        assert_eq!(res.status, CheckStatus::Critical);
    }

    // (5) a zone whose control query does not come back listed is not counted
    #[tokio::test]
    async fn control_query_without_listing_discards_the_zone() {
        let cfg = zone("z1.test", "warning");
        // Dead zone / zone that turns the resolver away: NXDOMAIN for the control address.
        let dead = FakeDns::new(LookupOutcome::NotFound);
        assert_eq!(
            query_zone(&dead, REVERSED, &cfg, Duration::from_millis(10)).await,
            ZoneAnswer::Refused
        );
        // A fake-IP DNS interceptor answers everything with an address outside 127.0.0.0/8.
        let fake_ip = FakeDns::new(addr("198.18.0.7"));
        assert_eq!(
            query_zone(&fake_ip, REVERSED, &cfg, Duration::from_millis(10)).await,
            ZoneAnswer::Error
        );
        // Two such zones plus one healthy one: only one zone vouches, not enough.
        let asns = asns_with_zones(3, "warning");
        let dns = healthy(FakeDns::new(LookupOutcome::NotFound), "z3.test");
        let (rep, res) = run(dns, &asns).await;
        assert_eq!(rep.answered(), 1);
        assert_eq!(res.status, CheckStatus::Unknown);
        // The same fake-IP answers on every zone: never "clean".
        let (_, res) = run(FakeDns::new(addr("198.18.0.7")), &asns).await;
        assert_eq!(res.status, CheckStatus::Unknown);
    }

    // (6) an IPv6 exit address
    #[tokio::test]
    async fn ipv6_exit_ip_is_unknown_and_not_queried() {
        let asns = asns_with_zones(4, "warning");
        let dns = Arc::new(FakeDns::new(LookupOutcome::NotFound));
        let rep = check_all_dnsbl_with(dns.clone(), "2606:4700::1111", &asns).await;
        let res = evaluate_dnsbl_report(&rep);
        assert_eq!(res.status, CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::NoData));
        assert_eq!(res.code, "DNSBL_IPV6_UNSUPPORTED");
        assert_eq!(dns.calls.load(Ordering::SeqCst), 0);
    }

    // (7) a zone task that panics is an error of that zone, never "clean"
    #[tokio::test]
    async fn a_panicking_zone_task_is_counted_as_an_error() {
        let asns = asns_with_zones(4, "warning");
        let all_ok = ["z1.test", "z2.test", "z3.test", "z4.test"]
            .iter()
            .fold(FakeDns::new(LookupOutcome::Timeout), |d, z| healthy(d, z));
        let (rep, res) = run(all_ok.panicking_on("z1.test"), &asns).await;
        assert_eq!(rep.failures, vec![UnknownReason::InternalError]);
        assert_eq!(rep.answered(), 3);
        assert!(res.message.contains("Ответили 3 из 4"), "{}", res.message);

        let (rep, res) = run(
            FakeDns::new(LookupOutcome::Timeout).panicking_on(".test"),
            &asns,
        )
        .await;
        assert_eq!(rep.failures, vec![UnknownReason::InternalError; 4]);
        assert_eq!(res.status, CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::InternalError));
    }

    // (8) Spamhaus PBL is not a listing (default decision), SBL/XBL are
    #[tokio::test]
    async fn spamhaus_pbl_answers_are_not_a_listing() {
        let cfg = zone("zen.spamhaus.org", "critical");
        let base = |ans: LookupOutcome| {
            FakeDns::new(LookupOutcome::NotFound)
                .with("2.0.0.127.zen.spamhaus.org", addr("127.0.0.2"))
                .with(&format!("{REVERSED}.zen.spamhaus.org"), ans)
        };
        let lim = Duration::from_millis(10);
        for pbl in ["127.0.0.10", "127.0.0.11"] {
            assert_eq!(
                query_zone(&base(addr(pbl)), REVERSED, &cfg, lim).await,
                ZoneAnswer::NotListed,
                "{pbl}"
            );
        }
        for listed in ["127.0.0.2", "127.0.0.3", "127.0.0.4"] {
            assert!(matches!(
                query_zone(&base(addr(listed)), REVERSED, &cfg, lim).await,
                ZoneAnswer::Listed(_)
            ));
        }
        // PBL together with SBL is still a listing.
        let both = LookupOutcome::Addrs(vec!["127.0.0.10".parse().unwrap(), "127.0.0.2".parse().unwrap()]);
        match query_zone(&base(both), REVERSED, &cfg, lim).await {
            ZoneAnswer::Listed(hit) => assert_eq!(hit.return_ip, "127.0.0.2"),
            other => panic!("{other:?}"),
        }
        // The exclusion belongs to Spamhaus only: 127.0.0.10 of another zone is a listing.
        let other = zone("z1.test", "warning");
        let dns = FakeDns::new(LookupOutcome::NotFound)
            .with("2.0.0.127.z1.test", addr("127.0.0.2"))
            .with(&format!("{REVERSED}.z1.test"), addr("127.0.0.10"));
        assert!(matches!(
            query_zone(&dns, REVERSED, &other, lim).await,
            ZoneAnswer::Listed(_)
        ));
    }

    #[tokio::test]
    async fn a_resolver_error_on_the_ip_query_is_not_a_clean_answer() {
        let cfg = zone("z1.test", "warning");
        let dns = FakeDns::new(LookupOutcome::Failed).with("2.0.0.127.z1.test", addr("127.0.0.2"));
        assert_eq!(
            query_zone(&dns, REVERSED, &cfg, Duration::from_millis(10)).await,
            ZoneAnswer::Error
        );
        let dns = FakeDns::new(LookupOutcome::Timeout).with("2.0.0.127.z1.test", addr("127.0.0.2"));
        assert_eq!(
            query_zone(&dns, REVERSED, &cfg, Duration::from_millis(10)).await,
            ZoneAnswer::Timeout
        );
    }

    fn report(total: usize, failures: Vec<UnknownReason>) -> DnsblReport {
        DnsblReport {
            total_checked: total,
            hits: Vec::new(),
            summary_label: String::new(),
            failures,
            unsupported_ip: false,
        }
    }

    #[test]
    fn report_classification() {
        use UnknownReason::*;
        assert_eq!(evaluate_dnsbl_report(&report(4, vec![])).status, CheckStatus::Ok);
        assert_eq!(evaluate_dnsbl_report(&report(4, vec![Timeout; 2])).status, CheckStatus::Ok);
        assert_eq!(evaluate_dnsbl_report(&report(4, vec![Timeout; 3])).status, CheckStatus::Unknown);
        assert_eq!(evaluate_dnsbl_report(&report(0, vec![])).status, CheckStatus::Unknown);
        let mixed = evaluate_dnsbl_report(&report(4, vec![Timeout, SourceRefused, NetworkError, SourceRefused]));
        assert_eq!(mixed.reason, Some(Timeout));
        let hit = DnsblZoneHit {
            zone: "z".into(),
            name: "Spamhaus ZEN".into(),
            return_ip: "127.0.0.2".into(),
            severity: "critical".into(),
            reason: "r".into(),
        };
        let mut listed = report(4, vec![Timeout; 3]);
        listed.hits.push(hit);
        let r = evaluate_dnsbl_report(&listed);
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Critical, "DNSBL_LISTED_CRITICAL"));
        assert!(r.message.contains("Spamhaus ZEN"));
    }

    #[test]
    fn test_asn_matching_and_pinning_bypass() {
        let asns = DangerousAsns::load_bundled().unwrap();

        let res_unpinned = evaluate_asn_reputation(Some(9009), Some("M247"), None, &asns, false);
        assert_eq!(res_unpinned.status, CheckStatus::Warning);
        assert_eq!(res_unpinned.code, "HIGH_RISK_MASS_VPN_ASN");

        let res_pinned = evaluate_asn_reputation(Some(9009), Some("M247"), None, &asns, true);
        assert_eq!(res_pinned.status, CheckStatus::Ok);
        assert_eq!(res_pinned.code, "ASN_VERIFIED_PINNED");

        let res_ru = evaluate_asn_reputation(Some(12389), Some("PJSC Rostelecom"), None, &asns, false);
        assert_eq!(res_ru.status, CheckStatus::Critical);
        assert_eq!(res_ru.code, "RUSSIAN_ISP_DETECTED");
    }

    #[test]
    fn test_asn_without_any_data_is_unknown() {
        let asns = DangerousAsns::load_bundled().unwrap();
        let res = evaluate_asn_reputation(None, None, None, &asns, false);
        assert_eq!(res.status, CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::NoData));
        // Blank strings are no data either.
        let res = evaluate_asn_reputation(None, Some("  "), Some(""), &asns, false);
        assert_eq!(res.status, CheckStatus::Unknown);
        // A known (clean) ASN is still a verdict, and the text names what was compared.
        let res = evaluate_asn_reputation(Some(64500), Some("Example Net"), None, &asns, false);
        assert_eq!(res.status, CheckStatus::Ok);
        assert!(res.message.contains("AS64500"), "{}", res.message);
    }
}
