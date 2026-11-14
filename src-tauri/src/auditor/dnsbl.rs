use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::auditor::geo_matrix::{CheckResult, GUIDE_PERSONAL_VPN, UnknownReason};
use crate::auditor::rules::{DangerousAsns, DnsblZoneConfig};
use crate::auditor::seams::{
    BoxFuture, DnsLookup, HttpProbeOutcome, IpProbe, LookupOutcome, SystemDns,
};

/// Time limit of one lookup (the zone's real query and its control query run side by side).
pub const DNSBL_TIMEOUT_MS: u64 = 1500;

/// Time limit of one DNS-over-HTTPS fallback lookup (`https://dns.google/resolve`).
pub const DNSBL_DOH_TIMEOUT_MS: u64 = 2000;
const DOH_RESOLVE_URL: &str = "https://dns.google/resolve";

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
            // The zones list IPv4 only: for an IPv6 exit the check does not apply.
            return Some(UnknownReason::NotApplicable);
        }
        if self.total_checked > 0 && self.answered() >= MIN_ANSWERING_ZONES.min(self.total_checked)
        {
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

    Ok(format!(
        "{}.{}.{}.{}",
        parts[3], parts[2], parts[1], parts[0]
    ))
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
    zone.trim_matches('.')
        .eq_ignore_ascii_case(SPAMHAUS_ZEN_ZONE)
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

/// Parses a Google Public DNS JSON response (`https://dns.google/resolve?name=...&type=A`)
/// into [`LookupOutcome`].
pub fn parse_doh_json_a_response(body: &str) -> LookupOutcome {
    #[derive(serde::Deserialize)]
    struct DohAnswer {
        #[serde(default)]
        r#type: u16,
        #[serde(default)]
        data: String,
    }
    #[derive(serde::Deserialize)]
    struct DohResponse {
        #[serde(rename = "Status")]
        status: i32,
        #[serde(rename = "Answer", default)]
        answer: Vec<DohAnswer>,
    }

    let Ok(parsed) = serde_json::from_str::<DohResponse>(body) else {
        return LookupOutcome::Failed;
    };
    match parsed.status {
        0 => {
            let addrs: Vec<IpAddr> = parsed
                .answer
                .into_iter()
                .filter(|a| a.r#type == 1)
                .filter_map(|a| a.data.trim().parse::<Ipv4Addr>().ok())
                .map(IpAddr::V4)
                .collect();
            if addrs.is_empty() {
                LookupOutcome::NotFound
            } else {
                LookupOutcome::Addrs(addrs)
            }
        }
        3 => LookupOutcome::NotFound,
        _ => LookupOutcome::Failed,
    }
}

/// DNS-over-HTTPS fallback resolver (`https://dns.google/resolve`) bypassing local FakeDNS
/// interception (`198.18.x.x`) and open-resolver Spamhaus refusals (`127.255.255.x`).
pub enum DohDns {
    Reqwest(reqwest::Client),
    Probe(Arc<dyn IpProbe>),
}

impl DohDns {
    /// Creates a shared `.no_proxy()` client for `https://dns.google/resolve`.
    pub fn real() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().no_proxy().build()?;
        Ok(Self::Reqwest(client))
    }

    /// Creates a DoH resolver backed by an [`IpProbe`] (for deterministic offline tests).
    pub fn with_probe(probe: Arc<dyn IpProbe>) -> Self {
        Self::Probe(probe)
    }
}

impl DnsLookup for DohDns {
    fn lookup<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, LookupOutcome> {
        Box::pin(async move {
            match self {
                Self::Reqwest(client) => {
                    let req = client
                        .get(DOH_RESOLVE_URL)
                        .query(&[("name", host), ("type", "A")])
                        .header(reqwest::header::ACCEPT, "application/dns-json")
                        .timeout(limit);
                    let resp = match req.send().await {
                        Ok(r) => r,
                        Err(e) if e.is_timeout() => return LookupOutcome::Timeout,
                        Err(_) => return LookupOutcome::Failed,
                    };
                    if !resp.status().is_success() {
                        return LookupOutcome::Failed;
                    }
                    match resp.text().await {
                        Ok(body) => parse_doh_json_a_response(&body),
                        Err(_) => LookupOutcome::Failed,
                    }
                }
                Self::Probe(probe) => {
                    let url = format!("{DOH_RESOLVE_URL}?name={host}&type=A");
                    match probe.get(&url, limit).await {
                        HttpProbeOutcome::Response { status, body }
                            if (200..300).contains(&status) =>
                        {
                            parse_doh_json_a_response(&body)
                        }
                        HttpProbeOutcome::Timeout => LookupOutcome::Timeout,
                        _ => LookupOutcome::Failed,
                    }
                }
            }
        })
    }
}

async fn run_zone_queries(
    dns: &Arc<dyn DnsLookup>,
    reversed: &str,
    zones: &[(usize, DnsblZoneConfig)],
    limit: Duration,
) -> Vec<(usize, Option<ZoneAnswer>)> {
    let mut tasks = Vec::with_capacity(zones.len());
    for (idx, zone) in zones {
        let idx = *idx;
        let (dns, reversed, zone) = (dns.clone(), reversed.to_string(), zone.clone());
        tasks.push(tokio::spawn(async move {
            let answer = query_zone(&*dns, &reversed, &zone, limit).await;
            (idx, answer)
        }));
    }

    let mut out = Vec::with_capacity(tasks.len());
    for (pos, task) in tasks.into_iter().enumerate() {
        let idx = zones[pos].0;
        match task.await {
            Ok((i, ans)) => out.push((i, Some(ans))),
            // A panicked zone task counts as an internal error rather than a silent clean answer.
            Err(_) => out.push((idx, None)),
        }
    }
    out
}

fn is_decisive_answer(ans: Option<&ZoneAnswer>) -> bool {
    matches!(ans, Some(ZoneAnswer::Listed(_) | ZoneAnswer::NotListed))
}

/// Queries all configured DNSBL zones in parallel through the OS resolver, falling back to
/// DNS-over-HTTPS (`https://dns.google/resolve`) when `< MIN_ANSWERING_ZONES` zones respond.
pub async fn check_all_dnsbl(ip: &str, dangerous_asns: &DangerousAsns) -> DnsblReport {
    let doh = DohDns::real()
        .ok()
        .map(|d| Arc::new(d) as Arc<dyn DnsLookup>);
    check_all_dnsbl_with_doh(Arc::new(SystemDns), doh, ip, dangerous_asns).await
}

/// [`check_all_dnsbl`] through `dns` without network DoH fallback (for offline unit tests).
pub async fn check_all_dnsbl_with(
    dns: Arc<dyn DnsLookup>,
    ip: &str,
    dangerous_asns: &DangerousAsns,
) -> DnsblReport {
    check_all_dnsbl_with_doh(dns, None, ip, dangerous_asns).await
}

/// [`check_all_dnsbl`] through primary `dns` and optional DoH fallback `doh` when primary yields
/// fewer than [`MIN_ANSWERING_ZONES`] decisive zone answers (FakeDNS / `127.255.255.x` refusals).
pub async fn check_all_dnsbl_with_doh(
    dns: Arc<dyn DnsLookup>,
    doh: Option<Arc<dyn DnsLookup>>,
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
                summary_label: "Не применимо к IPv6".to_string(),
                failures: vec![UnknownReason::NoData; total],
                unsupported_ip: true,
            };
        }
    };

    let indexed_zones: Vec<(usize, DnsblZoneConfig)> = dangerous_asns
        .dnsbl_zones
        .iter()
        .cloned()
        .enumerate()
        .collect();
    let mut answers: Vec<Option<ZoneAnswer>> = vec![None; total];
    for (idx, ans) in run_zone_queries(
        &dns,
        &reversed,
        &indexed_zones,
        Duration::from_millis(DNSBL_TIMEOUT_MS),
    )
    .await
    {
        answers[idx] = ans;
    }

    let primary_answered = answers
        .iter()
        .filter(|a| is_decisive_answer(a.as_ref()))
        .count();
    if primary_answered < MIN_ANSWERING_ZONES.min(total)
        && let Some(doh_dns) = doh
    {
        let retry_zones: Vec<(usize, DnsblZoneConfig)> = indexed_zones
            .into_iter()
            .filter(|(idx, _)| !is_decisive_answer(answers[*idx].as_ref()))
            .collect();
        if !retry_zones.is_empty() {
            for (idx, fallback_ans) in run_zone_queries(
                &doh_dns,
                &reversed,
                &retry_zones,
                Duration::from_millis(DNSBL_DOH_TIMEOUT_MS),
            )
            .await
            {
                if is_decisive_answer(fallback_ans.as_ref()) {
                    answers[idx] = fallback_ans;
                }
            }
        }
    }

    let mut hits = Vec::new();
    let mut failures = Vec::new();
    for ans in answers {
        match ans {
            Some(ZoneAnswer::Listed(hit)) => hits.push(hit),
            Some(ZoneAnswer::NotListed) => {}
            Some(ZoneAnswer::Refused) => failures.push(UnknownReason::SourceRefused),
            Some(ZoneAnswer::Timeout) => failures.push(UnknownReason::Timeout),
            Some(ZoneAnswer::Error) => failures.push(UnknownReason::NetworkError),
            None => failures.push(UnknownReason::InternalError),
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
                "Не применимо к IPv6: спам-базы DNSBL проверяют только адреса IPv4, а ваш выходной адрес IPv6. Это не значит, что адрес плохой.",
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
        CheckResult::critical(
            "DNSBL_LISTED_CRITICAL",
            msg,
            Some(GUIDE_PERSONAL_VPN.to_string()),
        )
    } else {
        CheckResult::warning(
            "DNSBL_LISTED_WARNING",
            msg,
            Some(GUIDE_PERSONAL_VPN.to_string()),
        )
    }
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
        asns.dnsbl_zones = (1..=n)
            .map(|i| zone(&format!("z{i}.test"), severity))
            .collect();
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
        assert!(
            !zones.iter().any(|z| z.contains("sorbs")),
            "SORBS is shut down"
        );
        assert!(zones.contains(&"zen.spamhaus.org"));
        assert!(asns.dnsbl_zones.len() >= MIN_ANSWERING_ZONES);
    }

    // (1) every zone times out
    #[tokio::test]
    async fn all_zones_timing_out_is_unknown_timeout() {
        let (rep, res) = run(
            FakeDns::new(LookupOutcome::Timeout),
            &asns_with_zones(4, "warning"),
        )
        .await;
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
        let two = healthy(
            healthy(FakeDns::new(LookupOutcome::Timeout), "z1.test"),
            "z2.test",
        );
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
        assert_eq!(res.reason, Some(UnknownReason::NotApplicable));
        assert!(res.is_not_applicable());
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
        let both = LookupOutcome::Addrs(vec![
            "127.0.0.10".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
        ]);
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
        assert_eq!(
            evaluate_dnsbl_report(&report(4, vec![])).status,
            CheckStatus::Ok
        );
        assert_eq!(
            evaluate_dnsbl_report(&report(4, vec![Timeout; 2])).status,
            CheckStatus::Ok
        );
        assert_eq!(
            evaluate_dnsbl_report(&report(4, vec![Timeout; 3])).status,
            CheckStatus::Unknown
        );
        assert_eq!(
            evaluate_dnsbl_report(&report(0, vec![])).status,
            CheckStatus::Unknown
        );
        let mixed = evaluate_dnsbl_report(&report(
            4,
            vec![Timeout, SourceRefused, NetworkError, SourceRefused],
        ));
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
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Critical, "DNSBL_LISTED_CRITICAL")
        );
        assert!(r.message.contains("Spamhaus ZEN"));
    }

    #[test]
    fn parse_doh_json_a_response_handles_listed_nxdomain_empty_and_refused() {
        let listed = r#"{"Status":0,"Answer":[{"name":"2.0.0.127.z1.test.","type":1,"TTL":300,"data":"127.0.0.2"}]}"#;
        assert_eq!(
            parse_doh_json_a_response(listed),
            LookupOutcome::Addrs(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))])
        );

        let nx = r#"{"Status":3,"Question":[{"name":"5.101.220.185.z1.test.","type":1}]}"#;
        assert_eq!(parse_doh_json_a_response(nx), LookupOutcome::NotFound);

        let empty_ok = r#"{"Status":0,"Answer":[]}"#;
        assert_eq!(parse_doh_json_a_response(empty_ok), LookupOutcome::NotFound);

        let servfail = r#"{"Status":2}"#;
        assert_eq!(parse_doh_json_a_response(servfail), LookupOutcome::Failed);
    }

    #[tokio::test]
    async fn fake_dns_and_open_resolver_refusal_fall_back_to_doh_json() {
        use crate::auditor::seams::fakes::FakeProbe;

        let zones = vec![
            zone("zen.spamhaus.org", "critical"),
            zone("dnsbl.dronebl.org", "critical"),
            zone("b.barracudacentral.org", "warning"),
        ];
        let rules = DangerousAsns {
            dnsbl_zones: zones,
            ..DangerousAsns::load_bundled().unwrap()
        };

        // Simulate V2Box FakeDNS returning 198.18.0.x for all zones plus 1.1.1.1-style
        // 127.255.255.254 refusal on Spamhaus; DoH rescues DroneBL and Barracuda (>= 2 zones).
        let primary = Arc::new(
            FakeDns::new(LookupOutcome::Addrs(vec![IpAddr::V4(Ipv4Addr::new(
                198, 18, 0, 44,
            ))]))
            .with("2.0.0.127.zen.spamhaus.org", addr("127.255.255.254"))
            .with("42.114.244.136.zen.spamhaus.org", addr("127.255.255.254")),
        );

        let doh_probe = Arc::new(
            FakeProbe::body(200, r#"{"Status":3}"#)
                .with_route(
                    "name=2.0.0.127.zen.spamhaus.org",
                    HttpProbeOutcome::Response {
                        status: 200,
                        body: r#"{"Status":0,"Answer":[{"type":1,"data":"127.255.255.254"}]}"#
                            .into(),
                    },
                )
                .with_route(
                    "name=2.0.0.127.dnsbl.dronebl.org",
                    HttpProbeOutcome::Response {
                        status: 200,
                        body: r#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.2"}]}"#.into(),
                    },
                )
                .with_route(
                    "name=2.0.0.127.b.barracudacentral.org",
                    HttpProbeOutcome::Response {
                        status: 200,
                        body: r#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.2"}]}"#.into(),
                    },
                ),
        );
        let doh = Arc::new(DohDns::with_probe(doh_probe)) as Arc<dyn DnsLookup>;

        let report = check_all_dnsbl_with_doh(primary, Some(doh), "136.244.114.42", &rules).await;
        assert_eq!(report.answered(), 2);
        assert!(report.hits.is_empty());
        let res = evaluate_dnsbl_report(&report);
        assert_eq!(
            (res.status, res.code.as_str()),
            (CheckStatus::Ok, "DNSBL_CLEAN")
        );
    }
}
