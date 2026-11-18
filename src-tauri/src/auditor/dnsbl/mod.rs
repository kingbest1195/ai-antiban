//! DNSBL spam/botnet list checks with control-address verification and DoH fallback.

mod doh;

#[cfg(test)]
mod tests;

pub use doh::{DNSBL_DOH_TIMEOUT_MS, DohDns, parse_doh_json_a_response};

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
