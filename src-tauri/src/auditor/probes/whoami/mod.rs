//! Which DNS resolver really sees the requests of this machine.
//!
//! Two public "whoami" names answer with the address of the resolver that asked them (not of the
//! client): `whoami.akamai.net` (record A) and `o-o.myaddr.l.google.com` (record TXT). The two
//! answers must agree; the resolver address is then located (country) through public geo
//! services. Whatever cannot be confirmed is `Unknown`, never "all fine".

mod geo;
mod verdict;

use std::net::IpAddr;
use std::time::Duration;

#[cfg(test)]
use crate::auditor::cache::TtlCache;
#[cfg(test)]
use crate::auditor::geo_matrix::CheckResult;
use crate::auditor::geo_matrix::{SourceState, SourceView, UnknownReason};
use crate::auditor::probes::public_dns::operator_of;
#[cfg(test)]
use crate::auditor::seams::HttpProbeOutcome;
use crate::auditor::seams::{LookupOutcome, TxtOutcome};
#[cfg(test)]
use geo::{parse_freeipapi, parse_ipinfo, parse_ipwhois};

pub use crate::core::net_safety::is_special_addr;
pub use geo::{
    GeoInfo, PUBLIC_DNS_SERVICES, PublicDns, geo_of_ip, measure_resolver, public_dns_service,
};
pub use verdict::{
    evaluate_dns_country, evaluate_dns_country_for_route, normalized_country, same_operator_note,
};

pub const AKAMAI_HOST: &str = "whoami.akamai.net";
pub const GOOGLE_TXT_HOST: &str = "o-o.myaddr.l.google.com";
/// `CheckResult::measured_via` of the checks that rest on both whoami sources.
pub const MEASURED_VIA: &str = "whoami:akamai+google";

/// Time limit of each whoami lookup (both A-record and TXT run in parallel).
/// Together with `GEO_TOTAL_LIMIT` (1400 ms) stays under `CHECK_LIMIT_IO` (4000 ms).
pub const WHOAMI_LIMIT: Duration = Duration::from_millis(2500);

/// What one whoami source gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceReading {
    /// An address that can belong to a real resolver.
    Addr(IpAddr),
    /// A private, loopback, link-local, CGNAT or benchmark (fake-IP) address.
    Special(IpAddr),
    /// An answer without a usable address (no such name, no records, unparsable text).
    Empty,
    Timeout,
    Failed,
    Unsupported,
}

impl SourceReading {
    fn describe(&self) -> &'static str {
        match self {
            Self::Addr(_) => "ответил",
            Self::Special(_) => "вернул служебный адрес",
            Self::Empty => "вернул пустой ответ",
            Self::Timeout => "не ответил вовремя",
            Self::Failed => "недоступен",
            Self::Unsupported => "не поддерживается на этой системе",
        }
    }

    fn state(&self) -> SourceState {
        match self {
            Self::Addr(_) => SourceState::Answered,
            Self::Special(_) => SourceState::Special,
            Self::Empty => SourceState::Empty,
            Self::Timeout => SourceState::Timeout,
            Self::Failed => SourceState::Failed,
            Self::Unsupported => SourceState::Unsupported,
        }
    }

    /// What this source showed, for the structured detail of a result.
    fn view(&self, source: &str) -> SourceView {
        let ip = match self {
            Self::Addr(ip) | Self::Special(ip) => Some(*ip),
            _ => None,
        };
        SourceView {
            source: source.to_string(),
            state: self.state(),
            addr: ip.map(|ip| ip.to_string()),
            operator: match self {
                Self::Addr(ip) => operator_of(*ip).map(str::to_string),
                _ => None,
            },
            country: None,
        }
    }
}

/// What both whoami sources showed (Akamai first).
pub fn source_views(akamai: &SourceReading, google: &SourceReading) -> Vec<SourceView> {
    vec![akamai.view("Akamai"), google.view("Google")]
}

/// Whether an IP address belongs to RFC 2544 (`198.18.0.0/15`), used by TUN/FakeDNS proxies.
pub fn is_tun_fake_ip(ip: IpAddr) -> bool {
    crate::core::net_safety::is_tun_fake_ip(&ip)
}

/// True when all recorded whoami sources returned `SourceState::Special` in `198.18.0.0/15`.
pub fn all_sources_tun_fake_ip(sources: &[SourceView]) -> bool {
    !sources.is_empty()
        && sources.iter().all(|s| {
            s.state == SourceState::Special
                && s.addr
                    .as_deref()
                    .and_then(|raw| raw.parse::<IpAddr>().ok())
                    .is_some_and(is_tun_fake_ip)
        })
}

fn classify(ip: IpAddr) -> SourceReading {
    if is_special_addr(&ip) {
        SourceReading::Special(ip)
    } else {
        SourceReading::Addr(ip)
    }
}

/// `whoami.akamai.net` (A): the first IPv4 address of the answer (or the first one).
pub fn akamai_reading(outcome: &LookupOutcome) -> SourceReading {
    match outcome {
        LookupOutcome::Addrs(addrs) => addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .map_or(SourceReading::Empty, |ip| classify(*ip)),
        LookupOutcome::NotFound => SourceReading::Empty,
        LookupOutcome::Timeout => SourceReading::Timeout,
        LookupOutcome::Failed => SourceReading::Failed,
    }
}

/// `o-o.myaddr.l.google.com` (TXT): the answer is a quoted address; Google adds records such as
/// `edns0-client-subnet 203.0.113.0/24` that are not the resolver and are skipped.
pub fn google_reading(outcome: &TxtOutcome) -> SourceReading {
    match outcome {
        TxtOutcome::Records(records) => records
            .iter()
            .find_map(|r| r.trim().trim_matches('"').trim().parse::<IpAddr>().ok())
            .map_or(SourceReading::Empty, classify),
        TxtOutcome::NotFound => SourceReading::Empty,
        TxtOutcome::Timeout => SourceReading::Timeout,
        TxtOutcome::Failed => SourceReading::Failed,
        TxtOutcome::Unsupported => SourceReading::Unsupported,
    }
}

/// Why the resolver could not be determined (becomes an `Unknown` check result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmeasured {
    pub code: &'static str,
    pub reason: UnknownReason,
    /// Clause that completes "... не выполнена: {detail}".
    pub detail: String,
    /// What each source showed.
    pub sources: Vec<SourceView>,
}

/// The resolver that sees the DNS requests of this machine, located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverView {
    Located {
        ip: IpAddr,
        /// Empty when the operator was known by its address range and no geo request was made
        /// (the country of an anycast service is not compared anyway).
        country: String,
        /// Name of the public DNS service whose egress address this is (see
        /// [`PUBLIC_DNS_SERVICES`]); its country says nothing about where the user is.
        public_service: Option<&'static str>,
        /// What each source showed.
        sources: Vec<SourceView>,
    },
    Unmeasured(Unmeasured),
}

impl ResolverView {
    pub fn is_located(&self) -> bool {
        matches!(self, Self::Located { .. })
    }
}

/// Two addresses of one resolver fleet: the same address, or the same IPv4 /24 / IPv6 /48
/// (a public resolver answers different queries from different addresses of its pool).
fn same_resolver_network(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..3] == b.octets()[..3],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.octets()[..6] == b.octets()[..6],
        _ => false,
    }
}

/// The resolver both sources agree on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agreed {
    pub ip: IpAddr,
    /// Set when both addresses belong to the same well-known public DNS service.
    pub operator: Option<&'static str>,
}

/// The resolver both sources agree on, or the reason it is not known. Two different addresses
/// agree when they are one resolver network (same /24 or /48) or belong to one public DNS
/// operator (anycast egress addresses of a fleet differ between queries).
pub fn combine_sources(
    akamai: &SourceReading,
    google: &SourceReading,
) -> Result<Agreed, Unmeasured> {
    use SourceReading::*;
    let sources = source_views(akamai, google);

    // If one source returns a TUN Fake-IP / local stub and the other source returns a valid
    // public resolver IP (e.g. V2Box FakeDNS intercepts A records while TXT passes through to
    // Cloudflare), prefer the valid public resolver rather than failing with DNS_WHOAMI_FAKE_IP.
    match (akamai, google) {
        (Special(_), Addr(pub_ip)) | (Addr(pub_ip), Special(_)) => {
            return Ok(Agreed {
                ip: *pub_ip,
                operator: operator_of(*pub_ip),
            });
        }
        (Special(ip), _) | (_, Special(ip)) => {
            return Err(Unmeasured {
                code: "DNS_WHOAMI_FAKE_IP",
                reason: UnknownReason::SourceRefused,
                detail: format!(
                    "DNS ответил служебным адресом {ip} (так выглядит fake-IP режим TUN-клиента или локальный DNS-перехватчик), реальный резолвер не виден"
                ),
                sources,
            });
        }
        _ => {}
    }

    match (akamai, google) {
        (Addr(a), Addr(g)) => {
            let (op_a, op_g) = (operator_of(*a), operator_of(*g));
            let operator = op_a.filter(|op| Some(*op) == op_g);
            if operator.is_some() || same_resolver_network(*a, *g) {
                return Ok(Agreed { ip: *a, operator });
            }
            let named = |ip: &IpAddr, op: Option<&str>| match op {
                Some(op) => format!("{ip}, {op}"),
                None => ip.to_string(),
            };
            Err(Unmeasured {
                code: "DNS_WHOAMI_DISAGREE",
                reason: UnknownReason::NoData,
                detail: format!(
                    "два независимых источника показали разные резолверы (Akamai: {}, Google: {}) и общего публичного DNS-сервиса у них нет, надёжно определить его нельзя",
                    named(a, op_a),
                    named(g, op_g)
                ),
                sources,
            })
        }
        (Addr(_), other) => Err(single_source("Akamai", "Google", other, sources)),
        (other, Addr(_)) => Err(single_source("Google", "Akamai", other, sources)),
        _ => {
            let both = [akamai, google];
            let (code, reason, why) = if both.iter().any(|r| **r == Timeout) {
                (
                    "DNS_WHOAMI_TIMEOUT",
                    UnknownReason::Timeout,
                    "ни один из источников не ответил вовремя",
                )
            } else if both.iter().any(|r| **r == Failed) {
                (
                    "DNS_WHOAMI_UNREACHABLE",
                    UnknownReason::NetworkError,
                    "источники недоступны (DNS не отвечает)",
                )
            } else if both.iter().any(|r| **r == Unsupported) {
                (
                    "DNS_WHOAMI_UNSUPPORTED",
                    UnknownReason::UnsupportedOs,
                    "на этой системе нечем запросить источники",
                )
            } else {
                (
                    "DNS_WHOAMI_EMPTY",
                    UnknownReason::EmptyResponse,
                    "источники вернули пустой ответ",
                )
            };
            Err(Unmeasured {
                code,
                reason,
                detail: format!("{why} (Akamai и Google)"),
                sources,
            })
        }
    }
}

fn single_source(
    answered: &str,
    silent: &str,
    other: &SourceReading,
    sources: Vec<SourceView>,
) -> Unmeasured {
    Unmeasured {
        code: "DNS_WHOAMI_SINGLE_SOURCE",
        reason: UnknownReason::NoData,
        detail: format!(
            "ответил только один источник ({answered}), {silent} {}: подтверждения нет",
            other.describe()
        ),
        sources,
    }
}

#[cfg(test)]
#[path = "../whoami_tests.rs"]
mod tests;
