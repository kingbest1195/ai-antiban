//! Which DNS resolver really sees the requests of this machine.
//!
//! Two public "whoami" names answer with the address of the resolver that asked them (not of the
//! client): `whoami.akamai.net` (record A) and `o-o.myaddr.l.google.com` (record TXT). The two
//! answers must agree; the resolver address is then located (country) through public geo
//! services. Whatever cannot be confirmed is `Unknown`, never "all fine".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::auditor::cache::{GEO_TTL, TtlCache};
use crate::auditor::geo_matrix::{
    CheckResult, GUIDE_OS_PRIVACY, SourceState, SourceView, UnknownReason,
};
use crate::auditor::probes::public_dns::operator_of;
use crate::auditor::seams::{DnsLookup, HttpProbeOutcome, IpProbe, LookupOutcome, TxtOutcome};

pub const AKAMAI_HOST: &str = "whoami.akamai.net";
pub const GOOGLE_TXT_HOST: &str = "o-o.myaddr.l.google.com";
/// `CheckResult::measured_via` of the checks that rest on both whoami sources.
pub const MEASURED_VIA: &str = "whoami:akamai+google";

/// Time limit of each whoami lookup (both A-record and TXT run in parallel).
/// Together with `GEO_TOTAL_LIMIT` (1800 ms) stays under `CHECK_LIMIT_IO` (4000 ms).
pub const WHOAMI_LIMIT: Duration = Duration::from_millis(2000);
/// Time limit of one geo request and of the whole geo cascade.
const GEO_REQUEST_LIMIT: Duration = Duration::from_millis(900);
const GEO_TOTAL_LIMIT: Duration = Duration::from_millis(1800);

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

/// Addresses that a real resolver never has on the Internet. Besides private and loopback ranges
/// this is the `198.18.0.0/15` pool in which fake-IP DNS of a TUN client (Throne, Clash...)
/// answers: such an answer comes from the local DNS stub, not from a resolver.
pub fn is_special_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_special_v4(*v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_special_v4(v4),
            None => is_special_v6(*v6),
        },
    }
}

fn is_special_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()                           // 127.0.0.0/8
        || ip.is_private()                            // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()                         // 169.254/16
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0                                  // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64)       // 100.64.0.0/10 (CGNAT)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)       // 198.18.0.0/15 (fake-IP / benchmarking)
        || o[0] >= 240 // reserved
}

fn is_special_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (first & 0xfe00) == 0xfc00 // fc00::/7 unique local
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

    // A service address instead of a resolver address: a local DNS stub answers for the name.
    let special = match (akamai, google) {
        (Special(ip), _) | (_, Special(ip)) => Some(*ip),
        _ => None,
    };
    if let Some(ip) = special {
        return Err(Unmeasured {
            code: "DNS_WHOAMI_FAKE_IP",
            reason: UnknownReason::SourceRefused,
            detail: format!(
                "DNS ответил служебным адресом {ip} (так выглядит fake-IP режим TUN-клиента или локальный DNS-перехватчик), реальный резолвер не виден"
            ),
            sources,
        });
    }

    match (akamai, google) {
        (Addr(a), Addr(g)) => {
            let (op_a, op_g) = (operator_of(*a), operator_of(*g));
            let operator = op_a.filter(|op| Some(*op) == op_g);
            if operator.is_some() || same_resolver_network(*a, *g) {
                return Ok(Agreed {
                    ip: *a,
                    operator,
                });
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

// ---------------------------------------------------------------------------------------------
// Resolver address -> country
// ---------------------------------------------------------------------------------------------

/// A well-known public DNS service (anycast): by ASN or by words of the organisation name.
pub struct PublicDns {
    pub name: &'static str,
    pub asns: &'static [u32],
    /// Lower-case fragments of the organisation / ISP name.
    pub org_keywords: &'static [&'static str],
}

/// Public resolvers whose whoami egress address is placed by geo services in the country of the
/// nearest point of presence: comparing that country with the exit country proves nothing.
pub const PUBLIC_DNS_SERVICES: [PublicDns; 5] = [
    PublicDns {
        name: "Google Public DNS",
        asns: &[15169, 36040, 19527, 396982],
        org_keywords: &["google"],
    },
    PublicDns {
        name: "Cloudflare",
        asns: &[13335, 209242],
        org_keywords: &["cloudflare"],
    },
    PublicDns {
        name: "Quad9",
        asns: &[19281],
        org_keywords: &["quad9"],
    },
    PublicDns {
        name: "Cisco OpenDNS",
        asns: &[36692],
        org_keywords: &["opendns"],
    },
    PublicDns {
        name: "AdGuard DNS",
        asns: &[212772],
        org_keywords: &["adguard"],
    },
];

/// The public DNS service an address belongs to, judged by its ASN or organisation name.
pub fn public_dns_service(asn: Option<u32>, org: Option<&str>) -> Option<&'static str> {
    let org = org.map(str::to_lowercase);
    PUBLIC_DNS_SERVICES
        .iter()
        .find(|svc| {
            asn.is_some_and(|a| svc.asns.contains(&a))
                || org
                    .as_deref()
                    .is_some_and(|o| svc.org_keywords.iter().any(|k| o.contains(k)))
        })
        .map(|svc| svc.name)
}

/// What a geo service says about an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoInfo {
    pub country: String,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

/// An ASN given as a number or as text (`15169`, `"AS15169"`, `"AS15169 Google LLC"`).
fn asn_from_value(v: &serde_json::Value) -> Option<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).ok();
    }
    let text = v.as_str()?.trim();
    let digits = text
        .strip_prefix("AS")
        .or_else(|| text.strip_prefix("as"))
        .unwrap_or(text);
    digits.split_whitespace().next()?.parse().ok()
}

fn text_of(v: Option<&serde_json::Value>) -> Option<String> {
    v.and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

/// A two-letter country code (never `XX`/`ZZ`).
fn valid_country(raw: &str) -> Option<String> {
    let code = raw.trim().to_uppercase();
    let valid = code.len() == 2
        && code.bytes().all(|b| b.is_ascii_uppercase())
        && !matches!(code.as_str(), "XX" | "ZZ");
    valid.then_some(code)
}

fn parse_json(body: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    (value.get("success").and_then(|s| s.as_bool()) != Some(false)).then_some(value)
}

/// `https://ipwho.is/<ip>`: `country_code`, `connection.{asn, org, isp}`.
fn parse_ipwhois(body: &str) -> Option<GeoInfo> {
    let v = parse_json(body)?;
    let conn = v.get("connection");
    Some(GeoInfo {
        country: valid_country(v.get("country_code")?.as_str()?)?,
        asn: conn.and_then(|c| c.get("asn")).and_then(asn_from_value),
        org: text_of(conn.and_then(|c| c.get("org")))
            .or_else(|| text_of(conn.and_then(|c| c.get("isp")))),
    })
}

/// `https://ipinfo.io/<ip>/json`: `country`, `org` = `"AS15169 Google LLC"`.
fn parse_ipinfo(body: &str) -> Option<GeoInfo> {
    let v = parse_json(body)?;
    let org = text_of(v.get("org"));
    Some(GeoInfo {
        country: valid_country(v.get("country")?.as_str()?)?,
        asn: v.get("org").and_then(asn_from_value),
        org,
    })
}

/// `https://freeipapi.com/api/json/<ip>`: `countryCode`, `asn`, `asnOrganization`.
fn parse_freeipapi(body: &str) -> Option<GeoInfo> {
    let v = parse_json(body)?;
    Some(GeoInfo {
        country: valid_country(v.get("countryCode")?.as_str()?)?,
        asn: v.get("asn").and_then(asn_from_value),
        org: text_of(v.get("asnOrganization")),
    })
}

/// Country (and ASN / organisation when the same answer has them) of `ip` through the public
/// services of the exit cascade (ipwho.is, ipinfo.io, freeipapi.com); the first usable answer wins.
pub async fn geo_of_ip(probe: &dyn IpProbe, ip: IpAddr) -> Result<GeoInfo, UnknownReason> {
    type Parser = fn(&str) -> Option<GeoInfo>;
    let services: [(String, Parser); 3] = [
        (format!("https://ipwho.is/{ip}"), parse_ipwhois),
        (format!("https://ipinfo.io/{ip}/json"), parse_ipinfo),
        (
            format!("https://freeipapi.com/api/json/{ip}"),
            parse_freeipapi,
        ),
    ];
    let cascade = async {
        let (mut timed_out, mut answered) = (false, false);
        for (url, parse) in &services {
            match probe.get(url, GEO_REQUEST_LIMIT).await {
                HttpProbeOutcome::Response { status, body } if (200..300).contains(&status) => {
                    answered = true;
                    if let Some(geo) = parse(&body) {
                        return Ok(geo);
                    }
                }
                HttpProbeOutcome::Response { .. } => answered = true,
                HttpProbeOutcome::Timeout => timed_out = true,
                _ => {}
            }
        }
        Err(if timed_out {
            UnknownReason::Timeout
        } else if answered {
            UnknownReason::EmptyResponse
        } else {
            UnknownReason::NetworkError
        })
    };
    tokio::time::timeout(GEO_TOTAL_LIMIT, cascade)
        .await
        .unwrap_or(Err(UnknownReason::Timeout))
}

/// Asks both whoami sources, requires them to agree and locates the resolver.
pub async fn measure_resolver(
    dns: &dyn DnsLookup,
    probe: &dyn IpProbe,
    geo_cache: &TtlCache<Result<GeoInfo, UnknownReason>>,
) -> ResolverView {
    let (akamai, google) = tokio::join!(
        dns.lookup(AKAMAI_HOST, WHOAMI_LIMIT),
        dns.lookup_txt(GOOGLE_TXT_HOST, WHOAMI_LIMIT)
    );
    let (akamai, google) = (akamai_reading(&akamai), google_reading(&google));
    let sources = source_views(&akamai, &google);
    let agreed = match combine_sources(&akamai, &google) {
        Ok(agreed) => agreed,
        Err(unmeasured) => return ResolverView::Unmeasured(unmeasured),
    };
    let ip = agreed.ip;
    // The operator is known by its address range: no geo request (its country is not compared).
    if let Some(service) = agreed.operator {
        return ResolverView::Located {
            ip,
            country: String::new(),
            public_service: Some(service),
            sources,
        };
    }
    let geo = geo_cache
        .get_or_compute(
            &ip.to_string(),
            GEO_TTL,
            |r| r.is_ok(),
            geo_of_ip(probe, ip),
        )
        .await;
    match geo {
        Ok(geo) => ResolverView::Located {
            ip,
            public_service: public_dns_service(geo.asn, geo.org.as_deref()),
            country: geo.country,
            sources,
        },
        Err(reason) => ResolverView::Unmeasured(Unmeasured {
            code: "DNS_RESOLVER_GEO_UNAVAILABLE",
            reason,
            detail: format!(
                "резолвер определён ({ip}), но его страну узнать не удалось: сервисы геолокации не дали ответа"
            ),
            sources,
        }),
    }
}

// ---------------------------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------------------------

/// The country as it is compared: upper case, `None` when it is not a country code.
pub fn normalized_country(raw: &str) -> Option<String> {
    let c = raw.trim().to_uppercase();
    (c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())).then_some(c)
}

/// " Источники показали разные адреса (A и B), но оба принадлежат {service}..." when the two
/// sources answered with different addresses of one public DNS service; empty otherwise.
pub fn same_operator_note(sources: &[SourceView], service: &str) -> String {
    let addrs: Vec<&str> = sources
        .iter()
        .filter(|s| s.state == SourceState::Answered)
        .filter_map(|s| s.addr.as_deref())
        .collect();
    match addrs.as_slice() {
        [a, b] if a != b => format!(
            " Источники показали разные адреса ({a} и {b}), но оба принадлежат {service}: это один и тот же публичный DNS."
        ),
        _ => String::new(),
    }
}

/// "DNS country = exit country" on a measured resolver.
pub fn evaluate_dns_country(view: &ResolverView, exit_country: &str) -> CheckResult {
    let (ip, country, public_service, sources) = match view {
        ResolverView::Located {
            ip,
            country,
            public_service,
            sources,
        } => (ip, country, public_service, sources),
        ResolverView::Unmeasured(u) => {
            return CheckResult::unknown(
                u.code,
                format!(
                    "Согласованность страны DNS и выходного узла не проверена: {}.",
                    u.detail
                ),
                u.reason,
            )
            .with_sources(&u.sources);
        }
    };
    if let Some(service) = public_service {
        // Not penalised and not counted: there is nothing to compare for an anycast service.
        return CheckResult::unknown(
            "DNS_COUNTRY_PUBLIC_RESOLVER",
            format!(
                "Запросы DNS идут на публичный резолвер {service} ({ip}); страна резолвера не сравнивается: это anycast-сервис. ECS и DNS-over-HTTPS в браузере или приложении могут менять картину.{}",
                same_operator_note(sources, service)
            ),
            UnknownReason::NotApplicable,
        )
        .with_measured_via(MEASURED_VIA)
        .with_sources(sources);
    }
    let Some(exit) = normalized_country(exit_country) else {
        return CheckResult::unknown(
            "DNS_COUNTRY_NO_EXIT",
            format!("Согласованность страны DNS и выходного узла не проверена: страна выхода не определена (резолвер {ip} находится в {country})."),
            UnknownReason::NoData,
        )
        .with_measured_via(MEASURED_VIA)
        .with_sources(sources);
    };
    if *country != exit {
        return CheckResult::warning(
            "DNS_COUNTRY_SPLIT",
            format!(
                "DNS-запросы видит резолвер {ip} в {country}, а выходной IP находится в {exit}: возможна утечка DNS мимо туннеля. Страна резолвера определена по его адресу, у публичных anycast-резолверов (1.1.1.1, 8.8.8.8) она бывает неточной; ECS и DNS-over-HTTPS в браузере могут менять картину."
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        )
        .with_measured_via(MEASURED_VIA)
        .with_sources(sources);
    }
    CheckResult::ok(
        "DNS_COUNTRY_CONSISTENT",
        format!(
            "DNS-запросы видит резолвер {ip} в {country}, страна совпадает со страной выхода ({exit}). Определено по двум публичным whoami-источникам (Akamai, Google); резолвер с ECS и DNS-over-HTTPS в браузере или приложении эту картину могут менять."
        ),
    )
    .with_measured_via(MEASURED_VIA)
    .with_sources(sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::geo_matrix::CheckStatus;
    use crate::auditor::seams::fakes::{FakeDns, FakeProbe, addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn txt(s: &str) -> TxtOutcome {
        TxtOutcome::Records(vec![s.to_string()])
    }

    fn geo_probe(country: &str) -> FakeProbe {
        FakeProbe::body(
            200,
            &format!("{{\"success\":true,\"country_code\":\"{country}\"}}"),
        )
    }

    async fn measure(dns: FakeDns, probe: &FakeProbe) -> ResolverView {
        measure_resolver(&dns, probe, &TtlCache::default()).await
    }

    fn agreeing(resolver: &str) -> FakeDns {
        FakeDns::new(LookupOutcome::Failed)
            .with(AKAMAI_HOST, addr(resolver))
            .with_txt(GOOGLE_TXT_HOST, txt(&format!("\"{resolver}\"")))
    }

    #[test]
    fn special_addresses_are_recognised() {
        for s in [
            "198.18.0.7",
            "198.19.255.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.9.9",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::53",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_special_addr(&ip(s)), "{s}");
        }
        for s in [
            "8.8.8.8",
            "77.88.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "203.0.113.5",
            "2001:4860:4860::8888",
        ] {
            assert!(!is_special_addr(&ip(s)), "{s}");
        }
    }

    #[test]
    fn google_txt_answer_is_parsed_and_the_subnet_record_skipped() {
        assert_eq!(
            google_reading(&txt("\"74.125.40.1\"")),
            SourceReading::Addr(ip("74.125.40.1"))
        );
        let with_ecs = TxtOutcome::Records(vec![
            "edns0-client-subnet 203.0.113.0/24".into(),
            "\"2a00:1450:4001::1\"".into(),
        ]);
        assert_eq!(
            google_reading(&with_ecs),
            SourceReading::Addr(ip("2a00:1450:4001::1"))
        );
        assert_eq!(google_reading(&txt("not an address")), SourceReading::Empty);
        assert_eq!(
            google_reading(&txt("\"10.0.0.2\"")),
            SourceReading::Special(ip("10.0.0.2"))
        );
        assert_eq!(google_reading(&TxtOutcome::NotFound), SourceReading::Empty);
    }

    /// `(ip, country, public_service)` of a located resolver.
    fn parts(view: &ResolverView) -> (IpAddr, &str, Option<&'static str>) {
        match view {
            ResolverView::Located {
                ip,
                country,
                public_service,
                ..
            } => (*ip, country.as_str(), *public_service),
            other => panic!("not located: {other:?}"),
        }
    }

    #[tokio::test]
    async fn agreeing_sources_give_a_located_resolver() {
        let view = measure(agreeing("77.88.8.8"), &geo_probe("RU")).await;
        assert_eq!(parts(&view), (ip("77.88.8.8"), "RU", None));
        let ResolverView::Located { sources, .. } = &view else {
            panic!()
        };
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].source, "Akamai");
        assert_eq!(sources[1].addr.as_deref(), Some("77.88.8.8"));
    }

    #[tokio::test]
    async fn two_addresses_of_one_resolver_pool_still_agree() {
        // The same /24 outside of any public DNS range: the geo answer places it.
        let dns = FakeDns::new(LookupOutcome::Failed)
            .with(AKAMAI_HOST, addr("203.0.113.10"))
            .with_txt(GOOGLE_TXT_HOST, txt("203.0.113.77"));
        let view = measure(dns, &geo_probe("US")).await;
        assert_eq!(parts(&view), (ip("203.0.113.10"), "US", None));
    }

    fn two(akamai: &str, google: &str) -> FakeDns {
        FakeDns::new(LookupOutcome::Failed)
            .with(AKAMAI_HOST, addr(akamai))
            .with_txt(GOOGLE_TXT_HOST, txt(&format!("\"{google}\"")))
    }

    #[tokio::test]
    async fn owner_case_two_cloudflare_addresses_agree_without_a_geo_request() {
        // Akamai and Google reached the same resolver from different addresses of its fleet.
        let probe = geo_probe("US");
        let view = measure(two("172.70.161.26", "172.71.240.11"), &probe).await;
        assert_eq!(parts(&view), (ip("172.70.161.26"), "", Some("Cloudflare")));
        assert_eq!(probe.calls(), 0);
        let ResolverView::Located { sources, .. } = &view else {
            panic!()
        };
        assert_eq!(sources[0].operator.as_deref(), Some("Cloudflare"));
        assert_eq!(sources[1].addr.as_deref(), Some("172.71.240.11"));
        assert!(same_operator_note(sources, "Cloudflare").contains("172.71.240.11"));
    }

    #[tokio::test]
    async fn owner_case_ends_as_ok_public_dns_with_both_sources_in_the_detail() {
        let view = measure(two("172.70.161.26", "172.71.240.11"), &geo_probe("US")).await;
        let config = CheckResult::ok("DNS_CONFIG_OK", "в настройках ОС всё чисто");
        let r = crate::auditor::leaks::evaluate_dns_resolver(config, &view, "NL");
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "DNS_PUBLIC_RESOLVER"));
        assert!(r.message.starts_with("Резолвер: Cloudflare (публичный DNS)"), "{}", r.message);
        assert!(r.message.contains("172.70.161.26") && r.message.contains("172.71.240.11"));
        let sources = r.detail.expect("detail").sources;
        assert_eq!(sources.len(), 2);
        assert!(sources.iter().all(|s| s.operator.as_deref() == Some("Cloudflare")));
        // The country check does not penalise it: not applicable.
        let c = evaluate_dns_country(&view, "NL");
        assert!(c.is_not_applicable());
        // The detail survives the JSON the interface reads.
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["detail"]["sources"][0]["source"], "Akamai");
        assert_eq!(json["detail"]["sources"][0]["state"], "answered");
    }

    #[tokio::test]
    async fn one_operator_in_one_range_of_google_or_in_ipv6_agrees() {
        let probe = geo_probe("US");
        let google = measure(two("74.125.40.10", "74.125.99.1"), &probe).await;
        assert_eq!(parts(&google).2, Some("Google Public DNS"));
        let v6 = measure(two("2606:4700:4700::1111", "2606:4700:4700::1001"), &probe).await;
        assert_eq!(parts(&v6).2, Some("Cloudflare"));
        let mixed_family = measure(two("1.1.1.1", "2606:4700:4700::1111"), &probe).await;
        assert_eq!(parts(&mixed_family).2, Some("Cloudflare"));
        assert_eq!(probe.calls(), 0);
    }

    #[tokio::test]
    async fn different_operators_stay_unknown_and_explain_both_sources() {
        let probe = geo_probe("US");
        let view = measure(two("172.70.161.26", "8.8.8.8"), &probe).await;
        let ResolverView::Unmeasured(u) = view else {
            panic!("{view:?}")
        };
        assert_eq!(u.code, "DNS_WHOAMI_DISAGREE");
        assert!(u.detail.contains("Cloudflare") && u.detail.contains("Google Public DNS"));
        assert_eq!(u.sources.len(), 2);
        assert_eq!(u.sources[0].operator.as_deref(), Some("Cloudflare"));
        assert_eq!(u.sources[1].operator.as_deref(), Some("Google Public DNS"));
        assert_eq!(probe.calls(), 0);
        // An unknown operator on one side is not an agreement either.
        let view = measure(two("172.70.161.26", "203.0.113.5"), &probe).await;
        assert!(matches!(view, ResolverView::Unmeasured(ref u) if u.code == "DNS_WHOAMI_DISAGREE"));
    }

    #[tokio::test]
    async fn fake_ip_or_one_silent_source_is_still_unknown_with_detail() {
        let probe = geo_probe("US");
        let fake = measure(two("198.18.0.7", "172.71.240.11"), &probe).await;
        let ResolverView::Unmeasured(u) = fake else {
            panic!()
        };
        assert_eq!(u.code, "DNS_WHOAMI_FAKE_IP");
        assert_eq!(u.sources[0].state, SourceState::Special);
        let dns = FakeDns::new(LookupOutcome::Failed)
            .with(AKAMAI_HOST, addr("172.70.161.26"))
            .with_txt(GOOGLE_TXT_HOST, TxtOutcome::Timeout);
        let ResolverView::Unmeasured(u) = measure(dns, &probe).await else {
            panic!()
        };
        assert_eq!(u.code, "DNS_WHOAMI_SINGLE_SOURCE");
        assert_eq!(u.sources[1].state, SourceState::Timeout);
        assert_eq!(u.sources[0].addr.as_deref(), Some("172.70.161.26"));
    }

    #[test]
    fn dns_country_of_an_unmeasured_resolver_carries_the_sources() {
        let u = combine_sources(
            &SourceReading::Addr(ip("172.70.161.26")),
            &SourceReading::Addr(ip("8.8.8.8")),
        )
        .unwrap_err();
        let r = evaluate_dns_country(&ResolverView::Unmeasured(u), "NL");
        assert_eq!(r.status, CheckStatus::Unknown);
        assert_eq!(r.detail.as_ref().map(|d| d.sources.len()), Some(2));
    }

    #[tokio::test]
    async fn disagreeing_sources_are_unknown() {
        let dns = FakeDns::new(LookupOutcome::Failed)
            .with(AKAMAI_HOST, addr("8.8.8.8"))
            .with_txt(GOOGLE_TXT_HOST, txt("77.88.8.8"));
        let probe = geo_probe("US");
        let view = measure(dns, &probe).await;
        let ResolverView::Unmeasured(u) = view else {
            panic!("{view:?}")
        };
        assert_eq!(
            (u.code, u.reason),
            ("DNS_WHOAMI_DISAGREE", UnknownReason::NoData)
        );
        assert_eq!(
            probe.calls(),
            0,
            "no geo request for an unconfirmed address"
        );
    }

    #[tokio::test]
    async fn silent_sources_are_unknown_with_a_reason() {
        let cases = [
            (
                LookupOutcome::Timeout,
                TxtOutcome::Timeout,
                UnknownReason::Timeout,
            ),
            (
                LookupOutcome::Failed,
                TxtOutcome::Failed,
                UnknownReason::NetworkError,
            ),
            (
                LookupOutcome::NotFound,
                TxtOutcome::NotFound,
                UnknownReason::EmptyResponse,
            ),
            (
                LookupOutcome::Failed,
                TxtOutcome::Unsupported,
                UnknownReason::NetworkError,
            ),
            (
                LookupOutcome::NotFound,
                TxtOutcome::Unsupported,
                UnknownReason::UnsupportedOs,
            ),
        ];
        for (a, g, want) in cases {
            let dns = FakeDns::new(LookupOutcome::Failed)
                .with(AKAMAI_HOST, a.clone())
                .with_txt(GOOGLE_TXT_HOST, g.clone());
            let view = measure(dns, &geo_probe("NL")).await;
            let ResolverView::Unmeasured(u) = view else {
                panic!("{a:?} {g:?}")
            };
            assert_eq!(u.reason, want, "{a:?} {g:?}");
        }
    }

    #[tokio::test]
    async fn one_silent_source_is_not_a_confirmation() {
        let dns = FakeDns::new(LookupOutcome::Failed)
            .with(AKAMAI_HOST, addr("8.8.8.8"))
            .with_txt(GOOGLE_TXT_HOST, TxtOutcome::Timeout);
        let view = measure(dns, &geo_probe("US")).await;
        let ResolverView::Unmeasured(u) = view else {
            panic!()
        };
        assert_eq!(
            (u.code, u.reason),
            ("DNS_WHOAMI_SINGLE_SOURCE", UnknownReason::NoData)
        );
    }

    #[tokio::test]
    async fn fake_ip_and_private_answers_are_source_refused() {
        for fake in [
            "198.18.0.9",
            "10.0.0.2",
            "192.168.1.1",
            "100.64.3.3",
            "127.0.0.1",
            "169.254.2.2",
        ] {
            let view = measure(agreeing(fake), &geo_probe("NL")).await;
            let ResolverView::Unmeasured(u) = view else {
                panic!("{fake}")
            };
            assert_eq!(
                (u.code, u.reason),
                ("DNS_WHOAMI_FAKE_IP", UnknownReason::SourceRefused),
                "{fake}"
            );
        }
        // One of the two being a stub answer is enough.
        let dns = FakeDns::new(LookupOutcome::Failed)
            .with(AKAMAI_HOST, addr("198.18.0.9"))
            .with_txt(GOOGLE_TXT_HOST, txt("8.8.8.8"));
        let ResolverView::Unmeasured(u) = measure(dns, &geo_probe("NL")).await else {
            panic!()
        };
        assert_eq!(u.reason, UnknownReason::SourceRefused);
    }

    #[tokio::test]
    async fn geo_cascade_falls_through_and_reports_why_it_failed() {
        let dns = || agreeing("77.88.8.8");
        // The first service fails, the second answers.
        let probe = FakeProbe::new(HttpProbeOutcome::Timeout).with_route(
            "ipinfo.io",
            HttpProbeOutcome::Response {
                status: 200,
                body: "{\"ip\":\"77.88.8.8\",\"country\":\"ru\"}".into(),
            },
        );
        assert_eq!(
            parts(&measure(dns(), &probe).await),
            (ip("77.88.8.8"), "RU", None)
        );
        // No service answers in time.
        let ResolverView::Unmeasured(u) =
            measure(dns(), &FakeProbe::new(HttpProbeOutcome::Timeout)).await
        else {
            panic!()
        };
        assert_eq!(
            (u.code, u.reason),
            ("DNS_RESOLVER_GEO_UNAVAILABLE", UnknownReason::Timeout)
        );
        // Services answer without a country (error body, bogon, rate limit).
        for body in [
            "{\"success\":false}",
            "{\"ip\":\"1.2.3.4\",\"bogon\":true}",
            "<html>",
            "{\"country_code\":\"XX\"}",
        ] {
            let ResolverView::Unmeasured(u) = measure(dns(), &FakeProbe::body(200, body)).await
            else {
                panic!()
            };
            assert_eq!(u.reason, UnknownReason::EmptyResponse, "{body}");
        }
        let ResolverView::Unmeasured(u) =
            measure(dns(), &FakeProbe::new(HttpProbeOutcome::ConnectFailed)).await
        else {
            panic!()
        };
        assert_eq!(u.reason, UnknownReason::NetworkError);
    }

    #[tokio::test]
    async fn geo_of_one_resolver_is_asked_once() {
        let cache = TtlCache::default();
        let probe = geo_probe("NL");
        let dns = agreeing("203.0.113.9");
        measure_resolver(&dns, &probe, &cache).await;
        measure_resolver(&dns, &probe, &cache).await;
        assert_eq!(probe.calls(), 1);
    }

    // ---- №11 verdicts ----

    fn located(ip_s: &str, cc: &str) -> ResolverView {
        ResolverView::Located {
            ip: ip(ip_s),
            country: cc.into(),
            public_service: None,
            sources: vec![],
        }
    }

    #[test]
    fn same_country_is_ok_with_the_ecs_caveat_and_the_source() {
        let r = evaluate_dns_country(&located("9.9.9.9", "NL"), "nl");
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Ok, "DNS_COUNTRY_CONSISTENT")
        );
        assert!(
            r.message.contains("ECS") && r.message.contains("DNS-over-HTTPS"),
            "{}",
            r.message
        );
        assert_eq!(r.measured_via.as_deref(), Some(MEASURED_VIA));
    }

    #[test]
    fn another_country_is_a_warning() {
        let r = evaluate_dns_country(&located("77.88.8.8", "RU"), "NL");
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Warning, "DNS_COUNTRY_SPLIT")
        );
        assert!(r.message.contains("RU") && r.message.contains("NL") && r.message.contains("ECS"));
        assert_eq!(r.measured_via.as_deref(), Some("whoami:akamai+google"));
    }

    #[test]
    fn unmeasured_resolver_or_exit_is_unknown_never_ok() {
        let u = ResolverView::Unmeasured(Unmeasured {
            code: "DNS_WHOAMI_TIMEOUT",
            reason: UnknownReason::Timeout,
            detail: "x".into(),
            sources: vec![],
        });
        let r = evaluate_dns_country(&u, "NL");
        assert_eq!(
            (r.status, r.reason),
            (CheckStatus::Unknown, Some(UnknownReason::Timeout))
        );
        for exit in ["", "  ", "T1", "XXX"] {
            let r = evaluate_dns_country(&located("9.9.9.9", "NL"), exit);
            assert_eq!(
                (r.status, r.reason),
                (CheckStatus::Unknown, Some(UnknownReason::NoData)),
                "{exit:?}"
            );
        }
    }

    // ---- public DNS services ----

    #[test]
    fn public_dns_services_are_told_by_asn_or_organisation() {
        let cases = [
            (Some(15169), None, Some("Google Public DNS")),
            (None, Some("Google LLC"), Some("Google Public DNS")),
            (Some(13335), Some("Cloudflare, Inc."), Some("Cloudflare")),
            (None, Some("CLOUDFLARENET"), Some("Cloudflare")),
            (Some(19281), None, Some("Quad9")),
            (None, Some("Quad9 Foundation"), Some("Quad9")),
            (Some(36692), None, Some("Cisco OpenDNS")),
            (None, Some("Cisco OpenDNS, LLC"), Some("Cisco OpenDNS")),
            // An ordinary provider, a missing answer, a plain "Cisco" are not public DNS.
            (Some(8359), Some("MTS PJSC"), None),
            (Some(3320), Some("Deutsche Telekom AG"), None),
            (None, Some("Cisco Systems"), None),
            (None, None, None),
        ];
        for (asn, org, want) in cases {
            assert_eq!(public_dns_service(asn, org), want, "{asn:?} {org:?}");
        }
    }

    #[test]
    fn geo_answers_of_all_three_services_give_asn_and_organisation() {
        let w = parse_ipwhois(
            "{\"success\":true,\"country_code\":\"US\",\"connection\":{\"asn\":15169,\"org\":\"Google LLC\",\"isp\":\"Google\"}}",
        )
        .unwrap();
        assert_eq!(
            (w.country.as_str(), w.asn, w.org.as_deref()),
            ("US", Some(15169), Some("Google LLC"))
        );
        let i = parse_ipinfo(
            "{\"ip\":\"1.1.1.1\",\"country\":\"AU\",\"org\":\"AS13335 Cloudflare, Inc.\"}",
        )
        .unwrap();
        assert_eq!((i.country.as_str(), i.asn), ("AU", Some(13335)));
        assert!(i.org.as_deref().unwrap().contains("Cloudflare"));
        let f = parse_freeipapi("{\"countryCode\":\"US\",\"asn\":\"AS36692\",\"asnOrganization\":\"Cisco OpenDNS, LLC\"}").unwrap();
        assert_eq!(
            (f.asn, f.org.as_deref()),
            (Some(36692), Some("Cisco OpenDNS, LLC"))
        );
        // A country without ASN data is still a geo answer.
        let bare = parse_ipwhois("{\"success\":true,\"country_code\":\"NL\"}").unwrap();
        assert_eq!((bare.asn, bare.org), (None, None));
    }

    fn probe_with_org(cc: &str, asn: u32, org: &str) -> FakeProbe {
        FakeProbe::body(
            200,
            &format!(
                "{{\"success\":true,\"country_code\":\"{cc}\",\"connection\":{{\"asn\":{asn},\"org\":\"{org}\"}}}}"
            ),
        )
    }

    #[tokio::test]
    async fn the_resolver_is_marked_as_a_public_service_from_the_same_geo_answer() {
        // An address outside of the built-in ranges: only the geo answer tells the operator.
        let probe = probe_with_org("US", 15169, "Google LLC");
        let view = measure(agreeing("35.199.1.1"), &probe).await;
        assert_eq!(
            parts(&view),
            (ip("35.199.1.1"), "US", Some("Google Public DNS"))
        );
        assert_eq!(probe.calls(), 1, "no extra request for the ASN");
        let plain = measure(
            agreeing("203.0.113.53"),
            &probe_with_org("DE", 3320, "Deutsche Telekom AG"),
        )
        .await;
        let ResolverView::Located { public_service, .. } = plain else {
            panic!()
        };
        assert_eq!(public_service, None);
    }

    #[test]
    fn country_of_a_public_resolver_is_not_applicable_not_a_warning() {
        let view = ResolverView::Located {
            ip: ip("1.1.1.1"),
            country: "AU".into(),
            public_service: Some("Cloudflare"),
            sources: vec![],
        };
        let r = evaluate_dns_country(&view, "NL");
        assert_eq!(
            (r.status, r.reason),
            (CheckStatus::Unknown, Some(UnknownReason::NotApplicable))
        );
        assert!(r.is_not_applicable());
        assert_eq!(r.code, "DNS_COUNTRY_PUBLIC_RESOLVER");
        assert!(
            r.message.contains("Cloudflare")
                && r.message.contains("anycast")
                && r.message.contains("ECS")
        );
    }
}
