//! Geolocation lookup and public DNS operator classification for measured resolvers.

use std::net::IpAddr;
use std::time::Duration;

use super::{
    AKAMAI_HOST, GOOGLE_TXT_HOST, ResolverView, Unmeasured, WHOAMI_LIMIT, akamai_reading,
    combine_sources, google_reading, source_views,
};
use crate::auditor::cache::{GEO_TTL, TtlCache};
use crate::auditor::geo_matrix::UnknownReason;
use crate::auditor::seams::{DnsLookup, HttpProbeOutcome, IpProbe};

/// Time limit of one geo request and of the whole geo cascade.
const GEO_REQUEST_LIMIT: Duration = Duration::from_millis(800);
const GEO_TOTAL_LIMIT: Duration = Duration::from_millis(1400);

/// A well-known public DNS service (anycast): by ASN or by words of the organisation name.
pub struct PublicDns {
    pub name: &'static str,
    pub asns: &'static [u32],
    /// Lower-case fragments of the organisation / ISP name.
    pub org_keywords: &'static [&'static str],
}

/// Public resolvers whose whoami egress address is placed by geo services in the country of the
/// nearest point of presence: comparing that country with the exit country proves nothing.
pub const PUBLIC_DNS_SERVICES: &[PublicDns] = &[
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
    PublicDns {
        name: "NextDNS",
        asns: &[34939],
        org_keywords: &["nextdns"],
    },
    PublicDns {
        name: "Control D",
        asns: &[399820],
        org_keywords: &["control d", "controld"],
    },
    PublicDns {
        name: "Mullvad DNS",
        asns: &[39351],
        org_keywords: &["mullvad"],
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
pub(super) fn parse_ipwhois(body: &str) -> Option<GeoInfo> {
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
pub(super) fn parse_ipinfo(body: &str) -> Option<GeoInfo> {
    let v = parse_json(body)?;
    let org = text_of(v.get("org"));
    Some(GeoInfo {
        country: valid_country(v.get("country")?.as_str()?)?,
        asn: v.get("org").and_then(asn_from_value),
        org,
    })
}

/// `https://freeipapi.com/api/json/<ip>`: `countryCode`, `asn`, `asnOrganization`.
pub(super) fn parse_freeipapi(body: &str) -> Option<GeoInfo> {
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
        dns.lookup_uncached(AKAMAI_HOST, WHOAMI_LIMIT),
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
