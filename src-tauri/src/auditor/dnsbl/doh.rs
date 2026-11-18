//! DNS-over-HTTPS (`https://dns.google/resolve`) fallback resolver for DNSBL lookups.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::auditor::seams::{BoxFuture, DnsLookup, HttpProbeOutcome, IpProbe, LookupOutcome};

/// Time limit of one DNS-over-HTTPS fallback lookup (`https://dns.google/resolve`).
pub const DNSBL_DOH_TIMEOUT_MS: u64 = 2000;
const DOH_RESOLVE_URL: &str = "https://dns.google/resolve";

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
