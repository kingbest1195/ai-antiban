//! Entry-node HTTP client builders and cascading geo-telemetry queries.

use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::exit_probe::parse_cloudflare_trace;
use super::resolver::NetworkResolver;
use super::{NEUTRAL_USER_AGENT, NetworkTelemetry, REQUEST_TIMEOUT_MS, current_timestamp};
use crate::routing::net::resolve_entry_checked;
use crate::routing::{Entry, EntryProto, Route};
use crate::state::UpstreamProxyConfig;

/// Builds a `reqwest::Client` that routes all traffic through a legacy single upstream proxy.
/// The upstream host must be an IP literal here (no name resolution takes place).
pub fn build_upstream_client(cfg: &UpstreamProxyConfig) -> Result<reqwest::Client, String> {
    let route = Route::from_legacy(cfg, 0)
        .ok_or_else(|| format!("Unsupported upstream proxy protocol: {}", cfg.protocol))?;
    let entry = route.entries.first().ok_or("route has no entries")?;
    let ip: IpAddr = entry
        .host
        .parse()
        .map_err(|_| "The legacy upstream client needs an IP address".to_string())?;
    let builder = entry_client_builder(entry, SocketAddr::new(ip, entry.port))?;
    builder
        .build()
        .map_err(|e| format!("Failed to build proxy reqwest client: {e}"))
}

fn url_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// reqwest builder going through `entry`, mirroring the gateway transport. `addr` is the entry
/// address that was already resolved and checked: the client connects to it and never resolves the
/// entry name on its own.
/// * `socks5` -> `socks5h://` (target names resolved by the node, like the gateway's ATYP=domain);
/// * `http`   -> `http://` proxy with `Proxy-Authorization: Basic`;
/// * `https`  -> `https://` proxy: reqwest 0.12 (`rustls-tls`, webpki roots) opens TLS to the proxy
///   with full certificate verification and ALPN http/1.1, then sends `CONNECT` with Basic auth.
///   The proxy URL host is the TLS server name and a DNS override pins it to `addr`.
///
/// Credentials never go into error messages.
fn entry_client_builder(entry: &Entry, addr: SocketAddr) -> Result<reqwest::ClientBuilder, String> {
    let scheme = match entry.proto {
        EntryProto::Socks5 => "socks5h",
        EntryProto::Http => "http",
        EntryProto::Https => "https",
    };
    let url_name = match entry.proto {
        EntryProto::Https => url_host(entry.tls_server_name()),
        _ => url_host(&addr.ip().to_string()),
    };
    let mut proxy_url = url::Url::parse(&format!("{scheme}://{url_name}:{}", entry.port))
        .map_err(|_| "Invalid entry address for the audit client".to_string())?;

    if entry.proto == EntryProto::Socks5 {
        // reqwest takes SOCKS credentials from the URL userinfo only.
        if let Some(u) = entry.username.as_deref() {
            proxy_url
                .set_username(u)
                .map_err(|_| "Invalid entry username".to_string())?;
            proxy_url
                .set_password(entry.password.as_deref())
                .map_err(|_| "Invalid entry password".to_string())?;
        }
    }

    let mut proxy = reqwest::Proxy::all(proxy_url.as_str())
        .map_err(|_| format!("Failed to configure {scheme} entry proxy for the audit client"))?;
    if entry.proto != EntryProto::Socks5
        && let Some(u) = entry.username.as_deref()
    {
        proxy = proxy.basic_auth(u, entry.password.as_deref().unwrap_or(""));
    }

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS))
        .pool_max_idle_per_host(0)
        .user_agent(NEUTRAL_USER_AGENT)
        .proxy(proxy);
    if entry.proto == EntryProto::Https {
        let name = entry.tls_server_name();
        if name.parse::<IpAddr>().is_err() {
            builder = builder.resolve(name, addr);
        }
    }
    Ok(builder)
}

/// Audit client going through the given route entry (same entry the gateway uses). The entry host
/// is resolved here, every address is checked against the entry policy (see
/// [`crate::routing::net`]) and the client is pinned to the checked address.
pub async fn build_entry_client(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
) -> Result<reqwest::Client, String> {
    let addr = checked_entry_addr(entry, allow_local, gateway_port).await?;
    entry_client_builder(entry, addr)?
        .build()
        .map_err(|e| format!("Failed to build audit client: {e}"))
}

pub(super) fn format_checked_entry_error(endpoint: &str, err: &std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        format!("Entry node {endpoint} rejected: {err}")
    } else {
        format!("Entry node {endpoint} DNS lookup failed: {err}")
    }
}

async fn checked_entry_addr(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
) -> Result<SocketAddr, String> {
    let addrs = resolve_entry_checked(entry, allow_local, gateway_port)
        .await
        .map_err(|e| format_checked_entry_error(&entry.endpoint(), &e))?;
    addrs
        .first()
        .copied()
        .ok_or_else(|| format!("Entry {} did not resolve", entry.endpoint()))
}

/// Test-only: same as [`build_entry_client`] but trusting an extra root (local TLS stub).
#[cfg(test)]
pub(super) async fn build_entry_client_with_root(
    entry: &Entry,
    root: reqwest::Certificate,
) -> Result<reqwest::Client, String> {
    let addr = checked_entry_addr(entry, true, 0).await?;
    entry_client_builder(entry, addr)?
        .add_root_certificate(root)
        .build()
        .map_err(|e| format!("Failed to build audit client: {e}"))
}

// Models for ipwho.is
#[derive(Deserialize)]
pub(super) struct IpWhoIsResponse {
    pub(super) ip: Option<String>,
    pub(super) country_code: Option<String>,
    pub(super) connection: Option<IpWhoIsConnection>,
    pub(super) timezone: Option<IpWhoIsTimezone>,
}

#[derive(Deserialize)]
pub(super) struct IpWhoIsConnection {
    pub(super) asn: Option<u32>,
    pub(super) org: Option<String>,
    pub(super) isp: Option<String>,
    pub(super) domain: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct IpWhoIsTimezone {
    pub(super) id: Option<String>,
}

// Models for ipinfo.io
#[derive(Deserialize)]
pub(super) struct IpInfoResponse {
    pub(super) ip: Option<String>,
    pub(super) hostname: Option<String>,
    pub(super) country: Option<String>,
    pub(super) org: Option<String>,
    pub(super) timezone: Option<String>,
}

// Models for freeipapi.com
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FreeIpApiResponse {
    ip_address: Option<String>,
    country_code: Option<String>,
    asn: Option<String>,
    asn_organization: Option<String>,
    time_zones: Option<Vec<String>>,
}

impl NetworkResolver {
    pub(super) async fn cascade_via_route(&self, route: &Route) -> Result<NetworkTelemetry, String> {
        if route.entries.is_empty() {
            return Err("route has no entry nodes".to_string());
        }
        let mut errors = Vec::new();
        let allow_local = route.allows_local_entries();
        let gateway_port = self.gateway_port();
        for (i, entry) in route.entries.iter().enumerate() {
            let res = match build_entry_client(entry, allow_local, gateway_port).await {
                Ok(client) => self.cascade_query(&client).await,
                Err(e) => Err(e),
            };
            match res {
                Ok(t) => return Ok(t),
                Err(e) => errors.push(format!("entry #{} {}: {e}", i + 1, entry.endpoint())),
            }
        }
        Err(format!("Route egress lookup failed: {}", errors.join("; ")))
    }

    pub(super) async fn cascade_query(
        &self,
        client: &reqwest::Client,
    ) -> Result<NetworkTelemetry, String> {
        let mut errors = Vec::new();

        // 1. Primary: ipwho.is
        match self.query_ipwhois(client).await {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(format!("ipwho.is failed: {e}")),
        }

        // 2. Fallback 1: ipinfo.io
        match self.query_ipinfo(client).await {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(format!("ipinfo.io failed: {e}")),
        }

        // 3. Fallback 2: freeipapi.com (rich metadata with ASN/ISP/Timezone)
        match self.query_freeipapi(client).await {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(format!("freeipapi.com failed: {e}")),
        }

        // 4. Fallback 3: 1.1.1.1/cdn-cgi/trace
        match self.query_cloudflare_trace(client).await {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(format!("1.1.1.1/cdn-cgi/trace failed: {e}")),
        }

        Err(format!("All geo resolvers failed: {}", errors.join("; ")))
    }

    async fn query_ipwhois(&self, client: &reqwest::Client) -> Result<NetworkTelemetry, String> {
        let resp = client
            .get("https://ipwho.is/")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let parsed: IpWhoIsResponse = resp.json().await.map_err(|e| e.to_string())?;

        let ip = parsed.ip.ok_or("ipwho.is missing 'ip'")?;
        let country_code = parsed
            .country_code
            .ok_or("ipwho.is missing 'country_code'")?
            .to_uppercase();

        let (asn, org, isp, domain) = match parsed.connection {
            Some(conn) => (conn.asn, conn.org, conn.isp, conn.domain),
            None => (None, None, None, None),
        };

        let timezone = parsed.timezone.and_then(|tz| tz.id);

        Ok(NetworkTelemetry {
            ip,
            country_code,
            hostname: domain,
            asn,
            org,
            isp,
            timezone,
            resolved_at: current_timestamp(),
        })
    }

    async fn query_ipinfo(&self, client: &reqwest::Client) -> Result<NetworkTelemetry, String> {
        let resp = client
            .get("https://ipinfo.io/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let parsed: IpInfoResponse = resp.json().await.map_err(|e| e.to_string())?;

        let ip = parsed.ip.ok_or("ipinfo.io missing 'ip'")?;
        let country_code = parsed
            .country
            .ok_or("ipinfo.io missing 'country'")?
            .to_uppercase();

        let mut asn = None;
        let mut org_name = None;

        if let Some(org_str) = parsed.org {
            // E.g. "AS20473 The Constant Company, LLC"
            let trimmed = org_str.trim();
            if let Some(rest) = trimmed.strip_prefix("AS") {
                let mut parts = rest.splitn(2, ' ');
                if let Some(asn_str) = parts.next() {
                    asn = asn_str.parse::<u32>().ok();
                }
                if let Some(name) = parts.next() {
                    org_name = Some(name.to_string());
                }
            } else {
                org_name = Some(trimmed.to_string());
            }
        }

        Ok(NetworkTelemetry {
            ip,
            country_code,
            hostname: parsed.hostname,
            asn,
            org: org_name.clone(),
            isp: org_name,
            timezone: parsed.timezone,
            resolved_at: current_timestamp(),
        })
    }

    async fn query_freeipapi(&self, client: &reqwest::Client) -> Result<NetworkTelemetry, String> {
        let resp = client
            .get("https://freeipapi.com/api/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let parsed: FreeIpApiResponse = resp.json().await.map_err(|e| e.to_string())?;

        let ip = parsed
            .ip_address
            .ok_or("freeipapi.com missing 'ipAddress'")?;
        let country_code = parsed
            .country_code
            .ok_or("freeipapi.com missing 'countryCode'")?
            .to_uppercase();

        let asn = parsed.asn.and_then(|s| {
            let trimmed = s.trim();
            let digits = trimmed.strip_prefix("AS").unwrap_or(trimmed);
            digits.parse::<u32>().ok()
        });
        let org = parsed.asn_organization;
        let timezone = parsed.time_zones.and_then(|mut v| {
            if v.is_empty() {
                None
            } else {
                Some(v.remove(0))
            }
        });

        Ok(NetworkTelemetry {
            ip,
            country_code,
            hostname: None,
            asn,
            org: org.clone(),
            isp: org,
            timezone,
            resolved_at: current_timestamp(),
        })
    }

    async fn query_cloudflare_trace(
        &self,
        client: &reqwest::Client,
    ) -> Result<NetworkTelemetry, String> {
        let resp = client
            .get("https://1.1.1.1/cdn-cgi/trace")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let text = resp.text().await.map_err(|e| e.to_string())?;
        let trace = parse_cloudflare_trace(&text)
            .ok_or_else(|| "1.1.1.1/cdn-cgi/trace missing 'ip'".to_string())?;
        let country_code = trace
            .loc
            .ok_or_else(|| "1.1.1.1/cdn-cgi/trace missing 'loc'".to_string())?;

        Ok(NetworkTelemetry {
            ip: trace.ip,
            country_code,
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            resolved_at: current_timestamp(),
        })
    }
}
