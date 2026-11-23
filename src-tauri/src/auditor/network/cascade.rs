//! Entry-node HTTP client builders and cascading geo-telemetry queries.

use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::exit_probe::parse_cloudflare_trace;
use super::resolver::NetworkResolver;
use super::{
    NEUTRAL_USER_AGENT, NetworkTelemetry, REQUEST_TIMEOUT_MS, ROUTE_REQUEST_TIMEOUT_MS,
    current_timestamp,
};
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
    entry_client_builder_with(entry, addr, REQUEST_TIMEOUT_MS, 0, false)
}

fn entry_client_builder_with(
    entry: &Entry,
    addr: SocketAddr,
    timeout_ms: u64,
    pool_idle_per_host: usize,
    force_http_plain: bool,
) -> Result<reqwest::ClientBuilder, String> {
    let eff_proto = if force_http_plain {
        EntryProto::Http
    } else {
        entry.proto
    };
    let scheme = match eff_proto {
        EntryProto::Socks5 => "socks5h",
        EntryProto::Http => "http",
        EntryProto::Https => "https",
    };
    let url_name = match eff_proto {
        EntryProto::Https => url_host(entry.tls_server_name()),
        _ => url_host(&addr.ip().to_string()),
    };
    let mut proxy_url = url::Url::parse(&format!("{scheme}://{url_name}:{}", addr.port()))
        .map_err(|_| "Invalid entry address for the audit client".to_string())?;

    if eff_proto == EntryProto::Socks5 {
        // reqwest takes SOCKS credentials from the URL userinfo only, and requires
        // `url.password().is_some()` (even `Some("")`) or it silently drops SOCKS5 auth.
        if let Some(u) = entry.username.as_deref() {
            proxy_url
                .set_username(u)
                .map_err(|_| "Invalid entry username".to_string())?;
            proxy_url
                .set_password(Some(entry.password.as_deref().unwrap_or("")))
                .map_err(|_| "Invalid entry password".to_string())?;
        }
    }

    let mut proxy = reqwest::Proxy::all(proxy_url.as_str())
        .map_err(|_| format!("Failed to configure {scheme} entry proxy for the audit client"))?;
    if eff_proto != EntryProto::Socks5
        && let Some(u) = entry.username.as_deref()
    {
        proxy = proxy.basic_auth(u, entry.password.as_deref().unwrap_or(""));
    }

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .pool_max_idle_per_host(pool_idle_per_host)
        .user_agent(NEUTRAL_USER_AGENT)
        .proxy(proxy);
    if eff_proto == EntryProto::Https {
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
/// Uses extended routed timeouts and keep-alive connection pooling within the audit pass.
pub async fn build_entry_client(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
) -> Result<reqwest::Client, String> {
    if let Some(cp) = crate::sysproxy::get_chained_proxy().filter(|cp| {
        !crate::sysproxy::is_gateway_host_port(cp, (gateway_port > 0).then_some(gateway_port))
    }) && let Some(relay_addr) =
        super::entry_relay::spawn_entry_relay(entry, &cp, allow_local, gateway_port).await?
    {
        let ip_literal_https =
            entry.proto == EntryProto::Https && entry.tls_server_name().parse::<IpAddr>().is_ok();
        return entry_client_builder_with(
            entry,
            relay_addr,
            ROUTE_REQUEST_TIMEOUT_MS,
            4,
            ip_literal_https,
        )?
        .build()
        .map_err(|e| format!("Failed to build chained audit client: {e}"));
    }
    let addr = checked_entry_addr(entry, allow_local, gateway_port).await?;
    entry_client_builder_with(entry, addr, ROUTE_REQUEST_TIMEOUT_MS, 4, false)?
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
    pub(crate) async fn client_for_route(&self, route: &Route) -> Option<reqwest::Client> {
        let allow_local = route.allows_local_entries();
        let gateway_port = self.gateway_port();
        for entry in &route.entries {
            if let Ok(client) = build_entry_client(entry, allow_local, gateway_port).await {
                return Some(client);
            }
        }
        None
    }

    pub(super) async fn cascade_via_route(
        &self,
        route: &Route,
    ) -> Result<NetworkTelemetry, String> {
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
        let mut no_meta_fallback: Option<NetworkTelemetry> = None;

        // 1. Primary: ipwho.is, then ipinfo.io, then freeipapi.com.
        // If a provider returns ip/country without ASN/ISP/org metadata, keep querying rich
        // sources instead of stopping early with empty provider metadata.
        for (name, res) in [
            ("ipwho.is", self.query_ipwhois(client).await),
            ("ipinfo.io", self.query_ipinfo(client).await),
            ("freeipapi.com", self.query_freeipapi(client).await),
        ] {
            match res {
                Ok(mut t) if t.has_provider_metadata() => {
                    if t.timezone.is_none()
                        && let Some(tz) = no_meta_fallback.as_ref().and_then(|f| f.timezone.clone())
                    {
                        t.timezone = Some(tz);
                    }
                    return Ok(t);
                }
                Ok(t) => {
                    if no_meta_fallback.is_none() {
                        no_meta_fallback = Some(t);
                    }
                }
                Err(e) => errors.push(format!("{name} failed: {e}")),
            }
        }

        if let Some(t) = no_meta_fallback {
            return Ok(t);
        }

        // 4. Last resort (no ASN/ISP/org): 1.1.1.1/cdn-cgi/trace
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

        let (asn, org_name) = parsed
            .org
            .as_deref()
            .map(parse_as_org)
            .unwrap_or((None, None));

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

        let asn = parsed.asn.and_then(|s| parse_as_org(&s).0);
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

pub(super) fn parse_as_org(org_str: &str) -> (Option<u32>, Option<String>) {
    let trimmed = org_str.trim();
    if trimmed.len() >= 2 && trimmed[..2].eq_ignore_ascii_case("AS") {
        let rest = &trimmed[2..];
        let digits_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits_len > 0 {
            let asn = rest[..digits_len].parse::<u32>().ok();
            let name = rest[digits_len..].trim();
            let org_name = (!name.is_empty()).then(|| name.to_string());
            return (asn, org_name);
        }
    }
    let org_name = (!trimmed.is_empty()).then(|| trimmed.to_string());
    (None, org_name)
}
