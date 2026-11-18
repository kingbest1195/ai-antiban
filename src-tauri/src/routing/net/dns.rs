//! Hickory & DoH DNS fallback resolvers for entry nodes when system DNS fails (e.g. TUN VPN).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use crate::auditor::dnsbl::parse_doh_json_a_response;
use crate::auditor::network::NEUTRAL_USER_AGENT;
use crate::auditor::seams::{LookupOutcome, is_usable_nameserver};

const HICKORY_DNS_TIMEOUT: Duration = Duration::from_millis(1200);
const DOH_DNS_TIMEOUT: Duration = Duration::from_millis(1800);
const FALLBACK_DNS_TIMEOUT: Duration = Duration::from_millis(2500);
const CLOUDFLARE_DOH_JSON_URL: &str = "https://1.1.1.1/dns-query";
const GOOGLE_DOH_JSON_URL: &str = "https://dns.google/resolve";

fn doh_http_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .no_proxy()
                .timeout(DOH_DNS_TIMEOUT)
                .user_agent(NEUTRAL_USER_AGENT)
                .build()
                .ok()
        })
        .as_ref()
}

fn build_hickory_entry_resolver(use_system_conf: bool) -> Option<hickory_resolver::TokioResolver> {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    let cfg = if use_system_conf {
        let (mut sys_cfg, _) = hickory_resolver::system_conf::read_system_conf().ok()?;
        sys_cfg
            .name_servers
            .retain(|ns| is_usable_nameserver(&ns.ip));
        if sys_cfg.name_servers.is_empty() {
            return None;
        }
        sys_cfg
    } else {
        let servers = vec![
            NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ];
        ResolverConfig::from_parts(None, vec![], servers)
    };

    let mut builder = TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        opts.cache_size = 0;
        opts.attempts = 2;
        opts.timeout = HICKORY_DNS_TIMEOUT;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.num_concurrent_reqs = 2;
    }
    builder.build().ok()
}

pub(super) async fn hickory_resolve_addrs(
    host: &str,
    port: u16,
    use_system_conf: bool,
) -> io::Result<Vec<SocketAddr>> {
    use hickory_resolver::net::NetError;
    use hickory_resolver::proto::rr::{RData, RecordType};

    let Some(resolver) = build_hickory_entry_resolver(use_system_conf) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no usable DNS nameservers configured",
        ));
    };

    let fqdn = format!("{}.", host.trim_end_matches('.'));
    let (res_a, res_aaaa) = tokio::join!(
        tokio::time::timeout(HICKORY_DNS_TIMEOUT, resolver.lookup(&fqdn, RecordType::A)),
        tokio::time::timeout(HICKORY_DNS_TIMEOUT, resolver.lookup(&fqdn, RecordType::AAAA)),
    );

    let mut addrs = Vec::new();
    let mut saw_timeout = false;
    let mut last_err: Option<String> = None;

    for (res, is_v6) in [(res_a, false), (res_aaaa, true)] {
        match res {
            Ok(Ok(lookup)) => {
                for r in lookup.answers() {
                    match (&r.data, is_v6) {
                        (RData::A(a), false) => addrs.push(SocketAddr::new(IpAddr::V4(a.0), port)),
                        (RData::AAAA(aaaa), true) => {
                            addrs.push(SocketAddr::new(IpAddr::V6(aaaa.0), port))
                        }
                        _ => {}
                    }
                }
            }
            Ok(Err(NetError::Timeout)) | Err(_) => saw_timeout = true,
            Ok(Err(e)) => last_err = Some(e.to_string()),
        }
    }

    if !addrs.is_empty() {
        return Ok(addrs);
    }
    if saw_timeout {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "hickory DNS fallback timed out",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        last_err.unwrap_or_else(|| "hickory DNS fallback returned no records".to_string()),
    ))
}

async fn doh_resolve_addrs_from_url(
    client: &reqwest::Client,
    doh_url: &str,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let resp = client
        .get(doh_url)
        .query(&[("name", host), ("type", "A")])
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .timeout(DOH_DNS_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            let kind = if e.is_timeout() {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::Other
            };
            io::Error::new(kind, format!("DoH request failed: {e}"))
        })?;
    if !resp.status().is_success() {
        return Err(io::Error::other(format!(
            "DoH endpoint returned HTTP {}",
            resp.status()
        )));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| io::Error::other(format!("DoH response read failed: {e}")))?;
    match parse_doh_json_a_response(&body) {
        LookupOutcome::Addrs(ips) => Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()),
        LookupOutcome::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DoH returned no addresses",
        )),
        LookupOutcome::Timeout => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "DoH lookup timed out",
        )),
        LookupOutcome::Failed => Err(io::Error::other("DoH response parse failed")),
    }
}

pub(super) async fn doh_resolve_addrs(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let client = doh_http_client()
        .ok_or_else(|| io::Error::other("DoH HTTP client could not be initialized"))?;
    let mut set = tokio::task::JoinSet::new();
    for url in [CLOUDFLARE_DOH_JSON_URL, GOOGLE_DOH_JSON_URL] {
        let host = host.to_string();
        set.spawn(async move { doh_resolve_addrs_from_url(client, url, &host, port).await });
    }
    let mut last_err: Option<io::Error> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(addrs)) if !addrs.is_empty() => return Ok(addrs),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => last_err = Some(e),
            Err(e) => last_err = Some(io::Error::other(format!("DoH task failed: {e}"))),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DoH found no records")))
}

/// Races system-config Hickory, public Hickory (1.1.1.1 / 8.8.8.8), and DoH in parallel under
/// [`FALLBACK_DNS_TIMEOUT`] so a single hung resolver cannot eat the route connect budget.
pub(super) async fn parallel_fallback_resolve_addrs(
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let race = async {
        let mut set = tokio::task::JoinSet::new();
        for use_sys in [true, false] {
            let h = host.to_string();
            set.spawn(async move { hickory_resolve_addrs(&h, port, use_sys).await });
        }
        {
            let h = host.to_string();
            set.spawn(async move { doh_resolve_addrs(&h, port).await });
        }
        let mut last_err: Option<io::Error> = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok(addrs)) if !addrs.is_empty() => return Ok(addrs),
                Ok(Ok(_)) => {}
                Ok(Err(e)) => last_err = Some(e),
                Err(e) => last_err = Some(io::Error::other(format!("DNS fallback task failed: {e}"))),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "entry DNS fallback found no addresses")
        }))
    };
    tokio::time::timeout(FALLBACK_DNS_TIMEOUT, race)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "entry DNS fallback timed out"))?
}
