//! Hickory cache-bypassing A and TXT queries.

use std::net::IpAddr;
use std::time::Duration;

use super::{LookupOutcome, TxtOutcome, is_usable_nameserver};

fn build_hickory_resolver(
    per_try_timeout: Duration,
    explicit_servers: Option<&[IpAddr]>,
) -> Option<hickory_resolver::TokioResolver> {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    let cfg = if let Some(ips) = explicit_servers {
        let usable: Vec<NameServerConfig> = ips
            .iter()
            .filter(|ip| is_usable_nameserver(ip))
            .copied()
            .map(NameServerConfig::udp_and_tcp)
            .collect();
        if usable.is_empty() {
            return None;
        }
        ResolverConfig::from_parts(None, vec![], usable)
    } else {
        let (mut sys_cfg, _) = hickory_resolver::system_conf::read_system_conf().ok()?;
        sys_cfg
            .name_servers
            .retain(|ns| is_usable_nameserver(&ns.ip));
        if sys_cfg.name_servers.is_empty() {
            return None;
        }
        sys_cfg
    };
    let mut builder = TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        opts.cache_size = 0;
        opts.attempts = 2;
        opts.timeout = per_try_timeout;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.num_concurrent_reqs = 2;
    }
    builder.build().ok()
}

pub(super) async fn hickory_a_query(
    host_fqdn: &str,
    per_try_timeout: Duration,
    explicit_servers: Option<&[IpAddr]>,
) -> LookupOutcome {
    use hickory_resolver::net::{DnsError, NetError};
    use hickory_resolver::proto::rr::{RData, RecordType};

    let Some(resolver) = build_hickory_resolver(per_try_timeout, explicit_servers) else {
        return LookupOutcome::Failed;
    };
    match resolver.lookup(host_fqdn, RecordType::A).await {
        Ok(lookup) => {
            let addrs: Vec<IpAddr> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::A(a) => Some(IpAddr::V4(a.0)),
                    _ => None,
                })
                .collect();
            if addrs.is_empty() {
                LookupOutcome::NotFound
            } else {
                LookupOutcome::Addrs(addrs)
            }
        }
        Err(NetError::Timeout) => LookupOutcome::Timeout,
        Err(NetError::Dns(DnsError::NoRecordsFound(_))) => LookupOutcome::NotFound,
        Err(_) => LookupOutcome::Failed,
    }
}

pub(super) async fn hickory_txt_query(
    host_fqdn: &str,
    per_try_timeout: Duration,
    explicit_servers: Option<&[IpAddr]>,
) -> TxtOutcome {
    use hickory_resolver::net::{DnsError, NetError};
    use hickory_resolver::proto::rr::{RData, RecordType};

    let Some(resolver) = build_hickory_resolver(per_try_timeout, explicit_servers) else {
        return TxtOutcome::Failed;
    };
    match resolver.lookup(host_fqdn, RecordType::TXT).await {
        Ok(lookup) => {
            let records: Vec<String> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(txt) => Some(
                        txt.txt_data
                            .iter()
                            .map(|part| String::from_utf8_lossy(part).into_owned())
                            .collect::<String>(),
                    ),
                    _ => None,
                })
                .collect();
            if records.is_empty() {
                TxtOutcome::NotFound
            } else {
                TxtOutcome::Records(records)
            }
        }
        Err(NetError::Timeout) => TxtOutcome::Timeout,
        Err(NetError::Dns(DnsError::NoRecordsFound(_))) => TxtOutcome::NotFound,
        Err(_) => TxtOutcome::Failed,
    }
}

pub(super) async fn hickory_ptr_query(
    ip: IpAddr,
    per_try_timeout: Duration,
    explicit_servers: Option<&[IpAddr]>,
) -> Option<String> {
    use hickory_resolver::proto::rr::RData;

    let resolver = build_hickory_resolver(per_try_timeout, explicit_servers)?;
    let lookup = resolver.reverse_lookup(ip).await.ok()?;
    lookup
        .answers()
        .iter()
        .filter_map(|r| match &r.data {
            RData::PTR(ptr) => {
                let raw = ptr.0.to_string();
                let trimmed = raw.trim().trim_end_matches('.');
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            _ => None,
        })
        .next()
}
