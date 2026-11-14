//! Replaceable sources of the checks: DNS lookups, the HTTP probe and everything that reads the host.
//!
//! The audit never talks to the network or starts a process directly: it goes through these
//! traits, so a test can substitute a fake and run without network and without child processes.

use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------------------------

/// Raw outcome of one name lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    /// The name resolved to these addresses (never empty).
    Addrs(Vec<IpAddr>),
    /// The resolver answered "no such name / no address" (NXDOMAIN or an empty answer).
    NotFound,
    /// No answer within the time limit.
    Timeout,
    /// Any other failure (resolver unreachable, SERVFAIL, socket error...).
    Failed,
}

/// Raw outcome of one TXT lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxtOutcome {
    /// The name has these TXT records (one string per record, character-strings joined).
    Records(Vec<String>),
    /// The resolver answered "no such name / no TXT record".
    NotFound,
    /// No answer within the time limit.
    Timeout,
    /// Any other failure (no resolver configured, SERVFAIL, socket error...).
    Failed,
    /// This source cannot do TXT lookups on this system.
    Unsupported,
}

/// Resolves a host name to addresses.
pub trait DnsLookup: Send + Sync {
    fn lookup<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, LookupOutcome>;

    /// Cache-bypassing A/address lookup (falls back to [`Self::lookup`] for fakes/implementations
    /// without a separate uncached path).
    fn lookup_uncached<'a>(
        &'a self,
        host: &'a str,
        limit: Duration,
    ) -> BoxFuture<'a, LookupOutcome> {
        self.lookup(host, limit)
    }

    /// TXT records of `host` (asked from the resolver configured in the OS).
    fn lookup_txt<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, TxtOutcome> {
        let _ = (host, limit);
        Box::pin(async { TxtOutcome::Unsupported })
    }
}

/// The operating system resolver (`getaddrinfo`) and cache-bypassing DNS queries.
pub struct SystemDns;

impl DnsLookup for SystemDns {
    fn lookup<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, LookupOutcome> {
        Box::pin(async move {
            match tokio::time::timeout(limit, tokio::net::lookup_host((host, 80u16))).await {
                Err(_) => LookupOutcome::Timeout,
                Ok(Ok(addrs)) => {
                    let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                    if ips.is_empty() {
                        LookupOutcome::NotFound
                    } else {
                        LookupOutcome::Addrs(ips)
                    }
                }
                Ok(Err(e)) if is_name_not_found(&e) => LookupOutcome::NotFound,
                Ok(Err(_)) => LookupOutcome::Failed,
            }
        })
    }

    fn lookup_uncached<'a>(
        &'a self,
        host: &'a str,
        limit: Duration,
    ) -> BoxFuture<'a, LookupOutcome> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let outcome = tokio::time::timeout(limit, system_a_lookup(host, limit))
                .await
                .unwrap_or(LookupOutcome::Timeout);
            if matches!(outcome, LookupOutcome::Addrs(_) | LookupOutcome::NotFound) {
                return outcome;
            }
            // Fall back to OS getaddrinfo only on transport/config failure with time remaining
            // (e.g. local stub that blocks raw UDP/TCP 53), not when the uncached query timed out.
            let remaining = limit.saturating_sub(started.elapsed());
            if matches!(outcome, LookupOutcome::Failed) && remaining >= Duration::from_millis(250) {
                return self.lookup(host, remaining).await;
            }
            outcome
        })
    }

    fn lookup_txt<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, TxtOutcome> {
        Box::pin(async move {
            tokio::time::timeout(limit, system_txt_lookup(host, limit))
                .await
                .unwrap_or(TxtOutcome::Timeout)
        })
    }
}

/// Returns `true` if `ip` is a plausibly reachable recursive DNS server address
/// (filters unspecified, multicast, link-local IPv6 without zone, and RFC3879 `fec0:0:0:ffff::*` Windows placeholders).
pub(crate) fn is_usable_nameserver(ip: &IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => {
            if v6.is_unicast_link_local() {
                return false;
            }
            let segs = v6.segments();
            // Windows RFC3879 / site-local dummy DNS addresses on interfaces without DHCPv6
            !(segs[0] == 0xfec0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0xffff)
        }
    }
}

/// Parses active reachable DNS nameservers from macOS `scutil --dns` output.
/// Global default resolvers (before `DNS configuration (for scoped queries)` and without a `domain :` filter)
/// come first; scoped default resolvers come second as fallback.
pub(crate) fn parse_scutil_dns_nameservers(output: &str) -> Vec<IpAddr> {
    let mut global_ips = Vec::new();
    let mut scoped_ips = Vec::new();
    let mut in_scoped_section = false;

    let mut cur_ips: Vec<IpAddr> = Vec::new();
    let mut has_domain = false;
    let mut not_reachable = false;
    let mut in_block = false;

    let flush = |in_block: bool,
                 has_domain: bool,
                 not_reachable: bool,
                 in_scoped: bool,
                 cur_ips: &mut Vec<IpAddr>,
                 global_ips: &mut Vec<IpAddr>,
                 scoped_ips: &mut Vec<IpAddr>| {
        if in_block && !has_domain && !not_reachable {
            let target = if in_scoped { scoped_ips } else { global_ips };
            for ip in cur_ips.drain(..) {
                if is_usable_nameserver(&ip) && !target.contains(&ip) {
                    target.push(ip);
                }
            }
        } else {
            cur_ips.clear();
        }
    };

    for raw in output.lines() {
        let line = raw.trim();
        if line.starts_with("DNS configuration (for scoped queries)") {
            flush(
                in_block,
                has_domain,
                not_reachable,
                in_scoped_section,
                &mut cur_ips,
                &mut global_ips,
                &mut scoped_ips,
            );
            in_block = false;
            has_domain = false;
            not_reachable = false;
            in_scoped_section = true;
            continue;
        }
        if line.starts_with("resolver #") {
            flush(
                in_block,
                has_domain,
                not_reachable,
                in_scoped_section,
                &mut cur_ips,
                &mut global_ips,
                &mut scoped_ips,
            );
            in_block = true;
            has_domain = false;
            not_reachable = false;
            continue;
        }
        if !in_block {
            continue;
        }
        if line.starts_with("domain") && line.contains(':') {
            has_domain = true;
        } else if line.starts_with("reach") && line.contains("Not Reachable") {
            not_reachable = true;
        } else if line.starts_with("nameserver[")
            && let Some((_, val)) = line.split_once(':')
            && let Ok(ip) = val.trim().parse::<IpAddr>()
        {
            cur_ips.push(ip);
        }
    }
    flush(
        in_block,
        has_domain,
        not_reachable,
        in_scoped_section,
        &mut cur_ips,
        &mut global_ips,
        &mut scoped_ips,
    );

    // Never mix scoped per-interface LAN resolvers with an active global VPN resolver:
    // racing them concurrently could make a local router answer before the VPN DNS.
    if !global_ips.is_empty() {
        global_ips
    } else {
        scoped_ips
    }
}

#[cfg(target_os = "macos")]
async fn macos_scutil_nameservers() -> Vec<IpAddr> {
    tokio::task::spawn_blocking(|| {
        let out = crate::sysproxy::silent_command("scutil")
            .arg("--dns")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(parse_scutil_dns_nameservers(&String::from_utf8_lossy(
            &out.stdout,
        )))
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default()
}

#[cfg(target_os = "windows")]
async fn windows_native_lookup<T: Send + 'static>(
    host: &str,
    limit: Duration,
    query: fn(&str) -> Option<T>,
) -> Option<T> {
    let host_fqdn = format!("{}.", host.trim_end_matches('.'));
    tokio::time::timeout(
        limit,
        tokio::task::spawn_blocking(move || query(&host_fqdn)),
    )
    .await
    .ok()
    .and_then(|res| res.ok())
    .flatten()
}

#[cfg(target_os = "windows")]
mod win_dns {
    use super::{LookupOutcome, TxtOutcome};
    use core::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr};

    const DNS_TYPE_A: u16 = 0x0001;
    const DNS_TYPE_TEXT: u16 = 0x0010;
    const DNS_QUERY_BYPASS_CACHE: u32 = 0x0000_0008;
    const DNS_QUERY_TREAT_AS_FQDN: u32 = 0x0000_1000;
    const DNS_FREE_RECORD_LIST: i32 = 1;
    const DNS_ERROR_RCODE_NAME_ERROR: i32 = 9003;
    const DNS_INFO_NO_RECORDS: i32 = 9501;
    const ERROR_TIMEOUT: i32 = 1460;

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct DnsAData {
        ip_address: u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct DnsTxtDataW {
        dw_string_count: u32,
        p_string_array: [*const u16; 1],
    }

    #[repr(C)]
    union DnsRecordData {
        a: DnsAData,
        txt: DnsTxtDataW,
        _pad: [usize; 8],
    }

    #[repr(C)]
    struct DnsRecordW {
        p_next: *mut DnsRecordW,
        p_name: *const u16,
        w_type: u16,
        w_data_length: u16,
        flags: u32,
        dw_ttl: u32,
        dw_reserved: u32,
        data: DnsRecordData,
    }

    #[link(name = "dnsapi")]
    unsafe extern "system" {
        fn DnsQuery_W(
            psz_name: *const u16,
            w_type: u16,
            options: u32,
            p_extra: *mut c_void,
            pp_query_results: *mut *mut DnsRecordW,
            p_reserved: *mut c_void,
        ) -> i32;
        fn DnsRecordListFree(p_record_list: *mut c_void, free_type: i32);
    }

    unsafe fn utf16_ptr_to_string(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        unsafe {
            while len < 4096 && *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr, len);
            Some(String::from_utf16_lossy(slice))
        }
    }

    enum QueryList {
        NotFound,
        Records(*mut DnsRecordW),
    }

    fn query_raw(host_fqdn: &str, record_type: u16) -> Option<QueryList> {
        let wide: Vec<u16> = host_fqdn.encode_utf16().chain(core::iter::once(0)).collect();
        let mut head: *mut DnsRecordW = core::ptr::null_mut();
        let status = unsafe {
            DnsQuery_W(
                wide.as_ptr(),
                record_type,
                DNS_QUERY_BYPASS_CACHE | DNS_QUERY_TREAT_AS_FQDN,
                core::ptr::null_mut(),
                &mut head,
                core::ptr::null_mut(),
            )
        };
        if status == DNS_ERROR_RCODE_NAME_ERROR || status == DNS_INFO_NO_RECORDS {
            if !head.is_null() {
                unsafe { DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST) };
            }
            return Some(QueryList::NotFound);
        }
        if status == ERROR_TIMEOUT {
            if !head.is_null() {
                unsafe { DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST) };
            }
            return None;
        }
        if status != 0 || head.is_null() {
            if !head.is_null() {
                unsafe { DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST) };
            }
            crate::diagnostics::record(
                "auditor:dns",
                &format!("DnsQuery_W(type={record_type}) failed status={status}"),
            );
            return None;
        }
        Some(QueryList::Records(head))
    }

    pub fn query_a(host_fqdn: &str) -> Option<LookupOutcome> {
        let head = match query_raw(host_fqdn, DNS_TYPE_A)? {
            QueryList::NotFound => return Some(LookupOutcome::NotFound),
            QueryList::Records(h) => h,
        };
        let mut addrs = Vec::new();
        let mut cur: *const DnsRecordW = head;
        unsafe {
            while !cur.is_null() {
                let w_type = core::ptr::addr_of!((*cur).w_type).read();
                let next = core::ptr::addr_of!((*cur).p_next).read();
                if w_type == DNS_TYPE_A {
                    let ip_raw = core::ptr::addr_of!((*cur).data.a.ip_address).read();
                    addrs.push(IpAddr::V4(Ipv4Addr::from(ip_raw.to_ne_bytes())));
                }
                cur = next;
            }
            DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST);
        }
        if addrs.is_empty() {
            Some(LookupOutcome::NotFound)
        } else {
            Some(LookupOutcome::Addrs(addrs))
        }
    }

    pub fn query_txt(host_fqdn: &str) -> Option<TxtOutcome> {
        let head = match query_raw(host_fqdn, DNS_TYPE_TEXT)? {
            QueryList::NotFound => return Some(TxtOutcome::NotFound),
            QueryList::Records(h) => h,
        };

        let mut records = Vec::new();
        let mut cur: *const DnsRecordW = head;
        unsafe {
            while !cur.is_null() {
                // Read fields via raw pointers to avoid slice/union provenance over Windows' variable-length pStringArray.
                let w_type = core::ptr::addr_of!((*cur).w_type).read();
                let data_len = core::ptr::addr_of!((*cur).w_data_length).read() as usize;
                let next = core::ptr::addr_of!((*cur).p_next).read();
                if w_type == DNS_TYPE_TEXT {
                    let count = core::ptr::addr_of!((*cur).data.txt.dw_string_count).read() as usize;
                    let header_bytes = core::mem::offset_of!(DnsTxtDataW, p_string_array);
                    let max_ptrs = data_len.saturating_sub(header_bytes) / core::mem::size_of::<*const u16>();
                    let bounded_count = count.min(max_ptrs).min(64);
                    let arr_ptr = core::ptr::addr_of!((*cur).data.txt.p_string_array).cast::<*const u16>();
                    let mut joined = String::new();
                    for i in 0..bounded_count {
                        if let Some(part) = utf16_ptr_to_string(*arr_ptr.add(i)) {
                            joined.push_str(&part);
                        }
                    }
                    if !joined.is_empty() {
                        records.push(joined);
                    }
                }
                cur = next;
            }
            DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST);
        }
        if records.is_empty() {
            Some(TxtOutcome::NotFound)
        } else {
            Some(TxtOutcome::Records(records))
        }
    }
}

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
        sys_cfg.name_servers.retain(|ns| is_usable_nameserver(&ns.ip));
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

async fn hickory_a_query(
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

async fn hickory_txt_query(
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

/// One cache-bypassing A query through the OS resolvers (`DnsQuery_W` on Windows,
/// `scutil --dns` / system configuration on macOS), matching `system_txt_lookup` so both whoami
/// probes hit the same live resolver.
async fn system_a_lookup(host: &str, limit: Duration) -> LookupOutcome {
    let name = format!("{}.", host.trim_end_matches('.'));
    let started = std::time::Instant::now();
    let per_try = Duration::from_millis((limit.as_millis() as u64 / 2).clamp(800, 1250));

    #[cfg(target_os = "windows")]
    if let Some(outcome) =
        windows_native_lookup(&name, per_try.max(Duration::from_millis(1200)), win_dns::query_a)
            .await
    {
        if matches!(outcome, LookupOutcome::Addrs(_) | LookupOutcome::NotFound) {
            return outcome;
        }
    }

    #[cfg(target_os = "macos")]
    {
        let scutil_ips = macos_scutil_nameservers().await;
        if !scutil_ips.is_empty() {
            let outcome = hickory_a_query(&name, per_try, Some(&scutil_ips)).await;
            if matches!(outcome, LookupOutcome::Addrs(_) | LookupOutcome::NotFound) {
                return outcome;
            }
            let remaining = limit.saturating_sub(started.elapsed());
            if remaining < Duration::from_millis(250) {
                return outcome;
            }
        }
    }

    let remaining = limit.saturating_sub(started.elapsed());
    let fallback_try = Duration::from_millis((remaining.as_millis() as u64 / 2).clamp(400, 1000));
    hickory_a_query(&name, fallback_try, None).await
}

/// One TXT query through the resolvers of the OS configuration (`DnsQuery_W` on Windows,
/// `scutil --dns` / system configuration on macOS), without cache and without search domains.
async fn system_txt_lookup(host: &str, limit: Duration) -> TxtOutcome {
    // The trailing dot makes the name absolute (no search-domain suffixes are tried).
    let name = format!("{}.", host.trim_end_matches('.'));
    let started = std::time::Instant::now();
    let per_try = Duration::from_millis((limit.as_millis() as u64 / 2).clamp(800, 1250));

    #[cfg(target_os = "windows")]
    if let Some(outcome) = windows_native_lookup(
        &name,
        per_try.max(Duration::from_millis(1200)),
        win_dns::query_txt,
    )
    .await
    {
        if matches!(outcome, TxtOutcome::Records(_) | TxtOutcome::NotFound) {
            return outcome;
        }
    }

    #[cfg(target_os = "macos")]
    {
        let scutil_ips = macos_scutil_nameservers().await;
        if !scutil_ips.is_empty() {
            let outcome = hickory_txt_query(&name, per_try, Some(&scutil_ips)).await;
            if matches!(outcome, TxtOutcome::Records(_) | TxtOutcome::NotFound) {
                return outcome;
            }
            crate::diagnostics::record(
                "auditor:dns",
                &format!(
                    "scutil TXT lookup for {host} via {} servers returned {outcome:?}, trying fallback",
                    scutil_ips.len()
                ),
            );
            let remaining = limit.saturating_sub(started.elapsed());
            if remaining < Duration::from_millis(250) {
                return outcome;
            }
        }
    }

    let remaining = limit.saturating_sub(started.elapsed());
    let fallback_try = Duration::from_millis((remaining.as_millis() as u64 / 2).clamp(400, 1000));
    let outcome = hickory_txt_query(&name, fallback_try, None).await;
    if !matches!(outcome, TxtOutcome::Records(_)) {
        crate::diagnostics::record(
            "auditor:dns",
            &format!("system TXT lookup for {host} finished with {outcome:?}"),
        );
    }
    outcome
}

/// `getaddrinfo` reports NXDOMAIN and a broken resolver through the same error type; only the
/// well-known "name does not exist" wordings (and the Windows codes) count as `NotFound`, every
/// other error stays `Failed` (never read as "not listed").
fn is_name_not_found(e: &std::io::Error) -> bool {
    // WSAHOST_NOT_FOUND / WSANO_DATA.
    if matches!(e.raw_os_error(), Some(11001 | 11004)) {
        return true;
    }
    let text = e.to_string().to_lowercase();
    [
        "not known",
        "no address associated",
        "does not resolve",
        "no such host",
        "nodename nor servname",
    ]
    .iter()
    .any(|m| text.contains(m))
}

// ---------------------------------------------------------------------------------------------
// HTTP probe
// ---------------------------------------------------------------------------------------------

/// Raw outcome of one HTTP GET probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProbeOutcome {
    Response {
        status: u16,
        body: String,
    },
    Timeout,
    /// The connection could not be established (no route, refused, TLS failure...).
    ConnectFailed,
    /// The connection worked, but the body could not be read.
    ReadFailed,
    /// The HTTP client could not be built.
    ClientError,
}

/// Performs a plain GET from the host's own network stack (used for the IPv6 leak probe).
pub trait IpProbe: Send + Sync {
    fn get<'a>(&'a self, url: &'a str, limit: Duration) -> BoxFuture<'a, HttpProbeOutcome>;
}

/// `reqwest` without any proxy: the probe must show what the OS network stack does, not what an
/// `HTTPS_PROXY` of this process would do.
pub struct ReqwestProbe;

impl IpProbe for ReqwestProbe {
    fn get<'a>(&'a self, url: &'a str, limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
        Box::pin(async move {
            let Ok(client) = reqwest::Client::builder().timeout(limit).no_proxy().build() else {
                return HttpProbeOutcome::ClientError;
            };
            let resp = match client.get(url).send().await {
                Ok(r) => r,
                Err(e) if e.is_timeout() => return HttpProbeOutcome::Timeout,
                Err(_) => return HttpProbeOutcome::ConnectFailed,
            };
            let status = resp.status().as_u16();
            match resp.text().await {
                Ok(body) => HttpProbeOutcome::Response { status, body },
                Err(e) if e.is_timeout() => HttpProbeOutcome::Timeout,
                Err(_) => HttpProbeOutcome::ReadFailed,
            }
        })
    }
}

// ---------------------------------------------------------------------------------------------
// UDP exchange
// ---------------------------------------------------------------------------------------------

/// Raw outcome of one UDP request/response exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpOutcome {
    /// The first datagram of the server that the `accept` filter let through.
    Reply(Vec<u8>),
    /// Nothing acceptable arrived within the time limit.
    Timeout,
    /// The server name did not resolve or the socket failed (no route, send error...).
    Failed,
}

/// One datagram out, one acceptable datagram back (used for the STUN binding request).
pub trait UdpProbe: Send + Sync {
    /// Sends `request` to `server` (`host:port`) from the host's own network stack and waits up to
    /// `limit` for a datagram of that server for which `accept` is true; any other datagram
    /// (garbage, a stray or forged answer) is skipped.
    fn exchange<'a>(
        &'a self,
        server: &'a str,
        request: &'a [u8],
        accept: &'a (dyn Fn(&[u8]) -> bool + Send + Sync),
        limit: Duration,
    ) -> BoxFuture<'a, UdpOutcome>;
}

/// A real `tokio` UDP socket bound to `0.0.0.0:0` (IPv4).
pub struct TokioUdp;

impl UdpProbe for TokioUdp {
    fn exchange<'a>(
        &'a self,
        server: &'a str,
        request: &'a [u8],
        accept: &'a (dyn Fn(&[u8]) -> bool + Send + Sync),
        limit: Duration,
    ) -> BoxFuture<'a, UdpOutcome> {
        Box::pin(async move {
            let work = async {
                let Ok(mut addrs) = tokio::net::lookup_host(server).await else {
                    return UdpOutcome::Failed;
                };
                let Some(target) = addrs.find(|a| a.is_ipv4()) else {
                    return UdpOutcome::Failed;
                };
                let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
                    return UdpOutcome::Failed;
                };
                if sock.send_to(request, target).await.is_err() {
                    return UdpOutcome::Failed;
                }
                let mut buf = [0u8; 1500];
                loop {
                    match sock.recv_from(&mut buf).await {
                        // Only the queried server counts: a datagram from anywhere else is noise.
                        Ok((n, from)) if from == target && accept(&buf[..n]) => {
                            return UdpOutcome::Reply(buf[..n].to_vec());
                        }
                        Ok(_) => {}
                        // Windows reports an ICMP "port unreachable" of an earlier datagram as a
                        // reset on the next read: not an answer, keep waiting for the limit.
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                        Err(_) => return UdpOutcome::Failed,
                    }
                }
            };
            tokio::time::timeout(limit, work)
                .await
                .unwrap_or(UdpOutcome::Timeout)
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Host information
// ---------------------------------------------------------------------------------------------

/// Why a host setting could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemReadError {
    /// This operating system has no such source.
    Unsupported,
    /// The source exists, but reading it failed (command missing, non-zero exit, empty output).
    Failed,
}

/// Everything the checks read from the host.
pub trait SystemInfo: Send + Sync {
    /// Whether the host has a global IPv6 address and a route for it. `None`: could not tell.
    fn has_global_ipv6(&self) -> Option<bool>;
    /// IANA name of the system time zone.
    fn system_timezone(&self) -> Result<String, String>;
    /// Current UTC offset of the host (seconds east).
    fn local_utc_offset_secs(&self) -> Option<i32>;
    /// Current UTC offset of an IANA zone (seconds east); `None` when it cannot be computed here.
    fn zone_utc_offset_secs(&self, zone: &str) -> Option<i32>;
    /// Environment variable of this process.
    fn env_var(&self, name: &str) -> Option<String>;
    /// User locale tags from the OS settings (macOS `AppleLocale`/`AppleLanguages`, Windows
    /// regional settings).
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError>;
    /// Text of the OS DNS configuration (`scutil --dns` / `ipconfig /all`).
    fn dns_listing(&self) -> Result<String, SystemReadError>;
    /// Output of `reg query` of the location consent value (Windows only).
    fn location_consent(&self, machine_wide: bool) -> Result<String, SystemReadError>;
    /// Whether the independent time zone / locale switch is on and really applied: a zone is being
    /// synced and the AI tools' environment carries `LANG` and `LC_TIME` (`en_US.UTF-8`). Unrelated
    /// to the CLI / IDE proxy protection.
    fn sync_ai_tz_active(&self) -> bool;
}

/// The real host.
pub struct RealSystem;

/// `2000::/3`: addresses that are routed on the Internet.
pub fn is_global_unicast_v6(addr: &Ipv6Addr) -> bool {
    (addr.octets()[0] & 0xe0) == 0x20
}

/// `"+0100"` / `"-0330"` (the output of `date +%z`) to seconds east of UTC.
pub fn parse_utc_offset(text: &str) -> Option<i32> {
    let t = text.trim();
    let (sign, digits) = match t.as_bytes().first()? {
        b'+' => (1, &t[1..]),
        b'-' => (-1, &t[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i32 = digits[..2].parse().ok()?;
    let minutes: i32 = digits[2..].parse().ok()?;
    if hours > 14 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

/// Values of a `defaults read` output: `ru_RU` or `(\n    "ru-RU",\n    "en-RU"\n)`.
pub fn parse_defaults_values(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| {
            l.trim()
                .trim_matches(|c: char| matches!(c, '(' | ')' | ',' | '"' | ' '))
        })
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// A zone name taken from a remote service is checked before it is used on a command line.
#[cfg_attr(not(unix), allow(dead_code))]
fn is_plain_zone_name(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 64
        && !zone.starts_with('/')
        && !zone.contains("..")
        && zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'+'))
}

impl SystemInfo for RealSystem {
    fn has_global_ipv6(&self) -> Option<bool> {
        use std::io::ErrorKind::{
            AddrNotAvailable, HostUnreachable, NetworkUnreachable, Unsupported,
        };
        // A connected UDP socket sends nothing: the kernel only picks the route and the source
        // address, so no global IPv6 route means no global source address.
        let sock = match UdpSocket::bind("[::]:0") {
            Ok(s) => s,
            Err(e) if matches!(e.kind(), AddrNotAvailable | Unsupported) => return Some(false),
            Err(_) => return None,
        };
        match sock.connect("[2606:4700:4700::1111]:53") {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    NetworkUnreachable | HostUnreachable | AddrNotAvailable | Unsupported
                ) =>
            {
                return Some(false);
            }
            Err(_) => return None,
        }
        match sock.local_addr().ok()?.ip() {
            IpAddr::V6(v6) => Some(is_global_unicast_v6(&v6)),
            IpAddr::V4(_) => None,
        }
    }

    fn system_timezone(&self) -> Result<String, String> {
        iana_time_zone::get_timezone().map_err(|e| e.to_string())
    }

    fn local_utc_offset_secs(&self) -> Option<i32> {
        Some(chrono::Local::now().offset().local_minus_utc())
    }

    #[cfg(unix)]
    fn zone_utc_offset_secs(&self, zone: &str) -> Option<i32> {
        if !is_plain_zone_name(zone) {
            return None;
        }
        // An unknown zone name makes `date` print UTC without any error: look the zone up first.
        let known = [
            "/usr/share/zoneinfo",
            "/var/db/timezone/zoneinfo",
            "/usr/lib/zoneinfo",
        ]
        .iter()
        .any(|root| std::path::Path::new(root).join(zone).is_file());
        if !known {
            return None;
        }
        let out = crate::sysproxy::silent_command("/bin/date")
            .arg("+%z")
            .env("TZ", zone)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_utc_offset(&String::from_utf8_lossy(&out.stdout))
    }

    #[cfg(not(unix))]
    fn zone_utc_offset_secs(&self, _zone: &str) -> Option<i32> {
        // No time zone database on this OS: the offset of an IANA name cannot be computed.
        None
    }

    fn env_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    #[cfg(target_os = "macos")]
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
        let mut found = Vec::new();
        for key in ["AppleLocale", "AppleLanguages"] {
            let out = crate::sysproxy::silent_command("/usr/bin/defaults")
                .args(["read", "-g", key])
                .output()
                .ok()
                .filter(|o| o.status.success());
            if let Some(out) = out {
                found.extend(parse_defaults_values(&String::from_utf8_lossy(&out.stdout)));
            }
        }
        if found.is_empty() {
            Err(SystemReadError::Failed)
        } else {
            Ok(found)
        }
    }

    // Not built locally (cfg(windows)): verified by the Windows CI only.
    #[cfg(target_os = "windows")]
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
        let mut found = Vec::new();
        if let Ok(Some(locale)) = crate::win_reg::get_string(
            crate::win_reg::RootKey::HkeyCurrentUser,
            r"Control Panel\International",
            "LocaleName",
        ) {
            let trimmed = locale.trim();
            if !trimmed.is_empty() {
                found.push(trimmed.to_string());
            }
        }
        if let Ok(Some(langs)) = crate::win_reg::get_multi_sz(
            crate::win_reg::RootKey::HkeyCurrentUser,
            r"Control Panel\International\User Profile",
            "Languages",
        ) {
            found.extend(langs);
        }
        if found.is_empty() {
            Err(SystemReadError::Failed)
        } else {
            Ok(found)
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    #[cfg(target_os = "macos")]
    fn dns_listing(&self) -> Result<String, SystemReadError> {
        run_for_text(crate::sysproxy::silent_command("scutil").arg("--dns"))
    }

    // Not built locally (cfg(windows)): verified by the Windows CI only.
    #[cfg(target_os = "windows")]
    fn dns_listing(&self) -> Result<String, SystemReadError> {
        run_for_text(crate::sysproxy::silent_command("ipconfig").arg("/all"))
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn dns_listing(&self) -> Result<String, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    // Not built locally (cfg(windows)): verified by the Windows CI only.
    #[cfg(target_os = "windows")]
    fn location_consent(&self, machine_wide: bool) -> Result<String, SystemReadError> {
        let (root, subkey) = if machine_wide {
            (
                crate::win_reg::RootKey::HkeyLocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            )
        } else {
            (
                crate::win_reg::RootKey::HkeyCurrentUser,
                r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            )
        };
        match crate::win_reg::get_string(root, subkey, "Value") {
            Ok(Some(val)) if !val.trim().is_empty() => Ok(val),
            _ => Err(SystemReadError::Failed),
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn location_consent(&self, _machine_wide: bool) -> Result<String, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    fn sync_ai_tz_active(&self) -> bool {
        crate::sysproxy::sync_ai_tz_active()
    }
}

/// Stdout of a finished command; a spawn error, a non-zero exit or an empty output is `Failed`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_for_text(cmd: &mut std::process::Command) -> Result<String, SystemReadError> {
    match cmd.output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            if text.trim().is_empty() {
                Err(SystemReadError::Failed)
            } else {
                Ok(text)
            }
        }
        _ => Err(SystemReadError::Failed),
    }
}

/// Values of `reg query` lines: `    LocaleName    REG_SZ    ru-RU` and
/// `    Languages    REG_MULTI_SZ    ru-RU\0en-US`.
#[cfg(any(test, target_os = "windows"))]
pub fn parse_reg_string_values(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(idx) = line.find("REG_") else {
            continue;
        };
        let after = &line[idx..];
        let mut parts = after.splitn(2, char::is_whitespace);
        let _kind = parts.next();
        let value = parts.next().unwrap_or("").trim();
        for item in value.split("\\0") {
            let item = item.trim();
            if !item.is_empty() {
                out.push(item.to_string());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------------------------

/// The sources an [`Auditor`](super::Auditor) works with.
#[derive(Clone)]
pub struct AuditEnv {
    pub dns: Arc<dyn DnsLookup>,
    pub probe: Arc<dyn IpProbe>,
    pub udp: Arc<dyn UdpProbe>,
    pub system: Arc<dyn SystemInfo>,
}

impl AuditEnv {
    /// DNS, HTTP and host of the machine the application runs on.
    pub fn real() -> Self {
        Self {
            dns: Arc::new(SystemDns),
            probe: Arc::new(ReqwestProbe),
            udp: Arc::new(TokioUdp),
            system: Arc::new(RealSystem),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fakes for tests (no network, no processes)
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
pub mod fakes {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Answers by host name; an unlisted host gets `default`. `panic_on` makes a lookup panic.
    pub struct FakeDns {
        pub answers: Mutex<HashMap<String, LookupOutcome>>,
        /// TXT answers by host name; an unlisted host gets `TxtOutcome::Timeout`.
        pub txt_answers: Mutex<HashMap<String, TxtOutcome>>,
        pub default: LookupOutcome,
        pub panic_on: Option<String>,
        pub calls: AtomicUsize,
    }

    impl FakeDns {
        pub fn new(default: LookupOutcome) -> Self {
            Self {
                answers: Mutex::default(),
                txt_answers: Mutex::default(),
                default,
                panic_on: None,
                calls: AtomicUsize::new(0),
            }
        }
        pub fn with(self, host: &str, outcome: LookupOutcome) -> Self {
            self.answers
                .lock()
                .unwrap()
                .insert(host.to_string(), outcome);
            self
        }
        pub fn with_txt(self, host: &str, outcome: TxtOutcome) -> Self {
            self.txt_answers
                .lock()
                .unwrap()
                .insert(host.to_string(), outcome);
            self
        }
        pub fn panicking_on(mut self, host_part: &str) -> Self {
            self.panic_on = Some(host_part.to_string());
            self
        }
    }

    pub fn addr(ip: &str) -> LookupOutcome {
        LookupOutcome::Addrs(vec![ip.parse().unwrap()])
    }

    impl DnsLookup for FakeDns {
        fn lookup<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, LookupOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(p) = &self.panic_on {
                if host.contains(p.as_str()) {
                    panic!("fake resolver panic");
                }
            }
            let out = self
                .answers
                .lock()
                .unwrap()
                .get(host)
                .cloned()
                .unwrap_or_else(|| self.default.clone());
            Box::pin(async move { out })
        }

        fn lookup_txt<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, TxtOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let out = self
                .txt_answers
                .lock()
                .unwrap()
                .get(host)
                .cloned()
                .unwrap_or(TxtOutcome::Timeout);
            Box::pin(async move { out })
        }
    }

    /// The same outcome for every URL, except the ones with a registered part of the URL; counts
    /// the calls.
    pub struct FakeProbe {
        pub outcome: HttpProbeOutcome,
        pub routes: Vec<(String, HttpProbeOutcome)>,
        pub calls: AtomicUsize,
    }

    impl FakeProbe {
        pub fn new(outcome: HttpProbeOutcome) -> Self {
            Self {
                outcome,
                routes: Vec::new(),
                calls: AtomicUsize::new(0),
            }
        }
        /// URLs that contain `url_part` get `outcome` instead of the default one.
        pub fn with_route(mut self, url_part: &str, outcome: HttpProbeOutcome) -> Self {
            self.routes.push((url_part.to_string(), outcome));
            self
        }
        pub fn body(status: u16, body: &str) -> Self {
            Self::new(HttpProbeOutcome::Response {
                status,
                body: body.to_string(),
            })
        }
        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl IpProbe for FakeProbe {
        fn get<'a>(&'a self, url: &'a str, _limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let out = self
                .routes
                .iter()
                .find(|(part, _)| url.contains(part.as_str()))
                .map(|(_, o)| o.clone())
                .unwrap_or_else(|| self.outcome.clone());
            Box::pin(async move { out })
        }
    }

    /// Builds the datagrams a fake server sends back for a request.
    pub type UdpResponder = Box<dyn Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync>;

    /// A UDP "network": per server a responder that gets the request and returns the datagrams
    /// that arrive (in order). A server without a responder stays silent (`Timeout`); the `accept`
    /// filter is applied exactly as the real socket does.
    #[derive(Default)]
    pub struct FakeUdp {
        pub servers: Mutex<HashMap<String, UdpResponder>>,
        pub failing: Mutex<Vec<String>>,
        pub calls: AtomicUsize,
    }

    impl FakeUdp {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn with_server(
            self,
            server: &str,
            responder: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync + 'static,
        ) -> Self {
            self.servers
                .lock()
                .unwrap()
                .insert(server.to_string(), Box::new(responder));
            self
        }
        /// The server name does not resolve / the socket fails.
        pub fn failing_server(self, server: &str) -> Self {
            self.failing.lock().unwrap().push(server.to_string());
            self
        }
        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl UdpProbe for FakeUdp {
        fn exchange<'a>(
            &'a self,
            server: &'a str,
            request: &'a [u8],
            accept: &'a (dyn Fn(&[u8]) -> bool + Send + Sync),
            _limit: Duration,
        ) -> BoxFuture<'a, UdpOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let out = if self.failing.lock().unwrap().iter().any(|s| s == server) {
                UdpOutcome::Failed
            } else {
                let datagrams = self
                    .servers
                    .lock()
                    .unwrap()
                    .get(server)
                    .map(|f| f(request))
                    .unwrap_or_default();
                datagrams
                    .into_iter()
                    .find(|d| accept(d))
                    .map_or(UdpOutcome::Timeout, UdpOutcome::Reply)
            };
            Box::pin(async move { out })
        }
    }

    /// A host with every field set explicitly. `FakeSystem::offline()` fails every read.
    #[derive(Clone)]
    pub struct FakeSystem {
        pub global_ipv6: Option<bool>,
        pub timezone: Result<String, String>,
        pub local_offset: Option<i32>,
        pub zone_offsets: HashMap<String, i32>,
        pub env: HashMap<String, String>,
        pub os_locales: Result<Vec<String>, SystemReadError>,
        pub dns_listing: Result<String, SystemReadError>,
        pub consent_machine: Result<String, SystemReadError>,
        pub consent_user: Result<String, SystemReadError>,
        pub sync_ai_tz: bool,
    }

    impl FakeSystem {
        /// A quiet, working host: NL time zone, English locale, plain DNS, no IPv6, macOS-like
        /// (no location setting).
        pub fn healthy() -> Self {
            Self {
                global_ipv6: Some(false),
                timezone: Ok("Europe/Amsterdam".into()),
                local_offset: Some(3600),
                zone_offsets: HashMap::from([
                    ("Europe/Amsterdam".to_string(), 3600),
                    ("Europe/Berlin".to_string(), 3600),
                ]),
                env: HashMap::from([("LANG".to_string(), "en_US.UTF-8".to_string())]),
                os_locales: Ok(vec!["en_US".into()]),
                dns_listing: Ok("resolver #1\n  nameserver[0] : 1.1.1.1\n".into()),
                consent_machine: Err(SystemReadError::Unsupported),
                consent_user: Err(SystemReadError::Unsupported),
                sync_ai_tz: false,
            }
        }

        /// Every read fails or returns nothing.
        pub fn offline() -> Self {
            Self {
                global_ipv6: None,
                timezone: Err("no tz".into()),
                local_offset: None,
                zone_offsets: HashMap::new(),
                env: HashMap::new(),
                os_locales: Err(SystemReadError::Failed),
                dns_listing: Err(SystemReadError::Failed),
                consent_machine: Err(SystemReadError::Unsupported),
                consent_user: Err(SystemReadError::Unsupported),
                sync_ai_tz: false,
            }
        }
    }

    impl SystemInfo for FakeSystem {
        fn has_global_ipv6(&self) -> Option<bool> {
            self.global_ipv6
        }
        fn system_timezone(&self) -> Result<String, String> {
            self.timezone.clone()
        }
        fn local_utc_offset_secs(&self) -> Option<i32> {
            self.local_offset
        }
        fn zone_utc_offset_secs(&self, zone: &str) -> Option<i32> {
            self.zone_offsets.get(zone).copied()
        }
        fn env_var(&self, name: &str) -> Option<String> {
            self.env.get(name).cloned()
        }
        fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
            self.os_locales.clone()
        }
        fn dns_listing(&self) -> Result<String, SystemReadError> {
            self.dns_listing.clone()
        }
        fn location_consent(&self, machine_wide: bool) -> Result<String, SystemReadError> {
            if machine_wide {
                self.consent_machine.clone()
            } else {
                self.consent_user.clone()
            }
        }
        fn sync_ai_tz_active(&self) -> bool {
            self.sync_ai_tz
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_unicast_is_2000_slash_3() {
        let g: Ipv6Addr = "2606:4700::1".parse().unwrap();
        let ula: Ipv6Addr = "fd00::1".parse().unwrap();
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_global_unicast_v6(&g));
        assert!(!is_global_unicast_v6(&ula));
        assert!(!is_global_unicast_v6(&ll));
        assert!(!is_global_unicast_v6(&Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn utc_offset_parsing() {
        assert_eq!(parse_utc_offset("+0100\n"), Some(3600));
        assert_eq!(parse_utc_offset("-0330"), Some(-12600));
        assert_eq!(parse_utc_offset("+0000"), Some(0));
        assert_eq!(parse_utc_offset("CET"), None);
        assert_eq!(parse_utc_offset("+01"), None);
        assert_eq!(parse_utc_offset("+9900"), None);
    }

    #[test]
    fn defaults_output_parsing() {
        assert_eq!(parse_defaults_values("ru_RU\n"), vec!["ru_RU"]);
        assert_eq!(
            parse_defaults_values("(\n    \"ru-RU\",\n    \"en-RU\"\n)\n"),
            vec!["ru-RU", "en-RU"]
        );
        assert!(parse_defaults_values("\n").is_empty());
    }

    #[test]
    fn reg_output_parsing() {
        let one = "\nHKEY_CURRENT_USER\\Control Panel\\International\n    LocaleName    REG_SZ    ru-RU\n";
        assert_eq!(parse_reg_string_values(one), vec!["ru-RU"]);
        let many = "    Languages    REG_MULTI_SZ    ru-RU\\0en-US\n";
        assert_eq!(parse_reg_string_values(many), vec!["ru-RU", "en-US"]);
    }

    #[test]
    fn zone_names_from_remote_services_are_validated() {
        assert!(is_plain_zone_name("Europe/Amsterdam"));
        assert!(is_plain_zone_name("America/Port-au-Prince"));
        assert!(is_plain_zone_name("Etc/GMT+3"));
        assert!(!is_plain_zone_name(""));
        assert!(!is_plain_zone_name("/etc/passwd"));
        assert!(!is_plain_zone_name("../../etc/passwd"));
        assert!(!is_plain_zone_name("Europe/Amsterdam; rm -rf"));
    }

    #[test]
    fn not_found_is_told_apart_from_a_broken_resolver() {
        use std::io::{Error, ErrorKind};
        let nx = Error::new(
            ErrorKind::Other,
            "failed to lookup address information: nodename nor servname provided, or not known",
        );
        assert!(is_name_not_found(&nx));
        let glibc = Error::new(ErrorKind::Other, "Name or service not known");
        assert!(is_name_not_found(&glibc));
        let broken = Error::new(
            ErrorKind::Other,
            "failed to lookup address information: Temporary failure in name resolution",
        );
        assert!(!is_name_not_found(&broken));
    }

    // The real probe against a loopback listener only (no traffic leaves this machine).
    async fn loopback(response: Option<&'static str>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    match response {
                        Some(r) => {
                            let _ = sock.write_all(r.as_bytes()).await;
                            let _ = sock.shutdown().await;
                        }
                        None => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        format!("http://{addr}/cdn-cgi/trace")
    }

    #[tokio::test]
    async fn reqwest_probe_tells_timeout_from_refused_from_a_response() {
        let silent = loopback(None).await;
        assert_eq!(
            ReqwestProbe.get(&silent, Duration::from_millis(50)).await,
            HttpProbeOutcome::Timeout
        );
        let ok = loopback(Some("HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nloc=NL")).await;
        assert_eq!(
            ReqwestProbe.get(&ok, Duration::from_secs(2)).await,
            HttpProbeOutcome::Response {
                status: 200,
                body: "loc=NL".into()
            }
        );
        // A port nobody listens on.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/", l.local_addr().unwrap())
        };
        let refused = ReqwestProbe.get(&closed, Duration::from_secs(2)).await;
        if cfg!(windows) {
            // Windows retries a refused loopback connect for about two seconds, so the short
            // limit can expire first; either way the probe reports a failure, never a response.
            assert!(
                matches!(refused, HttpProbeOutcome::ConnectFailed | HttpProbeOutcome::Timeout),
                "{refused:?}"
            );
        } else {
            assert_eq!(refused, HttpProbeOutcome::ConnectFailed);
        }
    }

    #[test]
    fn usable_nameserver_filters_unspecified_multicast_link_local_and_fec0_placeholders() {
        use std::net::IpAddr;
        assert!(is_usable_nameserver(&"1.1.1.1".parse::<IpAddr>().unwrap()));
        assert!(is_usable_nameserver(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_usable_nameserver(&"2606:4700:4700::1111".parse::<IpAddr>().unwrap()));
        assert!(!is_usable_nameserver(&"0.0.0.0".parse::<IpAddr>().unwrap()));
        assert!(!is_usable_nameserver(&"::".parse::<IpAddr>().unwrap()));
        assert!(!is_usable_nameserver(&"224.0.0.251".parse::<IpAddr>().unwrap()));
        assert!(!is_usable_nameserver(&"fe80::1".parse::<IpAddr>().unwrap()));
        assert!(!is_usable_nameserver(&"fec0:0:0:ffff::1".parse::<IpAddr>().unwrap()));
        assert!(!is_usable_nameserver(&"fec0:0:0:ffff::2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parse_scutil_dns_prioritizes_reachable_default_resolvers_and_skips_domain_or_unreachable() {
        use std::net::IpAddr;
        let sample = "\
DNS configuration

resolver #1
  nameserver[0] : 10.8.0.1
  nameserver[1] : fec0:0:0:ffff::1
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : corp.local
  nameserver[0] : 10.99.0.1
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #3
  nameserver[0] : 198.51.100.9
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
";
        let got = parse_scutil_dns_nameservers(sample);
        assert_eq!(got, vec!["10.8.0.1".parse::<IpAddr>().unwrap()]);

        let scoped_only = "\
DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
";
        assert_eq!(
            parse_scutil_dns_nameservers(scoped_only),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
    }
}
