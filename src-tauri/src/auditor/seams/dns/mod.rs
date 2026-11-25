//! DNS lookup traits and cache-bypassing OS resolver implementation.

mod hickory;
mod scutil;
#[cfg(target_os = "windows")]
mod win;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use super::BoxFuture;
use hickory::{hickory_a_query, hickory_ptr_query, hickory_txt_query};
#[cfg(target_os = "macos")]
use scutil::macos_scutil_nameservers;
#[cfg(any(target_os = "macos", test))]
pub(crate) use scutil::parse_scutil_dns_nameservers;

const DNS_DIAG_DEDUP_TTL: Duration = Duration::from_secs(300);
const DNS_DIAG_MAX_ENTRIES: usize = 64;

static DNS_DIAG_CACHE: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LAST_SCUTIL_NAMESERVER_SIG: LazyLock<Mutex<String>> =
    LazyLock::new(|| Mutex::new(String::new()));

pub fn nameserver_signature(ips: &[IpAddr]) -> String {
    if ips.is_empty() {
        return "none".to_string();
    }
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn last_known_nameserver_sig() -> String {
    LAST_SCUTIL_NAMESERVER_SIG
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[cfg(target_os = "macos")]
fn set_last_known_nameserver_sig(sig: &str) {
    let mut guard = LAST_SCUTIL_NAMESERVER_SIG
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if guard.as_str() != sig {
        *guard = sig.to_string();
    }
}

fn txt_outcome_tag(outcome: &TxtOutcome) -> &'static str {
    match outcome {
        TxtOutcome::Records(_) => "Records",
        TxtOutcome::NotFound => "NotFound",
        TxtOutcome::Timeout => "Timeout",
        TxtOutcome::Failed => "Failed",
        TxtOutcome::Unsupported => "Unsupported",
    }
}

pub fn should_record_dns_diag_in(
    cache: &Mutex<HashMap<String, Instant>>,
    stage: &str,
    host: &str,
    outcome: &TxtOutcome,
    nameserver_sig: &str,
    now: Instant,
) -> bool {
    let key = format!(
        "{stage}|{host}|{}|{nameserver_sig}",
        txt_outcome_tag(outcome)
    );
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    guard.retain(|_, ts| now.saturating_duration_since(*ts) < DNS_DIAG_DEDUP_TTL);
    if let Some(&prev) = guard.get(&key)
        && now.saturating_duration_since(prev) < DNS_DIAG_DEDUP_TTL
    {
        return false;
    }
    if guard.len() >= DNS_DIAG_MAX_ENTRIES {
        guard.clear();
    }
    guard.insert(key, now);
    true
}

fn clear_dns_diag_for_host(cache: &Mutex<HashMap<String, Instant>>, host: &str) {
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    let needle = format!("|{host}|");
    guard.retain(|k, _| !k.contains(&needle));
}

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

    /// Reverse DNS PTR lookup for `ip`. Returns `None` if unavailable or NXDOMAIN.
    fn reverse_ptr<'a>(&'a self, ip: IpAddr) -> BoxFuture<'a, Option<String>> {
        let _ = ip;
        Box::pin(async { None })
    }
}

/// The operating system resolver (`getaddrinfo`) and cache-bypassing DNS queries.
pub struct SystemDns;

impl SystemDns {
    /// Performs an uncached reverse DNS PTR lookup for `ip`.
    pub async fn reverse_ptr(&self, ip: IpAddr) -> Option<String> {
        tokio::time::timeout(
            Duration::from_millis(2000),
            system_ptr_lookup(ip, Duration::from_millis(1500)),
        )
        .await
        .ok()
        .flatten()
    }
}

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

    fn reverse_ptr<'a>(&'a self, ip: IpAddr) -> BoxFuture<'a, Option<String>> {
        Box::pin(async move { SystemDns::reverse_ptr(self, ip).await })
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

/// One cache-bypassing A query through the OS resolvers (`DnsQuery_W` on Windows,
/// `scutil --dns` / system configuration on macOS), matching `system_txt_lookup` so both whoami
/// probes hit the same live resolver.
async fn system_a_lookup(host: &str, limit: Duration) -> LookupOutcome {
    let name = format!("{}.", host.trim_end_matches('.'));
    let started = std::time::Instant::now();
    let per_try = Duration::from_millis((limit.as_millis() as u64 / 2).clamp(800, 1250));

    #[cfg(target_os = "windows")]
    if let Some(outcome) = win::windows_native_lookup(
        &name,
        per_try.max(Duration::from_millis(1200)),
        win::win_dns::query_a,
    )
    .await
        && matches!(outcome, LookupOutcome::Addrs(_) | LookupOutcome::NotFound)
    {
        return outcome;
    }

    #[cfg(target_os = "macos")]
    {
        let scutil_ips = macos_scutil_nameservers().await;
        set_last_known_nameserver_sig(&nameserver_signature(&scutil_ips));
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
    if let Some(outcome) = win::windows_native_lookup(
        &name,
        per_try.max(Duration::from_millis(1200)),
        win::win_dns::query_txt,
    )
    .await
        && matches!(outcome, TxtOutcome::Records(_) | TxtOutcome::NotFound)
    {
        return outcome;
    }

    #[cfg(target_os = "macos")]
    let ns_sig = {
        let scutil_ips = macos_scutil_nameservers().await;
        let sig = nameserver_signature(&scutil_ips);
        set_last_known_nameserver_sig(&sig);
        if !scutil_ips.is_empty() {
            let outcome = hickory_txt_query(&name, per_try, Some(&scutil_ips)).await;
            if matches!(outcome, TxtOutcome::Records(_)) {
                clear_dns_diag_for_host(&DNS_DIAG_CACHE, host);
                return outcome;
            }
            if matches!(outcome, TxtOutcome::NotFound) {
                return outcome;
            }
            if should_record_dns_diag_in(
                &DNS_DIAG_CACHE,
                "scutil",
                host,
                &outcome,
                &sig,
                Instant::now(),
            ) {
                crate::diagnostics::record(
                    "auditor:dns",
                    &format!(
                        "scutil TXT lookup for {host} via {} servers returned {outcome:?}, trying fallback",
                        scutil_ips.len()
                    ),
                );
            }
            let remaining = limit.saturating_sub(started.elapsed());
            if remaining < Duration::from_millis(250) {
                return outcome;
            }
        }
        sig
    };
    #[cfg(not(target_os = "macos"))]
    let ns_sig = "system".to_string();

    let remaining = limit.saturating_sub(started.elapsed());
    let fallback_try = Duration::from_millis((remaining.as_millis() as u64 / 2).clamp(400, 1000));
    let outcome = hickory_txt_query(&name, fallback_try, None).await;
    if matches!(outcome, TxtOutcome::Records(_)) {
        clear_dns_diag_for_host(&DNS_DIAG_CACHE, host);
    } else if should_record_dns_diag_in(
        &DNS_DIAG_CACHE,
        "system",
        host,
        &outcome,
        &ns_sig,
        Instant::now(),
    ) {
        crate::diagnostics::record(
            "auditor:dns",
            &format!("system TXT lookup for {host} finished with {outcome:?}"),
        );
    }
    outcome
}

async fn system_ptr_lookup(ip: IpAddr, limit: Duration) -> Option<String> {
    let started = std::time::Instant::now();

    #[cfg(target_os = "macos")]
    {
        let per_try = Duration::from_millis((limit.as_millis() as u64 / 2).clamp(600, 1200));
        let scutil_ips = macos_scutil_nameservers().await;
        if !scutil_ips.is_empty() {
            if let Some(ptr) = hickory_ptr_query(ip, per_try, Some(&scutil_ips)).await {
                return Some(ptr);
            }
            if limit.saturating_sub(started.elapsed()) < Duration::from_millis(250) {
                return None;
            }
        }
    }

    let remaining = limit.saturating_sub(started.elapsed());
    let fallback_try = Duration::from_millis((remaining.as_millis() as u64 / 2).clamp(400, 1000));
    hickory_ptr_query(ip, fallback_try, None).await
}

/// `getaddrinfo` reports NXDOMAIN and a broken resolver through the same error type; only the
/// well-known "name does not exist" wordings (and the Windows codes) count as `NotFound`, every
/// other error stays `Failed` (never read as "not listed").
pub(super) fn is_name_not_found(e: &std::io::Error) -> bool {
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

#[cfg(test)]
mod tests;
