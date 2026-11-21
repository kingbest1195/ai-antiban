//! Address policy for entry nodes: resolve once, check every address, connect to the checked one.
//!
//! * Keys that come from outside (`zastava://…`) may only point to public addresses.
//! * Keys the user typed in URL form (`socks5://`, `http://`, `https://`) may also point to
//!   loopback / private addresses: that is the user's own local proxy (Xray, sing-box, …).
//! * Nothing may point back to the gateway itself (loop), and link-local / metadata / multicast /
//!   reserved ranges stay forbidden for everyone.

mod cache;
mod dns;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod tests;

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use super::Entry;
use crate::core::net_safety::{
    DEFAULT_PROXY_PORT, FALLBACK_PROXY_PORT, embedded_ipv4, is_alias_port, is_forbidden_ip,
    is_tun_fake_ip,
};
pub use cache::clear_entry_dns_cache;
use cache::{EntryCacheKey, EntryDnsCache, global_entry_dns_cache};
use dns::parallel_fallback_resolve_addrs;

/// DNS lookup limit for entry hosts.
pub const ENTRY_DNS_TIMEOUT: Duration = Duration::from_secs(4);
const SYSTEM_DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1200);
const SYSTEM_DNS_RETRY_TIMEOUT: Duration = Duration::from_millis(800);
const SYSTEM_DNS_RETRY_DELAY: Duration = Duration::from_millis(100);
const ENTRY_DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const ENTRY_DNS_STALE_TTL: Duration = Duration::from_secs(900);
const ENTRY_DNS_EMERGENCY_STALE_TTL: Duration = Duration::from_secs(7200);
const EMERGENCY_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

fn unwrap_embedded(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => embedded_ipv4(v6).map(IpAddr::V4).unwrap_or(*ip),
        IpAddr::V4(_) => *ip,
    }
}

/// Loopback, private (RFC 1918 / ULA) and shared (RFC 6598, e.g. a tailnet) addresses: the
/// "user's own network" that manual URL keys may point to.
pub fn is_user_local_ip(ip: &IpAddr) -> bool {
    match unwrap_embedded(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback() || v4.is_private() || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn is_loopback_or_unspecified(ip: &IpAddr) -> bool {
    match unwrap_embedded(ip) {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// True when `ip:port` is (or may be) the gateway itself or a registered profile alias port.
/// `gateway_port == 0` means "unknown": then both default gateway ports are assumed.
pub fn is_gateway_loop(ip: &IpAddr, port: u16, gateway_port: u16) -> bool {
    if !is_loopback_or_unspecified(ip) {
        return false;
    }
    if is_alias_port(port) {
        return true;
    }
    if gateway_port != 0 {
        port == gateway_port
    } else {
        port == DEFAULT_PROXY_PORT || port == FALLBACK_PROXY_PORT
    }
}

/// Checks one resolved entry address. `via_hostname`: the address came from a DNS name (a TUN
/// FakeIP answer is then acceptable, as for direct connections).
pub fn check_entry_ip(
    ip: &IpAddr,
    port: u16,
    via_hostname: bool,
    allow_local: bool,
    gateway_port: u16,
) -> Result<(), &'static str> {
    if is_gateway_loop(ip, port, gateway_port) {
        return Err("entry node points to the Zastava gateway itself");
    }
    if !is_forbidden_ip(ip) {
        return Ok(());
    }
    if via_hostname && is_tun_fake_ip(ip) {
        return Ok(());
    }
    if allow_local && is_user_local_ip(ip) {
        return Ok(());
    }
    Err("entry node address belongs to a restricted local or reserved network")
}

trait EntryDnsBackend: Send + Sync {
    fn system_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

    fn fallback_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;
}

struct ProdEntryDnsBackend;

impl EntryDnsBackend for ProdEntryDnsBackend {
    fn system_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let resolved = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "entry DNS lookup timed out")
                })??;
            Ok(resolved.collect())
        })
    }

    fn fallback_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move { parallel_fallback_resolve_addrs(host, port).await })
    }
}

fn validate_entry_addrs(
    addrs: &[SocketAddr],
    via_hostname: bool,
    allow_local: bool,
    gateway_port: u16,
) -> io::Result<()> {
    validate_entry_addrs_tagged(addrs, via_hostname, allow_local, gateway_port, None)
}

fn validate_entry_addrs_tagged(
    addrs: &[SocketAddr],
    via_hostname: bool,
    allow_local: bool,
    gateway_port: u16,
    source: Option<&str>,
) -> io::Result<()> {
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "entry host did not resolve to any address",
        ));
    }
    for a in addrs {
        if let Err(reason) =
            check_entry_ip(&a.ip(), a.port(), via_hostname, allow_local, gateway_port)
        {
            let src = source.unwrap_or("literal");
            crate::diagnostics::record(
                "routing:dns",
                &format!(
                    "rejected ip={} port={} source={src} reason={reason}",
                    a.ip(),
                    a.port()
                ),
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{reason} (rejected ip={}, source={src})", a.ip()),
            ));
        }
    }
    Ok(())
}

enum AddrsOutcome {
    Clean(Vec<SocketAddr>),
    FakeIp(Vec<SocketAddr>),
}

fn classify_entry_addrs(
    host: &str,
    addrs: Vec<SocketAddr>,
    allow_local: bool,
    gateway_port: u16,
    source: &str,
) -> io::Result<AddrsOutcome> {
    validate_entry_addrs_tagged(&addrs, true, allow_local, gateway_port, Some(source))?;
    if addrs.iter().any(|a| is_tun_fake_ip(&a.ip())) {
        let fake_ips: Vec<String> = addrs
            .iter()
            .filter(|a| is_tun_fake_ip(&a.ip()))
            .map(|a| a.ip().to_string())
            .collect();
        crate::diagnostics::record(
            "routing:dns",
            &format!(
                "entry {host} got TUN FakeIP [{}] from {source}; querying public DNS/DoH",
                fake_ips.join(",")
            ),
        );
        return Ok(AddrsOutcome::FakeIp(addrs));
    }
    Ok(AddrsOutcome::Clean(addrs))
}

fn spawn_background_dns_refresh(entry: Entry, allow_local: bool, gateway_port: u16) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let key = EntryCacheKey {
            host: entry.host.to_ascii_lowercase(),
            port: entry.port,
            allow_local,
            gateway_port,
        };
        let backend = ProdEntryDnsBackend;
        let fresh = match backend
            .system_lookup(&entry.host, entry.port, SYSTEM_DNS_ATTEMPT_TIMEOUT)
            .await
        {
            Ok(addrs)
                if !addrs.is_empty()
                    && !addrs.iter().any(|a| is_tun_fake_ip(&a.ip()))
                    && validate_entry_addrs(&addrs, true, allow_local, gateway_port).is_ok() =>
            {
                Ok(addrs)
            }
            _ => backend.fallback_lookup(&entry.host, entry.port).await,
        };
        if let Ok(addrs) = fresh
            && !addrs.iter().any(|a| is_tun_fake_ip(&a.ip()))
            && validate_entry_addrs(&addrs, true, allow_local, gateway_port).is_ok()
        {
            global_entry_dns_cache().insert(key, addrs);
            crate::diagnostics::record(
                "routing:dns",
                &format!(
                    "entry {} refreshed asynchronously from stale cache",
                    entry.host
                ),
            );
        }
    });
}

async fn resolve_entry_checked_with(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
    backend: &dyn EntryDnsBackend,
    cache: &EntryDnsCache,
    allow_bg_refresh: bool,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = entry.host.parse::<IpAddr>() {
        let addrs = vec![SocketAddr::new(ip, entry.port)];
        validate_entry_addrs(&addrs, false, allow_local, gateway_port)?;
        return Ok(addrs);
    }

    let key = EntryCacheKey {
        host: entry.host.to_ascii_lowercase(),
        port: entry.port,
        allow_local,
        gateway_port,
    };

    if let Some(cached) = cache.get_within(&key, ENTRY_DNS_CACHE_TTL)
        && validate_entry_addrs(&cached, true, allow_local, gateway_port).is_ok()
    {
        return Ok(cached);
    }

    let mut last_err: Option<io::Error> = None;
    let mut fake_ip_candidate: Option<Vec<SocketAddr>> = None;
    let mut saw_policy_rejection = false;
    for (attempt, attempt_timeout) in [SYSTEM_DNS_ATTEMPT_TIMEOUT, SYSTEM_DNS_RETRY_TIMEOUT]
        .into_iter()
        .enumerate()
    {
        if attempt > 0 {
            if last_err
                .as_ref()
                .is_some_and(|e| e.kind() == io::ErrorKind::TimedOut)
            {
                break;
            }
            tokio::time::sleep(SYSTEM_DNS_RETRY_DELAY).await;
        }
        match backend
            .system_lookup(&entry.host, entry.port, attempt_timeout)
            .await
        {
            Ok(addrs) if !addrs.is_empty() => {
                match classify_entry_addrs(&entry.host, addrs, allow_local, gateway_port, "system")
                {
                    Ok(AddrsOutcome::Clean(clean)) => {
                        cache.insert(key, clean.clone());
                        return Ok(clean);
                    }
                    Ok(AddrsOutcome::FakeIp(fake)) => {
                        fake_ip_candidate = Some(fake);
                        break;
                    }
                    Err(e) => {
                        saw_policy_rejection = true;
                        last_err = Some(e);
                        break;
                    }
                }
            }
            Ok(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::NotFound,
                    "entry host did not resolve to any address",
                ));
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    match backend.fallback_lookup(&entry.host, entry.port).await {
        Ok(addrs) if !addrs.is_empty() => {
            match classify_entry_addrs(&entry.host, addrs, allow_local, gateway_port, "fallback") {
                Ok(AddrsOutcome::Clean(clean)) => {
                    cache.insert(key, clean.clone());
                    crate::diagnostics::record(
                        "routing:dns",
                        &format!(
                            "entry {} resolved via public DNS fallback after system lookup",
                            entry.host
                        ),
                    );
                    return Ok(clean);
                }
                Ok(AddrsOutcome::FakeIp(fake)) => {
                    if fake_ip_candidate.is_none() {
                        fake_ip_candidate = Some(fake);
                    }
                }
                Err(e) => {
                    saw_policy_rejection = true;
                    last_err = Some(e);
                }
            }
        }
        Ok(_) => {
            if last_err.is_none() {
                last_err = Some(io::Error::new(
                    io::ErrorKind::NotFound,
                    "entry host did not resolve to any address",
                ));
            }
        }
        Err(e) => {
            if last_err.is_none() {
                last_err = Some(e);
            }
        }
    }

    if !saw_policy_rejection && let Some(fake) = fake_ip_candidate {
        crate::diagnostics::record(
            "routing:dns",
            &format!(
                "entry {} accepting TUN FakeIP as last resort after public DNS/DoH failed",
                entry.host
            ),
        );
        return Ok(fake);
    }

    if !saw_policy_rejection {
        for (ttl, label, emergency) in [
            (ENTRY_DNS_STALE_TTL, "stale", false),
            (ENTRY_DNS_EMERGENCY_STALE_TTL, "emergency stale", true),
        ] {
            if let Some(stale) = cache.get_within(&key, ttl)
                && validate_entry_addrs(&stale, true, allow_local, gateway_port).is_ok()
            {
                let should_refresh =
                    cache.mark_stale_and_claim_refresh(&key, EMERGENCY_REFRESH_COOLDOWN);
                if emergency && allow_bg_refresh && should_refresh {
                    spawn_background_dns_refresh(entry.clone(), allow_local, gateway_port);
                }
                crate::diagnostics::record(
                    "routing:dns",
                    &format!(
                        "entry {} using {label} cached DNS after lookup failure",
                        entry.host
                    ),
                );
                return Ok(stale);
            }
        }
    }

    let err = last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "entry host did not resolve to any address",
        )
    });
    crate::diagnostics::record(
        "proxy:route",
        &format!("phase=dns host={} err={err}", entry.host),
    );
    Err(err)
}

/// Resolves `host` via public Hickory (`1.1.1.1`/`8.8.8.8`, `use_system_conf = false`)
/// and DoH (`A` + `AAAA`), bypassing system/TUN FakeDNS when possible.
pub async fn resolve_public_dns_ips(host: &str) -> io::Result<Vec<IpAddr>> {
    let addrs = parallel_fallback_resolve_addrs(host, 0).await?;
    Ok(addrs.into_iter().map(|a| a.ip()).collect())
}

/// Resolves the entry host (once) and verifies EVERY returned address. The caller must connect to
/// one of the returned `SocketAddr`s and never resolve the name again.
///
/// Uses a short retry on transient `lookup_host` failures, falls back to parallel `hickory-resolver`
/// and DoH when system DNS fails (e.g. Windows `os error 11001` under TUN VPNs), caches verified
/// results with TTL + stale/emergency-stale fallback, and always enforces [`check_entry_ip`].
pub async fn resolve_entry_checked(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
) -> io::Result<Vec<SocketAddr>> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(res) = test_support::check_test_dns_override(entry, allow_local, gateway_port) {
        return res;
    }
    resolve_entry_checked_with(
        entry,
        allow_local,
        gateway_port,
        &ProdEntryDnsBackend,
        global_entry_dns_cache(),
        true,
    )
    .await
}
