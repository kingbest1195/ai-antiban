//! Address policy for entry nodes: resolve once, check every address, connect to the checked one.
//!
//! * Keys that come from outside (`zastava://…`) may only point to public addresses.
//! * Keys the user typed in URL form (`socks5://`, `http://`, `https://`) may also point to
//!   loopback / private addresses: that is the user's own local proxy (Xray, sing-box, …).
//! * Nothing may point back to the gateway itself (loop), and link-local / metadata / multicast /
//!   reserved ranges stay forbidden for everyone.

mod dns;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use super::Entry;
use crate::proxy::server::{
    DEFAULT_PROXY_PORT, FALLBACK_PROXY_PORT, embedded_ipv4, is_forbidden_ip, is_tun_fake_ip,
};
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

/// True when `ip:port` is (or may be) the gateway itself. `gateway_port == 0` means "unknown":
/// then both default gateway ports are assumed.
pub fn is_gateway_loop(ip: &IpAddr, port: u16, gateway_port: u16) -> bool {
    if !is_loopback_or_unspecified(ip) {
        return false;
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EntryCacheKey {
    host: String,
    port: u16,
    allow_local: bool,
    gateway_port: u16,
}

#[derive(Debug, Clone)]
struct CachedEntryAddrs {
    addrs: Vec<SocketAddr>,
    resolved_at: tokio::time::Instant,
    stale: bool,
    last_refresh_attempt: Option<tokio::time::Instant>,
}

#[derive(Default)]
struct EntryDnsCache {
    entries: RwLock<HashMap<EntryCacheKey, CachedEntryAddrs>>,
}

impl EntryDnsCache {
    fn get_within(&self, key: &EntryCacheKey, max_age: Duration) -> Option<Vec<SocketAddr>> {
        let now = tokio::time::Instant::now();
        let guard = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let cached = guard.get(key)?;
        if now.saturating_duration_since(cached.resolved_at) < max_age {
            Some(cached.addrs.clone())
        } else {
            None
        }
    }

    fn insert(&self, key: EntryCacheKey, addrs: Vec<SocketAddr>) {
        let mut guard = self.entries.write().unwrap_or_else(|e| e.into_inner());
        guard.insert(
            key,
            CachedEntryAddrs {
                addrs,
                resolved_at: tokio::time::Instant::now(),
                stale: false,
                last_refresh_attempt: None,
            },
        );
    }

    fn mark_stale_and_claim_refresh(&self, key: &EntryCacheKey, cooldown: Duration) -> bool {
        let now = tokio::time::Instant::now();
        let mut guard = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let Some(cached) = guard.get_mut(key) else {
            return false;
        };
        cached.stale = true;
        let ready = cached
            .last_refresh_attempt
            .is_none_or(|last| now.saturating_duration_since(last) >= cooldown);
        if ready {
            cached.last_refresh_attempt = Some(now);
        }
        ready
    }
}

fn global_entry_dns_cache() -> &'static EntryDnsCache {
    static CACHE: OnceLock<EntryDnsCache> = OnceLock::new();
    CACHE.get_or_init(EntryDnsCache::default)
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
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "entry DNS lookup timed out"))??;
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
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "entry host did not resolve to any address",
        ));
    }
    for a in addrs {
        check_entry_ip(&a.ip(), a.port(), via_hostname, allow_local, gateway_port)
            .map_err(|m| io::Error::new(io::ErrorKind::PermissionDenied, m))?;
    }
    Ok(())
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
            Ok(addrs) if !addrs.is_empty() => Ok(addrs),
            _ => backend.fallback_lookup(&entry.host, entry.port).await,
        };
        if let Ok(addrs) = fresh
            && validate_entry_addrs(&addrs, true, allow_local, gateway_port).is_ok()
        {
            global_entry_dns_cache().insert(key, addrs);
            crate::diagnostics::record(
                "routing:dns",
                &format!("entry {} refreshed asynchronously from stale cache", entry.host),
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
                validate_entry_addrs(&addrs, true, allow_local, gateway_port)?;
                cache.insert(key, addrs.clone());
                return Ok(addrs);
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
            validate_entry_addrs(&addrs, true, allow_local, gateway_port)?;
            cache.insert(key, addrs.clone());
            crate::diagnostics::record(
                "routing:dns",
                &format!(
                    "entry {} resolved via DNS fallback after system lookup failed",
                    entry.host
                ),
            );
            return Ok(addrs);
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
