#![cfg(any(test, feature = "test-support"))]

use super::{
    Entry, EntryDnsBackend, EntryDnsCache, resolve_entry_checked_with, validate_entry_addrs_tagged,
};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub type EntryDnsOverrideFn =
    Arc<dyn Fn(&str, u16) -> Option<io::Result<Vec<SocketAddr>>> + Send + Sync>;

static TEST_DNS_OVERRIDE: OnceLock<Mutex<Option<EntryDnsOverrideFn>>> = OnceLock::new();

fn override_slot() -> &'static Mutex<Option<EntryDnsOverrideFn>> {
    TEST_DNS_OVERRIDE.get_or_init(|| Mutex::new(None))
}

pub(super) fn check_test_dns_override(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
) -> Option<io::Result<Vec<SocketAddr>>> {
    let cb = override_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()?;
    let res = cb(&entry.host, entry.port)?;
    Some(match res {
        Ok(addrs) => validate_entry_addrs_tagged(
            &addrs,
            true,
            allow_local,
            gateway_port,
            Some("test_override"),
        )
        .map(|()| addrs),
        Err(e) => Err(e),
    })
}

/// RAII guard installing an offline entry DNS override for [`super::resolve_entry_checked`].
pub struct TestEntryDnsGuard;

impl TestEntryDnsGuard {
    pub fn install(cb: EntryDnsOverrideFn) -> Self {
        *override_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(cb);
        Self
    }
}

impl Drop for TestEntryDnsGuard {
    fn drop(&mut self) {
        *override_slot().lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

struct ClosureDnsBackend<FSys, FPub> {
    system_fn: FSys,
    fallback_fn: FPub,
}

impl<FSys, FPub> EntryDnsBackend for ClosureDnsBackend<FSys, FPub>
where
    FSys: Fn(&str, u16, Duration) -> io::Result<Vec<SocketAddr>> + Send + Sync,
    FPub: Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync,
{
    fn system_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        let res = (self.system_fn)(host, port, timeout);
        Box::pin(async move { res })
    }

    fn fallback_lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        let res = (self.fallback_fn)(host, port);
        Box::pin(async move { res })
    }
}

/// Deterministic offline wrapper around [`resolve_entry_checked_with`] using closure-backed DNS.
pub async fn resolve_entry_checked_with_closures<FSys, FPub>(
    entry: &Entry,
    allow_local: bool,
    gateway_port: u16,
    system_fn: FSys,
    fallback_fn: FPub,
) -> io::Result<Vec<SocketAddr>>
where
    FSys: Fn(&str, u16, Duration) -> io::Result<Vec<SocketAddr>> + Send + Sync,
    FPub: Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync,
{
    let backend = ClosureDnsBackend {
        system_fn,
        fallback_fn,
    };
    let cache = EntryDnsCache::default();
    resolve_entry_checked_with(entry, allow_local, gateway_port, &backend, &cache, false).await
}
