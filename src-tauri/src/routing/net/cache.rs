use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct EntryCacheKey {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) allow_local: bool,
    pub(super) gateway_port: u16,
}

#[derive(Debug, Clone)]
pub(super) struct CachedEntryAddrs {
    pub(super) addrs: Vec<SocketAddr>,
    pub(super) resolved_at: tokio::time::Instant,
    pub(super) stale: bool,
    pub(super) last_refresh_attempt: Option<tokio::time::Instant>,
}

#[derive(Default)]
pub(super) struct EntryDnsCache {
    pub(super) entries: RwLock<HashMap<EntryCacheKey, CachedEntryAddrs>>,
}

impl EntryDnsCache {
    pub(super) fn get_within(
        &self,
        key: &EntryCacheKey,
        max_age: Duration,
    ) -> Option<Vec<SocketAddr>> {
        let now = tokio::time::Instant::now();
        let guard = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let cached = guard.get(key)?;
        if now.saturating_duration_since(cached.resolved_at) < max_age {
            Some(cached.addrs.clone())
        } else {
            None
        }
    }

    pub(super) fn insert(&self, key: EntryCacheKey, addrs: Vec<SocketAddr>) {
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

    pub(super) fn mark_stale_and_claim_refresh(
        &self,
        key: &EntryCacheKey,
        cooldown: Duration,
    ) -> bool {
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

pub(super) fn global_entry_dns_cache() -> &'static EntryDnsCache {
    static CACHE: OnceLock<EntryDnsCache> = OnceLock::new();
    CACHE.get_or_init(EntryDnsCache::default)
}
