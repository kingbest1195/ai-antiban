//! IP pinning and scoped exit-IP history management.

use super::AppState;
use super::schema::{AppStateData, IpHistoryEntry, MAX_HISTORY_ENTRIES_PER_PROVIDER, StateError};
use crate::routing::{DIRECT_ROUTE_ID, INVALID_PROFILE_ROUTE_ID, RouteSelection, select_route};
use std::collections::HashMap;

impl AppStateData {
    /// True when `pinned_ips` has a non-empty explicit per-provider entry for `provider`.
    pub fn has_explicit_pinned_ip(&self, provider: &str) -> bool {
        self.pinned_ips
            .get(provider)
            .map(String::as_str)
            .map(str::trim)
            .is_some_and(|s| !s.is_empty())
    }

    /// Returns the pinned IP that applies to `provider`.
    ///
    /// When `is_routed` is `true` (provider is routed via a bound Zastava key), only an explicit
    /// entry in `pinned_ips[provider]` is returned — it never falls back to `"default"` or the
    /// global `pinned_ip`. When `is_routed` is `false` (Direct / VPN), it checks
    /// `pinned_ips[provider]`, then `pinned_ips["default"]`, then legacy `pinned_ip`.
    pub fn pinned_ip_for_provider(&self, provider: &str, is_routed: bool) -> Option<&str> {
        if let Some(ip) = self
            .pinned_ips
            .get(provider)
            .map(String::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(ip);
        }
        if is_routed {
            return None;
        }
        self.pinned_ips
            .get("default")
            .map(String::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.pinned_ip
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
    }

    /// Key into `ip_history` for `provider` under `selection`.
    pub fn ip_history_key_for_selection(
        &self,
        provider: &str,
        selection: &RouteSelection,
    ) -> String {
        ip_history_key_for_selection(provider, selection)
    }

    /// Key into `ip_history` for `provider` using its current route selection.
    pub fn ip_history_key_for_provider(&self, provider: &str) -> String {
        let selection = select_route(self, provider);
        ip_history_key_for_selection(provider, &selection)
    }

    /// Returns the scoped IP history slice for `(provider, selection)`.
    /// Does not fall back to legacy unscoped keys so switching routes never inherits stale hops.
    pub fn ip_history_for_selection(
        &self,
        provider: &str,
        selection: &RouteSelection,
    ) -> Vec<IpHistoryEntry> {
        let key = ip_history_key_for_selection(provider, selection);
        self.ip_history.get(&key).cloned().unwrap_or_default()
    }

    /// Returns the scoped IP history for `provider` under its active route selection.
    pub fn ip_history_for_provider(&self, provider: &str) -> Vec<IpHistoryEntry> {
        let key = self.ip_history_key_for_provider(provider);
        self.ip_history.get(&key).cloned().unwrap_or_default()
    }
}

impl AppState {
    pub async fn get_pinned_ip(&self) -> Option<String> {
        self.inner.read().await.pinned_ip.clone()
    }

    pub async fn set_pinned_ip(&self, ip: Option<String>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            let cleaned = ip
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            w.pinned_ip = cleaned.clone();
            match cleaned {
                Some(val) => {
                    w.pinned_ips.insert("default".to_string(), val);
                }
                None => {
                    w.pinned_ips.remove("default");
                }
            }
        }
        self.save_async().await
    }

    pub async fn get_pinned_ips(&self) -> HashMap<String, String> {
        self.inner.read().await.pinned_ips.clone()
    }

    pub async fn has_explicit_pinned_ip(&self, provider: &str) -> bool {
        self.inner.read().await.has_explicit_pinned_ip(provider)
    }

    /// Sets or clears a pinned IP for a specific scope (`"default"` or provider ID such as
    /// `"anthropic"`, `"openai"`, `"gemini"`). Updating `"default"` keeps `pinned_ip` in sync
    /// for backwards compatibility.
    pub async fn set_pinned_ip_for(&self, key: &str, ip: Option<String>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            let cleaned = ip
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            match cleaned.clone() {
                Some(val) => {
                    w.pinned_ips.insert(key.to_string(), val);
                }
                None => {
                    w.pinned_ips.remove(key);
                }
            }
            if key == "default" {
                w.pinned_ip = cleaned;
            }
        }
        self.save_async().await
    }

    pub async fn clear_all_pinned_ips(&self) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.pinned_ip = None;
            w.pinned_ips.clear();
        }
        self.save_async().await
    }

    /// Appends a new IP history entry for the given provider, keeping at most 10 recent entries.
    /// Repeated sightings of the same IP/country only refresh the timestamp of the last entry
    /// (and are persisted at most once per minute) so busy sessions don't flood the disk.
    pub async fn record_ip_history(
        &self,
        provider: &str,
        entry: IpHistoryEntry,
    ) -> Result<(), StateError> {
        let mut should_save = true;
        {
            let mut w = self.inner.write().await;
            let history = w.ip_history.entry(provider.to_string()).or_default();

            let same_as_last = history
                .last()
                .map(|l| l.ip == entry.ip && l.country_code == entry.country_code)
                .unwrap_or(false);

            if same_as_last {
                if let Some(last) = history.last_mut() {
                    should_save = entry.timestamp.saturating_sub(last.timestamp) >= 60;
                    last.timestamp = last.timestamp.max(entry.timestamp);
                }
            } else {
                history.push(entry);
                if history.len() > MAX_HISTORY_ENTRIES_PER_PROVIDER {
                    let overflow = history.len() - MAX_HISTORY_ENTRIES_PER_PROVIDER;
                    history.drain(0..overflow);
                }
            }
        }
        if should_save {
            self.save_async().await
        } else {
            Ok(())
        }
    }

    /// Appends an IP history entry scoped to `(provider, selection)`.
    pub async fn record_ip_history_for_selection(
        &self,
        provider: &str,
        selection: &RouteSelection,
        entry: IpHistoryEntry,
    ) -> Result<(), StateError> {
        let key = ip_history_key_for_selection(provider, selection);
        self.record_ip_history(&key, entry).await
    }

    pub async fn get_ip_history(&self, provider: &str) -> Vec<IpHistoryEntry> {
        self.inner
            .read()
            .await
            .ip_history
            .get(provider)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn get_ip_history_for_selection(
        &self,
        provider: &str,
        selection: &RouteSelection,
    ) -> Vec<IpHistoryEntry> {
        let key = ip_history_key_for_selection(provider, selection);
        self.get_ip_history(&key).await
    }

    pub async fn get_last_ip_history(&self, provider: &str) -> Option<IpHistoryEntry> {
        self.inner
            .read()
            .await
            .ip_history
            .get(provider)
            .and_then(|h| h.last().cloned())
    }

    pub async fn clear_ip_history_for_provider(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            let prefix = format!("{provider}::");
            for (k, h) in w.ip_history.iter_mut() {
                if k == provider || k.starts_with(&prefix) {
                    h.clear();
                }
            }
        }
        self.save_async().await
    }
}

/// Returns the canonical `AppStateData::ip_history` key for `(provider, route_id)`.
/// Direct / VPN traffic (`None` or `DIRECT_ROUTE_ID`) uses `"{provider}::direct"`;
/// routed traffic uses `"{provider}::route:{route_id}"`.
pub fn ip_history_scope_key(provider: &str, route_id: Option<&str>) -> String {
    match route_id.filter(|id| !id.is_empty() && *id != DIRECT_ROUTE_ID) {
        Some(id) => format!("{provider}::route:{id}"),
        None => format!("{provider}::direct"),
    }
}

/// Returns the canonical `AppStateData::ip_history` key for `(provider, selection)`.
pub fn ip_history_key_for_selection(provider: &str, selection: &RouteSelection) -> String {
    match selection {
        RouteSelection::Direct => ip_history_scope_key(provider, None),
        RouteSelection::Route(r) => ip_history_scope_key(provider, Some(&r.id)),
        RouteSelection::Missing(id) => ip_history_scope_key(provider, Some(id)),
        RouteSelection::Invalid(_) => {
            ip_history_scope_key(provider, Some(INVALID_PROFILE_ROUTE_ID))
        }
    }
}
