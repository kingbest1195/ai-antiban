//! Per-provider blocks, ephemeral session allowances, trusted IP exceptions, and monitoring toggle.

use super::AppState;
use super::schema::{AppStateData, StateError};
use std::collections::HashSet;

impl AppStateData {
    /// Returns `true` when monitoring/PAC/audits are disabled for `provider`.
    pub fn is_provider_disabled(&self, provider: &str) -> bool {
        let key = canonical_provider_key(provider);
        !key.is_empty()
            && self
                .disabled_providers
                .iter()
                .any(|p| canonical_provider_key(p) == key)
    }

    /// Returns `true` if `(provider, ip)` was persisted in `trusted_exceptions`.
    pub fn is_ip_trusted_for_provider(&self, provider: &str, ip: &str) -> bool {
        let key = canonical_provider_key(provider);
        let norm_ip = normalize_ip_str(ip);
        if key.is_empty() || norm_ip.is_empty() {
            return false;
        }
        self.trusted_exceptions
            .iter()
            .filter(|(k, _)| canonical_provider_key(k) == key)
            .any(|(_, ips)| ips.iter().any(|stored| normalize_ip_str(stored) == norm_ip))
    }
}

impl AppState {
    // --- Session Allowed Providers ("Accept risk & proceed") ---

    pub async fn allow_provider_for_session(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.session_allowed_providers.insert(provider.to_string());
            // An allowed provider is unblocked if previously marked blocked
            w.blocked_providers.remove(provider);
        }
        self.save_async().await
    }

    pub async fn is_provider_session_allowed(&self, provider: &str) -> bool {
        self.inner
            .read()
            .await
            .session_allowed_providers
            .contains(provider)
    }

    pub async fn revoke_session_allowed_provider(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.session_allowed_providers.remove(provider);
        }
        self.save_async().await
    }

    pub async fn clear_session_allowed_providers(&self) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.session_allowed_providers.clear();
        }
        self.save_async().await
    }

    // --- Blocked Providers ("Block requests until network change") ---

    pub async fn block_provider(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.blocked_providers.insert(provider.to_string());
            // When blocked, remove from session allowed
            w.session_allowed_providers.remove(provider);
        }
        self.save_async().await
    }

    pub async fn unblock_provider(&self, provider: &str) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.blocked_providers.remove(provider);
        }
        self.save_async().await
    }

    pub async fn is_provider_blocked(&self, provider: &str) -> bool {
        self.inner.read().await.blocked_providers.contains(provider)
    }

    pub async fn clear_blocked_providers(&self) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.blocked_providers.clear();
        }
        self.save_async().await
    }

    // --- Persistent per-(provider, exit_ip) Trusted Exceptions ---

    pub async fn is_ip_trusted_for_provider(&self, provider: &str, ip: &str) -> bool {
        self.inner
            .read()
            .await
            .is_ip_trusted_for_provider(provider, ip)
    }

    pub async fn add_trusted_exception(&self, provider: &str, ip: &str) -> Result<(), StateError> {
        let key = canonical_provider_key(provider);
        let norm_ip = normalize_ip_str(ip);
        if key.is_empty() || norm_ip.is_empty() {
            return Ok(());
        }
        let changed = {
            let mut w = self.inner.write().await;
            let list = w.trusted_exceptions.entry(key).or_default();
            if list.iter().any(|existing| normalize_ip_str(existing) == norm_ip) {
                false
            } else {
                list.push(norm_ip);
                true
            }
        };
        if changed {
            self.save_async().await
        } else {
            Ok(())
        }
    }

    pub async fn remove_trusted_exception(
        &self,
        provider: &str,
        ip: &str,
    ) -> Result<(), StateError> {
        let key = canonical_provider_key(provider);
        let norm_ip = normalize_ip_str(ip);
        if key.is_empty() || norm_ip.is_empty() {
            return Ok(());
        }
        let changed = {
            let mut w = self.inner.write().await;
            let mut modified = false;
            let matching_keys: Vec<String> = w
                .trusted_exceptions
                .keys()
                .filter(|k| canonical_provider_key(k) == key)
                .cloned()
                .collect();
            for k in matching_keys {
                if let Some(list) = w.trusted_exceptions.get_mut(&k) {
                    let before = list.len();
                    list.retain(|stored| normalize_ip_str(stored) != norm_ip);
                    if list.len() != before {
                        modified = true;
                    }
                    if list.is_empty() {
                        w.trusted_exceptions.remove(&k);
                    }
                }
            }
            modified
        };
        if changed {
            self.save_async().await
        } else {
            Ok(())
        }
    }

    pub async fn clear_trusted_exceptions(
        &self,
        provider: Option<&str>,
    ) -> Result<(), StateError> {
        let changed = {
            let mut w = self.inner.write().await;
            match provider.map(str::trim).filter(|s| !s.is_empty()) {
                Some(p) => {
                    let key = canonical_provider_key(p);
                    let matching_keys: Vec<String> = w
                        .trusted_exceptions
                        .keys()
                        .filter(|k| canonical_provider_key(k) == key)
                        .cloned()
                        .collect();
                    let mut modified = false;
                    for k in matching_keys {
                        if w.trusted_exceptions.remove(&k).is_some() {
                            modified = true;
                        }
                    }
                    modified
                }
                None => {
                    let was_non_empty = !w.trusted_exceptions.is_empty();
                    w.trusted_exceptions.clear();
                    was_non_empty
                }
            }
        };
        if changed {
            self.save_async().await
        } else {
            Ok(())
        }
    }

    /// Clears persisted blocks and ephemeral session allowances for `provider` without touching
    /// persistent `trusted_exceptions` or sibling providers.
    pub async fn clear_provider_blocks_and_session(
        &self,
        provider: &str,
    ) -> Result<(), StateError> {
        let key = canonical_provider_key(provider);
        let changed = {
            let mut w = self.inner.write().await;
            let mut modified = false;
            let raw = provider.trim();
            modified |= w.blocked_providers.remove(&key);
            if !raw.is_empty() {
                modified |= w.blocked_providers.remove(raw);
            }
            modified |= w.session_allowed_providers.remove(&key);
            if !raw.is_empty() {
                modified |= w.session_allowed_providers.remove(raw);
            }
            modified
        };
        if changed {
            self.save_async().await
        } else {
            Ok(())
        }
    }

    /// Removes ephemeral session allowances for `provider` (or all providers when `None`) without
    /// altering `blocked_providers`.
    pub async fn revoke_provider_session_allowance(
        &self,
        provider: Option<&str>,
    ) -> Result<(), StateError> {
        let changed = {
            let mut w = self.inner.write().await;
            match provider {
                Some(p) => {
                    let key = canonical_provider_key(p);
                    let raw = p.trim();
                    let mut modified = w.session_allowed_providers.remove(&key);
                    if !raw.is_empty() {
                        modified |= w.session_allowed_providers.remove(raw);
                    }
                    modified
                }
                None => {
                    let was_non_empty = !w.session_allowed_providers.is_empty();
                    w.session_allowed_providers.clear();
                    was_non_empty
                }
            }
        };
        if changed {
            self.save_async().await
        } else {
            Ok(())
        }
    }

    // --- Per-Provider Monitoring Toggle (`disabled_providers`) ---

    pub async fn is_provider_disabled(&self, provider: &str) -> bool {
        self.inner.read().await.is_provider_disabled(provider)
    }

    pub async fn disabled_providers(&self) -> HashSet<String> {
        self.inner.read().await.disabled_providers.clone()
    }

    pub async fn set_provider_monitoring(
        &self,
        provider: &str,
        enabled: bool,
    ) -> Result<(), StateError> {
        let key = canonical_provider_key(provider);
        if key.is_empty() {
            return Ok(());
        }
        {
            let mut w = self.inner.write().await;
            let raw = provider.trim();
            if enabled {
                w.disabled_providers
                    .retain(|p| canonical_provider_key(p) != key);
            } else {
                w.disabled_providers.insert(key.clone());
                w.blocked_providers.remove(&key);
                if !raw.is_empty() {
                    w.blocked_providers.remove(raw);
                }
            }
        }
        self.save_async().await
    }
}

pub(super) fn canonical_provider_key(provider: &str) -> String {
    let trimmed = provider.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(pid) = crate::auditor::ProviderId::from_id(trimmed) {
        pid.as_str().to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

pub(super) fn normalize_ip_str(ip: &str) -> String {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    trimmed
        .parse::<std::net::IpAddr>()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| trimmed.to_string())
}
