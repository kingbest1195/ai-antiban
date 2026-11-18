//! Schema v0/v1/v2/v2.2.x migrations, legacy mirror sync, and lenient state.json recovery.

use super::AppState;
use super::schema::{AppStateData, CURRENT_SCHEMA_VERSION, StateError};
use crate::routing::Route;
use std::path::{Path, PathBuf};

impl AppStateData {
    /// Upgrades data loaded from an older `state.json`. Returns true if anything changed.
    pub fn migrate(&mut self, now: u64) -> bool {
        let before = self.clone();
        if self.schema_version < 2
            && let Some(cfg) = self.upstream_proxy.clone()
            && let Some(route) = Route::from_legacy(&cfg, now)
        {
            let id = route.id.clone();
            if !self.routes.iter().any(|r| r.id == id) {
                self.routes.push(route);
            }
            self.legacy_route_id = Some(id.clone());
            if cfg.enabled {
                self.default_route_id = Some(id);
            }
        }
        self.schema_version = self.schema_version.max(CURRENT_SCHEMA_VERSION);
        if let Some(ref ip) = self.pinned_ip {
            let trimmed = ip.trim();
            if !trimmed.is_empty() && !self.pinned_ips.contains_key("default") {
                self.pinned_ips
                    .insert("default".to_string(), trimmed.to_string());
            }
        }
        // Dangling references are deliberately kept: a binding to a missing route is `Missing`
        // (blocked), never silently "direct".
        self.sync_legacy_mirror();
        *self != before
    }

    pub(super) fn has_route(&self, id: &str) -> bool {
        self.routes.iter().any(|r| r.id == id)
    }

    /// True when a provider binding, the default or the profile slot points to `id`.
    pub(super) fn is_route_referenced(&self, id: &str) -> bool {
        self.provider_routes.values().any(|v| v == id)
            || self.default_route_id.as_deref() == Some(id)
            || self.profile_route_id.as_deref() == Some(id)
    }

    /// Id of the route the legacy commands act on: the legacy slot, else the default route.
    pub fn legacy_target_id(&self) -> Option<String> {
        self.legacy_route_id
            .clone()
            .or_else(|| self.default_route_id.clone())
    }

    /// Recomputes `upstream_proxy` from the routes. `enabled` there means "carries default traffic".
    pub fn sync_legacy_mirror(&mut self) {
        let mirror = self.legacy_target_id().and_then(|id| {
            let r = self.routes.iter().find(|r| r.id == id)?;
            let active = r.enabled && self.default_route_id.as_deref() == Some(id.as_str());
            r.to_legacy(active)
        });
        self.upstream_proxy = mirror;
    }

    /// Removes the route itself. Bindings that point to it stay (and become `Missing`, i.e.
    /// the providers are blocked until the user rebinds or unbinds them); only the legacy slot,
    /// which is not a routing reference, is cleared.
    pub(super) fn remove_route_locked(&mut self, id: &str) -> bool {
        let before = self.routes.len();
        self.routes.retain(|r| r.id != id);
        let removed = self.routes.len() != before;
        if self.legacy_route_id.as_deref() == Some(id) {
            self.legacy_route_id = None;
        }
        removed
    }

    /// Removes the legacy route `id` if nothing else references it.
    pub(super) fn gc_legacy_route(&mut self, id: &str) -> bool {
        if self.is_route_referenced(id) || self.legacy_route_id.as_deref() == Some(id) {
            return false;
        }
        self.remove_route_locked(id)
    }
}

impl AppState {
    /// Reads `state.json`; routes that this version cannot parse are moved to `skipped_routes`
    /// instead of failing the whole file.
    pub(super) fn read_state_lenient(path: &Path) -> Result<AppStateData, StateError> {
        let content = std::fs::read_to_string(path)?;
        let mut value: serde_json::Value = serde_json::from_str(&content)?;
        let obj = value
            .as_object_mut()
            .ok_or_else(|| StateError::PathError("state.json is not a JSON object".to_string()))?;
        let routes_value = obj.remove("routes");
        let mut data: AppStateData = serde_json::from_value(value)?;

        let mut candidates: Vec<serde_json::Value> = std::mem::take(&mut data.skipped_routes);
        match routes_value {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(items)) => {
                // Previously skipped routes go last: a newer build may understand them now.
                candidates = items.into_iter().chain(candidates).collect();
            }
            Some(_) => {
                return Err(StateError::PathError(
                    "`routes` is not an array".to_string(),
                ));
            }
        }
        for (i, item) in candidates.into_iter().enumerate() {
            match serde_json::from_value::<Route>(item.clone()) {
                Ok(r) => {
                    if !data.routes.iter().any(|x| x.id == r.id) {
                        data.routes.push(r);
                    }
                }
                Err(_) => {
                    // The error is not printed: serde may quote values of the key.
                    eprintln!(
                        "Warning: route #{i} of state.json is not understood by this version and was skipped"
                    );
                    data.skipped_routes.push(item);
                }
            }
        }
        Ok(data)
    }

    /// Copies an unreadable state file to `state.corrupt-<ts>.json` before it is replaced.
    pub(super) fn keep_corrupt_copy(path: &Path) -> Option<PathBuf> {
        let ts = crate::auditor::network::current_timestamp();
        let mut dest = path.with_file_name(format!("state.corrupt-{ts}.json"));
        let mut n = 1;
        while dest.exists() {
            dest = path.with_file_name(format!("state.corrupt-{ts}-{n}.json"));
            n += 1;
        }
        Self::copy_private(path, &dest).ok().map(|_| dest)
    }
}
