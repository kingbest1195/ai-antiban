//! Route management, per-provider bindings, profile route slots, and legacy upstream compat.

use super::AppState;
use super::schema::{AppStateData, KNOWN_PROVIDERS, StateError, UpstreamProxyConfig};
use crate::routing::{DIRECT_ROUTE_ID, Route, RouteSelection, select_route, select_route_id};

impl AppStateData {
    /// Known providers whose traffic currently goes through a route (fixed exit).
    pub fn routed_providers(&self) -> Vec<&'static str> {
        KNOWN_PROVIDERS
            .into_iter()
            .filter(|p| select_route_id(self, p).is_some())
            .collect()
    }

    /// Known providers whose traffic goes directly through the local network / VPN.
    pub fn unrouted_providers(&self) -> Vec<&'static str> {
        KNOWN_PROVIDERS
            .into_iter()
            .filter(|p| select_route_id(self, p).is_none())
            .collect()
    }

    /// Known providers whose monitoring is currently enabled.
    pub fn enabled_providers(&self) -> Vec<&'static str> {
        KNOWN_PROVIDERS
            .into_iter()
            .filter(|p| !self.is_provider_disabled(p))
            .collect()
    }

    /// Known enabled providers whose traffic goes directly through the local network / VPN.
    pub fn enabled_unrouted_providers(&self) -> Vec<&'static str> {
        KNOWN_PROVIDERS
            .into_iter()
            .filter(|p| !self.is_provider_disabled(p) && select_route_id(self, p).is_none())
            .collect()
    }
}

impl AppState {
    pub async fn get_upstream_proxy(&self) -> Option<UpstreamProxyConfig> {
        self.inner.read().await.upstream_proxy.clone()
    }

    /// Legacy single-proxy setter, implemented on top of routes: `Some` installs the config as the
    /// legacy route (default route when `enabled`), `None` is the legacy "clear" (see
    /// [`Self::clear_legacy_route`]).
    pub async fn set_upstream_proxy(
        &self,
        proxy: Option<UpstreamProxyConfig>,
    ) -> Result<(), StateError> {
        match proxy
            .as_ref()
            .and_then(|cfg| Route::from_legacy(cfg, crate::auditor::network::current_timestamp()))
        {
            Some(route) => self.install_legacy_route(route).await,
            None => self.clear_legacy_route().await,
        }
    }

    /// Installs `route` as the legacy route; it becomes the default route when enabled. Only the
    /// explicit legacy slot is ever replaced, never a route that merely serves as the default; a
    /// replaced legacy route nothing else uses is dropped, as the single slot used to be.
    pub async fn install_legacy_route(&self, route: Route) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            let previous = w.legacy_route_id.clone();
            let id = route.id.clone();
            let enabled = route.enabled;
            Self::upsert_route_locked(&mut w, route, false);
            w.legacy_route_id = Some(id.clone());
            if enabled {
                w.default_route_id = Some(id.clone());
            } else if w.default_route_id.as_deref() == Some(id.as_str()) {
                w.default_route_id = None;
            }
            self.route_health.remove(&id);
            if let Some(prev) = previous.filter(|p| *p != id) {
                if w.default_route_id.as_deref() == Some(prev.as_str()) {
                    w.default_route_id = if enabled { Some(id.clone()) } else { None };
                }
                if w.gc_legacy_route(&prev) {
                    self.route_health.remove(&prev);
                }
            }
            w.sync_legacy_mirror();
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Legacy "clear key": the key stops being the default for unbound providers and its legacy
    /// route is dropped, but ONLY the legacy role goes away. The profile route and explicit
    /// provider bindings are never touched; a route they still use is kept as an ordinary route.
    pub async fn clear_legacy_route(&self) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            match w.legacy_route_id.take() {
                Some(prev) => {
                    if w.default_route_id.as_deref() == Some(prev.as_str()) {
                        w.default_route_id = None;
                    }
                    if w.gc_legacy_route(&prev) {
                        self.route_health.remove(&prev);
                    }
                }
                None => {
                    // Legacy UI showed the default route: detach it, keep the route itself.
                    w.default_route_id = None;
                }
            }
            w.sync_legacy_mirror();
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Legacy toggle: enables the legacy route and makes it the default, or detaches it from the
    /// default slot (so unbound providers go direct, as in v1.3.x). Disabling never changes
    /// anything the profile route or an explicit binding uses.
    pub async fn toggle_legacy_upstream(
        &self,
        enabled: bool,
    ) -> Result<Option<UpstreamProxyConfig>, StateError> {
        let out = {
            let mut w = self.inner.write().await;
            let Some(id) = w.legacy_target_id().filter(|id| w.has_route(id)) else {
                return Ok(None);
            };
            // Used by the profile or an explicit binding: those must not be affected.
            let shared = w.provider_routes.values().any(|v| *v == id)
                || w.profile_route_id.as_deref() == Some(id.as_str());
            if enabled {
                if let Some(r) = w.routes.iter_mut().find(|r| r.id == id) {
                    r.enabled = true;
                }
                w.default_route_id = Some(id.clone());
            } else {
                if w.default_route_id.as_deref() == Some(id.as_str()) {
                    w.default_route_id = None;
                }
                if !shared && let Some(r) = w.routes.iter_mut().find(|r| r.id == id) {
                    r.enabled = false;
                }
            }
            w.legacy_route_id = Some(id);
            w.sync_legacy_mirror();
            self.bump_routing();
            w.upstream_proxy.clone()
        };
        self.save_async().await?;
        Ok(out)
    }

    /// Inserts or replaces (same id) a route. `preserve_enabled`: a re-import of an existing key
    /// must not silently re-enable a route the user disabled.
    fn upsert_route_locked(w: &mut AppStateData, mut route: Route, preserve_enabled: bool) {
        if let Some(existing) = w.routes.iter_mut().find(|r| r.id == route.id) {
            route.added_at = existing.added_at;
            if preserve_enabled {
                route.enabled = existing.enabled;
            }
            *existing = route;
        } else {
            w.routes.push(route);
        }
    }

    pub async fn get_routes(&self) -> Vec<Route> {
        self.inner.read().await.routes.clone()
    }

    pub async fn get_route(&self, id: &str) -> Option<Route> {
        self.inner
            .read()
            .await
            .routes
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    /// Adds or replaces (same id) a route; an existing route keeps its `enabled` flag. No
    /// validation here: keys are validated by the parser.
    pub async fn upsert_route(&self, route: Route) -> Result<String, StateError> {
        if route.id == DIRECT_ROUTE_ID {
            return Err(StateError::PathError(format!(
                "reserved route id: {}",
                route.id
            )));
        }
        let id = route.id.clone();
        {
            let mut w = self.inner.write().await;
            Self::upsert_route_locked(&mut w, route, true);
            w.sync_legacy_mirror();
            self.route_health.remove(&id);
            self.bump_routing();
        }
        self.save_async().await?;
        Ok(id)
    }

    /// Removes a route. Bindings that point to it are NOT cleaned up: they become `Missing` and the
    /// providers stay blocked until the user binds another key or unbinds explicitly
    /// (`bind_provider_route(provider, null)` / `set_default_route(null)`).
    pub async fn remove_route(&self, id: &str) -> Result<bool, StateError> {
        let removed = {
            let mut w = self.inner.write().await;
            let removed = w.remove_route_locked(id);
            w.sync_legacy_mirror();
            self.route_health.remove(id);
            self.bump_routing();
            removed
        };
        self.save_async().await?;
        Ok(removed)
    }

    pub async fn set_route_enabled(&self, id: &str, enabled: bool) -> Result<bool, StateError> {
        let found = {
            let mut w = self.inner.write().await;
            let found = match w.routes.iter_mut().find(|r| r.id == id) {
                Some(r) => {
                    r.enabled = enabled;
                    true
                }
                None => false,
            };
            w.sync_legacy_mirror();
            self.bump_routing();
            found
        };
        self.save_async().await?;
        Ok(found)
    }

    /// Binds a provider (canonical id) to a route (or [`DIRECT_ROUTE_ID`] to force direct even
    /// when `default_route_id` is set), or unbinds it with `None` to inherit `default_route_id`.
    pub async fn bind_provider_route(
        &self,
        provider: &str,
        route_id: Option<&str>,
    ) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            match route_id {
                Some(id) => {
                    if id != DIRECT_ROUTE_ID && !w.has_route(id) {
                        return Err(StateError::PathError(format!("unknown route id: {id}")));
                    }
                    w.provider_routes
                        .insert(provider.to_string(), id.to_string());
                }
                None => {
                    w.provider_routes.remove(provider);
                }
            }
            self.bump_routing();
        }
        self.save_async().await
    }

    pub async fn set_default_route(&self, route_id: Option<&str>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            if let Some(id) = route_id
                && !w.has_route(id)
            {
                return Err(StateError::PathError(format!("unknown route id: {id}")));
            }
            w.default_route_id = route_id.map(str::to_string);
            w.sync_legacy_mirror();
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Sets (or with `None` clears) the route of the active Claude profile; clears any "invalid".
    pub async fn set_profile_route(&self, route_id: Option<String>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            if route_id
                .as_deref()
                .map(|id| !w.has_route(id))
                .unwrap_or(false)
            {
                return Err(StateError::PathError("unknown route id".to_string()));
            }
            w.profile_route_id = route_id;
            w.profile_route_invalid = None;
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Sets `profile_route_id` even if `route_id` no longer exists in `routes` (preserves a
    /// fail-closed `DanglingBinding` / `RouteSelection::Missing` across switches and restarts).
    pub async fn set_profile_route_dangling(&self, route_id: String) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.profile_route_id = Some(route_id);
            w.profile_route_invalid = None;
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Imports the key of the active Claude profile as a route and makes it the profile route, in
    /// one step (the previous profile's route is never left in place). Binding an existing
    /// disabled route activates it (`enabled = true`).
    pub async fn apply_profile_route(&self, mut route: Route) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            route.enabled = true;
            let id = route.id.clone();
            Self::upsert_route_locked(&mut w, route, false);
            w.profile_route_id = Some(id.clone());
            w.profile_route_invalid = None;
            w.sync_legacy_mirror();
            self.route_health.remove(&id);
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Fail-closed state for a profile whose key does not pass validation: no profile route, and
    /// Claude is blocked with `reason` until a valid key (or no key) is applied.
    pub async fn invalidate_profile_route(&self, reason: String) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.profile_route_id = None;
            w.profile_route_invalid = Some(reason.chars().take(300).collect());
            self.bump_routing();
        }
        self.save_async().await
    }

    /// Effective routing decision for `provider` (see `crate::routing` for priorities).
    pub async fn route_selection(&self, provider: &str) -> RouteSelection {
        select_route(&*self.inner.read().await, provider)
    }

    pub async fn routed_providers(&self) -> Vec<&'static str> {
        self.inner.read().await.routed_providers()
    }

    pub async fn unrouted_providers(&self) -> Vec<&'static str> {
        self.inner.read().await.unrouted_providers()
    }

    pub async fn enabled_unrouted_providers(&self) -> Vec<&'static str> {
        self.inner.read().await.enabled_unrouted_providers()
    }

    /// Effective route id for a provider without cloning the route.
    pub async fn route_id_for_provider(&self, provider: &str) -> Option<String> {
        select_route_id(&*self.inner.read().await, provider)
    }
}
