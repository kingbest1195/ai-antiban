//! Per-(provider, route) `RiskReport` cache with single-flight coalescing and background refresh.
//!
//! Eliminates synchronous 14-point audit blocking on every incoming `CONNECT` for routed AI traffic
//! (e.g. Gemini's burst of parallel sockets over double-tunnel VPNs) while preserving all security
//! checks (`geo_matrix`, ASN/VPN/Tor reputation, AI Studio stability, and `RouteDownReason`).

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;

use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::{Auditor, RiskReport};
use crate::routing::{Route, RouteSelection, route_fingerprint};
use crate::state::{AppState, AppStateData};

pub(super) const ROUTE_REPORT_FRESH_TTL: Duration = Duration::from_secs(60);
pub(super) const ROUTE_REPORT_BG_REFRESH_AFTER: Duration = Duration::from_secs(30);

type CacheKey = (ProviderId, String);

struct CachedEntry {
    route_fp: u64,
    state_sig: u64,
    stored_at: Instant,
    report: RiskReport,
    refreshing: bool,
}

#[derive(Default)]
pub(super) struct RouteReportCache {
    entries: RwLock<HashMap<CacheKey, CachedEntry>>,
    flights: Mutex<HashMap<CacheKey, Arc<Mutex<()>>>>,
}

fn compute_state_sig(route: &Route, provider: ProviderId, st: &AppStateData) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    route.country.hash(&mut h);
    route.exit_ip.hash(&mut h);
    st.pinned_ip_for_provider(provider.as_str(), true)
        .hash(&mut h);
    st.strict_pinning_enabled.hash(&mut h);
    let mut trusted: Vec<String> = st
        .trusted_exceptions
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(provider.as_str()))
        .flat_map(|(_, ips)| ips.iter().cloned())
        .collect();
    trusted.sort();
    trusted.hash(&mut h);
    h.finish()
}

pub(super) struct RoutedAuditOutcome {
    pub(super) report: RiskReport,
    pub(super) state: AppStateData,
    pub(super) from_cache: bool,
}

impl RouteReportCache {
    async fn flight_lock(&self, key: &CacheKey) -> Arc<Mutex<()>> {
        let mut guard = self.flights.lock().await;
        Arc::clone(
            guard
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    async fn try_get_fresh(
        &self,
        key: &CacheKey,
        route_fp: u64,
        state_sig: u64,
    ) -> Option<(RiskReport, bool)> {
        let guard = self.entries.read().await;
        let entry = guard.get(key)?;
        if entry.route_fp != route_fp || entry.state_sig != state_sig {
            return None;
        }
        let age = entry.stored_at.elapsed();
        if age >= ROUTE_REPORT_FRESH_TTL {
            return None;
        }
        let needs_bg_refresh = age >= ROUTE_REPORT_BG_REFRESH_AFTER && !entry.refreshing;
        Some((entry.report.clone(), needs_bg_refresh))
    }

    async fn invalidate(&self, key: &CacheKey) {
        self.entries.write().await.remove(key);
    }

    async fn store_if_allowed(
        &self,
        key: CacheKey,
        route_fp: u64,
        state_sig: u64,
        report: &RiskReport,
        st: &AppStateData,
    ) {
        if crate::proxy::guard::report_allowed_for_state(report, st, true) {
            self.entries.write().await.insert(
                key,
                CachedEntry {
                    route_fp,
                    state_sig,
                    stored_at: Instant::now(),
                    report: report.clone(),
                    refreshing: false,
                },
            );
        } else {
            self.entries.write().await.remove(&key);
        }
    }

    fn maybe_spawn_bg_refresh(
        self: &Arc<Self>,
        key: CacheKey,
        route_fp: u64,
        route: Route,
        auditor: Auditor,
        state: AppState,
    ) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let cache = Arc::clone(self);
        handle.spawn(async move {
            {
                let mut guard = cache.entries.write().await;
                let Some(entry) = guard.get_mut(&key) else {
                    return;
                };
                if entry.refreshing {
                    return;
                }
                entry.refreshing = true;
            }
            let selection = RouteSelection::Route(route.clone());
            let res = auditor
                .evaluate_all_with(key.0, &state, &selection, false)
                .await;
            match res {
                Ok(report) => {
                    let st_now = state.get_data().await;
                    let sig = compute_state_sig(&route, key.0, &st_now);
                    cache
                        .store_if_allowed(key, route_fp, sig, &report, &st_now)
                        .await;
                }
                Err(_) => {
                    let mut guard = cache.entries.write().await;
                    if let Some(entry) = guard.get_mut(&key) {
                        entry.refreshing = false;
                    }
                }
            }
        });
    }

    /// Returns a fresh cached `RiskReport` for `(provider, route)` or coalesces concurrent callers
    /// into a single `auditor.evaluate_all_with(...)` execution.
    pub(super) async fn get_or_evaluate(
        self: &Arc<Self>,
        auditor: &Auditor,
        state: &AppState,
        provider: ProviderId,
        route: &Route,
        selection: &RouteSelection,
    ) -> Result<RoutedAuditOutcome, String> {
        let key = (provider, route.id.clone());
        let route_fp = route_fingerprint(route);
        let route_marked_down = state
            .route_health()
            .get(&route.id)
            .is_some_and(|h| h.reachable == Some(false));
        if route_marked_down {
            self.invalidate(&key).await;
        } else {
            let st_now = state.get_data().await;
            let sig = compute_state_sig(route, provider, &st_now);
            if let Some((report, needs_bg)) = self.try_get_fresh(&key, route_fp, sig).await {
                if needs_bg {
                    self.maybe_spawn_bg_refresh(
                        key,
                        route_fp,
                        route.clone(),
                        auditor.clone(),
                        state.clone(),
                    );
                }
                return Ok(RoutedAuditOutcome {
                    report,
                    state: st_now,
                    from_cache: true,
                });
            }
        }

        let lock = self.flight_lock(&key).await;
        let _flight_guard = lock.lock().await;

        let route_marked_down = state
            .route_health()
            .get(&route.id)
            .is_some_and(|h| h.reachable == Some(false));
        if !route_marked_down {
            let st_now = state.get_data().await;
            let sig = compute_state_sig(route, provider, &st_now);
            if let Some((report, _)) = self.try_get_fresh(&key, route_fp, sig).await {
                return Ok(RoutedAuditOutcome {
                    report,
                    state: st_now,
                    from_cache: true,
                });
            }
        }

        let report = auditor
            .evaluate_all_with(provider, state, selection, false)
            .await?;
        let st_now = state.get_data().await;
        let sig = compute_state_sig(route, provider, &st_now);
        self.store_if_allowed(key, route_fp, sig, &report, &st_now)
            .await;
        Ok(RoutedAuditOutcome {
            report,
            state: st_now,
            from_cache: false,
        })
    }
}

pub(super) async fn can_soft_bypass_audit(
    auditor: &Auditor,
    state: &AppState,
    route: &Route,
    is_canary: bool,
    err: &str,
) -> bool {
    if is_canary {
        return false;
    }
    let health_ok = state
        .route_health()
        .get(&route.id)
        .is_some_and(|h| h.reachable == Some(true));
    let cached_tel = auditor.resolver.last_known_telemetry_for_route(route).await;
    let geo_ok = !route
        .country
        .as_deref()
        .is_some_and(crate::core::sanctions::is_blocked_geo_code)
        && !cached_tel
            .as_ref()
            .is_some_and(|t| crate::core::sanctions::is_blocked_geo_code(&t.country_code));
    if (health_ok || cached_tel.is_some()) && geo_ok {
        crate::diagnostics::record(
            "proxy:route",
            &format!("route={} phase=audit_soft_bypass err={err}", route.id),
        );
        true
    } else {
        false
    }
}
