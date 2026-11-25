//! Keeps an established tunnel honest about its route.
//!
//! A tunnel is admitted with a snapshot of the provider's [`RouteSelection`] (the same snapshot the
//! audit used). From then on any change of the effective routing of that provider — another route,
//! a disabled / removed / replaced route, a different profile, a binding that appeared or
//! disappeared — ends the tunnel, direct tunnels included. A route that expires while a tunnel is
//! open ends it too (checked on a timer).

use std::time::Duration;

use tokio::sync::watch;

use crate::auditor::geo_matrix::ProviderId;
use crate::routing::{Route, RouteSelection, route_fingerprint};
use crate::state::AppState;

/// How often an open tunnel re-checks `expires_at` of its route.
pub const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(30);

pub struct RouteWatch {
    state: AppState,
    provider: ProviderId,
    snapshot: RouteSelection,
    rx: watch::Receiver<u64>,
}

impl RouteWatch {
    /// Subscribes to routing changes. Call [`Self::is_stale`] right after to cover a change that
    /// happened between the moment the snapshot was taken and now.
    pub fn new(state: &AppState, provider: ProviderId, snapshot: RouteSelection) -> Self {
        Self {
            state: state.clone(),
            provider,
            snapshot,
            rx: state.subscribe_routing(),
        }
    }

    /// True when the provider's effective selection changed in transport identity (route id, entry
    /// nodes, or local-entry policy), or the current route can no longer carry traffic (disabled /
    /// expired). Metadata-only refreshes (`expires_at`, `grace_extended`, `label`, etc.) keep
    /// live active tunnels open.
    pub async fn is_stale(&self) -> bool {
        let current = self.state.route_selection(self.provider.as_str()).await;
        match (&self.snapshot, &current) {
            (RouteSelection::Direct, RouteSelection::Direct) => false,
            (RouteSelection::Route(snap), RouteSelection::Route(curr)) => {
                !same_transport_identity(snap, curr)
                    || curr
                        .check_usable(crate::auditor::network::current_timestamp())
                        .is_err()
            }
            // Never keep a tunnel on mismatched selection or Missing/Invalid states.
            _ => true,
        }
    }

    /// Completes when the tunnel must be torn down. Cancel-safe.
    pub async fn stale(&mut self) {
        loop {
            tokio::select! {
                changed = self.rx.changed() => {
                    if changed.is_err() {
                        // The state is gone: nothing can change any more.
                        std::future::pending::<()>().await;
                    }
                    if self.is_stale().await {
                        return;
                    }
                }
                _ = tokio::time::sleep(EXPIRY_CHECK_INTERVAL) => {
                    if self.is_stale().await {
                        return;
                    }
                }
            }
        }
    }
}

pub(crate) fn same_transport_identity(a: &Route, b: &Route) -> bool {
    a.id == b.id
        && a.entries == b.entries
        && route_fingerprint(a) == route_fingerprint(b)
        && a.allows_local_entries() == b.allows_local_entries()
}
