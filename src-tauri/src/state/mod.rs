//! Application state facade, re-exporting schema, persistence, stats, pinning, routes,
//! exceptions, and settings.

mod exceptions;
mod migration;
mod persistence;
mod pinning;
mod routes;
mod schema;
mod settings;
mod stats;

use std::path::PathBuf;
#[cfg(test)]
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{RwLock, watch};

use crate::routing::RouteHealthRegistry;
#[cfg(test)]
use crate::routing::{DIRECT_ROUTE_ID, RouteSelection, select_route, select_route_id};

pub use persistence::init_app_state;
pub use pinning::{ip_history_key_for_selection, ip_history_scope_key};
pub use schema::{
    AppStateData, CURRENT_SCHEMA_VERSION, CliMode, DEFAULT_IP_CHANGE_COOLDOWN_SECS,
    InterceptionBehavior, IpHistoryEntry, KNOWN_PROVIDERS, MAX_HISTORY_ENTRIES_PER_PROVIDER,
    PROVIDER_ANTHROPIC, PROVIDER_GEMINI, PROVIDER_OPENAI, PopupPosition, STATE_FILE_NAME,
    STATE_V1_BACKUP_NAME, StateError, UpstreamProxyConfig,
};
pub use stats::{GatewayStatsSnapshot, GatewayStatsTracker, RecentGatewayEvent, TunnelGuard};

/// Thread-safe wrapper for persistent application state.
pub type AppContext = AppState;

#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppStateData>>,
    storage_path: Option<PathBuf>,
    save_lock: Arc<tokio::sync::Mutex<()>>,
    stats: Arc<GatewayStatsTracker>,
    route_health: Arc<RouteHealthRegistry>,
    /// Routing generation: bumped by every change that can alter which route a provider uses (or
    /// the route itself). Established tunnels watch it and re-check their provider's selection.
    routing_gen: Arc<watch::Sender<u64>>,
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
