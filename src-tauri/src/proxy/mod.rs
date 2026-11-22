pub mod allow_error;
pub mod coverage;
pub mod guard;
pub mod hold_queue;
pub mod http_forward;
pub mod pac;
pub mod popup_port;
pub mod route_watch;
pub mod server;
pub mod transit;
pub mod upstream;

use crate::auditor::Auditor;
use crate::state::AppState;
pub use allow_error::{AllowError, AllowErrorCode};
pub use coverage::{
    AppCoverageItem, CoverageSnapshot, CoverageTracker, classify_process_name,
    lookup_process_name_by_port,
};
pub use guard::{ALL_PROVIDERS, Gate, GuardCtx, NetworkGuard};
pub use hold_queue::{
    CheckoutRiskAlert, HoldQueue, HoldResolution, InterceptionAction, RiskInterceptPayload,
};
pub use pac::generate_pac_script;
pub use server::ProxyServer;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
pub use transit::Transit;
pub use upstream::{connect_via_upstream, parse_upstream_key};

struct AliasHandle {
    port: u16,
    route_id: Option<String>,
    stop_tx: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

async fn stop_alias_handle(handle: AliasHandle) {
    let _ = handle.stop_tx.send(true);
    let mut task = handle.task;
    if tokio::time::timeout(std::time::Duration::from_millis(100), &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
    crate::core::net_safety::unregister_alias_port(handle.port);
}

#[derive(Clone)]
pub struct ProxyManager {
    pub server: Arc<ProxyServer>,
    pub hold_queue: Arc<HoldQueue>,
    pub guard: Arc<NetworkGuard>,
    pub coverage: Arc<CoverageTracker>,
    aliases: Arc<Mutex<HashMap<String, AliasHandle>>>,
}

impl ProxyManager {
    pub async fn start(
        auditor: Auditor,
        state: AppState,
        app_handle: Option<tauri::AppHandle>,
    ) -> Result<Self, std::io::Error> {
        let hold_queue = Arc::new(HoldQueue::new());
        let server =
            Arc::new(ProxyServer::bind(auditor, state, Arc::clone(&hold_queue), app_handle).await?);
        let guard = Arc::clone(&server.guard);
        let coverage = Arc::clone(&server.coverage);

        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            srv.run().await;
        });

        Ok(Self {
            server,
            hold_queue,
            guard,
            coverage,
            aliases: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn from_server(server: Arc<ProxyServer>) -> Self {
        let hold_queue = Arc::clone(&server.hold_queue);
        let guard = Arc::clone(&server.guard);
        let coverage = Arc::clone(&server.coverage);
        Self {
            server,
            hold_queue,
            guard,
            coverage,
            aliases: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Ensures a loopback alias listener is running for `profile_id` bound to `bound_route_id`.
    /// If an alias already exists for a different route, it is stopped and replaced.
    pub async fn ensure_profile_alias(
        &self,
        profile_id: &str,
        bound_route_id: Option<String>,
    ) -> Result<u16, String> {
        self.ensure_profile_alias_preferred(profile_id, bound_route_id, None)
            .await
    }

    /// Ensures a loopback alias listener is running for `profile_id` bound to `bound_route_id`,
    /// preferring `preferred_port` (or the previously bound alias port on route rebind) if free.
    pub async fn ensure_profile_alias_preferred(
        &self,
        profile_id: &str,
        bound_route_id: Option<String>,
        preferred_port: Option<u16>,
    ) -> Result<u16, String> {
        let mut guard = self.aliases.lock().await;
        if let Some(existing) = guard.get(profile_id)
            && existing.route_id == bound_route_id
            && !existing.task.is_finished()
        {
            return Ok(existing.port);
        }

        let mut desired_port = preferred_port;
        if let Some(old) = guard.remove(profile_id) {
            if desired_port.is_none() {
                desired_port = Some(old.port);
            }
            stop_alias_handle(old).await;
        }

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let alias_srv = Arc::new(
            self.server
                .bind_alias_on(bound_route_id.clone(), desired_port, Some(stop_rx))
                .await
                .map_err(|e| {
                    format!("Не удалось запустить локальный прокси-алиас песочницы: {e}")
                })?,
        );
        let port = alias_srv.bound_addr.port();
        let srv_for_task = Arc::clone(&alias_srv);
        let task = tokio::spawn(async move {
            srv_for_task.run().await;
        });

        guard.insert(
            profile_id.to_string(),
            AliasHandle {
                port,
                route_id: bound_route_id,
                stop_tx,
                task,
            },
        );
        Ok(port)
    }

    /// Stops and unregisters the loopback alias listener for `profile_id`, if active.
    pub async fn stop_profile_alias(&self, profile_id: &str) {
        let mut guard = self.aliases.lock().await;
        if let Some(old) = guard.remove(profile_id) {
            stop_alias_handle(old).await;
        }
    }

    /// Stops and unregisters all loopback alias listeners bound to `route_id`.
    pub async fn stop_aliases_for_route(&self, route_id: &str) {
        let mut guard = self.aliases.lock().await;
        let matching: Vec<String> = guard
            .iter()
            .filter(|(_, h)| h.route_id.as_deref() == Some(route_id))
            .map(|(k, _)| k.clone())
            .collect();
        for profile_id in matching {
            if let Some(old) = guard.remove(&profile_id) {
                stop_alias_handle(old).await;
            }
        }
    }

    pub async fn get_profile_alias_port(&self, profile_id: &str) -> Option<u16> {
        let guard = self.aliases.lock().await;
        guard
            .get(profile_id)
            .filter(|h| !h.task.is_finished())
            .map(|h| h.port)
    }
}
