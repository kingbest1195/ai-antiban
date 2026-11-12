pub mod coverage;
pub mod guard;
pub mod hold_queue;
pub mod http_forward;
pub mod pac;
pub mod route_watch;
pub mod server;
pub mod transit;
pub mod upstream;

use std::sync::Arc;
pub use coverage::{
    classify_process_name, lookup_process_name_by_port, AppCoverageItem, CoverageSnapshot,
    CoverageTracker,
};
pub use guard::{Gate, GuardCtx, NetworkGuard, ALL_PROVIDERS};
pub use hold_queue::{HoldQueue, HoldResolution, InterceptionAction, RiskInterceptPayload};
pub use pac::generate_pac_script;
pub use server::ProxyServer;
pub use transit::Transit;
pub use upstream::{connect_via_upstream, parse_upstream_key};
use crate::auditor::Auditor;
use crate::state::AppState;

#[derive(Clone)]
pub struct ProxyManager {
    pub server: Arc<ProxyServer>,
    pub hold_queue: Arc<HoldQueue>,
    pub guard: Arc<NetworkGuard>,
    pub coverage: Arc<CoverageTracker>,
}

impl ProxyManager {
    pub async fn start(
        auditor: Auditor,
        state: AppState,
        app_handle: Option<tauri::AppHandle>,
    ) -> Result<Self, std::io::Error> {
        let hold_queue = Arc::new(HoldQueue::new());
        let server = Arc::new(
            ProxyServer::bind(auditor, state, Arc::clone(&hold_queue), app_handle).await?,
        );
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
        })
    }
}
