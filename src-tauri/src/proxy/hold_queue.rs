use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::RiskReport;

pub const DEFAULT_HOLD_TTL_SECS: u64 = 60;

/// `RiskInterceptPayload::phase` / `EnrichedPayload::phase`: the window is open, data still loading.
pub const PHASE_DETECTING: &str = "detecting";
/// The report is complete.
pub const PHASE_READY: &str = "ready";
/// The audit failed or timed out; the gate stays closed and the window is not reopened.
pub const PHASE_FAILED: &str = "failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldResolution {
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum InterceptionAction {
    #[serde(alias = "AllowSession")]
    AllowSession,
    #[serde(alias = "BlockUntilNetworkChange")]
    BlockUntilNetworkChange,
    #[serde(alias = "OpenGuideAndBlock")]
    OpenGuideAndBlock,
}

/// Describes a sudden egress-IP change detected by the network guard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkChange {
    pub old_ip: Option<String>,
    pub old_country: Option<String>,
    /// `None` while the new egress IP has not been probed yet.
    #[serde(default)]
    pub new_ip: Option<String>,
    /// `None` until the geo lookup of the new IP has finished.
    #[serde(default)]
    pub new_country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskInterceptPayload {
    pub id: String,
    pub provider: ProviderId,
    pub host: String,
    /// `None` while `phase == "detecting"` (the window is shown before the audit finishes).
    #[serde(default)]
    pub report: Option<RiskReport>,
    pub ttl_seconds: u64,
    /// `"provider"` — single held CONNECT; `"network"` — global pause after IP change.
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default)]
    pub network_change: Option<NetworkChange>,
    #[serde(default)]
    pub is_simulation: bool,
    /// Unix time (ms) when the change was detected.
    #[serde(default)]
    pub detected_at_ms: u64,
    /// `"detecting"` (minimal payload, `report == None`) or `"ready"`.
    #[serde(default = "default_phase")]
    pub phase: String,
}

/// `interceptor://enriched`: data that arrives after the window was already shown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedPayload {
    pub id: String,
    /// Guard epoch of the alert this data belongs to (stale epochs must be ignored).
    pub epoch: u64,
    /// `"ready"` or `"failed"`.
    pub phase: String,
    pub report: Option<RiskReport>,
    pub network_change: NetworkChange,
}

fn default_scope() -> String {
    "provider".to_string()
}

fn default_phase() -> String {
    PHASE_READY.to_string()
}

struct HoldEntry {
    provider_id: String,
    sender: oneshot::Sender<HoldResolution>,
}

#[derive(Clone, Default)]
pub struct HoldQueue {
    entries: Arc<RwLock<HashMap<String, HoldEntry>>>,
    /// Snapshot of the alert the popup currently shows (for `take_pending_alert`): a hidden
    /// window may not have registered its event listeners yet when the first event is emitted.
    alert: Arc<std::sync::Mutex<Option<RiskInterceptPayload>>>,
}

impl HoldQueue {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            alert: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn alert_slot(&self) -> std::sync::MutexGuard<'_, Option<RiskInterceptPayload>> {
        self.alert.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Remembers the alert that was just emitted. Cleared when its hold is resolved or removed.
    pub fn set_alert(&self, payload: RiskInterceptPayload) {
        *self.alert_slot() = Some(payload);
    }

    /// Folds an `interceptor://enriched` update into the remembered alert (same id only).
    pub fn update_alert(&self, enriched: &EnrichedPayload) {
        let mut slot = self.alert_slot();
        let Some(cur) = slot.as_mut().filter(|cur| cur.id == enriched.id) else {
            return;
        };
        cur.phase = enriched.phase.clone();
        cur.report = enriched.report.clone();
        cur.network_change = Some(enriched.network_change.clone());
    }

    /// The alert that is currently waiting for a decision, with all data known so far.
    /// Not consumed: it disappears when the hold is resolved or removed.
    pub fn current_alert(&self) -> Option<RiskInterceptPayload> {
        self.alert_slot().clone()
    }

    fn clear_alert_if(&self, id: &str) {
        let mut slot = self.alert_slot();
        if slot.as_ref().is_some_and(|a| a.id == id) {
            *slot = None;
        }
    }

    /// Registers a connection in the hold queue and returns a receiver to await resolution.
    pub async fn register(
        &self,
        id: String,
        provider: &str,
    ) -> oneshot::Receiver<HoldResolution> {
        let (tx, rx) = oneshot::channel();
        let mut w = self.entries.write().await;
        w.insert(
            id,
            HoldEntry {
                provider_id: provider.to_string(),
                sender: tx,
            },
        );
        rx
    }

    /// Resolves a single held connection by ID.
    pub async fn resolve(&self, id: &str, resolution: HoldResolution) -> bool {
        let mut w = self.entries.write().await;
        self.clear_alert_if(id);
        if let Some(entry) = w.remove(id) {
            let _ = entry.sender.send(resolution);
            true
        } else {
            false
        }
    }

    /// Resolves all held connections matching a provider ID.
    pub async fn resolve_all_for_provider(&self, provider: &str, resolution: HoldResolution) -> usize {
        let mut w = self.entries.write().await;
        let mut resolved = 0;
        let keys_to_remove: Vec<String> = w
            .iter()
            .filter(|(_, entry)| entry.provider_id == provider)
            .map(|(k, _)| k.clone())
            .collect();

        for key in keys_to_remove {
            self.clear_alert_if(&key);
            if let Some(entry) = w.remove(&key) {
                let _ = entry.sender.send(resolution);
                resolved += 1;
            }
        }
        resolved
    }

    /// Removes an entry without sending resolution (e.g. on client abort).
    pub async fn remove(&self, id: &str) {
        let mut w = self.entries.write().await;
        self.clear_alert_if(id);
        w.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connect_hold_and_allow_session() {
        let queue = HoldQueue::new();
        let id = "test-req-1".to_string();

        let rx = queue.register(id.clone(), "anthropic").await;

        let resolved = queue.resolve(&id, HoldResolution::Allow).await;
        assert!(resolved);

        let res = rx.await.expect("channel should resolve");
        assert_eq!(res, HoldResolution::Allow);
    }

    #[tokio::test]
    async fn test_connect_hold_and_block() {
        let queue = HoldQueue::new();
        let id = "test-req-2".to_string();

        let rx = queue.register(id.clone(), "gemini").await;

        let resolved = queue.resolve(&id, HoldResolution::Block).await;
        assert!(resolved);

        let res = rx.await.expect("channel should resolve");
        assert_eq!(res, HoldResolution::Block);
    }

    #[tokio::test]
    async fn test_resolve_all_for_provider() {
        let queue = HoldQueue::new();
        let rx1 = queue.register("req-1".into(), "openai").await;
        let rx2 = queue.register("req-2".into(), "openai").await;
        let rx3 = queue.register("req-3".into(), "anthropic").await;

        let count = queue.resolve_all_for_provider("openai", HoldResolution::Allow).await;
        assert_eq!(count, 2);

        assert_eq!(rx1.await.unwrap(), HoldResolution::Allow);
        assert_eq!(rx2.await.unwrap(), HoldResolution::Allow);

        // Anthropic still in queue
        let res3 = queue.resolve("req-3", HoldResolution::Block).await;
        assert!(res3);
        assert_eq!(rx3.await.unwrap(), HoldResolution::Block);
    }
}
