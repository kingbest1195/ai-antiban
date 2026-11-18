use crate::auditor::RiskReport;
use crate::auditor::geo_matrix::ProviderId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, oneshot};

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
    /// Pending hold was superseded by network recovery or policy/route change; do not block.
    Superseded,
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
    /// Human-readable reason explaining why traffic was held or gated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_reason: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_reason: Option<String>,
}

/// Builds a concise, human-readable `gate_reason` from an audit report and/or network change.
pub fn build_gate_reason(
    report: Option<&RiskReport>,
    network_change: Option<&NetworkChange>,
    is_simulation: bool,
) -> String {
    if is_simulation {
        if let Some(r) = report {
            let top = r
                .checks
                .iter()
                .find(|c| c.status.is_critical())
                .or_else(|| r.checks.iter().find(|c| c.status.is_warning()));
            if let Some(c) = top {
                return format!("Демо-перехват ({}): {}", c.code, c.message);
            }
        }
        if let Some(nc) = network_change
            && let (Some(old_ip), Some(new_ip)) = (nc.old_ip.as_deref(), nc.new_ip.as_deref())
        {
            return format!(
                "Демо-перехват: имитация обрыва VPN ({old_ip} -> {new_ip}) и небезопасного выхода"
            );
        }
        return "Демо-перехват: имитация обрыва VPN и небезопасного выхода".to_string();
    }

    if let Some(r) = report {
        let top_issue = r
            .checks
            .iter()
            .find(|c| c.status.is_critical())
            .or_else(|| {
                if r.geo_result.status.is_critical() {
                    Some(&r.geo_result)
                } else if r.pinning_result.status.is_critical() {
                    Some(&r.pinning_result)
                } else {
                    None
                }
            })
            .or_else(|| r.checks.iter().find(|c| c.status.is_warning()))
            .or_else(|| {
                r.checks
                    .iter()
                    .find(|c| c.status.is_unknown() && !c.is_not_applicable())
            });
        if let Some(c) = top_issue {
            return format!("{}: {}", c.code, c.message);
        }
        if r.incomplete {
            return "Часть проверок безопасности не завершилась — соединение удержано".to_string();
        }
    }

    if let Some(nc) = network_change {
        match (nc.old_country.as_deref(), nc.new_country.as_deref()) {
            (Some(old_cc), Some(new_cc)) if !old_cc.is_empty() && !new_cc.is_empty() => {
                return format!(
                    "Смена сети ({old_cc} -> {new_cc}) — требуется подтверждение безопасности"
                );
            }
            _ if nc.old_ip.is_some() || nc.new_ip.is_some() => {
                return "Смена внешнего IP или сетевого интерфейса — выполняется проверка безопасности"
                    .to_string();
            }
            _ => {}
        }
    }

    "Проверка безопасности сети перед открытием соединения".to_string()
}

fn default_scope() -> String {
    "provider".to_string()
}

fn default_phase() -> String {
    PHASE_READY.to_string()
}

struct HoldEntry {
    provider_id: String,
    senders: Vec<oneshot::Sender<HoldResolution>>,
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
        if let Some(reason) = enriched.gate_reason.as_ref() {
            cur.gate_reason = Some(reason.clone());
        }
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
    pub async fn register(&self, id: String, provider: &str) -> oneshot::Receiver<HoldResolution> {
        let (tx, rx) = oneshot::channel();
        let mut w = self.entries.write().await;
        w.insert(
            id,
            HoldEntry {
                provider_id: provider.to_string(),
                senders: vec![tx],
            },
        );
        rx
    }

    /// Registers a critical provider hold or coalesces onto an already active non-simulation hold
    /// for `provider`. Returns `(hold_id, rx, is_leader)` where `is_leader == true` only for the
    /// connection that created the hold (so callers emit/show the popup once per active hold).
    pub async fn register_or_coalesce_provider(
        &self,
        id: String,
        provider: &str,
    ) -> (String, oneshot::Receiver<HoldResolution>, bool) {
        let (tx, rx) = oneshot::channel();
        let mut w = self.entries.write().await;
        if let Some((existing_id, entry)) = w
            .iter_mut()
            .find(|(k, e)| !k.starts_with("sim-") && e.provider_id == provider)
        {
            entry.senders.push(tx);
            return (existing_id.clone(), rx, false);
        }
        w.insert(
            id.clone(),
            HoldEntry {
                provider_id: provider.to_string(),
                senders: vec![tx],
            },
        );
        (id, rx, true)
    }

    #[cfg(test)]
    pub(crate) async fn active_entry_count(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns `true` when `id` is currently waiting in the hold queue (not yet resolved,
    /// removed, or superseded).
    pub async fn is_active(&self, id: &str) -> bool {
        self.entries.read().await.contains_key(id)
    }

    /// Returns `true` when any real (non-simulation) hold entry is currently active.
    pub async fn has_active_non_sim_holds(&self) -> bool {
        self.entries
            .read()
            .await
            .keys()
            .any(|k| !k.starts_with("sim-"))
    }

    /// Resolves a single held connection (and any coalesced waiters on the same hold ID).
    pub async fn resolve(&self, id: &str, resolution: HoldResolution) -> bool {
        let mut w = self.entries.write().await;
        self.clear_alert_if(id);
        if let Some(entry) = w.remove(id) {
            for tx in entry.senders {
                let _ = tx.send(resolution);
            }
            true
        } else {
            false
        }
    }

    /// Resolves all held connections matching a provider ID.
    pub async fn resolve_all_for_provider(
        &self,
        provider: &str,
        resolution: HoldResolution,
    ) -> usize {
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
                for tx in entry.senders {
                    let _ = tx.send(resolution);
                    resolved += 1;
                }
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

    /// Resolves and drains all currently pending holds as [`HoldResolution::Superseded`]
    /// so orphaned 60s hold timers cannot fire and block providers after network recovery.
    pub async fn cancel_all_superseded(&self) -> usize {
        let mut w = self.entries.write().await;
        let drained: Vec<(String, HoldEntry)> = w.drain().collect();
        let mut resolved = 0;
        for (key, entry) in drained {
            self.clear_alert_if(&key);
            for tx in entry.senders {
                let _ = tx.send(HoldResolution::Superseded);
                resolved += 1;
            }
        }
        *self.alert_slot() = None;
        resolved
    }
}


#[cfg(test)]
#[path = "hold_queue_tests.rs"]
mod tests;
