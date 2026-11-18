use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::sync::atomic::Ordering;
#[cfg(test)]
use std::time::{Duration, Instant};

use crate::auditor::geo_matrix::ProviderId;
#[cfg(test)]
use crate::auditor::{Auditor, RiskReport};
use crate::proxy::hold_queue::HoldResolution;
#[cfg(test)]
use crate::proxy::hold_queue::HoldQueue;
use crate::state::AppState;

use super::types::{Env, Gate, Inner, NetworkGuard};
#[cfg(test)]
use super::types::{AuditFn, GuardIo};

impl NetworkGuard {
    pub(super) async fn drain_pending_route_sync_locked(&self, env: Option<&Env>, inner: &mut Inner) {
        let pending_sync: HashMap<String, bool> = {
            let mut map = self
                .pending_route_sync
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            std::mem::take(&mut *map)
        };
        if pending_sync.is_empty() {
            return;
        }
        for (provider, routed) in pending_sync {
            if routed {
                if !self.is_manual_killswitch()
                    && let Some(env) = env
                {
                    let _ = env.state.unblock_provider(&provider).await;
                    let resolved = env
                        .hold_queue
                        .resolve_all_for_provider(&provider, HoldResolution::Superseded)
                        .await;
                    if resolved > 0 && env.hold_queue.current_alert().is_none() {
                        self.hide_popup(env);
                    }
                }
                if let Some(p) = inner.pending.as_mut() {
                    p.affected_providers.retain(|x| *x != provider);
                    p.already_blocked_providers.retain(|x| *x != provider);
                    if p.affected_providers.is_empty()
                        && let Some(env) = env
                    {
                        let old_id = p.id.clone();
                        inner.invalidate_alert();
                        env.hold_queue.remove(&old_id).await;
                        self.hide_popup(env);
                        if !self.is_manual_killswitch() {
                            self.set_gate_reason(None);
                        }
                    }
                }
            } else {
                inner.handled_ip = None;
                inner.last_probe = None;
                inner.needs_reaudit = true;
            }
        }
    }

    /// Synchronises guard gates & audit state when `provider`'s route binding changes.
    /// When `routed == true`, opens `provider`'s gate (respecting manual kill-switch) and queues
    /// pending/blocked state cleanup lock-free so signals are never dropped when `inner` is held.
    /// When `routed == false`, resets gate/handled state and kicks an immediate re-audit so
    /// `provider` does not skip verification after unbinding.
    pub fn sync_provider_route_change(&self, provider: &str, routed: bool) {
        let canonical = ProviderId::from_id(provider).map(|p| p.as_str()).unwrap_or(provider);
        {
            let mut map = self
                .pending_route_sync
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            map.insert(canonical.to_string(), routed);
        }
        if routed {
            self.open_routed_providers(&[canonical]);
            if let Ok(mut inner) = self.inner.try_lock()
                && let Some(p) = inner.pending.as_mut()
            {
                p.affected_providers.retain(|x| *x != canonical);
                p.already_blocked_providers.retain(|x| *x != canonical);
            }
            if self.loop_running.load(Ordering::SeqCst) {
                self.wake_notify.notify_one();
            }
            return;
        }

        self.force_reaudit.store(true, Ordering::SeqCst);
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }
        if !self.is_manual_killswitch()
            && let Some(pid) = ProviderId::from_id(canonical)
            && let Some(tx) = self.provider_gates.get(&pid)
        {
            let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
            if !*self.kill_tx.borrow() {
                if self.env.get().is_some() {
                    tx.send_replace(Gate::Pending);
                } else {
                    tx.send_replace(Gate::Open);
                }
            }
        }
        self.kick_reaudit();
    }

    /// Kicks an immediate background guard check/re-audit (e.g. after route unbind, monitoring
    /// re-enable, or trusted exception removal). Uses an atomic `force_reaudit` flag so the
    /// signal is never dropped even when `self.inner` is actively locked by `check_route_and_tick`.
    pub fn kick_reaudit(&self) {
        self.force_reaudit.store(true, Ordering::SeqCst);
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }
        if self.loop_running.load(Ordering::SeqCst) {
            self.wake_notify.notify_one();
            return;
        }
        if let (Some(env), Some(guard_arc)) = (
            self.env.get().cloned(),
            self.self_weak.get().and_then(Weak::upgrade),
        ) && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                guard_arc.check_route_and_tick(&env).await;
            });
        }
    }

    /// Opens `provider`'s gate and removes it from any active pending alert when monitoring is
    /// disabled for that provider.
    pub async fn sync_provider_disabled(self: &Arc<Self>, provider: &str, state: &AppState) {
        let canonical = ProviderId::from_id(provider).map(|p| p.as_str()).unwrap_or(provider);
        self.open_routed_providers(&[canonical]);
        let mut inner = self.inner.lock().await;
        if let Some(p) = inner.pending.as_mut() {
            p.affected_providers.retain(|x| *x != canonical);
            p.already_blocked_providers.retain(|x| *x != canonical);
            if p.affected_providers.is_empty()
                && let Some(env) = self.env.get()
            {
                let old_id = p.id.clone();
                inner.invalidate_alert();
                env.hold_queue.remove(&old_id).await;
                self.hide_popup(env);
                self.set_gate_reason(None);
            }
        }
        let st = state.get_data().await;
        self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
        if let Some(env) = self.env.get() {
            let resolved = env
                .hold_queue
                .resolve_all_for_provider(canonical, HoldResolution::Superseded)
                .await;
            if resolved > 0 && env.hold_queue.current_alert().is_none() {
                self.hide_popup(env);
            }
            self.spawn_refresh_tray(env);
        }
    }

    /// Marks `needs_reaudit` and wakes the guard when a provider's monitoring is re-enabled.
    pub async fn sync_provider_monitoring_enabled(&self, _provider: &str) {
        self.force_reaudit.store(true, Ordering::SeqCst);
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }
        self.kick_reaudit();
    }

    /// Opens per-provider gates for providers that just moved onto a fixed route without
    /// disturbing unrouted providers' gates. Respects the manual kill-switch.
    pub fn open_routed_providers(&self, routed: &[&str]) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        if *self.kill_tx.borrow() {
            return;
        }
        for pid_str in routed {
            if let Some(pid) = ProviderId::from_id(pid_str)
                && let Some(tx) = self.provider_gates.get(&pid)
            {
                tx.send_replace(Gate::Open);
            }
        }
        if self
            .provider_gates
            .values()
            .all(|tx| *tx.borrow() == Gate::Open)
        {
            self.gate_tx.send_replace(Gate::Open);
        }
    }

    /// Test seam: sets the gate directly (e.g. `Pending`, which only a real network change sets).
    #[cfg(test)]
    pub(crate) fn set_gate_for_test(&self, gate: Gate) {
        self.set_gate(gate);
    }

    #[cfg(test)]
    pub(crate) fn install_noop_env_for_test(
        &self,
        auditor: Auditor,
        state: AppState,
        hold_queue: Arc<HoldQueue>,
    ) {
        struct NoopIo;
        impl GuardIo for NoopIo {
            fn emit(&self, _event: &str, _payload: serde_json::Value) {}
            fn show_alert_popup(&self, _timing: Option<(String, Instant)>) {}
            fn hide_alert_popup(&self) {}
            fn tray_report(&self, _report: &RiskReport, _is_pinned: bool, _has_blocked: bool) {}
            fn tray_status(&self, _color: &str, _title: Option<&str>) {}
        }
        let audit: AuditFn = Arc::new(|_provider, _force| {
            Box::pin(async move { Err("noop test audit".to_string()) })
        });
        let _ = self.install_env(Env {
            auditor,
            state,
            hold_queue,
            io: Arc::new(NoopIo),
            audit,
            probe: None,
            resolve: None,
            audit_timeout: Duration::from_secs(1),
        });
    }

    #[cfg(test)]
    pub(crate) async fn restore_for_test(self: &Arc<Self>) {
        if let Some(env) = self.env.get() {
            let mut inner = self.inner.lock().await;
            self.restore_locked(env, &mut inner).await;
        }
    }

    #[cfg(test)]
    pub(crate) fn bump_restore_epoch_for_test(&self) {
        self.restore_epoch.fetch_add(1, Ordering::SeqCst);
    }

}
