use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::watch;

use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::hold_queue::DEFAULT_HOLD_TTL_SECS;
use crate::state::{AppState, KNOWN_PROVIDERS};

use super::types::{Gate, GuardPauseStatus, Inner, MAX_STALL_SECS, NetworkGuard, PauseMode};

/// Waits until the gate is open. Returns `false` immediately when blocked or stall limit is exceeded.
pub async fn wait_open(rx: &mut watch::Receiver<Gate>) -> bool {
    let fut = async {
        loop {
            match *rx.borrow_and_update() {
                Gate::Open => return true,
                Gate::Blocked => return false,
                Gate::Pending => {}
            }
            if rx.changed().await.is_err() {
                return false;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(MAX_STALL_SECS), fut)
        .await
        .unwrap_or(false)
}

/// Completes as soon as the gate leaves the `Open` state.
pub async fn gate_closed(rx: &mut watch::Receiver<Gate>) {
    loop {
        if *rx.borrow_and_update() != Gate::Open {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}


impl NetworkGuard {
    /// Engages the kill flag and blocks the gate as one step with respect to `set_gate`.
    fn engage_kill(&self) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.kill_tx.send_replace(true);
        self.set_pause_mode_raw(PauseMode::Manual);
        self.set_gate_reason(Some(
            "Включён ручной Kill-Switch — все ИИ-запросы остановлены".to_string(),
        ));
        self.gate_tx.send_replace(Gate::Blocked);
        for tx in self.provider_gates.values() {
            tx.send_replace(Gate::Blocked);
        }
    }

    /// Lifts the kill flag and opens the gate as one step with respect to `set_gate`.
    fn release_kill(&self) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.kill_tx.send_replace(false);
        self.set_pause_mode_raw(PauseMode::None);
        self.set_gate_reason(None);
        self.gate_tx.send_replace(Gate::Open);
        for tx in self.provider_gates.values() {
            tx.send_replace(Gate::Open);
        }
    }

    /// Puts the guard in `PauseMode::UntilNetworkChange`: unrouted AI traffic stays paused
    /// (`Gate::Blocked`) until the network interface/IP changes or `invalidate_cache` clears it.
    /// Does not override an active manual kill-switch.
    pub async fn pause_until_network_change(
        &self,
        state: &AppState,
        reason: Option<String>,
    ) -> GuardPauseStatus {
        if self.is_manual_killswitch() {
            return self.pause_status();
        }
        let cleaned_reason = reason
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "Защита поставлена на паузу до следующей смены сети".to_string());
        self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
        self.set_gate_reason(Some(cleaned_reason.clone()));
        self.abort_active_tunnels();

        let enabled_unrouted = state.enabled_unrouted_providers().await;
        for p in &enabled_unrouted {
            let _ = state.block_provider(p).await;
        }
        let st = state.get_data().await;
        {
            let mut inner = self.inner.lock().await;
            if let (Some(p), Some(env)) = (inner.invalidate_alert(), self.env.get()) {
                env.hold_queue.remove(&p.id).await;
            }
            let current_ip = inner
                .observed_ip
                .clone()
                .or_else(|| inner.baseline.as_ref().map(|b| b.ip.clone()));
            inner.paused_ip = current_ip.clone();
            if inner.handled_ip.is_none() {
                inner.handled_ip = current_ip;
            }
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
        }
        if let Some(env) = self.env.get() {
            self.hide_popup(env);
            env.io.tray_status("red", Some(&cleaned_reason));
        }
        self.pause_status()
    }

    /// Marks `PauseMode::UntilNetworkChange` when an alert is blocked until network change
    /// without clearing `blocked_providers` or overriding explicit target selections.
    pub async fn mark_paused_until_network_change(&self, reason: Option<String>) {
        if self.is_manual_killswitch() {
            return;
        }
        if let Some(r) = reason
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            self.set_gate_reason(Some(r));
        } else if self.gate_reason().is_none() {
            self.set_gate_reason(Some("Защита на паузе до следующей смены сети".to_string()));
        }
        self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
        let mut inner = self.inner.lock().await;
        let current_ip = inner
            .observed_ip
            .clone()
            .or_else(|| inner.pending.as_ref().map(|p| p.target_ip.clone()))
            .or_else(|| inner.handled_ip.clone())
            .or_else(|| inner.baseline.as_ref().map(|b| b.ip.clone()));
        inner.paused_ip = current_ip;
        if let Some(env) = self.env.get() {
            let st = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
        } else {
            self.set_gate(Gate::Blocked);
        }
    }

    pub(super) fn clear_until_network_change_locked(&self, inner: &mut Inner) -> bool {
        if self.is_manual_killswitch() {
            return false;
        }
        let mut pm = self.pause_mode.lock().unwrap_or_else(|p| p.into_inner());
        let was_until_change = *pm == PauseMode::UntilNetworkChange;
        if was_until_change {
            *pm = PauseMode::None;
        }
        drop(pm);
        inner.paused_ip = None;
        if was_until_change {
            self.set_gate_reason(None);
        }
        was_until_change
    }

    /// Clears `PauseMode::UntilNetworkChange` on network change or cache invalidation.
    /// Never lifts a manual kill-switch. Returns `true` when an `UntilNetworkChange` pause was cleared.
    pub async fn clear_pause_on_network_change(
        &self,
        state: Option<&AppState>,
        open_gate_if_blocked: bool,
    ) -> bool {
        if self.is_manual_killswitch() {
            return false;
        }
        let cleared = {
            let mut inner = self.inner.lock().await;
            let cleared = self.clear_until_network_change_locked(&mut inner);
            if cleared {
                inner.handled_ip = None;
            }
            cleared
        };
        if cleared {
            if let Some(st) = state {
                let _ = st.clear_blocked_providers().await;
            }
            if open_gate_if_blocked && self.any_provider_gate_blocked() {
                self.set_gate(Gate::Open);
            }
        }
        cleared
    }

    /// Invalidates cached network telemetry and automatically clears any `UntilNetworkChange` pause.
    pub async fn invalidate_cache_and_clear_pause(
        &self,
        resolver: &crate::auditor::network::NetworkResolver,
        state: Option<&AppState>,
    ) -> bool {
        resolver.invalidate_cache().await;
        self.clear_pause_on_network_change(state, true).await
    }

    /// Clears automatic provider blocks, `PauseMode::UntilNetworkChange`, and pending alerts
    /// when `!is_manual_killswitch()`, opens gates, and triggers an immediate re-audit.
    /// Used when the user clicks "Снять СТОП СЕТИ" in the tray or UI while only automatic blocks
    /// (never the manual kill-switch) are active.
    pub async fn clear_stop_and_reaudit(&self, state: &AppState) {
        if self.is_manual_killswitch() {
            return;
        }
        {
            let mut inner = self.inner.lock().await;
            self.clear_until_network_change_locked(&mut inner);
            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
            if let (Some(p), Some(env)) = (inner.invalidate_alert(), self.env.get()) {
                env.hold_queue.remove(&p.id).await;
            }
            if let Some(env) = self.env.get() {
                env.hold_queue.cancel_all_superseded().await;
            }
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }
        self.set_gate_reason(None);
        let _ = state.clear_blocked_providers().await;
        let st = state.get_data().await;
        self.sync_gates_with_state_and_pending(&st, None);
        if let Some(env) = self.env.get() {
            self.hide_popup(env);
            env.io.tray_status("green", None);
        }
        self.kick_reaudit();
    }

    /// Re-engages a manual kill-switch saved by a previous run (a restart must not lift it).
    /// Returns whether it is engaged.
    pub async fn restore_manual_killswitch(&self, state: &AppState) -> bool {
        if state.is_manual_killswitch_saved().await {
            self.engage_kill();
            true
        } else {
            false
        }
    }

    pub fn is_gate_blocked(&self) -> bool {
        self.gate() == Gate::Blocked
    }

    pub async fn set_manual_killswitch(&self, freeze: bool, state: &AppState) -> bool {
        if freeze {
            self.engage_kill();
            self.abort_active_tunnels();
            if let Err(e) = state.set_manual_killswitch_saved(true).await {
                eprintln!("Warning: could not persist the kill-switch: {e}");
            }
            let mut inner = self.inner.lock().await;
            if let (Some(p), Some(env)) = (inner.invalidate_alert(), self.env.get()) {
                env.hold_queue.remove(&p.id).await;
            }
            drop(inner);
            for p in KNOWN_PROVIDERS {
                let _ = state.block_provider(p).await;
            }
            if let Some(env) = self.env.get() {
                self.hide_popup(env);
                env.io
                    .tray_status("red", Some("⛔ СТОП СЕТИ (Ручная блокировка ИИ)"));
            }
            true
        } else {
            self.release_kill();
            if let Err(e) = state.set_manual_killswitch_saved(false).await {
                eprintln!("Warning: could not persist the kill-switch: {e}");
            }
            let mut inner = self.inner.lock().await;
            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
            if let (Some(p), Some(env)) = (inner.invalidate_alert(), self.env.get()) {
                env.hold_queue.remove(&p.id).await;
            }
            if let Some(env) = self.env.get() {
                env.hold_queue.cancel_all_superseded().await;
            }
            inner.paused_ip = None;
            inner.handled_ip = None;
            inner.needs_reaudit = false;
            drop(inner);
            let _ = state.clear_blocked_providers().await;
            if let Some(env) = self.env.get() {
                self.hide_popup(env);
                env.io.tray_status("green", None);
            }
            false
        }
    }

    pub async fn freeze_for_test(&self) {
        self.set_gate(Gate::Blocked);
        self.abort_active_tunnels();
        if let Some(env) = self.env.get() {
            env.io.show_alert_popup(None);
        }
    }

    pub async fn verify_before_connect(self: &Arc<Self>) -> bool {
        self.ensure_fresh().await;
        self.gate() == Gate::Open
    }

    async fn await_gate_rx(mut rx: watch::Receiver<Gate>) -> Gate {
        let fut = async {
            loop {
                let g = *rx.borrow_and_update();
                if g != Gate::Pending {
                    return g;
                }
                if rx.changed().await.is_err() {
                    return Gate::Blocked;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(DEFAULT_HOLD_TTL_SECS + 15), fut)
            .await
            .unwrap_or(Gate::Blocked)
    }

    /// Used by new CONNECT requests: waits for the user's decision while the gate is pending.
    pub async fn await_decision(&self) -> Gate {
        Self::await_gate_rx(self.gate_tx.subscribe()).await
    }

    /// Waits for a specific provider's gate decision while pending.
    pub async fn await_decision_for(&self, provider: ProviderId) -> Gate {
        Self::await_gate_rx(self.subscribe_for(provider)).await
    }

}
