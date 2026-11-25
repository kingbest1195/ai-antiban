use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;

use crate::auditor::RiskReport;
use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::hold_queue::{DEFAULT_HOLD_TTL_SECS, HoldResolution};
use crate::state::IpHistoryEntry;

use super::policy::{effective_tray_report, is_ip_pinned_for_state};
use super::types::{Baseline, Env, Gate, GuardPauseStatus, NetworkGuard, PauseMode};

impl NetworkGuard {
    pub fn pause_status(&self) -> GuardPauseStatus {
        let mode = self.pause_mode();
        let manual_killswitch = self.is_manual_killswitch();
        let gate = match self.gate() {
            Gate::Open => "open",
            Gate::Pending => "pending",
            Gate::Blocked => "blocked",
        }
        .to_string();
        let mut pending_providers = Vec::new();
        let mut blocked_providers = Vec::new();
        for (pid, tx) in &self.provider_gates {
            let g = if manual_killswitch {
                Gate::Blocked
            } else {
                *tx.borrow()
            };
            match g {
                Gate::Pending => pending_providers.push(pid.as_str().to_string()),
                Gate::Blocked => blocked_providers.push(pid.as_str().to_string()),
                Gate::Open => {}
            }
        }
        pending_providers.sort();
        blocked_providers.sort();
        let has_active_risk_alert = self
            .env
            .get()
            .and_then(|env| env.hold_queue.current_alert())
            .is_some_and(|a| {
                !a.is_simulation
                    && (a.phase == crate::proxy::hold_queue::PHASE_READY
                        || a.phase == crate::proxy::hold_queue::PHASE_FAILED)
            });
        GuardPauseStatus {
            paused: mode != PauseMode::None,
            mode,
            gate,
            gate_reason: self.gate_reason(),
            manual_killswitch,
            pending_providers,
            blocked_providers,
            has_active_risk_alert,
        }
    }

    pub(super) fn emit_pause_status(&self) {
        if let Some(env) = self.env.get() {
            let status = self.pause_status();
            env.io.tray_guard_status(&status);
            env.emit("guard://pause-status-changed", &status);
        }
    }
    /// Waits for the user's decision (or the hold TTL) and applies it, unless the alert was
    /// superseded meanwhile. Anything but an explicit `Allow` blocks ONLY `affected` (critical /
    /// blocked-geo / failed) providers, never `healthy` (including `Yellow`) providers.
    pub(super) fn spawn_decision_waiter(
        self: &Arc<Self>,
        env: &Env,
        id: String,
        epoch: u64,
        rx: oneshot::Receiver<HoldResolution>,
    ) {
        let guard = Arc::clone(self);
        let env = env.clone();
        tokio::spawn(async move {
            let res = tokio::time::timeout(Duration::from_secs(DEFAULT_HOLD_TTL_SECS), rx).await;
            if matches!(res, Ok(Ok(HoldResolution::Superseded))) {
                return;
            }
            let allow = matches!(res, Ok(Ok(HoldResolution::Allow)));

            let mut inner = guard.inner.lock().await;
            if !inner.is_current(&id, epoch) {
                return; // superseded by a newer change or already accepted/restored
            }
            let was_detecting_unresolved = inner.probe_in_flight
                || inner.route_dirty
                || inner
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.target_ip.is_empty());
            let pending = if !allow && was_detecting_unresolved {
                inner.invalidate_alert_keep_probe()
            } else {
                inner.invalidate_alert()
            };
            env.hold_queue.remove(&id).await;
            let (tel, target_ip, clear_old_state, affected, already_blocked, healthy) =
                match pending {
                    Some(p) => (
                        p.tel,
                        p.target_ip,
                        p.clear_old_state,
                        p.affected_providers,
                        p.already_blocked_providers,
                        p.healthy_providers,
                    ),
                    None => (
                        None,
                        String::new(),
                        None,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ),
                };
            if let Some(clear) = clear_old_state {
                // The old network's clean-up lands before anything this decision writes.
                let _ = clear.await;
            }

            // An allow is honoured only for a network that was audited (telemetry known). An
            // allow before / without the audit is NOT a decision about anything the user saw.
            if allow {
                if let Some(tel) = tel {
                    let ip = inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone());
                    if already_blocked.is_empty() {
                        guard.accept_locked(&env, &mut inner, &ip, &tel).await;
                        return;
                    }
                    let now = crate::auditor::network::current_timestamp();
                    for p in affected.iter().chain(healthy.iter()) {
                        let _ = env.state.allow_provider_for_session(p).await;
                        if !guard.is_manual_killswitch() {
                            let _ = env.state.unblock_provider(p).await;
                        }
                        let entry = IpHistoryEntry::new(
                            tel.ip.clone(),
                            tel.country_code.clone(),
                            tel.asn,
                            now,
                        );
                        let _ = env
                            .state
                            .record_ip_history_for_selection(
                                p,
                                &crate::routing::RouteSelection::Direct,
                                entry,
                            )
                            .await;
                    }
                    for p in &already_blocked {
                        let _ = env.state.block_provider(p).await;
                    }
                    inner.baseline = Some(Baseline {
                        ip,
                        country: Some(tel.country_code.clone()),
                        trusted: true,
                    });
                    inner.handled_ip = None;
                    inner.needs_reaudit = false;
                    guard.clear_until_network_change_locked(&mut inner);
                    guard.set_gate_reason(None);
                    let st_after = env.state.get_data().await;
                    guard.sync_gates_with_state_and_pending(&st_after, None);
                    guard.hide_popup(&env);
                    env.emit("network://changed", &());
                    guard.spawn_refresh_tray(&env);
                    return;
                }
                eprintln!("Network guard: allow without a finished audit, traffic stays blocked");
            }
            let st = env.state.get_data().await;
            let enabled_unrouted = st.enabled_unrouted_providers();
            let to_block: Vec<&'static str> = affected
                .iter()
                .copied()
                .filter(|p| enabled_unrouted.contains(p))
                .collect();
            for p in &to_block {
                let _ = env.state.block_provider(p).await;
            }
            for p in &already_blocked {
                if enabled_unrouted.contains(p) && !st.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            let st_after = env.state.get_data().await;
            let remaining_open: Vec<&'static str> = enabled_unrouted
                .iter()
                .copied()
                .filter(|p| !st_after.blocked_providers.contains(*p))
                .collect();

            if !to_block.is_empty() && remaining_open.is_empty() && !guard.is_manual_killswitch() {
                guard.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                if guard.gate_reason().is_none() {
                    guard.set_gate_reason(Some(
                        "Запросы на паузе до следующей смены сети".to_string(),
                    ));
                }
                guard.bind_pause_ip_locked(
                    &mut inner,
                    Some(target_ip.as_str()),
                    was_detecting_unresolved,
                );
            } else if to_block.is_empty() && !guard.is_manual_killswitch() {
                guard.clear_until_network_change_locked(&mut inner);
                if remaining_open.len() == enabled_unrouted.len() {
                    guard.set_gate_reason(None);
                }
                if let Some(ref tel) = tel {
                    let ip = inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone());
                    inner.baseline = Some(Baseline {
                        ip,
                        country: Some(tel.country_code.clone()),
                        trusted: true,
                    });
                    inner.handled_ip = None;
                }
            }
            guard.sync_gates_with_state_and_pending(&st_after, None);
            guard.hide_popup(&env);
            if !to_block.is_empty() {
                env.emit("network://changed", &());
            }
            guard.spawn_refresh_tray(&env);
        });
    }

    pub(super) fn hide_popup(&self, env: &Env) {
        if env
            .hold_queue
            .current_alert()
            .is_some_and(|a| a.scope == "checkout")
        {
            return;
        }
        env.io.hide_alert_popup();
        env.io.emit(
            "interceptor://resolved",
            serde_json::Value::String(String::new()),
        );
    }

    pub(super) async fn update_tray(&self, env: &Env, report: &RiskReport) {
        let st = env.state.get_data().await;
        if self.is_manual_killswitch()
            || self.is_paused()
            || self.any_provider_gate_pending()
            || self.any_provider_gate_blocked()
            || !st.blocked_providers.is_empty()
        {
            let mut status = self.pause_status();
            if !self.is_manual_killswitch() && !st.blocked_providers.is_empty() {
                for p in &st.blocked_providers {
                    if !status.blocked_providers.contains(p) {
                        status.blocked_providers.push(p.clone());
                    }
                }
                status.blocked_providers.sort();
            }
            env.io.tray_guard_status(&status);
            return;
        }
        let is_pinned = is_ip_pinned_for_state(&st, report.provider, &report.telemetry.ip);
        let tray_report = effective_tray_report(report, false, &st);
        env.io.tray_report(&tray_report, is_pinned, false);
    }

    /// Re-reads the status for the tray in the background (a full audit: 0.3-2 s must never be
    /// spent under `tick_lock` / `inner`). Audits the first enabled provider only.
    pub(super) fn spawn_refresh_tray(self: &Arc<Self>, env: &Env) {
        let guard = Arc::clone(self);
        let env = env.clone();
        tokio::spawn(async move {
            if guard.is_manual_killswitch()
                || guard.is_paused()
                || guard.any_provider_gate_pending()
            {
                env.io.tray_guard_status(&guard.pause_status());
                return;
            }
            let st = env.state.get_data().await;
            let Some(pid) = st
                .enabled_providers()
                .into_iter()
                .find_map(ProviderId::from_id)
            else {
                if guard.is_manual_killswitch() || guard.is_paused() {
                    env.io.tray_guard_status(&guard.pause_status());
                } else {
                    env.io
                        .tray_status("green", Some("Мониторинг провайдеров отключён"));
                }
                return;
            };
            if let Ok(report) = (env.audit)(pid, false).await {
                guard.update_tray(&env, &report).await;
            }
        });
    }

    #[cfg(any(test, feature = "test-support"))]
    pub async fn refresh_tray_with_report_for_test(&self, report: &RiskReport) {
        if let Some(env) = self.env.get() {
            self.update_tray(env, report).await;
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn trigger_refresh_tray_for_test(self: &Arc<Self>) {
        if let Some(env) = self.env.get() {
            self.spawn_refresh_tray(env);
        }
    }

    /// Returns the newly affected providers for an active network alert `id`, if present.
    pub async fn affected_providers_for_alert(&self, id: &str) -> Option<Vec<String>> {
        let mut inner = self.inner.lock().await;
        self.drain_pending_route_sync_locked(self.env.get(), &mut inner)
            .await;
        inner
            .pending
            .as_ref()
            .filter(|p| p.id == id)
            .map(|p| p.affected_providers.iter().map(|s| s.to_string()).collect())
    }
}
