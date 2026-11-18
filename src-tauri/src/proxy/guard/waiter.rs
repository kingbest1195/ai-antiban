use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;

use crate::auditor::RiskReport;
use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::hold_queue::{DEFAULT_HOLD_TTL_SECS, HoldResolution};
use crate::state::IpHistoryEntry;

use super::policy::{effective_tray_report, is_ip_pinned_for_state};
use super::types::{Baseline, Env, NetworkGuard, PauseMode};

impl NetworkGuard {
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
            let pending = inner.invalidate_alert();
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

            if !to_block.is_empty() && remaining_open.is_empty() && !guard.is_manual_killswitch()
            {
                guard.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                if guard.gate_reason().is_none() {
                    guard.set_gate_reason(Some(
                        "Запросы на паузе до следующей смены сети".to_string(),
                    ));
                }
                inner.paused_ip = inner
                    .observed_ip
                    .clone()
                    .or_else(|| (!target_ip.is_empty()).then_some(target_ip.clone()))
                    .or_else(|| inner.handled_ip.clone());
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
        env.io.hide_alert_popup();
        env.io.emit(
            "interceptor://resolved",
            serde_json::Value::String(String::new()),
        );
    }

    pub(super) async fn update_tray(&self, env: &Env, report: &RiskReport) {
        let st = env.state.get_data().await;
        let is_pinned = is_ip_pinned_for_state(
            &st,
            report.provider,
            &report.telemetry.ip,
        );
        let held = self.any_provider_gate_closed() || !st.blocked_providers.is_empty();
        let tray_report = effective_tray_report(report, held, &st);
        env.io.tray_report(&tray_report, is_pinned, held);
    }

    /// Re-reads the status for the tray in the background (a full audit: 0.3-2 s must never be
    /// spent under `tick_lock` / `inner`). Audits the first enabled provider only.
    pub(super) fn spawn_refresh_tray(self: &Arc<Self>, env: &Env) {
        let guard = Arc::clone(self);
        let env = env.clone();
        tokio::spawn(async move {
            let st = env.state.get_data().await;
            let Some(pid) = st.enabled_providers().into_iter().find_map(ProviderId::from_id) else {
                env.io.tray_status("green", Some("Мониторинг провайдеров отключён"));
                return;
            };
            if let Ok(report) = (env.audit)(pid, false).await {
                guard.update_tray(&env, &report).await;
            }
        });
    }
}
