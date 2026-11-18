use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::auditor::NetworkTelemetry;
use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::allow_error::{AllowError, AllowErrorCode};
use crate::state::IpHistoryEntry;

use super::types::{ALL_PROVIDERS, Baseline, Env, Gate, Inner, NetworkGuard};

impl NetworkGuard {
    /// Confirms the current network as the new trusted baseline and resumes traffic.
    pub(super) async fn accept_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        ip: &str,
        tel: &NetworkTelemetry,
    ) {
        self.restore_epoch.fetch_add(1, Ordering::SeqCst);
        inner.baseline = Some(Baseline {
            ip: ip.to_string(),
            country: Some(tel.country_code.clone()),
            trusted: true,
        });
        inner.handled_ip = None;
        inner.needs_reaudit = false;
        self.clear_until_network_change_locked(inner);
        if !self.is_manual_killswitch() {
            self.set_gate_reason(None);
        }
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        env.hold_queue.cancel_all_superseded().await;

        // Only enabled unrouted providers record Direct IP history.
        let now = crate::auditor::network::current_timestamp();
        for p in env.state.enabled_unrouted_providers().await {
            let entry = IpHistoryEntry::new(tel.ip.clone(), tel.country_code.clone(), tel.asn, now);
            let _ = env
                .state
                .record_ip_history_for_selection(p, &crate::routing::RouteSelection::Direct, entry)
                .await;
        }

        if !self.is_manual_killswitch() {
            let _ = env.state.clear_blocked_providers().await;
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
        } else {
            self.set_gate(Gate::Blocked);
        }
        self.hide_popup(env);
        env.emit("network://changed", &());
        self.spawn_refresh_tray(env);
    }

    /// Opens the guard gate (when not under a manual kill-switch) after a single provider was
    /// verified and unblocked, without touching remaining entries in `blocked_providers`.
    pub async fn ensure_open_for_verified(self: &Arc<Self>, tel: &NetworkTelemetry) {
        let Some(env) = self.env.get() else {
            return;
        };
        if self.is_manual_killswitch() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        inner.handled_ip = None;
        inner.needs_reaudit = false;
        self.clear_until_network_change_locked(&mut inner);
        self.set_gate_reason(None);
        inner.baseline = Some(Baseline {
            ip: tel.ip.clone(),
            country: Some(tel.country_code.clone()),
            trusted: true,
        });
        let st = env.state.get_data().await;
        self.sync_gates_with_state_and_pending(&st, None);
        if !self.any_provider_gate_closed() && st.blocked_providers.is_empty() {
            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
            env.hold_queue.cancel_all_superseded().await;
        }
        self.hide_popup(env);
    }

    /// The previous (trusted) or fully healthy/excepted network is active: resume traffic.
    pub(super) async fn restore_locked(self: &Arc<Self>, env: &Env, inner: &mut Inner) {
        self.restore_epoch.fetch_add(1, Ordering::SeqCst);
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        env.hold_queue.cancel_all_superseded().await;
        inner.handled_ip = None;
        inner.needs_reaudit = false;
        self.clear_until_network_change_locked(inner);
        if !self.is_manual_killswitch() {
            self.set_gate_reason(None);
        }
        env.auditor.resolver.invalidate_direct_cache().await;
        if !self.is_manual_killswitch() {
            let _ = env.state.clear_blocked_providers().await;
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
        } else {
            self.set_gate(Gate::Blocked);
        }
        self.hide_popup(env);
        env.emit("network://changed", &());
        self.spawn_refresh_tray(env);
    }

    /// Manual override from the main window ("Разблокировать и разрешить доступ").
    /// If the current network cannot be resolved, nothing is opened: the gate stays as it is
    /// (an unverifiable network is never confirmed by a side effect).
    pub async fn accept_current(self: &Arc<Self>) {
        let Some(env) = self.env.get() else {
            return;
        };
        // Only the explicit toggle lifts the manual kill-switch.
        if self.is_manual_killswitch() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if !self.any_provider_gate_closed() {
            return;
        }
        match env.resolve_telemetry().await {
            Ok(tel) => {
                let ip = inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone());
                self.accept_locked(env, &mut inner, &ip, &tel).await;
            }
            Err(e) => {
                eprintln!("Network guard: cannot confirm the network, gate stays closed: {e}")
            }
        }
    }

    /// The user's "allow" for the network alert `id` (command layer). Accepted only while that
    /// alert is still the current one (same id and epoch) AND its audit finished (`phase ==
    /// "ready"` and `alert_emitted == true`); otherwise nothing is opened or written and an error
    /// goes back to the window. Persists `(provider, exit_ip)` in `trusted_exceptions`, preserves
    /// unrelated `already_blocked_providers`, and opens only the allowed providers.
    pub async fn allow_network_alert(
        self: &Arc<Self>,
        id: &str,
        providers: &[String],
    ) -> Result<(), AllowError> {
        let env = self.env.get().ok_or_else(|| {
            AllowError::new(
                AllowErrorCode::GuardNotRunning,
                "network guard is not running",
            )
        })?;
        if self.is_manual_killswitch() {
            return Err(AllowError::new(
                AllowErrorCode::BlockedByManualKillswitch,
                "manual kill-switch is engaged",
            ));
        }
        let mut inner = self.inner.lock().await;
        let epoch = inner.epoch;
        if !inner.is_current(id, epoch) {
            return Err(AllowError::new(
                AllowErrorCode::AlertStale,
                "this alert is no longer current",
            ));
        }
        let Some(tel) = inner
            .pending
            .as_ref()
            .filter(|p| p.alert_emitted)
            .and_then(|p| p.tel.clone())
        else {
            return Err(AllowError::new(
                AllowErrorCode::AuditPending,
                "the network audit is not finished",
            ));
        };
        if let Some(clear) = inner
            .pending
            .as_mut()
            .and_then(|p| p.clear_old_state.take())
        {
            let _ = clear.await;
        }
        let ip = inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone());
        let st_before = env.state.get_data().await;
        let targets: Vec<String> = {
            let pending_affected = inner
                .pending
                .as_ref()
                .map(|p| p.affected_providers.clone())
                .unwrap_or_default();
            if providers.is_empty() || providers.iter().any(|p| p == ALL_PROVIDERS) {
                pending_affected.into_iter().map(|p| p.to_string()).collect()
            } else {
                let mut seen = HashSet::new();
                let mut list = Vec::new();
                for raw in providers {
                    let canonical = ProviderId::from_id(raw)
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_else(|| raw.clone());
                    if !st_before.is_provider_disabled(&canonical) && seen.insert(canonical.clone())
                    {
                        list.push(canonical);
                    }
                }
                list
            }
        };

        let now = crate::auditor::network::current_timestamp();
        for p in &targets {
            env.state
                .allow_provider_for_session(p)
                .await
                .map_err(|e| AllowError::new(AllowErrorCode::Internal, e.to_string()))?;
            if !ip.trim().is_empty() {
                env.state
                    .add_trusted_exception(p, &ip)
                    .await
                    .map_err(|e| AllowError::new(AllowErrorCode::Internal, e.to_string()))?;
            }
            env.state
                .unblock_provider(p)
                .await
                .map_err(|e| AllowError::new(AllowErrorCode::Internal, e.to_string()))?;
            let entry = IpHistoryEntry::new(tel.ip.clone(), tel.country_code.clone(), tel.asn, now);
            let _ = env
                .state
                .record_ip_history_for_selection(p, &crate::routing::RouteSelection::Direct, entry)
                .await;
        }

        let target_set: HashSet<&str> = targets.iter().map(String::as_str).collect();
        let (remaining_affected, already_blocked) = if let Some(p) = inner.pending.as_mut() {
            p.affected_providers.retain(|x| !target_set.contains(*x));
            p.already_blocked_providers
                .retain(|x| !target_set.contains(*x));
            (
                p.affected_providers.clone(),
                p.already_blocked_providers.clone(),
            )
        } else {
            (Vec::new(), Vec::new())
        };

        if remaining_affected.is_empty() {
            let st_now = env.state.get_data().await;
            let has_remaining_blocks = !already_blocked.is_empty()
                || st_now
                    .enabled_unrouted_providers()
                    .iter()
                    .any(|p| st_now.blocked_providers.contains(*p));
            if !has_remaining_blocks {
                self.accept_locked(env, &mut inner, &ip, &tel).await;
            } else {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                for p in &already_blocked {
                    if !st_now.blocked_providers.contains(*p) {
                        let _ = env.state.block_provider(p).await;
                    }
                }
                inner.baseline = Some(Baseline {
                    ip,
                    country: Some(tel.country_code.clone()),
                    trusted: true,
                });
                inner.handled_ip = None;
                inner.needs_reaudit = false;
                self.clear_until_network_change_locked(&mut inner);
                self.set_gate_reason(None);
                let st_after = env.state.get_data().await;
                self.sync_gates_with_state_and_pending(&st_after, None);
                self.hide_popup(env);
                env.emit("network://changed", &());
                self.spawn_refresh_tray(env);
            }
        } else {
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, inner.pending.as_ref());
            self.spawn_refresh_tray(env);
        }
        Ok(())
    }

}
