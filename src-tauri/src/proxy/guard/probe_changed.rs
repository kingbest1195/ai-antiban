use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::core::timing::log_timing;
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, PHASE_DETECTING, RiskInterceptPayload, build_gate_reason,
};

use super::policy::{
    all_excepted, all_pinned_or_excepted_for, all_unrouted_session_or_excepted,
    is_blocked_geo_code, network_change, now_unix_ms,
};
use super::types::{ALL_PROVIDERS, Baseline, Env, Gate, Inner, NetworkGuard, PauseMode, Pending};

/// RAII drop guard ensuring `Inner::probe_in_flight` and `Inner::probe_abort` are cleared
/// even if the background probe task exits early, is cancelled, or panics.
struct ProbeInFlightGuard {
    guard: Arc<NetworkGuard>,
    armed: bool,
}

impl ProbeInFlightGuard {
    fn new(guard: Arc<NetworkGuard>) -> Self {
        Self { guard, armed: true }
    }

    fn disarm(&mut self, inner: &mut Inner) {
        self.armed = false;
        inner.probe_in_flight = false;
        inner.probe_abort = None;
    }
}

impl Drop for ProbeInFlightGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut inner) = self.guard.inner.try_lock() {
            inner.probe_in_flight = false;
            inner.probe_abort = None;
        } else if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let guard = Arc::clone(&self.guard);
            handle.spawn(async move {
                let mut inner = guard.inner.lock().await;
                inner.probe_in_flight = false;
                inner.probe_abort = None;
            });
        }
    }
}

impl NetworkGuard {
    /// Handles `TickPlan::ProbeChanged(t0, planned_fp)` immediately with ZERO network waits:
    /// freezes non-blocked enabled unrouted providers, aborts active tunnels, emits
    /// `interceptor://risk-detected` (`phase: "detecting"`, `new_ip: None`) and shows the
    /// popup under `AskPopup`, then spawns a background probe + audit task with epoch check.
    pub(super) async fn begin_changed_probe(
        self: &Arc<Self>,
        env: &Env,
        t0: Instant,
        planned_fp: String,
        was_blocked: bool,
    ) {
        crate::routing::net::clear_entry_dns_cache();
        crate::proxy::transit::invalidate_all_dns_caches();
        env.auditor.resolver.invalidate_direct_cache().await;

        let mut inner = self.inner.lock().await;
        self.drain_pending_route_sync_locked(Some(env), &mut inner)
            .await;
        if self.is_manual_killswitch() {
            self.set_gate(Gate::Blocked);
            return;
        }

        let st = env.state.get_data().await;
        self.unblock_disabled_and_routed(env, &st).await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            let had_alert = inner.invalidate_alert().is_some()
                || env
                    .hold_queue
                    .has_active_non_checkout_alerts_or_holds()
                    .await;
            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
            let cancelled = env.hold_queue.cancel_all_superseded().await;
            inner.handled_ip = None;
            inner.needs_reaudit = false;
            self.sync_gates_with_state_and_pending(&st, None);
            if had_alert || cancelled > 0 {
                self.hide_popup(env);
            }
            return;
        }

        if self.clear_until_network_change_locked(&mut inner) {
            inner.handled_ip = None;
        }
        let needs_reaudit = std::mem::take(&mut inner.needs_reaudit);
        let was_blocked_set = self.collect_was_blocked_set(&inner, &st);
        let already_blocked_vec: Vec<&'static str> = enabled_unrouted
            .iter()
            .copied()
            .filter(|p| was_blocked_set.contains(*p))
            .collect();
        let non_blocked: Vec<&'static str> = enabled_unrouted
            .iter()
            .copied()
            .filter(|p| !was_blocked_set.contains(*p))
            .collect();

        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        self.freeze_providers_pending(&st, &non_blocked, &was_blocked_set);
        self.abort_active_tunnels();

        if !non_blocked.is_empty() {
            let old_country = inner
                .baseline
                .as_ref()
                .and_then(|b| b.country.clone())
                .unwrap_or_else(|| "??".to_string());
            env.state
                .stats()
                .record_intercepted("all", "NetworkGuard", "HELD", &old_country);
        }

        let epoch = inner.epoch;
        let alert_id = if st.interception_behavior == crate::state::InterceptionBehavior::AskPopup
            && !non_blocked.is_empty()
        {
            let id = Uuid::new_v4().to_string();
            let rx = env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
            inner.needs_reaudit = false;
            inner.pending = Some(Pending {
                id: id.clone(),
                epoch,
                target_ip: String::new(),
                tel: None,
                clear_old_state: None,
                affected_providers: non_blocked.clone(),
                already_blocked_providers: already_blocked_vec.clone(),
                healthy_providers: Vec::new(),
                alert_emitted: true,
            });

            let provider = non_blocked
                .iter()
                .find_map(|p| ProviderId::from_id(p))
                .unwrap_or(ProviderId::Anthropic);
            let net_change = network_change(inner.baseline.as_ref(), None, None);
            let reason = build_gate_reason(None, Some(&net_change), false);
            self.set_gate_reason(Some(reason.clone()));
            let payload = RiskInterceptPayload {
                id: id.clone(),
                provider,
                host: "Смена сети · все ИИ-сервисы".to_string(),
                report: None,
                ttl_seconds: DEFAULT_HOLD_TTL_SECS,
                scope: "network".to_string(),
                network_change: Some(net_change),
                is_simulation: false,
                detected_at_ms: now_unix_ms(),
                phase: PHASE_DETECTING.to_string(),
                gate_reason: Some(reason),
                checkout_risk: None,
            };

            log_timing(&id, "detected", t0);
            env.hold_queue.set_alert(payload.clone());
            env.emit("interceptor://risk-detected", &payload);
            log_timing(&id, "risk_detected_emitted", t0);
            env.io.show_alert_popup(Some((id.clone(), t0)));
            log_timing(&id, "popup_show_queued", t0);
            env.io.tray_status("yellow", None);
            self.spawn_decision_waiter(env, id.clone(), epoch, rx);
            Some(id)
        } else {
            if !non_blocked.is_empty() {
                let (msg, color) = match st.interception_behavior {
                    crate::state::InterceptionBehavior::AutoLockSilent => {
                        ("Смена сети — трафик приостановлен на время проверки", "red")
                    }
                    crate::state::InterceptionBehavior::AutoAllowTrusted
                    | crate::state::InterceptionBehavior::AskPopup => {
                        ("Смена сети — проверяем безопасность подключения", "yellow")
                    }
                };
                self.set_gate_reason(Some(msg.to_string()));
                env.io.tray_status(color, None);
            }
            None
        };

        inner.probe_in_flight = true;
        let (guard, env2) = (Arc::clone(self), env.clone());
        let handle = tokio::spawn(async move {
            guard
                .run_changed_probe_background(
                    env2,
                    alert_id,
                    epoch,
                    planned_fp,
                    was_blocked,
                    needs_reaudit,
                    non_blocked,
                    already_blocked_vec,
                    t0,
                )
                .await;
        });
        inner.probe_abort = Some(handle.abort_handle());
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_changed_probe_background(
        self: &Arc<Self>,
        env: Env,
        alert_id: Option<String>,
        epoch: u64,
        planned_fp: String,
        was_blocked: bool,
        needs_reaudit: bool,
        non_blocked: Vec<&'static str>,
        already_blocked: Vec<&'static str>,
        t0: Instant,
    ) {
        let mut in_flight_guard = ProbeInFlightGuard::new(Arc::clone(self));
        let probed = self
            .probe_with_offline_retries(&env, &alert_id, epoch, &planned_fp)
            .await;

        let mut inner = self.inner.lock().await;
        in_flight_guard.disarm(&mut inner);
        if self.is_manual_killswitch() {
            self.set_gate(Gate::Blocked);
            return;
        }

        let st = env.state.get_data().await;
        if st.split_tunnel_mode {
            if let Some(ip) = probed {
                inner.observed_ip = Some(ip.clone());
                let country = inner.baseline.as_ref().and_then(|b| b.country.clone());
                inner.baseline = Some(Baseline {
                    ip,
                    country,
                    trusted: true,
                });
            }
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
                self.hide_popup(&env);
            }
            inner.handled_ip = None;
            inner.needs_reaudit = false;
            self.sync_gates_with_state_and_pending(&st, None);
            return;
        }

        // If the user paused/closed the `detecting` alert before `probe` resolved, bind `paused_ip`
        // to the newly probed IP on this route without clearing the pause or re-opening the popup.
        if self.pause_mode() == PauseMode::UntilNetworkChange && inner.pending_pause_ip_bind {
            if let Some(ref new_ip) = probed
                && !inner.route_dirty
                && (inner.paused_route_fp.is_none()
                    || inner.paused_route_fp.as_deref() == Some(planned_fp.as_str()))
                && !self.probe_is_stale(&inner, &planned_fp)
            {
                let unrouted = st.enabled_unrouted_providers();
                let matches_pin = !unrouted.is_empty()
                    && unrouted.iter().all(|p| {
                        st.pinned_ip_for_provider(p, false)
                            .is_some_and(|pin| pin.trim() == new_ip.trim())
                    });
                if !matches_pin {
                    inner.last_probe = Some(Instant::now());
                    inner.observed_ip = Some(new_ip.clone());
                    inner.paused_ip = Some(new_ip.clone());
                    inner.handled_ip = Some(new_ip.clone());
                    inner.pending_pause_ip_bind = false;
                    return;
                }
                self.clear_until_network_change_locked(&mut inner);
            } else {
                return;
            }
        } else if inner.epoch != epoch
            || alert_id
                .as_ref()
                .is_some_and(|id| !inner.is_current(id, epoch))
        {
            return;
        }

        let Some(new_ip) = probed else {
            if st.split_tunnel_mode || self.is_manual_killswitch() {
                return;
            }
            inner.last_probe = Some(Instant::now());
            self.abort_active_tunnels();
            env.auditor.resolver.invalidate_direct_cache().await;
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            if let Some(id) = alert_id {
                let old_baseline = inner.baseline.clone();
                self.enrich_offline_failed_alert_locked(
                    &env,
                    &mut inner,
                    old_baseline.as_ref(),
                    &id,
                    &already_blocked,
                    &non_blocked,
                    t0,
                )
                .await;
            }
            return;
        };

        if self.probe_is_stale(&inner, &planned_fp) {
            inner.last_probe = None;
            inner.route_dirty = true;
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            return;
        }
        inner.last_probe = Some(Instant::now());

        let prev_observed_ip = inner.observed_ip.replace(new_ip.clone());
        self.unblock_disabled_and_routed(&env, &st).await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            self.restore_locked(&env, &mut inner).await;
            return;
        }

        if let Some((baseline_ip, baseline_trusted, baseline_country)) = inner
            .baseline
            .as_ref()
            .map(|b| (b.ip.clone(), b.trusted, b.country.clone()))
            && baseline_ip == new_ip
        {
            let returning_from_other = prev_observed_ip.as_deref().is_some_and(|p| p != new_ip);
            if baseline_trusted {
                let cc_ok = baseline_country
                    .as_deref()
                    .is_some_and(|c| !is_blocked_geo_code(c));
                if !was_blocked && !needs_reaudit && (cc_ok || returning_from_other) {
                    self.restore_locked(&env, &mut inner).await;
                    let cur_epoch = inner.epoch;
                    self.spawn_verify_restored_baseline(&env, new_ip, cur_epoch);
                } else {
                    drop(inner);
                    self.verify_and_restore_baseline(&env, &new_ip, was_blocked)
                        .await;
                }
                return;
            }
            if all_unrouted_session_or_excepted(&enabled_unrouted, &st, &new_ip) {
                if let Some(b) = inner.baseline.as_mut() {
                    b.trusted = true;
                }
                self.restore_locked(&env, &mut inner).await;
                return;
            }
            if needs_reaudit || was_blocked {
                drop(inner);
                self.verify_and_restore_baseline(&env, &new_ip, was_blocked)
                    .await;
                return;
            }
            if alert_id.is_none() && !returning_from_other {
                self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
                return;
            }
        }

        if all_excepted(&st, &enabled_unrouted, &new_ip) {
            inner.baseline = Some(Baseline {
                ip: new_ip.clone(),
                country: None,
                trusted: true,
            });
            self.restore_locked(&env, &mut inner).await;
            let cur_epoch = inner.epoch;
            self.spawn_verify_restored_baseline(&env, new_ip, cur_epoch);
            return;
        }

        let all_pinned = all_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);
        if all_pinned {
            self.clear_until_network_change_locked(&mut inner);
            let cached_cc = env.auditor.resolver.cached_direct_country(&new_ip).await;
            if cached_cc
                .as_deref()
                .is_some_and(|c| !is_blocked_geo_code(c))
            {
                inner.baseline = Some(Baseline {
                    ip: new_ip.clone(),
                    country: cached_cc,
                    trusted: true,
                });
                self.restore_locked(&env, &mut inner).await;
                let cur_epoch = inner.epoch;
                self.spawn_verify_restored_baseline(&env, new_ip, cur_epoch);
                return;
            }
        }

        let active_alert = alert_id.filter(|id| inner.is_current(id, epoch));
        let (audit_id, audit_epoch) = match active_alert {
            Some(id) if !all_pinned => {
                inner.handled_ip = Some(new_ip.clone());
                inner.needs_reaudit = false;
                if let Some(p) = inner.pending.as_mut() {
                    p.target_ip = new_ip.clone();
                    p.clear_old_state = Some(self.spawn_clear_old_network_state(&env));
                }
                (id, epoch)
            }
            Some(_) => {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                self.hide_popup(&env);
                self.prepare_silent_pending_locked(
                    &env,
                    &mut inner,
                    &new_ip,
                    &non_blocked,
                    &already_blocked,
                )
            }
            None => {
                if inner.handled_ip.as_deref() == Some(new_ip.as_str()) && !needs_reaudit {
                    self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
                    return;
                }
                if all_pinned {
                    self.hide_popup(&env);
                }
                self.prepare_silent_pending_locked(
                    &env,
                    &mut inner,
                    &new_ip,
                    &non_blocked,
                    &already_blocked,
                )
            }
        };

        self.spawn_background_audit_task(
            &env,
            &mut inner,
            audit_id,
            audit_epoch,
            new_ip,
            enabled_unrouted,
            st.disabled_providers,
            t0,
        );
    }
}
