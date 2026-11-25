use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::auditor::geo_matrix::ProviderId;
use crate::core::timing::log_timing;
use crate::proxy::hold_queue::{PHASE_DETECTING, build_gate_reason};

use super::diag;
use super::policy::{
    all_excepted, all_pinned_or_excepted_for, all_unrouted_session_or_excepted,
    any_blocked_pinned_or_excepted_for, is_blocked_geo_code, network_change,
};
use super::types::{Baseline, Env, Gate, NetworkGuard, PauseMode};

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

        let default_moved = std::mem::take(&mut inner.default_route_moved);
        let paused_until_change = self.pause_mode() == PauseMode::UntilNetworkChange;
        if paused_until_change && inner.pending_pause_ip_bind {
            inner.paused_route_fp = Some(planned_fp.clone());
            self.hide_popup(env);
            if inner.probe_in_flight {
                return;
            }
            inner.probe_in_flight = true;
            let epoch = inner.epoch;
            let (guard, env2) = (Arc::clone(self), env.clone());
            let handle = tokio::spawn(async move {
                guard
                    .run_changed_probe_background(
                        env2,
                        None,
                        epoch,
                        planned_fp,
                        was_blocked,
                        false,
                        Vec::new(),
                        Vec::new(),
                        t0,
                    )
                    .await;
            });
            inner.probe_abort = Some(handle.abort_handle());
            return;
        }
        if paused_until_change {
            // Keep PauseMode::UntilNetworkChange active while verifying the new route silently.
            inner.paused_route_fp = Some(planned_fp.clone());
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
        self.freeze_providers_pending_quiet(&st, &non_blocked, &was_blocked_set);
        if default_moved && !non_blocked.is_empty() {
            diag::record_tunnel_abort("default_route_moved");
            self.abort_active_tunnels();
        }
        if !non_blocked.is_empty() {
            diag::record_gate_freeze("route_changed", &non_blocked);
        }

        let epoch = inner.epoch;
        let alert_id = if st.interception_behavior == crate::state::InterceptionBehavior::AskPopup
            && !non_blocked.is_empty()
            && !paused_until_change
        {
            inner.needs_reaudit = false;
            let provider = non_blocked
                .iter()
                .find_map(|p| ProviderId::from_id(p))
                .unwrap_or(ProviderId::Anthropic);
            let net_change = network_change(inner.baseline.as_ref(), None, None);
            let reason = build_gate_reason(None, Some(&net_change), false);
            log_timing("detecting", "detected", t0);
            let (id, _) = self
                .register_and_emit_network_alert_locked(
                    env,
                    &mut inner,
                    super::alerts::NetworkAlertSpec {
                        existing_id: None,
                        target_ip: String::new(),
                        tel: None,
                        clear_old_state: None,
                        affected_providers: &non_blocked,
                        already_blocked_providers: &already_blocked_vec,
                        healthy_providers: &[],
                        provider,
                        report: None,
                        network_change: net_change,
                        phase: PHASE_DETECTING,
                        gate_reason: reason,
                        timing_label: "risk_detected_emitted",
                        emit_pause_status: true,
                        emit_network_changed: false,
                        t0,
                    },
                )
                .await;
            Some(id)
        } else {
            if !non_blocked.is_empty() {
                let msg = match st.interception_behavior {
                    crate::state::InterceptionBehavior::AutoLockSilent => {
                        "Смена сети — трафик приостановлен на время проверки"
                    }
                    crate::state::InterceptionBehavior::AutoAllowTrusted
                    | crate::state::InterceptionBehavior::AskPopup => {
                        "Смена сети — проверяем безопасность подключения"
                    }
                };
                self.set_gate_reason(Some(msg.to_string()));
                self.emit_pause_status();
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
    pub(super) async fn run_changed_probe_background(
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
        let mut in_flight_guard = super::probe_offline::ProbeInFlightGuard::new(Arc::clone(self));
        let (probed, planned_fp) = self
            .probe_changed_with_settling(&env, &alert_id, epoch, planned_fp)
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

        // If the user paused/closed the `detecting` alert before `probe` resolved, adopt
        // the newly probed IP on this route without clearing the pause or re-opening the popup.
        if self.pause_mode() == PauseMode::UntilNetworkChange && inner.pending_pause_ip_bind {
            if let Some(ref new_ip) = probed {
                let unrouted = st.enabled_unrouted_providers();
                let matches_pin = all_pinned_or_excepted_for(&st, &unrouted, new_ip)
                    || any_blocked_pinned_or_excepted_for(&st, &unrouted, new_ip);
                if !matches_pin {
                    inner.last_probe = Some(Instant::now());
                    inner.consecutive_probe_failures = 0;
                    inner.observed_ip = Some(new_ip.clone());
                    inner.paused_ip = Some(new_ip.clone());
                    inner.paused_route_fp = inner.last_route_fp.clone().or(Some(planned_fp));
                    inner.handled_ip = Some(new_ip.clone());
                    inner.pending_pause_ip_bind = false;
                    inner.route_dirty = false;
                    self.hide_popup(&env);
                    return;
                }
            } else {
                self.hide_popup(&env);
                return;
            }
        } else if self.pause_mode() == PauseMode::UntilNetworkChange {
            if probed.is_none() {
                inner.last_probe = Some(Instant::now());
                inner.paused_route_fp = inner.last_route_fp.clone().or(Some(planned_fp));
                self.sync_gates_with_state_and_pending(&st, None);
                self.hide_popup(&env);
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
            diag::record_tunnel_abort("probe_changed_offline");
            self.abort_active_tunnels();
            env.auditor.resolver.invalidate_direct_cache().await;
            let enabled_unrouted = st.enabled_unrouted_providers();
            Self::revoke_unrouted_session_allows(&env, &enabled_unrouted).await;
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
            } else {
                self.emit_pause_status();
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
        inner.consecutive_probe_failures = 0;

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
                let all_pinned_match = all_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);
                let explicit_reaudit = self.force_reaudit.load(Ordering::SeqCst);
                if ((!was_blocked && !needs_reaudit) || (all_pinned_match && !explicit_reaudit))
                    && (cc_ok || returning_from_other)
                {
                    self.restore_locked(&env, &mut inner).await;
                    let cur_epoch = inner.epoch;
                    self.spawn_verify_restored_baseline(&env, new_ip, cur_epoch);
                } else {
                    drop(inner);
                    Box::pin(self.verify_and_restore_baseline(&env, &new_ip, was_blocked)).await;
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

        let baseline_changed = inner.baseline.as_ref().is_some_and(|b| b.ip != new_ip);
        if all_excepted(&st, &enabled_unrouted, &new_ip) {
            if baseline_changed {
                let _ = env.state.clear_session_allowed_providers().await;
            }
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
            let cached_cc = match env.auditor.resolver.cached_direct_country(&new_ip).await {
                Some(cc) => Some(cc),
                None => {
                    env.auditor
                        .resolver
                        .cached_verified_pinned_country(&new_ip)
                        .await
                }
            };
            if cached_cc
                .as_deref()
                .is_some_and(|c| !is_blocked_geo_code(c))
            {
                self.clear_until_network_change_locked(&mut inner);
                if baseline_changed {
                    let _ = env.state.clear_session_allowed_providers().await;
                }
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

        let ip_changed_from_baseline = inner
            .baseline
            .as_ref()
            .is_some_and(|b| b.ip.trim() != new_ip.trim());
        env.auditor.resolver.invalidate_direct_cache().await;
        let active_alert = alert_id.filter(|id| inner.is_current(id, epoch));
        let (audit_id, audit_epoch) = match active_alert {
            Some(id) if !all_pinned => {
                inner.handled_ip = Some(new_ip.clone());
                inner.needs_reaudit = false;
                if let Some(p) = inner.pending.as_mut() {
                    p.target_ip = new_ip.clone();
                    p.clear_old_state = if ip_changed_from_baseline {
                        Some(self.spawn_clear_old_network_state(&env))
                    } else {
                        None
                    };
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
                let has_blocked_match =
                    any_blocked_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);
                if inner.handled_ip.as_deref() == Some(new_ip.as_str())
                    && !needs_reaudit
                    && !has_blocked_match
                {
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
