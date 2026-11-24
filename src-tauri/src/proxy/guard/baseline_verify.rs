use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::audit_summary::{audit_enabled, summarize_for_state};
use super::baseline_restore::VerifyInFlightGuard;
use super::policy::all_pinned_or_excepted_for;
use super::types::{Env, Inner, NetworkGuard};

impl NetworkGuard {
    /// Returns the most recently observed egress IP, if any.
    pub async fn current_observed_ip(&self) -> Option<String> {
        let inner = self.inner.lock().await;
        inner
            .observed_ip
            .clone()
            .or_else(|| inner.baseline.as_ref().map(|b| b.ip.clone()))
    }

    /// Emits the current `GuardPauseStatus` (including `has_active_risk_alert`) to the tray and UI.
    pub fn notify_pause_status(&self) {
        self.emit_pause_status();
    }

    /// Non-blocking check whether a route transition, probe, or baseline verification is active.
    pub fn is_network_transition_active(&self) -> bool {
        self.any_provider_gate_pending()
            || self.verify_in_flight.load(Ordering::SeqCst)
            || self
                .inner
                .try_lock()
                .is_ok_and(|g| g.probe_in_flight || g.route_dirty)
    }

    pub fn is_env_installed(&self) -> bool {
        self.env.get().is_some()
    }

    pub async fn has_baseline(&self) -> bool {
        self.inner.lock().await.baseline.is_some()
    }

    /// Handles a route-fingerprint change detected while `ProbeRegular` was in flight.
    pub(super) async fn handle_fp_moved_during_regular_probe(
        self: &Arc<Self>,
        env: &Env,
        was_blocked: bool,
    ) {
        let t0 = Instant::now();
        let new_fp = self.current_local_route_fingerprint();
        let already_in_flight = {
            let mut inner = self.inner.lock().await;
            inner.last_route_fp = Some(new_fp.clone());
            inner.last_fp_change_at = Some(t0);
            if let Some(abort) = inner.verify_abort.take() {
                abort.abort();
            }
            inner.verify_ip = None;
            let in_flight = inner.probe_in_flight
                || (self.any_provider_gate_pending() && inner.audit_abort.is_some());
            if in_flight {
                inner.deferred_recheck_fp = Some(new_fp.clone());
            }
            in_flight
        };
        if !self.is_manual_killswitch() {
            self.freeze_open_gates_pending();
            self.abort_active_tunnels();
            if !already_in_flight {
                self.begin_changed_probe(env, t0, new_fp, was_blocked).await;
            }
        }
    }

    /// Spawns `verify_and_restore_baseline` as a cancellable background task so `probe_loop`
    /// never blocks for `AUDIT_TIMEOUT_SECS` (25s) and keeps polling `fingerprint` every 150ms.
    pub(super) fn spawn_verify_and_restore_baseline(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        baseline_ip: String,
        was_blocked: bool,
    ) {
        if self.verify_in_flight.load(Ordering::SeqCst)
            && inner.verify_ip.as_deref() == Some(baseline_ip.as_str())
            && !self.force_reaudit.load(Ordering::SeqCst)
        {
            return;
        }
        if let Some(old_abort) = inner.verify_abort.take() {
            old_abort.abort();
        }
        inner.verify_ip = Some(baseline_ip.clone());
        self.verify_in_flight.store(true, Ordering::SeqCst);
        let guard = Arc::clone(self);
        let env = env.clone();
        let handle = tokio::spawn(async move {
            guard
                .verify_and_restore_baseline(&env, &baseline_ip, was_blocked)
                .await;
        });
        inner.verify_abort = Some(handle.abort_handle());
    }

    /// Background verification spawned immediately after instant auto-recovery onto a verified
    /// baseline or pinned/excepted IP. Updates tray & Direct IP history; only re-blocks if a real
    /// non-travel critical violation (`Ok(Red)`) is reported for the restored network.
    pub(super) fn spawn_verify_restored_baseline(
        self: &Arc<Self>,
        env: &Env,
        ip: String,
        epoch: u64,
    ) {
        let guard = Arc::clone(self);
        let env = env.clone();
        tokio::spawn(async move {
            let _verify_guard = VerifyInFlightGuard::enter(Arc::clone(&guard));
            let st_before = env.state.get_data().await;
            let enabled_unrouted = st_before.enabled_unrouted_providers();
            if enabled_unrouted.is_empty() {
                return;
            }
            let audited = tokio::time::timeout(
                env.audit_timeout,
                audit_enabled(&env.audit, &st_before.disabled_providers),
            )
            .await;
            let Ok(results) = audited else {
                let mut inner = guard.inner.lock().await;
                if inner.epoch == epoch
                    && !guard.is_manual_killswitch()
                    && inner.observed_ip.as_deref() == Some(ip.as_str())
                {
                    let st = env.state.get_data().await;
                    let cur_unrouted = st.enabled_unrouted_providers();
                    if all_pinned_or_excepted_for(&st, &cur_unrouted, &ip) {
                        inner.handled_ip = None;
                        inner.needs_reaudit = true;
                    }
                }
                return;
            };
            let mut inner = guard.inner.lock().await;
            if inner.epoch != epoch
                || guard.is_manual_killswitch()
                || inner.observed_ip.as_deref() != Some(ip.as_str())
            {
                return;
            }
            let st = env.state.get_data().await;
            let cur_unrouted = st.enabled_unrouted_providers();
            let trusted_base = inner.trusted_baseline_ip().map(str::to_string);
            let Some(summary) =
                summarize_for_state(&results, &cur_unrouted, &st, trusted_base.as_deref())
            else {
                if all_pinned_or_excepted_for(&st, &cur_unrouted, &ip) {
                    inner.handled_ip = None;
                    inner.needs_reaudit = true;
                }
                return;
            };
            guard.update_tray(&env, &summary.tray).await;
            let any_transient_pinned = summary
                .affected_providers
                .iter()
                .any(|p| summary.is_transient_pinned_error(&st, p, &ip));
            let real_violations: Vec<&'static str> = summary
                .affected_providers
                .iter()
                .copied()
                .filter(|p| {
                    !summary.failed_providers.contains(p)
                        && !summary.is_transient_pinned_error(&st, p, &ip)
                })
                .collect();
            if real_violations.is_empty() {
                if !summary.failed_providers.is_empty() || any_transient_pinned {
                    inner.handled_ip = None;
                    inner.needs_reaudit = true;
                } else if let Some(b) = inner.baseline.as_mut()
                    && b.ip == ip
                {
                    b.country = Some(summary.tel.country_code.clone());
                    b.trusted = true;
                }
                summary.record_healthy_history(&env.state, &st).await;
                return;
            }

            let old = inner.baseline.clone();
            let empty_blocked = HashSet::new();
            guard
                .apply_audit_outcome_locked(
                    &env,
                    &mut inner,
                    ip,
                    old.as_ref(),
                    &results,
                    &empty_blocked,
                    None,
                    false,
                    None,
                    Instant::now(),
                )
                .await;
        });
    }
}
