use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::audit_outcome::AuditOutcomeMode;
use super::audit_summary::audit_enabled;
use super::policy::all_pinned_or_excepted_for;
use super::types::{Env, Gate, NetworkGuard};

pub(super) struct VerifyInFlightGuard(Arc<NetworkGuard>);

impl VerifyInFlightGuard {
    pub(super) fn enter(guard: Arc<NetworkGuard>) -> Self {
        guard.verify_in_flight.fetch_add(1, Ordering::SeqCst);
        Self(guard)
    }
}

impl Drop for VerifyInFlightGuard {
    fn drop(&mut self) {
        self.0.verify_in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl NetworkGuard {
    /// Re-audits the baseline IP after a prior block, recovery, route unbind, or monitoring toggle.
    /// Silently clears `blocked_providers` and opens gates for any provider meeting
    /// `no_critical_and_geo_ok` (Green OR Yellow), matching `pinned_ip`/`pinned_ips[provider]`
    /// on allowed geo, or present in `trusted_exceptions[(provider, exit_ip)]`.
    /// Never pops up an alert when all violated enabled providers are already blocked, and never
    /// latches `handled_ip` or pops a failed-audit alert on transient audit errors.
    /// Releases `self.inner` before awaiting `audit_enabled()` so `check_route_fingerprint_sync`
    /// (`try_lock`) never misses route changes during the audit.
    pub(super) async fn verify_and_restore_baseline(
        self: &Arc<Self>,
        env: &Env,
        baseline_ip: &str,
        was_blocked: bool,
    ) {
        let _verify_guard = VerifyInFlightGuard::enter(Arc::clone(self));
        let (
            st_before,
            enabled_unrouted,
            was_blocked_set,
            epoch_before,
            route_fp_before,
            local_fp_before,
        ) = {
            let mut inner = self.inner.lock().await;
            if self.is_manual_killswitch() {
                self.set_gate(Gate::Blocked);
                return;
            }
            inner.needs_reaudit = false;
            self.force_reaudit.store(false, Ordering::SeqCst);
            self.drain_pending_route_sync_locked(Some(env), &mut inner)
                .await;
            env.auditor.resolver.invalidate_direct_cache().await;
            let st_before = env.state.get_data().await;
            self.unblock_disabled_and_routed(env, &st_before).await;
            let enabled_unrouted = st_before.enabled_unrouted_providers();
            if enabled_unrouted.is_empty() {
                self.restore_locked(env, &mut inner).await;
                return;
            }
            let was_blocked_set = self.currently_blocked_set(&st_before);
            let route_fp_before = inner.last_route_fp.clone();
            let local_fp_before = self.current_local_route_fingerprint();
            (
                st_before,
                enabled_unrouted,
                was_blocked_set,
                inner.epoch,
                route_fp_before,
                local_fp_before,
            )
        };

        let audited = tokio::time::timeout(
            env.audit_timeout,
            audit_enabled(&env.audit, &st_before.disabled_providers),
        )
        .await;

        let mut inner_guard = self.inner.lock().await;
        let has_pending_route_sync = !self
            .pending_route_sync
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty();
        let current_local_fp = self.current_local_route_fingerprint();
        let route_fp_changed = inner_guard.last_route_fp != route_fp_before
            || current_local_fp != local_fp_before
            || inner_guard.last_route_fp.as_deref().is_some_and(|fp| {
                route_fp_before.as_deref() == Some(local_fp_before.as_str())
                    && fp != current_local_fp
            });
        if inner_guard.epoch != epoch_before
            || self.is_manual_killswitch()
            || inner_guard.route_dirty
            || has_pending_route_sync
            || inner_guard
                .observed_ip
                .as_deref()
                .is_some_and(|obs| obs != baseline_ip)
        {
            inner_guard.needs_reaudit = true;
            return;
        }
        if route_fp_changed {
            drop(inner_guard);
            let still_baseline = self.probe(env).await.as_deref() == Some(baseline_ip);
            inner_guard = self.inner.lock().await;
            if !still_baseline
                || inner_guard.epoch != epoch_before
                || self.is_manual_killswitch()
                || inner_guard.route_dirty
                || inner_guard
                    .observed_ip
                    .as_deref()
                    .is_some_and(|obs| obs != baseline_ip)
            {
                inner_guard.needs_reaudit = true;
                return;
            }
            inner_guard.last_route_fp = Some(self.current_local_route_fingerprint());
        }
        let inner = &mut *inner_guard;

        let Ok(results) = audited else {
            self.drain_pending_route_sync_locked(Some(env), inner).await;
            let st_cur = env.state.get_data().await;
            if all_pinned_or_excepted_for(&st_cur, &enabled_unrouted, baseline_ip)
                && let Some(p) = inner.invalidate_alert()
            {
                env.hold_queue.remove(&p.id).await;
                self.hide_popup(env);
            }
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            if was_blocked || self.any_provider_gate_closed() {
                self.sync_gates_with_state_and_pending(&st_cur, inner.pending.as_ref());
            }
            return;
        };

        let old_baseline = inner.baseline.clone();
        let detecting_alert_id = inner
            .pending
            .as_ref()
            .filter(|p| p.alert_emitted && p.target_ip.is_empty())
            .map(|p| p.id.clone());
        let existing_alert_emitted = detecting_alert_id.is_some();
        self.apply_audit_outcome_with_mode_locked(
            env,
            inner,
            baseline_ip.to_string(),
            old_baseline.as_ref(),
            &results,
            &was_blocked_set,
            detecting_alert_id,
            existing_alert_emitted,
            None,
            AuditOutcomeMode::BaselineRestore { was_blocked },
            Instant::now(),
        )
        .await;
    }
}
