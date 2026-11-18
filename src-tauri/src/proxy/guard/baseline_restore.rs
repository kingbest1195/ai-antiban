use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::state::IpHistoryEntry;

use super::audit_summary::{audit_enabled, summarize_for_state};
use super::policy::{
    all_pinned_or_excepted_for, is_pinned_transient_unknown_geo, is_report_pinned_travel_only,
    report_no_critical_and_geo_ok,
};
use super::types::{Baseline, Env, Gate, Inner, NetworkGuard, PauseMode};

impl NetworkGuard {
    /// Re-audits the baseline IP after a prior block, recovery, route unbind, or monitoring toggle.
    /// Silently clears `blocked_providers` and opens gates for any provider meeting
    /// `no_critical_and_geo_ok` (Green OR Yellow), matching `pinned_ip`/`pinned_ips[provider]`
    /// on allowed geo, or present in `trusted_exceptions[(provider, exit_ip)]`.
    /// Never pops up an alert when all violated enabled providers are already blocked, and never
    /// latches `handled_ip` or pops a failed-audit alert on transient audit errors.
    pub(super) async fn verify_and_restore_baseline_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        baseline_ip: &str,
        was_blocked: bool,
    ) {
        if self.is_manual_killswitch() {
            self.set_gate(Gate::Blocked);
            return;
        }
        self.clear_until_network_change_locked(inner);
        inner.needs_reaudit = false;
        self.drain_pending_route_sync_locked(Some(env), inner).await;
        env.auditor.resolver.invalidate_direct_cache().await;
        let st_before = env.state.get_data().await;
        self.unblock_disabled_and_routed(env, &st_before).await;
        let enabled_unrouted = st_before.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            self.restore_locked(env, inner).await;
            return;
        }
        let was_blocked_set = self.currently_blocked_set(&st_before);

        let audited = tokio::time::timeout(
            env.audit_timeout,
            audit_enabled(&env.audit, &st_before.disabled_providers),
        )
        .await;
        let Some(summary) = audited
            .ok()
            .and_then(|results| summarize_for_state(&results, &enabled_unrouted, &st_before))
        else {
            self.drain_pending_route_sync_locked(Some(env), inner).await;
            let st_cur = env.state.get_data().await;
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            if was_blocked || self.any_provider_gate_closed() {
                self.sync_gates_with_state_and_pending(&st_cur, inner.pending.as_ref());
            }
            return;
        };

        for p in &summary.healthy_providers {
            if st_before.blocked_providers.contains(*p) {
                let _ = env.state.unblock_provider(p).await;
            }
        }

        if summary.affected_providers.is_empty() {
            if inner.baseline.is_none() {
                inner.baseline = Some(Baseline {
                    ip: baseline_ip.to_string(),
                    country: Some(summary.tel.country_code.clone()),
                    trusted: true,
                });
            } else if let Some(b) = inner.baseline.as_mut() {
                b.trusted = true;
                if b.country.is_none() {
                    b.country = Some(summary.tel.country_code.clone());
                }
            }
            let now = crate::auditor::network::current_timestamp();
            for p in &summary.healthy_providers {
                if let Some(r) = summary.reports.get(p)
                    && (report_no_critical_and_geo_ok(r)
                        || is_report_pinned_travel_only(r, &st_before))
                {
                    let entry = IpHistoryEntry::new(
                        r.telemetry.ip.clone(),
                        r.telemetry.country_code.clone(),
                        r.telemetry.asn,
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
            }
            self.restore_locked(env, inner).await;
            self.update_tray(env, &summary.tray).await;
            return;
        }

        let already_blocked: Vec<&'static str> = summary
            .affected_providers
            .iter()
            .copied()
            .filter(|p| was_blocked_set.contains(*p))
            .collect();
        let newly_affected: Vec<&'static str> = summary
            .affected_providers
            .iter()
            .copied()
            .filter(|p| !already_blocked.contains(p))
            .collect();

        if newly_affected.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            if !summary.failed_providers.is_empty() {
                inner.handled_ip = None;
                inner.needs_reaudit = true;
            } else {
                inner.handled_ip = Some(baseline_ip.to_string());
            }
            for p in &already_blocked {
                if !st_before.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
            self.hide_popup(env);
            env.emit("network://changed", &summary.worst);
            self.update_tray(env, &summary.tray).await;
            return;
        }

        // Transient failures (`Err` / unknown geo during `utun` stabilization) on a saved pinned
        // IP must retry silently without blocking, alerting, or locking `PauseMode` onto `baseline_ip`.
        let is_transient_pinned_failure = |p: &str| -> bool {
            let is_pinned = st_before
                .pinned_ip_for_provider(p, false)
                .is_some_and(|pin| pin.trim() == baseline_ip.trim());
            if !is_pinned {
                return false;
            }
            summary.failed_providers.contains(&p)
                || summary
                    .reports
                    .get(p)
                    .is_some_and(|r| is_pinned_transient_unknown_geo(r, &st_before, false))
        };
        let has_transient_pinned = newly_affected.iter().any(|p| is_transient_pinned_failure(p));
        let newly_affected: Vec<&'static str> = newly_affected
            .into_iter()
            .filter(|p| !is_transient_pinned_failure(p))
            .collect();
        if newly_affected.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            for p in &already_blocked {
                if !st_before.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
            self.hide_popup(env);
            self.update_tray(env, &summary.tray).await;
            return;
        }

        // At least one currently allowed enabled non-excepted provider has a Critical violation or failed.
        let has_newly_report = newly_affected
            .iter()
            .any(|p| summary.reports.contains_key(p));
        let worst_newly = summary.worst_for(&newly_affected);
        match st_before.interception_behavior {
            crate::state::InterceptionBehavior::AutoLockSilent
            | crate::state::InterceptionBehavior::AutoAllowTrusted => {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                for p in &newly_affected {
                    let _ = env.state.block_provider(p).await;
                }
                for p in &already_blocked {
                    if !st_before.blocked_providers.contains(*p) {
                        let _ = env.state.block_provider(p).await;
                    }
                }
                let st_after = env.state.get_data().await;
                let all_blocked = enabled_unrouted
                    .iter()
                    .all(|p| st_after.blocked_providers.contains(*p));
                if all_blocked
                    && !self.is_manual_killswitch()
                    && summary.failed_providers.is_empty()
                    && !has_transient_pinned
                {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(baseline_ip.to_string());
                }
                if !summary.failed_providers.is_empty() || has_transient_pinned {
                    inner.handled_ip = None;
                    inner.needs_reaudit = true;
                } else {
                    inner.handled_ip = Some(baseline_ip.to_string());
                }
                self.sync_gates_with_state_and_pending(&st_after, None);
                self.hide_popup(env);
                if has_newly_report {
                    env.emit("network://changed", &worst_newly);
                }
                self.update_tray(env, &summary.tray).await;
            }
            crate::state::InterceptionBehavior::AskPopup => {
                if inner.handled_ip.as_deref() == Some(baseline_ip) || inner.pending.is_some() {
                    let st_after = env.state.get_data().await;
                    self.sync_gates_with_state_and_pending(&st_after, inner.pending.as_ref());
                    self.update_tray(env, &summary.tray).await;
                    return;
                }
                let old_baseline = inner.baseline.clone();
                let ip_owned = baseline_ip.to_string();
                if has_newly_report {
                    self.emit_ready_network_alert_locked(
                        env,
                        inner,
                        old_baseline.as_ref(),
                        ip_owned,
                        &summary,
                        &already_blocked,
                        &newly_affected,
                        None,
                        None,
                        None,
                        Instant::now(),
                    )
                    .await;
                } else {
                    self.emit_failed_network_alert_locked(
                        env,
                        inner,
                        old_baseline.as_ref(),
                        ip_owned,
                        &already_blocked,
                        &newly_affected,
                        &summary.healthy_providers,
                        None,
                        Instant::now(),
                    )
                    .await;
                }
                if has_transient_pinned {
                    inner.needs_reaudit = true;
                }
                self.update_tray(env, &summary.tray).await;
            }
        }
    }

    /// Background verification spawned immediately after instant auto-recovery onto a verified
    /// baseline or pinned/excepted IP. Updates tray & Direct IP history; only re-blocks if a real
    /// non-travel critical violation (`Ok(Red)`) is reported for the restored network.
    pub(super) fn spawn_verify_restored_baseline(self: &Arc<Self>, env: &Env, ip: String, epoch: u64) {
        let guard = Arc::clone(self);
        let env = env.clone();
        tokio::spawn(async move {
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
            let Some(summary) = summarize_for_state(&results, &cur_unrouted, &st) else {
                if all_pinned_or_excepted_for(&st, &cur_unrouted, &ip) {
                    inner.handled_ip = None;
                    inner.needs_reaudit = true;
                }
                return;
            };
            guard.update_tray(&env, &summary.tray).await;
            let is_transient_pinned = |p: &str| -> bool {
                let is_pinned = st
                    .pinned_ip_for_provider(p, false)
                    .is_some_and(|pin| pin.trim() == ip.trim());
                if !is_pinned {
                    return false;
                }
                summary.failed_providers.contains(&p)
                    || summary
                        .reports
                        .get(p)
                        .is_some_and(|r| is_pinned_transient_unknown_geo(r, &st, false))
            };
            let any_transient_pinned = summary.affected_providers.iter().any(|p| is_transient_pinned(p));
            let real_violations: Vec<&'static str> = summary
                .affected_providers
                .iter()
                .copied()
                .filter(|p| !summary.failed_providers.contains(p) && !is_transient_pinned(p))
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
                let now = crate::auditor::network::current_timestamp();
                for p in &summary.healthy_providers {
                    if let Some(r) = summary.reports.get(p)
                        && (report_no_critical_and_geo_ok(r)
                            || is_report_pinned_travel_only(r, &st))
                    {
                        let entry = IpHistoryEntry::new(
                            r.telemetry.ip.clone(),
                            r.telemetry.country_code.clone(),
                            r.telemetry.asn,
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
                }
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
