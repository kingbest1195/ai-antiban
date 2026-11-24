use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinHandle;

use crate::proxy::hold_queue::HoldResolution;

use super::audit_summary::summarize_for_state;
use super::policy::{
    all_pinned_or_excepted_for, any_pinned_or_excepted_for, canonical_probe_ip, network_change,
    report_allowed_for_state, resolve_gate_reason_with_cooldown,
};
use super::types::{AuditResults, Baseline, Env, Inner, NetworkGuard, PauseMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuditOutcomeMode {
    Runtime,
    BaselineRestore { was_blocked: bool },
}

impl NetworkGuard {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn apply_audit_outcome_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        old_baseline: Option<&Baseline>,
        results: &AuditResults,
        was_blocked_set: &HashSet<String>,
        existing_id: Option<String>,
        existing_alert_emitted: bool,
        clear_old_state: Option<JoinHandle<()>>,
        t0: Instant,
    ) {
        self.apply_audit_outcome_with_mode_locked(
            env,
            inner,
            new_ip,
            old_baseline,
            results,
            was_blocked_set,
            existing_id,
            existing_alert_emitted,
            clear_old_state,
            AuditOutcomeMode::Runtime,
            t0,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn apply_audit_outcome_with_mode_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        old_baseline: Option<&Baseline>,
        results: &AuditResults,
        was_blocked_set: &HashSet<String>,
        existing_id: Option<String>,
        existing_alert_emitted: bool,
        clear_old_state: Option<JoinHandle<()>>,
        mode: AuditOutcomeMode,
        t0: Instant,
    ) {
        if let Some(clear) = clear_old_state {
            let _ = clear.await;
        }
        self.drain_pending_route_sync_locked(Some(env), inner).await;
        let st = env.state.get_data().await;
        self.unblock_disabled_and_routed(env, &st).await;
        let ok_reports: Vec<crate::auditor::RiskReport> = results
            .iter()
            .filter_map(|(_, r)| r.as_ref().ok().cloned())
            .collect();
        let st = if !ok_reports.is_empty()
            && self
                .try_auto_unblock_pinned_providers_locked(&env.state, inner, &ok_reports)
                .await
        {
            env.state.get_data().await
        } else {
            st
        };
        let enabled_unrouted = st.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            self.restore_locked(env, inner).await;
            return;
        }
        let all_pinned = all_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);
        let any_pinned = any_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);

        let trusted_baseline_ip = match mode {
            AuditOutcomeMode::BaselineRestore { .. } => Some(new_ip.as_str()),
            AuditOutcomeMode::Runtime => old_baseline.filter(|b| b.trusted).map(|b| b.ip.as_str()),
        };
        let Some(mut summary) =
            summarize_for_state(results, &enabled_unrouted, &st, trusted_baseline_ip)
        else {
            self.apply_missing_summary_outcome_locked(
                env,
                inner,
                new_ip,
                old_baseline,
                &st,
                &enabled_unrouted,
                was_blocked_set,
                existing_id,
                existing_alert_emitted,
                all_pinned,
                any_pinned,
                mode,
                t0,
            )
            .await;
            return;
        };

        let now_u64 = crate::auditor::network::current_timestamp();
        let cooldown_reason = summary.enforce_ip_change_cooldown(
            &st,
            &new_ip,
            old_baseline.map(|b| b.ip.as_str()),
            now_u64 as i64,
        );

        // Silent recovery for any enabled provider meeting `no_critical_and_geo_ok`, pinned IP,
        // or `(provider, exit_ip)` in `trusted_exceptions`.
        if !self.is_manual_killswitch() {
            for p in &summary.healthy_providers {
                if st.blocked_providers.contains(*p) {
                    let _ = env.state.unblock_provider(p).await;
                }
                env.hold_queue
                    .resolve_all_for_provider(p, HoldResolution::Superseded)
                    .await;
            }
        }

        let already_blocked: Vec<&'static str> = summary
            .affected_providers
            .iter()
            .copied()
            .filter(|p| was_blocked_set.contains(*p) || st.blocked_providers.contains(*p))
            .collect();
        let newly_affected: Vec<&'static str> = summary
            .affected_providers
            .iter()
            .copied()
            .filter(|p| !already_blocked.contains(p))
            .collect();

        if summary.affected_providers.is_empty() {
            let ip = canonical_probe_ip(&new_ip, &summary.tel.ip);
            inner.observed_ip = Some(ip.clone());
            self.accept_locked(env, inner, &ip, &summary.tel).await;
            return;
        }

        // Record history only for non-critical, geo-allowed healthy providers (or pinned returns).
        summary.record_healthy_history(&env.state, &st).await;

        let has_transient_blocked = already_blocked
            .iter()
            .any(|p| summary.is_transient_pinned_error(&st, p, &new_ip));

        if newly_affected.is_empty() {
            // If previously-blocked providers switched onto a clean new IP under AskPopup (e.g.
            // out of RU onto a clean unpinned foreign IP), ask the user to confirm the new network
            // instead of leaving them silently trapped in PauseMode::UntilNetworkChange.
            let clean_reconfirm: Vec<&'static str> = if st.interception_behavior
                == crate::state::InterceptionBehavior::AskPopup
                && old_baseline.is_some_and(|b| b.ip.trim() != new_ip.trim())
            {
                already_blocked
                    .iter()
                    .copied()
                    .filter(|p| {
                        summary
                            .reports
                            .get(p)
                            .is_some_and(|r| report_allowed_for_state(r, &st, false))
                    })
                    .collect()
            } else {
                Vec::new()
            };
            if !clean_reconfirm.is_empty() {
                let still_blocked: Vec<&'static str> = already_blocked
                    .iter()
                    .copied()
                    .filter(|p| !clean_reconfirm.contains(p))
                    .collect();
                if existing_alert_emitted && let Some(ref alert_id) = existing_id {
                    self.enrich_ready_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        alert_id,
                        &summary,
                        &still_blocked,
                        &clean_reconfirm,
                        cooldown_reason.as_deref(),
                        t0,
                    )
                    .await;
                } else {
                    self.emit_ready_network_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        &summary,
                        &still_blocked,
                        &clean_reconfirm,
                        existing_id,
                        None,
                        cooldown_reason.as_deref(),
                        t0,
                    )
                    .await;
                }
                return;
            }
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            for p in &already_blocked {
                if !st.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            if !summary.healthy_providers.is_empty() && !self.is_manual_killswitch() {
                self.clear_until_network_change_locked(inner);
                inner.baseline = Some(Baseline {
                    ip: new_ip.clone(),
                    country: Some(summary.tel.country_code.clone()),
                    trusted: true,
                });
            }
            let st_after = env.state.get_data().await;
            if (all_pinned && !summary.failed_providers.is_empty()) || has_transient_blocked {
                inner.handled_ip = None;
                inner.needs_reaudit = true;
            } else {
                inner.handled_ip = Some(new_ip.clone());
                inner.needs_reaudit = false;
                if (summary.healthy_providers.is_empty()
                    || self.pause_mode() == PauseMode::UntilNetworkChange)
                    && !self.is_manual_killswitch()
                {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(new_ip);
                    inner.paused_route_fp = inner.last_route_fp.clone();
                }
            }
            self.sync_gates_with_state_and_pending(&st_after, None);
            self.hide_popup(env);
            self.update_tray(env, &summary.tray).await;
            env.emit("network://changed", &summary.worst);
            return;
        }

        let has_transient_pinned = has_transient_blocked
            || newly_affected
                .iter()
                .any(|p| summary.is_transient_pinned_error(&st, p, &new_ip));
        let newly_affected: Vec<&'static str> = newly_affected
            .into_iter()
            .filter(|p| !summary.is_transient_pinned_error(&st, p, &new_ip))
            .collect();
        if newly_affected.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            if !summary.healthy_providers.is_empty() && !self.is_manual_killswitch() {
                self.clear_until_network_change_locked(inner);
                inner.baseline = Some(Baseline {
                    ip: new_ip,
                    country: Some(summary.tel.country_code.clone()),
                    trusted: true,
                });
                if already_blocked.is_empty() {
                    self.set_gate_reason(None);
                }
            }
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
            if existing_alert_emitted {
                self.hide_popup(env);
            }
            self.update_tray(env, &summary.tray).await;
            return;
        }

        let has_newly_report = newly_affected
            .iter()
            .any(|p| summary.reports.contains_key(p));
        let worst_newly = summary.worst_for(&newly_affected);
        if (self.pause_mode() == PauseMode::UntilNetworkChange && !existing_alert_emitted)
            || matches!(
                st.interception_behavior,
                crate::state::InterceptionBehavior::AutoLockSilent
                    | crate::state::InterceptionBehavior::AutoAllowTrusted
            )
        {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            let reason = if has_newly_report {
                let change = network_change(
                    old_baseline,
                    Some(worst_newly.telemetry.ip.clone()),
                    Some(worst_newly.telemetry.country_code.clone()),
                );
                resolve_gate_reason_with_cooldown(&worst_newly, &change, cooldown_reason.as_deref())
            } else {
                "Не удалось проверить новую сеть после смены IP — запросы временно остановлены"
                    .to_string()
            };
            self.set_gate_reason(Some(reason));
            for p in &newly_affected {
                let _ = env.state.block_provider(p).await;
            }
            for p in &already_blocked {
                if !st.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            let st_after = env.state.get_data().await;
            let all_blocked = enabled_unrouted
                .iter()
                .all(|p| st_after.blocked_providers.contains(*p));
            if (all_pinned && !summary.failed_providers.is_empty()) || has_transient_pinned {
                inner.handled_ip = None;
                inner.needs_reaudit = true;
            } else {
                if all_blocked && !self.is_manual_killswitch() {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(new_ip.clone());
                    inner.paused_route_fp = inner.last_route_fp.clone();
                } else if self.pause_mode() == PauseMode::UntilNetworkChange {
                    inner.paused_ip = Some(new_ip.clone());
                    inner.paused_route_fp = inner.last_route_fp.clone();
                }
                inner.handled_ip = Some(new_ip);
                inner.needs_reaudit = false;
            }
            self.sync_gates_with_state_and_pending(&st_after, None);
            self.hide_popup(env);
            if has_newly_report {
                self.update_tray(env, &worst_newly).await;
                env.emit("network://changed", &worst_newly);
            } else {
                self.update_tray(env, &summary.tray).await;
                env.emit("network://changed", &summary.tray);
            }
        } else {
            if matches!(mode, AuditOutcomeMode::BaselineRestore { .. })
                && (inner.handled_ip.as_deref() == Some(new_ip.as_str())
                    || (inner.pending.is_some() && existing_id.is_none()))
            {
                let st_after = env.state.get_data().await;
                self.sync_gates_with_state_and_pending(&st_after, inner.pending.as_ref());
                self.update_tray(env, &summary.tray).await;
                return;
            }
            if existing_alert_emitted && let Some(ref alert_id) = existing_id {
                if has_newly_report {
                    self.enrich_ready_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        alert_id,
                        &summary,
                        &already_blocked,
                        &newly_affected,
                        cooldown_reason.as_deref(),
                        t0,
                    )
                    .await;
                } else {
                    self.enrich_failed_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        alert_id,
                        &already_blocked,
                        &newly_affected,
                        &summary.healthy_providers,
                        t0,
                    )
                    .await;
                }
            } else if has_newly_report {
                self.emit_ready_network_alert_locked(
                    env,
                    inner,
                    old_baseline,
                    new_ip,
                    &summary,
                    &already_blocked,
                    &newly_affected,
                    existing_id,
                    None,
                    cooldown_reason.as_deref(),
                    t0,
                )
                .await;
            } else {
                self.emit_failed_network_alert_locked(
                    env,
                    inner,
                    old_baseline,
                    new_ip,
                    &already_blocked,
                    &newly_affected,
                    &summary.healthy_providers,
                    existing_id,
                    t0,
                )
                .await;
            }
        }
    }
}
