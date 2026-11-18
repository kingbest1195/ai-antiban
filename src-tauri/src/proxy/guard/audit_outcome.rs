use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinHandle;

use crate::proxy::hold_queue::HoldResolution;
use crate::state::IpHistoryEntry;

use super::audit_summary::summarize_for_state;
use super::policy::{
    all_pinned_or_excepted_for, is_pinned_transient_unknown_geo, is_report_pinned_travel_only,
    network_change, report_no_critical_and_geo_ok, resolve_gate_reason_with_cooldown,
};
use super::types::{AuditResults, Baseline, Env, Inner, NetworkGuard, PauseMode};

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
        if let Some(clear) = clear_old_state {
            let _ = clear.await;
        }
        self.drain_pending_route_sync_locked(Some(env), inner).await;
        let st = env.state.get_data().await;
        self.unblock_disabled_and_routed(env, &st).await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            self.restore_locked(env, inner).await;
            return;
        }
        let all_pinned = all_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);

        let Some(mut summary) = summarize_for_state(results, &enabled_unrouted, &st) else {
            let newly_failed: Vec<&'static str> = enabled_unrouted
                .iter()
                .copied()
                .filter(|p| !was_blocked_set.contains(*p) && !st.blocked_providers.contains(*p))
                .collect();
            let already_blocked_vec: Vec<&'static str> = enabled_unrouted
                .iter()
                .copied()
                .filter(|p| was_blocked_set.contains(*p) || st.blocked_providers.contains(*p))
                .collect();
            if all_pinned {
                // Never latch handled_ip or pop a failed-audit alert on a pinned IP during
                // transient VPN handshake failures; retry on subsequent ticks!
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                inner.handled_ip = None;
                inner.needs_reaudit = true;
                self.sync_gates_with_state_and_pending(&st, None);
                if existing_alert_emitted {
                    self.hide_popup(env);
                }
                return;
            }
            for p in &already_blocked_vec {
                if !st.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            if newly_failed.is_empty() {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                inner.handled_ip = Some(new_ip.clone());
                inner.needs_reaudit = false;
                if !self.is_manual_killswitch() {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(new_ip);
                }
                let st_after = env.state.get_data().await;
                self.sync_gates_with_state_and_pending(&st_after, None);
                self.hide_popup(env);
                env.io.tray_status("red", None);
            } else if st.interception_behavior == crate::state::InterceptionBehavior::AskPopup {
                if existing_alert_emitted && let Some(ref alert_id) = existing_id {
                    self.enrich_failed_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        alert_id,
                        &already_blocked_vec,
                        &newly_failed,
                        &[],
                        t0,
                    )
                    .await;
                } else {
                    self.emit_failed_network_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        &already_blocked_vec,
                        &newly_failed,
                        &[],
                        existing_id,
                        t0,
                    )
                    .await;
                }
            } else {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                self.set_gate_reason(Some(
                    "Не удалось проверить новую сеть после смены IP — запросы временно остановлены"
                        .to_string(),
                ));
                for p in &newly_failed {
                    let _ = env.state.block_provider(p).await;
                }
                let st_after = env.state.get_data().await;
                let all_blocked = enabled_unrouted
                    .iter()
                    .all(|p| st_after.blocked_providers.contains(*p));
                if all_blocked && !self.is_manual_killswitch() {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(new_ip.clone());
                }
                inner.handled_ip = Some(new_ip);
                inner.needs_reaudit = false;
                self.sync_gates_with_state_and_pending(&st_after, None);
                self.hide_popup(env);
                env.io.tray_status("red", None);
                env.emit("network://changed", &());
            }
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
            let ip = inner
                .observed_ip
                .clone()
                .unwrap_or_else(|| summary.tel.ip.clone());
            self.accept_locked(env, inner, &ip, &summary.tel).await;
            return;
        }

        // Record history only for non-critical, geo-allowed healthy providers (or pinned returns).
        let now = crate::auditor::network::current_timestamp();
        for p in &summary.healthy_providers {
            if let Some(r) = summary.reports.get(p)
                && (report_no_critical_and_geo_ok(r) || is_report_pinned_travel_only(r, &st))
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

        if newly_affected.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            for p in &already_blocked {
                if !st.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            let st_after = env.state.get_data().await;
            if all_pinned && !summary.failed_providers.is_empty() {
                inner.handled_ip = None;
                inner.needs_reaudit = true;
            } else {
                inner.handled_ip = Some(new_ip.clone());
                inner.needs_reaudit = false;
                if summary.healthy_providers.is_empty() && !self.is_manual_killswitch() {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(new_ip);
                }
            }
            self.sync_gates_with_state_and_pending(&st_after, None);
            self.hide_popup(env);
            self.update_tray(env, &summary.tray).await;
            env.emit("network://changed", &summary.worst);
            return;
        }

        // Transient audit errors or unknown geo on a saved pinned IP must retry silently without
        // blocking, alerting, or locking `PauseMode` onto the pinned IP.
        let is_transient_pinned = |p: &str| -> bool {
            let is_pinned = st
                .pinned_ip_for_provider(p, false)
                .is_some_and(|pin| pin.trim() == new_ip.trim());
            if !is_pinned {
                return false;
            }
            summary.failed_providers.contains(&p)
                || summary
                    .reports
                    .get(p)
                    .is_some_and(|r| is_pinned_transient_unknown_geo(r, &st, false))
        };
        let has_transient_pinned = newly_affected.iter().any(|p| is_transient_pinned(p));
        let newly_affected: Vec<&'static str> = newly_affected
            .into_iter()
            .filter(|p| !is_transient_pinned(p))
            .collect();
        if newly_affected.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
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
        match st.interception_behavior {
            crate::state::InterceptionBehavior::AutoLockSilent
            | crate::state::InterceptionBehavior::AutoAllowTrusted => {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                let reason = if has_newly_report {
                    let change = network_change(
                        old_baseline,
                        Some(worst_newly.telemetry.ip.clone()),
                        Some(worst_newly.telemetry.country_code.clone()),
                    );
                    resolve_gate_reason_with_cooldown(
                        &worst_newly,
                        &change,
                        cooldown_reason.as_deref(),
                    )
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
            }
            crate::state::InterceptionBehavior::AskPopup => {
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

}
