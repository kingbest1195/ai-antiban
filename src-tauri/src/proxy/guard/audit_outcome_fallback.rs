use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use super::audit_outcome::AuditOutcomeMode;
use super::policy::is_provider_pinned_or_excepted;
use super::types::{Baseline, Env, Inner, NetworkGuard, PauseMode};

impl NetworkGuard {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn apply_missing_summary_outcome_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        old_baseline: Option<&Baseline>,
        st: &crate::state::AppStateData,
        enabled_unrouted: &[&'static str],
        was_blocked_set: &HashSet<String>,
        existing_id: Option<String>,
        existing_alert_emitted: bool,
        all_pinned: bool,
        any_pinned: bool,
        mode: AuditOutcomeMode,
        t0: Instant,
    ) {
        if let AuditOutcomeMode::BaselineRestore { was_blocked } = mode {
            if all_pinned && let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
                self.hide_popup(env);
            }
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            if was_blocked || self.any_provider_gate_closed() {
                self.sync_gates_with_state_and_pending(st, inner.pending.as_ref());
            }
            return;
        }
        let unpinned_newly_failed: Vec<&'static str> = enabled_unrouted
            .iter()
            .copied()
            .filter(|p| {
                !was_blocked_set.contains(*p)
                    && !st.blocked_providers.contains(*p)
                    && !is_provider_pinned_or_excepted(st, p, &new_ip)
            })
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
            self.sync_gates_with_state_and_pending(st, None);
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
        if unpinned_newly_failed.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            if any_pinned {
                inner.handled_ip = None;
                inner.needs_reaudit = true;
            } else {
                inner.handled_ip = Some(new_ip.clone());
                inner.needs_reaudit = false;
                if !self.is_manual_killswitch() {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(new_ip);
                }
            }
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
            self.hide_popup(env);
        } else if st.interception_behavior == crate::state::InterceptionBehavior::AskPopup
            && self.pause_mode() != PauseMode::UntilNetworkChange
        {
            if existing_alert_emitted && let Some(ref alert_id) = existing_id {
                self.enrich_failed_alert_locked(
                    env,
                    inner,
                    old_baseline,
                    new_ip,
                    alert_id,
                    &already_blocked_vec,
                    &unpinned_newly_failed,
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
                    &unpinned_newly_failed,
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
            for p in &unpinned_newly_failed {
                let _ = env.state.block_provider(p).await;
            }
            let st_after = env.state.get_data().await;
            let all_blocked = enabled_unrouted
                .iter()
                .all(|p| st_after.blocked_providers.contains(*p));
            if any_pinned {
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
            env.emit("network://changed", &());
        }
    }
}
