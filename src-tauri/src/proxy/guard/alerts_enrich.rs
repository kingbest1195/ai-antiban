use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::core::timing::log_timing;
use crate::proxy::hold_queue::{EnrichedPayload, PHASE_FAILED, PHASE_READY};

use super::audit_summary::AuditSummary;
use super::policy::{canonical_probe_ip, network_change, resolve_gate_reason_with_cooldown};
use super::types::{Baseline, Env, Inner, NetworkGuard};

impl NetworkGuard {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn enrich_ready_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        old_baseline: Option<&Baseline>,
        new_ip: String,
        id: &str,
        summary: &AuditSummary,
        already_blocked: &[&'static str],
        newly_affected: &[&'static str],
        cooldown_reason: Option<&str>,
        t0: Instant,
    ) {
        if self.is_manual_killswitch() {
            self.hide_popup(env);
            return;
        }
        let st = env.state.get_data().await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        let mut blocked_set: HashSet<String> =
            already_blocked.iter().map(|s| (*s).to_string()).collect();
        for p in &st.blocked_providers {
            if enabled_unrouted.contains(&p.as_str()) && !newly_affected.contains(&p.as_str()) {
                blocked_set.insert(p.clone());
            }
        }
        for p in already_blocked {
            if !st.blocked_providers.contains(*p) {
                let _ = env.state.block_provider(p).await;
            }
        }
        self.freeze_providers_pending_quiet(&st, newly_affected, &blocked_set);
        inner.handled_ip = Some(new_ip.clone());
        inner.needs_reaudit = false;

        let canonical_ip = canonical_probe_ip(&new_ip, &summary.tel.ip);
        let epoch = inner.epoch;
        if let Some(p) = inner.pending.as_mut() {
            p.target_ip = new_ip;
            p.tel = Some(summary.tel.clone());
            p.affected_providers = newly_affected.to_vec();
            p.already_blocked_providers = already_blocked.to_vec();
            p.healthy_providers = summary.healthy_providers.clone();
        }

        let worst_newly = summary.worst_for(newly_affected);
        let net_change = network_change(
            old_baseline,
            Some(canonical_ip),
            Some(summary.tel.country_code.clone()),
        );
        let reason = resolve_gate_reason_with_cooldown(&worst_newly, &net_change, cooldown_reason);
        self.set_gate_reason(Some(reason.clone()));

        let enriched = EnrichedPayload {
            id: id.to_string(),
            epoch,
            phase: PHASE_READY.to_string(),
            report: Some(worst_newly.clone()),
            network_change: net_change,
            gate_reason: Some(reason),
        };
        env.hold_queue.update_alert(&enriched);
        self.update_tray(env, &worst_newly).await;
        env.emit("interceptor://enriched", &enriched);
        log_timing(id, "enriched_ready", t0);
        self.maybe_show_popup_locked(env, inner, id, t0);
        env.emit("network://changed", &worst_newly);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn enrich_failed_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        old_baseline: Option<&Baseline>,
        new_ip: String,
        id: &str,
        already_blocked: &[&'static str],
        newly_affected: &[&'static str],
        healthy_providers: &[&'static str],
        t0: Instant,
    ) {
        if self.is_manual_killswitch() {
            self.hide_popup(env);
            return;
        }
        let st = env.state.get_data().await;
        let blocked_set: HashSet<String> = already_blocked
            .iter()
            .map(|s| (*s).to_string())
            .chain(st.blocked_providers.iter().cloned())
            .filter(|p| {
                !newly_affected.contains(&p.as_str()) && !healthy_providers.contains(&p.as_str())
            })
            .collect();
        self.freeze_providers_pending_quiet(&st, newly_affected, &blocked_set);
        inner.handled_ip = Some(new_ip.clone());
        inner.needs_reaudit = false;

        let epoch = inner.epoch;
        if let Some(p) = inner.pending.as_mut() {
            p.target_ip = new_ip.clone();
            p.tel = None;
            p.affected_providers = newly_affected.to_vec();
            p.already_blocked_providers = already_blocked.to_vec();
            p.healthy_providers = healthy_providers.to_vec();
        }

        let reason =
            "Не удалось проверить новую сеть после смены IP — запросы временно остановлены"
                .to_string();
        self.set_gate_reason(Some(reason.clone()));

        let enriched = EnrichedPayload {
            id: id.to_string(),
            epoch,
            phase: PHASE_FAILED.to_string(),
            report: None,
            network_change: network_change(old_baseline, Some(new_ip), None),
            gate_reason: Some(reason),
        };
        env.hold_queue.update_alert(&enriched);
        env.emit("interceptor://enriched", &enriched);
        self.maybe_show_popup_locked(env, inner, id, t0);
        self.emit_pause_status();
        log_timing(id, "enriched_failed", t0);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn enrich_offline_failed_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        old_baseline: Option<&Baseline>,
        id: &str,
        already_blocked: &[&'static str],
        newly_affected: &[&'static str],
        t0: Instant,
    ) {
        if self.is_manual_killswitch() {
            self.hide_popup(env);
            return;
        }
        let st = env.state.get_data().await;
        let blocked_set: HashSet<String> = already_blocked
            .iter()
            .map(|s| (*s).to_string())
            .chain(st.blocked_providers.iter().cloned())
            .filter(|p| !newly_affected.contains(&p.as_str()))
            .collect();
        self.freeze_providers_pending(&st, newly_affected, &blocked_set);
        // Never latch handled_ip when offline so subsequent recovery ticks re-probe and recover.
        inner.handled_ip = None;
        inner.needs_reaudit = true;

        let epoch = inner.epoch;
        if let Some(p) = inner.pending.as_mut() {
            p.tel = None;
            p.affected_providers = newly_affected.to_vec();
            p.already_blocked_providers = already_blocked.to_vec();
            p.healthy_providers.clear();
        }

        let reason = "Нет подключения к сети после смены маршрута — запросы временно остановлены"
            .to_string();
        self.set_gate_reason(Some(reason.clone()));

        let enriched = EnrichedPayload {
            id: id.to_string(),
            epoch,
            phase: PHASE_FAILED.to_string(),
            report: None,
            network_change: network_change(old_baseline, None, None),
            gate_reason: Some(reason),
        };
        env.hold_queue.update_alert(&enriched);
        env.emit("interceptor://enriched", &enriched);
        self.maybe_show_popup_locked(env, inner, id, t0);
        self.emit_pause_status();
        log_timing(id, "enriched_offline_failed", t0);
    }
}
