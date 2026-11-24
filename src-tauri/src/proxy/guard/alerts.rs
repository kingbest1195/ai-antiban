use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::core::timing::log_timing;
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, EnrichedPayload, PHASE_FAILED, PHASE_READY, RiskInterceptPayload,
};

use super::audit_summary::AuditSummary;
use super::policy::{
    canonical_probe_ip, network_change, now_unix_ms, resolve_gate_reason_with_cooldown,
};
pub(super) use super::types::NetworkAlertSpec;
use super::types::{ALL_PROVIDERS, AuditResults, Baseline, Env, Inner, NetworkGuard, Pending};

impl NetworkGuard {
    pub(super) async fn register_and_emit_network_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        spec: NetworkAlertSpec<'_>,
    ) -> (String, u64) {
        let id = spec
            .existing_id
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let rx = env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
        let epoch = inner.epoch;
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            target_ip: spec.target_ip,
            tel: spec.tel,
            clear_old_state: spec.clear_old_state,
            affected_providers: spec.affected_providers.to_vec(),
            already_blocked_providers: spec.already_blocked_providers.to_vec(),
            healthy_providers: spec.healthy_providers.to_vec(),
            alert_emitted: true,
        });

        self.set_gate_reason(Some(spec.gate_reason.clone()));
        let payload = RiskInterceptPayload {
            id: id.clone(),
            provider: spec.provider,
            host: "Смена сети · все ИИ-сервисы".to_string(),
            report: spec.report.clone(),
            ttl_seconds: DEFAULT_HOLD_TTL_SECS,
            scope: "network".to_string(),
            network_change: Some(spec.network_change),
            is_simulation: false,
            detected_at_ms: now_unix_ms(),
            phase: spec.phase.to_string(),
            gate_reason: Some(spec.gate_reason),
            checkout_risk: None,
        };

        env.hold_queue.set_alert(payload.clone());
        env.emit("interceptor://risk-detected", &payload);
        log_timing(&id, spec.timing_label, spec.t0);
        env.io.show_alert_popup(Some((id.clone(), spec.t0)));
        if spec.emit_pause_status {
            self.emit_pause_status();
        }
        if spec.emit_network_changed
            && let Some(ref r) = spec.report
        {
            env.emit("network://changed", r);
        }
        self.spawn_decision_waiter(env, id.clone(), epoch, rx);
        (id, epoch)
    }
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
        self.emit_pause_status();
        log_timing(id, "enriched_offline_failed", t0);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn emit_ready_network_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        old_baseline: Option<&Baseline>,
        new_ip: String,
        summary: &AuditSummary,
        already_blocked: &[&'static str],
        newly_affected: &[&'static str],
        existing_id: Option<String>,
        clear_old_state: Option<JoinHandle<()>>,
        cooldown_reason: Option<&str>,
        t0: Instant,
    ) {
        if self.is_manual_killswitch() {
            self.hide_popup(env);
            return;
        }
        if let Some(clear) = clear_old_state {
            let _ = clear.await;
        }
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
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
        let worst_newly = summary.worst_for(newly_affected);
        let net_change = network_change(
            old_baseline,
            Some(canonical_ip),
            Some(summary.tel.country_code.clone()),
        );
        let reason = resolve_gate_reason_with_cooldown(&worst_newly, &net_change, cooldown_reason);
        self.register_and_emit_network_alert_locked(
            env,
            inner,
            NetworkAlertSpec {
                existing_id,
                target_ip: new_ip,
                tel: Some(summary.tel.clone()),
                clear_old_state: None,
                affected_providers: newly_affected,
                already_blocked_providers: already_blocked,
                healthy_providers: &summary.healthy_providers,
                provider: worst_newly.provider,
                report: Some(worst_newly),
                network_change: net_change,
                phase: PHASE_READY,
                gate_reason: reason,
                timing_label: "risk_detected_emitted",
                emit_pause_status: true,
                emit_network_changed: true,
                t0,
            },
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn emit_failed_network_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        old_baseline: Option<&Baseline>,
        new_ip: String,
        already_blocked: &[&'static str],
        newly_affected: &[&'static str],
        healthy_providers: &[&'static str],
        existing_id: Option<String>,
        t0: Instant,
    ) {
        if self.is_manual_killswitch() {
            self.hide_popup(env);
            return;
        }
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
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

        let provider = newly_affected
            .iter()
            .find_map(|p| ProviderId::from_id(p))
            .unwrap_or(ProviderId::Anthropic);
        let net_change = network_change(old_baseline, Some(new_ip.clone()), None);
        let reason =
            "Не удалось проверить новую сеть после смены IP — запросы временно остановлены"
                .to_string();
        self.register_and_emit_network_alert_locked(
            env,
            inner,
            NetworkAlertSpec {
                existing_id,
                target_ip: new_ip,
                tel: None,
                clear_old_state: None,
                affected_providers: newly_affected,
                already_blocked_providers: already_blocked,
                healthy_providers,
                provider,
                report: None,
                network_change: net_change,
                phase: PHASE_FAILED,
                gate_reason: reason,
                timing_label: "risk_detected_failed_emitted",
                emit_pause_status: true,
                emit_network_changed: false,
                t0,
            },
        )
        .await;
    }

    /// Delivers the result of the background audit started by `handle_change_locked`.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn finish_audit(
        self: &Arc<Self>,
        env: &Env,
        id: &str,
        epoch: u64,
        new_ip: String,
        _unrouted: &[&'static str],
        results: Option<AuditResults>,
        t0: Instant,
    ) {
        let mut inner = self.inner.lock().await;
        if !inner.is_current(id, epoch) {
            log_timing(id, "audit_dropped_stale", t0);
            return;
        }
        for _ in 0..5 {
            if inner.deferred_recheck_fp.take().is_none() {
                break;
            }
            let settle_wait = inner
                .last_fp_change_at
                .map(|t| std::time::Duration::from_millis(350).saturating_sub(t.elapsed()))
                .unwrap_or_default();
            drop(inner);
            if !settle_wait.is_zero() {
                tokio::time::sleep(settle_wait).await;
            }
            let latest_ip = self.probe(env).await;
            inner = self.inner.lock().await;
            if !inner.is_current(id, epoch) {
                log_timing(id, "audit_dropped_stale", t0);
                return;
            }
            if latest_ip.as_deref() != Some(new_ip.as_str()) {
                inner.probe_abort = None;
                inner.audit_abort = None;
                if let Some(changed_ip) = latest_ip {
                    self.handle_change_locked(env, &mut inner, changed_ip, t0)
                        .await;
                    return;
                }
                inner.handled_ip = None;
                inner.needs_reaudit = true;
                inner.route_dirty = true;
                inner.dirty_since.get_or_insert_with(Instant::now);
                self.wake();
                return;
            }
        }
        if inner.deferred_recheck_fp.take().is_some() {
            inner.route_dirty = true;
            inner.dirty_since.get_or_insert_with(Instant::now);
            inner.handled_ip = None;
            inner.needs_reaudit = true;
        }
        inner.probe_abort = None;
        inner.audit_abort = None;
        let old = inner.baseline.clone();
        let (clear_old_state, prev_already_blocked, alert_emitted) = match inner.pending.as_mut() {
            Some(p) => (
                p.clear_old_state.take(),
                p.already_blocked_providers
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect::<HashSet<String>>(),
                p.alert_emitted,
            ),
            None => (None, HashSet::new(), false),
        };

        let res_vec = results.unwrap_or_default();
        self.apply_audit_outcome_locked(
            env,
            &mut inner,
            new_ip,
            old.as_ref(),
            &res_vec,
            &prev_already_blocked,
            Some(id.to_string()),
            alert_emitted,
            clear_old_state,
            t0,
        )
        .await;
    }
}
