use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::core::timing::log_timing;
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, PHASE_DETECTING, RiskInterceptPayload, build_gate_reason,
};

use super::audit_summary::audit_enabled;
use super::policy::{
    all_excepted, all_pinned_or_excepted_for, is_blocked_geo_code, network_change, now_unix_ms,
};
use super::types::{ALL_PROVIDERS, Baseline, Env, Inner, NetworkGuard, Pending};

impl NetworkGuard {
    /// Persists "the previous temporary session allowances belonged to the old network" in the
    /// background. Neither `trusted_exceptions` nor `blocked_providers` is cleared here:
    /// persistent exceptions always survive network switches, and `apply_audit_outcome_locked`
    /// keeps or silently unblocks `blocked_providers` based on the new network's audit.
    pub(super) fn spawn_clear_old_network_state(self: &Arc<Self>, env: &Env) -> JoinHandle<()> {
        let state = env.state.clone();
        tokio::spawn(async move {
            let _ = state.clear_session_allowed_providers().await;
        })
    }

    pub(super) fn collect_was_blocked_set(
        &self,
        inner: &Inner,
        st: &crate::state::AppStateData,
    ) -> HashSet<String> {
        let mut set = self.currently_blocked_set(st);
        if let Some(p) = inner.pending.as_ref() {
            for b in &p.already_blocked_providers {
                set.insert((*b).to_string());
            }
        }
        set
    }

    pub(super) async fn handle_change_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        t0: Instant,
    ) {
        self.drain_pending_route_sync_locked(Some(env), inner).await;
        let st = env.state.get_data().await;
        self.unblock_disabled_and_routed(env, &st).await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            // Every enabled provider is routed (or all providers disabled): local network change
            // does not trigger alerts or block traffic.
            let had_alert = inner.invalidate_alert().is_some()
                || env.hold_queue.has_active_non_sim_holds().await;
            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
            let cancelled = env.hold_queue.cancel_all_superseded().await;
            inner.handled_ip = Some(new_ip);
            inner.needs_reaudit = false;
            self.sync_gates_with_state_and_pending(&st, None);
            if had_alert || cancelled > 0 {
                self.hide_popup(env);
            }
            return;
        }

        let old = inner.baseline.clone();
        // Never abort/restart an in-flight audit or already-handled check for the exact same IP
        // unless `needs_reaudit` was explicitly armed (e.g. route unbind / exception removed).
        if !inner.needs_reaudit
            && (inner.pending.as_ref().is_some_and(|p| p.target_ip == new_ip)
                || (old.as_ref().map(|b| b.ip.as_str()) == Some(new_ip.as_str())
                    && inner.handled_ip.as_deref() == Some(new_ip.as_str())))
        {
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
            return;
        }

        // Fast-path 1: every enabled unrouted provider has an explicit persistent trusted exception
        // for `new_ip` -> immediately open/restore without interrupting traffic or showing a popup.
        if all_excepted(&st, &enabled_unrouted, &new_ip) {
            inner.baseline = Some(Baseline {
                ip: new_ip.clone(),
                country: None,
                trusted: true,
            });
            self.restore_locked(env, inner).await;
            let epoch = inner.epoch;
            self.spawn_verify_restored_baseline(env, new_ip, epoch);
            return;
        }

        // Fast-path 2: return-to-pinned IP for all enabled unrouted providers whose geo is already
        // known non-sanctioned -> recover immediately without flashing Gate::Pending or popup.
        let all_pinned = all_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);
        if all_pinned {
            self.clear_until_network_change_locked(inner);
            let cached_cc = env.auditor.resolver.cached_direct_country(&new_ip).await;
            if cached_cc.as_deref().is_some_and(|c| !is_blocked_geo_code(c)) {
                inner.baseline = Some(Baseline {
                    ip: new_ip.clone(),
                    country: cached_cc,
                    trusted: true,
                });
                self.restore_locked(env, inner).await;
                let epoch = inner.epoch;
                self.spawn_verify_restored_baseline(env, new_ip, epoch);
                return;
            }
        }

        // Capture which enabled unrouted providers are ALREADY blocked before touching gates,
        // then freeze ONLY allowed enabled unrouted providers to Pending while auditing runs.
        let was_blocked_set = self.collect_was_blocked_set(inner, &st);
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

        self.freeze_providers_pending(&st, &non_blocked, &was_blocked_set);
        self.abort_active_tunnels();
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        env.auditor.resolver.invalidate_direct_cache().await;

        if !non_blocked.is_empty() {
            let old_country = old
                .as_ref()
                .and_then(|b| b.country.clone())
                .unwrap_or_else(|| "??".to_string());
            env.state
                .stats()
                .record_intercepted("all", "NetworkGuard", "HELD", &old_country);
        }

        // Instant alert-first for AskPopup when at least one enabled unrouted provider was open
        // and the new IP is not pinned/excepted; silent/pinned modes keep zero popup and load
        // the audit asynchronously under `Pending.target_ip` protection (no 1s probe starvation!).
        if st.interception_behavior == crate::state::InterceptionBehavior::AskPopup
            && !all_pinned
            && !non_blocked.is_empty()
        {
            self.alert_first_locked(
                env,
                inner,
                new_ip,
                &old,
                &enabled_unrouted,
                &non_blocked,
                &already_blocked_vec,
                t0,
            )
            .await;
            return;
        }

        if all_pinned {
            self.hide_popup(env);
        }
        self.spawn_silent_audit_locked(
            env,
            inner,
            new_ip,
            &st,
            &enabled_unrouted,
            &non_blocked,
            &already_blocked_vec,
            all_pinned,
            t0,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn alert_first_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        old_baseline: &Option<Baseline>,
        enabled_unrouted: &[&'static str],
        non_blocked: &[&'static str],
        already_blocked: &[&'static str],
        t0: Instant,
    ) {
        inner.handled_ip = Some(new_ip.clone());
        inner.needs_reaudit = false;

        let id = Uuid::new_v4().to_string();
        let rx = env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
        let epoch = inner.epoch;
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            target_ip: new_ip.clone(),
            tel: None,
            clear_old_state: Some(self.spawn_clear_old_network_state(env)),
            affected_providers: non_blocked.to_vec(),
            already_blocked_providers: already_blocked.to_vec(),
            healthy_providers: Vec::new(),
            alert_emitted: true,
        });

        let provider = non_blocked
            .iter()
            .find_map(|p| ProviderId::from_id(p))
            .unwrap_or(ProviderId::Anthropic);
        let net_change = network_change(old_baseline.as_ref(), Some(new_ip.clone()), None);
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
        };

        log_timing(&id, "detected", t0);
        env.hold_queue.set_alert(payload.clone());
        env.emit("interceptor://risk-detected", &payload);
        log_timing(&id, "risk_detected_emitted", t0);
        env.io.show_alert_popup(Some((id.clone(), t0)));
        log_timing(&id, "popup_show_queued", t0);
        env.io.tray_status("yellow", None);

        let st = env.state.get_data().await;
        self.spawn_background_audit_task(
            env,
            inner,
            id.clone(),
            epoch,
            new_ip,
            enabled_unrouted.to_vec(),
            st.disabled_providers,
            t0,
        );
        self.spawn_decision_waiter(env, id, epoch, rx);
    }

    #[allow(clippy::too_many_arguments)]
    async fn spawn_silent_audit_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        st: &crate::state::AppStateData,
        enabled_unrouted: &[&'static str],
        non_blocked: &[&'static str],
        already_blocked: &[&'static str],
        all_pinned: bool,
        t0: Instant,
    ) {
        inner.needs_reaudit = false;
        let id = Uuid::new_v4().to_string();
        let epoch = inner.epoch;
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            target_ip: new_ip.clone(),
            tel: None,
            clear_old_state: Some(self.spawn_clear_old_network_state(env)),
            affected_providers: non_blocked.to_vec(),
            already_blocked_providers: already_blocked.to_vec(),
            healthy_providers: Vec::new(),
            alert_emitted: false,
        });

        if !non_blocked.is_empty() {
            if all_pinned {
                env.io.tray_status("yellow", None);
            } else {
                match st.interception_behavior {
                    crate::state::InterceptionBehavior::AutoLockSilent => {
                        self.set_gate_reason(Some(
                            "Смена сети — трафик приостановлен на время проверки".to_string(),
                        ));
                        env.io.tray_status("red", None);
                    }
                    crate::state::InterceptionBehavior::AutoAllowTrusted
                    | crate::state::InterceptionBehavior::AskPopup => {
                        self.set_gate_reason(Some(
                            "Смена сети — проверяем безопасность подключения".to_string(),
                        ));
                        env.io.tray_status("yellow", None);
                    }
                }
            }
        }

        self.spawn_background_audit_task(
            env,
            inner,
            id,
            epoch,
            new_ip,
            enabled_unrouted.to_vec(),
            st.disabled_providers.clone(),
            t0,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_background_audit_task(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        id: String,
        epoch: u64,
        new_ip: String,
        enabled_unrouted: Vec<&'static str>,
        disabled: HashSet<String>,
        t0: Instant,
    ) {
        let audit_env = env.clone();
        let audit = tokio::spawn(async move { audit_enabled(&audit_env.audit, &disabled).await });
        let audit_abort = audit.abort_handle();
        inner.audit_abort = Some(audit_abort.clone());

        let guard = Arc::clone(self);
        let env2 = env.clone();
        tokio::spawn(async move {
            let results = match tokio::time::timeout(env2.audit_timeout, audit).await {
                Ok(Ok(results)) => Some(results),
                Ok(Err(e)) => {
                    if !e.is_cancelled() {
                        eprintln!("Network guard: audit task ended abnormally: {e}");
                    }
                    None
                }
                Err(_) => {
                    audit_abort.abort();
                    eprintln!("Network guard: audit of the new network timed out");
                    None
                }
            };
            guard
                .finish_audit(&env2, &id, epoch, new_ip, &enabled_unrouted, results, t0)
                .await;
        });
    }

}
