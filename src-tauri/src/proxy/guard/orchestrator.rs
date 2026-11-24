use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
#[cfg(any(test, feature = "test-support"))]
use std::time::Duration;
use std::time::Instant;

use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::hold_queue::{PHASE_DETECTING, build_gate_reason};
use crate::state::KNOWN_PROVIDERS;

use super::audit_summary::audit_enabled;
use super::fingerprint::compute_local_route_fingerprint;
use super::policy::{
    all_excepted, all_pinned_or_excepted_for, any_blocked_pinned_or_excepted_for,
    is_blocked_geo_code, network_change,
};
use super::types::{Baseline, Env, Gate, GuardCtx, Inner, NetworkGuard, Pending};

impl NetworkGuard {
    /// Computes the current local route fingerprint, isolating unit tests from global
    /// `sysproxy::set_chained_proxy` mutations in parallel `sysproxy` unit test threads.
    pub(super) fn current_local_route_fingerprint(&self) -> String {
        #[cfg(test)]
        let chained: Option<String> = None;
        #[cfg(not(test))]
        let chained = crate::sysproxy::get_chained_proxy();
        self.compute_route_fp(chained.as_deref())
    }

    /// True when the route moved (or a CONNECT flagged it) while a probe was in flight. Such a
    /// probe may have travelled over the old route, so it must never open the gate: the gate is
    /// kept closed and the next tick (fingerprint differs / `route_dirty`) handles the change.
    pub(super) fn probe_is_stale(&self, inner: &Inner, planned_fp: &str) -> bool {
        let stale = inner.route_dirty
            || inner.deferred_recheck_fp.is_some()
            || self.current_local_route_fingerprint() != planned_fp;
        if stale && self.gate() == Gate::Open {
            self.set_gate(Gate::Pending);
        }
        stale
    }

    pub(super) async fn unblock_disabled_and_routed(
        &self,
        env: &Env,
        st: &crate::state::AppStateData,
    ) {
        if self.is_manual_killswitch() {
            return;
        }
        let enabled_unrouted = st.enabled_unrouted_providers();
        for p in KNOWN_PROVIDERS {
            if st.blocked_providers.contains(p) && !enabled_unrouted.contains(&p) {
                let _ = env.state.unblock_provider(p).await;
            }
        }
    }

    pub async fn tick(self: &Arc<Self>, ctx: &GuardCtx) {
        match self.env.get() {
            Some(env) => self.check_route_and_tick(env).await,
            None => self.check_route_and_tick(&Env::from_ctx(ctx.clone())).await,
        }
    }

    /// Waits for an asynchronous `ProbeChanged` probe task to finish (test helper).
    #[cfg(any(test, feature = "test-support"))]
    pub async fn wait_probe_settled_for_test(&self) {
        for _ in 0..200 {
            if !self.inner.lock().await.probe_in_flight && !self.is_verify_in_flight() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Integration-test seam: seeds a trusted baseline and matching route fingerprint without
    /// installing `Env` (so `ensure_fresh` stays a no-op when testing `connect.rs` pre-checks).
    #[cfg(any(test, feature = "test-support"))]
    pub async fn seed_baseline_for_test(&self, ip: &str, cc: &str, upstream_key: Option<&str>) {
        let mut inner = self.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: ip.to_string(),
            country: Some(cc.to_string()),
            trusted: true,
        });
        inner.last_route_fp = Some(compute_local_route_fingerprint(upstream_key));
        inner.route_dirty = false;
    }

    /// Persists "the previous temporary session allowances belonged to the old network" in the
    /// background. Neither `trusted_exceptions` nor `blocked_providers` is cleared here:
    /// persistent exceptions always survive network switches, and `apply_audit_outcome_locked`
    /// keeps or silently unblocks `blocked_providers` based on the new network's audit.
    pub(super) fn clear_old_if_ip_changed(
        self: &Arc<Self>,
        env: &Env,
        old_baseline: Option<&Baseline>,
        new_ip: &str,
    ) -> Option<JoinHandle<()>> {
        old_baseline
            .is_some_and(|b| b.ip.trim() != new_ip.trim())
            .then(|| self.spawn_clear_old_network_state(env))
    }

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
            // does not trigger alerts or block traffic, nor hide an active PayShield checkout alert.
            let had_alert = inner.invalidate_alert().is_some()
                || env
                    .hold_queue
                    .has_active_non_checkout_alerts_or_holds()
                    .await;
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
        let all_pinned = all_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);
        let has_blocked_pin_match =
            any_blocked_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);
        let paused_until_change = self.pause_mode() == super::types::PauseMode::UntilNetworkChange;
        // Never abort/restart an in-flight audit or already-handled check for the exact same IP
        // unless `needs_reaudit` was explicitly armed, pause is re-checking a changed IP, or a
        // blocked provider matches pin/exception.
        if !inner.needs_reaudit
            && !has_blocked_pin_match
            && (!paused_until_change || inner.paused_ip.as_deref() == Some(new_ip.as_str()))
            && (inner
                .pending
                .as_ref()
                .is_some_and(|p| p.target_ip == new_ip)
                || (old.as_ref().map(|b| b.ip.as_str()) == Some(new_ip.as_str())
                    && inner.handled_ip.as_deref() == Some(new_ip.as_str())))
        {
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
            return;
        }

        // Fast-path 1: every enabled unrouted provider has an explicit persistent trusted exception
        // for `new_ip` -> immediately open/restore without interrupting traffic or showing a popup.
        if all_excepted(&st, &enabled_unrouted, &new_ip) {
            self.clear_until_network_change_locked(inner);
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
                self.clear_until_network_change_locked(inner);
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

        self.freeze_providers_pending_quiet(&st, &non_blocked, &was_blocked_set);
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
        if self.is_manual_killswitch() {
            self.hide_popup(env);
            return;
        }
        inner.handled_ip = Some(new_ip.clone());
        inner.needs_reaudit = false;

        let clear_old_state = self.clear_old_if_ip_changed(env, old_baseline.as_ref(), &new_ip);
        let provider = non_blocked
            .iter()
            .find_map(|p| ProviderId::from_id(p))
            .unwrap_or(ProviderId::Anthropic);
        let net_change = network_change(old_baseline.as_ref(), Some(new_ip.clone()), None);
        let reason = build_gate_reason(None, Some(&net_change), false);
        let (id, epoch) = self
            .register_and_emit_network_alert_locked(
                env,
                inner,
                super::alerts::NetworkAlertSpec {
                    existing_id: None,
                    target_ip: new_ip.clone(),
                    tel: None,
                    clear_old_state,
                    affected_providers: non_blocked,
                    already_blocked_providers: already_blocked,
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

        let st = env.state.get_data().await;
        self.spawn_background_audit_task(
            env,
            inner,
            id,
            epoch,
            new_ip,
            enabled_unrouted.to_vec(),
            st.disabled_providers,
            t0,
        );
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
        let clear_old_state = self.clear_old_if_ip_changed(env, inner.baseline.as_ref(), &new_ip);
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            target_ip: new_ip.clone(),
            tel: None,
            clear_old_state,
            affected_providers: non_blocked.to_vec(),
            already_blocked_providers: already_blocked.to_vec(),
            healthy_providers: Vec::new(),
            alert_emitted: false,
        });

        if !non_blocked.is_empty() {
            if !all_pinned {
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
            }
            self.emit_pause_status();
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

    pub(super) fn prepare_silent_pending_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: &str,
        non_blocked: &[&'static str],
        already_blocked: &[&'static str],
    ) -> (String, u64) {
        let (silent_id, silent_epoch) = (Uuid::new_v4().to_string(), inner.epoch);
        inner.needs_reaudit = false;
        let clear_old_state = self.clear_old_if_ip_changed(env, inner.baseline.as_ref(), new_ip);
        inner.pending = Some(Pending {
            id: silent_id.clone(),
            epoch: silent_epoch,
            target_ip: new_ip.to_string(),
            tel: None,
            clear_old_state,
            affected_providers: non_blocked.to_vec(),
            already_blocked_providers: already_blocked.to_vec(),
            healthy_providers: Vec::new(),
            alert_emitted: false,
        });
        (silent_id, silent_epoch)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_background_audit_task(
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
