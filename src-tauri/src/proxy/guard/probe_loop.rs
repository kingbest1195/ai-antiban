use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[cfg(any(test, feature = "test-support"))]
use crate::auditor::{Auditor, RiskReport};
#[cfg(any(test, feature = "test-support"))]
use crate::proxy::hold_queue::HoldQueue;
#[cfg(any(test, feature = "test-support"))]
use crate::state::AppState;
use crate::state::KNOWN_PROVIDERS;

use super::types::{
    Env, Gate, GuardCtx, Inner, NetworkGuard, PROBE_MIN_GAP_MS, ROUTE_CHECK_INTERVAL_MS,
    TickPlan, compute_local_route_fingerprint,
};
#[cfg(any(test, feature = "test-support"))]
use super::types::{AUDIT_TIMEOUT_SECS, AuditFn, GuardIo, ProbeFn, ResolveFn};

impl NetworkGuard {
    /// Starts the background monitor (call once from the Tauri setup hook).
    pub fn start(self: &Arc<Self>, ctx: GuardCtx) {
        self.register_self_weak();
        if !self.install_env(Env::from_ctx(ctx)) {
            return;
        }
        self.start_loop();
    }

    #[cfg(test)]
    pub(crate) fn start_with_env(self: &Arc<Self>, env: Env) {
        self.register_self_weak();
        self.install_env(env);
        self.start_loop();
    }

    /// Integration-test seam: installs an offline [`Env`] wired to `auditor.evaluate_all`,
    /// optional `probe`, and optional `resolve` without starting a wall-clock background loop;
    /// drive ticks deterministically via [`Self::tick_test`] or `ensure_fresh`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn start_with_test_env(
        self: &Arc<Self>,
        auditor: Auditor,
        state: AppState,
        hold_queue: Arc<HoldQueue>,
        probe: Option<ProbeFn>,
        resolve: Option<ResolveFn>,
    ) {
        struct TestNoopIo;
        impl GuardIo for TestNoopIo {
            fn emit(&self, _event: &str, _payload: serde_json::Value) {}
            fn show_alert_popup(&self, _timing: Option<(String, Instant)>) {}
            fn hide_alert_popup(&self) {}
            fn tray_report(&self, _report: &RiskReport, _is_pinned: bool, _has_blocked: bool) {}
            fn tray_status(&self, _color: &str, _title: Option<&str>) {}
        }
        let audit_auditor = auditor.clone();
        let audit_state = state.clone();
        let audit: AuditFn = Arc::new(move |provider, force| {
            let (auditor, state) = (audit_auditor.clone(), audit_state.clone());
            Box::pin(async move { auditor.evaluate_all(provider, &state, force).await })
        });
        self.register_self_weak();
        let _ = self.install_env(Env {
            auditor,
            state,
            hold_queue,
            io: Arc::new(TestNoopIo),
            audit,
            probe,
            resolve,
            audit_timeout: Duration::from_secs(AUDIT_TIMEOUT_SECS),
        });
    }

    /// Deterministic integration-test driver for one full guard route/IP/audit tick.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn tick_test(self: &Arc<Self>) {
        self.register_self_weak();
        self.inner.lock().await.last_probe = None;
        if let Some(env) = self.env.get() {
            self.check_route_and_tick(env).await;
        }
    }

    pub(super) fn start_loop(self: &Arc<Self>) {
        if self.loop_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let guard = Arc::clone(self);
        let task = async move {
            #[cfg(not(test))]
            let mut n: u64 = 0;
            loop {
                if let Some(env) = guard.env.get() {
                    guard.check_route_and_tick(env).await;
                    #[cfg(not(test))]
                    if n.is_multiple_of(20) {
                        let _ = tokio::task::spawn_blocking(|| {
                            crate::sysproxy::refresh_if_services_changed();
                            crate::sysproxy::reconcile_browser_pac_prefs(None);
                        })
                        .await;
                    }
                }
                #[cfg(not(test))]
                {
                    n = n.wrapping_add(1);
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(ROUTE_CHECK_INTERVAL_MS)) => {}
                    _ = guard.wake_notify.notified() => {}
                }
            }
        };
        #[cfg(not(test))]
        tauri::async_runtime::spawn(task);
        #[cfg(test)]
        tokio::spawn(task);
    }

    /// Stores the dependencies; `false` when they were already set.
    pub(super) fn install_env(&self, env: Env) -> bool {
        self.env.set(env).is_ok()
    }

    /// Cheap pre-flight check used by every new CONNECT (no-op when the monitor is not running).
    pub async fn ensure_fresh(self: &Arc<Self>) {
        self.register_self_weak();
        if let Some(env) = self.env.get() {
            self.check_route_and_tick(env).await;
        }
    }

    /// Fetches the current egress IP (Cloudflare trace, falls back to ipify).
    async fn probe_ip(&self) -> Option<String> {
        if let Ok(resp) = self
            .client
            .get("https://1.1.1.1/cdn-cgi/trace")
            .send()
            .await
            && let Ok(text) = resp.text().await
        {
            for line in text.lines() {
                if let Some(val) = line.strip_prefix("ip=") {
                    let val = val.trim();
                    if val.parse::<IpAddr>().is_ok() {
                        return Some(val.to_string());
                    }
                }
            }
        }
        if let Ok(resp) = self.client.get("https://api.ipify.org").send().await
            && let Ok(text) = resp.text().await
        {
            let val = text.trim();
            if val.parse::<IpAddr>().is_ok() {
                return Some(val.to_string());
            }
        }
        None
    }

    pub(super) async fn probe(&self, env: &Env) -> Option<String> {
        match &env.probe {
            Some(probe) => probe().await,
            None => self.probe_ip().await,
        }
    }

    /// First part of a tick, under the `inner` lock (no network I/O).
    pub(super) async fn plan_tick(
        &self,
        env: &Env,
        current_fp: String,
        st_data: &crate::state::AppStateData,
        unrouted: &[&'static str],
    ) -> TickPlan {
        let mut inner = self.inner.lock().await;
        self.drain_pending_route_sync_locked(Some(env), &mut inner)
            .await;
        let dirty = std::mem::take(&mut inner.route_dirty);
        let dirty_since = inner.dirty_since.take();

        // A provider that just lost its route or re-enabled monitoring must be re-checked.
        let gained_unrouted = inner
            .last_unrouted
            .as_ref()
            .map(|prev| unrouted.iter().any(|p| !prev.contains(p)))
            .unwrap_or(false);
        if gained_unrouted {
            inner.handled_ip = None;
            inner.needs_reaudit = true;
        }
        inner.last_unrouted = Some(unrouted.to_vec());

        // Manual kill-switch: nothing to decide until the user lifts it.
        if self.is_manual_killswitch() {
            inner.last_route_fp = Some(current_fp);
            return TickPlan::Done;
        }

        // Every enabled provider has a fixed exit (or all disabled): local network changes are irrelevant.
        if unrouted.is_empty() {
            inner.last_route_fp = Some(current_fp);
            if self.gate() != Gate::Open
                || self.any_provider_gate_closed()
                || inner.pending.is_some()
                || env.hold_queue.has_active_non_sim_holds().await
            {
                self.restore_epoch.fetch_add(1, Ordering::SeqCst);
                inner.invalidate_alert();
                env.hold_queue.cancel_all_superseded().await;
                self.set_gate(Gate::Open);
                self.hide_popup(env);
            }
            return TickPlan::Done;
        }

        if self.force_reaudit.swap(false, Ordering::SeqCst) {
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }

        if st_data.split_tunnel_mode {
            // In split-tunnel / PAC mode, general interface / 1.1.1.1 jitter is expected:
            // never hold gates in `Gate::Pending` (keep any explicit `Blocked` providers synced),
            // and run telemetry probes on regular cadence.
            inner.last_route_fp = Some(current_fp.clone());
            if self.any_provider_gate_pending() {
                self.sync_gates_with_state_and_pending(st_data, None);
            }
            if let Some(t) = inner.last_probe
                && t.elapsed() < Duration::from_millis(PROBE_MIN_GAP_MS)
            {
                return TickPlan::Done;
            }
            return TickPlan::ProbeRegular(current_fp);
        }

        let route_changed = if inner.baseline.is_some() {
            // `dirty`: a CONNECT already saw the change (and overwrote the fingerprint).
            dirty
                || inner
                    .last_route_fp
                    .as_ref()
                    .is_some_and(|old_fp| *old_fp != current_fp)
        } else {
            false
        };

        if route_changed {
            inner.last_route_fp = Some(current_fp.clone());
            // Immediately freeze ONLY non-already-blocked enabled unrouted providers (Pending).
            return TickPlan::ProbeChanged(dirty_since.unwrap_or_else(Instant::now), current_fp);
        }

        inner.last_route_fp = Some(current_fp.clone());

        if let Some(t) = inner.last_probe
            && t.elapsed() < Duration::from_millis(PROBE_MIN_GAP_MS)
        {
            return TickPlan::Done;
        }
        TickPlan::ProbeRegular(current_fp)
    }

    /// True when the route moved (or a CONNECT flagged it) while a probe was in flight. Such a
    /// probe may have travelled over the old route, so it must never open the gate: the gate is
    /// kept closed and the next tick (fingerprint differs / `route_dirty`) handles the change.
    pub(super) fn probe_is_stale(&self, inner: &Inner, planned_fp: &str) -> bool {
        let stale = inner.route_dirty || compute_local_route_fingerprint(None) != planned_fp;
        if stale && self.gate() == Gate::Open {
            self.set_gate(Gate::Pending);
        }
        stale
    }

    pub(super) async fn check_route_and_tick(self: &Arc<Self>, env: &Env) {
        self.register_self_weak();
        let _tick = self.tick_lock.lock().await;
        // Routes do not take part in the fingerprint: routed traffic has a fixed exit and is not
        // governed by the gate, and the probe below measures the direct egress only.
        let current_fp = compute_local_route_fingerprint(None);
        let st_data = env.state.get_data().await;
        let enabled_unrouted = st_data.enabled_unrouted_providers();
        if !self.is_manual_killswitch() {
            for p in KNOWN_PROVIDERS {
                if st_data.blocked_providers.contains(p) && !enabled_unrouted.contains(&p) {
                    let _ = env.state.unblock_provider(p).await;
                }
            }
        }
        // Capture before `plan_tick` transitions any gates.
        let was_blocked = self.any_provider_gate_blocked() || !st_data.blocked_providers.is_empty();

        match self
            .plan_tick(env, current_fp, &st_data, &enabled_unrouted)
            .await
        {
            TickPlan::Done => {}
            TickPlan::ProbeChanged(t0, planned_fp) => {
                let already_blocked = self.currently_blocked_set(&st_data);
                self.freeze_providers_pending(&st_data, &enabled_unrouted, &already_blocked);
                // 2. Probe external IP (no lock held: other tasks keep working meanwhile)
                let probed = self.probe(env).await;
                let mut inner = self.inner.lock().await;
                self.apply_changed_probe(env, &mut inner, probed, t0, &planned_fp, was_blocked)
                    .await;
            }
            TickPlan::ProbeRegular(planned_fp) => {
                let probed = self.probe(env).await;
                let mut inner = self.inner.lock().await;
                self.apply_regular_probe(env, &mut inner, probed, &planned_fp, was_blocked)
                    .await;
            }
        }
    }

    pub(super) async fn unblock_disabled_and_routed(&self, env: &Env, st: &crate::state::AppStateData) {
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

}
