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

#[cfg(any(test, feature = "test-support"))]
use super::types::{AUDIT_TIMEOUT_SECS, AuditFn, GuardIo, ProbeFn, ResolveFn};
use super::types::{
    Env, Gate, GuardCtx, NetworkGuard, PROBE_MIN_GAP_MS, ROUTE_CHECK_INTERVAL_MS, TickPlan,
};

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
            self.wait_probe_settled_for_test().await;
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
            #[cfg(not(test))]
            let mut sync_tracker = PeriodicSysproxySync::default();
            loop {
                if let Some(env) = guard.env.get() {
                    guard.check_route_and_tick(env).await;
                    #[cfg(not(test))]
                    {
                        let current_fp = guard.current_local_route_fingerprint();
                        let sysproxy_active = crate::sysproxy::is_sysproxy_active();
                        let os_pac_deferred = crate::sysproxy::is_os_pac_deferred();
                        let sync_busy = guard.sysproxy_sync_in_flight.load(Ordering::SeqCst);
                        let needs_refresh = !sync_busy
                            && sync_tracker.should_refresh(
                                &current_fp,
                                sysproxy_active,
                                os_pac_deferred,
                            );
                        let should_reconcile_prefs =
                            !sync_busy && !cfg!(target_os = "windows") && n.is_multiple_of(20);

                        if needs_refresh || should_reconcile_prefs {
                            if !guard.sysproxy_sync_in_flight.swap(true, Ordering::SeqCst) {
                                let guard_sync = Arc::clone(&guard);
                                let env_sync = env.clone();
                                tauri::async_runtime::spawn(async move {
                                    struct ResetFlag<'a>(&'a std::sync::atomic::AtomicBool);
                                    impl Drop for ResetFlag<'_> {
                                        fn drop(&mut self) {
                                            self.0.store(false, Ordering::SeqCst);
                                        }
                                    }
                                    let _reset = ResetFlag(&guard_sync.sysproxy_sync_in_flight);
                                    let _ = tokio::task::spawn_blocking(move || {
                                        if needs_refresh {
                                            crate::sysproxy::refresh_if_services_changed();
                                        }
                                        if should_reconcile_prefs {
                                            crate::sysproxy::reconcile_browser_pac_prefs(None);
                                        }
                                    })
                                    .await;
                                    env_sync.auditor.set_protection_flags(
                                        crate::auditor::AuditProtectionFlags {
                                            sysproxy_active: crate::sysproxy::is_sysproxy_active(),
                                            cli_or_sandbox_protection_active:
                                                crate::sysproxy::is_cli_protection_enabled()
                                                    || crate::sysproxy::is_browser_pac_policy_active(),
                                            os_pac_deferred: crate::sysproxy::is_os_pac_deferred(),
                                        },
                                    );
                                });
                            }
                        } else if n.is_multiple_of(20) {
                            env.auditor.set_protection_flags(
                                crate::auditor::AuditProtectionFlags {
                                    sysproxy_active: crate::sysproxy::is_sysproxy_active(),
                                    cli_or_sandbox_protection_active:
                                        crate::sysproxy::is_cli_protection_enabled()
                                            || crate::sysproxy::is_browser_pac_policy_active(),
                                    os_pac_deferred: crate::sysproxy::is_os_pac_deferred(),
                                },
                            );
                        }
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

    /// Fetches the current egress IP (Cloudflare trace, falls back to ipify),
    /// honoring an active external `chained_proxy` when configured (caching its `reqwest::Client`).
    async fn probe_ip(&self) -> Option<String> {
        let proxied = match crate::sysproxy::get_chained_proxy() {
            Some(cp) => {
                let cached = {
                    let cache = self
                        .chained_client
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    cache
                        .as_ref()
                        .filter(|(cached_cp, _)| *cached_cp == cp)
                        .map(|(_, client)| client.clone())
                };
                if let Some(client) = cached {
                    Some(client)
                } else {
                    reqwest::Proxy::all(&cp).ok().and_then(|proxy| {
                        let client = reqwest::Client::builder()
                            .proxy(proxy)
                            .timeout(Duration::from_millis(3000))
                            .pool_max_idle_per_host(0)
                            .user_agent(crate::auditor::network::NEUTRAL_USER_AGENT)
                            .build()
                            .ok()?;
                        let mut cache = self
                            .chained_client
                            .lock()
                            .unwrap_or_else(|p| p.into_inner());
                        *cache = Some((cp, client.clone()));
                        Some(client)
                    })
                }
            }
            None => {
                let mut cache = self
                    .chained_client
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                *cache = None;
                None
            }
        };
        let client = proxied.as_ref().unwrap_or(&self.client);
        if let Ok(resp) = client.get("https://1.1.1.1/cdn-cgi/trace").send().await
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
        if let Ok(resp) = client.get("https://api.ipify.org").send().await
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

        if inner
            .last_route_fp
            .as_ref()
            .is_some_and(|old| *old != current_fp)
        {
            crate::routing::net::clear_entry_dns_cache();
            crate::proxy::transit::invalidate_all_dns_caches();
        }

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
                || env
                    .hold_queue
                    .has_active_non_checkout_alerts_or_holds()
                    .await
            {
                let had_non_checkout = inner.invalidate_alert().is_some()
                    || env
                        .hold_queue
                        .has_active_non_checkout_alerts_or_holds()
                        .await;
                self.restore_epoch.fetch_add(1, Ordering::SeqCst);
                let cancelled = env.hold_queue.cancel_all_superseded().await;
                self.set_gate(Gate::Open);
                if had_non_checkout || cancelled > 0 {
                    self.hide_popup(env);
                }
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

        if inner.probe_in_flight {
            return TickPlan::Done;
        }
        if let Some(t) = inner.last_probe
            && t.elapsed() < Duration::from_millis(PROBE_MIN_GAP_MS)
        {
            return TickPlan::Done;
        }
        inner.last_probe = Some(Instant::now());
        TickPlan::ProbeRegular(current_fp)
    }

    pub(super) async fn check_route_and_tick(self: &Arc<Self>, env: &Env) {
        self.register_self_weak();
        let tick_guard = self.tick_lock.lock().await;
        // Include external system proxy (`chained_proxy`) so switching Clash/v2rayN/Happ
        // triggers immediate re-audit and DNS cache invalidation even if local IP is unchanged.
        let current_fp = self.current_local_route_fingerprint();
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
                // Window-first: freeze gates, abort tunnels, emit risk-detected (`phase: detecting`),
                // and spawn the background probe + audit without holding `tick_lock` or `inner`.
                self.begin_changed_probe(env, t0, planned_fp, was_blocked)
                    .await;
            }
            TickPlan::ProbeRegular(planned_fp) => {
                drop(tick_guard);
                let probed = self.probe(env).await;
                self.apply_regular_probe_unlocked(env, probed, &planned_fp, was_blocked)
                    .await;
            }
        }
    }
}

/// Tracks the last route/proxy state synced via `refresh_if_services_changed()` so steady-state
/// ticks never re-open the ownership journal or rewrite WinINet/browser policies every 5 seconds.
/// When `os_pac_deferred` is set (macOS temporary VPN DNS), retries at most once every 5s;
/// otherwise performs a low-frequency self-heal & newly-installed-browser check every 120s.
#[derive(Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct PeriodicSysproxySync {
    last_route_fp: Option<String>,
    last_active: bool,
    last_refresh_at: Option<Instant>,
}

impl PeriodicSysproxySync {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) const DEFERRED_RETRY_INTERVAL: Duration = Duration::from_secs(5);
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) const SELF_HEAL_INTERVAL: Duration = Duration::from_secs(120);

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn should_refresh(
        &mut self,
        route_fp: &str,
        sysproxy_active: bool,
        os_pac_deferred: bool,
    ) -> bool {
        self.should_refresh_at(route_fp, sysproxy_active, os_pac_deferred, Instant::now())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn should_refresh_at(
        &mut self,
        route_fp: &str,
        sysproxy_active: bool,
        os_pac_deferred: bool,
        now: Instant,
    ) -> bool {
        if !sysproxy_active {
            self.last_active = false;
            self.last_route_fp = None;
            self.last_refresh_at = None;
            return false;
        }
        let route_or_active_changed =
            !self.last_active || self.last_route_fp.as_deref() != Some(route_fp);
        let interval = if os_pac_deferred {
            Self::DEFERRED_RETRY_INTERVAL
        } else {
            Self::SELF_HEAL_INTERVAL
        };
        let timer_due = self
            .last_refresh_at
            .is_none_or(|t| now.saturating_duration_since(t) >= interval);
        let refresh = route_or_active_changed || timer_due;
        if refresh {
            self.last_active = true;
            self.last_route_fp = Some(route_fp.to_string());
            self.last_refresh_at = Some(now);
        }
        refresh
    }
}
