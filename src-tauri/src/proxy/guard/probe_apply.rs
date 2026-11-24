use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::MutexGuard;

use super::policy::{
    all_pinned_or_excepted_for, all_unrouted_session_or_excepted,
    any_blocked_pinned_or_excepted_for, is_blocked_geo_code,
};
use super::types::{Baseline, Env, Inner, NetworkGuard, PauseMode};

const OFFLINE_PROBE_RETRY_DELAYS_MS: &[u64] = &[350, 500, 750, 1000, 1000];
const OFFLINE_PROBE_MAX_BUDGET_SECS: u64 = 6;
const FP_SETTLE_WINDOW_MS: u64 = 350;
const FP_SETTLE_MAX_ROUNDS: usize = 5;

impl NetworkGuard {
    pub(super) async fn probe_with_offline_retries(
        self: &Arc<Self>,
        env: &Env,
        alert_id: &Option<String>,
        epoch: u64,
        _planned_fp: &str,
    ) -> Option<String> {
        let mut probed = self.probe(env).await;
        if probed.is_some() {
            return probed;
        }
        let retry_start = tokio::time::Instant::now();
        let max_budget = Duration::from_secs(OFFLINE_PROBE_MAX_BUDGET_SECS);
        for &delay_ms in OFFLINE_PROBE_RETRY_DELAYS_MS {
            if retry_start.elapsed() >= max_budget {
                break;
            }
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            {
                let inner = self.inner.lock().await;
                let pause_waiting = self.pause_mode() == PauseMode::UntilNetworkChange
                    && inner.pending_pause_ip_bind;
                if self.is_manual_killswitch()
                    || (!pause_waiting
                        && (inner.epoch != epoch
                            || alert_id
                                .as_ref()
                                .is_some_and(|id| !inner.is_current(id, epoch))))
                {
                    return None;
                }
            }
            probed = self.probe(env).await;
            if probed.is_some() {
                break;
            }
        }
        probed
    }

    /// Probes the new route with offline retries and absorbs intermediate route-fingerprint
    /// flaps (`utun`/IPv6/DNS) via a short settling window without killing the active alert.
    pub(super) async fn probe_changed_with_settling(
        self: &Arc<Self>,
        env: &Env,
        alert_id: &Option<String>,
        epoch: u64,
        planned_fp: String,
    ) -> (Option<String>, String) {
        let mut active_fp = planned_fp;
        if !self.is_manual_killswitch()
            && !self.is_paused()
            && !self.any_provider_gate_pending()
            && self.gate() == super::types::Gate::Open
        {
            self.freeze_open_gates_pending();
        }
        for _ in 0..FP_SETTLE_MAX_ROUNDS {
            let probed = self
                .probe_with_offline_retries(env, alert_id, epoch, &active_fp)
                .await;
            let (flapped, settle_wait) = {
                let mut inner = self.inner.lock().await;
                let pause_waiting = self.pause_mode() == PauseMode::UntilNetworkChange
                    && inner.pending_pause_ip_bind;
                if self.is_manual_killswitch()
                    || (!pause_waiting
                        && (inner.epoch != epoch
                            || alert_id
                                .as_ref()
                                .is_some_and(|id| !inner.is_current(id, epoch))))
                {
                    return (probed, active_fp);
                }
                let cur_fp = self.current_local_route_fingerprint();
                let flapped = inner.deferred_recheck_fp.take().is_some()
                    || inner.route_dirty
                    || cur_fp != active_fp;
                if !flapped {
                    return (probed, active_fp);
                }
                let wait = inner
                    .last_fp_change_at
                    .map(|t| Duration::from_millis(FP_SETTLE_WINDOW_MS).saturating_sub(t.elapsed()))
                    .unwrap_or_else(|| Duration::from_millis(FP_SETTLE_WINDOW_MS));
                inner.route_dirty = false;
                active_fp = cur_fp.clone();
                inner.last_route_fp = Some(cur_fp);
                if pause_waiting {
                    inner.paused_route_fp = Some(active_fp.clone());
                }
                (true, wait)
            };
            if flapped && !settle_wait.is_zero() {
                tokio::time::sleep(settle_wait).await;
                let mut inner = self.inner.lock().await;
                let cur_fp = self.current_local_route_fingerprint();
                inner.deferred_recheck_fp = None;
                inner.route_dirty = false;
                active_fp = cur_fp.clone();
                inner.last_route_fp = Some(cur_fp);
            }
        }
        let probed = self
            .probe_with_offline_retries(env, alert_id, epoch, &active_fp)
            .await;
        (probed, active_fp)
    }
    #[allow(clippy::too_many_arguments)]
    async fn handle_same_baseline(
        self: &Arc<Self>,
        env: &Env,
        mut inner: MutexGuard<'_, Inner>,
        ip: &str,
        baseline_trusted: bool,
        baseline_country: Option<&str>,
        planned_fp: &str,
        was_blocked: bool,
        needs_reaudit: bool,
        returning_from_other_ip: bool,
    ) -> bool {
        if baseline_trusted {
            if needs_reaudit
                || self.any_provider_gate_closed()
                || inner.pending.is_some()
                || was_blocked
            {
                if self.probe_is_stale(&inner, planned_fp) {
                    inner.last_probe = None;
                    inner.route_dirty = true;
                    return true;
                }
                let country_ok = baseline_country.is_some_and(|c| !is_blocked_geo_code(c));
                let st_check = env.state.get_data().await;
                let enabled_unrouted = st_check.enabled_unrouted_providers();
                let all_pinned_match = all_pinned_or_excepted_for(&st_check, &enabled_unrouted, ip);
                let has_explicit_pin_mismatch =
                    was_blocked && st_check.strict_pinning_enabled && !all_pinned_match;
                let explicit_reaudit = self.force_reaudit.load(Ordering::SeqCst);
                if returning_from_other_ip
                    && (!needs_reaudit || (all_pinned_match && !explicit_reaudit))
                    && country_ok
                    && !has_explicit_pin_mismatch
                    && !self.is_manual_killswitch()
                {
                    self.restore_locked(env, &mut inner).await;
                    let epoch = inner.epoch;
                    self.spawn_verify_restored_baseline(env, ip.to_string(), epoch);
                } else {
                    self.spawn_verify_and_restore_baseline(
                        env,
                        &mut inner,
                        ip.to_string(),
                        was_blocked,
                    );
                }
            } else {
                inner.handled_ip = None;
                let st = env.state.get_data().await;
                self.sync_gates_with_state_and_pending(&st, None);
            }
            return true;
        }

        let st = env.state.get_data().await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        if all_unrouted_session_or_excepted(&enabled_unrouted, &st, ip) {
            if let Some(b) = inner.baseline.as_mut() {
                b.trusted = true;
            }
            inner.handled_ip = None;
            if self.any_provider_gate_closed() || inner.pending.is_some() || was_blocked {
                if self.probe_is_stale(&inner, planned_fp) {
                    inner.last_probe = None;
                    inner.route_dirty = true;
                    return true;
                }
                self.restore_locked(env, &mut inner).await;
            }
            return true;
        }

        if needs_reaudit || was_blocked {
            if self.probe_is_stale(&inner, planned_fp) {
                return true;
            }
            self.spawn_verify_and_restore_baseline(env, &mut inner, ip.to_string(), was_blocked);
            return true;
        }

        // If the app booted on a sanctioned IP without prior blocks (`baseline.trusted == false`),
        // keep cold startup quiet (CONNECTs still enforce fail-closed in `server.rs`); only treat
        // returning to it from another IP as a network change!
        !returning_from_other_ip
    }

    /// Periodic probe without a route change.
    pub(super) async fn apply_regular_probe_unlocked(
        self: &Arc<Self>,
        env: &Env,
        probed: Option<String>,
        planned_fp: &str,
        was_blocked: bool,
    ) {
        let mut inner = self.inner.lock().await;
        inner.last_probe = Some(Instant::now());
        let t0 = Instant::now();
        let Some(ip) = probed else {
            self.handle_regular_probe_offline_locked(env, &mut inner, planned_fp, was_blocked, t0)
                .await;
            return;
        };
        if inner.probe_in_flight {
            return;
        }

        if self.pause_mode() == PauseMode::UntilNetworkChange && inner.pending_pause_ip_bind {
            let st_pause = env.state.get_data().await;
            let unrouted_pause = st_pause.enabled_unrouted_providers();
            let ip_matches_pin = !self.is_manual_killswitch()
                && (all_pinned_or_excepted_for(&st_pause, &unrouted_pause, &ip)
                    || any_blocked_pinned_or_excepted_for(&st_pause, &unrouted_pause, &ip));
            if !ip_matches_pin {
                inner.observed_ip = Some(ip.clone());
                inner.paused_ip = Some(ip.clone());
                inner.paused_route_fp = inner.last_route_fp.clone();
                inner.handled_ip = Some(ip.clone());
                inner.pending_pause_ip_bind = false;
                inner.route_dirty = false;
                self.hide_popup(env);
                return;
            }
        }

        let prev_paused_ip = inner.paused_ip.clone();
        let mut pinned_untrapped = false;
        // If user explicitly paused until the next network change on this exact IP, stay paused
        // until the external IP changes or route fingerprint invalidates — UNLESS this IP matches
        // saved `pinned_ip` / `pinned_ips` / `trusted_exceptions` (and `!is_manual_killswitch()`),
        // in which case we never trap the pinned IP permanently and silently recover cleanly.
        if self.pause_mode() == PauseMode::UntilNetworkChange
            && prev_paused_ip.as_deref() == Some(ip.as_str())
            && !inner.needs_reaudit
            && !self.force_reaudit.load(Ordering::SeqCst)
        {
            let st_pause = env.state.get_data().await;
            let unrouted_pause = st_pause.enabled_unrouted_providers();
            let ip_matches_pin = !self.is_manual_killswitch()
                && (all_pinned_or_excepted_for(&st_pause, &unrouted_pause, &ip)
                    || any_blocked_pinned_or_excepted_for(&st_pause, &unrouted_pause, &ip));
            if !ip_matches_pin {
                inner.observed_ip = Some(ip);
                return;
            }
            pinned_untrapped = true;
            inner.needs_reaudit = true;
        }
        let prev_observed_ip = inner.observed_ip.replace(ip.clone());
        let pause_cleared = self.clear_until_network_change_locked(&mut inner) || pinned_untrapped;
        if pause_cleared {
            inner.handled_ip = None;
        }

        if env.state.is_split_tunnel_mode().await {
            let prev_baseline_ip = inner.baseline.as_ref().map(|b| b.ip.clone());
            let ip_changed = prev_baseline_ip
                .as_deref()
                .is_some_and(|old| old != ip.as_str());
            if let Some(b) = inner.baseline.as_mut() {
                b.ip = ip;
                b.trusted = true;
            } else {
                inner.baseline = Some(Baseline {
                    ip,
                    country: None,
                    trusted: true,
                });
            }
            let needs_reaudit = std::mem::take(&mut inner.needs_reaudit);
            if !self.is_manual_killswitch()
                && (ip_changed || pause_cleared || needs_reaudit)
                && (was_blocked || self.any_provider_gate_closed() || inner.pending.is_some())
            {
                self.restore_locked(env, &mut inner).await;
            } else {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                    self.hide_popup(env);
                }
                inner.handled_ip = None;
                let st = env.state.get_data().await;
                self.sync_gates_with_state_and_pending(&st, None);
            }
            return;
        }

        let Some((baseline_ip, baseline_trusted, baseline_country)) = inner
            .baseline
            .as_ref()
            .map(|b| (b.ip.clone(), b.trusted, b.country.clone()))
        else {
            // Startup baseline initialization: NEVER fire alert_first before auditing;
            // silently clear any stale persisted `blocked_providers` that now satisfy
            // `no_critical_and_geo_ok`, pinned IP, or `trusted_exceptions`.
            let st = env.state.get_data().await;
            self.unblock_disabled_and_routed(env, &st).await;
            let enabled_unrouted = st.enabled_unrouted_providers();
            let matches_pinned_or_excepted =
                all_pinned_or_excepted_for(&st, &enabled_unrouted, &ip);
            let country = env
                .auditor
                .resolve_direct(false)
                .await
                .ok()
                .map(|t| t.country_code);
            let country_ok = country.as_deref().is_some_and(|c| !is_blocked_geo_code(c));
            let trusted = matches_pinned_or_excepted || country_ok;
            inner.baseline = Some(Baseline {
                ip: ip.clone(),
                country,
                trusted,
            });
            inner.needs_reaudit = false;
            let st_after = env.state.get_data().await;
            let still_blocked =
                !st_after.blocked_providers.is_empty() || self.any_provider_gate_closed();
            if still_blocked && !self.is_manual_killswitch() {
                self.spawn_verify_and_restore_baseline(env, &mut inner, ip, true);
            }
            return;
        };

        let needs_reaudit = std::mem::take(&mut inner.needs_reaudit);

        // Critical anti-starvation guard: if an audit or alert is already running/active for
        // this exact IP, regular 1s probes must NOT abort or restart it!
        if inner.pending.as_ref().is_some_and(|p| p.target_ip == ip) && !needs_reaudit {
            return;
        }

        if ip == baseline_ip {
            let pending_other_ip = inner.pending.as_ref().is_some_and(|p| p.target_ip != ip);
            let observed_other_ip = prev_observed_ip
                .as_deref()
                .is_some_and(|prev| prev != ip.as_str());
            let paused_other_ip = prev_paused_ip
                .as_deref()
                .is_some_and(|prev| prev != ip.as_str());
            let returning_from_other_ip =
                pending_other_ip || observed_other_ip || paused_other_ip || pause_cleared;
            if self
                .handle_same_baseline(
                    env,
                    inner,
                    &ip,
                    baseline_trusted,
                    baseline_country.as_deref(),
                    planned_fp,
                    was_blocked,
                    needs_reaudit,
                    returning_from_other_ip,
                )
                .await
            {
                return;
            }
            // Re-acquire lock when falling through from untrusted baseline return.
            let mut inner = self.inner.lock().await;
            if inner.handled_ip.as_deref() == Some(ip.as_str()) && !needs_reaudit {
                return;
            }
            self.handle_change_locked(env, &mut inner, ip, t0).await;
            return;
        }

        let has_blocked_pin_match = if inner.handled_ip.as_deref() == Some(ip.as_str())
            && !needs_reaudit
            && !self.is_manual_killswitch()
        {
            let st_check = env.state.get_data().await;
            let unrouted_check = st_check.enabled_unrouted_providers();
            if any_blocked_pinned_or_excepted_for(&st_check, &unrouted_check, &ip) {
                inner.handled_ip = None;
                true
            } else {
                false
            }
        } else {
            false
        };
        if inner.handled_ip.as_deref() == Some(ip.as_str())
            && !needs_reaudit
            && !has_blocked_pin_match
        {
            return; // user already decided about this network
        }

        self.handle_change_locked(env, &mut inner, ip, t0).await;
    }
}
