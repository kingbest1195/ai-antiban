use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::MutexGuard;

use super::policy::{all_excepted, all_unrouted_session_or_excepted, is_blocked_geo_code};
use super::types::{Baseline, Env, Inner, NetworkGuard, PauseMode};

const OFFLINE_PROBE_RETRY_DELAYS_MS: &[u64] = &[350, 500, 750, 1000, 1000];
const OFFLINE_PROBE_MAX_BUDGET_SECS: u64 = 6;

impl NetworkGuard {
    pub(super) async fn probe_with_offline_retries(
        self: &Arc<Self>,
        env: &Env,
        alert_id: &Option<String>,
        epoch: u64,
        planned_fp: &str,
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
                    && inner.pending_pause_ip_bind
                    && inner.paused_route_fp.as_deref() == Some(planned_fp);
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
                if returning_from_other_ip
                    && !needs_reaudit
                    && country_ok
                    && !self.is_manual_killswitch()
                {
                    self.restore_locked(env, &mut inner).await;
                    let epoch = inner.epoch;
                    self.spawn_verify_restored_baseline(env, ip.to_string(), epoch);
                } else {
                    drop(inner);
                    self.verify_and_restore_baseline(env, ip, was_blocked).await;
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
            drop(inner);
            self.verify_and_restore_baseline(env, ip, was_blocked).await;
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
            return; // offline: nothing to compare
        };
        if inner.probe_in_flight {
            return;
        }

        if self.pause_mode() == PauseMode::UntilNetworkChange && inner.pending_pause_ip_bind {
            let route_still_same = !inner.route_dirty
                && (inner.paused_route_fp.is_none()
                    || inner.paused_route_fp == inner.last_route_fp)
                && !self.probe_is_stale(&inner, planned_fp);
            if route_still_same {
                inner.paused_ip = Some(ip.clone());
                inner.handled_ip = Some(ip.clone());
                inner.pending_pause_ip_bind = false;
            }
        }

        let prev_paused_ip = inner.paused_ip.clone();
        let mut pinned_untrapped = false;
        // If user explicitly paused until the next network change on this exact IP, stay paused
        // until the external IP changes or route fingerprint invalidates — UNLESS this IP matches
        // saved `pinned_ip` / `pinned_ips` (and `!is_manual_killswitch()`), in which case we never
        // trap the pinned IP permanently and silently recover cleanly.
        if self.pause_mode() == PauseMode::UntilNetworkChange
            && prev_paused_ip.as_deref() == Some(ip.as_str())
            && !inner.needs_reaudit
            && !self.force_reaudit.load(Ordering::SeqCst)
        {
            let st_pause = env.state.get_data().await;
            let unrouted_pause = st_pause.enabled_unrouted_providers();
            let ip_matches_pin = !self.is_manual_killswitch()
                && !unrouted_pause.is_empty()
                && unrouted_pause.iter().all(|p| {
                    st_pause
                        .pinned_ip_for_provider(p, false)
                        .is_some_and(|pin| pin.trim() == ip.trim())
                });
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
            let matches_pinned = !enabled_unrouted.is_empty()
                && enabled_unrouted.iter().all(|p| {
                    st.pinned_ip_for_provider(p, false)
                        .is_some_and(|pin| pin.trim() == ip.trim())
                });
            let matches_exception = all_excepted(&st, &enabled_unrouted, &ip);
            let country = env
                .auditor
                .resolve_direct(false)
                .await
                .ok()
                .map(|t| t.country_code);
            let country_ok = country.as_deref().is_some_and(|c| !is_blocked_geo_code(c));
            let trusted = matches_pinned || matches_exception || country_ok;
            inner.baseline = Some(Baseline {
                ip: ip.clone(),
                country,
                trusted,
            });
            inner.needs_reaudit = false;
            let st_after = env.state.get_data().await;
            let still_blocked =
                !st_after.blocked_providers.is_empty() || self.any_provider_gate_blocked();
            if still_blocked && !self.is_manual_killswitch() {
                drop(inner);
                self.verify_and_restore_baseline(env, &ip, true).await;
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

        if inner.handled_ip.as_deref() == Some(ip.as_str()) && !needs_reaudit {
            return; // user already decided about this network
        }

        self.handle_change_locked(env, &mut inner, ip, t0).await;
    }
}
