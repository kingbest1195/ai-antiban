use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::policy::{all_excepted, all_unrouted_session_or_excepted, is_blocked_geo_code};
use super::types::{Baseline, Env, Inner, NetworkGuard, PauseMode};

impl NetworkGuard {
    #[allow(clippy::too_many_arguments)]
    async fn handle_same_baseline_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
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
                if self.probe_is_stale(inner, planned_fp) {
                    return true;
                }
                let country_ok = baseline_country.is_some_and(|c| !is_blocked_geo_code(c));
                if returning_from_other_ip
                    && !needs_reaudit
                    && country_ok
                    && !self.is_manual_killswitch()
                {
                    self.restore_locked(env, inner).await;
                    let epoch = inner.epoch;
                    self.spawn_verify_restored_baseline(env, ip.to_string(), epoch);
                } else {
                    self.verify_and_restore_baseline_locked(env, inner, ip, was_blocked)
                        .await;
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
                if self.probe_is_stale(inner, planned_fp) {
                    return true;
                }
                self.restore_locked(env, inner).await;
            }
            return true;
        }

        if needs_reaudit || was_blocked {
            if self.probe_is_stale(inner, planned_fp) {
                return true;
            }
            self.verify_and_restore_baseline_locked(env, inner, ip, was_blocked)
                .await;
            return true;
        }

        // If the app booted on a sanctioned IP without prior blocks (`baseline.trusted == false`),
        // keep cold startup quiet (CONNECTs still enforce fail-closed in `server.rs`); only treat
        // returning to it from another IP as a network change!
        !returning_from_other_ip
    }

    /// The route fingerprint changed: decide what the probed IP means.
    pub(super) async fn apply_changed_probe(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        probed: Option<String>,
        t0: Instant,
        planned_fp: &str,
        was_blocked: bool,
    ) {
        inner.last_probe = Some(Instant::now());
        let Some(new_ip) = probed else {
            self.abort_active_tunnels();
            env.auditor.resolver.invalidate_direct_cache().await;
            let old_country = inner
                .baseline
                .as_ref()
                .and_then(|b| b.country.clone())
                .unwrap_or_else(|| "??".to_string());
            env.state
                .stats()
                .record_intercepted("all", "NetworkGuard", "HELD", &old_country);
            return;
        };

        let needs_reaudit = std::mem::take(&mut inner.needs_reaudit);
        if inner.pending.as_ref().is_some_and(|p| p.target_ip == new_ip) && !needs_reaudit {
            let st = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
            return;
        }

        let prev_observed_ip = inner.observed_ip.replace(new_ip.clone());
        let prev_paused_ip = inner.paused_ip.clone();
        // Local network interface / route changed: clear temporary pause-until-network-change.
        let pause_cleared = self.clear_until_network_change_locked(inner);
        if pause_cleared {
            inner.handled_ip = None;
        }

        if let Some((baseline_ip, baseline_trusted, baseline_country)) = inner
            .baseline
            .as_ref()
            .map(|b| (b.ip.clone(), b.trusted, b.country.clone()))
            && baseline_ip == new_ip
        {
            let pending_other_ip = inner.pending.as_ref().is_some_and(|p| p.target_ip != new_ip);
            let observed_other_ip = prev_observed_ip
                .as_deref()
                .is_some_and(|prev| prev != new_ip.as_str());
            let paused_other_ip = prev_paused_ip
                .as_deref()
                .is_some_and(|prev| prev != new_ip.as_str());
            let returning_from_other_ip =
                pending_other_ip || observed_other_ip || paused_other_ip || pause_cleared;
            if self
                .handle_same_baseline_locked(
                    env,
                    inner,
                    &new_ip,
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
        }

        if inner.handled_ip.as_deref() == Some(new_ip.as_str()) && !needs_reaudit {
            let st = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
            return;
        }

        self.handle_change_locked(env, inner, new_ip, t0).await;
    }

    /// Periodic probe without a route change.
    pub(super) async fn apply_regular_probe(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        probed: Option<String>,
        planned_fp: &str,
        was_blocked: bool,
    ) {
        inner.last_probe = Some(Instant::now());
        let t0 = Instant::now();
        let Some(ip) = probed else {
            return; // offline: nothing to compare
        };

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
        let pause_cleared = self.clear_until_network_change_locked(inner) || pinned_untrapped;
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
                self.restore_locked(env, inner).await;
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
            let country_ok = country
                .as_deref()
                .is_some_and(|c| !is_blocked_geo_code(c));
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
                self.verify_and_restore_baseline_locked(env, inner, &ip, true)
                    .await;
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
                .handle_same_baseline_locked(
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
        }

        if inner.handled_ip.as_deref() == Some(ip.as_str()) && !needs_reaudit {
            return; // user already decided about this network
        }

        self.handle_change_locked(env, inner, ip, t0).await;
    }

}
