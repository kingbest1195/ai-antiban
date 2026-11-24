use std::sync::Arc;
use std::time::Instant;

use tokio::sync::MutexGuard;
use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::core::timing::log_timing;
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, PHASE_DETECTING, RiskInterceptPayload, build_gate_reason,
};

use super::policy::{network_change, now_unix_ms};
use super::types::{ALL_PROVIDERS, Env, Gate, Inner, NetworkGuard, PauseMode, Pending};

impl NetworkGuard {
    /// Revokes session-level ephemeral approvals for currently enabled unrouted providers.
    pub(super) async fn revoke_unrouted_session_allows(env: &Env, unrouted: &[&'static str]) {
        for p in unrouted {
            let _ = env.state.revoke_session_allowed_provider(p).await;
        }
    }

    /// Fail-closed handler when a regular periodic/pre-CONNECT probe returns `None` (network drop
    /// or mid-switch timeout during VPN server switch where local route fingerprint did not change):
    /// immediately freezes unrouted gates to `Pending`, revokes ephemeral session allowances,
    /// invalidates DNS & direct telemetry caches, aborts active unrouted tunnels, shows the
    /// `detecting` alert popup (< 150ms), and spawns rapid background offline retry/recovery.
    pub(super) async fn handle_regular_probe_offline_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut MutexGuard<'_, Inner>,
        planned_fp: &str,
        was_blocked: bool,
        t0: Instant,
    ) {
        if inner.probe_in_flight || self.is_manual_killswitch() {
            return;
        }
        // Only engage switch-protection fail-closed once a baseline was established; cold startup
        // while offline already fails closed in `connect.rs` without spurious switch popups.
        if inner.baseline.is_none() {
            return;
        }
        self.drain_pending_route_sync_locked(Some(env), inner).await;
        let st = env.state.get_data().await;
        if st.split_tunnel_mode {
            return;
        }
        self.unblock_disabled_and_routed(env, &st).await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            return;
        }

        crate::routing::net::clear_entry_dns_cache();
        crate::proxy::transit::invalidate_all_dns_caches();
        env.auditor.resolver.invalidate_direct_cache().await;
        Self::revoke_unrouted_session_allows(env, &enabled_unrouted).await;

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

        if non_blocked.is_empty() || self.pause_mode() == PauseMode::UntilNetworkChange {
            self.freeze_providers_pending(&st, &non_blocked, &was_blocked_set);
            self.abort_active_tunnels();
            return;
        }

        inner.handled_ip = None;
        inner.needs_reaudit = true;

        // Avoid replacing an already open offline/detecting popup on subsequent ticks.
        if inner
            .pending
            .as_ref()
            .is_some_and(|p| p.alert_emitted && p.target_ip.is_empty())
        {
            self.freeze_providers_pending(&st, &non_blocked, &was_blocked_set);
            self.abort_active_tunnels();
            return;
        }

        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        self.freeze_providers_pending(&st, &non_blocked, &was_blocked_set);
        self.abort_active_tunnels();

        let old_country = inner
            .baseline
            .as_ref()
            .and_then(|b| b.country.clone())
            .unwrap_or_else(|| "??".to_string());
        env.state
            .stats()
            .record_intercepted("all", "NetworkGuard", "HELD", &old_country);

        let epoch = inner.epoch;
        let alert_id = if st.interception_behavior == crate::state::InterceptionBehavior::AskPopup {
            let id = Uuid::new_v4().to_string();
            let rx = env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
            inner.pending = Some(Pending {
                id: id.clone(),
                epoch,
                target_ip: String::new(),
                tel: None,
                clear_old_state: None,
                affected_providers: non_blocked.clone(),
                already_blocked_providers: already_blocked_vec.clone(),
                healthy_providers: Vec::new(),
                alert_emitted: true,
            });
            let provider = non_blocked
                .iter()
                .find_map(|p| ProviderId::from_id(p))
                .unwrap_or(ProviderId::Anthropic);
            let net_change = network_change(inner.baseline.as_ref(), None, None);
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
                checkout_risk: None,
            };
            env.hold_queue.set_alert(payload.clone());
            env.emit("interceptor://risk-detected", &payload);
            env.io.show_alert_popup(Some((id.clone(), t0)));
            env.io.tray_status("yellow", None);
            log_timing(&id, "offline_regular_freeze", t0);
            self.spawn_decision_waiter(env, id.clone(), epoch, rx);
            Some(id)
        } else {
            let (msg, color) = match st.interception_behavior {
                crate::state::InterceptionBehavior::AutoLockSilent => (
                    "Потеряна связь с сетью — трафик приостановлен на время проверки",
                    "red",
                ),
                crate::state::InterceptionBehavior::AutoAllowTrusted
                | crate::state::InterceptionBehavior::AskPopup => (
                    "Потеряна связь с сетью — проверяем безопасность подключения",
                    "yellow",
                ),
            };
            self.set_gate_reason(Some(msg.to_string()));
            env.io.tray_status(color, None);
            None
        };

        inner.probe_in_flight = true;
        let (guard, env2, fp) = (Arc::clone(self), env.clone(), planned_fp.to_string());
        let handle = tokio::spawn(async move {
            guard
                .run_changed_probe_background(
                    env2,
                    alert_id,
                    epoch,
                    fp,
                    was_blocked,
                    true,
                    non_blocked,
                    already_blocked_vec,
                    t0,
                )
                .await;
        });
        inner.probe_abort = Some(handle.abort_handle());
    }

    /// True only when an unrouted provider's gate is open and no network transition or unverified
    /// startup state invalidates cached `session_allowed_providers`.
    pub async fn can_use_session_allowance(&self, provider: ProviderId) -> bool {
        if self.gate_for(provider) != Gate::Open
            || self.is_manual_killswitch()
            || self.pause_mode() != PauseMode::None
        {
            return false;
        }
        if !self.is_env_installed() {
            return true;
        }
        let inner = self.inner.lock().await;
        let Some(ref baseline) = inner.baseline else {
            return false;
        };
        if inner.probe_in_flight
            || inner.route_dirty
            || inner.needs_reaudit
            || inner.pending.is_some()
        {
            return false;
        }
        inner
            .observed_ip
            .as_deref()
            .is_none_or(|ip| ip == baseline.ip)
    }

    /// True when direct unrouted egress telemetry must bypass the 15s cache because a route check
    /// or probe mismatch leaves the current egress unverified.
    pub async fn needs_direct_audit_refresh(
        &self,
        resolver: &crate::auditor::network::NetworkResolver,
    ) -> bool {
        if !self.is_env_installed() {
            return false;
        }
        let cur_ip = {
            let inner = self.inner.lock().await;
            if inner.route_dirty
                || inner.needs_reaudit
                || inner.probe_in_flight
                || inner.pending.is_some()
            {
                return true;
            }
            inner
                .observed_ip
                .clone()
                .or_else(|| inner.baseline.as_ref().map(|b| b.ip.clone()))
        };
        match cur_ip {
            Some(ip) => resolver.cached_direct_country(&ip).await.is_none(),
            None => false,
        }
    }

    /// Checks whether direct egress telemetry must be refreshed and invalidates any short-TTL
    /// in-memory telemetry cache whenever route transitions or IP mismatches invalidate it.
    pub async fn prepare_direct_audit_refresh(
        &self,
        resolver: &crate::auditor::network::NetworkResolver,
    ) -> bool {
        if !self.is_env_installed() {
            return false;
        }
        let (dirty_or_pending, cur_ip) = {
            let inner = self.inner.lock().await;
            (
                inner.route_dirty
                    || inner.needs_reaudit
                    || inner.probe_in_flight
                    || inner.pending.is_some(),
                inner
                    .observed_ip
                    .clone()
                    .or_else(|| inner.baseline.as_ref().map(|b| b.ip.clone())),
            )
        };
        if dirty_or_pending {
            resolver.invalidate_direct_cache().await;
            return true;
        }
        match cur_ip {
            Some(ip) => {
                if resolver.cached_direct_country(&ip).await.is_none() {
                    resolver.invalidate_direct_cache().await;
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    /// Forces the background guard loop to re-probe immediately after a failed unrouted request.
    pub async fn wake_immediate_probe(&self) {
        if !self.is_env_installed() || self.is_manual_killswitch() {
            return;
        }
        {
            let mut inner = self.inner.lock().await;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }
        self.wake();
    }

    /// Strict Step-4 admission for `CONNECT`: rejects silent pass-through if an unrouted
    /// connection observes a new unpinned/unexcepted IP that differs from `baseline` under
    /// `AskPopup` or `AutoLockSilent`.
    pub async fn is_report_allowed_for_connect(
        &self,
        report: &crate::auditor::RiskReport,
        st: &crate::state::AppStateData,
        routed: bool,
    ) -> bool {
        if routed {
            return super::policy::report_allowed_for_state(report, st, true);
        }
        if !self.is_env_installed() || st.split_tunnel_mode {
            return super::policy::report_allowed_for_state(report, st, false);
        }
        let trusted_baseline_ip = {
            let inner = self.inner.lock().await;
            inner
                .baseline
                .as_ref()
                .filter(|b| b.trusted)
                .map(|b| b.ip.clone())
        };
        match trusted_baseline_ip {
            Some(ref base_ip) if base_ip.trim() != report.telemetry.ip.trim() => {
                super::policy::report_allowed_on_network_switch(report, st, Some(base_ip.as_str()))
            }
            _ => super::policy::report_allowed_for_state(report, st, false),
        }
    }
}
