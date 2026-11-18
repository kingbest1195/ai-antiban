use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::auditor::NetworkTelemetry;
use crate::auditor::geo_matrix::ProviderId;

use super::types::{Baseline, Gate, NetworkGuard};

impl NetworkGuard {
    /// Scoped per-provider confirmation after explicit user override ("Разрешить принудительно" /
    /// `allow_provider_session` / single-provider `AllowSession`).
    /// Never leaks across other unrelated blocked/pending providers and cleanly sets
    /// `baseline.trusted = true` even when telemetry could not be resolved externally.
    pub async fn confirm_provider_session(
        self: &Arc<Self>,
        provider: &str,
        tel: Option<&NetworkTelemetry>,
    ) {
        if self.is_manual_killswitch() {
            return;
        }
        let canonical = ProviderId::from_id(provider)
            .map(|p| p.as_str())
            .unwrap_or(provider);
        let mut inner = self.inner.lock().await;
        if let Some(env) = self.env.get() {
            let st = env.state.get_data().await;
            let is_direct_enabled = !st.is_provider_disabled(canonical)
                && crate::routing::select_route_id(&st, canonical).is_none();
            let has_enabled_unrouted = !st.enabled_unrouted_providers().is_empty();
            // Never fall back to direct egress telemetry (or mark an untrusted direct baseline
            // as trusted) when the confirmed provider is routed/disabled or all providers are routed.
            if is_direct_enabled && has_enabled_unrouted {
                let resolved = match tel {
                    Some(t) => Some(t.clone()),
                    None => env.resolve_telemetry().await.ok(),
                };
                if let Some(t) = resolved {
                    let ip = inner.observed_ip.clone().unwrap_or_else(|| t.ip.clone());
                    inner.baseline = Some(Baseline {
                        ip,
                        country: Some(t.country_code.clone()),
                        trusted: true,
                    });
                } else if let Some(b) = inner.baseline.as_mut() {
                    b.trusted = true;
                }
            }
            if let Some(p) = inner.pending.as_mut() {
                p.affected_providers.retain(|x| *x != canonical);
                p.already_blocked_providers.retain(|x| *x != canonical);
                if p.affected_providers.is_empty() {
                    let old_id = p.id.clone();
                    inner.invalidate_alert();
                    env.hold_queue.remove(&old_id).await;
                }
            }
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
            if !self.any_provider_gate_closed() {
                self.restore_epoch.fetch_add(1, Ordering::SeqCst);
                env.hold_queue.cancel_all_superseded().await;
                inner.handled_ip = None;
                inner.needs_reaudit = false;
                self.clear_until_network_change_locked(&mut inner);
                self.set_gate_reason(None);
                self.hide_popup(env);
            }
            self.spawn_refresh_tray(env);
            return;
        }

        if let Some(t) = tel {
            inner.baseline = Some(Baseline {
                ip: t.ip.clone(),
                country: Some(t.country_code.clone()),
                trusted: true,
            });
        } else if let Some(b) = inner.baseline.as_mut() {
            b.trusted = true;
        }
        if let Some(pid) = ProviderId::from_id(canonical)
            && let Some(tx) = self.provider_gates.get(&pid)
        {
            let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
            if !*self.kill_tx.borrow() {
                tx.send_replace(Gate::Open);
                if self.provider_gates.values().all(|g| *g.borrow() == Gate::Open) {
                    self.gate_tx.send_replace(Gate::Open);
                    inner.handled_ip = None;
                }
            }
        }
    }

    /// Confirms the current network as a trusted baseline after explicit user confirmation in the
    /// main window (`allow_provider_session` / `unblock_provider_cmd`). Unlike `accept_current`,
    /// this also updates `baseline.trusted = true` when the gate is already `Gate::Open` (e.g.
    /// startup on a warning/untrusted network) so subsequent regular probes on the same IP do not
    /// re-freeze or block traffic. Never lifts a manual kill-switch or opens a closed gate without
    /// resolved telemetry.
    pub async fn confirm_current_session(self: &Arc<Self>, tel: Option<&NetworkTelemetry>) {
        if self.is_manual_killswitch() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if let Some(env) = self.env.get() {
            let resolved = match tel {
                Some(t) => Ok(t.clone()),
                None => env.resolve_telemetry().await,
            };
            match resolved {
                Ok(t) => {
                    let ip = inner.observed_ip.clone().unwrap_or_else(|| t.ip.clone());
                    let st = env.state.get_data().await;
                    if self.any_provider_gate_closed() && st.blocked_providers.is_empty() {
                        self.accept_locked(env, &mut inner, &ip, &t).await;
                    } else {
                        if let Some(p) = inner.invalidate_alert() {
                            env.hold_queue.remove(&p.id).await;
                        }
                        if st.blocked_providers.is_empty() {
                            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
                            env.hold_queue.cancel_all_superseded().await;
                        }
                        inner.baseline = Some(Baseline {
                            ip,
                            country: Some(t.country_code.clone()),
                            trusted: true,
                        });
                        inner.handled_ip = None;
                        inner.needs_reaudit = false;
                        self.clear_until_network_change_locked(&mut inner);
                        self.set_gate_reason(None);
                        self.sync_gates_with_state_and_pending(&st, None);
                        self.hide_popup(env);
                    }
                }
                Err(e) => {
                    if !self.any_provider_gate_closed() {
                        if let Some(b) = inner.baseline.as_mut() {
                            b.trusted = true;
                        }
                        inner.handled_ip = None;
                    } else {
                        eprintln!(
                            "Network guard: cannot confirm the network, gate stays closed: {e}"
                        );
                    }
                }
            }
            return;
        }

        if let Some(t) = tel {
            inner.invalidate_alert();
            inner.baseline = Some(Baseline {
                ip: t.ip.clone(),
                country: Some(t.country_code.clone()),
                trusted: true,
            });
            inner.handled_ip = None;
            self.set_gate(Gate::Open);
        } else if !self.any_provider_gate_closed() {
            if let Some(b) = inner.baseline.as_mut() {
                b.trusted = true;
            }
            inner.handled_ip = None;
        }
    }
}
