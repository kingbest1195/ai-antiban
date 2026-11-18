use tokio::net::TcpStream;

use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::guard::Gate;
use crate::routing::{INVALID_PROFILE_ROUTE_ID, Route, RouteDownReason, RouteSelection};
use crate::state::IpHistoryEntry;

use super::ProxyServer;
use super::responses::{send_canary_intercepted, send_forbidden};
use super::ssrf::{parse_host_port, validate_tunnel_target};

impl ProxyServer {
    pub(super) async fn handle_connect_request(
        &self,
        client: &mut TcpStream,
        raw_target: &str,
        peer_port: u16,
        user_agent: Option<String>,
    ) -> Result<(), std::io::Error> {
        let (host, port) = parse_host_port(raw_target);

        if let Err(reason) = validate_tunnel_target(&host, port, self.bound_addr.port()) {
            return send_forbidden(client, reason).await;
        }

        let is_canary = host == "canary-test.anthropic.zastava.local";
        let st_snapshot = self.state.get_data().await;
        let provider_opt = ProviderId::from_host_with_custom(&host, &st_snapshot.custom_ai_domains)
            .filter(|p| !st_snapshot.is_provider_disabled(p.as_str()));

        let provider = match provider_opt {
            Some(p) => {
                // Only a tunnel to an enabled AI host is an AI request (the canary is Zastava's
                // own probe). Disabled providers & transit traffic pass through directly.
                if !is_canary {
                    self.coverage.record_incoming(
                        peer_port,
                        user_agent,
                        crate::proxy::coverage::TrafficKind::AiRequest,
                    );
                }
                p
            }
            None => {
                // Direct pass-through for non-AI or monitoring-disabled domains: allows terminal
                // users to set HTTPS_PROXY cleanly without interfering with excluded providers.
                self.state.stats().record_direct_bypassed_host(&host);
                return self
                    .tunnel_to_target(client, &host, port, None, &RouteSelection::Direct)
                    .await;
            }
        };

        // Route selection (fail-closed): once a route is chosen for this provider, the connection
        // either goes through it or is refused — never directly. This one snapshot is used for the
        // audit AND for the tunnel; the tunnel re-checks it right before it connects and watches it
        // for as long as it lives (`RouteWatch`).
        let selection = self.state.route_selection(provider.as_str()).await;
        let route: Option<Route> = match &selection {
            RouteSelection::Direct => None,
            RouteSelection::Missing(id) => {
                return self
                    .refuse_route_down(
                        client,
                        &host,
                        provider,
                        id,
                        RouteDownReason::Missing,
                        None,
                        is_canary,
                    )
                    .await;
            }
            RouteSelection::Invalid(why) => {
                return self
                    .refuse_route_down(
                        client,
                        &host,
                        provider,
                        INVALID_PROFILE_ROUTE_ID,
                        RouteDownReason::Invalid,
                        Some(why),
                        is_canary,
                    )
                    .await;
            }
            RouteSelection::Route(r) => {
                if let Err(reason) = r.check_usable(crate::auditor::network::current_timestamp()) {
                    return self
                        .refuse_route_down(client, &host, provider, &r.id, reason, None, is_canary)
                        .await;
                }
                Some(r.clone())
            }
        };

        if route.is_some() {
            // Fixed exit IP: local network / VPN changes do not concern this provider.
            // Only the manual kill-switch ("СТОП СЕТИ") stops it.
            if self.guard.is_manual_killswitch() {
                self.state
                    .stats()
                    .record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
                if is_canary {
                    return send_canary_intercepted(client).await;
                }
                return send_forbidden(
                    client,
                    "Network kill-switch is engaged in Zastava: all AI traffic is stopped.",
                )
                .await;
            }
        } else {
            // Step 0: Fast Kernel Route Check & Network guard — a sudden IP change freezes every connection until the
            // user confirms the new network (or the old IP comes back).
            if !self.state.is_split_tunnel_mode().await
                && self.guard.check_route_fingerprint_sync(None)
            {
                self.auditor.resolver.invalidate_direct_cache().await;
                self.guard
                    .clear_pause_on_network_change(Some(&self.state), false)
                    .await;
            }

            self.guard.ensure_fresh().await;
            match self.guard.gate_for(provider) {
                Gate::Open => {}
                Gate::Pending => {
                    self.state.stats().record_intercepted(
                        &host,
                        provider.as_str(),
                        "BLOCKED",
                        "??",
                    );
                    if is_canary {
                        return send_canary_intercepted(client).await;
                    }
                    if self.guard.await_decision_for(provider).await != Gate::Open {
                        return send_forbidden(
                        client,
                        "Network change blocked by Zastava Risk Auditor: connection was not confirmed.",
                    )
                    .await;
                    }
                }
                Gate::Blocked => {
                    if !self
                        .try_silent_recovery_on_startup(provider, &selection, route.is_some())
                        .await
                    {
                        self.state.stats().record_intercepted(
                            &host,
                            provider.as_str(),
                            "BLOCKED",
                            "??",
                        );
                        if is_canary {
                            return send_canary_intercepted(client).await;
                        }
                        return send_forbidden(
                        client,
                        "Network change blocked by Zastava Risk Auditor: switch back to the trusted IP or confirm the new network.",
                    )
                    .await;
                    }
                }
            }
        }

        // Step 1: Check if provider is blocked
        if self.state.is_provider_blocked(provider.as_str()).await
            && !self
                .try_silent_recovery_on_startup(provider, &selection, route.is_some())
                .await
        {
            self.state
                .stats()
                .record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
            if is_canary {
                return send_canary_intercepted(client).await;
            }
            return send_forbidden(
                client,
                "Requests to this provider are blocked until network change.",
            )
            .await;
        }

        // Step 2: Check if provider has active session allowance
        if self
            .state
            .is_provider_session_allowed(provider.as_str())
            .await
        {
            if is_canary {
                return self
                    .canary_protected(client, &host, provider, route.as_ref(), "ALLOWED")
                    .await;
            }
            self.state
                .stats()
                .record_protected(&host, provider.as_str(), "ALLOWED");
            return self
                .tunnel_to_target(client, &host, port, Some(provider), &selection)
                .await;
        }

        // Step 3: Run comprehensive risk audit (on this provider's own egress).
        // If `guard.restore_epoch()` advances mid-audit (network recovered cleanly while probing
        // the old network), re-run once against the restored state/cache before deciding.
        let mut attempt = 0u8;
        let (report, st_after_audit) = loop {
            let pre_audit_epoch = self.guard.restore_epoch();
            let eval_res = self
                .auditor
                .evaluate_all_with(provider, &self.state, &selection, false)
                .await;
            match eval_res {
                Ok(r) => {
                    let st_now = self.state.get_data().await;
                    if route.is_none()
                        && attempt == 0
                        && self.guard.restore_epoch() != pre_audit_epoch
                        && !crate::proxy::guard::report_allowed_for_state(&r, &st_now, false)
                    {
                        attempt += 1;
                        continue;
                    }
                    break (r, st_now);
                }
                Err(e) if route.is_some() => {
                    let r = route.as_ref().expect("checked");
                    return self
                        .refuse_route_down(
                            client,
                            &host,
                            provider,
                            &r.id,
                            RouteDownReason::Unreachable,
                            Some(&e),
                            is_canary,
                        )
                        .await;
                }
                Err(e) => {
                    if route.is_none()
                        && attempt == 0
                        && self.guard.restore_epoch() != pre_audit_epoch
                    {
                        attempt += 1;
                        continue;
                    }
                    eprintln!("Auditor evaluation failed: {e}");
                    self.state
                        .stats()
                        .record_intercepted(&host, provider.as_str(), "ERROR", "??");
                    if is_canary {
                        return send_canary_intercepted(client).await;
                    }
                    // In case of auditor error, fall back to hold for safety
                    return send_forbidden(client, &format!("Audit error: {e}")).await;
                }
            }
        };

        // Step 4: Allow silently when verdict is Green, Yellow (`no_critical_and_geo_ok`),
        // `(provider, exit_ip)` is in `trusted_exceptions`, or IP matches pinned IP on allowed geo.
        if crate::proxy::guard::report_allowed_for_state(&report, &st_after_audit, route.is_some())
        {
            if is_canary {
                return self
                    .canary_protected(
                        client,
                        &host,
                        provider,
                        route.as_ref(),
                        &report.telemetry.country_code,
                    )
                    .await;
            }
            if crate::proxy::guard::report_no_critical_and_geo_ok(&report)
                || crate::proxy::guard::is_report_pinned_travel_only(&report, &st_after_audit)
            {
                let entry = IpHistoryEntry::new(
                    report.telemetry.ip.clone(),
                    report.telemetry.country_code.clone(),
                    report.telemetry.asn,
                    report.telemetry.resolved_at,
                );
                let _ = self
                    .state
                    .record_ip_history_for_selection(provider.as_str(), &selection, entry)
                    .await;
            }
            self.state.stats().record_protected(
                &host,
                provider.as_str(),
                &report.telemetry.country_code,
            );
            return self
                .tunnel_to_target(client, &host, port, Some(provider), &selection)
                .await;
        }

        // If critical/blocked and is canary test, immediately return intercepted status (<5ms response)
        if is_canary {
            self.state.stats().record_intercepted(
                &host,
                provider.as_str(),
                "BLOCKED",
                &report.telemetry.country_code,
            );
            return send_canary_intercepted(client).await;
        }

        // Already-blocked alert suppression: never pop up a new alert if provider is already blocked.
        if st_after_audit.blocked_providers.contains(provider.as_str())
            || self.guard.gate_for(provider) == Gate::Blocked
        {
            self.state.stats().record_intercepted(
                &host,
                provider.as_str(),
                "BLOCKED",
                &report.telemetry.country_code,
            );
            return send_forbidden(
                client,
                "Requests to this provider are blocked until network change.",
            )
            .await;
        }

        // Step 5: Non-excepted Critical / Blocked Geo / Strict Pinning mismatch -> apply preset InterceptionBehavior
        match st_after_audit.interception_behavior {
            crate::state::InterceptionBehavior::AutoLockSilent
            | crate::state::InterceptionBehavior::AutoAllowTrusted => {
                self.state.stats().record_intercepted(
                    &host,
                    provider.as_str(),
                    "BLOCKED",
                    &report.telemetry.country_code,
                );
                let _ = self.state.block_provider(provider.as_str()).await;
                self.guard.sync_gates_with_state(&self.state).await;
                return send_forbidden(client, "Auto-locked by Zastava rule").await;
            }
            crate::state::InterceptionBehavior::AskPopup => {
                // proceed with hold_queue and show_and_position_alert_popup
            }
        }
        self.handle_connect_hold(
            client,
            &host,
            port,
            provider,
            route.as_ref(),
            &selection,
            &report,
        )
        .await
    }
}
