use tauri::Emitter;
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::auditor::RiskReport;
use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::guard::Gate;
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, HoldResolution, PHASE_READY, RiskInterceptPayload, build_gate_reason,
};
use crate::routing::{Route, RouteSelection};
use crate::state::IpHistoryEntry;

use super::ProxyServer;
use super::responses::{send_forbidden, send_routing_changed};

impl ProxyServer {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_connect_hold(
        &self,
        client: &mut TcpStream,
        host: &str,
        port: u16,
        provider: ProviderId,
        route: Option<&Route>,
        selection: &RouteSelection,
        report: &RiskReport,
    ) -> Result<(), std::io::Error> {
        self.state.stats().record_intercepted(
            host,
            provider.as_str(),
            "HELD",
            &report.telemetry.country_code,
        );
        let hold_epoch = self.guard.restore_epoch();
        let (hold_id, rx, is_leader) = self
            .hold_queue
            .register_or_coalesce_provider(Uuid::new_v4().to_string(), provider.as_str())
            .await;

        if is_leader {
            let payload = RiskInterceptPayload {
                id: hold_id.clone(),
                provider,
                host: host.to_string(),
                report: Some(report.clone()),
                ttl_seconds: DEFAULT_HOLD_TTL_SECS,
                scope: "provider".to_string(),
                network_change: None,
                is_simulation: false,
                detected_at_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                phase: PHASE_READY.to_string(),
                gate_reason: Some(build_gate_reason(Some(report), None, false)),
            };

            // Emit event to UI and bring emergency modal to front once per active provider hold.
            self.hold_queue.set_alert(payload.clone());
            if let Some(app) = &self.app_handle {
                let _ = app.emit("interceptor://risk-detected", &payload);
                crate::show_and_position_alert_popup(app);
            }
        }

        // Wait up to hold_ttl (default 60s) for user action
        let resolution = tokio::time::timeout(self.hold_ttl, rx).await;

        match resolution {
            Ok(Ok(HoldResolution::Allow)) => {
                if self.guard.is_manual_killswitch() {
                    return send_forbidden(
                        client,
                        "Network kill-switch is engaged in Zastava.",
                    )
                    .await;
                }
                let entry = IpHistoryEntry::new(
                    report.telemetry.ip.clone(),
                    report.telemetry.country_code.clone(),
                    report.telemetry.asn,
                    report.telemetry.resolved_at,
                );
                let _ = self
                    .state
                    .record_ip_history_for_selection(provider.as_str(), selection, entry)
                    .await;
                self.state.stats().record_protected(
                    host,
                    provider.as_str(),
                    &report.telemetry.country_code,
                );
                self.tunnel_to_target(client, host, port, Some(provider), selection)
                    .await
            }
            Ok(Ok(HoldResolution::Superseded)) => {
                self.hold_queue.remove(&hold_id).await;
                if let Some(app) = &self.app_handle
                    && self.hold_queue.current_alert().is_none()
                {
                    crate::proxy::popup_port::hide_alert_popup(app);
                    let _ = app.emit("interceptor://resolved", "");
                }
                let st_now = self.state.get_data().await;
                let provider_disabled = st_now.is_provider_disabled(provider.as_str());
                let provider_routed =
                    crate::routing::select_route_id(&st_now, provider.as_str()).is_some();
                if !self.guard.is_manual_killswitch() && provider_routed && route.is_none() {
                    return send_routing_changed(client).await;
                }
                if !self.guard.is_manual_killswitch()
                    && (provider_disabled
                        || (!st_now.blocked_providers.contains(provider.as_str())
                            && self.guard.gate_for(provider) == Gate::Open))
                {
                    self.state
                        .stats()
                        .record_protected(host, provider.as_str(), "OK");
                    return self
                        .tunnel_to_target(client, host, port, Some(provider), selection)
                        .await;
                }
                send_forbidden(
                    client,
                    "Connection hold superseded by network or policy update.",
                )
                .await
            }
            Ok(Ok(HoldResolution::Block)) => {
                self.hold_queue.remove(&hold_id).await;
                let st_now = self.state.get_data().await;
                let now_allowed = self.guard.restore_epoch() != hold_epoch
                    || st_now.is_provider_disabled(provider.as_str())
                    || crate::routing::select_route_id(&st_now, provider.as_str()).is_some()
                    || st_now
                        .session_allowed_providers
                        .contains(provider.as_str())
                    || crate::proxy::guard::report_allowed_for_state(
                        report,
                        &st_now,
                        route.is_some(),
                    );
                if !now_allowed && !st_now.blocked_providers.contains(provider.as_str()) {
                    let _ = self.state.block_provider(provider.as_str()).await;
                    self.guard.sync_gates_with_state(&self.state).await;
                }
                send_forbidden(
                    client,
                    "Connection held and blocked by Zastava Risk Auditor.",
                )
                .await
            }
            Ok(Err(_)) => {
                self.hold_queue.remove(&hold_id).await;
                let st_now = self.state.get_data().await;
                if self.guard.restore_epoch() != hold_epoch
                    && !self.guard.is_manual_killswitch()
                    && !st_now.blocked_providers.contains(provider.as_str())
                    && self.guard.gate_for(provider) == Gate::Open
                {
                    return self
                        .tunnel_to_target(client, host, port, Some(provider), selection)
                        .await;
                }
                send_forbidden(
                    client,
                    "Connection held and blocked by Zastava Risk Auditor.",
                )
                .await
            }
            Err(_) => {
                let st_now = self.state.get_data().await;
                let epoch_changed = self.guard.restore_epoch() != hold_epoch;
                let provider_disabled = st_now.is_provider_disabled(provider.as_str());
                let provider_routed =
                    crate::routing::select_route_id(&st_now, provider.as_str()).is_some();
                let session_allowed = st_now
                    .session_allowed_providers
                    .contains(provider.as_str());
                let now_allowed = epoch_changed
                    || provider_disabled
                    || provider_routed
                    || session_allowed
                    || crate::proxy::guard::report_allowed_for_state(
                        report,
                        &st_now,
                        route.is_some(),
                    );

                if now_allowed {
                    self.hold_queue
                        .resolve(&hold_id, HoldResolution::Superseded)
                        .await;
                    if let Some(app) = &self.app_handle
                        && self.hold_queue.current_alert().is_none()
                    {
                        crate::proxy::popup_port::hide_alert_popup(app);
                        let _ = app.emit("interceptor://resolved", "");
                    }
                    if !self.guard.is_manual_killswitch() && provider_routed && route.is_none() {
                        return send_routing_changed(client).await;
                    }
                    if !self.guard.is_manual_killswitch()
                        && (provider_disabled
                            || (!st_now.blocked_providers.contains(provider.as_str())
                                && self.guard.gate_for(provider) == Gate::Open))
                    {
                        self.state
                            .stats()
                            .record_protected(host, provider.as_str(), "OK");
                        return self
                            .tunnel_to_target(client, host, port, Some(provider), selection)
                            .await;
                    }
                    return send_forbidden(
                        client,
                        "Connection hold superseded by network or policy update.",
                    )
                    .await;
                }

                // Hold TTL expired without a user decision: resolve any coalesced waiters as Block
                // and persist the block so critical providers do not stay inconsistently open.
                let timed_out_active = self
                    .hold_queue
                    .resolve(&hold_id, HoldResolution::Block)
                    .await;
                if timed_out_active
                    || (!session_allowed
                        && !st_now.is_ip_trusted_for_provider(
                            provider.as_str(),
                            &report.telemetry.ip,
                        ))
                {
                    let _ = self.state.block_provider(provider.as_str()).await;
                    self.guard.sync_gates_with_state(&self.state).await;
                }
                if let Some(app) = &self.app_handle
                    && self.hold_queue.current_alert().is_none()
                {
                    crate::proxy::popup_port::hide_alert_popup(app);
                    let _ = app.emit("interceptor://resolved", "");
                }
                send_forbidden(
                    client,
                    "Connection held and blocked by Zastava Risk Auditor.",
                )
                .await
            }
        }
    }
}
