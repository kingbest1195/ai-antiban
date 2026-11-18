use std::time::{Duration, Instant};
use tauri::Emitter;
use tokio::net::TcpStream;

use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::upstream::connect_via_route_with_chained;
use crate::routing::{Route, RouteDownReason, RouteSelection};

use super::responses::{send_bad_gateway, send_canary_intercepted, send_canary_protected, send_forbidden};
use super::{
    CANARY_PROBE_HOST, CANARY_PROBE_TIMEOUT_MS, ProxyServer, ROUTE_ALERT_THROTTLE_SECS,
    RouteUnavailablePayload, VERDICT_ROUTE_DOWN,
};

impl ProxyServer {
    pub(super) async fn try_silent_recovery_on_startup(
        &self,
        provider: ProviderId,
        selection: &RouteSelection,
        routed: bool,
    ) -> bool {
        if self.guard.is_manual_killswitch()
            || self.guard.pause_mode() != crate::proxy::guard::PauseMode::None
            || self.guard.has_baseline().await
            || !self.state.is_provider_blocked(provider.as_str()).await
        {
            return false;
        }
        let Ok(report) = self
            .auditor
            .evaluate_all_with(provider, &self.state, selection, false)
            .await
        else {
            return false;
        };
        let st = self.state.get_data().await;
        if crate::proxy::guard::report_allowed_for_state(&report, &st, routed) {
            let _ = self.state.unblock_provider(provider.as_str()).await;
            self.guard.ensure_open_for_verified(&report.telemetry).await;
            return true;
        }
        false
    }

    /// Fail-closed refusal for a provider whose route cannot carry traffic: records a
    /// `ROUTE_DOWN` verdict, emits `route://unavailable` (throttled) and answers 502/403.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn refuse_route_down(
        &self,
        client: &mut TcpStream,
        host: &str,
        provider: ProviderId,
        route_id: &str,
        reason: RouteDownReason,
        detail: Option<&str>,
        is_canary: bool,
    ) -> Result<(), std::io::Error> {
        self.state
            .stats()
            .record_intercepted(host, provider.as_str(), VERDICT_ROUTE_DOWN, "??");
        let sanitized_detail = detail
            .map(crate::diagnostics::sanitize_diagnostic_text)
            .unwrap_or_else(|| reason.message().to_string());
        crate::diagnostics::record(
            "proxy:route",
            &format!(
                "refuse_route_down route={route_id} provider={} reason={} detail={sanitized_detail}",
                provider.as_str(),
                reason.as_str()
            ),
        );
        if reason == RouteDownReason::Unreachable {
            self.state
                .route_health()
                .mark_unreachable(route_id, detail.unwrap_or(reason.message()));
        }
        self.emit_route_unavailable(route_id, provider, reason, detail);
        if is_canary {
            return send_canary_intercepted(client).await;
        }
        // The client of the gateway only gets a generic reason: no entry node addresses, no key
        // details (those stay in the UI event and the route health).
        let msg = format!(
            "Zastava route for {} is unavailable: {}. The connection was NOT sent directly (fail-closed).",
            provider.as_str(),
            reason.message()
        );
        if reason == RouteDownReason::Unreachable {
            send_bad_gateway(client, &msg).await
        } else {
            send_forbidden(client, &msg).await
        }
    }

    fn emit_route_unavailable(
        &self,
        route_id: &str,
        provider: ProviderId,
        reason: RouteDownReason,
        detail: Option<&str>,
    ) {
        let now = Instant::now();
        {
            let Ok(mut alerts) = self.route_alerts.lock() else {
                return;
            };
            if let Some(last) = alerts.get(route_id)
                && now.duration_since(*last) < Duration::from_secs(ROUTE_ALERT_THROTTLE_SECS)
            {
                return;
            }
            alerts.insert(route_id.to_string(), now);
        }
        if let Some(app) = &self.app_handle {
            let payload = RouteUnavailablePayload {
                route_id: route_id.to_string(),
                provider: provider.as_str().to_string(),
                reason: reason.as_str().to_string(),
                message: detail
                    .unwrap_or(reason.message_ru())
                    .chars()
                    .take(300)
                    .collect(),
            };
            let _ = app.emit("route://unavailable", &payload);
        }
    }

    /// Crash-test canary: PROTECTED only when the provider's route really carries a tunnel.
    pub(super) async fn canary_protected(
        &self,
        client: &mut TcpStream,
        host: &str,
        provider: ProviderId,
        route: Option<&Route>,
        country: &str,
    ) -> Result<(), std::io::Error> {
        if let Some(r) = route {
            let chained = self.transit.chained_proxy(self.bound_addr.port());
            let probe = connect_via_route_with_chained(
                r,
                CANARY_PROBE_HOST,
                443,
                Duration::from_millis(CANARY_PROBE_TIMEOUT_MS),
                self.bound_addr.port(),
                chained.as_deref(),
            )
            .await;
            match probe {
                Ok(_) => self.state.route_health().mark_reachable(&r.id),
                Err(e) => {
                    let detail = e.to_string();
                    return self
                        .refuse_route_down(
                            client,
                            host,
                            provider,
                            &r.id,
                            RouteDownReason::Unreachable,
                            Some(&detail),
                            true,
                        )
                        .await;
                }
            }
        }
        self.state
            .stats()
            .record_protected(host, provider.as_str(), country);
        send_canary_protected(client).await
    }
}
