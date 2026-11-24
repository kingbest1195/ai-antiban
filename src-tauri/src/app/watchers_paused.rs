use std::sync::Arc;

use crate::{auditor, proxy, state};

/// Lightweight silent recovery check while `PauseMode::UntilNetworkChange` is active.
/// Evaluates blocked unrouted providers that have a pinned IP and attempts `try_auto_unblock_pinned_providers`.
/// Returns `Some(report)` only when pinned providers unblocked and pause cleared; otherwise `None`
/// (emitting zero UI events so the tray stays smoothly on Gray `Пауза`).
pub async fn try_silent_paused_recovery(
    risk_auditor: &auditor::Auditor,
    app_state: &state::AppState,
    guard: &Arc<proxy::NetworkGuard>,
    protection: auditor::AuditProtectionFlags,
) -> Option<auditor::RiskReport> {
    if guard.pause_mode() != proxy::PauseMode::UntilNetworkChange
        || guard.is_manual_killswitch()
        || guard.any_provider_gate_pending()
    {
        return None;
    }
    let st = app_state.get_data().await;
    if st.blocked_providers.is_empty() {
        return None;
    }
    let pinned_blocked: Vec<auditor::ProviderId> = st
        .enabled_unrouted_providers()
        .into_iter()
        .filter(|p| {
            st.blocked_providers.contains(*p) && st.pinned_ip_for_provider(p, false).is_some()
        })
        .filter_map(auditor::ProviderId::from_id)
        .collect();
    if pinned_blocked.is_empty() {
        return None;
    }
    let mut reports = Vec::with_capacity(pinned_blocked.len());
    for pid in pinned_blocked {
        if let Ok(report) = risk_auditor
            .evaluate_all_with_protection(pid, app_state, false, protection)
            .await
        {
            reports.push(report);
        }
    }
    if reports.is_empty() {
        return None;
    }
    if proxy::try_auto_unblock_pinned_providers(app_state, guard, &reports).await
        && !guard.is_paused()
    {
        reports.into_iter().next()
    } else {
        None
    }
}
