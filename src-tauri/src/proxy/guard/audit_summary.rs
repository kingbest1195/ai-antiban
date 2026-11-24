use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[cfg(test)]
use crate::auditor::OverallStatus;
use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::{NetworkTelemetry, RiskReport};

use super::policy::{
    ips_equal, is_pinned_transient_unknown_geo, is_report_pinned_travel_only,
    report_allowed_on_network_switch, report_no_critical_and_geo_ok, severity,
};
use super::types::{AuditFn, AuditResults};

async fn audit_one_with_retry(
    audit: &AuditFn,
    provider: ProviderId,
    force: bool,
) -> Result<RiskReport, String> {
    match audit(provider, force).await {
        Ok(r) => Ok(r),
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(400)).await;
            audit(provider, force).await
        }
    }
}

/// Audits enabled providers (each on its own egress) concurrently, each with 1 short retry for
/// transient VPN interface handshakes. Only the first enabled call forces a fresh geo lookup;
/// disabled providers are skipped completely.
pub(super) async fn audit_enabled(audit: &AuditFn, disabled: &HashSet<String>) -> AuditResults {
    let enabled: Vec<ProviderId> = [
        ProviderId::Anthropic,
        ProviderId::Openai,
        ProviderId::Gemini,
    ]
    .into_iter()
    .filter(|p| {
        let pid = p.as_str();
        !disabled.iter().any(|d| {
            ProviderId::from_id(d.trim())
                .map(|dp| dp.as_str() == pid)
                .unwrap_or_else(|| d.trim().eq_ignore_ascii_case(pid))
        })
    })
    .collect();

    match enabled.as_slice() {
        [] => Vec::new(),
        [a] => vec![(*a, audit_one_with_retry(audit, *a, true).await)],
        [a, b] => {
            let (ra, rb) = tokio::join!(
                audit_one_with_retry(audit, *a, true),
                audit_one_with_retry(audit, *b, false),
            );
            vec![(*a, ra), (*b, rb)]
        }
        [a, b, c, ..] => {
            let (ra, rb, rc) = tokio::join!(
                audit_one_with_retry(audit, *a, true),
                audit_one_with_retry(audit, *b, false),
                audit_one_with_retry(audit, *c, false),
            );
            vec![(*a, ra), (*b, rb), (*c, rc)]
        }
    }
}

/// Audits anthropic, openai and gemini concurrently (all enabled).
#[cfg(test)]
pub(super) async fn audit_all(audit: &AuditFn) -> AuditResults {
    audit_enabled(audit, &HashSet::new()).await
}

/// True when an individual provider has a critical risk, blocked country, or failed audit.
#[cfg(test)]
fn is_provider_critical_or_blocked(res: &Result<RiskReport, String>) -> bool {
    match res {
        Ok(r) => !report_no_critical_and_geo_ok(r),
        Err(_) => true,
    }
}

/// True when an enabled unrouted provider's audit permits traffic without blocking or alerting.
fn provider_allowed_by_audit(
    _pid: &str,
    res: &Result<RiskReport, String>,
    st: &crate::state::AppStateData,
    trusted_baseline_ip: Option<&str>,
) -> bool {
    match res {
        Ok(r) => report_allowed_on_network_switch(r, st, trusted_baseline_ip),
        Err(_) => false,
    }
}

/// What the decision logic needs from an audit of the new network.
pub(super) struct AuditSummary {
    /// Report for the tray (the first enabled report that succeeded).
    pub(super) tray: RiskReport,
    /// The worst report among the providers that use the changed network.
    pub(super) worst: RiskReport,
    pub(super) tel: NetworkTelemetry,
    /// Every enabled unrouted provider was audited successfully and is green.
    #[cfg(test)]
    pub(super) all_green: bool,
    /// Every enabled unrouted provider was audited successfully, geo is allowed, and zero critical issues.
    #[cfg(test)]
    pub(super) no_critical_and_geo_ok: bool,
    /// Enabled unrouted providers permitted without blocking (`no_critical_and_geo_ok` / excepted / pinned-geo-ok).
    pub(super) healthy_providers: Vec<&'static str>,
    /// Enabled unrouted providers with a non-excepted critical risk, blocked geo, or failed audit.
    pub(super) affected_providers: Vec<&'static str>,
    /// Enabled unrouted providers with a critical issue (`Red`), blocked geo, or failed audit (excl. trusted exceptions).
    #[cfg(test)]
    pub(super) critical_providers: Vec<&'static str>,
    /// Enabled unrouted providers whose audit call failed (`Err(...)`).
    pub(super) failed_providers: Vec<&'static str>,
    /// Successful reports keyed by provider id for selecting worst report of a subset.
    pub(super) reports: HashMap<&'static str, RiskReport>,
}

impl AuditSummary {
    pub(super) fn worst_for(&self, providers: &[&'static str]) -> RiskReport {
        providers
            .iter()
            .filter_map(|p| self.reports.get(p))
            .max_by_key(|r| severity(r))
            .cloned()
            .unwrap_or_else(|| self.worst.clone())
    }

    /// Under `AskPopup` / `AutoLockSilent`, when the post-logout IP-change cooldown is active and
    /// a sudden IP/ASN change occurs, prevents silent `accept_locked` for unpinned/unexcepted
    /// providers and returns the Russian cooldown reason for `alert-popup` / `gate_reason`.
    pub(super) fn enforce_ip_change_cooldown(
        &mut self,
        st: &crate::state::AppStateData,
        new_ip: &str,
        old_baseline_ip: Option<&str>,
        now_i64: i64,
    ) -> Option<String> {
        let remaining = st.ip_change_cooldown_remaining_secs(now_i64)?;
        let sudden_ip_change = old_baseline_ip.is_none_or(|b| b.trim() != new_ip.trim());
        if !sudden_ip_change
            || !matches!(
                st.interception_behavior,
                crate::state::InterceptionBehavior::AskPopup
                    | crate::state::InterceptionBehavior::AutoLockSilent
            )
        {
            return None;
        }
        let mut demoted_any = false;
        let mut kept_healthy = Vec::with_capacity(self.healthy_providers.len());
        for pid in self.healthy_providers.drain(..) {
            let ip = self
                .reports
                .get(pid)
                .map(|r| r.telemetry.ip.as_str())
                .unwrap_or(new_ip);
            let is_pinned = ProviderId::from_id(pid)
                .is_some_and(|p| super::policy::is_ip_pinned_for_state(st, p, ip));
            let is_excepted = st.is_ip_trusted_for_provider(pid, ip);
            if is_pinned || is_excepted {
                kept_healthy.push(pid);
            } else {
                if !self.affected_providers.contains(&pid) {
                    self.affected_providers.push(pid);
                }
                demoted_any = true;
            }
        }
        self.healthy_providers = kept_healthy;
        if demoted_any || !self.affected_providers.is_empty() {
            Some(super::policy::format_cooldown_gate_reason(remaining))
        } else {
            None
        }
    }

    pub(super) fn is_transient_pinned_error(
        &self,
        st: &crate::state::AppStateData,
        provider: &str,
        ip: &str,
    ) -> bool {
        let is_pinned = st
            .pinned_ip_for_provider(provider, false)
            .is_some_and(|pin| ips_equal(pin, ip));
        is_pinned
            && (self.failed_providers.contains(&provider)
                || self
                    .reports
                    .get(provider)
                    .is_some_and(|r| is_pinned_transient_unknown_geo(r, st, false)))
    }

    pub(super) async fn record_healthy_history(
        &self,
        state: &crate::state::AppState,
        st: &crate::state::AppStateData,
    ) {
        let now = crate::auditor::network::current_timestamp();
        for p in &self.healthy_providers {
            if let Some(r) = self.reports.get(p)
                && (report_no_critical_and_geo_ok(r) || is_report_pinned_travel_only(r, st))
            {
                let entry = crate::state::IpHistoryEntry::new(
                    r.telemetry.ip.clone(),
                    r.telemetry.country_code.clone(),
                    r.telemetry.asn,
                    now,
                );
                let _ = state
                    .record_ip_history_for_selection(
                        p,
                        &crate::routing::RouteSelection::Direct,
                        entry,
                    )
                    .await;
            }
        }
    }
}

#[cfg(test)]
pub(super) fn summarize(results: &AuditResults, unrouted: &[&'static str]) -> Option<AuditSummary> {
    let st = crate::state::AppStateData {
        interception_behavior: crate::state::InterceptionBehavior::AutoAllowTrusted,
        ..Default::default()
    };
    summarize_for_state(results, unrouted, &st, None)
}

/// Returns `None` only when NO enabled unrouted provider produced a report (all failed or none
/// unrouted). Partial failures where the first provider fails while sibling providers succeed
/// preserve sibling results in `healthy_providers`/`affected_providers` and record the failure
/// in `failed_providers` / `affected_providers` / `critical_providers`.
pub(super) fn summarize_for_state(
    results: &AuditResults,
    unrouted: &[&'static str],
    st: &crate::state::AppStateData,
    trusted_baseline_ip: Option<&str>,
) -> Option<AuditSummary> {
    let relevant_id = |p: &ProviderId| unrouted.contains(&p.as_str());
    let relevant: Vec<&RiskReport> = results
        .iter()
        .filter(|(p, _)| relevant_id(p))
        .filter_map(|(_, r)| r.as_ref().ok())
        .collect();
    let active_report = *relevant.first()?;

    let mut worst = active_report;
    for r in relevant.iter().skip(1) {
        if severity(r) > severity(worst) {
            worst = r;
        }
    }
    #[cfg(test)]
    let any_unrouted_failed = results.iter().any(|(p, r)| relevant_id(p) && r.is_err());
    #[cfg(test)]
    let all_green = !any_unrouted_failed
        && relevant
            .iter()
            .all(|r| r.overall_status == OverallStatus::Green);
    #[cfg(test)]
    let no_critical_and_geo_ok = !any_unrouted_failed
        && !relevant.is_empty()
        && relevant.iter().all(|r| report_no_critical_and_geo_ok(r));

    let mut healthy_providers = Vec::new();
    let mut affected_providers = Vec::new();
    #[cfg(test)]
    let mut critical_providers = Vec::new();
    let mut failed_providers = Vec::new();
    let mut reports = HashMap::new();
    for (p, res) in results {
        let pid = p.as_str();
        if let Ok(r) = res {
            reports.insert(pid, r.clone());
        }
        if !unrouted.contains(&pid) {
            continue;
        }
        if res.is_err() {
            failed_providers.push(pid);
        }
        if provider_allowed_by_audit(pid, res, st, trusted_baseline_ip) {
            healthy_providers.push(pid);
        } else {
            affected_providers.push(pid);
            #[cfg(test)]
            if is_provider_critical_or_blocked(res) || st.strict_pinning_enabled {
                critical_providers.push(pid);
            }
        }
    }

    let tray = active_report.clone();
    let worst = worst.clone();
    let tel = worst.telemetry.clone();
    Some(AuditSummary {
        tray,
        worst,
        tel,
        #[cfg(test)]
        all_green,
        #[cfg(test)]
        no_critical_and_geo_ok,
        healthy_providers,
        affected_providers,
        #[cfg(test)]
        critical_providers,
        failed_providers,
        reports,
    })
}
