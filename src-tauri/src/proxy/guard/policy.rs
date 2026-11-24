use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::{OverallStatus, RiskReport};
use crate::proxy::hold_queue::NetworkChange;

use super::types::Baseline;

pub(crate) use crate::core::sanctions::is_blocked_geo_code;

pub(super) fn ips_equal(a: &str, b: &str) -> bool {
    let na = crate::state::normalize_ip_str(a);
    let nb = crate::state::normalize_ip_str(b);
    !na.is_empty() && na == nb
}

pub(super) fn same_ip_family(a: &str, b: &str) -> bool {
    match (
        crate::state::normalize_ip_str(a).parse::<std::net::IpAddr>(),
        crate::state::normalize_ip_str(b).parse::<std::net::IpAddr>(),
    ) {
        (Ok(ip_a), Ok(ip_b)) => ip_a.is_ipv4() == ip_b.is_ipv4(),
        _ => true,
    }
}

/// Keeps `guard` IP state anchored to `probe_ip`'s IP family when `tel_ip` has a different family
/// (e.g. dual-stack IPv6 `summary.tel.ip` vs IPv4 `probe_ip`).
pub(super) fn canonical_probe_ip(probe_ip: &str, tel_ip: &str) -> String {
    let tel = tel_ip.trim();
    let probe = probe_ip.trim();
    if !tel.is_empty() && (probe.is_empty() || same_ip_family(probe, tel)) {
        tel.to_string()
    } else {
        probe.to_string()
    }
}

fn is_travel_anomaly_code(code: &str) -> bool {
    matches!(
        code,
        "IMPOSSIBLE_TRAVEL_CRITICAL"
            | "IMPOSSIBLE_TRAVEL_WARNING"
            | "TRAVEL_ASN_JUMP_SAME_COUNTRY"
            | "AI_STUDIO_IP_UNSTABLE"
    )
}

pub(super) fn has_non_travel_critical_checks(report: &RiskReport) -> bool {
    report
        .checks
        .iter()
        .any(|c| c.status.is_critical() && !is_travel_anomaly_code(&c.code))
        || (report.pinning_result.status.is_critical()
            && !is_travel_anomaly_code(&report.pinning_result.code))
        || report.dnsbl_result.status.is_critical()
        || report.asn_result.status.is_critical()
        || report.ipv6_result.status.is_critical()
}

/// Returns `true` when `exit_ip` matches the saved/routed pin for `provider_id`.
pub(crate) fn is_ip_pinned_for_state(
    st: &crate::state::AppStateData,
    provider_id: ProviderId,
    exit_ip: &str,
) -> bool {
    let is_routed = matches!(
        crate::routing::select_route(st, provider_id.as_str()),
        crate::routing::RouteSelection::Route(_)
    );
    if is_routed {
        if let Some(pin) = st.pinned_ip_for_provider(provider_id.as_str(), true) {
            return ips_equal(pin, exit_ip);
        }
        // A bound Zastava key already locks this provider to the key endpoint IP.
        return true;
    }
    st.pinned_ip_for_provider(provider_id.as_str(), false)
        .is_some_and(|p| ips_equal(p, exit_ip))
}

pub(super) fn severity(report: &RiskReport) -> u8 {
    match report.overall_status {
        OverallStatus::Red => 2,
        OverallStatus::Yellow => 1,
        OverallStatus::Green => 0,
    }
}

pub(super) fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn network_change(
    old: Option<&Baseline>,
    new_ip: Option<String>,
    new_country: Option<String>,
) -> NetworkChange {
    NetworkChange {
        old_ip: old.map(|b| b.ip.clone()),
        old_country: old.and_then(|b| b.country.clone()),
        new_ip,
        new_country,
    }
}

/// Returns `true` when `report` has an allowed, resolved exit country and zero critical
/// failures (non-critical Yellow warnings such as KZ, RS, Timezone, AI Studio warning remain acceptable).
pub(crate) fn report_no_critical_and_geo_ok(report: &RiskReport) -> bool {
    report.overall_status != OverallStatus::Red
        && !report.checks.iter().any(|c| c.status.is_critical())
        && !report.geo_result.status.is_critical()
        && !report.geo_result.status.is_unknown()
        && !is_blocked_geo_code(&report.telemetry.country_code)
}

/// True when `report` matches the provider's saved/routed pin on a non-sanctioned/non-blocked
/// country and has NO non-travel critical checks (so `IMPOSSIBLE_TRAVEL_CRITICAL` / `WARNING`
/// alone must not brand the pinned IP as Red/`"СТОП СЕТИ"`).
pub(crate) fn is_report_pinned_travel_only(
    report: &RiskReport,
    st: &crate::state::AppStateData,
) -> bool {
    let pid = report.provider.as_str();
    let routed = crate::routing::select_route_id(st, pid).is_some();
    let is_pinned = if routed {
        st.pinned_ip_for_provider(pid, true)
            .is_none_or(|pin| ips_equal(pin, &report.telemetry.ip))
    } else {
        st.pinned_ip_for_provider(pid, false)
            .is_some_and(|pin| ips_equal(pin, &report.telemetry.ip))
    };
    if !is_pinned {
        return false;
    }
    if is_blocked_geo_code(&report.telemetry.country_code)
        || report.geo_result.status.is_critical()
        || report.geo_result.status.is_unknown()
    {
        return false;
    }
    !has_non_travel_critical_checks(report)
}

/// True when `report` matches the provider's pinned IP and the ONLY failure preventing admission
/// is a transient `Unknown` geo check during `utun` stabilization (no critical checks and not
/// a globally sanctioned/blocked country).
pub(super) fn is_pinned_transient_unknown_geo(
    report: &RiskReport,
    st: &crate::state::AppStateData,
    routed: bool,
) -> bool {
    let pid = report.provider.as_str();
    let matches_pin = st
        .pinned_ip_for_provider(pid, routed)
        .is_some_and(|pin| ips_equal(pin, &report.telemetry.ip));
    matches_pin
        && report.geo_result.status.is_unknown()
        && !report.geo_result.status.is_critical()
        && !is_blocked_geo_code(&report.telemetry.country_code)
        && !has_non_travel_critical_checks(report)
}

/// Downgrades a `Red` report for tray display when traffic is actually flowing (`!has_blocked`):
/// - Returns `Green` (or `Yellow` if unrelated warnings exist) when returning to an explicitly
///   pinned non-sanctioned IP where `IMPOSSIBLE_TRAVEL_CRITICAL` / `WARNING` was the only issue.
/// - Downgrades `Red` -> `Yellow` when the user explicitly allowed the audited provider for the
///   session or via a persistent trusted exception.
pub(crate) fn effective_tray_report<'a>(
    report: &'a RiskReport,
    has_blocked: bool,
    st: &crate::state::AppStateData,
) -> std::borrow::Cow<'a, RiskReport> {
    if !has_blocked
        && matches!(
            report.overall_status,
            OverallStatus::Red | OverallStatus::Yellow
        )
        && is_report_pinned_travel_only(report, st)
    {
        let mut adjusted = report.clone();
        if crate::auditor::history::apply_pinned_travel_grace(&mut adjusted, true) {
            return std::borrow::Cow::Owned(adjusted);
        }
    }
    let allowed = st
        .session_allowed_providers
        .contains(report.provider.as_str())
        || st.is_ip_trusted_for_provider(report.provider.as_str(), &report.telemetry.ip);
    if !has_blocked && report.overall_status == OverallStatus::Red && allowed {
        let mut adjusted = report.clone();
        adjusted.overall_status = OverallStatus::Yellow;
        std::borrow::Cow::Owned(adjusted)
    } else {
        std::borrow::Cow::Borrowed(report)
    }
}

pub(super) fn all_excepted(
    st: &crate::state::AppStateData,
    unrouted: &[&'static str],
    ip: &str,
) -> bool {
    !unrouted.is_empty()
        && unrouted
            .iter()
            .all(|p| st.is_ip_trusted_for_provider(p, ip))
}

pub(super) fn is_provider_pinned_or_excepted(
    st: &crate::state::AppStateData,
    provider: &str,
    ip: &str,
) -> bool {
    st.pinned_ip_for_provider(provider, false)
        .is_some_and(|pin| ips_equal(pin, ip))
        || st.is_ip_trusted_for_provider(provider, ip)
}

pub(super) fn all_pinned_or_excepted_for(
    st: &crate::state::AppStateData,
    unrouted: &[&'static str],
    ip: &str,
) -> bool {
    !unrouted.is_empty()
        && unrouted
            .iter()
            .all(|p| is_provider_pinned_or_excepted(st, p, ip))
}

pub(super) fn any_pinned_or_excepted_for(
    st: &crate::state::AppStateData,
    unrouted: &[&'static str],
    ip: &str,
) -> bool {
    unrouted
        .iter()
        .any(|p| is_provider_pinned_or_excepted(st, p, ip))
}

pub(super) fn any_blocked_pinned_or_excepted_for(
    st: &crate::state::AppStateData,
    unrouted: &[&'static str],
    ip: &str,
) -> bool {
    unrouted
        .iter()
        .any(|p| st.blocked_providers.contains(*p) && is_provider_pinned_or_excepted(st, p, ip))
}

pub(super) fn all_unrouted_session_or_excepted(
    unrouted: &[&'static str],
    st: &crate::state::AppStateData,
    ip: &str,
) -> bool {
    !unrouted.is_empty()
        && unrouted.iter().all(|p| {
            st.session_allowed_providers.contains(*p) || st.is_ip_trusted_for_provider(p, ip)
        })
}

/// True when `report` triggered a same-country ASN/datacenter jump or AI Studio IP instability without 4h pause.
pub(crate) fn has_same_country_asn_jump(report: &RiskReport) -> bool {
    let is_instability = |code: &str| {
        matches!(
            code,
            "TRAVEL_ASN_JUMP_SAME_COUNTRY" | "AI_STUDIO_IP_UNSTABLE"
        )
    };
    is_instability(&report.travel_result.code)
        || report.checks.iter().any(|c| is_instability(&c.code))
}

pub(super) fn format_cooldown_gate_reason(remaining_secs: u64) -> String {
    let mins = remaining_secs.div_ceil(60);
    let hours = mins / 60;
    let rem_mins = mins % 60;
    let wait_str = if hours > 0 {
        format!("{hours} ч {rem_mins} мин")
    } else {
        format!("{mins} мин")
    };
    format!(
        "Активен 4-часовой период охлаждения после выхода из Claude (осталось {wait_str}) — смена IP/ASN требует явного подтверждения"
    )
}

pub(super) fn resolve_gate_reason_with_cooldown(
    report: &RiskReport,
    net_change: &NetworkChange,
    cooldown_reason: Option<&str>,
) -> String {
    let has_high_priority_issue = report.checks.iter().any(|c| {
        c.status.is_critical()
            || matches!(
                c.code.as_str(),
                "TRAVEL_ASN_JUMP_SAME_COUNTRY" | "AI_STUDIO_IP_UNSTABLE"
            )
    }) || report.geo_result.status.is_critical()
        || report.pinning_result.status.is_critical();
    if !has_high_priority_issue && let Some(reason) = cooldown_reason {
        return reason.to_string();
    }
    crate::proxy::hold_queue::build_gate_reason(Some(report), Some(net_change), false)
}

/// True when `report` permits traffic without blocking or alerting for `st`:
/// either `(provider, exit_ip)` is in `trusted_exceptions`, OR `no_critical_and_geo_ok`
/// (Green or non-critical Yellow without strict-pinning mismatch and without
/// `TRAVEL_ASN_JUMP_SAME_COUNTRY`), OR the IP matches `pinned_ip`/`pinned_ips[provider]`
/// on an allowed geo with no non-travel critical checks.
pub(crate) fn report_allowed_for_state(
    report: &RiskReport,
    st: &crate::state::AppStateData,
    routed: bool,
) -> bool {
    let pid = report.provider.as_str();
    if st.is_ip_trusted_for_provider(pid, &report.telemetry.ip) {
        return true;
    }
    let geo_ok = !is_blocked_geo_code(&report.telemetry.country_code)
        && !report.geo_result.status.is_critical()
        && !report.geo_result.status.is_unknown();
    let has_non_travel_critical = has_non_travel_critical_checks(report);
    if has_same_country_asn_jump(report) {
        let pinned = is_ip_pinned_for_state(st, report.provider, &report.telemetry.ip);
        return pinned && geo_ok && !has_non_travel_critical;
    }
    if report_no_critical_and_geo_ok(report) {
        if st.strict_pinning_enabled
            && let Some(pin) = st.pinned_ip_for_provider(pid, routed)
            && !ips_equal(pin, &report.telemetry.ip)
        {
            return false;
        }
        return true;
    }
    let matches_pin = st
        .pinned_ip_for_provider(pid, routed)
        .is_some_and(|pin| ips_equal(pin, &report.telemetry.ip));
    matches_pin && geo_ok && !has_non_travel_critical
}

/// Returns `true` when `report` may auto-open on a network switch to a new IP without
/// prompting (`AskPopup`) or silently locking (`AutoLockSilent`).
///
/// Explicit `trusted_exceptions`, matching `pinned_ip`/`pinned_ips`, returning to an
/// already-trusted `baseline_ip`, or `InterceptionBehavior::AutoAllowTrusted` permit
/// auto-admission when `report_allowed_for_state` holds; under `AskPopup` and
/// `AutoLockSilent`, a new unpinned/unexcepted IP requires explicit user confirmation or lock.
pub(crate) fn report_allowed_on_network_switch(
    report: &RiskReport,
    st: &crate::state::AppStateData,
    trusted_baseline_ip: Option<&str>,
) -> bool {
    let pid = report.provider.as_str();
    let ip = report.telemetry.ip.trim();
    if trusted_baseline_ip.is_some_and(|b| ips_equal(b, ip))
        && st.session_allowed_providers.contains(pid)
    {
        return true;
    }
    if !report_allowed_for_state(report, st, false) {
        return false;
    }
    if st.is_ip_trusted_for_provider(pid, ip) {
        return true;
    }
    if st
        .pinned_ip_for_provider(pid, false)
        .is_some_and(|pin| ips_equal(pin, ip))
    {
        return true;
    }
    if trusted_baseline_ip.is_some_and(|b| ips_equal(b, ip)) {
        return true;
    }
    st.interception_behavior == crate::state::InterceptionBehavior::AutoAllowTrusted
}

/// Returns `true` when active AI Studio / Vertex AI traffic must be held on IP/ASN instability.
pub(crate) fn should_hold_ai_studio_session(
    provider: ProviderId,
    host: &str,
    report: &RiskReport,
    st: &crate::state::AppStateData,
    studio_stability_rule: bool,
) -> bool {
    studio_stability_rule
        && provider == ProviderId::Gemini
        && crate::auditor::geo_matrix::is_ai_studio_host(host)
        && !st.is_ip_trusted_for_provider("gemini", &report.telemetry.ip)
        && !is_report_pinned_travel_only(report, st)
        && matches!(
            report.travel_result.code.as_str(),
            "IMPOSSIBLE_TRAVEL_WARNING" | "TRAVEL_ASN_JUMP_SAME_COUNTRY" | "AI_STUDIO_IP_UNSTABLE"
        )
}
