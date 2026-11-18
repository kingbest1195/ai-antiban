//! Sanitized diagnostic bundle and copyable error report builders.

pub use crate::core::redact::{mask_ip_address, sanitize_diagnostic_text};
use crate::{auditor, routing, state, sysproxy};
use std::collections::{BTreeMap, HashMap};

/// Sanitized route binding summary for a provider (never contains URLs, hosts, ports, or keys).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticProviderRoute {
    pub mode: String,
    pub route_id: Option<String>,
    pub name: Option<String>,
    pub country: Option<String>,
    pub enabled: bool,
    pub is_default: bool,
    pub is_profile_route: bool,
}

/// Sanitized check entry inside [`DiagnosticProviderAudit`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticCheckSummary {
    pub code: String,
    pub status: auditor::CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<auditor::UnknownReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_via: Option<String>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_addrs_masked: Vec<String>,
}

/// Sanitized audit status per AI provider (`anthropic`, `openai`, `gemini`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticProviderAudit {
    pub status: String,
    pub trust_score: Option<u8>,
    pub incomplete: bool,
    pub unknown_count: u8,
    pub applicable_count: u8,
    pub exit_ip_masked: Option<String>,
    pub exit_country: Option<String>,
    pub asn: Option<u32>,
    pub checks: Vec<DiagnosticCheckSummary>,
    pub last_history_country: Option<String>,
    pub last_history_ip_masked: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Sanitized gateway counters included in [`DiagnosticBundle`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticGatewayStats {
    pub protected_ai_requests: u64,
    pub intercepted_leaks: u64,
    pub direct_bypassed_requests: u64,
    pub active_ai_tunnels: u64,
    pub uptime_seconds: u64,
}

/// Sanitized, shareable diagnostic report produced by `export_diagnostic_bundle_cmd`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticBundle {
    pub app_version: String,
    pub os: String,
    pub arch: String,
    pub os_version: Option<String>,
    pub sysproxy_enabled: bool,
    pub cli_protection_enabled: bool,
    pub cli_mode: state::CliMode,
    pub split_tunnel_mode: bool,
    pub sync_ai_tz_enabled: bool,
    pub synced_ai_timezone: Option<String>,
    pub hide_ip_mode: bool,
    pub strict_pinning_enabled: bool,
    pub manual_killswitch: bool,
    pub interception_behavior: state::InterceptionBehavior,
    pub gateway_port: u16,
    pub blocked_providers: Vec<String>,
    pub session_allowed_providers: Vec<String>,
    pub provider_routes: BTreeMap<String, DiagnosticProviderRoute>,
    pub audit_reports: BTreeMap<String, DiagnosticProviderAudit>,
    pub gateway_stats: DiagnosticGatewayStats,
    pub recent_diagnostics: Vec<String>,
}

pub fn build_error_diagnostics_report(
    error_title: Option<&str>,
    error_message: Option<&str>,
    gateway_port: u16,
    os_lines: &[String],
    entries: &[String],
) -> String {
    let mut out = Vec::new();
    out.push(format!(
        "Zastava v{} ({}/{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    if let Some(title) = error_title.map(str::trim).filter(|s| !s.is_empty()) {
        out.push(format!("Error title: {title}"));
    }
    if let Some(msg) = error_message.map(str::trim).filter(|s| !s.is_empty()) {
        out.push(format!("Error text: {msg}"));
    }
    out.push(format!(
        "State: sysproxy_active={}, cli_active={}, gateway_port={}, chained_proxy_set={}",
        sysproxy::is_sysproxy_active(),
        sysproxy::is_cli_protection_enabled(),
        gateway_port,
        sysproxy::get_chained_proxy().is_some()
    ));

    if !os_lines.is_empty() {
        out.push("--- OS Network Snapshot ---".to_string());
        out.extend(os_lines.iter().cloned());
    }

    out.push("--- Diagnostic Log ---".to_string());
    if entries.is_empty() {
        out.push("(no recorded events in this session)".to_string());
    } else {
        out.extend(entries.iter().cloned());
    }

    out.join("\n")
}

fn sanitize_report_entry(
    report: &auditor::RiskReport,
    last_history: Option<&state::IpHistoryEntry>,
) -> DiagnosticProviderAudit {
    let status = match report.overall_status {
        auditor::OverallStatus::Green => "green",
        auditor::OverallStatus::Yellow => "yellow",
        auditor::OverallStatus::Red => "red",
    }
    .to_string();

    let exit_ip_masked =
        (!report.telemetry.ip.trim().is_empty()).then(|| mask_ip_address(&report.telemetry.ip));
    let exit_country = (!report.telemetry.country_code.trim().is_empty())
        .then(|| report.telemetry.country_code.trim().to_uppercase());

    let checks = report
        .checks
        .iter()
        .map(|c| {
            let source_addrs_masked = c
                .detail
                .as_ref()
                .map(|d| {
                    d.sources
                        .iter()
                        .filter_map(|s| s.addr.as_deref())
                        .map(mask_ip_address)
                        .collect()
                })
                .unwrap_or_default();
            DiagnosticCheckSummary {
                code: c.code.clone(),
                status: c.status,
                reason: c.reason,
                measured_via: c.measured_via.as_deref().map(sanitize_diagnostic_text),
                message: sanitize_diagnostic_text(&c.message),
                source_addrs_masked,
            }
        })
        .collect();

    DiagnosticProviderAudit {
        status,
        trust_score: Some(report.trust_score),
        incomplete: report.incomplete,
        unknown_count: report.unknown_count,
        applicable_count: report.applicable_count,
        exit_ip_masked,
        exit_country,
        asn: report.telemetry.asn,
        checks,
        last_history_country: last_history.map(|h| h.country_code.clone()),
        last_history_ip_masked: last_history.map(|h| mask_ip_address(&h.ip)),
        error: None,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_sanitized_diagnostic_bundle(
    data: &state::AppStateData,
    stats: &state::GatewayStatsSnapshot,
    provider_reports: &HashMap<String, Result<auditor::RiskReport, String>>,
    sysproxy_enabled: bool,
    cli_protection_enabled: bool,
    gateway_port: u16,
    os_version: Option<String>,
    diag_entries: &[String],
) -> DiagnosticBundle {
    let mut blocked_providers: Vec<String> = data.blocked_providers.iter().cloned().collect();
    blocked_providers.sort();
    let mut session_allowed_providers: Vec<String> =
        data.session_allowed_providers.iter().cloned().collect();
    session_allowed_providers.sort();

    let mut provider_routes = BTreeMap::new();
    let mut audit_reports = BTreeMap::new();

    for provider in state::KNOWN_PROVIDERS {
        let selection = routing::select_route(data, provider);
        let route_summary = match selection {
            routing::RouteSelection::Direct => DiagnosticProviderRoute {
                mode: "direct".to_string(),
                route_id: None,
                name: None,
                country: None,
                enabled: true,
                is_default: false,
                is_profile_route: false,
            },
            routing::RouteSelection::Route(r) => DiagnosticProviderRoute {
                mode: "route".to_string(),
                route_id: Some(r.id.clone()),
                name: Some(sanitize_diagnostic_text(&r.label)),
                country: r.country.clone(),
                enabled: r.enabled,
                is_default: data.default_route_id.as_deref() == Some(r.id.as_str()),
                is_profile_route: data.profile_route_id.as_deref() == Some(r.id.as_str()),
            },
            routing::RouteSelection::Missing(id) => DiagnosticProviderRoute {
                mode: "missing".to_string(),
                route_id: Some(sanitize_diagnostic_text(&id)),
                name: None,
                country: None,
                enabled: false,
                is_default: false,
                is_profile_route: false,
            },
            routing::RouteSelection::Invalid(_) => DiagnosticProviderRoute {
                mode: "invalid".to_string(),
                route_id: Some(routing::INVALID_PROFILE_ROUTE_ID.to_string()),
                name: None,
                country: None,
                enabled: false,
                is_default: false,
                is_profile_route: true,
            },
        };
        provider_routes.insert(provider.to_string(), route_summary);

        let scoped_key = data.ip_history_key_for_provider(provider);
        let last_history = data
            .ip_history
            .get(&scoped_key)
            .and_then(|h| h.last())
            .or_else(|| data.ip_history.get(provider).and_then(|h| h.last()));
        let audit_summary = match provider_reports.get(provider) {
            Some(Ok(report)) => sanitize_report_entry(report, last_history),
            Some(Err(err)) => DiagnosticProviderAudit {
                status: "unavailable".to_string(),
                trust_score: None,
                incomplete: true,
                unknown_count: 0,
                applicable_count: 0,
                exit_ip_masked: None,
                exit_country: None,
                asn: last_history.and_then(|h| h.asn),
                checks: Vec::new(),
                last_history_country: last_history.map(|h| h.country_code.clone()),
                last_history_ip_masked: last_history.map(|h| mask_ip_address(&h.ip)),
                error: Some(sanitize_diagnostic_text(err)),
            },
            None => DiagnosticProviderAudit {
                status: "unavailable".to_string(),
                trust_score: None,
                incomplete: true,
                unknown_count: 0,
                applicable_count: 0,
                exit_ip_masked: None,
                exit_country: None,
                asn: last_history.and_then(|h| h.asn),
                checks: Vec::new(),
                last_history_country: last_history.map(|h| h.country_code.clone()),
                last_history_ip_masked: last_history.map(|h| mask_ip_address(&h.ip)),
                error: None,
            },
        };
        audit_reports.insert(provider.to_string(), audit_summary);
    }

    DiagnosticBundle {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        os_version: os_version.map(|v| sanitize_diagnostic_text(&v)),
        sysproxy_enabled,
        cli_protection_enabled,
        cli_mode: data.cli_mode,
        split_tunnel_mode: data.split_tunnel_mode,
        sync_ai_tz_enabled: data.sync_ai_tz_enabled,
        synced_ai_timezone: data.synced_ai_timezone.clone(),
        hide_ip_mode: data.hide_ip_mode,
        strict_pinning_enabled: data.strict_pinning_enabled,
        manual_killswitch: data.manual_killswitch,
        interception_behavior: data.interception_behavior,
        gateway_port,
        blocked_providers,
        session_allowed_providers,
        provider_routes,
        audit_reports,
        gateway_stats: DiagnosticGatewayStats {
            protected_ai_requests: stats.protected_ai_requests,
            intercepted_leaks: stats.intercepted_leaks,
            direct_bypassed_requests: stats.direct_bypassed_requests,
            active_ai_tunnels: stats.active_ai_tunnels,
            uptime_seconds: stats.uptime_seconds,
        },
        recent_diagnostics: diag_entries
            .iter()
            .map(|line| sanitize_diagnostic_text(line))
            .collect(),
    }
}

pub fn extract_os_version_from_snapshot(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .find_map(|l| l.strip_prefix("macos_version: "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
