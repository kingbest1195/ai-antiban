//! Strictly read-only Clean Room pre-flight trace detector.
//!
//! Safety Charter invariant: NEVER reads Windows Credential Manager, DPAPI keys,
//! SQLite `Cookies` contents, macOS Keychain, or session tokens. Only inspects
//! filesystem metadata/existence and process lists.

use std::path::{Path, PathBuf};

use crate::auditor::RiskReport;
use crate::auditor::geo_matrix::{CheckStatus, ProviderId};
use crate::auditor::profile_switcher::ClaudeProfile;
use crate::state::AppStateData;

pub use super::detector_env::{DetectorEnv, RealDetectorEnv};
use super::tz_guard::evaluate_tz_guard;
use super::{CleanRoomAuditReport, CleanRoomFinding, CleanRoomFixAction, TraceSeverity};

pub const IP_COLLISION_WINDOW_SECS: u64 = 30 * 86_400;

const CLAUDE_TRACE_FILES: &[&str] = &[
    "Cookies",
    "Network/Cookies",
    "Local Storage",
    "ant-device-registry.json",
    "ccd-ids.json",
    "dispatch-footprint-census.json",
];

const CHATGPT_TRACE_FILES: &[&str] = &["Cookies", "Network/Cookies", "Local Storage"];

pub struct DetectorInput<'a> {
    pub target_provider: ProviderId,
    pub target_profile_id: Option<&'a str>,
    pub risk_report: Option<&'a RiskReport>,
    pub audit_error: Option<&'a str>,
    pub state_data: &'a AppStateData,
    pub claude_profiles: &'a [ClaudeProfile],
    pub os_tz: Option<&'a str>,
    pub now_secs: u64,
}

pub fn run_clean_room_audit_with<E: DetectorEnv>(
    env: &E,
    input: &DetectorInput<'_>,
) -> CleanRoomAuditReport {
    let mut findings = Vec::new();

    check_browser_traces(env, &mut findings);
    check_desktop_app_traces(env, input.target_provider, &mut findings);
    check_cursor_traces(env, &mut findings);
    check_running_processes(env, input.target_provider, &mut findings);

    let exit_ip = input.risk_report.map(|r| r.telemetry.ip.clone());
    let exit_country = input.risk_report.map(|r| r.telemetry.country_code.clone());
    let exit_timezone = input.risk_report.and_then(|r| r.telemetry.timezone.clone());

    let ip_is_tainted = check_ip_collision(input, exit_ip.as_deref(), &mut findings);
    let tz_eval = evaluate_tz_guard(env.is_windows(), input.os_tz, exit_timezone.as_deref());
    check_network_and_os_hygiene(
        input.risk_report,
        input.audit_error,
        &tz_eval,
        &mut findings,
    );

    if input.state_data.manual_killswitch {
        findings.push(CleanRoomFinding {
            id: "manual_killswitch_active".to_string(),
            category: "network_leak".to_string(),
            title: "Manual kill-switch is active".to_string(),
            detail: "Disable the manual kill-switch before launching an isolated browser."
                .to_string(),
            severity: TraceSeverity::Critical,
            path_hint: None,
            fix_action: Some(CleanRoomFixAction::SwitchRouteOrVpn),
        });
    }

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == TraceSeverity::Critical)
        .count();
    let warning_count = findings
        .iter()
        .filter(|f| f.severity == TraceSeverity::Warning)
        .count();
    let ready_to_launch = critical_count == 0 && !input.state_data.manual_killswitch;

    CleanRoomAuditReport {
        checked_at: input.now_secs,
        exit_ip,
        exit_country,
        exit_timezone,
        ip_is_tainted,
        os_tz_matches_exit: tz_eval.os_tz_matches_exit,
        findings,
        critical_count,
        warning_count,
        ready_to_launch,
    }
}

fn check_browser_traces<E: DetectorEnv>(env: &E, findings: &mut Vec<CleanRoomFinding>) {
    let found: Vec<&'static str> = env
        .browser_profile_dirs()
        .into_iter()
        .filter(|(_, p)| env.path_exists(p))
        .map(|(name, _)| name)
        .collect();
    if !found.is_empty() {
        findings.push(CleanRoomFinding {
            id: "personal_browsers_present".to_string(),
            category: "browser".to_string(),
            title: "Personal browser profiles detected".to_string(),
            detail: format!(
                "Detected existing profiles ({}). Use Zastava's isolated sandbox window instead of your personal browser.",
                found.join(", ")
            ),
            severity: TraceSeverity::Warning,
            path_hint: None,
            fix_action: Some(CleanRoomFixAction::AcknowledgeSandboxIsolation),
        });
    }
}

fn check_desktop_app_traces<E: DetectorEnv>(
    env: &E,
    target_provider: ProviderId,
    findings: &mut Vec<CleanRoomFinding>,
) {
    let claude_hits: Vec<PathBuf> = env
        .claude_data_dirs()
        .into_iter()
        .filter(|dir| {
            CLAUDE_TRACE_FILES
                .iter()
                .any(|f| env.path_exists(&dir.join(f)))
        })
        .collect();
    if !claude_hits.is_empty() {
        let severity = if target_provider == ProviderId::Anthropic {
            TraceSeverity::Critical
        } else {
            TraceSeverity::Warning
        };
        findings.push(CleanRoomFinding {
            id: "claude_desktop_traces".to_string(),
            category: "desktop_traces".to_string(),
            title: "Claude Desktop session/device traces found".to_string(),
            detail: "Cookies, Local Storage, or device registry files exist in Claude Desktop data directory.".to_string(),
            severity,
            path_hint: Some(mask_path_hint(&claude_hits[0])),
            fix_action: Some(CleanRoomFixAction::CleanAppCache {
                provider: "anthropic".to_string(),
            }),
        });
    }

    let chatgpt_hits: Vec<PathBuf> = env
        .chatgpt_data_dirs()
        .into_iter()
        .filter(|dir| {
            CHATGPT_TRACE_FILES
                .iter()
                .any(|f| env.path_exists(&dir.join(f)))
        })
        .collect();
    if !chatgpt_hits.is_empty() {
        let severity = if target_provider == ProviderId::Openai {
            TraceSeverity::Critical
        } else {
            TraceSeverity::Warning
        };
        findings.push(CleanRoomFinding {
            id: "chatgpt_desktop_traces".to_string(),
            category: "desktop_traces".to_string(),
            title: "ChatGPT Desktop session traces found".to_string(),
            detail: "Cookies or Local Storage files exist in ChatGPT Desktop data directory."
                .to_string(),
            severity,
            path_hint: Some(mask_path_hint(&chatgpt_hits[0])),
            fix_action: Some(CleanRoomFixAction::CleanAppCache {
                provider: "openai".to_string(),
            }),
        });
    }
}

fn check_cursor_traces<E: DetectorEnv>(env: &E, findings: &mut Vec<CleanRoomFinding>) {
    if let Some(dir) = env
        .cursor_data_dirs()
        .into_iter()
        .find(|d| env.path_exists(d))
    {
        findings.push(CleanRoomFinding {
            id: "cursor_ide_present".to_string(),
            category: "desktop_traces".to_string(),
            title: "Cursor IDE profile directory detected".to_string(),
            detail: "Close or re-authenticate Cursor before switching AI accounts.".to_string(),
            severity: TraceSeverity::Warning,
            path_hint: Some(mask_path_hint(&dir)),
            fix_action: Some(CleanRoomFixAction::CloseRunningApp {
                process_name: if env.is_windows() {
                    "Cursor.exe"
                } else {
                    "Cursor"
                }
                .to_string(),
            }),
        });
    }
}

fn check_running_processes<E: DetectorEnv>(
    env: &E,
    target_provider: ProviderId,
    findings: &mut Vec<CleanRoomFinding>,
) {
    let running = env.running_ai_processes();
    for proc_name in running {
        let lower = proc_name.to_ascii_lowercase();
        let is_claude = lower.contains("claude");
        let is_chatgpt = lower.contains("chatgpt");
        let is_target = (is_claude && target_provider == ProviderId::Anthropic)
            || (is_chatgpt && target_provider == ProviderId::Openai);
        let severity = if is_target {
            TraceSeverity::Critical
        } else {
            TraceSeverity::Warning
        };
        findings.push(CleanRoomFinding {
            id: format!("running_app_{}", lower.replace(".exe", "")),
            category: "desktop_traces".to_string(),
            title: format!("{proc_name} is currently running"),
            detail: "Running desktop clients hold file locks and active sessions.".to_string(),
            severity,
            path_hint: None,
            fix_action: Some(CleanRoomFixAction::CloseRunningApp {
                process_name: proc_name,
            }),
        });
    }
}

fn check_ip_collision(
    input: &DetectorInput<'_>,
    exit_ip: Option<&str>,
    findings: &mut Vec<CleanRoomFinding>,
) -> bool {
    let Some(ip) = exit_ip.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    let mut tainted = false;
    if input.state_data.clean_room.tainted_ips.contains_key(ip) {
        tainted = true;
        findings.push(CleanRoomFinding {
            id: "exit_ip_tainted".to_string(),
            category: "ip_collision".to_string(),
            title: "Current exit IP is marked tainted".to_string(),
            detail: format!("Exit IP {ip} was previously flagged for a ban or Persona trigger."),
            severity: TraceSeverity::Critical,
            path_hint: None,
            fix_action: Some(CleanRoomFixAction::SwitchRouteOrVpn),
        });
    }

    let cutoff = input.now_secs.saturating_sub(IP_COLLISION_WINDOW_SECS);
    let used_by_other_clean = input.state_data.clean_room.profiles.iter().any(|p| {
        Some(p.id.as_str()) != input.target_profile_id
            && p.last_exit_ip.as_deref() == Some(ip)
            && p.last_opened_at.unwrap_or(p.created_at) >= cutoff
    });
    let used_by_claude_profile = input
        .claude_profiles
        .iter()
        .any(|p| !p.is_active && p.bound_ip.as_deref() == Some(ip) && p.last_used_at >= cutoff);
    let used_in_history = input
        .state_data
        .ip_history
        .values()
        .flatten()
        .any(|entry| entry.ip == ip && entry.timestamp >= cutoff);

    if used_by_other_clean || used_by_claude_profile {
        findings.push(CleanRoomFinding {
            id: "ip_used_by_other_profile".to_string(),
            category: "ip_collision".to_string(),
            title: "Exit IP collided with another profile (30d)".to_string(),
            detail: format!("Exit IP {ip} was used by another profile within the last 30 days."),
            severity: TraceSeverity::Critical,
            path_hint: None,
            fix_action: Some(CleanRoomFixAction::SwitchRouteOrVpn),
        });
    } else if used_in_history && !tainted {
        findings.push(CleanRoomFinding {
            id: "ip_seen_in_history".to_string(),
            category: "ip_collision".to_string(),
            title: "Exit IP was previously used in session history (30d)".to_string(),
            detail: format!("Exit IP {ip} appears in ip_history within the last 30 days."),
            severity: TraceSeverity::Warning,
            path_hint: None,
            fix_action: Some(CleanRoomFixAction::SwitchRouteOrVpn),
        });
    }

    tainted
}

fn check_network_and_os_hygiene(
    report: Option<&RiskReport>,
    audit_error: Option<&str>,
    tz_eval: &super::tz_guard::TzGuardEvaluation,
    findings: &mut Vec<CleanRoomFinding>,
) {
    if let Some(r) = report {
        let mut add_if_critical = |id: &str, title: &str, check: &crate::auditor::CheckResult| {
            if check.status == CheckStatus::Critical {
                findings.push(CleanRoomFinding {
                    id: id.to_string(),
                    category: "network_leak".to_string(),
                    title: title.to_string(),
                    detail: check.message.clone(),
                    severity: TraceSeverity::Critical,
                    path_hint: None,
                    fix_action: Some(CleanRoomFixAction::SwitchRouteOrVpn),
                });
            }
        };
        add_if_critical(
            "geo_sanctioned",
            "Exit IP geo is blocked or sanctioned",
            &r.geo_result,
        );
        add_if_critical("ipv6_leak", "IPv6 leak detected", &r.ipv6_result);
        add_if_critical("dnsbl_red", "Exit IP is listed on DNSBL", &r.dnsbl_result);
        for c in &r.checks {
            let lower = c.code.to_ascii_lowercase();
            if c.status == CheckStatus::Critical
                && (lower.contains("dns") || lower.contains("stun") || lower.contains("udp"))
            {
                findings.push(CleanRoomFinding {
                    id: format!("net_check_{lower}"),
                    category: "network_leak".to_string(),
                    title: format!("Network hygiene check failed ({})", c.code),
                    detail: c.message.clone(),
                    severity: TraceSeverity::Critical,
                    path_hint: None,
                    fix_action: Some(CleanRoomFixAction::SwitchRouteOrVpn),
                });
            }
        }
    } else {
        let detail = audit_error
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| format!("Network audit could not verify exit IP or route hygiene: {s}"))
            .unwrap_or_else(|| {
                "Network audit could not verify exit IP or route hygiene; launching is blocked until a clean exit is verified.".to_string()
            });
        findings.push(CleanRoomFinding {
            id: "network_audit_failed".to_string(),
            category: "network_leak".to_string(),
            title: "Network audit unavailable or bound route unreachable".to_string(),
            detail,
            severity: TraceSeverity::Critical,
            path_hint: None,
            fix_action: Some(CleanRoomFixAction::SwitchRouteOrVpn),
        });
    }

    if tz_eval.requires_os_sync {
        let target_iana = tz_eval
            .target_iana
            .clone()
            .unwrap_or_else(|| "America/New_York".to_string());
        findings.push(CleanRoomFinding {
            id: "windows_os_tz_mismatch".to_string(),
            category: "os_tz_locale".to_string(),
            title: "Windows OS timezone does not match exit IP".to_string(),
            detail: "Chromium on Windows ignores TZ env and reads OS timezone directly."
                .to_string(),
            severity: TraceSeverity::Critical,
            path_hint: None,
            fix_action: Some(CleanRoomFixAction::SyncOsTimezone { target_iana }),
        });
    }
}

fn mask_path_hint(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(idx) = s.find("AppData") {
        return format!("~/{}", &s[idx..].replace('\\', "/"));
    }
    if let Some(idx) = s.find("Library") {
        return format!("~/{}", &s[idx..]);
    }
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "profile-dir".to_string())
}
