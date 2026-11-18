//! Scoring logic for the 14-point audit report.

use super::{CheckResult, CheckStatus, OverallStatus};

/// Positions in `RiskReport::checks` of the core checks (geo matrix, impossible travel): when one
/// of them could not be performed the gateway must not let traffic through on its own (fail-closed).
/// An `Unknown` in any other check is shown, but does not change the admit decision.
pub(super) const CORE_CHECKS: [usize; 2] = [0, 2];

/// Outcome of scoring the checks of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub overall_status: OverallStatus,
    pub trust_score: u8,
    pub unknown_count: u8,
    pub applicable_count: u8,
    pub incomplete: bool,
}

/// `(unknown_count, applicable_count)`: not-applicable checks are in neither.
pub fn count_checks(checks: &[CheckResult]) -> (u8, u8) {
    let not_applicable = checks.iter().filter(|c| c.is_not_applicable()).count();
    let unknown = checks.iter().filter(|c| c.is_unknown()).count() - not_applicable;
    let applicable = checks.len() - not_applicable;
    (unknown.min(255) as u8, applicable.min(255) as u8)
}

/// Failed/timed-out/disagreeing DNS resolver probes (indices 6 and 10) must not cap the trust
/// score at 94 or flip the report into `incomplete`/yellow when every other check is clean.
/// `DNS_WHOAMI_FAKE_IP` (active local TUN DNS stub) is intentionally NOT exempted here.
fn is_exempt_dns_unknown(index: usize, check: &CheckResult) -> bool {
    if !matches!(index, 6 | 10) || !check.is_unknown() || check.is_not_applicable() {
        return false;
    }
    matches!(
        check.code.as_str(),
        "DNS_WHOAMI_TIMEOUT"
            | "DNS_WHOAMI_UNREACHABLE"
            | "DNS_WHOAMI_UNSUPPORTED"
            | "DNS_WHOAMI_EMPTY"
            | "DNS_WHOAMI_SINGLE_SOURCE"
            | "DNS_WHOAMI_DISAGREE"
            | "DNS_RESOLVER_GEO_UNAVAILABLE"
            | "DNS_COUNTRY_NO_EXIT"
            | "DNS_UNSUPPORTED_OS"
            | "DNS_RESOLVERS_UNREADABLE"
            | "DNS_RESOLVERS_EMPTY"
            | "CHECK_TIMEOUT"
            | "CHECK_INTERNAL_ERROR"
    )
}

/// Critical -40, Warning -15, Unknown -5 (the sum of the Unknown penalties is capped at -15);
/// not-applicable checks cost nothing. With any non-exempt Unknown the score never exceeds 94.
pub fn score_checks(checks: &[CheckResult], is_pinned: bool) -> Verdict {
    const UNKNOWN_PENALTY: i32 = 5;
    const UNKNOWN_PENALTY_CAP: i32 = 15;
    const MAX_SCORE_WITH_UNKNOWN: i32 = 94;

    let (unknown_count, applicable_count) = count_checks(checks);
    let scoring_unknown_count = checks
        .iter()
        .enumerate()
        .filter(|(idx, c)| {
            c.is_unknown() && !c.is_not_applicable() && !is_exempt_dns_unknown(*idx, c)
        })
        .count();
    let mut score: i32 = 100;
    let mut has_critical = false;
    let mut has_warning = false;

    for check in checks {
        match check.status {
            CheckStatus::Critical => {
                has_critical = true;
                score -= 40;
            }
            CheckStatus::Warning => {
                has_warning = true;
                score -= 15;
            }
            CheckStatus::Ok | CheckStatus::Unknown => {}
        }
    }
    score -= (scoring_unknown_count as i32 * UNKNOWN_PENALTY).min(UNKNOWN_PENALTY_CAP);

    // A core check that could not be performed can never end in an automatic "green".
    let core_unknown = CORE_CHECKS
        .iter()
        .filter_map(|&i| checks.get(i))
        .any(|c| c.is_unknown() && !c.is_not_applicable());

    if is_pinned && !has_critical {
        score = (score + 10).min(100);
    }
    if scoring_unknown_count > 0 {
        score = score.min(MAX_SCORE_WITH_UNKNOWN);
    }

    let overall_status = if has_critical {
        score = score.clamp(0, 35);
        OverallStatus::Red
    } else if has_warning || core_unknown {
        score = score.clamp(36, 85);
        OverallStatus::Yellow
    } else {
        score = score.clamp(
            86,
            if scoring_unknown_count > 0 {
                MAX_SCORE_WITH_UNKNOWN
            } else {
                100
            },
        );
        OverallStatus::Green
    };

    Verdict {
        overall_status,
        trust_score: score as u8,
        unknown_count,
        applicable_count,
        incomplete: scoring_unknown_count > 0,
    }
}
