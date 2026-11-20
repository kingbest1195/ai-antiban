//! Cross-platform timezone guard for Clean Room browser launches.
//!
//! - macOS: Chromium honors `TZ=<target_iana>` on child process spawn, so OS timezone does not
//!   need to be mutated.
//! - Windows: Chromium ignores `TZ` env and reads Win32 system timezone directly, so Clean Room
//!   verifies `os_tz_matches_exit` and requires `sync_os_timezone` before launch.

use crate::auditor::os_env::is_russian_or_belarusian_timezone;
use crate::os_tz::canonicalize_iana_tz;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TzGuardEvaluation {
    pub os_tz_matches_exit: bool,
    pub is_ru_by_os_tz: bool,
    pub target_iana: Option<String>,
    pub requires_os_sync: bool,
}

/// Evaluates whether the host OS timezone is safe for launching a Clean Room browser against
/// `exit_tz`. Pure helper for deterministic unit testing across Windows & macOS.
pub fn evaluate_tz_guard(
    is_windows: bool,
    os_tz: Option<&str>,
    exit_tz: Option<&str>,
) -> TzGuardEvaluation {
    let clean_os = os_tz.map(str::trim).filter(|s| !s.is_empty());
    let clean_exit = exit_tz.map(str::trim).filter(|s| !s.is_empty());
    let canon_os = clean_os.map(canonicalize_iana_tz);
    let canon_exit = clean_exit.map(canonicalize_iana_tz);

    let is_ru_by_os_tz = canon_os.is_some_and(is_russian_or_belarusian_timezone);

    let os_matches_exit = match (canon_os, canon_exit) {
        (Some(o), Some(e)) => o.eq_ignore_ascii_case(e),
        (Some(_), None) => !is_ru_by_os_tz,
        (None, _) => !is_windows,
    };

    if is_windows {
        let requires_os_sync = !os_matches_exit || is_ru_by_os_tz;
        TzGuardEvaluation {
            os_tz_matches_exit: os_matches_exit && !is_ru_by_os_tz,
            is_ru_by_os_tz,
            target_iana: canon_exit.map(str::to_string),
            requires_os_sync,
        }
    } else {
        // On macOS, `TZ=<exit_tz>` is injected into the sandboxed browser child process.
        TzGuardEvaluation {
            os_tz_matches_exit: os_matches_exit,
            is_ru_by_os_tz,
            target_iana: canon_exit.map(str::to_string),
            requires_os_sync: false,
        }
    }
}

/// Returns the IANA timezone string to pass as `TZ` env on macOS browser spawn.
pub fn resolve_target_tz_for_spawn(is_macos: bool, exit_tz: Option<&str>) -> Option<String> {
    if !is_macos {
        return None;
    }
    exit_tz
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(canonicalize_iana_tz)
        .filter(|tz| !is_russian_or_belarusian_timezone(tz))
        .map(str::to_string)
}
