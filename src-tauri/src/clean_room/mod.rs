//! Clean Room pre-flight trace detector, browser discovery, hardened sandbox launcher,
//! and cross-platform timezone guard.

pub mod browser_discovery;
pub mod browser_sandbox;
pub mod detector;
pub mod detector_env;
pub mod tz_guard;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

pub use crate::state::{CleanProfileStatus, CleanRoomProfile, CleanRoomState};

pub const MAX_CLEAN_PROFILE_ID_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceSeverity {
    Ok,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CleanRoomFixAction {
    CleanAppCache { provider: String },
    SyncOsTimezone { target_iana: String },
    SwitchRouteOrVpn,
    CloseRunningApp { process_name: String },
    AcknowledgeSandboxIsolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanRoomFinding {
    pub id: String,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub severity: TraceSeverity,
    pub path_hint: Option<String>,
    pub fix_action: Option<CleanRoomFixAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanRoomAuditReport {
    pub checked_at: u64,
    pub exit_ip: Option<String>,
    pub exit_country: Option<String>,
    pub exit_timezone: Option<String>,
    pub ip_is_tainted: bool,
    pub os_tz_matches_exit: bool,
    pub findings: Vec<CleanRoomFinding>,
    pub critical_count: usize,
    pub warning_count: usize,
    /// Hard Readiness Gate: `true` ONLY when `critical_count == 0 && !manual_killswitch`.
    pub ready_to_launch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedBrowser {
    pub engine: String,
    pub display_name: String,
    pub executable_path: String,
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateCleanProfileInput {
    pub label: String,
    pub provider: String,
    pub browser_engine: String,
    #[serde(default)]
    pub bound_route_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchCleanBrowserResult {
    pub profile_id: String,
    pub browser_engine: String,
    pub pid: Option<u32>,
    pub alias_port: u16,
    pub target_url: Option<String>,
    pub tz_applied: Option<String>,
    pub profile_dir: String,
}

/// Validates a Clean Room profile ID against path traversal and unsafe filesystem characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanProfileId(String);

impl CleanProfileId {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("Profile ID cannot be empty".to_string());
        }
        if trimmed.len() > MAX_CLEAN_PROFILE_ID_LEN {
            return Err(format!(
                "Profile ID exceeds max length ({MAX_CLEAN_PROFILE_ID_LEN})"
            ));
        }
        if trimmed == "."
            || trimmed == ".."
            || trimmed.contains("..")
            || trimmed.contains('/')
            || trimmed.contains('\\')
            || trimmed.contains(':')
            || trimmed.contains('\0')
        {
            return Err("Invalid profile ID: path traversal characters are forbidden".to_string());
        }
        if !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(
                "Invalid profile ID: only ASCII letters, digits, '-' and '_' are allowed"
                    .to_string(),
            );
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
