//! Schema v3 state structs: Clean Room profiles, Data Bunker settings, and Persona self-check.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DEFAULT_BUNKER_INTERVAL_HOURS: u32 = 24;
pub const DEFAULT_BUNKER_RETENTION_COUNT: usize = 7;
pub const DEFAULT_BUNKER_MAX_TOTAL_MB: u64 = 500;

fn default_true() -> bool {
    true
}

fn default_bunker_interval_hours() -> u32 {
    DEFAULT_BUNKER_INTERVAL_HOURS
}

fn default_bunker_retention() -> usize {
    DEFAULT_BUNKER_RETENTION_COUNT
}

fn default_bunker_max_mb() -> u64 {
    DEFAULT_BUNKER_MAX_TOTAL_MB
}

fn default_launchpad_step() -> u8 {
    1
}

/// Lifecycle state of a Clean Room isolated browser profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CleanProfileStatus {
    #[default]
    Active,
    WarmingUp,
    Ready,
    Tainted,
}

/// 72-hour post-payment quarantine lock persisted on a Clean Room profile or global state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PostPaymentQuarantine {
    pub started_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub pinned_route_id: Option<String>,
    #[serde(default)]
    pub pinned_exit_ip: Option<String>,
    #[serde(default)]
    pub pinned_asn: Option<u32>,
    #[serde(default)]
    pub pinned_country: Option<String>,
    #[serde(default)]
    pub overridden_at: Option<u64>,
}

/// Isolated browser sandbox profile persisted inside `AppStateData.clean_room`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanRoomProfile {
    pub id: String,
    pub label: String,
    pub provider: String,
    pub browser_engine: String,
    #[serde(default)]
    pub bound_route_id: Option<String>,
    #[serde(default)]
    pub last_exit_ip: Option<String>,
    #[serde(default)]
    pub last_exit_country: Option<String>,
    #[serde(default)]
    pub status: CleanProfileStatus,
    pub created_at: u64,
    #[serde(default)]
    pub last_opened_at: Option<u64>,
    #[serde(default)]
    pub warmup_started_at: Option<u64>,
    #[serde(default = "default_launchpad_step")]
    pub launchpad_step: u8,
    #[serde(default)]
    pub completed_checklist: Vec<String>,
    #[serde(default)]
    pub post_payment_quarantine: Option<PostPaymentQuarantine>,
}

/// Persistent Clean Room state (`profiles`, `active_profile_id`, and `tainted_ips`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CleanRoomState {
    #[serde(default)]
    pub profiles: Vec<CleanRoomProfile>,
    #[serde(default)]
    pub active_profile_id: Option<String>,
    /// Exit IPs marked as tainted (ban / Persona trigger) with Unix timestamp (seconds).
    #[serde(default)]
    pub tainted_ips: HashMap<String, u64>,
    /// Fallback 72h post-payment quarantine when no Clean Room profile is active.
    #[serde(default)]
    pub global_post_payment_quarantine: Option<PostPaymentQuarantine>,
}

/// Local Data Bunker backup settings and last snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BunkerSettings {
    #[serde(default = "default_true")]
    pub auto_backup_enabled: bool,
    #[serde(default = "default_bunker_interval_hours")]
    pub interval_hours: u32,
    #[serde(default = "default_bunker_retention")]
    pub retention_count: usize,
    #[serde(default = "default_bunker_max_mb")]
    pub max_total_mb: u64,
    #[serde(default)]
    pub last_backup_at: Option<u64>,
    #[serde(default)]
    pub last_backup_size_bytes: Option<u64>,
}

impl Default for BunkerSettings {
    fn default() -> Self {
        Self {
            auto_backup_enabled: true,
            interval_hours: DEFAULT_BUNKER_INTERVAL_HOURS,
            retention_count: DEFAULT_BUNKER_RETENTION_COUNT,
            max_total_mb: DEFAULT_BUNKER_MAX_TOTAL_MB,
            last_backup_at: None,
            last_backup_size_bytes: None,
        }
    }
}

/// Voluntary behavioral risk factors used in the proactive Persona Risk Index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PersonaSelfCheck {
    #[serde(default)]
    pub bought_or_grey_account: bool,
    #[serde(default)]
    pub virtual_sms_used: bool,
    #[serde(default)]
    pub reseller_payment_used: bool,
    #[serde(default)]
    pub multi_account_same_browser: bool,
}
