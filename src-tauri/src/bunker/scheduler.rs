//! Background auto-backup scheduler for Data Bunker.

use std::path::Path;

use crate::state::BunkerSettings;

/// Pure scheduling predicate: returns `true` when automatic backup is enabled, local data exists,
/// and `interval_hours` (default 24h) has elapsed since `last_backup_at`.
pub fn should_run_scheduled_backup(
    settings: &BunkerSettings,
    now_secs: u64,
    has_local_data: bool,
) -> bool {
    if !settings.auto_backup_enabled || !has_local_data {
        return false;
    }
    let interval_secs = u64::from(settings.interval_hours.max(1)) * 3600;
    match settings.last_backup_at {
        None => true,
        Some(last) => now_secs.saturating_sub(last) >= interval_secs,
    }
}

/// Runs a single scheduled backup pass if due, respecting `os_effects_enabled()`.
pub fn run_scheduled_backup_if_due(
    app_data_dir: &Path,
    home_dir: &Path,
    settings: &BunkerSettings,
    now_secs: u64,
) -> Result<Option<super::BunkerBackupResult>, String> {
    if !crate::sysproxy::os_effects_enabled() {
        return Ok(None);
    }
    let status = super::get_bunker_status_in(app_data_dir, home_dir, settings);
    if !should_run_scheduled_backup(settings, now_secs, status.has_any_local_data) {
        return Ok(None);
    }
    let res = super::run_bunker_backup_in(app_data_dir, home_dir, settings, "auto", None)?;
    Ok(Some(res))
}
