//! Core OS timezone sync/restore orchestration (injectable over `OsTzPlatform` and `data_dir`).

use super::baseline::{read_baseline, remove_baseline, write_baseline_atomic};
use super::mapping::{validate_iana_tz, zones_equivalent};
use super::{
    BASELINE_FILE_NAME, EXIT_RESTORE_RAN, OS_TZ_OPS, OsTzBaseline, OsTzPlatform, OsTzSyncStatus,
    RealOsTzPlatform, resolve_app_data_dir,
};
use chrono::Utc;
use std::path::Path;
use std::sync::atomic::Ordering;

fn build_status(platform: &dyn OsTzPlatform, baseline: Option<&OsTzBaseline>) -> OsTzSyncStatus {
    let current_os_tz = platform.current_iana_timezone().ok();
    match baseline {
        Some(b) => OsTzSyncStatus {
            synced: true,
            current_os_tz,
            original_os_tz: Some(b.original_iana.clone()),
            synced_target_tz: Some(b.synced_iana.clone()),
            auto_restore_pending: true,
        },
        None => OsTzSyncStatus {
            synced: false,
            current_os_tz,
            original_os_tz: None,
            synced_target_tz: None,
            auto_restore_pending: false,
        },
    }
}

/// Returns the current OS timezone sync status using `RealOsTzPlatform`.
pub fn get_os_timezone_sync_status(data_dir: &Path) -> Result<OsTzSyncStatus, String> {
    get_os_timezone_sync_status_with(&RealOsTzPlatform, data_dir)
}

/// Returns the current OS timezone sync status using an injectable `OsTzPlatform`.
pub fn get_os_timezone_sync_status_with(
    platform: &dyn OsTzPlatform,
    data_dir: &Path,
) -> Result<OsTzSyncStatus, String> {
    let _guard = OS_TZ_OPS.lock().unwrap_or_else(|e| e.into_inner());
    let baseline = read_baseline(data_dir)?;
    Ok(build_status(platform, baseline.as_ref()))
}

/// Syncs the OS system timezone to `target_iana`, saving the original baseline atomically before
/// modifying the OS. Subsequent syncs preserve the original baseline.
pub fn sync_os_timezone(data_dir: &Path, target_iana: &str) -> Result<OsTzSyncStatus, String> {
    sync_os_timezone_with(&RealOsTzPlatform, data_dir, target_iana)
}

/// Injectable version of [`sync_os_timezone`] for unit tests.
pub fn sync_os_timezone_with(
    platform: &dyn OsTzPlatform,
    data_dir: &Path,
    target_iana: &str,
) -> Result<OsTzSyncStatus, String> {
    let _guard = OS_TZ_OPS.lock().unwrap_or_else(|e| e.into_inner());
    let clean_target = validate_iana_tz(target_iana)?;
    if crate::auditor::os_env::is_russian_or_belarusian_timezone(&clean_target) {
        return Err(format!(
            "Отказ синхронизации: часовой пояс '{clean_target}' относится к РФ/РБ."
        ));
    }

    let existing = read_baseline(data_dir)?;
    let current_iana = platform.current_iana_timezone()?;

    // If no baseline exists yet and the OS is already on the target timezone, no elevation is needed.
    if existing.is_none() && zones_equivalent(&current_iana, &clean_target) {
        return Ok(OsTzSyncStatus {
            synced: false,
            current_os_tz: Some(current_iana),
            original_os_tz: None,
            synced_target_tz: None,
            auto_restore_pending: false,
        });
    }

    let mut baseline = match existing.as_ref() {
        Some(prev) => {
            let mut b = prev.clone();
            b.synced_iana = clean_target.clone();
            b.synced_at_utc = Utc::now().to_rfc3339();
            b
        }
        None => {
            let orig_win = platform.current_windows_tz_id()?;
            let orig_auto = platform.is_auto_tz_enabled()?;
            OsTzBaseline {
                original_iana: current_iana,
                original_windows_id: orig_win,
                original_auto_tz: orig_auto,
                synced_iana: clean_target.clone(),
                synced_at_utc: Utc::now().to_rfc3339(),
            }
        }
    };

    // Persist baseline atomically BEFORE touching the OS, so a crash never loses the original TZ.
    write_baseline_atomic(data_dir, &baseline)?;

    if let Err(err) = platform.apply_timezone(&clean_target, true) {
        match existing {
            Some(prev) => {
                // Keep the prior baseline intact since the new target was not applied.
                let _ = write_baseline_atomic(data_dir, &prev);
            }
            None => {
                // Newly created baseline, OS was not changed: remove baseline.
                let _ = remove_baseline(data_dir);
            }
        }
        return Err(err);
    }

    // Re-stamp UTC after apply if needed (already fresh).
    baseline.synced_at_utc = Utc::now().to_rfc3339();
    let _ = write_baseline_atomic(data_dir, &baseline);

    Ok(build_status(platform, Some(&baseline)))
}

/// Restores the OS system timezone from `os_tz_baseline.json` and removes the baseline file on
/// success.
pub fn restore_os_timezone(data_dir: &Path) -> Result<OsTzSyncStatus, String> {
    restore_os_timezone_with(&RealOsTzPlatform, data_dir)
}

/// Injectable version of [`restore_os_timezone`] for unit tests.
pub fn restore_os_timezone_with(
    platform: &dyn OsTzPlatform,
    data_dir: &Path,
) -> Result<OsTzSyncStatus, String> {
    let _guard = OS_TZ_OPS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(baseline) = read_baseline(data_dir)? else {
        return Ok(build_status(platform, None));
    };

    let current_iana = platform.current_iana_timezone().ok();
    let already_original = current_iana
        .as_deref()
        .is_some_and(|cur| zones_equivalent(cur, &baseline.original_iana));

    if !already_original || baseline.original_auto_tz == Some(true) {
        platform.restore_timezone(
            &baseline.original_iana,
            baseline.original_windows_id.as_deref(),
            baseline.original_auto_tz,
        )?;
    }

    remove_baseline(data_dir)?;
    Ok(build_status(platform, None))
}

/// Restores the baseline OS timezone on startup if a previous run crashed while synced.
/// Never panics; keeps `os_tz_baseline.json` intact if restoration fails/is cancelled.
pub fn recover_baseline_on_start(data_dir: &Path) {
    recover_baseline_on_start_with(&RealOsTzPlatform, data_dir);
}

pub fn recover_baseline_on_start_with(platform: &dyn OsTzPlatform, data_dir: &Path) {
    let Ok(Some(baseline)) = read_baseline(data_dir) else {
        return;
    };
    eprintln!(
        "Застава: обнаружен незавершённый синхронизированный часовой пояс ОС ({} -> {}), выполняется восстановление {}",
        baseline.synced_iana, baseline.original_iana, BASELINE_FILE_NAME
    );
    match restore_os_timezone_with(platform, data_dir) {
        Ok(_) => eprintln!(
            "Застава: системный часовой пояс ОС восстановлен до {}",
            baseline.original_iana
        ),
        Err(err) => {
            crate::diagnostics::record("startup:os_tz_recover", &err);
            eprintln!("Застава: не удалось автоматически восстановить часовой пояс ОС: {err}");
        }
    }
}

/// Best-effort restore when disabling system proxy protection (`toggle_sysproxy(false)`).
pub fn restore_if_synced_on_disable(data_dir: &Path) -> Result<bool, String> {
    restore_if_synced_on_disable_with(&RealOsTzPlatform, data_dir)
}

pub fn restore_if_synced_on_disable_with(
    platform: &dyn OsTzPlatform,
    data_dir: &Path,
) -> Result<bool, String> {
    if read_baseline(data_dir)?.is_none() {
        return Ok(false);
    }
    restore_os_timezone_with(platform, data_dir)?;
    Ok(true)
}

/// Best-effort non-panicking restore on application quit. Guarded so `ExitRequested` + `Exit`
/// cannot prompt twice in the same process exit.
pub fn restore_on_exit_once(app: Option<&tauri::AppHandle>) {
    if EXIT_RESTORE_RAN.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(dir) = resolve_app_data_dir(app) else {
        return;
    };
    let Ok(Some(baseline)) = read_baseline(&dir) else {
        return;
    };
    if let Err(err) = restore_os_timezone(&dir) {
        crate::diagnostics::record("exit:os_tz_restore", &err);
        eprintln!(
            "Застава: не удалось восстановить часовой пояс ОС ({}) при выходе: {err}",
            baseline.original_iana
        );
    }
}
