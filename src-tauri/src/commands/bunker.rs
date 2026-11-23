//! Tauri commands for Free Local Data Bunker: status, settings, backup, snapshots,
//! folder open, Web JSON/ZIP converter, and RESTORE_PROMPT.md generation.

use std::path::{Path, PathBuf};

use tauri::Manager;

use super::AppContext;
use crate::auditor::claude_exporter::get_home_dir;
use crate::bunker::retention::{list_snapshots, prune_old_web_exports};
use crate::bunker::teleport::run_context_teleport_in;
use crate::bunker::web_helper::convert_web_export_to;
use crate::bunker::{
    BunkerBackupResult, BunkerSettingsPatch, BunkerSnapshotMeta, BunkerStatus,
    WebExportConvertResult, allocate_timestamped_dir, bunker_snapshots_dir, bunker_web_exports_dir,
    clear_bunker_snapshots_in, generate_bunker_restore_prompt_in, get_bunker_status_in,
    run_bunker_backup_in,
};
use crate::core::context_teleport::{ContextTeleportResult, TeleportTarget};
use crate::state::BunkerSettings;

fn resolve_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))
}

fn resolve_home_dir() -> Result<PathBuf, String> {
    get_home_dir().ok_or_else(|| "Домашняя директория пользователя не найдена.".to_string())
}

#[tauri::command]
pub async fn get_bunker_status(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
) -> Result<BunkerStatus, String> {
    let data_dir = resolve_data_dir(&app)?;
    let home_dir = resolve_home_dir()?;
    let settings = state.get_data().await.bunker;
    tokio::task::spawn_blocking(move || get_bunker_status_in(&data_dir, &home_dir, &settings))
        .await
        .map_err(|e| format!("Bunker status task failed: {e}"))
}

#[tauri::command]
pub async fn update_bunker_settings(
    settings: BunkerSettingsPatch,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
) -> Result<BunkerSettings, String> {
    let updated = {
        let mut w = state.write().await;
        if let Some(enabled) = settings.auto_backup_enabled {
            w.bunker.auto_backup_enabled = enabled;
        }
        if let Some(hours) = settings.interval_hours {
            w.bunker.interval_hours = hours.max(1);
        }
        if let Some(retention) = settings.retention_count {
            w.bunker.retention_count = retention.max(1);
        }
        if let Some(max_mb) = settings.max_total_mb {
            w.bunker.max_total_mb = max_mb.max(50);
        }
        w.bunker.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;

    if settings.retention_count.is_some() || settings.max_total_mb.is_some() {
        let data_dir = resolve_data_dir(&app)?;
        let retention_count = updated.retention_count;
        let max_total_bytes = updated.max_total_mb.saturating_mul(1024 * 1024);
        let _ = tokio::task::spawn_blocking(move || {
            let snapshots_dir = bunker_snapshots_dir(&data_dir);
            let exports_dir = bunker_web_exports_dir(&data_dir);
            let _ = crate::bunker::retention::prune_old_snapshots(
                &snapshots_dir,
                retention_count,
                max_total_bytes,
            );
            let _ = prune_old_web_exports(&exports_dir, retention_count, max_total_bytes);
        })
        .await;
    }

    Ok(updated)
}

#[tauri::command]
pub async fn run_bunker_backup_now(
    destination_dir: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
) -> Result<BunkerBackupResult, String> {
    let data_dir = resolve_data_dir(&app)?;
    let home_dir = resolve_home_dir()?;
    let settings = state.get_data().await.bunker;
    let dest = destination_dir
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    let result = tokio::task::spawn_blocking(move || {
        run_bunker_backup_in(&data_dir, &home_dir, &settings, "manual", dest.as_deref())
    })
    .await
    .map_err(|e| format!("Bunker backup task failed: {e}"))??;

    {
        let mut w = state.write().await;
        w.bunker.last_backup_at = Some(result.snapshot.created_at);
        w.bunker.last_backup_size_bytes = Some(result.snapshot.total_bytes);
    }
    state.save_async().await.map_err(|e| e.to_string())?;
    Ok(result)
}

#[tauri::command]
pub async fn list_bunker_snapshots(
    app: tauri::AppHandle,
) -> Result<Vec<BunkerSnapshotMeta>, String> {
    let data_dir = resolve_data_dir(&app)?;
    let snapshots_dir = bunker_snapshots_dir(&data_dir);
    tokio::task::spawn_blocking(move || list_snapshots(&snapshots_dir))
        .await
        .map_err(|e| format!("List snapshots task failed: {e}"))
}

#[tauri::command]
pub async fn open_bunker_folder(app: tauri::AppHandle) -> Result<(), String> {
    let data_dir = resolve_data_dir(&app)?;
    let snapshots_dir = bunker_snapshots_dir(&data_dir);
    std::fs::create_dir_all(&snapshots_dir)
        .map_err(|e| format!("Не удалось создать папку Бункера: {e}"))?;

    if !crate::sysproxy::os_effects_enabled() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = crate::sysproxy::silent_command("open");
        c.arg(&snapshots_dir);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("explorer");
        c.arg(&snapshots_dir);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut cmd = {
        let mut c = crate::sysproxy::silent_command("xdg-open");
        c.arg(&snapshots_dir);
        c
    };

    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("Не удалось открыть папку Бункера: {e}"))
}

pub fn convert_web_export_in(
    app_data_dir: &Path,
    source_path: &Path,
    output_dir: Option<&Path>,
    retention_count: usize,
) -> Result<WebExportConvertResult, String> {
    convert_web_export_in_with_quota(
        app_data_dir,
        source_path,
        output_dir,
        retention_count,
        500 * 1024 * 1024,
    )
}

pub fn convert_web_export_in_with_quota(
    app_data_dir: &Path,
    source_path: &Path,
    output_dir: Option<&Path>,
    retention_count: usize,
    max_total_bytes: u64,
) -> Result<WebExportConvertResult, String> {
    if let Some(custom_dir) = output_dir {
        return convert_web_export_to(source_path, custom_dir);
    }
    let exports_root = bunker_web_exports_dir(app_data_dir);
    let (_stamp, target_dir) = allocate_timestamped_dir(&exports_root)?;
    let res = convert_web_export_to(source_path, &target_dir);
    if res.is_err() {
        let _ = std::fs::remove_dir_all(&target_dir);
    } else {
        let _ = prune_old_web_exports(&exports_root, retention_count, max_total_bytes);
    }
    res
}

#[tauri::command]
pub async fn convert_web_export(
    source_path: String,
    output_dir: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
) -> Result<WebExportConvertResult, String> {
    let clean_source = source_path.trim().to_string();
    if clean_source.is_empty() {
        return Err("Укажите путь к файлу conversations.json или export.zip.".to_string());
    }
    let data_dir = resolve_data_dir(&app)?;
    let bunker_cfg = state.get_data().await.bunker;
    let retention_count = bunker_cfg.retention_count;
    let max_total_bytes = bunker_cfg.max_total_mb.saturating_mul(1024 * 1024);
    let custom_out = output_dir
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    tokio::task::spawn_blocking(move || {
        convert_web_export_in_with_quota(
            &data_dir,
            PathBuf::from(&clean_source).as_path(),
            custom_out.as_deref(),
            retention_count,
            max_total_bytes,
        )
    })
    .await
    .map_err(|e| format!("Web export conversion task failed: {e}"))?
}

#[tauri::command]
pub async fn generate_bunker_restore_prompt(app: tauri::AppHandle) -> Result<String, String> {
    let data_dir = resolve_data_dir(&app)?;
    let home_dir = resolve_home_dir()?;
    tokio::task::spawn_blocking(move || generate_bunker_restore_prompt_in(&data_dir, &home_dir))
        .await
        .map_err(|e| format!("Generate restore prompt task failed: {e}"))
}

#[tauri::command]
pub async fn clear_bunker_snapshots(
    keep_latest: Option<bool>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
) -> Result<BunkerStatus, String> {
    let data_dir = resolve_data_dir(&app)?;
    let home_dir = resolve_home_dir()?;
    let settings = state.get_data().await.bunker;
    let keep = keep_latest.unwrap_or(true);
    let mut status = tokio::task::spawn_blocking(move || {
        clear_bunker_snapshots_in(&data_dir, &home_dir, &settings, keep)
    })
    .await
    .map_err(|e| format!("Clear Bunker snapshots task failed: {e}"))??;

    if status.snapshots_count == 0 {
        let mut w = state.write().await;
        w.bunker.last_backup_at = None;
        w.bunker.last_backup_size_bytes = None;
        status.settings = w.bunker.clone();
        drop(w);
        state.save_async().await.map_err(|e| e.to_string())?;
    } else if let Some(latest) = &status.latest_snapshot {
        let mut w = state.write().await;
        w.bunker.last_backup_at = Some(latest.created_at);
        w.bunker.last_backup_size_bytes = Some(latest.total_bytes);
        status.settings = w.bunker.clone();
        drop(w);
        state.save_async().await.map_err(|e| e.to_string())?;
    }

    Ok(status)
}

#[tauri::command]
pub async fn get_payment_passport(
    profile_id: String,
    app: tauri::AppHandle,
) -> Result<Option<crate::bunker::payment_passport::PaymentPassport>, String> {
    let data_dir = resolve_data_dir(&app)?;
    tokio::task::spawn_blocking(move || {
        crate::bunker::payment_passport::load_payment_passport_in(&data_dir, &profile_id)
    })
    .await
    .map_err(|e| format!("Load PaymentPassport task failed: {e}"))?
}

#[tauri::command]
pub async fn save_payment_passport(
    passport: crate::bunker::payment_passport::PaymentPassport,
    app: tauri::AppHandle,
) -> Result<crate::bunker::payment_passport::PaymentPassport, String> {
    let data_dir = resolve_data_dir(&app)?;
    tokio::task::spawn_blocking(move || {
        crate::bunker::payment_passport::save_payment_passport_in(&data_dir, passport)
    })
    .await
    .map_err(|e| format!("Save PaymentPassport task failed: {e}"))?
}

#[tauri::command]
pub async fn verify_payment_passport(
    profile_id: String,
    current: crate::bunker::payment_passport::RenewalCheckInput,
    app: tauri::AppHandle,
) -> Result<crate::bunker::payment_passport::PassportVerificationResult, String> {
    let data_dir = resolve_data_dir(&app)?;
    tokio::task::spawn_blocking(move || {
        let passport =
            crate::bunker::payment_passport::load_payment_passport_in(&data_dir, &profile_id)?
                .ok_or_else(|| {
                    format!("Платёжный паспорт для профиля «{profile_id}» ещё не сохранён.")
                })?;
        Ok(crate::bunker::payment_passport::verify_renewal_against_passport(&passport, &current))
    })
    .await
    .map_err(|e| format!("Verify PaymentPassport task failed: {e}"))?
}

#[tauri::command]
pub async fn run_context_teleport(
    target: TeleportTarget,
    destination_dir: Option<String>,
    copy_only: Option<bool>,
    app: tauri::AppHandle,
) -> Result<ContextTeleportResult, String> {
    let data_dir = resolve_data_dir(&app)?;
    let home_dir = resolve_home_dir()?;
    let dest = destination_dir
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    tokio::task::spawn_blocking(move || {
        run_context_teleport_in(&data_dir, &home_dir, target, dest.as_deref(), copy_only)
    })
    .await
    .map_err(|e| format!("Context teleport task failed: {e}"))?
}
