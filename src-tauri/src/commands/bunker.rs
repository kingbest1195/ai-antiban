//! Tauri commands for Free Local Data Bunker: status, settings, backup, snapshots,
//! folder open, Web JSON/ZIP converter, and RESTORE_PROMPT.md generation.

use std::path::{Path, PathBuf};

use tauri::Manager;

use super::AppContext;
use crate::auditor::claude_exporter::get_home_dir;
use crate::bunker::retention::{list_snapshots, prune_old_web_exports};
use crate::bunker::web_helper::convert_web_export_to;
use crate::bunker::{
    BunkerBackupResult, BunkerSettingsPatch, BunkerSnapshotMeta, BunkerStatus,
    WebExportConvertResult, allocate_timestamped_dir, bunker_snapshots_dir, bunker_web_exports_dir,
    generate_bunker_restore_prompt_in, get_bunker_status_in, run_bunker_backup_in,
};
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
        w.bunker.clone()
    };
    state.save_async().await.map_err(|e| e.to_string())?;
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
        let mut c = crate::sysproxy::silent_command("explorer");
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
    if let Some(custom_dir) = output_dir {
        return convert_web_export_to(source_path, custom_dir);
    }
    let exports_root = bunker_web_exports_dir(app_data_dir);
    let (_stamp, target_dir) = allocate_timestamped_dir(&exports_root)?;
    let res = convert_web_export_to(source_path, &target_dir);
    if res.is_err() {
        let _ = std::fs::remove_dir_all(&target_dir);
    } else {
        let _ = prune_old_web_exports(&exports_root, retention_count);
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
    let retention_count = state.get_data().await.bunker.retention_count;
    let custom_out = output_dir
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    tokio::task::spawn_blocking(move || {
        convert_web_export_in(
            &data_dir,
            PathBuf::from(&clean_source).as_path(),
            custom_out.as_deref(),
            retention_count,
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
