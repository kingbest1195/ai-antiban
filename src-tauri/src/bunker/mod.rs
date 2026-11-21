//! Free Local Data Bunker: snapshot creation (Claude Code, Claude Desktop Classic/MSIX,
//! Cursor IDE), secret sanitization, 7-snapshot FIFO retention, Web JSON/ZIP converter,
//! and background auto-backup scheduler.

pub mod cursor_export;
pub mod restore_prompt;
pub mod retention;
pub mod scheduler;
pub mod web_helper;

mod sanitize;
mod web_parsers;

#[cfg(test)]
mod tests;

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Local;
use serde::{Deserialize, Serialize};

use crate::auditor::claude_exporter::{get_claude_desktop_config_path, scan_claude_dir};
use crate::auditor::network::current_timestamp;
use crate::state::BunkerSettings;

use cursor_export::{export_cursor_to, scan_cursor_data};
use restore_prompt::build_restore_prompt_md;
use retention::{list_snapshots, prune_old_snapshots, write_snapshot_meta};
use sanitize::{
    copy_private_dir_filtered, copy_private_file, copy_sanitized_json_file, ensure_private_dir,
    is_excluded_secret_name, write_private_file,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BunkerSourceSummary {
    pub kind: String,
    pub available: bool,
    pub label: String,
    pub path_hint: Option<String>,
    pub items_count: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BunkerSnapshotMeta {
    pub id: String,
    pub created_at: u64,
    pub snapshot_dir: String,
    pub total_bytes: u64,
    pub files_count: usize,
    pub sources: Vec<String>,
    pub has_restore_prompt: bool,
    pub trigger: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BunkerStatus {
    pub settings: BunkerSettings,
    pub bunker_dir: String,
    pub snapshots_count: usize,
    pub total_snapshots_bytes: u64,
    pub latest_snapshot: Option<BunkerSnapshotMeta>,
    pub sources: Vec<BunkerSourceSummary>,
    pub has_any_local_data: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BunkerBackupResult {
    pub snapshot: BunkerSnapshotMeta,
    pub restore_prompt_path: String,
    pub exported_copy_dir: Option<String>,
    pub pruned_snapshots: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebExportConvertResult {
    pub source_path: String,
    pub detected_provider: String,
    pub output_dir: String,
    pub markdown_files: Vec<String>,
    pub conversations_count: usize,
    pub restore_prompt_path: String,
    pub restore_prompt_preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BunkerSettingsPatch {
    #[serde(default)]
    pub auto_backup_enabled: Option<bool>,
    #[serde(default)]
    pub interval_hours: Option<u32>,
    #[serde(default)]
    pub retention_count: Option<usize>,
    #[serde(default)]
    pub max_total_mb: Option<u64>,
}

pub fn bunker_snapshots_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("bunker").join("snapshots")
}

pub fn bunker_web_exports_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("bunker").join("web-exports")
}

/// Inspects local AI data sources and existing snapshots to produce [`BunkerStatus`].
pub fn get_bunker_status_in(
    app_data_dir: &Path,
    home_dir: &Path,
    settings: &BunkerSettings,
) -> BunkerStatus {
    let claude_dir = home_dir.join(".claude");
    let claude_scan = scan_claude_dir(&claude_dir, home_dir);
    let desktop_cfg = get_claude_desktop_config_path(home_dir);
    let cursor_scan = scan_cursor_data(home_dir, &claude_dir);
    let web_exports_dir = bunker_web_exports_dir(app_data_dir);
    let (web_count, web_bytes) = count_dir_items(&web_exports_dir);

    let sources = vec![
        BunkerSourceSummary {
            kind: "claude_code".to_string(),
            available: claude_scan.exists || claude_scan.has_claude_json,
            label: "Claude Code (~/.claude)".to_string(),
            path_hint: (claude_scan.exists || claude_scan.has_claude_json)
                .then(|| "~/.claude".to_string()),
            items_count: claude_scan.projects_count + claude_scan.plans_count,
            total_bytes: claude_scan.total_size_bytes,
        },
        BunkerSourceSummary {
            kind: "claude_desktop".to_string(),
            available: desktop_cfg.is_some(),
            label: "Claude Desktop (MCP & config)".to_string(),
            path_hint: desktop_cfg.as_ref().map(|p| {
                p.file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
            }),
            items_count: usize::from(desktop_cfg.is_some()),
            total_bytes: desktop_cfg
                .as_ref()
                .and_then(|p| fs::metadata(p).ok())
                .map_or(0, |m| m.len()),
        },
        BunkerSourceSummary {
            kind: "cursor".to_string(),
            available: cursor_scan.available,
            label: "Cursor IDE (settings & MCP)".to_string(),
            path_hint: cursor_scan.path_hint,
            items_count: cursor_scan.items_count,
            total_bytes: cursor_scan.total_bytes,
        },
        BunkerSourceSummary {
            kind: "web_export".to_string(),
            available: web_count > 0,
            label: "Web Export (Claude / ChatGPT)".to_string(),
            path_hint: (web_count > 0).then(|| web_exports_dir.to_string_lossy().into_owned()),
            items_count: web_count,
            total_bytes: web_bytes,
        },
    ];

    let snapshots_dir = bunker_snapshots_dir(app_data_dir);
    let snapshots = list_snapshots(&snapshots_dir);
    let total_snapshots_bytes = snapshots.iter().map(|s| s.total_bytes).sum();
    let has_any_local_data = sources.iter().any(|s| s.available);

    BunkerStatus {
        settings: settings.clone(),
        bunker_dir: snapshots_dir.to_string_lossy().to_string(),
        snapshots_count: snapshots.len(),
        total_snapshots_bytes,
        latest_snapshot: snapshots.into_iter().next(),
        sources,
        has_any_local_data,
    }
}

/// Creates a sanitized snapshot at `<app_data_dir>/bunker/snapshots/<YYYY-MM-DD_HHMMSS>/`
/// via atomic `.tmp-<id>` staging, writes `RESTORE_PROMPT.md`, enforces FIFO + byte-quota
/// retention, and optionally copies to `destination_dir`.
pub fn run_bunker_backup_in(
    app_data_dir: &Path,
    home_dir: &Path,
    settings: &BunkerSettings,
    trigger: &str,
    destination_dir: Option<&Path>,
) -> Result<BunkerBackupResult, String> {
    let snapshots_dir = bunker_snapshots_dir(app_data_dir);
    retention::cleanup_stale_staging_dirs(&snapshots_dir);
    let (snapshot_id, staging_dir, final_dir) = allocate_staged_snapshot_dir(&snapshots_dir)?;

    let res = populate_snapshot_staging(&staging_dir, &final_dir, &snapshot_id, home_dir, trigger);
    let (meta, restore_prompt_path) = match res {
        Ok(ok) => ok,
        Err(err) => {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(err);
        }
    };

    if let Err(err) = fs::rename(&staging_dir, &final_dir) {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(format!(
            "Failed to finalize Bunker snapshot {}: {err}",
            final_dir.display()
        ));
    }

    let max_bytes = settings.max_total_mb.saturating_mul(1024 * 1024);
    let pruned_snapshots =
        prune_old_snapshots(&snapshots_dir, settings.retention_count, max_bytes)?;

    let exported_copy_dir = match destination_dir {
        Some(dest) => {
            let copy_target = dest.join(format!("Zastava_Bunker_{snapshot_id}"));
            copy_private_dir_filtered(&final_dir, &copy_target)?;
            Some(copy_target.to_string_lossy().to_string())
        }
        None => None,
    };

    Ok(BunkerBackupResult {
        snapshot: meta,
        restore_prompt_path: restore_prompt_path.to_string_lossy().to_string(),
        exported_copy_dir,
        pruned_snapshots,
    })
}

fn populate_snapshot_staging(
    staging_dir: &Path,
    final_dir: &Path,
    snapshot_id: &str,
    home_dir: &Path,
    trigger: &str,
) -> Result<(BunkerSnapshotMeta, PathBuf), String> {
    let claude_dir = home_dir.join(".claude");
    let mut files_count = 0usize;
    let mut total_bytes = 0u64;
    let mut sources = Vec::new();

    let (cc_files, cc_bytes) = copy_claude_code_sources(&claude_dir, home_dir, staging_dir)?;
    if cc_files > 0 {
        sources.push("claude_code".to_string());
        files_count += cc_files;
        total_bytes += cc_bytes;
    }

    if let Some(desktop_cfg) = get_claude_desktop_config_path(home_dir) {
        let dst = staging_dir
            .join("configs")
            .join("claude_desktop_config.json");
        let bytes = copy_sanitized_json_file(&desktop_cfg, &dst)?;
        sources.push("claude_desktop".to_string());
        files_count += 1;
        total_bytes += bytes;
    }

    let (cur_files, cur_bytes, _cur_mcps) =
        export_cursor_to(home_dir, &claude_dir, &staging_dir.join("cursor"))?;
    if cur_files > 0 {
        sources.push("cursor".to_string());
        files_count += cur_files;
        total_bytes += cur_bytes;
    }

    let prompt_text = build_restore_prompt_md(home_dir, &claude_dir, Some(staging_dir));
    write_private_file(
        &staging_dir.join("RESTORE_PROMPT.md"),
        prompt_text.as_bytes(),
    )?;
    files_count += 1;
    total_bytes += prompt_text.len() as u64;

    let meta = BunkerSnapshotMeta {
        id: snapshot_id.to_string(),
        created_at: current_timestamp(),
        snapshot_dir: final_dir.to_string_lossy().to_string(),
        total_bytes,
        files_count,
        sources,
        has_restore_prompt: true,
        trigger: trigger.to_string(),
    };
    write_snapshot_meta(staging_dir, &meta)?;
    Ok((meta, final_dir.join("RESTORE_PROMPT.md")))
}

/// Clears Bunker snapshots safely (keeping newest 1 when `keep_latest` is `true`, or all
/// when `false`) and removes leftover `.tmp-*` staging directories.
pub fn clear_bunker_snapshots_in(
    app_data_dir: &Path,
    home_dir: &Path,
    settings: &BunkerSettings,
    keep_latest: bool,
) -> Result<BunkerStatus, String> {
    let snapshots_dir = bunker_snapshots_dir(app_data_dir);
    retention::cleanup_stale_staging_dirs(&snapshots_dir);
    let snapshots = list_snapshots(&snapshots_dir);
    let skip = usize::from(keep_latest);
    for old in snapshots.into_iter().skip(skip) {
        let dir = Path::new(&old.snapshot_dir);
        if dir.is_dir() {
            fs::remove_dir_all(dir)
                .map_err(|e| format!("Failed to remove snapshot {}: {e}", dir.display()))?;
        }
    }
    Ok(get_bunker_status_in(app_data_dir, home_dir, settings))
}

/// Generates an up-to-date `RESTORE_PROMPT.md` string covering Claude Code, MCP, and Cursor IDE.
pub fn generate_bunker_restore_prompt_in(app_data_dir: &Path, home_dir: &Path) -> String {
    let claude_dir = home_dir.join(".claude");
    let latest_dir = list_snapshots(&bunker_snapshots_dir(app_data_dir))
        .into_iter()
        .next()
        .map(|s| PathBuf::from(s.snapshot_dir));
    build_restore_prompt_md(home_dir, &claude_dir, latest_dir.as_deref())
}

/// Atomically allocates a unique timestamped subdirectory inside `parent_dir` using
/// `fs::create_dir` (avoiding `.exists()` TOCTOU races) and sets private permissions.
pub fn allocate_timestamped_dir(parent_dir: &Path) -> Result<(String, PathBuf), String> {
    ensure_private_dir(parent_dir)?;
    let base = Local::now().format("%Y-%m-%d_%H%M%S").to_string();
    for idx in 0..=999u32 {
        let id = if idx == 0 {
            base.clone()
        } else {
            format!("{base}_{idx:02}")
        };
        let candidate = parent_dir.join(&id);
        match fs::create_dir(&candidate) {
            Ok(()) => {
                ensure_private_dir(&candidate)?;
                return Ok((id, candidate));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "Failed to allocate unique Bunker directory {}: {e}",
                    candidate.display()
                ));
            }
        }
    }
    Err("Failed to allocate unique Bunker snapshot directory".to_string())
}

#[cfg(test)]
fn allocate_snapshot_dir(snapshots_dir: &Path) -> Result<(String, PathBuf), String> {
    allocate_timestamped_dir(snapshots_dir)
}

fn allocate_staged_snapshot_dir(
    snapshots_dir: &Path,
) -> Result<(String, PathBuf, PathBuf), String> {
    ensure_private_dir(snapshots_dir)?;
    let base = Local::now().format("%Y-%m-%d_%H%M%S").to_string();
    for idx in 0..=999u32 {
        let id = if idx == 0 {
            base.clone()
        } else {
            format!("{base}_{idx:02}")
        };
        let final_dir = snapshots_dir.join(&id);
        if final_dir.exists() {
            continue;
        }
        let staging_dir = snapshots_dir.join(format!(".tmp-{id}"));
        match fs::create_dir(&staging_dir) {
            Ok(()) => {
                ensure_private_dir(&staging_dir)?;
                return Ok((id, staging_dir, final_dir));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "Failed to allocate Bunker staging directory {}: {e}",
                    staging_dir.display()
                ));
            }
        }
    }
    Err("Failed to allocate unique Bunker snapshot directory".to_string())
}

fn copy_claude_code_sources(
    claude_dir: &Path,
    home_dir: &Path,
    snapshot_dir: &Path,
) -> Result<(usize, u64), String> {
    let mut files = 0usize;
    let mut bytes = 0u64;

    if claude_dir.is_dir() {
        for sub in ["projects", "plans", "skills"] {
            let src = claude_dir.join(sub);
            if src.is_dir() {
                let (f, b) = copy_private_dir_filtered(&src, &snapshot_dir.join(sub))?;
                files += f;
                bytes += b;
            }
        }
        for item in ["CLAUDE.md", "history.jsonl", "settings.json"] {
            if is_excluded_secret_name(item) {
                continue;
            }
            let src = claude_dir.join(item);
            if src.is_file() {
                let dst = snapshot_dir.join(item);
                let b = if item.ends_with(".json") {
                    copy_sanitized_json_file(&src, &dst)?
                } else {
                    copy_private_file(&src, &dst)?
                };
                files += 1;
                bytes += b;
            }
        }
    }

    let cli_cfg = home_dir.join(".claude.json");
    if cli_cfg.is_file() {
        let dst = snapshot_dir.join("configs").join("claude_cli_config.json");
        bytes += copy_sanitized_json_file(&cli_cfg, &dst)?;
        files += 1;
    }

    Ok((files, bytes))
}

fn count_dir_items(dir: &Path) -> (usize, u64) {
    if !dir.is_dir() {
        return (0, 0);
    }
    let mut count = 0usize;
    let mut bytes = 0u64;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let (c, b) = count_dir_items(&p);
                count += c;
                bytes += b;
            } else if p.is_file()
                && let Ok(meta) = fs::metadata(&p)
            {
                count += 1;
                bytes += meta.len();
            }
        }
    }
    (count, bytes)
}
