//! Snapshot metadata persistence, listing, and 7-snapshot FIFO retention.

use std::fs;
use std::path::Path;

use super::BunkerSnapshotMeta;
use super::sanitize::write_private_file;

pub const SNAPSHOT_META_FILENAME: &str = "snapshot_meta.json";

/// Persists snapshot metadata inside `<snapshot_dir>/snapshot_meta.json` (`0o600` on Unix).
pub fn write_snapshot_meta(snapshot_dir: &Path, meta: &BunkerSnapshotMeta) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(meta)
        .map_err(|e| format!("Failed to serialize snapshot meta: {e}"))?;
    write_private_file(&snapshot_dir.join(SNAPSHOT_META_FILENAME), &json)
}

fn dir_stats(dir: &Path) -> (usize, u64) {
    let mut files = 0usize;
    let mut bytes = 0u64;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                let (sf, sb) = dir_stats(&path);
                files += sf;
                bytes += sb;
            } else if ft.is_file()
                && let Ok(meta) = fs::metadata(&path)
            {
                files += 1;
                bytes += meta.len();
            }
        }
    }
    (files, bytes)
}

/// Reads snapshot metadata from `snapshot_meta.json`, falling back to filesystem inspection.
pub fn read_snapshot_meta(snapshot_dir: &Path) -> Option<BunkerSnapshotMeta> {
    if !snapshot_dir.is_dir() {
        return None;
    }
    let meta_path = snapshot_dir.join(SNAPSHOT_META_FILENAME);
    if let Ok(raw) = fs::read_to_string(&meta_path)
        && let Ok(mut parsed) = serde_json::from_str::<BunkerSnapshotMeta>(&raw)
    {
        parsed.snapshot_dir = snapshot_dir.to_string_lossy().to_string();
        return Some(parsed);
    }

    let id = snapshot_dir.file_name()?.to_string_lossy().to_string();
    let created_at = fs::metadata(snapshot_dir)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (files_count, total_bytes) = dir_stats(snapshot_dir);
    let mut sources = Vec::new();
    if snapshot_dir.join("claude_code").is_dir() || snapshot_dir.join("projects").is_dir() {
        sources.push("claude_code".to_string());
    }
    if snapshot_dir
        .join("configs")
        .join("claude_desktop_config.json")
        .is_file()
    {
        sources.push("claude_desktop".to_string());
    }
    if snapshot_dir.join("cursor").is_dir() {
        sources.push("cursor".to_string());
    }
    let has_restore_prompt = snapshot_dir.join("RESTORE_PROMPT.md").is_file();
    Some(BunkerSnapshotMeta {
        id,
        created_at,
        snapshot_dir: snapshot_dir.to_string_lossy().to_string(),
        total_bytes,
        files_count,
        sources,
        has_restore_prompt,
        trigger: "manual".to_string(),
    })
}

/// Lists all valid snapshots inside `snapshots_dir`, sorted newest-first.
/// Ignores `.tmp-*` staging directories.
pub fn list_snapshots(snapshots_dir: &Path) -> Vec<BunkerSnapshotMeta> {
    if !snapshots_dir.is_dir() {
        return Vec::new();
    }
    let mut list = Vec::new();
    if let Ok(entries) = fs::read_dir(snapshots_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let is_tmp = entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(".tmp-"));
            if !is_tmp
                && p.is_dir()
                && let Some(meta) = read_snapshot_meta(&p)
            {
                list.push(meta);
            }
        }
    }
    list.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    list
}

/// Removes any leftover `.tmp-*` staging directories inside `snapshots_dir`.
pub fn cleanup_stale_staging_dirs(snapshots_dir: &Path) {
    if !snapshots_dir.is_dir() {
        return;
    }
    if let Ok(entries) = fs::read_dir(snapshots_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(".tmp-"))
            {
                let _ = fs::remove_dir_all(&p);
            }
        }
    }
}

/// Enforces FIFO + byte-quota retention on `snapshots_dir`, keeping at most `retention_count.max(1)`
/// newest snapshots and keeping total size `<= max_total_bytes` (when `max_total_bytes > 0`),
/// while ALWAYS preserving at least the newest 1 valid snapshot.
pub fn prune_old_snapshots(
    snapshots_dir: &Path,
    retention_count: usize,
    max_total_bytes: u64,
) -> Result<usize, String> {
    cleanup_stale_staging_dirs(snapshots_dir);
    let keep = retention_count.max(1);
    let mut snapshots = list_snapshots(snapshots_dir);
    if snapshots.len() <= 1 {
        return Ok(0);
    }
    let mut remaining_count = snapshots.len();
    let mut remaining_bytes: u64 = snapshots.iter().map(|s| s.total_bytes).sum();

    // `snapshots` is newest-first; reverse to iterate oldest-first while preserving index 0 (newest).
    snapshots.reverse();
    let mut pruned = 0usize;
    for old in snapshots.into_iter() {
        if remaining_count <= 1 {
            break;
        }
        let over_count = remaining_count > keep;
        let over_quota = max_total_bytes > 0 && remaining_bytes > max_total_bytes;
        if !over_count && !over_quota {
            break;
        }
        let dir = Path::new(&old.snapshot_dir);
        if dir.is_dir() {
            fs::remove_dir_all(dir)
                .map_err(|e| format!("Failed to prune old snapshot {}: {e}", dir.display()))?;
            pruned += 1;
        }
        remaining_count -= 1;
        remaining_bytes = remaining_bytes.saturating_sub(old.total_bytes);
    }
    Ok(pruned)
}

/// Enforces FIFO + byte-quota retention on `web_exports_dir`, keeping at most `retention_count.max(1)`
/// newest web-export directories and keeping total size `<= max_total_bytes` (when `> 0`),
/// while ALWAYS preserving at least the newest 1 export directory.
pub fn prune_old_web_exports(
    web_exports_dir: &Path,
    retention_count: usize,
    max_total_bytes: u64,
) -> Result<usize, String> {
    if !web_exports_dir.is_dir() {
        return Ok(0);
    }
    let keep = retention_count.max(1);
    let mut dirs: Vec<(u128, String, std::path::PathBuf, u64)> = Vec::new();
    if let Ok(entries) = fs::read_dir(web_exports_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let mtime_nanos = fs::metadata(&p)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            let (_, bytes) = dir_stats(&p);
            dirs.push((mtime_nanos, name, p, bytes));
        }
    }
    if dirs.len() <= 1 {
        return Ok(0);
    }
    // Newest first (by timestamp, then lexicographic timestamped folder name).
    dirs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    let mut remaining_count = dirs.len();
    let mut remaining_bytes: u64 = dirs.iter().map(|d| d.3).sum();
    // Reverse to iterate oldest-first while preserving the newest 1.
    dirs.reverse();
    let mut pruned = 0usize;
    for (_, _, old_dir, bytes) in dirs {
        if remaining_count <= 1 {
            break;
        }
        let over_count = remaining_count > keep;
        let over_quota = max_total_bytes > 0 && remaining_bytes > max_total_bytes;
        if !over_count && !over_quota {
            break;
        }
        if old_dir.is_dir() {
            fs::remove_dir_all(&old_dir).map_err(|e| {
                format!("Failed to prune old web export {}: {e}", old_dir.display())
            })?;
            pruned += 1;
        }
        remaining_count -= 1;
        remaining_bytes = remaining_bytes.saturating_sub(bytes);
    }
    Ok(pruned)
}
