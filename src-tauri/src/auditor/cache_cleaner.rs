#[path = "cache_cleaner_process.rs"]
mod process;

use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::profile_switcher::resolve_ai_app_data_dirs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub use process::{
    filter_windows_claude_desktop_pids, is_macos_claude_desktop_cmd, is_windows_claude_desktop_exe,
    soft_close_ai_client,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanResult {
    pub provider: ProviderId,
    pub cleaned_targets: Vec<String>,
    pub files_removed: usize,
    pub bytes_freed: u64,
    pub success: bool,
    pub message: String,
    pub found_dir: bool,
    pub locked_targets: Vec<String>,
}

const TARGET_NAMES: &[&str] = &[
    // Root browser / session caches
    "Cookies",
    "Cookies-journal",
    "IndexedDB",
    "Local Storage",
    "Session Storage",
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "Network Action Predictor",
    "TransportSecurity",
    // Nested Chromium Network Service state
    "Network/Cookies",
    "Network/Cookies-journal",
    "Network/Network Persistent State",
    "Network/TransportSecurity",
    "Network/Trust Tokens",
    "Network/Trust Tokens-journal",
    "Network/Reporting and Nel",
    "Network/Reporting and Nel-journal",
    "Network/SCT Auditing Pending Reports",
    // Device telemetry and anti-fraud markers
    "ant-device-registry.json",
    "ccd-ids.json",
    "dispatch-footprint-census.json",
    "Local State",
    "Preferences",
    "DIPS",
    "DIPS-wal",
    "DIPS-shm",
    "SharedStorage",
    "SharedStorage-wal",
    "Crashpad",
    "sentry",
    "blob_storage",
    "WebStorage",
];

pub fn get_ai_app_data_dir(provider: ProviderId) -> Option<PathBuf> {
    resolve_ai_app_data_dirs(provider).into_iter().next()
}

pub fn clean_ai_app_cache(provider: ProviderId) -> CleanResult {
    let _ = soft_close_ai_client(provider);
    let app_dirs = resolve_ai_app_data_dirs(provider);
    clean_ai_app_cache_in_dirs(provider, &app_dirs)
}

fn is_strictly_whitelisted(target: &str, path: &Path) -> bool {
    let t_lower = target.to_ascii_lowercase();
    if t_lower.contains("claude_desktop_config") || t_lower.contains(".claude") {
        return true;
    }
    if path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(".claude"))
    }) {
        return true;
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let name_lower = name.to_ascii_lowercase();
        if name_lower == "claude_desktop_config.json"
            || name_lower.starts_with(".claude")
            || name_lower.ends_with(".claude.json")
        {
            return true;
        }
    }
    false
}

pub fn clean_ai_app_cache_in_dir(provider: ProviderId, app_dir: &Path) -> CleanResult {
    clean_ai_app_cache_in_dirs(provider, &[app_dir.to_path_buf()])
}

pub fn clean_ai_app_cache_in_dirs(provider: ProviderId, app_dirs: &[PathBuf]) -> CleanResult {
    clean_ai_app_cache_in_dirs_with(provider, app_dirs, &|p| std::fs::remove_file(p))
}

pub(crate) fn clean_ai_app_cache_in_dirs_with(
    provider: ProviderId,
    app_dirs: &[PathBuf],
    remove_file_fn: &dyn Fn(&Path) -> std::io::Result<()>,
) -> CleanResult {
    let existing_dirs: Vec<&PathBuf> = app_dirs.iter().filter(|d| d.is_dir()).collect();
    if existing_dirs.is_empty() {
        return CleanResult {
            provider,
            cleaned_targets: Vec::new(),
            files_removed: 0,
            bytes_freed: 0,
            success: true,
            message: format!(
                "Папка настольного клиента {} не найдена.",
                provider.display_name()
            ),
            found_dir: false,
            locked_targets: Vec::new(),
        };
    }

    let mut cleaned_targets = Vec::new();
    let mut locked_targets = Vec::new();
    let mut files_removed = 0usize;
    let mut bytes_freed = 0u64;

    for app_dir in existing_dirs {
        for target in TARGET_NAMES {
            let path = app_dir.join(target);
            if is_strictly_whitelisted(target, &path) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let ft = meta.file_type();
            if ft.is_dir() {
                let mut dir_locked = Vec::new();
                if let Ok((count, bytes)) =
                    remove_dir_contents_with(&path, target, remove_file_fn, &mut dir_locked)
                {
                    files_removed += count;
                    bytes_freed += bytes;
                    if dir_locked.is_empty() {
                        match std::fs::remove_dir_all(&path) {
                            Ok(()) => push_unique(&mut cleaned_targets, (*target).to_string()),
                            Err(_) => push_unique(&mut locked_targets, (*target).to_string()),
                        }
                    } else {
                        for item in dir_locked {
                            push_unique(&mut locked_targets, item);
                        }
                    }
                }
            } else if ft.is_file() || ft.is_symlink() {
                let size = if ft.is_file() { meta.len() } else { 0 };
                if remove_file_fn(&path).is_ok() {
                    files_removed += 1;
                    bytes_freed += size;
                    push_unique(&mut cleaned_targets, (*target).to_string());
                } else {
                    push_unique(&mut locked_targets, (*target).to_string());
                }
            }
        }

        let network_dir = app_dir.join("Network");
        if network_dir.is_dir()
            && let Ok(mut entries) = std::fs::read_dir(&network_dir)
            && entries.next().is_none()
        {
            let _ = std::fs::remove_dir(&network_dir);
        }
    }

    let success = locked_targets.is_empty();
    let message = if !success {
        format!(
            "Часть файлов {} заблокирована запущенным процессом ({} не удалено).",
            provider.display_name(),
            locked_targets.len()
        )
    } else {
        format!(
            "Следы старой сессии и кэш {} успешно очищены (удалено файлов: {}).",
            provider.display_name(),
            files_removed
        )
    };

    CleanResult {
        provider,
        cleaned_targets,
        files_removed,
        bytes_freed,
        success,
        message,
        found_dir: true,
        locked_targets,
    }
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.contains(&item) {
        list.push(item);
    }
}

fn remove_dir_contents_with(
    path: &Path,
    rel_prefix: &str,
    remove_file_fn: &dyn Fn(&Path) -> std::io::Result<()>,
    locked_targets: &mut Vec<String>,
) -> std::io::Result<(usize, u64)> {
    let mut count = 0usize;
    let mut bytes = 0u64;
    for entry in std::fs::read_dir(path)?.flatten() {
        let entry_path = entry.path();
        if is_strictly_whitelisted("", &entry_path) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if rel_prefix.is_empty() {
            name
        } else {
            format!("{rel_prefix}/{name}")
        };
        let Ok(meta) = std::fs::symlink_metadata(&entry_path) else {
            continue;
        };
        let ft = meta.file_type();
        if ft.is_dir() {
            let mut sub_locked = Vec::new();
            let (c, b) =
                remove_dir_contents_with(&entry_path, &rel, remove_file_fn, &mut sub_locked)?;
            count += c;
            bytes += b;
            if sub_locked.is_empty() {
                if std::fs::remove_dir(&entry_path).is_err() {
                    locked_targets.push(rel);
                }
            } else {
                locked_targets.extend(sub_locked);
            }
        } else if ft.is_file() || ft.is_symlink() {
            let size = if ft.is_file() { meta.len() } else { 0 };
            if remove_file_fn(&entry_path).is_ok() {
                count += 1;
                bytes += size;
            } else {
                locked_targets.push(rel);
            }
        }
    }
    Ok((count, bytes))
}

#[cfg(test)]
#[path = "cache_cleaner_tests.rs"]
mod tests;
