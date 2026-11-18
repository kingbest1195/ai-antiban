//! Filesystem safety primitives, OS directory resolution, and device registry initialization.

use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn clean_opt(val: Option<String>) -> Option<String> {
    val.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub(super) fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

pub(super) fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false)
}

pub(super) fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Removes a file, symlink, or real directory cleanly without ever following a symlink
/// into external targets (security guard against planted symlink deletion or traversal).
pub(super) fn remove_entry_safe(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        // On Windows, directory symlinks/junctions fail `remove_file` and require `remove_dir`.
        fs::remove_file(path).is_ok() || fs::remove_dir(path).is_ok()
    } else if ft.is_file() {
        fs::remove_file(path).is_ok()
    } else if ft.is_dir() {
        fs::remove_dir_all(path).is_ok()
    } else {
        false
    }
}

pub(super) fn read_json_bom_safe(path: &Path) -> Result<String, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    Ok(raw.trim_start_matches('\u{feff}').to_string())
}

pub(super) fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

pub(super) fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

pub(super) fn write_json_atomic(path: &Path, json: &str) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    {
        let mut f = create_private_file(&tmp).map_err(|e| e.to_string())?;
        f.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        let mut f = create_private_file(path).map_err(|_| e.to_string())?;
        restrict_to_owner(path);
        f.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(super) fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<usize> {
    let mut count = 0;
    if !is_real_dir(src) {
        return Ok(0);
    }
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            count += copy_dir_recursive(&from, &to)?;
        } else if ty.is_file() {
            fs::copy(&from, &to)?;
            count += 1;
        }
    }
    Ok(count)
}

pub fn get_user_home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .map(PathBuf::from)
            })
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
    }
}

pub fn default_profiles_storage_dir() -> PathBuf {
    if let Some(home) = get_user_home_dir() {
        home.join(".zastava").join("claude_profiles")
    } else {
        PathBuf::from(".zastava").join("claude_profiles")
    }
}

/// Resolves the Claude Desktop data directory for a given OS (`"macos"`, `"windows"`, `"linux"`),
/// checking MSIX Store package paths on Windows when the classic `%APPDATA%\Claude` folder does
/// not exist yet.
pub fn resolve_claude_desktop_dir_for_platform(
    os: &str,
    home: Option<&Path>,
    appdata: Option<&Path>,
    local_appdata: Option<&Path>,
) -> Option<PathBuf> {
    match os {
        "macos" => {
            let h = home?;
            Some(h.join("Library").join("Application Support").join("Claude"))
        }
        "windows" => {
            let classic = appdata
                .map(|p| p.join("Claude"))
                .or_else(|| home.map(|h| h.join("AppData").join("Roaming").join("Claude")));
            if let Some(ref p) = classic
                && is_real_dir(p)
            {
                return classic;
            }
            let local_base = local_appdata
                .map(PathBuf::from)
                .or_else(|| home.map(|h| h.join("AppData").join("Local")));
            if let Some(local) = local_base {
                let packages = local.join("Packages");
                if is_real_dir(&packages)
                    && let Ok(entries) = fs::read_dir(&packages)
                {
                    let mut candidates: Vec<PathBuf> = entries
                        .flatten()
                        .filter_map(|e| {
                            let name = e.file_name();
                            let name_str = name.to_string_lossy();
                            if name_str.starts_with("Claude_") {
                                let candidate = e
                                    .path()
                                    .join("LocalCache")
                                    .join("Roaming")
                                    .join("Claude");
                                is_real_dir(&candidate).then_some(candidate)
                            } else {
                                None
                            }
                        })
                        .collect();
                    candidates.sort();
                    if let Some(found) = candidates.into_iter().next() {
                        return Some(found);
                    }
                }
            }
            classic
        }
        _ => {
            let h = home?;
            Some(h.join(".config").join("Claude"))
        }
    }
}

pub fn default_claude_desktop_dir() -> Option<PathBuf> {
    let home = get_user_home_dir();
    #[cfg(target_os = "macos")]
    let os = "macos";
    #[cfg(target_os = "windows")]
    let os = "windows";
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let os = "linux";

    let appdata = std::env::var_os("APPDATA").map(PathBuf::from);
    let local_appdata = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    resolve_claude_desktop_dir_for_platform(
        os,
        home.as_deref(),
        appdata.as_deref(),
        local_appdata.as_deref(),
    )
}

pub(super) fn read_existing_device_id(claude_dir: &Path) -> Option<String> {
    let registry_file = claude_dir.join("ant-device-registry.json");
    if is_regular_file(&registry_file)
        && let Ok(content) = read_json_bom_safe(&registry_file)
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&content)
        && let Some(id) = val.get("deviceId").and_then(|v| v.as_str())
    {
        let clean = id.trim();
        if !clean.is_empty() {
            return Some(clean.to_string());
        }
    }
    None
}

pub(super) fn init_fresh_device_registry(
    claude_dir: &Path,
    isolated_device_id: &str,
) -> Result<(), String> {
    fs::create_dir_all(claude_dir).map_err(|e| e.to_string())?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let ant_registry = serde_json::json!({
        "deviceId": isolated_device_id,
        "createdAt": now_ms,
        "version": 1
    });
    fs::write(
        claude_dir.join("ant-device-registry.json"),
        serde_json::to_string_pretty(&ant_registry).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let prefix = isolated_device_id.get(..12).unwrap_or(isolated_device_id);
    let ccd_ids = serde_json::json!({
        "device_id": isolated_device_id,
        "client_id": format!("client_{prefix}")
    });
    fs::write(
        claude_dir.join("ccd-ids.json"),
        serde_json::to_string_pretty(&ccd_ids).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}
