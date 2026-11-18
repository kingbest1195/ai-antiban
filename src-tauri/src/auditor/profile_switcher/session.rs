//! Claude Desktop & Claude Code CLI session snapshot, restore, and cache/auth cleanup.

use std::fs;
use std::path::{Path, PathBuf};

use super::device_registry::{
    copy_dir_recursive, init_fresh_device_registry, is_real_dir, is_regular_file, is_symlink,
    read_json_bom_safe, remove_entry_safe, restrict_to_owner, write_json_atomic,
};

const DESKTOP_SESSION_FILES: &[&str] = &[
    "Cookies",
    "Cookies-journal",
    "Preferences",
    "Local State",
    "TransportSecurity",
    "ant-device-registry.json",
    "ccd-ids.json",
    "dispatch-footprint-census.json",
    "DIPS",
    "DIPS-wal",
    "DIPS-shm",
    "SharedStorage",
    "SharedStorage-wal",
];
const DESKTOP_SESSION_DIRS: &[&str] = &["Network", "Local Storage"];
const DESKTOP_CACHE_DIRS: &[&str] = &[
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "Service Worker",
    "Session Storage",
    "IndexedDB",
    "Network Action Predictor",
    "WebStorage",
    "blob_storage",
];
const SNAPSHOT_CLI_CREDS: &str = "cli_credentials.json";
const SNAPSHOT_CLI_OAUTH: &str = "cli_oauth.json";

pub(super) fn claude_cli_credentials_path(home_dir: &Path) -> PathBuf {
    home_dir.join(".claude").join(".credentials.json")
}

fn claude_cli_config_path(home_dir: &Path) -> PathBuf {
    home_dir.join(".claude.json")
}

fn has_desktop_auth_artifacts(claude_dir: &Path) -> bool {
    is_regular_file(&claude_dir.join("Cookies"))
        || is_regular_file(&claude_dir.join("Network").join("Cookies"))
        || is_regular_file(&claude_dir.join("Local State"))
        || is_regular_file(&claude_dir.join("Preferences"))
        || is_regular_file(&claude_dir.join("dispatch-footprint-census.json"))
        || is_real_dir(&claude_dir.join("Local Storage"))
}

fn read_cli_oauth_slice(home_dir: &Path) -> Option<serde_json::Map<String, serde_json::Value>> {
    let path = claude_cli_config_path(home_dir);
    if !is_regular_file(&path) {
        return None;
    }
    let content = read_json_bom_safe(&path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&content).ok()?;
    let obj = val.as_object()?;
    let mut slice = serde_json::Map::new();
    for key in ["oauthAccount", "userID"] {
        if let Some(v) = obj.get(key)
            && !v.is_null()
        {
            slice.insert(key.to_string(), v.clone());
        }
    }
    (!slice.is_empty()).then_some(slice)
}

pub(super) fn strip_cli_oauth_from_claude_json(home_dir: &Path) -> Result<bool, String> {
    let path = claude_cli_config_path(home_dir);
    if !is_regular_file(&path) {
        return Ok(false);
    }
    let content = read_json_bom_safe(&path)?;
    let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Ok(false);
    };
    let Some(obj) = val.as_object_mut() else {
        return Ok(false);
    };
    let removed_oauth = obj.remove("oauthAccount").is_some();
    let removed_uid = obj.remove("userID").is_some();
    if removed_oauth || removed_uid {
        let updated = serde_json::to_string_pretty(&val).map_err(|e| e.to_string())?;
        write_json_atomic(&path, &updated)?;
        return Ok(true);
    }
    Ok(false)
}

fn merge_cli_oauth_into_claude_json(
    home_dir: &Path,
    oauth_slice: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let path = claude_cli_config_path(home_dir);
    let mut obj = if is_regular_file(&path) {
        let content = read_json_bom_safe(&path)?;
        serde_json::from_str::<serde_json::Value>(&content)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default()
    } else {
        serde_json::Map::new()
    };
    for (k, v) in oauth_slice {
        obj.insert(k.clone(), v.clone());
    }
    let updated = serde_json::to_string_pretty(&serde_json::Value::Object(obj))
        .map_err(|e| e.to_string())?;
    write_json_atomic(&path, &updated)
}

/// Removes active Claude Desktop session/device artifacts and (when `home_dir` is provided)
/// Claude Code CLI credentials (`.claude/.credentials.json`, `oauthAccount`/`userID` in
/// `.claude.json`) while strictly preserving `claude_desktop_config.json`, `.claude/settings.json`,
/// `mcpServers`, and `projects`.
pub fn clean_claude_auth_artifacts(
    claude_dir: &Path,
    home_dir: Option<&Path>,
) -> Result<usize, String> {
    let mut removed = 0;
    if is_real_dir(claude_dir) {
        for name in DESKTOP_SESSION_FILES {
            let f = claude_dir.join(name);
            if remove_entry_safe(&f) {
                removed += 1;
            }
        }
        for dir in DESKTOP_SESSION_DIRS.iter().chain(DESKTOP_CACHE_DIRS.iter()) {
            let d = claude_dir.join(dir);
            if remove_entry_safe(&d) {
                removed += 1;
            }
        }
    }
    if let Some(home) = home_dir {
        let creds = claude_cli_credentials_path(home);
        if (is_regular_file(&creds) || is_symlink(&creds)) && fs::remove_file(&creds).is_ok() {
            removed += 1;
        }
        if strip_cli_oauth_from_claude_json(home)? {
            removed += 1;
        }
    }
    Ok(removed)
}

fn clear_snapshot_dir(snapshot_dir: &Path) {
    if is_real_dir(snapshot_dir) {
        let _ = fs::remove_dir_all(snapshot_dir);
    }
}

pub(super) fn snapshot_claude_session_with_home(
    claude_dir: &Path,
    home_dir: Option<&Path>,
    snapshot_dir: &Path,
) -> Result<(bool, bool), String> {
    let desktop_exists = is_real_dir(claude_dir);
    let cli_creds_exists = home_dir.is_some_and(|h| is_regular_file(&claude_cli_credentials_path(h)));
    let cli_oauth = home_dir.and_then(read_cli_oauth_slice);

    if !desktop_exists && !cli_creds_exists && cli_oauth.is_none() {
        return Ok((false, false));
    }

    clear_snapshot_dir(snapshot_dir);
    fs::create_dir_all(snapshot_dir).map_err(|e| e.to_string())?;
    let mut copied_any = false;
    let mut has_real_auth = cli_creds_exists || cli_oauth.is_some();

    if desktop_exists {
        if has_desktop_auth_artifacts(claude_dir) {
            has_real_auth = true;
        }
        for name in DESKTOP_SESSION_FILES {
            let src = claude_dir.join(name);
            let dst = snapshot_dir.join(name);
            if is_regular_file(&src) && fs::copy(&src, &dst).is_ok() {
                restrict_to_owner(&dst);
                copied_any = true;
            }
        }
        for name in DESKTOP_SESSION_DIRS {
            let src = claude_dir.join(name);
            let dst = snapshot_dir.join(name);
            if is_real_dir(&src)
                && let Ok(cnt) = copy_dir_recursive(&src, &dst)
                && cnt > 0
            {
                copied_any = true;
            }
        }
    }

    if let Some(home) = home_dir {
        let creds_src = claude_cli_credentials_path(home);
        if is_regular_file(&creds_src) {
            let dst = snapshot_dir.join(SNAPSHOT_CLI_CREDS);
            if fs::copy(&creds_src, &dst).is_ok() {
                restrict_to_owner(&dst);
                copied_any = true;
            }
        }
        if let Some(oauth) = cli_oauth {
            let json = serde_json::to_string_pretty(&serde_json::Value::Object(oauth))
                .map_err(|e| e.to_string())?;
            write_json_atomic(&snapshot_dir.join(SNAPSHOT_CLI_OAUTH), &json)?;
            copied_any = true;
        }
    }

    Ok((copied_any, has_real_auth))
}

pub(super) fn clean_claude_caches(claude_dir: &Path) -> Result<usize, String> {
    if !is_real_dir(claude_dir) {
        return Ok(0);
    }
    let mut cleaned_count = 0;
    for name in DESKTOP_CACHE_DIRS {
        let target = claude_dir.join(name);
        if remove_entry_safe(&target) {
            cleaned_count += 1;
        }
    }
    Ok(cleaned_count)
}

pub(super) fn restore_claude_session_with_home(
    snapshot_dir: &Path,
    claude_dir: &Path,
    home_dir: Option<&Path>,
    isolated_device_id: &str,
) -> Result<usize, String> {
    // Always purge previous account artifacts first so unoverwritten files never leak across profiles.
    clean_claude_auth_artifacts(claude_dir, home_dir)?;
    if !is_real_dir(snapshot_dir) {
        init_fresh_device_registry(claude_dir, isolated_device_id)?;
        return Ok(0);
    }
    fs::create_dir_all(claude_dir).map_err(|e| e.to_string())?;
    let mut restored = 0;

    for name in DESKTOP_SESSION_FILES {
        let src = snapshot_dir.join(name);
        let dst = claude_dir.join(name);
        if is_regular_file(&src) && fs::copy(&src, &dst).is_ok() {
            restrict_to_owner(&dst);
            restored += 1;
        }
    }

    for name in DESKTOP_SESSION_DIRS {
        let src = snapshot_dir.join(name);
        let dst = claude_dir.join(name);
        if is_real_dir(&src)
            && let Ok(cnt) = copy_dir_recursive(&src, &dst)
        {
            restored += cnt;
        }
    }

    if !is_regular_file(&claude_dir.join("ant-device-registry.json")) {
        init_fresh_device_registry(claude_dir, isolated_device_id)?;
    }

    if let Some(home) = home_dir {
        let cli_creds_snap = snapshot_dir.join(SNAPSHOT_CLI_CREDS);
        if is_regular_file(&cli_creds_snap) {
            let dst = claude_cli_credentials_path(home);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            if fs::copy(&cli_creds_snap, &dst).is_ok() {
                restrict_to_owner(&dst);
                restored += 1;
            }
        }
        let cli_oauth_snap = snapshot_dir.join(SNAPSHOT_CLI_OAUTH);
        if is_regular_file(&cli_oauth_snap)
            && let Ok(content) = read_json_bom_safe(&cli_oauth_snap)
            && let Ok(serde_json::Value::Object(map)) = serde_json::from_str(&content)
        {
            merge_cli_oauth_into_claude_json(home, &map)?;
            restored += 1;
        }
    }

    Ok(restored)
}
