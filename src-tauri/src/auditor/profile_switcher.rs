use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

static PROFILES_LOCK: Mutex<()> = Mutex::new(());

fn lock_profiles() -> MutexGuard<'static, ()> {
    PROFILES_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeProfile {
    pub id: String,
    pub name: String,
    pub bound_ip: Option<String>,
    pub bound_country: Option<String>,
    #[serde(default)]
    pub bound_upstream_key: Option<String>,
    #[serde(default)]
    pub bound_route_id: Option<String>,
    pub isolated_device_id: String,
    pub created_at: u64,
    pub last_used_at: u64,
    pub is_active: bool,
    pub has_saved_session: bool,
}

pub fn resolve_route_id_for_key(key: Option<&str>) -> Option<String> {
    let trimmed = key.map(str::trim).filter(|s| !s.is_empty())?;
    crate::routing::parse_route_key(trimmed, 0)
        .ok()
        .map(|r| r.id)
        .or_else(|| Some(crate::routing::route_id_for_raw_key(trimmed)))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeProfileListResponse {
    pub profiles: Vec<ClaudeProfile>,
    pub active_profile_id: String,
    pub claude_desktop_installed: bool,
    pub storage_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileSwitchResult {
    pub previous_profile_id: String,
    pub active_profile: ClaudeProfile,
    pub cleaned_cache_items: usize,
    pub restored_files: usize,
    pub pinned_ip_updated: Option<String>,
    pub bound_upstream_key_updated: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProfilesStorage {
    pub profiles: Vec<ClaudeProfile>,
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn clean_opt(val: Option<String>) -> Option<String> {
    val.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false)
}

fn read_json_bom_safe(path: &Path) -> Result<String, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    Ok(raw.trim_start_matches('\u{feff}').to_string())
}

fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
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

fn load_or_init_storage_in(
    storage_dir: &Path,
    claude_dir: &Path,
    current_pinned_ip: Option<&str>,
) -> Result<ProfilesStorage, String> {
    fs::create_dir_all(storage_dir).map_err(|e| e.to_string())?;
    let profiles_file = storage_dir.join("profiles.json");

    if is_regular_file(&profiles_file) {
        let content = read_json_bom_safe(&profiles_file)?;
        if let Ok(storage) = serde_json::from_str::<ProfilesStorage>(&content)
            && !storage.profiles.is_empty()
        {
            return Ok(storage);
        }
    }

    // Initialize default profile
    let now = current_timestamp();
    let existing_device_id = read_existing_device_id(claude_dir);
    let device_id = existing_device_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let has_saved_session = is_real_dir(claude_dir)
        && (is_regular_file(&claude_dir.join("Cookies"))
            || is_regular_file(&claude_dir.join("Network").join("Cookies"))
            || is_regular_file(&claude_dir.join("ant-device-registry.json")));

    let default_profile = ClaudeProfile {
        id: "default".to_string(),
        name: "Основной аккаунт".to_string(),
        bound_ip: clean_opt(current_pinned_ip.map(str::to_string)),
        bound_country: None,
        bound_upstream_key: None,
        bound_route_id: None,
        isolated_device_id: device_id,
        created_at: now,
        last_used_at: now,
        is_active: true,
        has_saved_session,
    };

    let storage = ProfilesStorage {
        profiles: vec![default_profile],
    };
    save_storage_in(storage_dir, &storage)?;
    Ok(storage)
}

fn save_storage_in(storage_dir: &Path, storage: &ProfilesStorage) -> Result<(), String> {
    use std::io::Write;
    fs::create_dir_all(storage_dir).map_err(|e| e.to_string())?;
    let profiles_file = storage_dir.join("profiles.json");
    let json = serde_json::to_string_pretty(storage).map_err(|e| e.to_string())?;
    let tmp_path = storage_dir.join(format!("profiles.json.tmp.{}", std::process::id()));
    {
        let mut f = create_private_file(&tmp_path).map_err(|e| e.to_string())?;
        f.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    if let Err(e) = fs::rename(&tmp_path, &profiles_file) {
        let _ = fs::remove_file(&tmp_path);
        let mut f = create_private_file(&profiles_file).map_err(|_| e.to_string())?;
        restrict_to_owner(&profiles_file);
        f.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(storage_dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn read_existing_device_id(claude_dir: &Path) -> Option<String> {
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

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<usize> {
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

fn claude_cli_credentials_path(home_dir: &Path) -> PathBuf {
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

fn write_json_atomic(path: &Path, json: &str) -> Result<(), String> {
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

fn strip_cli_oauth_from_claude_json(home_dir: &Path) -> Result<bool, String> {
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

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Removes a file, symlink, or real directory cleanly without ever following a symlink
/// into external targets (security guard against planted symlink deletion or traversal).
fn remove_entry_safe(path: &Path) -> bool {
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

fn snapshot_claude_session_with_home(
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

fn clean_claude_caches(claude_dir: &Path) -> Result<usize, String> {
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

fn init_fresh_device_registry(claude_dir: &Path, isolated_device_id: &str) -> Result<(), String> {
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

fn restore_claude_session_with_home(
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

fn build_list_response(
    storage_dir: &Path,
    claude_dir: &Path,
    storage: &ProfilesStorage,
) -> Result<ClaudeProfileListResponse, String> {
    let active_id = storage
        .profiles
        .iter()
        .find(|p| p.is_active)
        .map(|p| p.id.clone())
        .unwrap_or_else(|| "default".to_string());

    let profiles = storage
        .profiles
        .iter()
        .cloned()
        .map(|mut p| {
            if p.bound_route_id.is_none() {
                p.bound_route_id = resolve_route_id_for_key(p.bound_upstream_key.as_deref());
            }
            p
        })
        .collect();

    Ok(ClaudeProfileListResponse {
        profiles,
        active_profile_id: active_id,
        claude_desktop_installed: claude_dir.exists(),
        storage_dir: storage_dir.to_string_lossy().to_string(),
    })
}

// -----------------------------------------------------------------------------
// Core Functional API (serialized via `PROFILES_LOCK`)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProfileBindingState {
    pub profile_id: String,
    pub bound_ip: Option<String>,
    pub bound_upstream_key: Option<String>,
    pub bound_route_id: Option<String>,
}

pub fn list_claude_profiles_in(
    storage_dir: &Path,
    claude_dir: &Path,
    current_pinned_ip: Option<&str>,
) -> Result<ClaudeProfileListResponse, String> {
    let _guard = lock_profiles();
    let storage = load_or_init_storage_in(storage_dir, claude_dir, current_pinned_ip)?;
    build_list_response(storage_dir, claude_dir, &storage)
}

pub fn create_claude_profile_in(
    storage_dir: &Path,
    claude_dir: &Path,
    name: &str,
    bind_ip: Option<String>,
    bind_country: Option<String>,
    bind_upstream_key: Option<String>,
) -> Result<ClaudeProfileListResponse, String> {
    let _guard = lock_profiles();
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let new_id = format!("profile-{}", &Uuid::new_v4().to_string()[..8]);
    let device_id = Uuid::new_v4().to_string();
    let now = current_timestamp();

    let bind_ip = clean_opt(bind_ip);
    let bind_country = clean_opt(bind_country);
    let bind_upstream_key = clean_opt(bind_upstream_key);
    let bound_route_id = resolve_route_id_for_key(bind_upstream_key.as_deref());
    let new_profile = ClaudeProfile {
        id: new_id.clone(),
        name: name.trim().to_string(),
        bound_ip: bind_ip,
        bound_country: bind_country,
        bound_upstream_key: bind_upstream_key,
        bound_route_id,
        isolated_device_id: device_id,
        created_at: now,
        last_used_at: now,
        is_active: false,
        has_saved_session: false,
    };

    let snapshot_dir = storage_dir.join(&new_id).join("snapshot");
    fs::create_dir_all(&snapshot_dir).map_err(|e| e.to_string())?;

    storage.profiles.push(new_profile);
    save_storage_in(storage_dir, &storage)?;
    build_list_response(storage_dir, claude_dir, &storage)
}

fn switch_claude_profile_in_locked(
    storage_dir: &Path,
    claude_dir: &Path,
    home_dir: Option<&Path>,
    target_id: &str,
) -> Result<ProfileSwitchResult, String> {
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let prev_idx = storage
        .profiles
        .iter()
        .position(|p| p.is_active)
        .unwrap_or(0);
    let prev_id = storage.profiles[prev_idx].id.clone();

    let target_idx = storage
        .profiles
        .iter()
        .position(|p| p.id == target_id)
        .ok_or_else(|| format!("Профиль «{target_id}» не найден."))?;

    if prev_id == target_id {
        let now = current_timestamp();
        storage.profiles[target_idx].last_used_at = now;
        if storage.profiles[target_idx].bound_route_id.is_none() {
            storage.profiles[target_idx].bound_route_id =
                resolve_route_id_for_key(storage.profiles[target_idx].bound_upstream_key.as_deref());
        }
        let active_profile = storage.profiles[target_idx].clone();
        save_storage_in(storage_dir, &storage)?;
        return Ok(ProfileSwitchResult {
            previous_profile_id: prev_id,
            pinned_ip_updated: active_profile.bound_ip.clone(),
            bound_upstream_key_updated: active_profile.bound_upstream_key.clone(),
            active_profile: active_profile.clone(),
            cleaned_cache_items: 0,
            restored_files: 0,
            message: format!("Профиль «{}» уже активен.", active_profile.name),
        });
    }

    // 1. Snapshot current profile session (only real auth artifacts flip `has_saved_session`)
    let prev_snapshot = storage_dir.join(&prev_id).join("snapshot");
    let (_, has_real_auth) =
        snapshot_claude_session_with_home(claude_dir, home_dir, &prev_snapshot)?;
    if has_real_auth {
        storage.profiles[prev_idx].has_saved_session = true;
    }

    // 2. Clean caches
    let cleaned_cache_items = clean_claude_caches(claude_dir)?;

    // 3. Restore target session (purging previous credentials first) or init fresh clean device
    let target_snapshot = storage_dir.join(target_id).join("snapshot");
    let target_profile = &storage.profiles[target_idx];
    let mut restored_files = 0;

    if target_snapshot.exists() && target_profile.has_saved_session {
        restored_files = restore_claude_session_with_home(
            &target_snapshot,
            claude_dir,
            home_dir,
            &target_profile.isolated_device_id,
        )?;
    } else {
        clean_claude_auth_artifacts(claude_dir, home_dir)?;
        init_fresh_device_registry(claude_dir, &target_profile.isolated_device_id)?;
    }

    // 4. Mark target active
    for p in &mut storage.profiles {
        p.is_active = p.id == target_id;
    }
    let now = current_timestamp();
    storage.profiles[target_idx].last_used_at = now;
    if storage.profiles[target_idx].bound_route_id.is_none() {
        storage.profiles[target_idx].bound_route_id =
            resolve_route_id_for_key(storage.profiles[target_idx].bound_upstream_key.as_deref());
    }
    let active_profile = storage.profiles[target_idx].clone();

    save_storage_in(storage_dir, &storage)?;

    Ok(ProfileSwitchResult {
        previous_profile_id: prev_id,
        pinned_ip_updated: active_profile.bound_ip.clone(),
        bound_upstream_key_updated: active_profile.bound_upstream_key.clone(),
        active_profile: active_profile.clone(),
        cleaned_cache_items,
        restored_files,
        message: format!("Успешно переключено на профиль «{}».", active_profile.name),
    })
}

pub fn switch_claude_profile_in_with_home(
    storage_dir: &Path,
    claude_dir: &Path,
    home_dir: Option<&Path>,
    target_id: &str,
) -> Result<ProfileSwitchResult, String> {
    let _guard = lock_profiles();
    switch_claude_profile_in_locked(storage_dir, claude_dir, home_dir, target_id)
}

pub fn switch_claude_profile_in(
    storage_dir: &Path,
    claude_dir: &Path,
    target_id: &str,
) -> Result<ProfileSwitchResult, String> {
    switch_claude_profile_in_with_home(storage_dir, claude_dir, None, target_id)
}

pub fn delete_claude_profile_in_with_home(
    storage_dir: &Path,
    claude_dir: &Path,
    home_dir: Option<&Path>,
    profile_id: &str,
) -> Result<ClaudeProfileListResponse, String> {
    let _guard = lock_profiles();
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    if storage.profiles.len() <= 1 {
        return Err("Нельзя удалить единственный профиль.".to_string());
    }

    let del_idx = storage
        .profiles
        .iter()
        .position(|p| p.id == profile_id)
        .ok_or_else(|| format!("Профиль «{profile_id}» не найден."))?;

    let was_active = storage.profiles[del_idx].is_active;
    if was_active {
        let new_active_id = storage
            .profiles
            .iter()
            .find(|p| p.id != profile_id)
            .map(|p| p.id.clone())
            .ok_or_else(|| "Не найден резервный профиль для переключения.".to_string())?;
        // Switch while the deleted profile is still marked active so `switch_claude_profile_in_locked`
        // does not snapshot the deleted session over the target profile, then reload fresh metadata.
        switch_claude_profile_in_locked(storage_dir, claude_dir, home_dir, &new_active_id)?;
        storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    }

    storage.profiles.retain(|p| p.id != profile_id);
    if !storage.profiles.is_empty() && !storage.profiles.iter().any(|p| p.is_active) {
        storage.profiles[0].is_active = true;
    }

    let p_dir = storage_dir.join(profile_id);
    if is_real_dir(&p_dir) {
        let _ = fs::remove_dir_all(p_dir);
    }

    save_storage_in(storage_dir, &storage)?;
    build_list_response(storage_dir, claude_dir, &storage)
}

pub fn delete_claude_profile_in(
    storage_dir: &Path,
    claude_dir: &Path,
    profile_id: &str,
) -> Result<ClaudeProfileListResponse, String> {
    delete_claude_profile_in_with_home(storage_dir, claude_dir, None, profile_id)
}

pub fn update_profile_bound_ip_in(
    storage_dir: &Path,
    claude_dir: &Path,
    profile_id: &str,
    bind_ip: Option<String>,
    bind_country: Option<String>,
) -> Result<ClaudeProfileListResponse, String> {
    let _guard = lock_profiles();
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let p = storage
        .profiles
        .iter_mut()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("Профиль «{profile_id}» не найден."))?;

    p.bound_ip = clean_opt(bind_ip);
    p.bound_country = clean_opt(bind_country);

    save_storage_in(storage_dir, &storage)?;
    build_list_response(storage_dir, claude_dir, &storage)
}

pub fn update_profile_bound_upstream_in(
    storage_dir: &Path,
    claude_dir: &Path,
    profile_id: &str,
    upstream_key: Option<String>,
) -> Result<ClaudeProfileListResponse, String> {
    let _guard = lock_profiles();
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let p = storage
        .profiles
        .iter_mut()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("Профиль «{profile_id}» не найден."))?;

    let upstream_key = clean_opt(upstream_key);
    p.bound_route_id = resolve_route_id_for_key(upstream_key.as_deref());
    p.bound_upstream_key = upstream_key;

    save_storage_in(storage_dir, &storage)?;
    build_list_response(storage_dir, claude_dir, &storage)
}

/// Keeps saved Claude profiles in sync when a route is updated (`new_raw_key = Some(...)`)
/// or explicitly detached (`new_raw_key = None`). Returns `Some(new_active_key)` when the currently
/// active profile was modified so callers can refresh runtime routing state.
pub fn sync_profiles_for_route_update_in(
    storage_dir: &Path,
    claude_dir: &Path,
    route_id: &str,
    new_raw_key: Option<&str>,
) -> Result<Option<Option<String>>, String> {
    let _guard = lock_profiles();
    if !is_regular_file(&storage_dir.join("profiles.json")) {
        return Ok(None);
    }
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let mut changed = false;
    let mut active_updated: Option<Option<String>> = None;

    for p in &mut storage.profiles {
        let current_id = p
            .bound_route_id
            .clone()
            .or_else(|| resolve_route_id_for_key(p.bound_upstream_key.as_deref()));
        if current_id.as_deref() == Some(route_id) {
            match new_raw_key {
                Some(raw_key) => {
                    let next_key = Some(raw_key.to_string());
                    if p.bound_upstream_key.as_ref() != next_key.as_ref()
                        || p.bound_route_id.as_deref() != Some(route_id)
                    {
                        p.bound_upstream_key = next_key.clone();
                        p.bound_route_id = Some(route_id.to_string());
                        changed = true;
                        if p.is_active {
                            active_updated = Some(next_key);
                        }
                    }
                }
                None => {
                    p.bound_upstream_key = None;
                    p.bound_route_id = None;
                    changed = true;
                    if p.is_active {
                        active_updated = Some(None);
                    }
                }
            }
        }
    }

    if changed {
        save_storage_in(storage_dir, &storage)?;
    }
    Ok(active_updated)
}

/// Marks profiles bound to a deleted route `route_id` as dangling: clears `bound_upstream_key` so
/// the deleted raw key is never resurrected on restart, while preserving `bound_route_id` so BOTH
/// active and inactive profiles stay fail-closed (`Missing(route_id)` / `DanglingBinding`) until
/// explicitly unbound or re-imported. Returns `Some(true)` if the active profile was affected.
pub fn mark_profiles_route_removed_in(
    storage_dir: &Path,
    claude_dir: &Path,
    route_id: &str,
) -> Result<bool, String> {
    let _guard = lock_profiles();
    if !is_regular_file(&storage_dir.join("profiles.json")) {
        return Ok(false);
    }
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let mut changed = false;
    let mut active_affected = false;

    for p in &mut storage.profiles {
        let current_id = p
            .bound_route_id
            .clone()
            .or_else(|| resolve_route_id_for_key(p.bound_upstream_key.as_deref()));
        if current_id.as_deref() == Some(route_id) {
            if p.bound_upstream_key.is_some() || p.bound_route_id.as_deref() != Some(route_id) {
                p.bound_upstream_key = None;
                p.bound_route_id = Some(route_id.to_string());
                changed = true;
            }
            if p.is_active {
                active_affected = true;
            }
        }
    }

    if changed {
        save_storage_in(storage_dir, &storage)?;
    }
    Ok(active_affected)
}

/// Reads the active profile's route/IP binding from `profiles.json` for startup reconciliation,
/// without creating `profiles.json` if it does not exist yet.
pub fn active_profile_binding_state_in(
    storage_dir: &Path,
) -> Result<Option<ActiveProfileBindingState>, String> {
    let _guard = lock_profiles();
    let profiles_file = storage_dir.join("profiles.json");
    if !is_regular_file(&profiles_file) {
        return Ok(None);
    }
    let content = read_json_bom_safe(&profiles_file)?;
    let storage: ProfilesStorage =
        serde_json::from_str(&content).map_err(|e| format!("Не удалось разобрать profiles.json: {e}"))?;
    let Some(active) = storage
        .profiles
        .iter()
        .find(|p| p.is_active)
        .or_else(|| storage.profiles.first())
    else {
        return Ok(None);
    };
    let bound_ip = active
        .bound_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let bound_upstream_key = active
        .bound_upstream_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let bound_route_id = active
        .bound_route_id
        .clone()
        .or_else(|| resolve_route_id_for_key(bound_upstream_key.as_deref()));

    Ok(Some(ActiveProfileBindingState {
        profile_id: active.id.clone(),
        bound_ip,
        bound_upstream_key,
        bound_route_id,
    }))
}

// -----------------------------------------------------------------------------
// Public Environment-Aware Wrappers
// -----------------------------------------------------------------------------

pub fn list_claude_profiles(
    current_pinned_ip: Option<&str>,
) -> Result<ClaudeProfileListResponse, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    list_claude_profiles_in(&storage_dir, &claude_dir, current_pinned_ip)
}

pub fn create_claude_profile(
    name: &str,
    bind_ip: Option<String>,
    bind_country: Option<String>,
    bind_upstream_key: Option<String>,
) -> Result<ClaudeProfileListResponse, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    create_claude_profile_in(
        &storage_dir,
        &claude_dir,
        name,
        bind_ip,
        bind_country,
        bind_upstream_key,
    )
}

pub fn switch_claude_profile(target_id: &str) -> Result<ProfileSwitchResult, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    let home_dir = get_user_home_dir();
    switch_claude_profile_in_with_home(&storage_dir, &claude_dir, home_dir.as_deref(), target_id)
}

pub fn delete_claude_profile(profile_id: &str) -> Result<ClaudeProfileListResponse, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    let home_dir = get_user_home_dir();
    delete_claude_profile_in_with_home(&storage_dir, &claude_dir, home_dir.as_deref(), profile_id)
}

pub fn update_profile_bound_ip(
    profile_id: &str,
    bind_ip: Option<String>,
    bind_country: Option<String>,
) -> Result<ClaudeProfileListResponse, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    update_profile_bound_ip_in(&storage_dir, &claude_dir, profile_id, bind_ip, bind_country)
}

pub fn update_profile_bound_upstream(
    profile_id: &str,
    upstream_key: Option<String>,
) -> Result<ClaudeProfileListResponse, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    update_profile_bound_upstream_in(&storage_dir, &claude_dir, profile_id, upstream_key)
}

pub fn sync_profiles_for_route_update(
    route_id: &str,
    new_raw_key: Option<&str>,
) -> Result<Option<Option<String>>, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    sync_profiles_for_route_update_in(&storage_dir, &claude_dir, route_id, new_raw_key)
}

pub fn mark_profiles_route_removed(route_id: &str) -> Result<bool, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    mark_profiles_route_removed_in(&storage_dir, &claude_dir, route_id)
}

pub fn active_profile_binding_state() -> Result<Option<ActiveProfileBindingState>, String> {
    let storage_dir = default_profiles_storage_dir();
    active_profile_binding_state_in(&storage_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_creation_and_default_initialization() {
        let temp = tempfile::tempdir().unwrap();
        let storage_dir = temp.path().join(".zastava").join("claude_profiles");
        let claude_dir = temp.path().join("Claude");
        fs::create_dir_all(&claude_dir).unwrap();

        // 1. Initial list auto-creates default profile
        let resp =
            list_claude_profiles_in(&storage_dir, &claude_dir, Some("145.241.10.5")).unwrap();
        assert_eq!(resp.profiles.len(), 1);
        assert_eq!(resp.profiles[0].id, "default");
        assert_eq!(resp.profiles[0].name, "Основной аккаунт");
        assert_eq!(resp.profiles[0].bound_ip.as_deref(), Some("145.241.10.5"));
        assert!(resp.profiles[0].is_active);

        // 2. Create second profile
        let resp2 = create_claude_profile_in(
            &storage_dir,
            &claude_dir,
            "Рабочий Claude Pro",
            Some("195.12.34.56".to_string()),
            Some("NL".to_string()),
            Some("socks5://proxy.example.com:1080".to_string()),
        )
        .unwrap();
        assert_eq!(resp2.profiles.len(), 2);
        assert_eq!(resp2.profiles[1].name, "Рабочий Claude Pro");
        assert_eq!(
            resp2.profiles[1].bound_upstream_key.as_deref(),
            Some("socks5://proxy.example.com:1080")
        );
        assert_ne!(
            resp2.profiles[0].isolated_device_id,
            resp2.profiles[1].isolated_device_id
        );
    }

    #[test]
    fn test_profile_switching_and_snapshot_restoration() {
        let temp = tempfile::tempdir().unwrap();
        let storage_dir = temp.path().join(".zastava").join("claude_profiles");
        let claude_dir = temp.path().join("Claude");
        fs::create_dir_all(&claude_dir).unwrap();

        // Put initial session file in claude_dir for default profile
        fs::write(claude_dir.join("Cookies"), "session_default_cookie_data").unwrap();
        fs::create_dir_all(claude_dir.join("Cache")).unwrap();
        fs::write(
            claude_dir.join("Cache").join("cache_file.bin"),
            "cached_telemetry",
        )
        .unwrap();

        // Preserve claude_desktop_config.json
        fs::write(
            claude_dir.join("claude_desktop_config.json"),
            r#"{"mcpServers":{}}"#,
        )
        .unwrap();

        // Create second profile
        let resp = create_claude_profile_in(
            &storage_dir,
            &claude_dir,
            "Резервный аккаунт",
            None,
            None,
            Some("http://10.0.0.1:8080".to_string()),
        )
        .unwrap();
        let p2_id = resp.profiles[1].id.clone();

        // Switch to profile 2
        let switch_res = switch_claude_profile_in(&storage_dir, &claude_dir, &p2_id).unwrap();
        assert_eq!(switch_res.previous_profile_id, "default");
        assert_eq!(switch_res.active_profile.id, p2_id);
        assert_eq!(
            switch_res.bound_upstream_key_updated.as_deref(),
            Some("http://10.0.0.1:8080")
        );

        // Caches were cleaned
        assert!(!claude_dir.join("Cache").exists());
        // claude_desktop_config.json strictly preserved
        assert!(claude_dir.join("claude_desktop_config.json").exists());

        // Default profile's snapshot contains old Cookies
        let default_snapshot = storage_dir.join("default").join("snapshot").join("Cookies");
        assert!(default_snapshot.exists());
        assert_eq!(
            fs::read_to_string(&default_snapshot).unwrap(),
            "session_default_cookie_data"
        );

        // Claude dir now has profile 2's fresh isolated device registry
        assert!(claude_dir.join("ant-device-registry.json").exists());
        let registry_content =
            fs::read_to_string(claude_dir.join("ant-device-registry.json")).unwrap();
        assert!(registry_content.contains(&resp.profiles[1].isolated_device_id));

        // Switch back to default profile
        let switch_back = switch_claude_profile_in(&storage_dir, &claude_dir, "default").unwrap();
        assert_eq!(switch_back.active_profile.id, "default");
        assert_eq!(switch_back.bound_upstream_key_updated, None);
        assert!(claude_dir.join("Cookies").exists());
        assert_eq!(
            fs::read_to_string(claude_dir.join("Cookies")).unwrap(),
            "session_default_cookie_data"
        );
    }

    #[test]
    fn test_delete_profile_and_prevent_last_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let storage_dir = temp.path().join(".zastava").join("claude_profiles");
        let claude_dir = temp.path().join("Claude");

        // Single profile cannot be deleted
        let _ = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
        let del_err = delete_claude_profile_in(&storage_dir, &claude_dir, "default");
        assert!(del_err.is_err());

        // Add second profile and delete it
        let resp =
            create_claude_profile_in(&storage_dir, &claude_dir, "Temporary", None, None, None)
                .unwrap();
        let p2_id = resp.profiles[1].id.clone();
        let after_del = delete_claude_profile_in(&storage_dir, &claude_dir, &p2_id).unwrap();
        assert_eq!(after_del.profiles.len(), 1);
    }

    #[test]
    fn test_ip_binding_update() {
        let temp = tempfile::tempdir().unwrap();
        let storage_dir = temp.path().join(".zastava").join("claude_profiles");
        let claude_dir = temp.path().join("Claude");

        let _ = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
        let updated = update_profile_bound_ip_in(
            &storage_dir,
            &claude_dir,
            "default",
            Some("104.28.19.2".to_string()),
            Some("US".to_string()),
        )
        .unwrap();

        assert_eq!(updated.profiles[0].bound_ip.as_deref(), Some("104.28.19.2"));
        assert_eq!(updated.profiles[0].bound_country.as_deref(), Some("US"));

        let updated_upstream = update_profile_bound_upstream_in(
            &storage_dir,
            &claude_dir,
            "default",
            Some("socks5://127.0.0.1:1080".to_string()),
        )
        .unwrap();
        assert_eq!(
            updated_upstream.profiles[0].bound_upstream_key.as_deref(),
            Some("socks5://127.0.0.1:1080")
        );
        assert!(updated_upstream.profiles[0].bound_route_id.is_some());
    }

    #[test]
    fn test_sync_profiles_for_route_update_in() {
        let temp = tempfile::tempdir().unwrap();
        let storage_dir = temp.path().join(".zastava").join("claude_profiles");
        let claude_dir = temp.path().join("Claude");

        let _ = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
        let initial_key = "socks5://127.0.0.1:1080#NL";
        let bound = update_profile_bound_upstream_in(
            &storage_dir,
            &claude_dir,
            "default",
            Some(initial_key.to_string()),
        )
        .unwrap();
        let route_id = bound.profiles[0].bound_route_id.clone().unwrap();

        // Update raw key for the same route ID
        let updated_key = "socks5://127.0.0.1:1080#NL-Updated";
        let res = sync_profiles_for_route_update_in(
            &storage_dir,
            &claude_dir,
            &route_id,
            Some(updated_key),
        )
        .unwrap();
        assert_eq!(res, Some(Some(updated_key.to_string())));

        // Remove route -> clears profile binding and reports active profile cleared
        let removed =
            sync_profiles_for_route_update_in(&storage_dir, &claude_dir, &route_id, None).unwrap();
        assert_eq!(removed, Some(None));
        let after = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
        assert_eq!(after.profiles[0].bound_upstream_key, None);
        assert_eq!(after.profiles[0].bound_route_id, None);
    }

    #[test]
    fn test_delete_active_profile_switches_and_persists_cleanly() {
        let temp = tempfile::tempdir().unwrap();
        let storage_dir = temp.path().join(".zastava").join("claude_profiles");
        let claude_dir = temp.path().join("Claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(claude_dir.join("Cookies"), "default_cookies").unwrap();

        let _ = list_claude_profiles_in(&storage_dir, &claude_dir, Some("1.1.1.1")).unwrap();
        update_profile_bound_upstream_in(
            &storage_dir,
            &claude_dir,
            "default",
            Some("socks5://127.0.0.1:1080#DefaultNL".to_string()),
        )
        .unwrap();

        let created = create_claude_profile_in(
            &storage_dir,
            &claude_dir,
            "TempActive",
            Some("2.2.2.2".to_string()),
            Some("DE".to_string()),
            Some("socks5://127.0.0.1:1081#TempDE".to_string()),
        )
        .unwrap();
        let temp_id = created.profiles[1].id.clone();

        switch_claude_profile_in(&storage_dir, &claude_dir, &temp_id).unwrap();
        fs::write(claude_dir.join("Cookies"), "temp_active_cookies").unwrap();

        let after_del = delete_claude_profile_in(&storage_dir, &claude_dir, &temp_id).unwrap();
        assert_eq!(after_del.profiles.len(), 1);
        assert_eq!(after_del.active_profile_id, "default");
        assert!(after_del.profiles[0].is_active);
        assert_eq!(after_del.profiles[0].bound_ip.as_deref(), Some("1.1.1.1"));
        assert_eq!(
            after_del.profiles[0].bound_upstream_key.as_deref(),
            Some("socks5://127.0.0.1:1080#DefaultNL")
        );
        assert!(!storage_dir.join(&temp_id).exists());
        assert_eq!(
            fs::read_to_string(claude_dir.join("Cookies")).unwrap(),
            "default_cookies"
        );

        let reloaded = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
        assert_eq!(reloaded.profiles.len(), 1);
        assert_eq!(reloaded.active_profile_id, "default");
    }

    #[test]
    fn test_concurrent_profile_operations_do_not_corrupt_storage() {
        let temp = tempfile::tempdir().unwrap();
        let storage_dir = temp.path().join(".zastava").join("claude_profiles");
        let claude_dir = temp.path().join("Claude");
        fs::create_dir_all(&claude_dir).unwrap();
        let _ = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();

        std::thread::scope(|s| {
            for i in 0..8 {
                let sd = &storage_dir;
                let cd = &claude_dir;
                s.spawn(move || {
                    create_claude_profile_in(
                        sd,
                        cd,
                        &format!("Worker-{i}"),
                        Some(format!("10.0.0.{}", i + 10)),
                        Some("NL".to_string()),
                        None,
                    )
                    .unwrap();
                });
            }
        });

        let listed = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
        assert_eq!(listed.profiles.len(), 9);
    }

    #[test]
    fn test_active_profile_binding_state_in() {
        let temp = tempfile::tempdir().unwrap();
        let storage_dir = temp.path().join(".zastava").join("claude_profiles");
        let claude_dir = temp.path().join("Claude");
        fs::create_dir_all(&claude_dir).unwrap();

        assert_eq!(active_profile_binding_state_in(&storage_dir).unwrap(), None);

        let created = create_claude_profile_in(
            &storage_dir,
            &claude_dir,
            "Work",
            Some("185.10.20.30".to_string()),
            Some("FR".to_string()),
            Some("socks5://127.0.0.1:1080#FR".to_string()),
        )
        .unwrap();
        let work_id = created.profiles[1].id.clone();
        switch_claude_profile_in(&storage_dir, &claude_dir, &work_id).unwrap();

        let state = active_profile_binding_state_in(&storage_dir)
            .unwrap()
            .expect("binding state must exist");
        assert_eq!(state.profile_id, work_id);
        assert_eq!(state.bound_ip.as_deref(), Some("185.10.20.30"));
        assert_eq!(
            state.bound_upstream_key.as_deref(),
            Some("socks5://127.0.0.1:1080#FR")
        );
        assert!(state.bound_route_id.is_some());
    }
}
