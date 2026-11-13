use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

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

pub fn get_user_home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .ok()
            .map(PathBuf::from)
            .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

pub fn default_profiles_storage_dir() -> PathBuf {
    if let Some(home) = get_user_home_dir() {
        home.join(".zastava").join("claude_profiles")
    } else {
        PathBuf::from(".zastava").join("claude_profiles")
    }
}

pub fn default_claude_desktop_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = get_user_home_dir()?;
        Some(home.join("Library").join("Application Support").join("Claude"))
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            Some(PathBuf::from(appdata).join("Claude"))
        } else if let Some(home) = get_user_home_dir() {
            Some(home.join("AppData").join("Roaming").join("Claude"))
        } else {
            None
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let home = get_user_home_dir()?;
        Some(home.join(".config").join("Claude"))
    }
}

fn load_or_init_storage_in(
    storage_dir: &Path,
    claude_dir: &Path,
    current_pinned_ip: Option<&str>,
) -> Result<ProfilesStorage, String> {
    fs::create_dir_all(storage_dir).map_err(|e| e.to_string())?;
    let profiles_file = storage_dir.join("profiles.json");

    if profiles_file.exists() {
        let content = fs::read_to_string(&profiles_file).map_err(|e| e.to_string())?;
        if let Ok(storage) = serde_json::from_str::<ProfilesStorage>(&content) {
            if !storage.profiles.is_empty() {
                return Ok(storage);
            }
        }
    }

    // Initialize default profile
    let now = current_timestamp();
    let existing_device_id = read_existing_device_id(claude_dir);
    let device_id = existing_device_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let has_saved_session = claude_dir.exists()
        && (claude_dir.join("Cookies").exists()
            || claude_dir.join("Network").join("Cookies").exists()
            || claude_dir.join("ant-device-registry.json").exists());

    let default_profile = ClaudeProfile {
        id: "default".to_string(),
        name: "Основной аккаунт".to_string(),
        bound_ip: current_pinned_ip.map(|s| s.to_string()),
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
    fs::create_dir_all(storage_dir).map_err(|e| e.to_string())?;
    let profiles_file = storage_dir.join("profiles.json");
    let json = serde_json::to_string_pretty(storage).map_err(|e| e.to_string())?;
    fs::write(&profiles_file, json).map_err(|e| e.to_string())?;
    Ok(())
}

fn read_existing_device_id(claude_dir: &Path) -> Option<String> {
    let registry_file = claude_dir.join("ant-device-registry.json");
    if registry_file.exists() {
        if let Ok(content) = fs::read_to_string(&registry_file) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(id) = val.get("deviceId").and_then(|v| v.as_str()) {
                    let clean = id.trim();
                    if !clean.is_empty() {
                        return Some(clean.to_string());
                    }
                }
            }
        }
    }
    None
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<usize> {
    let mut count = 0;
    if !src.exists() {
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

fn snapshot_claude_session(claude_dir: &Path, snapshot_dir: &Path) -> Result<bool, String> {
    if !claude_dir.exists() {
        return Ok(false);
    }
    fs::create_dir_all(snapshot_dir).map_err(|e| e.to_string())?;
    let mut copied_any = false;

    // Single files
    let session_files = [
        "Cookies",
        "Preferences",
        "Local State",
        "ant-device-registry.json",
        "ccd-ids.json",
        "dispatch-footprint-census.json",
    ];

    for name in session_files {
        let src = claude_dir.join(name);
        let dst = snapshot_dir.join(name);
        if src.is_file() {
            let _ = fs::copy(&src, &dst);
            copied_any = true;
        }
    }

    // Directories
    let session_dirs = ["Network", "Local Storage"];
    for name in session_dirs {
        let src = claude_dir.join(name);
        let dst = snapshot_dir.join(name);
        if src.is_dir() {
            if let Ok(cnt) = copy_dir_recursive(&src, &dst) {
                if cnt > 0 {
                    copied_any = true;
                }
            }
        }
    }

    Ok(copied_any)
}

fn clean_claude_caches(claude_dir: &Path) -> Result<usize, String> {
    if !claude_dir.exists() {
        return Ok(0);
    }
    let mut cleaned_count = 0;
    let cache_dirs = [
        "Cache",
        "Code Cache",
        "GPUCache",
        "DawnCache",
        "Service Worker",
        "Session Storage",
        "IndexedDB",
    ];

    for name in cache_dirs {
        let target = claude_dir.join(name);
        if target.exists() {
            if fs::remove_dir_all(&target).is_ok() {
                cleaned_count += 1;
            }
        }
    }

    Ok(cleaned_count)
}

fn purge_active_claude_credentials(claude_dir: &Path) -> Result<(), String> {
    if !claude_dir.exists() {
        return Ok(());
    }
    let targets_to_remove = [
        "Cookies",
        "Preferences",
        "Local State",
        "ant-device-registry.json",
        "ccd-ids.json",
        "dispatch-footprint-census.json",
    ];
    for name in targets_to_remove {
        let f = claude_dir.join(name);
        if f.is_file() {
            let _ = fs::remove_file(f);
        }
    }
    for dir in ["Network", "Local Storage"] {
        let d = claude_dir.join(dir);
        if d.is_dir() {
            let _ = fs::remove_dir_all(d);
        }
    }
    Ok(())
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

    let ccd_ids = serde_json::json!({
        "device_id": isolated_device_id,
        "client_id": format!("client_{}", &isolated_device_id[..12])
    });
    fs::write(
        claude_dir.join("ccd-ids.json"),
        serde_json::to_string_pretty(&ccd_ids).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

fn restore_claude_session(snapshot_dir: &Path, claude_dir: &Path) -> Result<usize, String> {
    if !snapshot_dir.exists() {
        return Ok(0);
    }
    fs::create_dir_all(claude_dir).map_err(|e| e.to_string())?;
    let mut restored = 0;

    let session_files = [
        "Cookies",
        "Preferences",
        "Local State",
        "ant-device-registry.json",
        "ccd-ids.json",
        "dispatch-footprint-census.json",
    ];

    for name in session_files {
        let src = snapshot_dir.join(name);
        let dst = claude_dir.join(name);
        if src.is_file() {
            if fs::copy(&src, &dst).is_ok() {
                restored += 1;
            }
        }
    }

    let session_dirs = ["Network", "Local Storage"];
    for name in session_dirs {
        let src = snapshot_dir.join(name);
        let dst = claude_dir.join(name);
        if src.is_dir() {
            if let Ok(cnt) = copy_dir_recursive(&src, &dst) {
                restored += cnt;
            }
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
// Core Functional API
// -----------------------------------------------------------------------------

pub fn list_claude_profiles_in(
    storage_dir: &Path,
    claude_dir: &Path,
    current_pinned_ip: Option<&str>,
) -> Result<ClaudeProfileListResponse, String> {
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
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let new_id = format!("profile-{}", &Uuid::new_v4().to_string()[..8]);
    let device_id = Uuid::new_v4().to_string();
    let now = current_timestamp();

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

pub fn switch_claude_profile_in(
    storage_dir: &Path,
    claude_dir: &Path,
    target_id: &str,
) -> Result<ProfileSwitchResult, String> {
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let prev_idx = storage.profiles.iter().position(|p| p.is_active).unwrap_or(0);
    let prev_id = storage.profiles[prev_idx].id.clone();

    let target_idx = storage
        .profiles
        .iter()
        .position(|p| p.id == target_id)
        .ok_or_else(|| format!("Профиль «{target_id}» не найден."))?;

    // 1. Snapshot current profile session
    if claude_dir.exists() {
        let prev_snapshot = storage_dir.join(&prev_id).join("snapshot");
        fs::create_dir_all(&prev_snapshot).map_err(|e| e.to_string())?;
        let saved_any = snapshot_claude_session(claude_dir, &prev_snapshot)?;
        if saved_any {
            storage.profiles[prev_idx].has_saved_session = true;
        }
    }

    // 2. Clean caches
    let cleaned_cache_items = clean_claude_caches(claude_dir)?;

    // 3. Restore target session or init fresh device
    let target_snapshot = storage_dir.join(target_id).join("snapshot");
    let target_profile = &storage.profiles[target_idx];
    let mut restored_files = 0;

    if target_snapshot.exists() && target_profile.has_saved_session {
        restored_files = restore_claude_session(&target_snapshot, claude_dir)?;
    } else {
        // Brand-new clean profile
        purge_active_claude_credentials(claude_dir)?;
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

pub fn delete_claude_profile_in(
    storage_dir: &Path,
    claude_dir: &Path,
    profile_id: &str,
) -> Result<ClaudeProfileListResponse, String> {
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
    storage.profiles.remove(del_idx);

    if was_active {
        storage.profiles[0].is_active = true;
        let new_active_id = storage.profiles[0].id.clone();
        let _ = switch_claude_profile_in(storage_dir, claude_dir, &new_active_id);
    }

    let p_dir = storage_dir.join(profile_id);
    if p_dir.exists() {
        let _ = fs::remove_dir_all(p_dir);
    }

    save_storage_in(storage_dir, &storage)?;
    build_list_response(storage_dir, claude_dir, &storage)
}

pub fn update_profile_bound_ip_in(
    storage_dir: &Path,
    claude_dir: &Path,
    profile_id: &str,
    bind_ip: Option<String>,
    bind_country: Option<String>,
) -> Result<ClaudeProfileListResponse, String> {
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let p = storage
        .profiles
        .iter_mut()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("Профиль «{profile_id}» не найден."))?;

    p.bound_ip = bind_ip;
    p.bound_country = bind_country;

    save_storage_in(storage_dir, &storage)?;
    build_list_response(storage_dir, claude_dir, &storage)
}

pub fn update_profile_bound_upstream_in(
    storage_dir: &Path,
    claude_dir: &Path,
    profile_id: &str,
    upstream_key: Option<String>,
) -> Result<ClaudeProfileListResponse, String> {
    let mut storage = load_or_init_storage_in(storage_dir, claude_dir, None)?;
    let p = storage
        .profiles
        .iter_mut()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| format!("Профиль «{profile_id}» не найден."))?;

    p.bound_route_id = resolve_route_id_for_key(upstream_key.as_deref());
    p.bound_upstream_key = upstream_key;

    save_storage_in(storage_dir, &storage)?;
    build_list_response(storage_dir, claude_dir, &storage)
}

/// Keeps saved Claude profiles in sync when a route is updated (`new_raw_key = Some(...)`)
/// or deleted (`new_raw_key = None`). Returns `Some(new_active_key)` when the currently active
/// profile was modified so callers can refresh runtime routing state.
pub fn sync_profiles_for_route_update_in(
    storage_dir: &Path,
    claude_dir: &Path,
    route_id: &str,
    new_raw_key: Option<&str>,
) -> Result<Option<Option<String>>, String> {
    if !storage_dir.join("profiles.json").exists() {
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

// -----------------------------------------------------------------------------
// Public Environment-Aware Wrappers
// -----------------------------------------------------------------------------

pub fn list_claude_profiles(current_pinned_ip: Option<&str>) -> Result<ClaudeProfileListResponse, String> {
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
    create_claude_profile_in(&storage_dir, &claude_dir, name, bind_ip, bind_country, bind_upstream_key)
}

pub fn switch_claude_profile(target_id: &str) -> Result<ProfileSwitchResult, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    switch_claude_profile_in(&storage_dir, &claude_dir, target_id)
}

pub fn delete_claude_profile(profile_id: &str) -> Result<ClaudeProfileListResponse, String> {
    let storage_dir = default_profiles_storage_dir();
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    delete_claude_profile_in(&storage_dir, &claude_dir, profile_id)
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
        let resp = list_claude_profiles_in(&storage_dir, &claude_dir, Some("145.241.10.5")).unwrap();
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
        assert_eq!(resp2.profiles[1].bound_upstream_key.as_deref(), Some("socks5://proxy.example.com:1080"));
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
        fs::write(claude_dir.join("Cache").join("cache_file.bin"), "cached_telemetry").unwrap();

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
        assert_eq!(switch_res.bound_upstream_key_updated.as_deref(), Some("http://10.0.0.1:8080"));

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
        let registry_content = fs::read_to_string(claude_dir.join("ant-device-registry.json")).unwrap();
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
        let resp = create_claude_profile_in(&storage_dir, &claude_dir, "Temporary", None, None, None).unwrap();
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
        let removed = sync_profiles_for_route_update_in(
            &storage_dir,
            &claude_dir,
            &route_id,
            None,
        )
        .unwrap();
        assert_eq!(removed, Some(None));
        let after = list_claude_profiles_in(&storage_dir, &claude_dir, None).unwrap();
        assert_eq!(after.profiles[0].bound_upstream_key, None);
        assert_eq!(after.profiles[0].bound_route_id, None);
    }
}
