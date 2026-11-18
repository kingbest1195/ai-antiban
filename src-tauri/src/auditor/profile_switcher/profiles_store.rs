//! Profile store persistence (`profiles.json`), CRUD operations, and route-sync helpers.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use super::device_registry::{
    clean_opt, create_private_file, current_timestamp, init_fresh_device_registry, is_real_dir,
    is_regular_file, read_existing_device_id, restrict_to_owner,
};
use super::session::{
    clean_claude_auth_artifacts, clean_claude_caches, restore_claude_session_with_home,
    snapshot_claude_session_with_home,
};
use super::{
    ClaudeProfile, ClaudeProfileListResponse, ProfileSwitchResult, resolve_route_id_for_key,
};

static PROFILES_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn lock_profiles() -> MutexGuard<'static, ()> {
    PROFILES_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct ProfilesStorage {
    pub profiles: Vec<ClaudeProfile>,
}

pub(super) fn load_or_init_storage_in(
    storage_dir: &Path,
    claude_dir: &Path,
    current_pinned_ip: Option<&str>,
) -> Result<ProfilesStorage, String> {
    fs::create_dir_all(storage_dir).map_err(|e| e.to_string())?;
    let profiles_file = storage_dir.join("profiles.json");

    if is_regular_file(&profiles_file) {
        let content = super::device_registry::read_json_bom_safe(&profiles_file)?;
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

pub(super) fn save_storage_in(storage_dir: &Path, storage: &ProfilesStorage) -> Result<(), String> {
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
