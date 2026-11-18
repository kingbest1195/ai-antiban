//! Route synchronization and startup binding queries for Claude profiles.

use std::path::Path;

use super::device_registry::{is_regular_file, read_json_bom_safe};
use super::profiles_store::{
    ProfilesStorage, load_or_init_storage_in, lock_profiles, save_storage_in,
};
use super::{ActiveProfileBindingState, resolve_route_id_for_key};

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
    let storage: ProfilesStorage = serde_json::from_str(&content)
        .map_err(|e| format!("Не удалось разобрать profiles.json: {e}"))?;
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
