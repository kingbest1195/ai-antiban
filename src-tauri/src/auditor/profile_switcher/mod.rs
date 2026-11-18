//! Isolated Claude Desktop & Claude Code CLI profile switcher and session store.

mod device_registry;
mod profiles_store;
mod route_sync;
mod safe_logout;
mod session;

#[cfg(test)]
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use device_registry::{
    default_claude_desktop_dir, default_profiles_storage_dir, get_user_home_dir,
    resolve_claude_desktop_dir_for_platform,
};
pub use profiles_store::{
    create_claude_profile_in, delete_claude_profile_in, delete_claude_profile_in_with_home,
    list_claude_profiles_in, switch_claude_profile_in, switch_claude_profile_in_with_home,
    update_profile_bound_ip_in, update_profile_bound_upstream_in,
};
pub use route_sync::{
    active_profile_binding_state_in, mark_profiles_route_removed_in,
    sync_profiles_for_route_update_in,
};
pub use safe_logout::{
    SafeLogoutResult, safe_logout_claude, safe_logout_claude_fs_in, safe_logout_claude_with_dirs,
};
pub use session::clean_claude_auth_artifacts;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProfileBindingState {
    pub profile_id: String,
    pub bound_ip: Option<String>,
    pub bound_upstream_key: Option<String>,
    pub bound_route_id: Option<String>,
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
#[path = "../profile_switcher_tests.rs"]
mod tests;
