//! Claude Code & Claude Desktop local data scanner and Desktop context exporter.

mod export;
mod scan;

#[cfg(test)]
mod tests;

pub use export::{
    export_claude_dir_to, export_claude_local_data, generate_index_summary_md,
    generate_restore_prompt_md,
};
pub use scan::{
    decode_project_slug, extract_last_user_query_from_jsonl, scan_claude_dir,
    scan_claude_local_data,
};

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Brief summary of a single project detected in ~/.claude/projects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeProjectBrief {
    pub slug: String,
    pub decoded_path: String,
    pub sessions_count: usize,
    pub has_memory: bool,
    pub total_bytes: u64,
    pub last_modified: Option<u64>,
}

/// Comprehensive scan result of local Claude Code and Claude Desktop artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeLocalDataSummary {
    pub exists: bool,
    pub claude_dir_path: String,
    pub projects_count: usize,
    pub sessions_count: usize,
    pub plans_count: usize,
    pub memory_files_count: usize,
    pub total_size_bytes: u64,
    pub projects: Vec<ClaudeProjectBrief>,
    pub has_claude_md: bool,
    pub has_history: bool,
    pub has_settings: bool,
    pub has_desktop_config: bool,
    pub has_claude_json: bool,
}

/// Result returned after exporting local Claude artifacts to Desktop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeExportResult {
    pub export_dir_path: String,
    pub zip_archive_path: Option<String>,
    pub index_summary_path: String,
    pub restore_prompt_path: String,
    pub restore_prompt_text: String,
    pub projects_exported: usize,
    pub sessions_exported: usize,
    pub total_bytes: u64,
}

pub fn get_home_dir() -> Option<PathBuf> {
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

pub fn get_desktop_dir(home: &Path) -> PathBuf {
    let desktop = home.join("Desktop");
    if desktop.is_dir() {
        desktop
    } else {
        home.to_path_buf()
    }
}

pub fn get_claude_desktop_config_path(home: &Path) -> Option<PathBuf> {
    use crate::auditor::geo_matrix::ProviderId;
    #[cfg(target_os = "windows")]
    use crate::auditor::profile_switcher::resolve_ai_app_data_dirs;
    use crate::auditor::profile_switcher::resolve_ai_app_data_dirs_for_platform;

    #[cfg(target_os = "macos")]
    let os = "macos";
    #[cfg(target_os = "windows")]
    let os = "windows";
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let os = "linux";

    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut dirs =
        resolve_ai_app_data_dirs_for_platform(ProviderId::Anthropic, os, Some(home), None, None);
    #[cfg(target_os = "windows")]
    for dir in resolve_ai_app_data_dirs(ProviderId::Anthropic) {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }

    dirs.into_iter()
        .map(|dir| dir.join("claude_desktop_config.json"))
        .find(|p| p.exists())
}
