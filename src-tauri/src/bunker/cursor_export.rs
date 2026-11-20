//! Cursor IDE settings, keybindings, snippets, MCP config, and `.cursorrules` exporter.
//!
//! Safety Charter invariant: STRICTLY NEVER copies `state.vscdb`, auth tokens, Cookies, or
//! `Local Storage`.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::auditor::claude_exporter::decode_project_slug;

use super::sanitize::{
    copy_private_dir_filtered, copy_private_file, copy_sanitized_json_file, ensure_private_dir,
    extract_mcp_server_names, is_excluded_secret_name,
};

#[derive(Debug, Clone)]
pub struct CursorScanInfo {
    pub available: bool,
    pub path_hint: Option<String>,
    pub user_dir: Option<PathBuf>,
    pub mcp_json_path: Option<PathBuf>,
    pub rules_paths: Vec<(String, PathBuf)>,
    pub items_count: usize,
    pub total_bytes: u64,
    pub mcp_servers: Vec<String>,
}

/// Resolves Cursor IDE `User` configuration directory on the current OS relative to `home_dir`.
pub fn resolve_cursor_user_dir(home_dir: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    #[cfg(target_os = "macos")]
    {
        candidates.push(
            home_dir
                .join("Library")
                .join("Application Support")
                .join("Cursor")
                .join("User"),
        );
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            candidates.push(PathBuf::from(appdata).join("Cursor").join("User"));
        }
        candidates.push(
            home_dir
                .join("AppData")
                .join("Roaming")
                .join("Cursor")
                .join("User"),
        );
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        candidates.push(home_dir.join(".config").join("Cursor").join("User"));
    }

    candidates.into_iter().find(|p| p.is_dir())
}

/// Scans Cursor IDE configuration files, `~/.cursor/mcp.json`, and project `.cursorrules`.
pub fn scan_cursor_data(home_dir: &Path, claude_dir: &Path) -> CursorScanInfo {
    let user_dir = resolve_cursor_user_dir(home_dir);
    let mcp_candidate = home_dir.join(".cursor").join("mcp.json");
    let mcp_json_path = mcp_candidate.is_file().then_some(mcp_candidate);

    let rules_paths = collect_cursorrules_paths(home_dir, claude_dir);
    let mut items_count = 0usize;
    let mut total_bytes = 0u64;

    if let Some(ud) = &user_dir {
        for name in ["settings.json", "keybindings.json"] {
            let p = ud.join(name);
            if p.is_file()
                && let Ok(meta) = fs::metadata(&p)
            {
                items_count += 1;
                total_bytes += meta.len();
            }
        }
        let snippets = ud.join("snippets");
        if snippets.is_dir() {
            let (cnt, bytes) = count_safe_files(&snippets);
            items_count += cnt;
            total_bytes += bytes;
        }
    }

    let mut mcp_servers = Vec::new();
    if let Some(mcp) = &mcp_json_path
        && let Ok(meta) = fs::metadata(mcp)
    {
        items_count += 1;
        total_bytes += meta.len();
        mcp_servers = extract_mcp_server_names(mcp);
    }

    for (_, rule_path) in &rules_paths {
        if let Ok(meta) = fs::metadata(rule_path) {
            items_count += 1;
            total_bytes += meta.len();
        }
    }

    let path_hint = user_dir.as_ref().map(|p| mask_cursor_hint(p)).or_else(|| {
        mcp_json_path
            .as_ref()
            .map(|_| "~/.cursor/mcp.json".to_string())
    });

    CursorScanInfo {
        available: items_count > 0,
        path_hint,
        user_dir,
        mcp_json_path,
        rules_paths,
        items_count,
        total_bytes,
        mcp_servers,
    }
}

/// Exports Cursor IDE configs, snippets, `~/.cursor/mcp.json`, and `.cursorrules` into
/// `dst_cursor_dir`, strictly excluding `state.vscdb` and any auth tokens.
pub fn export_cursor_to(
    home_dir: &Path,
    claude_dir: &Path,
    dst_cursor_dir: &Path,
) -> Result<(usize, u64, Vec<String>), String> {
    let scan = scan_cursor_data(home_dir, claude_dir);
    if !scan.available {
        return Ok((0, 0, Vec::new()));
    }
    ensure_private_dir(dst_cursor_dir)?;

    let mut files_count = 0usize;
    let mut total_bytes = 0u64;

    if let Some(user_dir) = &scan.user_dir {
        let user_dst = dst_cursor_dir.join("User");
        ensure_private_dir(&user_dst)?;

        let settings_src = user_dir.join("settings.json");
        if settings_src.is_file() {
            total_bytes +=
                copy_sanitized_json_file(&settings_src, &user_dst.join("settings.json"))?;
            files_count += 1;
        }
        let keybindings_src = user_dir.join("keybindings.json");
        if keybindings_src.is_file() {
            total_bytes += copy_private_file(&keybindings_src, &user_dst.join("keybindings.json"))?;
            files_count += 1;
        }
        let snippets_src = user_dir.join("snippets");
        if snippets_src.is_dir() {
            let (cnt, bytes) =
                copy_private_dir_filtered(&snippets_src, &user_dst.join("snippets"))?;
            files_count += cnt;
            total_bytes += bytes;
        }
    }

    if let Some(mcp_src) = &scan.mcp_json_path {
        total_bytes += copy_sanitized_json_file(mcp_src, &dst_cursor_dir.join("mcp.json"))?;
        files_count += 1;
    }

    if !scan.rules_paths.is_empty() {
        let rules_dst = dst_cursor_dir.join("rules");
        ensure_private_dir(&rules_dst)?;
        for (label, rule_src) in &scan.rules_paths {
            let safe_name = format!("{}.cursorrules", sanitize_slug(label));
            total_bytes += copy_private_file(rule_src, &rules_dst.join(safe_name))?;
            files_count += 1;
        }
    }

    Ok((files_count, total_bytes, scan.mcp_servers))
}

fn collect_cursorrules_paths(home_dir: &Path, claude_dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let home_rules = home_dir.join(".cursorrules");
    if home_rules.is_file() && seen.insert(home_rules.clone()) {
        out.push(("global".to_string(), home_rules));
    }

    let projects_dir = claude_dir.join("projects");
    if projects_dir.is_dir()
        && let Ok(entries) = fs::read_dir(&projects_dir)
    {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let slug = entry.file_name().to_string_lossy().to_string();
            let decoded = decode_project_slug(&slug);
            let candidate = PathBuf::from(&decoded).join(".cursorrules");
            if candidate.is_file() && seen.insert(candidate.clone()) {
                out.push((slug, candidate));
            }
        }
    }
    out
}

fn count_safe_files(dir: &Path) -> (usize, u64) {
    let mut count = 0usize;
    let mut bytes = 0u64;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_excluded_secret_name(&name) {
                continue;
            }
            let p = entry.path();
            if p.is_dir() {
                let (c, b) = count_safe_files(&p);
                count += c;
                bytes += b;
            } else if p.is_file()
                && let Ok(meta) = fs::metadata(&p)
            {
                count += 1;
                bytes += meta.len();
            }
        }
    }
    (count, bytes)
}

fn sanitize_slug(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        "project".to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}

fn mask_cursor_hint(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(idx) = s.find("AppData") {
        return format!("~/{}", s[idx..].replace('\\', "/"));
    }
    if let Some(idx) = s.find("Library") {
        return format!("~/{}", &s[idx..]);
    }
    if let Some(idx) = s.find(".config") {
        return format!("~/{}", &s[idx..]);
    }
    "~/Cursor/User".to_string()
}
