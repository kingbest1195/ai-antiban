//! Layer 2 Data Bunker Context Teleport collector and private-filesystem writer.
//!
//! Strictly read-only on source workspaces; NEVER reads `.credentials.json`, `Cookies`,
//! `state.vscdb`, `ant-device-registry.json`, or `ccd-ids.json`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::auditor::claude_exporter::{
    extract_last_user_query_from_jsonl, get_claude_desktop_config_path, scan_claude_dir,
};
use crate::core::context_teleport::{
    ContextTeleportResult, TeleportProjectInput, TeleportSourceInput, TeleportTarget,
    format_teleport_bundle,
};

use super::bunker_web_exports_dir;
use super::cursor_export::scan_cursor_data;
use super::sanitize::{
    ensure_private_dir, extract_mcp_server_names, is_excluded_secret_name, write_private_file,
};
use super::web_parsers::parse_conversations;

const MAX_TELEPORT_FILE_BYTES: u64 = 512 * 1024;

pub fn bunker_teleports_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("bunker").join("teleports")
}

/// Runs Zero-LLM context teleport for `target`. When `copy_only == Some(true)`, operates strictly
/// in memory without creating directories or writing files on disk.
pub fn run_context_teleport_in(
    app_data_dir: &Path,
    home_dir: &Path,
    target: TeleportTarget,
    destination_dir: Option<&Path>,
    copy_only: Option<bool>,
) -> Result<ContextTeleportResult, String> {
    let (input, sources_used) = collect_teleport_sources(app_data_dir, home_dir);
    let bundle = format_teleport_bundle(target, &input);

    if copy_only == Some(true) {
        return Ok(ContextTeleportResult {
            target,
            output_dir: String::new(),
            sources_used,
            secrets_redacted_count: bundle.secrets_redacted_count,
            primary_paste_text: bundle.primary_paste_text,
            files_written: Vec::new(),
        });
    }

    let target_dir = match destination_dir {
        Some(custom) => {
            ensure_private_dir(custom)?;
            custom.to_path_buf()
        }
        None => {
            let root = bunker_teleports_dir(app_data_dir);
            let (_id, dir) = super::allocate_timestamped_dir(&root)?;
            dir
        }
    };

    let mut files_written = Vec::with_capacity(bundle.files.len());
    for (rel_path, content) in &bundle.files {
        let out_path = target_dir.join(rel_path);
        write_private_file(&out_path, content.as_bytes())?;
        files_written.push(out_path.to_string_lossy().into_owned());
    }

    Ok(ContextTeleportResult {
        target,
        output_dir: target_dir.to_string_lossy().into_owned(),
        sources_used,
        secrets_redacted_count: bundle.secrets_redacted_count,
        primary_paste_text: bundle.primary_paste_text,
        files_written,
    })
}

fn read_safe_text(path: &Path) -> Option<String> {
    let name = path.file_name().and_then(|n| n.to_str())?;
    if is_excluded_secret_name(name) {
        return None;
    }
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_TELEPORT_FILE_BYTES {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn collect_teleport_sources(
    app_data_dir: &Path,
    home_dir: &Path,
) -> (TeleportSourceInput, Vec<String>) {
    let claude_dir = home_dir.join(".claude");
    let claude_scan = scan_claude_dir(&claude_dir, home_dir);
    let cursor_scan = scan_cursor_data(home_dir, &claude_dir);
    let desktop_cfg = get_claude_desktop_config_path(home_dir);

    let mut sources_used = Vec::new();
    let global_claude_md = read_safe_text(&claude_dir.join("CLAUDE.md"));
    let mut has_claude_code = global_claude_md.is_some();

    let mut projects = Vec::new();
    for proj in claude_scan.projects.iter().take(12) {
        let proj_dir = claude_dir.join("projects").join(&proj.slug);
        let memory_md = read_safe_text(&proj_dir.join("memory").join("MEMORY.md"));
        let last_query = find_latest_jsonl_query(&proj_dir);
        if memory_md.is_some() || last_query.is_some() || proj.sessions_count > 0 {
            has_claude_code = true;
        }
        projects.push(TeleportProjectInput {
            slug: proj.slug.clone(),
            decoded_path: proj.decoded_path.clone(),
            sessions_count: proj.sessions_count,
            memory_md,
            last_query,
        });
    }

    let mut plans = Vec::new();
    let plans_dir = claude_dir.join("plans");
    if plans_dir.is_dir()
        && let Ok(entries) = fs::read_dir(&plans_dir)
    {
        let mut plan_paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("md")))
            .collect();
        plan_paths.sort();
        for p in plan_paths.into_iter().take(8) {
            if let Some(body) = read_safe_text(&p) {
                let name = p
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                plans.push((name, body));
                has_claude_code = true;
            }
        }
    }
    if has_claude_code {
        sources_used.push("claude_code".to_string());
    }

    let mut mcp_set = BTreeSet::new();
    if let Some(cfg_path) = &desktop_cfg {
        let names = extract_mcp_server_names(cfg_path);
        if !names.is_empty() {
            sources_used.push("claude_desktop".to_string());
        }
        mcp_set.extend(names);
    }
    for name in &cursor_scan.mcp_servers {
        mcp_set.insert(name.clone());
    }

    let mut cursor_rules = Vec::new();
    for (label, rule_path) in &cursor_scan.rules_paths {
        if let Some(body) = read_safe_text(rule_path) {
            cursor_rules.push((label.clone(), body));
        }
    }
    if cursor_scan.available || !cursor_rules.is_empty() {
        sources_used.push("cursor".to_string());
    }

    let web_summaries = collect_web_summaries(&bunker_web_exports_dir(app_data_dir));
    if !web_summaries.is_empty() {
        sources_used.push("web_export".to_string());
    }

    (
        TeleportSourceInput {
            global_claude_md,
            projects,
            plans,
            mcp_servers: mcp_set.into_iter().collect(),
            cursor_rules,
            web_summaries,
            snapshot_root_hint: None,
        },
        sources_used,
    )
}

fn find_latest_jsonl_query(project_dir: &Path) -> Option<String> {
    let mut latest: Option<(u64, PathBuf)> = None;
    let entries = fs::read_dir(project_dir).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if is_excluded_secret_name(name) {
            continue;
        }
        if p.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
        {
            let mtime = fs::metadata(&p)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            if latest.as_ref().is_none_or(|(prev, _)| mtime >= *prev) {
                latest = Some((mtime, p));
            }
        }
    }
    latest.and_then(|(_, p)| extract_last_user_query_from_jsonl(&p))
}

fn collect_web_summaries(web_exports_dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if !web_exports_dir.is_dir() {
        return out;
    }
    let Ok(entries) = fs::read_dir(web_exports_dir) else {
        return out;
    };
    let mut dirs: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    dirs.sort();
    dirs.reverse();

    for dir in dirs.into_iter().take(2) {
        if dir.is_file()
            && dir.file_name().is_some_and(|n| n == "conversations.json")
            && let Some(raw) = read_safe_text(&dir)
            && let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw)
            && let Ok((_, convs)) = parse_conversations(&val)
        {
            for c in convs.into_iter().take(6) {
                let first = c
                    .turns
                    .iter()
                    .find(|t| t.role == "User")
                    .map(|t| t.text.clone())
                    .unwrap_or_default();
                out.push((c.title, first));
            }
            continue;
        }
        if !dir.is_dir() {
            continue;
        }
        let conv_json = dir.join("conversations.json");
        if conv_json.is_file()
            && let Some(raw) = read_safe_text(&conv_json)
            && let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw)
            && let Ok((_, convs)) = parse_conversations(&val)
        {
            for c in convs.into_iter().take(6) {
                let first = c
                    .turns
                    .iter()
                    .find(|t| t.role == "User")
                    .map(|t| t.text.clone())
                    .unwrap_or_default();
                out.push((c.title, first));
            }
        } else if let Ok(sub) = fs::read_dir(&dir) {
            let mut md_files: Vec<PathBuf> = sub
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|e| e.eq_ignore_ascii_case("md"))
                        && p.file_name().is_some_and(|n| n != "RESTORE_PROMPT.md")
                })
                .collect();
            md_files.sort();
            for mf in md_files.into_iter().take(6) {
                if let Some(body) = read_safe_text(&mf) {
                    let title = mf
                        .file_stem()
                        .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
                    out.push((title, body));
                }
            }
        }
    }
    out
}
