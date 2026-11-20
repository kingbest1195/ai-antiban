//! RESTORE_PROMPT.md generator for Zastava Data Bunker (Claude Code + Cursor IDE + MCP).

use std::fs;
use std::path::{Path, PathBuf};

use crate::auditor::claude_exporter::{
    extract_last_user_query_from_jsonl, get_claude_desktop_config_path, scan_claude_dir,
};

use super::cursor_export::scan_cursor_data;
use super::sanitize::extract_mcp_server_names;

/// Builds `RESTORE_PROMPT.md` including Claude Code projects + last session context,
/// Claude Desktop MCP servers, Cursor IDE settings + MCP servers, and `.cursorrules`.
pub fn build_restore_prompt_md(
    home_dir: &Path,
    claude_dir: &Path,
    snapshot_dir: Option<&Path>,
) -> String {
    let claude_scan = scan_claude_dir(claude_dir, home_dir);
    let cursor_scan = scan_cursor_data(home_dir, claude_dir);
    let desktop_mcps = get_claude_desktop_config_path(home_dir)
        .map(|p| extract_mcp_server_names(&p))
        .unwrap_or_default();

    let mut md = String::new();
    md.push_str("# Контекст восстановления (Zastava Data Bunker)\n\n");
    md.push_str(
        "Ты — ведущий инженер-архитектор. Восстанови рабочий контекст пользователя и продолжай с места остановки без переписывания готовых модулей.\n\n",
    );
    if let Some(dir) = snapshot_dir {
        md.push_str(&format!("Корень снапшота: `{}`\n\n", dir.display()));
    }

    md.push_str("## Активные проекты Claude Code\n\n");
    if claude_scan.projects.is_empty() {
        md.push_str("_Проекты Claude Code не обнаружены._\n\n");
    } else {
        for proj in claude_scan.projects.iter().take(8) {
            let last_q = find_latest_project_query(&claude_dir.join("projects").join(&proj.slug))
                .unwrap_or_else(|| "нет сохранённого последнего запроса".to_string());
            md.push_str(&format!(
                "- `{}` (`{}` · сессий: {}, память: {}): {}\n",
                proj.slug,
                proj.decoded_path,
                proj.sessions_count,
                if proj.has_memory {
                    "MEMORY.md"
                } else {
                    "нет"
                },
                last_q.replace('\n', " ")
            ));
        }
        md.push('\n');
    }

    md.push_str("## Конфигурация Cursor IDE и MCP\n\n");
    if cursor_scan.available {
        md.push_str(&format!(
            "- Настройки Cursor IDE: `{}` (файлов: {})\n",
            cursor_scan.path_hint.as_deref().unwrap_or("~/.cursor"),
            cursor_scan.items_count
        ));
    } else {
        md.push_str("- Настройки Cursor IDE не найдены.\n");
    }
    if !cursor_scan.mcp_servers.is_empty() {
        md.push_str(&format!(
            "- Cursor MCP-серверы (`~/.cursor/mcp.json`): {}\n",
            cursor_scan.mcp_servers.join(", ")
        ));
    }
    if !desktop_mcps.is_empty() {
        md.push_str(&format!(
            "- Claude Desktop MCP-серверы (`claude_desktop_config.json`): {}\n",
            desktop_mcps.join(", ")
        ));
    }
    if !cursor_scan.rules_paths.is_empty() {
        let names: Vec<&str> = cursor_scan
            .rules_paths
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        md.push_str(&format!("- Правила `.cursorrules`: {}\n", names.join(", ")));
    }
    md.push_str("\nПродолжи работу с последнего зафиксированного контекста сессии.\n");
    md
}

fn find_latest_project_query(project_dir: &Path) -> Option<String> {
    let mut latest: Option<(u64, PathBuf)> = None;
    let entries = fs::read_dir(project_dir).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
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
