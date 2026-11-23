//! Deterministic Zero-LLM context teleport formatters and secret redactor (Layer 0).

use serde::{Deserialize, Serialize};

pub use super::context_teleport_redact::redact_inline_secrets_counting;

pub const CHATGPT_BLOCK_CHAR_LIMIT: usize = 1500;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TeleportTarget {
    GeminiAntigravity,
    Cursor,
    Chatgpt,
    Universal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContextTeleportResult {
    pub target: TeleportTarget,
    pub output_dir: String,
    pub sources_used: Vec<String>,
    pub secrets_redacted_count: usize,
    pub primary_paste_text: String,
    pub files_written: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TeleportProjectInput {
    pub slug: String,
    pub decoded_path: String,
    pub sessions_count: usize,
    pub memory_md: Option<String>,
    pub last_query: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TeleportSourceInput {
    pub global_claude_md: Option<String>,
    pub projects: Vec<TeleportProjectInput>,
    pub plans: Vec<(String, String)>,
    pub mcp_servers: Vec<String>,
    pub cursor_rules: Vec<(String, String)>,
    pub web_summaries: Vec<(String, String)>,
    pub snapshot_root_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TeleportBundle {
    pub files: Vec<(String, String)>,
    pub primary_paste_text: String,
    pub secrets_redacted_count: usize,
}

fn sanitize_input(input: &TeleportSourceInput) -> (TeleportSourceInput, usize) {
    let mut total_redactions = 0usize;
    let mut clean_str = |s: &str| -> String {
        let (clean, n) = redact_inline_secrets_counting(s);
        total_redactions += n;
        clean
    };

    let global_claude_md = input.global_claude_md.as_deref().map(&mut clean_str);
    let projects = input
        .projects
        .iter()
        .map(|p| TeleportProjectInput {
            slug: clean_str(&p.slug),
            decoded_path: clean_str(&p.decoded_path),
            sessions_count: p.sessions_count,
            memory_md: p.memory_md.as_deref().map(&mut clean_str),
            last_query: p.last_query.as_deref().map(&mut clean_str),
        })
        .collect();
    let plans = input
        .plans
        .iter()
        .map(|(name, body)| (clean_str(name), clean_str(body)))
        .collect();
    let mcp_servers = input.mcp_servers.iter().map(|m| clean_str(m)).collect();
    let cursor_rules = input
        .cursor_rules
        .iter()
        .map(|(name, body)| (clean_str(name), clean_str(body)))
        .collect();
    let web_summaries = input
        .web_summaries
        .iter()
        .map(|(title, text)| (clean_str(title), clean_str(text)))
        .collect();

    (
        TeleportSourceInput {
            global_claude_md,
            projects,
            plans,
            mcp_servers,
            cursor_rules,
            web_summaries,
            snapshot_root_hint: input.snapshot_root_hint.clone(),
        },
        total_redactions,
    )
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    if max_chars <= 3 {
        return text.chars().take(max_chars).collect();
    }
    let prefix: String = text.chars().take(max_chars - 1).collect();
    format!("{prefix}…")
}

/// Formats sanitized local AI context into the requested `TeleportTarget` bundle without LLM calls.
pub fn format_teleport_bundle(
    target: TeleportTarget,
    raw_input: &TeleportSourceInput,
) -> TeleportBundle {
    let (input, secrets_redacted_count) = sanitize_input(raw_input);
    match target {
        TeleportTarget::GeminiAntigravity => format_gemini_bundle(&input, secrets_redacted_count),
        TeleportTarget::Cursor => format_cursor_bundle(&input, secrets_redacted_count),
        TeleportTarget::Chatgpt => format_chatgpt_bundle(&input, secrets_redacted_count),
        TeleportTarget::Universal => format_universal_bundle(&input, secrets_redacted_count),
    }
}

fn append_common_sections(md: &mut String, input: &TeleportSourceInput, max_snippet: usize) {
    if let Some(rules) = &input.global_claude_md
        && !rules.trim().is_empty()
    {
        md.push_str("## Global Rules\n\n");
        md.push_str(rules.trim());
        md.push_str("\n\n");
    }

    md.push_str("## Active Projects\n\n");
    if input.projects.is_empty() {
        md.push_str("_No local projects found._\n\n");
    } else {
        for proj in input.projects.iter().take(10) {
            let last_q = proj
                .last_query
                .as_deref()
                .map(|q| q.replace('\n', " "))
                .unwrap_or_else(|| "no saved query".to_string());
            md.push_str(&format!(
                "- `{}` (`{}` · sessions: {}): {}\n",
                proj.slug, proj.decoded_path, proj.sessions_count, last_q
            ));
            if let Some(mem) = &proj.memory_md
                && !mem.trim().is_empty()
            {
                let snippet = truncate_chars(mem.trim(), max_snippet);
                md.push_str(&format!("  - Memory: {}\n", snippet.replace('\n', " ")));
            }
        }
        md.push('\n');
    }

    if !input.plans.is_empty() {
        md.push_str("## Saved Plans\n\n");
        for (name, body) in input.plans.iter().take(8) {
            md.push_str(&format!(
                "- **{}**: {}\n",
                name,
                truncate_chars(body.trim(), 320).replace('\n', " ")
            ));
        }
        md.push('\n');
    }

    md.push_str("## MCP Servers (names only, secrets excluded)\n\n");
    if input.mcp_servers.is_empty() {
        md.push_str("- None configured.\n\n");
    } else {
        for srv in &input.mcp_servers {
            md.push_str(&format!("- `{srv}`\n"));
        }
        md.push('\n');
    }

    if !input.cursor_rules.is_empty() {
        md.push_str("## Cursor Rules\n\n");
        for (label, body) in input.cursor_rules.iter().take(6) {
            md.push_str(&format!(
                "### {label}\n\n{}\n\n",
                truncate_chars(body.trim(), 600)
            ));
        }
    }

    if !input.web_summaries.is_empty() {
        md.push_str("## Web Conversation Highlights\n\n");
        for (title, snippet) in input.web_summaries.iter().take(8) {
            md.push_str(&format!(
                "- **{}**: {}\n",
                title,
                truncate_chars(snippet.trim(), 220).replace('\n', " ")
            ));
        }
        md.push('\n');
    }
}

fn format_gemini_bundle(
    input: &TeleportSourceInput,
    secrets_redacted_count: usize,
) -> TeleportBundle {
    let mut gemini_md =
        String::from("# GEMINI.md — Project Context & Rules (Zastava Teleport)\n\n");
    append_common_sections(&mut gemini_md, input, 400);

    let mut sys = String::from(
        "You are a senior software architect continuing the user's existing workspace.\n\
         Respect all project conventions below and do not rewrite completed modules.\n\n",
    );
    if let Some(rules) = &input.global_claude_md
        && !rules.trim().is_empty()
    {
        sys.push_str("Project rules:\n");
        sys.push_str(&truncate_chars(rules.trim(), 1200));
        sys.push_str("\n\n");
    }
    if !input.projects.is_empty() {
        sys.push_str("Active projects:\n");
        for p in input.projects.iter().take(6) {
            sys.push_str(&format!(
                "- {} ({}): {}\n",
                p.slug,
                p.decoded_path,
                p.last_query.as_deref().unwrap_or("active")
            ));
        }
        sys.push('\n');
    }
    if !input.mcp_servers.is_empty() {
        sys.push_str(&format!(
            "MCP tools available (names only): {}\n",
            input.mcp_servers.join(", ")
        ));
    }

    TeleportBundle {
        primary_paste_text: gemini_md.clone(),
        files: vec![
            ("GEMINI.md".to_string(), gemini_md),
            ("SYSTEM_INSTRUCTIONS_GEMINI.txt".to_string(), sys),
        ],
        secrets_redacted_count,
    }
}

fn format_cursor_bundle(
    input: &TeleportSourceInput,
    secrets_redacted_count: usize,
) -> TeleportBundle {
    let mut mdc = String::from(
        "---\n\
         description: Migrated workspace context, memory, and rules from Zastava Bunker\n\
         globs:\n\
         alwaysApply: true\n\
         ---\n\n\
         # Migrated AI Workspace Context\n\n",
    );
    append_common_sections(&mut mdc, input, 400);
    TeleportBundle {
        primary_paste_text: mdc.clone(),
        files: vec![(".cursor/rules/migrated-context.mdc".to_string(), mdc)],
        secrets_redacted_count,
    }
}

/// Splits `CHATGPT_CUSTOM_INSTRUCTIONS.txt` into its 2 blocks for verification/UI display.
pub fn build_chatgpt_instruction_blocks(input: &TeleportSourceInput) -> (String, String) {
    let mut about = String::from("Workspace & Active Projects:\n");
    for p in input.projects.iter().take(6) {
        about.push_str(&format!("- {} ({})", p.slug, p.decoded_path));
        if let Some(q) = &p.last_query {
            about.push_str(&format!(": {}", truncate_chars(&q.replace('\n', " "), 120)));
        }
        about.push('\n');
        if let Some(mem) = &p.memory_md {
            about.push_str(&format!(
                "  Memory: {}\n",
                truncate_chars(&mem.replace('\n', " "), 160)
            ));
        }
    }
    if !input.mcp_servers.is_empty() {
        about.push_str(&format!("MCP servers: {}\n", input.mcp_servers.join(", ")));
    }
    if !input.web_summaries.is_empty() {
        about.push_str("Recent topics:\n");
        for (title, _) in input.web_summaries.iter().take(4) {
            about.push_str(&format!("- {title}\n"));
        }
    }

    let mut respond = String::from(
        "Act as a senior engineer continuing this workspace without rewriting working modules.\n",
    );
    if let Some(rules) = &input.global_claude_md
        && !rules.trim().is_empty()
    {
        respond.push_str("Follow these project rules:\n");
        respond.push_str(rules.trim());
        respond.push('\n');
    }
    for (label, body) in input.cursor_rules.iter().take(3) {
        respond.push_str(&format!("[{label}] {}\n", body.trim()));
    }

    (
        truncate_chars(about.trim(), CHATGPT_BLOCK_CHAR_LIMIT),
        truncate_chars(respond.trim(), CHATGPT_BLOCK_CHAR_LIMIT),
    )
}

fn format_chatgpt_bundle(
    input: &TeleportSourceInput,
    secrets_redacted_count: usize,
) -> TeleportBundle {
    let (raw_about, raw_respond) = build_chatgpt_instruction_blocks(input);
    let h1 = "=== Block 1: What would you like ChatGPT to know about you? ===\n";
    let h2 = "=== Block 2: How would you like ChatGPT to respond? ===\n";
    let b1_body = truncate_chars(
        &raw_about,
        CHATGPT_BLOCK_CHAR_LIMIT.saturating_sub(h1.chars().count()),
    );
    let b2_body = truncate_chars(
        &raw_respond,
        CHATGPT_BLOCK_CHAR_LIMIT.saturating_sub(h2.chars().count()),
    );
    let instructions = format!("{h1}{b1_body}\n\n{h2}{b2_body}\n");

    let mut seed =
        String::from("# MEMORY_SEED.md — Migrated Workspace Memory (Zastava Teleport)\n\n");
    append_common_sections(&mut seed, input, 600);

    TeleportBundle {
        primary_paste_text: instructions.clone(),
        files: vec![
            ("CHATGPT_CUSTOM_INSTRUCTIONS.txt".to_string(), instructions),
            ("MEMORY_SEED.md".to_string(), seed),
        ],
        secrets_redacted_count,
    }
}

fn format_universal_bundle(
    input: &TeleportSourceInput,
    secrets_redacted_count: usize,
) -> TeleportBundle {
    let mut md = String::from("# Контекст восстановления (Zastava Data Bunker)\n\n");
    md.push_str(
        "Ты — ведущий инженер-архитектор. Восстанови рабочий контекст пользователя и продолжай с места остановки без переписывания готовых модулей.\n\n",
    );
    if let Some(root) = &input.snapshot_root_hint {
        md.push_str(&format!("Корень снапшота: `{root}`\n\n"));
    }
    append_common_sections(&mut md, input, 450);
    md.push_str("Продолжи работу с последнего зафиксированного контекста сессии.\n");

    TeleportBundle {
        primary_paste_text: md.clone(),
        files: vec![("RESTORE_PROMPT.md".to_string(), md)],
        secrets_redacted_count,
    }
}

#[cfg(test)]
#[path = "context_teleport_tests.rs"]
mod tests;
