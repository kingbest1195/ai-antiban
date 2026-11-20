//! Claude and ChatGPT `conversations.json` parsing and Markdown rendering for Web Export Helper.

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ParsedTurn {
    pub role: String,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct ParsedConversation {
    pub title: String,
    pub created_at: Option<String>,
    pub turns: Vec<ParsedTurn>,
}

pub fn parse_conversations(root: &Value) -> Result<(String, Vec<ParsedConversation>), String> {
    let items = root
        .as_array()
        .ok_or_else(|| "Ожидался JSON-массив диалогов в conversations.json.".to_string())?;

    let mut provider = "unknown".to_string();
    let mut out = Vec::with_capacity(items.len());

    for (idx, item) in items.iter().enumerate() {
        if item.get("chat_messages").is_some() {
            provider = "claude".to_string();
            out.push(parse_claude_conversation(item, idx));
        } else if item.get("mapping").is_some() {
            provider = "chatgpt".to_string();
            out.push(parse_chatgpt_conversation(item, idx));
        }
    }

    Ok((provider, out))
}

fn parse_claude_conversation(item: &Value, idx: usize) -> ParsedConversation {
    let title = item
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("Claude Conversation {}", idx + 1));
    let created_at = item
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    let mut turns = Vec::new();
    if let Some(msgs) = item.get("chat_messages").and_then(|v| v.as_array()) {
        for msg in msgs {
            let sender = msg
                .get("sender")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let role = match sender {
                "human" => "User",
                "assistant" => "Assistant",
                other => other,
            }
            .to_string();
            let text = extract_claude_message_text(msg);
            if !text.trim().is_empty() {
                turns.push(ParsedTurn { role, text });
            }
        }
    }

    ParsedConversation {
        title,
        created_at,
        turns,
    }
}

fn extract_claude_message_text(msg: &Value) -> String {
    if let Some(t) = msg.get("text").and_then(|v| v.as_str())
        && !t.trim().is_empty()
    {
        return t.to_string();
    }
    if let Some(parts) = msg.get("content").and_then(|v| v.as_array()) {
        let joined: Vec<&str> = parts
            .iter()
            .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
            .collect();
        if !joined.is_empty() {
            return joined.join("\n\n");
        }
    }
    String::new()
}

fn parse_chatgpt_conversation(item: &Value, idx: usize) -> ParsedConversation {
    let title = item
        .get("title")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("ChatGPT Conversation {}", idx + 1));
    let created_at = item
        .get("create_time")
        .and_then(|v| v.as_f64())
        .map(|ts| format!("{ts:.0}"));

    let mut turns = Vec::new();
    if let Some(mapping) = item.get("mapping").and_then(|v| v.as_object()) {
        for node_id in resolve_chatgpt_node_order(item, mapping) {
            let Some(msg) = mapping
                .get(&node_id)
                .and_then(|n| n.get("message"))
                .filter(|m| !m.is_null())
            else {
                continue;
            };
            let role_raw = msg
                .get("author")
                .and_then(|a| a.get("role"))
                .and_then(|r| r.as_str())
                .unwrap_or("unknown");
            if role_raw == "system" {
                continue;
            }
            let role = match role_raw {
                "user" => "User",
                "assistant" => "Assistant",
                other => other,
            }
            .to_string();
            let text = extract_chatgpt_message_text(msg);
            if !text.trim().is_empty() {
                turns.push(ParsedTurn { role, text });
            }
        }
    }

    ParsedConversation {
        title,
        created_at,
        turns,
    }
}

fn resolve_chatgpt_node_order(
    item: &Value,
    mapping: &serde_json::Map<String, Value>,
) -> Vec<String> {
    if let Some(mut cur) = item
        .get("current_node")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
    {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        while visited.insert(cur.clone()) {
            chain.push(cur.clone());
            let Some(parent) = mapping
                .get(&cur)
                .and_then(|n| n.get("parent"))
                .and_then(|p| p.as_str())
            else {
                break;
            };
            cur = parent.to_string();
        }
        chain.reverse();
        if !chain.is_empty() {
            return chain;
        }
    }

    let mut timed: Vec<(f64, String)> = mapping
        .iter()
        .map(|(k, v)| {
            let t = v
                .get("message")
                .and_then(|m| m.get("create_time"))
                .and_then(|c| c.as_f64())
                .unwrap_or(0.0);
            (t, k.clone())
        })
        .collect();
    timed.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    timed.into_iter().map(|(_, k)| k).collect()
}

fn extract_chatgpt_message_text(msg: &Value) -> String {
    let Some(content) = msg.get("content") else {
        return String::new();
    };
    if let Some(parts) = content.get("parts").and_then(|p| p.as_array()) {
        let texts: Vec<String> = parts
            .iter()
            .filter_map(|part| {
                part.as_str().map(ToString::to_string).or_else(|| {
                    part.get("text")
                        .and_then(|t| t.as_str())
                        .map(ToString::to_string)
                })
            })
            .collect();
        return texts.join("\n\n");
    }
    content
        .get("text")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn render_conversation_md(conv: &ParsedConversation, provider: &str) -> String {
    let mut out = format!("# {}\n\n- **Источник:** {provider}\n", conv.title);
    if let Some(ts) = &conv.created_at {
        out.push_str(&format!("- **Создан:** {ts}\n"));
    }
    out.push_str("\n---\n\n");
    for turn in &conv.turns {
        out.push_str(&format!("## {}\n\n{}\n\n", turn.role, turn.text.trim()));
    }
    out
}

pub fn build_web_restore_prompt(
    provider: &str,
    conversations: &[ParsedConversation],
    markdown_files: &[String],
) -> String {
    let mut md = format!(
        "# Контекст восстановления веб-сессий (Zastava Data Bunker)\n\nИсточник экспорта: **{provider}** · Всего диалогов: **{}**\n\n## Последние диалоги и темы\n\n",
        conversations.len()
    );
    for (idx, conv) in conversations.iter().take(10).enumerate() {
        let last_user = conv
            .turns
            .iter()
            .rev()
            .find(|t| t.role == "User")
            .map(|t| {
                t.text
                    .replace('\n', " ")
                    .chars()
                    .take(180)
                    .collect::<String>()
            })
            .unwrap_or_else(|| "нет пользовательского запроса".to_string());
        let file_hint = markdown_files
            .get(idx)
            .and_then(|p| Path::new(p).file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        md.push_str(&format!(
            "- **{}** (`{file_hint}`): {}\n",
            conv.title, last_user
        ));
    }
    md.push_str(
        "\n## Инструкция для нового аккаунта или Plan B (OpenRouter / Open WebUI)\n\n\
         1. Продолжи работу с пользователем, опираясь на темы и решения из перечисленных Markdown-файлов.\n\
         2. При необходимости попроси пользователя прикрепить нужный `.md` файл из папки экспорта.\n",
    );
    md
}
