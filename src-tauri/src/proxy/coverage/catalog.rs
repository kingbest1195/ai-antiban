// Catalog & process classification

pub struct KnownAppInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
}

pub fn get_known_app_info(id: &str) -> Option<KnownAppInfo> {
    let (id, name, category) = match id {
        "browsers" => (
            "browsers",
            "Браузеры (Chrome, Safari, Arc, Edge...)",
            "browser",
        ),
        "claude-desktop" => ("claude-desktop", "Claude Desktop", "desktop"),
        "chatgpt-desktop" => ("chatgpt-desktop", "ChatGPT Desktop", "desktop"),
        "antigravity" => ("antigravity", "Antigravity", "ide"),
        "cursor" => ("cursor", "Cursor", "ide"),
        "vscode" => ("vscode", "VS Code", "ide"),
        "windsurf" => ("windsurf", "Windsurf", "ide"),
        "jetbrains" => ("jetbrains", "JetBrains IDE (PyCharm, IntelliJ...)", "ide"),
        "claude-code" => ("claude-code", "Claude Code", "cli"),
        "gemini-cli" => ("gemini-cli", "Gemini CLI", "cli"),
        "opencode" => ("opencode", "OpenCode", "cli"),
        "node-cli" => ("node-cli", "Node.js / CLI", "cli"),
        "python-cli" => ("python-cli", "Python / CLI", "cli"),
        "curl" => ("curl", "curl", "cli"),
        _ => return None,
    };
    Some(KnownAppInfo { id, name, category })
}

/// Splits a process name into lower-case words (non-alphanumeric characters separate words;
/// trailing digits of a word are dropped: `idea64` -> `idea`).
fn name_words(lower: &str) -> Vec<String> {
    lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| {
            let t = w.trim_end_matches(|c: char| c.is_ascii_digit());
            if t.is_empty() { w } else { t }.to_string()
        })
        .collect()
}

/// Normalizes raw OS process names to canonical Zastava app identifiers. Names are compared as
/// whole words / exact binary names, never as substrings (`provider` is not `rider`,
/// `knowledge` is not `edge`).
pub fn classify_process_name(name: &str) -> &'static str {
    let lower_buf = name.to_lowercase();
    let lower = lower_buf.trim().trim_end_matches(".exe");
    let words = name_words(lower);
    let has = |w: &str| words.iter().any(|x| x == w);
    let first = words.first().map(String::as_str).unwrap_or("");

    if lower.contains("claude-code") || lower.contains("claude_code") {
        return "claude-code";
    }
    if first == "claude" {
        return "claude-desktop";
    }
    if has("chatgpt") && !has("atlas") {
        return "chatgpt-desktop";
    }
    if has("antigravity") {
        return "antigravity";
    }
    if has("cursor") {
        return "cursor";
    }
    if first == "code"
        || has("vscode")
        || has("vscodium")
        || (has("visual") && has("studio") && has("code"))
    {
        return "vscode";
    }
    if has("windsurf") {
        return "windsurf";
    }
    if has("chrome")
        || has("chromium")
        || has("safari")
        || has("firefox")
        || has("brave")
        || has("msedge")
        || has("edge")
        || has("arc")
        || has("vivaldi")
        || has("opera")
        || has("comet")
        || has("dia")
        || has("atlas")
        || has("zen")
        || has("waterfox")
        || words
            .iter()
            .any(|w| w.starts_with("yandex") || w.starts_with("яндекс"))
    {
        return "browsers";
    }
    const JETBRAINS_WORDS: [&str; 11] = [
        "idea", "pycharm", "webstorm", "datagrip", "clion", "rider", "goland", "rubymine",
        "phpstorm", "fleet", "appcode",
    ];
    if JETBRAINS_WORDS.iter().any(|w| has(w))
        || (has("android") && has("studio"))
        || lower == "studio64"
    {
        return "jetbrains";
    }
    if lower == "gemini" || lower.contains("gemini-cli") {
        return "gemini-cli";
    }
    if has("opencode") {
        return "opencode";
    }
    if lower == "node" || lower.starts_with("node ") {
        return "node-cli";
    }
    if first == "python" {
        return "python-cli";
    }
    if lower == "curl" {
        return "curl";
    }

    "other"
}

/// Resolves an app identifier, human-readable name, and category from process info.
pub fn resolve_app_identity(
    raw_process_name: &str,
    user_agent: Option<&str>,
) -> (String, String, String) {
    if let Some(ua) = user_agent {
        let ua_lower = ua.to_lowercase();
        if ua_lower.starts_with("curl/") {
            return ("curl".to_string(), "curl".to_string(), "cli".to_string());
        }
        if ua_lower.contains("claude-code") {
            return (
                "claude-code".to_string(),
                "Claude Code".to_string(),
                "cli".to_string(),
            );
        }
    }

    let classified = classify_process_name(raw_process_name);
    if classified != "other"
        && let Some(info) = get_known_app_info(classified)
    {
        return (
            info.id.to_string(),
            info.name.to_string(),
            info.category.to_string(),
        );
    }

    let clean_id = raw_process_name
        .to_lowercase()
        .replace([' ', '_', '/'], "-");
    (clean_id, raw_process_name.to_string(), "cli".to_string())
}
