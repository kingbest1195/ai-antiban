//! Secret sanitization and private file/directory permission helpers (Layer 0).

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

const SECRET_EXACT_FILENAMES: &[&str] = &[
    ".credentials.json",
    "credentials.json",
    "cookies",
    "cookies-journal",
    "ant-device-registry.json",
    "ccd-ids.json",
    "dispatch-footprint-census.json",
    "state.vscdb",
    "state.vscdb.backup",
];

const SECRET_JSON_KEY_SUBSTRINGS: &[&str] = &[
    "oauth",
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "credential",
    "sessionkey",
    "session_key",
    "private_key",
    "auth_cookie",
    "bearer",
];

/// Ensures `dir` exists and has `0o700` permissions on Unix.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create directory {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Applies `0o600` permissions to an existing file on Unix (no-op on Windows).
pub fn restrict_file_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Writes `bytes` to `path` with `0o600` permissions on Unix.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("Failed to write bytes to {}: {e}", path.display()))?;
    restrict_file_to_owner(path);
    Ok(())
}

/// Copies a single file privately (`0o600` on Unix) and returns its byte size.
pub fn copy_private_file(src: &Path, dst: &Path) -> Result<u64, String> {
    if let Some(parent) = dst.parent() {
        ensure_private_dir(parent)?;
    }
    let mut input =
        File::open(src).map_err(|e| format!("Failed to open {}: {e}", src.display()))?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut output = opts
        .open(dst)
        .map_err(|e| format!("Failed to create {}: {e}", dst.display()))?;
    let bytes = std::io::copy(&mut input, &mut output)
        .map_err(|e| format!("Failed to copy {} -> {}: {e}", src.display(), dst.display()))?;
    restrict_file_to_owner(dst);
    Ok(bytes)
}

/// Returns `true` for credential/auth/session files that must NEVER enter a backup/export.
pub fn is_excluded_secret_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    if SECRET_EXACT_FILENAMES.contains(&lower.as_str()) {
        return true;
    }
    if lower == ".env"
        || lower.starts_with(".env.")
        || lower.starts_with(".credentials")
        || lower.starts_with("state.vscdb")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
    {
        return true;
    }
    matches!(
        lower.as_str(),
        "local storage" | "session storage" | "network" | "cache" | "code cache" | "gpucache"
    )
}

fn is_sensitive_json_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_JSON_KEY_SUBSTRINGS
        .iter()
        .any(|needle| lower.contains(needle))
}

const MAX_SANITIZED_TEXT_BYTES: u64 = 16 * 1024 * 1024;

fn is_prefix_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

fn is_bearer_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'/' | b'=')
}

fn is_word_boundary_before(bytes: &[u8], idx: usize) -> bool {
    idx == 0 || !(bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'_')
}

fn scan_token_end(bytes: &[u8], start: usize, pred: fn(u8) -> bool) -> usize {
    let mut end = start;
    while end < bytes.len() && pred(bytes[end]) {
        end += 1;
    }
    end
}

fn scan_env_value_end(bytes: &[u8], start: usize) -> usize {
    if start >= bytes.len() {
        return start;
    }
    if bytes[start] == b'"' || bytes[start] == b'\'' {
        let quote = bytes[start];
        let mut end = start + 1;
        while end < bytes.len() && bytes[end] != quote && bytes[end] != b'\n' && bytes[end] != b'\r'
        {
            end += 1;
        }
        if end < bytes.len() && bytes[end] == quote {
            end += 1;
        }
        return end;
    }
    let mut end = start;
    while end < bytes.len()
        && !bytes[end].is_ascii_whitespace()
        && !matches!(bytes[end], b'"' | b'\'' | b',' | b';' | b')' | b']' | b'}')
    {
        end += 1;
    }
    end
}

/// Redacts API keys, Bearer tokens, and env-var secret assignments embedded in arbitrary text.
pub fn redact_secrets_in_text(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        // 1. Env assignments: ANTHROPIC_API_KEY=... / OPENAI_API_KEY=...
        if is_word_boundary_before(bytes, i) {
            let env_prefix = ["ANTHROPIC_API_KEY=", "OPENAI_API_KEY="]
                .iter()
                .find(|p| bytes[i..].starts_with(p.as_bytes()));
            if let Some(prefix) = env_prefix {
                let val_start = i + prefix.len();
                let val_end = scan_env_value_end(bytes, val_start);
                if val_end > val_start {
                    out.push_str(&input[last..val_start]);
                    out.push_str("[REDACTED]");
                    last = val_end;
                    i = val_end;
                    continue;
                }
            }
        }

        // 2. Bearer <token> (case-insensitive)
        if is_word_boundary_before(bytes, i)
            && bytes.len().saturating_sub(i) > 7
            && bytes[i..i + 7].eq_ignore_ascii_case(b"bearer ")
        {
            let tok_start = i + 7;
            let tok_end = scan_token_end(bytes, tok_start, is_bearer_token_char);
            if tok_end - tok_start >= 8 {
                out.push_str(&input[last..tok_start]);
                out.push_str("[REDACTED]");
                last = tok_end;
                i = tok_end;
                continue;
            }
        }

        // 3. Known secret token prefixes
        if is_word_boundary_before(bytes, i) {
            let matched = [
                ("sk-ant-", 8usize),
                ("sk-proj-", 8usize),
                ("sk-or-v1-", 8usize),
                ("sk-", 20usize),
                ("xoxb-", 10usize),
                ("ghp_", 16usize),
                ("AIza", 20usize),
            ]
            .into_iter()
            .find(|(pfx, _)| bytes[i..].starts_with(pfx.as_bytes()));

            if let Some((pfx, min_tail)) = matched {
                let tail_start = i + pfx.len();
                let tok_end = scan_token_end(bytes, tail_start, is_prefix_token_char);
                if tok_end - tail_start >= min_tail {
                    out.push_str(&input[last..i]);
                    out.push_str("[REDACTED]");
                    last = tok_end;
                    i = tok_end;
                    continue;
                }
            }
        }

        // Advance by one UTF-8 character.
        let ch_len = input[i..].chars().next().map_or(1, char::len_utf8);
        i += ch_len;
    }

    if last == 0 {
        return input.to_string();
    }
    out.push_str(&input[last..]);
    out
}

/// Recursively redacts OAuth, API key, token, password, and credential values in JSON.
pub fn sanitize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_sensitive_json_key(k) {
                    *v = serde_json::Value::String("[REDACTED]".to_string());
                } else {
                    sanitize_json_value(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_json_value(item);
            }
        }
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.starts_with("sk-ant-")
                || trimmed.starts_with("sk-proj-")
                || trimmed.starts_with("sk-or-v1-")
                || (trimmed.starts_with("sk-") && trimmed.len() >= 24)
            {
                *s = "[REDACTED]".to_string();
            } else {
                let redacted = redact_secrets_in_text(s);
                if redacted != *s {
                    *s = redacted;
                }
            }
        }
        _ => {}
    }
}

/// Copies a JSON config file while redacting secret fields, falling back to redacted private copy if non-JSON.
pub fn copy_sanitized_json_file(src: &Path, dst: &Path) -> Result<u64, String> {
    let raw =
        fs::read_to_string(src).map_err(|e| format!("Failed to read {}: {e}", src.display()))?;
    if let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
        sanitize_json_value(&mut parsed);
        let serialized = serde_json::to_vec_pretty(&parsed)
            .map_err(|e| format!("Failed to serialize sanitized JSON {}: {e}", dst.display()))?;
        write_private_file(dst, &serialized)?;
        return Ok(serialized.len() as u64);
    }
    let redacted = redact_secrets_in_text(&raw);
    write_private_file(dst, redacted.as_bytes())?;
    Ok(redacted.len() as u64)
}

fn is_sanitized_text_ext(lower_name: &str) -> bool {
    [".jsonl", ".md", ".txt", ".toml", ".yaml", ".yml"]
        .iter()
        .any(|ext| lower_name.ends_with(ext))
}

/// Copies a text/JSONL file while redacting secret keys/tokens; skips sanitization for huge/binary files.
pub fn copy_sanitized_text_file(src: &Path, dst: &Path, is_jsonl: bool) -> Result<u64, String> {
    let size = fs::metadata(src).map(|m| m.len()).unwrap_or(0);
    if size > MAX_SANITIZED_TEXT_BYTES {
        return copy_private_file(src, dst);
    }
    let Ok(raw) = fs::read_to_string(src) else {
        return copy_private_file(src, dst);
    };
    let sanitized = if is_jsonl {
        let mut out = String::with_capacity(raw.len());
        for (idx, line) in raw.lines().enumerate() {
            if idx > 0 {
                out.push('\n');
            }
            if let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(line) {
                sanitize_json_value(&mut parsed);
                if let Ok(s) = serde_json::to_string(&parsed) {
                    out.push_str(&s);
                    continue;
                }
            }
            out.push_str(&redact_secrets_in_text(line));
        }
        if raw.ends_with('\n') {
            out.push('\n');
        }
        out
    } else {
        redact_secrets_in_text(&raw)
    };
    write_private_file(dst, sanitized.as_bytes())?;
    Ok(sanitized.len() as u64)
}

/// Recursively copies a directory tree privately (`0o700` dirs / `0o600` files), skipping any
/// entry whose filename matches `is_excluded_secret_name`.
pub fn copy_private_dir_filtered(src: &Path, dst: &Path) -> Result<(usize, u64), String> {
    ensure_private_dir(dst)?;
    let mut files_count = 0usize;
    let mut total_bytes = 0u64;

    let entries =
        fs::read_dir(src).map_err(|e| format!("Failed to read {}: {e}", src.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if is_excluded_secret_name(&name) {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let (sub_files, sub_bytes) = copy_private_dir_filtered(&from, &to)?;
            files_count += sub_files;
            total_bytes += sub_bytes;
        } else if ft.is_file() {
            let lower_name = name.to_ascii_lowercase();
            let bytes = if lower_name.ends_with(".json") {
                copy_sanitized_json_file(&from, &to)?
            } else if is_sanitized_text_ext(&lower_name) {
                copy_sanitized_text_file(&from, &to, lower_name.ends_with(".jsonl"))?
            } else {
                copy_private_file(&from, &to)?
            };
            files_count += 1;
            total_bytes += bytes;
        }
    }

    Ok((files_count, total_bytes))
}

#[cfg(test)]
#[path = "sanitize_tests.rs"]
mod tests;
