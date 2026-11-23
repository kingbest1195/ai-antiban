//! Secret redaction and redaction counting for Context Teleport (Layer 0).

use super::sanitize::redact_secrets_in_text;

/// Redacts inline secrets (`sk-ant-*`, `sk-*`, `AIza*`, `ghp_*`, `xoxb-*`, bearer/oauth/token/password)
/// on top of `core::sanitize::redact_secrets_in_text` and returns `(sanitized, redactions_count)`.
pub fn redact_inline_secrets_counting(input: &str) -> (String, usize) {
    if input.is_empty() {
        return (String::new(), 0);
    }
    let existing_markers = input.matches("[REDACTED]").count();
    let pass1 = redact_secrets_in_text(input);
    let mut count = pass1
        .matches("[REDACTED]")
        .count()
        .saturating_sub(existing_markers);

    let (pass2, extra_prefixes) = redact_extra_prefixes(&pass1);
    count += extra_prefixes;

    let (pass3, extra_kv) = redact_sensitive_kv_assignments(&pass2);
    count += extra_kv;

    (pass3, count)
}

fn redact_extra_prefixes(input: &str) -> (String, usize) {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut i = 0usize;
    let mut count = 0usize;

    while i < bytes.len() {
        let before_ok = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if before_ok
            && bytes.len().saturating_sub(i) > 7
            && bytes[i..i + 7].eq_ignore_ascii_case(b"bearer ")
        {
            let tok_start = i + 7;
            let mut tok_end = tok_start;
            while tok_end < bytes.len()
                && (bytes[tok_end].is_ascii_alphanumeric()
                    || matches!(bytes[tok_end], b'_' | b'-' | b'.' | b'+' | b'/' | b'='))
            {
                tok_end += 1;
            }
            if tok_end > tok_start
                && !bytes[tok_start..tok_end].starts_with(b"[REDACTED]")
                && tok_end - tok_start >= 4
            {
                out.push_str(&input[last..tok_start]);
                out.push_str("[REDACTED]");
                count += 1;
                last = tok_end;
                i = tok_end;
                continue;
            }
        }
        if before_ok {
            let matched = [
                ("sk-ant-", 4usize),
                ("sk-proj-", 4usize),
                ("sk-or-v1-", 4usize),
                ("sk-", 10usize),
                ("AIza", 10usize),
                ("ghp_", 8usize),
                ("xoxb-", 6usize),
            ]
            .into_iter()
            .find(|(pfx, _)| bytes[i..].starts_with(pfx.as_bytes()));
            if let Some((pfx, min_tail)) = matched {
                let mut end = i + pfx.len();
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric()
                        || matches!(bytes[end], b'_' | b'-' | b'.'))
                {
                    end += 1;
                }
                if end - (i + pfx.len()) >= min_tail {
                    out.push_str(&input[last..i]);
                    out.push_str("[REDACTED]");
                    count += 1;
                    last = end;
                    i = end;
                    continue;
                }
            }
        }
        i += input[i..].chars().next().map_or(1, char::len_utf8);
    }

    if last == 0 {
        return (input.to_string(), 0);
    }
    out.push_str(&input[last..]);
    (out, count)
}

fn redact_sensitive_kv_assignments(input: &str) -> (String, usize) {
    const KEYS: &[&str] = &[
        "anthropic_api_key",
        "openai_api_key",
        "gemini_api_key",
        "google_api_key",
        "private_key",
        "access_token",
        "refresh_token",
        "oauth_token",
        "session_key",
        "api_key",
        "apikey",
        "password",
        "passwd",
        "secret",
        "oauth",
        "token",
    ];
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut i = 0usize;
    let mut count = 0usize;

    while i < bytes.len() {
        let before_ok = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if before_ok
            && let Some(key) = KEYS.iter().find(|k| {
                bytes.len() - i >= k.len()
                    && bytes[i..i + k.len()].eq_ignore_ascii_case(k.as_bytes())
            })
        {
            let after_key = i + key.len();
            let mut pos = after_key;
            if pos < bytes.len() && (bytes[pos] == b'"' || bytes[pos] == b'\'') {
                pos += 1;
            }
            while pos < bytes.len() && bytes[pos] == b' ' {
                pos += 1;
            }
            if pos < bytes.len() && (bytes[pos] == b'=' || bytes[pos] == b':') {
                let sep_pos = pos;
                pos += 1;
                while pos < bytes.len() && bytes[pos] == b' ' {
                    pos += 1;
                }
                if pos < bytes.len() && (bytes[pos] == b'"' || bytes[pos] == b'\'') {
                    let quote = bytes[pos];
                    let val_start = pos + 1;
                    let mut val_end = val_start;
                    while val_end < bytes.len()
                        && bytes[val_end] != quote
                        && bytes[val_end] != b'\n'
                        && bytes[val_end] != b'\r'
                    {
                        val_end += 1;
                    }
                    let val = &input[val_start..val_end];
                    if !val.trim().is_empty() && !val.contains("[REDACTED]") {
                        out.push_str(&input[last..val_start]);
                        out.push_str("[REDACTED]");
                        count += 1;
                        last = val_end;
                        i = val_end;
                        continue;
                    }
                } else if pos < bytes.len()
                    && !matches!(bytes[pos], b'\n' | b'\r' | b'{' | b'[' | b'`')
                {
                    let val_start = pos;
                    let mut val_end = val_start;
                    while val_end < bytes.len()
                        && !bytes[val_end].is_ascii_whitespace()
                        && !matches!(bytes[val_end], b',' | b';' | b')' | b']' | b'}' | b'`')
                    {
                        val_end += 1;
                    }
                    let val = &input[val_start..val_end];
                    if val.len() >= 4
                        && !val.contains("[REDACTED]")
                        && !(bytes[sep_pos] == b':' && val.chars().all(|c| c.is_ascii_digit()))
                    {
                        out.push_str(&input[last..val_start]);
                        out.push_str("[REDACTED]");
                        count += 1;
                        last = val_end;
                        i = val_end;
                        continue;
                    }
                }
            }
        }
        i += input[i..].chars().next().map_or(1, char::len_utf8);
    }

    if last == 0 {
        return (input.to_string(), 0);
    }
    out.push_str(&input[last..]);
    (out, count)
}
