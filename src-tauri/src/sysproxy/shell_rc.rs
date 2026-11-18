//! Shell profile blocks (zsh/bash RC files and PowerShell `$PROFILE`): building, upserting and removing
//! the Zastava guard block that exports proxy / timezone / locale variables.

use super::{FileCtx, NO_PROXY_VALUE, ZASTAVA_RC_END, ZASTAVA_RC_START, is_known_no_proxy_value};
use std::ops::Range;
use std::path::{Path, PathBuf};

pub(super) fn normalize_proxy_url_and_port(proxy_addr_or_url: &str) -> (String, u16) {
    let trimmed = proxy_addr_or_url
        .trim()
        .trim_end_matches("/proxy.pac")
        .trim_end_matches('/');
    let url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let port = trimmed
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(8899);
    (url, port)
}

/// Builds the shell RC block that enables proxy variables in new terminals ONLY when
/// Zastava is actively listening on `127.0.0.1:<port>`. If Zastava is closed, `nc -z`
/// exits immediately and the terminal works directly without proxy errors.
pub fn build_shell_rc_guard_block(proxy_url: &str, port: u16) -> String {
    build_shell_rc_guard_block_with_tz(proxy_url, port, None)
}

/// Validates and sanitizes a timezone identifier string.
/// Returns Some(sanitized) if valid (non-empty, len <= 64, ASCII alphanumeric + '/' | '_' | '-' | '+').
pub fn sanitize_timezone(tz: &str) -> Option<String> {
    let trimmed = tz.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    if trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+'))
    {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// The safe locale: the only values Zastava puts next to `TZ`. `LC_ALL` is never exported (it
/// overrides every other `LC_*` and breaks Ruby / Homebrew and build scripts).
pub(super) const SAFE_LOCALE: &str = "en_US.UTF-8";

/// Builds the shell RC block including optional timezone and clean UTF-8 locale sync.
pub fn build_shell_rc_guard_block_with_tz(proxy_url: &str, port: u16, tz: Option<&str>) -> String {
    build_shell_block(port, Some(proxy_url), tz)
}

/// The shell block with independent parts: the proxy variables (`proxy_url`) and the time zone /
/// locale variables (`tz`: `TZ`, `LANG`, `LC_TIME`). Both are exported only while Zastava listens
/// on `127.0.0.1:<port>`; with neither part the guard is empty (callers do not write such a block).
pub(super) fn build_shell_block(port: u16, proxy_url: Option<&str>, tz: Option<&str>) -> String {
    let mut exports = String::new();
    if let Some(url) = proxy_url {
        for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
            exports.push_str(&format!("\n  export {name}=\"{url}\""));
        }
        for name in ["http_proxy", "https_proxy", "all_proxy"] {
            exports.push_str(&format!("\n  export {name}=\"{url}\""));
        }
        exports.push_str(&format!("\n  export NO_PROXY=\"{NO_PROXY_VALUE}\""));
        exports.push_str(&format!("\n  export no_proxy=\"{NO_PROXY_VALUE}\""));
    }
    if let Some(timezone) = tz.and_then(sanitize_timezone) {
        exports.push_str(&format!(
            "\n  export TZ=\"{timezone}\"\n  export LANG=\"{SAFE_LOCALE}\"\n  export LC_TIME=\"{SAFE_LOCALE}\""
        ));
    }
    format!(
        "{ZASTAVA_RC_START}\nif command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 {port} >/dev/null 2>&1; then{exports}\nfi\n{ZASTAVA_RC_END}"
    )
}

/// Builds the PowerShell profile block with proxy settings and optional timezone/locale.
/// Wraps proxy assignments inside a zero-latency kernel TCP listener check so PowerShell never hangs
/// or fails when Zastava is closed or uninstalled. When Zastava is down the block sets nothing and removes nothing.
pub fn build_powershell_guard_block_with_tz(proxy_url: &str, tz: Option<&str>) -> String {
    let (url, port) = normalize_proxy_url_and_port(proxy_url);
    build_powershell_block(port, Some(&url), tz)
}

/// The PowerShell block with independent parts (see [`build_shell_block`]); `TZ`, `LANG` and
/// `LC_TIME` are written only together with a time zone.
pub(super) fn build_powershell_block(
    port: u16,
    proxy_url: Option<&str>,
    tz: Option<&str>,
) -> String {
    let mut assignments = String::new();
    if let Some(url) = proxy_url {
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assignments.push_str(&format!("\n  $env:{name} = \"{url}\""));
        }
        assignments.push_str(&format!("\n  $env:NO_PROXY = \"{NO_PROXY_VALUE}\""));
        assignments.push_str(&format!("\n  $env:no_proxy = \"{NO_PROXY_VALUE}\""));
    }
    if let Some(timezone) = tz.and_then(sanitize_timezone) {
        assignments.push_str(&format!(
            "\n  $env:TZ = \"{timezone}\"\n  $env:LANG = \"{SAFE_LOCALE}\"\n  $env:LC_TIME = \"{SAFE_LOCALE}\""
        ));
    }
    format!(
        "{ZASTAVA_RC_START}\n$__zastavaUp = $false\ntry {{\n  $__zastavaUp = [bool]([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object {{ $_.Port -eq {port} }})\n}} catch {{}}\nif ($__zastavaUp) {{{assignments}\n}}\n{ZASTAVA_RC_END}"
    )
}

/// The profile text cannot be edited safely: partial or repeated markers, a marker that is not on
/// a line of its own, or the end marker before the start marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BlockAmbiguous;

/// Locates the Zastava block: from the first byte of the start marker line to the last byte of
/// the end marker (line end not included). The markers must be whole lines; any other occurrence
/// of the marker text, a missing partner or a wrong order is [`BlockAmbiguous`]. `Ok(None)`: the
/// file has no block at all.
pub(super) fn find_block(text: &str) -> Result<Option<Range<usize>>, BlockAmbiguous> {
    let mut starts = Vec::new();
    let mut ends = Vec::new();
    let mut pos = 0usize;
    for raw in text.split_inclusive('\n') {
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let body = if pos == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        let skip = line.len() - body.len();
        if body == ZASTAVA_RC_START {
            starts.push(pos + skip);
        } else if body == ZASTAVA_RC_END {
            ends.push(pos + line.len());
        }
        pos += raw.len();
    }
    if text.matches(ZASTAVA_RC_START).count() != starts.len()
        || text.matches(ZASTAVA_RC_END).count() != ends.len()
    {
        return Err(BlockAmbiguous);
    }
    match (starts.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([s], [e]) if s < e => Ok(Some(*s..*e)),
        _ => Err(BlockAmbiguous),
    }
}

fn detect_eol(text: &str) -> &'static str {
    match text.find('\n') {
        Some(i) if i > 0 && text.as_bytes()[i - 1] == b'\r' => "\r\n",
        _ => "\n",
    }
}

/// Puts `block` (lines separated by `\n`) into the profile: in place of the existing block, or
/// appended after a blank line. Every other byte of `text` stays as it is; the new lines use the
/// line ending of the file.
pub(super) fn upsert_block(text: &str, block: &str) -> Result<String, BlockAmbiguous> {
    let eol = detect_eol(text);
    let block = block.replace("\r\n", "\n").replace('\n', eol);
    if let Some(r) = find_block(text)? {
        return Ok(format!("{}{}{}", &text[..r.start], block, &text[r.end..]));
    }
    let mut out = text.to_string();
    // A profile whose last line has no line end keeps it that way: our block becomes the last
    // line without one, which is how `remove_block` knows to take the separator away again.
    let mut last_line_open = false;
    if !text.trim_start_matches('\u{feff}').is_empty() {
        if !out.ends_with('\n') {
            out.push_str(eol);
            last_line_open = true;
        }
        out.push_str(eol); // the blank line that separates our block from the user's text
    }
    out.push_str(&block);
    if !last_line_open {
        out.push_str(eol);
    }
    Ok(out)
}

/// Removes the block, the line end after it and the blank line that was put before it. The
/// text around is untouched; a profile without a block is returned unchanged.
pub(super) fn remove_block(text: &str) -> Result<String, BlockAmbiguous> {
    let Some(r) = find_block(text)? else {
        return Ok(text.to_string());
    };
    let (mut start, mut end) = (r.start, r.end);
    // The block is the last line of the file and has no line end: `upsert_block` wrote it so
    // after a profile that did not end with a line end, and that line end goes with it.
    let open_last_line = end == text.len();
    if text[end..].starts_with("\r\n") {
        end += 2;
    } else if text[end..].starts_with('\n') {
        end += 1;
    }
    let before = &text[..start];
    let content_before = before.trim_start_matches('\u{feff}');
    if content_before.ends_with("\r\n\r\n") {
        start -= if open_last_line { 4 } else { 2 };
    } else if content_before.ends_with("\n\n") {
        start -= if open_last_line { 2 } else { 1 };
    }
    Ok(format!("{}{}", &text[..start], &text[end..]))
}

/// The exact line an old build put into the `else` branch of the PowerShell block.
const OLD_POWERSHELL_ELSE_LINE: &str = "Remove-Item Env:HTTP_PROXY,Env:HTTPS_PROXY,Env:ALL_PROXY,Env:http_proxy,Env:https_proxy,Env:all_proxy,Env:TZ,Env:LANG,Env:LC_TIME,Env:LC_ALL -ErrorAction SilentlyContinue";

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

fn assignment_is_generated(name: &str, value: &str) -> bool {
    match name {
        "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "http_proxy" | "https_proxy" | "all_proxy" => {
            value
                .strip_prefix("http://127.0.0.1:")
                .or_else(|| value.strip_prefix("http://localhost:"))
                .is_some_and(all_digits)
        }
        "NO_PROXY" | "no_proxy" => is_known_no_proxy_value(value),
        "TZ" => sanitize_timezone(value).as_deref() == Some(value),
        "LANG" | "LC_TIME" | "LC_ALL" => value == "en_US.UTF-8",
        _ => false,
    }
}

fn quoted(s: &str) -> Option<&str> {
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains(['"', '$', '`', '\\'])).then_some(inner)
}

fn line_is_generated(line: &str) -> bool {
    let t = line.trim();
    if matches!(
        t,
        "" | "fi"
            | "try {"
            | "} catch {}"
            | "if ($__zastavaUp) {"
            | "}"
            | "} else {"
            | "$__zastavaUp = $false"
            | OLD_POWERSHELL_ELSE_LINE
    ) {
        return true;
    }
    if let Some(rest) = t.strip_prefix("if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 ") {
        return rest
            .strip_suffix(" >/dev/null 2>&1; then")
            .is_some_and(all_digits);
    }
    if let Some(rest) = t.strip_prefix("$__zastavaUp = [bool]([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object { $_.Port -eq ") {
        return rest.strip_suffix(" })").is_some_and(all_digits);
    }
    if let Some(rest) = t.strip_prefix("export ") {
        return rest
            .split_once('=')
            .and_then(|(n, v)| quoted(v).map(|v| (n, v)))
            .is_some_and(|(n, v)| assignment_is_generated(n, v));
    }
    if let Some(rest) = t.strip_prefix("$env:") {
        return rest
            .split_once(" = ")
            .and_then(|(n, v)| quoted(v).map(|v| (n, v)))
            .is_some_and(|(n, v)| assignment_is_generated(n, v));
    }
    false
}

/// Whether `block` (as returned by `find_block`) consists only of lines a Zastava build writes,
/// with values that carry the Zastava gateway signature. A block the user edited, or anything
/// else, is not "generated" and is never removed without a journal record.
pub(super) fn is_generated_block(block: &str) -> bool {
    let lines: Vec<&str> = block
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    let (Some(first), Some(last)) = (lines.first(), lines.last()) else {
        return false;
    };
    lines.len() >= 2
        && *first == ZASTAVA_RC_START
        && *last == ZASTAVA_RC_END
        && lines[1..lines.len() - 1]
            .iter()
            .all(|l| line_is_generated(l))
}

/// PowerShell profiles of a user with the given home directory (Windows PowerShell and
/// PowerShell 7).
pub fn powershell_profile_paths(home: &Path) -> Vec<PathBuf> {
    let docs = home.join("Documents");
    vec![
        docs.join("PowerShell")
            .join("Microsoft.PowerShell_profile.ps1"),
        docs.join("WindowsPowerShell")
            .join("Microsoft.PowerShell_profile.ps1"),
    ]
}

/// PowerShell profiles of the current user (the real home; the scratch home in OS dry-run).
pub fn get_windows_powershell_profile_paths() -> Vec<PathBuf> {
    FileCtx::real()
        .map(|c| c.powershell_profiles())
        .unwrap_or_default()
}

/// Idempotently inserts or updates the Zastava CLI guard block inside a PowerShell profile file
/// content. A profile whose markers are partial or repeated is returned unchanged.
pub fn upsert_powershell_profile_content_with_tz(
    existing: &str,
    proxy_url: &str,
    tz: Option<&str>,
) -> String {
    let block = build_powershell_guard_block_with_tz(proxy_url, tz);
    upsert_block(existing, &block).unwrap_or_else(|_| existing.to_string())
}

/// Idempotently inserts or updates the Zastava CLI guard block inside a shell RC file content.
pub fn upsert_shell_rc_content(existing: &str, proxy_url: &str, port: u16) -> String {
    upsert_shell_rc_content_with_tz(existing, proxy_url, port, None)
}

/// Idempotently inserts or updates the Zastava CLI guard block with timezone synchronization.
pub fn upsert_shell_rc_content_with_tz(
    existing: &str,
    proxy_url: &str,
    port: u16,
    tz: Option<&str>,
) -> String {
    let block = build_shell_rc_guard_block_with_tz(proxy_url, port, tz);
    upsert_block(existing, &block).unwrap_or_else(|_| existing.to_string())
}

/// Removes the Zastava block from a profile text. Unchanged when there is none or when the
/// markers are ambiguous.
pub fn remove_shell_rc_block(existing: &str) -> String {
    remove_block(existing).unwrap_or_else(|_| existing.to_string())
}

#[cfg(test)]
#[path = "shell_rc_tests.rs"]
mod tests;
