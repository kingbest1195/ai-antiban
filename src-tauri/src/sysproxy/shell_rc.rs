//! Shell profile blocks (zsh/bash RC files and PowerShell `$PROFILE`): building, upserting and removing
//! the Zastava guard block that exports proxy / timezone / locale variables.

use super::{user_home_dir, NO_PROXY_VALUE, ZASTAVA_RC_END, ZASTAVA_RC_START};
use std::path::PathBuf;

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
pub fn build_shell_rc_guard_block_with_tz(
    proxy_url: &str,
    port: u16,
    tz: Option<&str>,
) -> String {
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
pub fn build_powershell_guard_block_with_tz(
    proxy_url: &str,
    tz: Option<&str>,
) -> String {
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

/// Idempotently inserts or updates the Zastava CLI guard block inside a PowerShell profile file content.
pub fn upsert_powershell_profile_content_with_tz(
    existing: &str,
    proxy_url: &str,
    tz: Option<&str>,
) -> String {
    let block = build_powershell_guard_block_with_tz(proxy_url, tz);
    if let (Some(start_idx), Some(end_idx)) = (
        existing.find(ZASTAVA_RC_START),
        existing.find(ZASTAVA_RC_END),
    ) {
        if start_idx <= end_idx {
            let after_end = end_idx + ZASTAVA_RC_END.len();
            let mut result = String::with_capacity(existing.len() + block.len());
            result.push_str(&existing[..start_idx]);
            result.push_str(&block);
            result.push_str(&existing[after_end..]);
            return result;
        }
    }

    let mut result = existing.to_string();
    if !result.is_empty() && !result.ends_with('\n') {
        result.push('\n');
    }
    if !result.is_empty() {
        result.push('\n');
    }
    result.push_str(&block);
    result.push('\n');
    result
}

pub fn get_windows_powershell_profile_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = user_home_dir() {
        let docs = home.join("Documents");
        paths.push(docs.join("PowerShell").join("Microsoft.PowerShell_profile.ps1"));
        paths.push(docs.join("WindowsPowerShell").join("Microsoft.PowerShell_profile.ps1"));
    }
    paths
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
    if let (Some(start_idx), Some(end_idx)) = (
        existing.find(ZASTAVA_RC_START),
        existing.find(ZASTAVA_RC_END),
    ) {
        if start_idx <= end_idx {
            let after_end = end_idx + ZASTAVA_RC_END.len();
            let mut result = String::with_capacity(existing.len() + block.len());
            result.push_str(&existing[..start_idx]);
            result.push_str(&block);
            result.push_str(&existing[after_end..]);
            return result;
        }
    }

    let mut result = existing.to_string();
    if !result.is_empty() && !result.ends_with('\n') {
        result.push('\n');
    }
    if !result.is_empty() {
        result.push('\n');
    }
    result.push_str(&block);
    result.push('\n');
    result
}

pub fn remove_shell_rc_block(existing: &str) -> String {
    if let (Some(start_idx), Some(end_idx)) = (
        existing.find(ZASTAVA_RC_START),
        existing.find(ZASTAVA_RC_END),
    ) {
        if start_idx <= end_idx {
            let mut after_end = end_idx + ZASTAVA_RC_END.len();
            if existing[after_end..].starts_with('\n') {
                after_end += 1;
            }
            let mut result = String::with_capacity(existing.len());
            result.push_str(&existing[..start_idx]);
            result.push_str(&existing[after_end..]);
            return result;
        }
    }
    existing.to_string()
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
        assert_eq!(sanitize_timezone("Europe/London"), Some("Europe/London".to_string()));
        assert_eq!(sanitize_timezone(" America/New_York "), Some("America/New_York".to_string()));
        assert_eq!(sanitize_timezone("Etc/GMT+3"), Some("Etc/GMT+3".to_string()));
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
}
