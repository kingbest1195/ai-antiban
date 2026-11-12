//! CLI / IDE protection orchestration: enable (Claude Code, Gemini CLI, shell RC files, PowerShell
//! profiles, IDE settings, macOS launchd), disable, and status detection.

use super::ai_cli::{
    apply_claude_code_settings_file_with_tz, apply_gemini_cli_settings_file,
    cleanup_claude_code_settings_file, cleanup_gemini_cli_settings_file,
};
use super::ide::{apply_ide_settings_file_with_tz, candidate_ide_settings_paths, cleanup_ide_settings_file};
use super::shell_rc::{normalize_proxy_url_and_port, remove_shell_rc_block};
#[cfg(unix)]
use super::shell_rc::upsert_shell_rc_content_with_tz;
#[cfg(target_os = "windows")]
use super::shell_rc::{get_windows_powershell_profile_paths, upsert_powershell_profile_content_with_tz};
#[cfg(target_os = "windows")]
use super::cleanup_legacy_windows_user_env;
use super::{
    is_zastava_local_proxy_val, user_home_dir, CliProtectionReport, CLI_PROTECTION_ACTIVE,
    NO_PROXY_VALUE, ZASTAVA_RC_START,
};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use super::silent_command;
use std::fs;
use std::sync::atomic::Ordering;

/// Automatically configures CLI & IDE protection across:
/// 1. `~/.claude/settings.json` and `~/.gemini/settings.json` (`env.HTTPS_PROXY`, `env.HTTP_PROXY`, optional `TZ`)
/// 2. VS Code / Cursor / Windsurf `settings.json` (`http.proxy` + `terminal.integrated.env.*`)
/// 3. Shell profiles (`~/.zshrc`, `~/.bash_profile`) with an automatic `nc -z` liveness check
/// 4. macOS `launchctl setenv` for GUI apps launched from Dock
pub fn enable_cli_and_ide_protection(proxy_addr_or_url: &str) -> CliProtectionReport {
    enable_cli_and_ide_protection_with_tz(proxy_addr_or_url, None)
}

/// Configures CLI & IDE protection with optional 1-click timezone (`TZ`) and UTF-8 locale sync.
pub fn enable_cli_and_ide_protection_with_tz(
    proxy_addr_or_url: &str,
    tz: Option<&str>,
) -> CliProtectionReport {
    let (proxy_url, _port) = normalize_proxy_url_and_port(proxy_addr_or_url);
    let mut configured_targets = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let mut vars = vec![
            ("HTTP_PROXY", proxy_url.as_str()),
            ("HTTPS_PROXY", proxy_url.as_str()),
            ("ALL_PROXY", proxy_url.as_str()),
            ("NO_PROXY", NO_PROXY_VALUE),
        ];
        let sanitized_tz = tz.and_then(super::shell_rc::sanitize_timezone);
        if let Some(ref timezone) = sanitized_tz {
            vars.push(("TZ", timezone.as_str()));
        }
        let mut launchd_ok = false;
        for (k, v) in vars {
            if silent_command("launchctl")
                .args(["setenv", k, v])
                .output()
                .is_ok()
            {
                launchd_ok = true;
            }
        }
        if launchd_ok {
            configured_targets.push("macOS Launchd (GUI)".to_string());
        }
    }

    if let Some(home) = user_home_dir() {
        // 1. Claude Code settings (~/.claude/settings.json)
        let claude_settings = home.join(".claude").join("settings.json");
        if apply_claude_code_settings_file_with_tz(&claude_settings, &proxy_url, tz).is_ok() {
            configured_targets.push("Claude Code".to_string());
        }

        // 2. Gemini CLI / Antigravity settings (~/.gemini/settings.json if directory exists)
        let gemini_dir = home.join(".gemini");
        if gemini_dir.is_dir() {
            let gemini_settings = gemini_dir.join("settings.json");
            if apply_gemini_cli_settings_file(&gemini_settings, &proxy_url, tz).is_ok() {
                configured_targets.push("Gemini CLI".to_string());
            }
        }

        // 3. Shell RC files on Unix (~/.zshenv, ~/.zshrc, ~/.bash_profile)
        #[cfg(unix)]
        {
            let mut shell_configured = false;
            for rc_name in [".zshenv", ".zshrc", ".bash_profile"] {
                let rc_path = home.join(rc_name);
                if rc_name == ".zshenv" || rc_name == ".zshrc" || rc_path.exists() {
                    let existing = fs::read_to_string(&rc_path).unwrap_or_default();
                    let updated = upsert_shell_rc_content_with_tz(&existing, &proxy_url, _port, tz);
                    if fs::write(&rc_path, updated).is_ok() {
                        shell_configured = true;
                    }
                }
            }
            if shell_configured {
                configured_targets.push("Терминал (~/.zshenv, ~/.zshrc)".to_string());
            }
        }

        // 3b. Windows User Environment & PowerShell Profiles
        #[cfg(target_os = "windows")]
        {
            // NEVER write proxy vars or TZ / LANG / LC_TIME into global HKCU\Environment: Windows CRT
            // (_tzset) and Qt/Electron apps cannot parse IANA timezone strings and fall back to UTC+0.
            // Enabling protection does not touch the registry; stale values written by old versions
            // are removed only by the signature-based cleanup on disable/exit.

            let mut ps_configured = false;
            for ps_path in get_windows_powershell_profile_paths() {
                if let Some(parent) = ps_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let existing = fs::read_to_string(&ps_path).unwrap_or_default();
                let updated = upsert_powershell_profile_content_with_tz(&existing, &proxy_url, tz);
                if fs::write(&ps_path, updated).is_ok() {
                    ps_configured = true;
                }
            }
            if ps_configured {
                configured_targets.push("PowerShell ($PROFILE)".to_string());
            }
        }
    }

    // 4. Installed IDEs (VS Code, Cursor, Windsurf, VSCodium, Antigravity)
    for (label, settings_path) in candidate_ide_settings_paths() {
        if apply_ide_settings_file_with_tz(&settings_path, &proxy_url, tz).unwrap_or(false) {
            configured_targets.push(label.to_string());
        }
    }

    CLI_PROTECTION_ACTIVE.store(true, Ordering::SeqCst);

    let mut shell_command = format!(
        "export HTTP_PROXY=\"{proxy_url}\" HTTPS_PROXY=\"{proxy_url}\" ALL_PROXY=\"{proxy_url}\" NO_PROXY=\"{NO_PROXY_VALUE}\""
    );
    if let Some(trimmed) = tz.and_then(super::shell_rc::sanitize_timezone) {
        shell_command.push_str(&format!(
            " TZ=\"{trimmed}\" LANG=\"en_US.UTF-8\" LC_ALL=\"en_US.UTF-8\""
        ));
    }

    CliProtectionReport {
        enabled: true,
        proxy_url,
        configured_targets,
        shell_command,
    }
}

/// Cleans up runtime proxy settings in IDE `settings.json`, `~/.claude/settings.json`,
/// `~/.gemini/settings.json`, and macOS `launchctl` environment.
pub fn disable_cli_and_ide_runtime_settings() {
    #[cfg(target_os = "macos")]
    {
        for k in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
            "TZ",
        ] {
            let _ = silent_command("launchctl")
                .args(["unsetenv", k])
                .output();
        }
    }

    if let Some(home) = user_home_dir() {
        let claude_settings = home.join(".claude").join("settings.json");
        let _ = cleanup_claude_code_settings_file(&claude_settings);

        let gemini_settings = home.join(".gemini").join("settings.json");
        if gemini_settings.exists() {
            let _ = cleanup_gemini_cli_settings_file(&gemini_settings);
        }
    }

    for (_label, settings_path) in candidate_ide_settings_paths() {
        let _ = cleanup_ide_settings_file(&settings_path);
    }
}

pub fn disable_cli_protection() {
    CLI_PROTECTION_ACTIVE.store(false, Ordering::SeqCst);
    disable_cli_and_ide_runtime_settings();
    if let Some(home) = user_home_dir() {
        for rc_name in [".zshenv", ".zshrc", ".bash_profile"] {
            let rc_path = home.join(rc_name);
            if rc_path.exists() {
                if let Ok(content) = fs::read_to_string(&rc_path) {
                    let cleaned = remove_shell_rc_block(&content);
                    if cleaned != content {
                        let _ = fs::write(&rc_path, cleaned);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        cleanup_legacy_windows_user_env();

        for ps_path in get_windows_powershell_profile_paths() {
            if ps_path.exists() {
                if let Ok(content) = fs::read_to_string(&ps_path) {
                    let cleaned = remove_shell_rc_block(&content);
                    if cleaned != content {
                        let _ = fs::write(&ps_path, cleaned);
                    }
                }
            }
        }
    }
}

/// Checks whether CLI protection is currently enabled in memory, in shell RC files (~/.zshenv, ~/.zshrc, ~/.bash_profile),
/// Claude/Gemini settings, or Windows registry/PowerShell environment.
pub fn is_cli_protection_enabled() -> bool {
    if CLI_PROTECTION_ACTIVE.load(Ordering::SeqCst) {
        return true;
    }
    if let Some(home) = user_home_dir() {
        for rc_name in [".zshenv", ".zshrc", ".bash_profile"] {
            let rc_path = home.join(rc_name);
            if rc_path.exists() {
                if let Ok(content) = fs::read_to_string(&rc_path) {
                    if content.contains(ZASTAVA_RC_START)
                        || content.contains("# >>> ZASTAVA AI GUARD >>>")
                        || content.to_ascii_uppercase().contains("ZASTAVA AI")
                        || content.contains("127.0.0.1:8899")
                    {
                        return true;
                    }
                }
            }
        }
        let claude_settings = home.join(".claude").join("settings.json");
        if claude_settings.exists() {
            if let Ok(content) = fs::read_to_string(&claude_settings) {
                if is_zastava_local_proxy_val(&content) {
                    return true;
                }
            }
        }
        let gemini_settings = home.join(".gemini").join("settings.json");
        if gemini_settings.exists() {
            if let Ok(content) = fs::read_to_string(&gemini_settings) {
                if is_zastava_local_proxy_val(&content) {
                    return true;
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = silent_command("reg")
            .args(["query", r"HKCU\Environment", "/v", "HTTP_PROXY"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if is_zastava_local_proxy_val(&stdout) {
                return true;
            }
        }
        for ps_path in get_windows_powershell_profile_paths() {
            if ps_path.exists() {
                if let Ok(content) = fs::read_to_string(&ps_path) {
                    if content.contains(ZASTAVA_RC_START) || is_zastava_local_proxy_val(&content) {
                        return true;
                    }
                }
            }
        }
    }
    false
}
