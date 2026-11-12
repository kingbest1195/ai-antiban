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
use super::journal::{Journal, Resource, Value};
use super::platform::Platform;
use super::{
    is_zastava_local_proxy_val, user_home_dir, CliProtectionReport, Run, CLI_PROTECTION_ACTIVE,
    NO_PROXY_VALUE, ZASTAVA_RC_START,
};
use std::fs;
use std::sync::atomic::Ordering;

/// Sets the given variables in the user environment (launchd) through the ownership journal and
/// returns how many of them are now Zastava's. A variable that already holds a value Zastava did
/// not write (a corporate `HTTPS_PROXY`, the user's own `TZ`) is left exactly as it is.
pub(super) fn apply_user_env(j: &mut Journal, p: &dyn Platform, vars: &[(&str, &str)]) -> usize {
    let mut ours = 0;
    for (name, value) in vars {
        let res = Resource::UserEnv {
            name: (*name).to_string(),
        };
        let Ok(cur) = p.get_user_env(name).map(Value::Env) else {
            continue;
        };
        let free = matches!(cur, Value::Env(None));
        if !(free || j.owns(&res, &cur)) {
            continue; // a foreign value: neither overwritten now nor removed later
        }
        match j.apply(p, &res, Value::Env(Some((*value).to_string()))) {
            Ok(_) => ours += 1,
            Err(e) => eprintln!("Застава: {} не записана: {e}", res.id()),
        }
    }
    ours
}

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

    // GUI apps started from the Dock inherit these from launchd. On Windows nothing is written
    // into `HKCU\Environment`: the CRT and Qt/Electron cannot parse IANA timezones there.
    if cfg!(target_os = "macos") {
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
        if let Run::Done(n) =
            super::with_journal("launchctl:setenv", |j, p| apply_user_env(j, p, &vars))
            && n > 0
        {
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

/// Cleans up runtime proxy settings in IDE `settings.json`, `~/.claude/settings.json` and
/// `~/.gemini/settings.json`. The launchd environment is restored from the ownership journal
/// (see [`disable_cli_protection`]), not guessed here.
pub fn disable_cli_and_ide_runtime_settings() {
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

/// Switches CLI protection off: the user environment Zastava set is restored from the ownership
/// journal (foreign values stay), then the IDE / CLI / shell files are cleaned.
pub fn disable_cli_protection() {
    let _ = super::cleanup::restore_user_env();
    disable_cli_files();
}

/// The file side of [`disable_cli_protection`]: IDE / CLI settings, shell profiles, PowerShell
/// profiles.
pub(super) fn disable_cli_files() {
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
        if super::real_user_env("HTTP_PROXY").is_some_and(|v| is_zastava_local_proxy_val(&v)) {
            return true;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysproxy::fs::FakeFs;
    use crate::sysproxy::platform::FakePlatform;
    use std::path::Path;
    use std::sync::Arc;

    fn open(fs: &FakeFs) -> Journal {
        Journal::open(Arc::new(fs.clone()), Path::new("/data")).unwrap()
    }

    const VARS: [(&str, &str); 3] = [
        ("HTTP_PROXY", "http://127.0.0.1:8899"),
        ("HTTPS_PROXY", "http://127.0.0.1:8899"),
        ("TZ", "Europe/Amsterdam"),
    ];

    #[test]
    fn foreign_variables_are_neither_overwritten_nor_removed() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_env("HTTPS_PROXY", "http://corp:3128");
        p.seed_env("TZ", "Europe/Berlin");
        let mut j = open(&fs);
        let ours = apply_user_env(&mut j, &p, &VARS);
        assert_eq!(ours, 1, "only the free HTTP_PROXY is ours");
        assert_eq!(p.env_of("HTTPS_PROXY"), Some("http://corp:3128".into()));
        assert_eq!(p.env_of("TZ"), Some("Europe/Berlin".into()));
        assert_eq!(p.env_of("HTTP_PROXY"), Some("http://127.0.0.1:8899".into()));
        // Cleanup restores what is ours and leaves the foreign values.
        let rep = crate::sysproxy::cleanup::restore_with(
            &mut j,
            &p,
            crate::sysproxy::cleanup::Scope::UserEnv,
        );
        assert_eq!(rep.restored(), 1);
        assert_eq!(p.env_of("HTTP_PROXY"), None);
        assert_eq!(p.env_of("HTTPS_PROXY"), Some("http://corp:3128".into()));
        assert_eq!(p.env_of("TZ"), Some("Europe/Berlin".into()));
    }

    #[test]
    fn our_own_values_are_updated_and_restored_to_absence() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        let mut j = open(&fs);
        assert_eq!(apply_user_env(&mut j, &p, &VARS), 3);
        // The timezone is re-synced to another value: still ours, so it may be updated.
        let again = [("TZ", "Asia/Tokyo")];
        assert_eq!(apply_user_env(&mut j, &p, &again), 1);
        assert_eq!(p.env_of("TZ"), Some("Asia/Tokyo".into()));
        let before = p.os_writes();
        assert_eq!(apply_user_env(&mut j, &p, &VARS[..2]), 2);
        assert_eq!(p.os_writes(), before, "repeating changes nothing");
        j.restore_all(&p);
        for n in ["HTTP_PROXY", "HTTPS_PROXY", "TZ"] {
            assert_eq!(p.env_of(n), None, "{n}");
        }
    }

    #[test]
    fn a_variable_changed_by_the_user_after_us_is_not_overwritten_again() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        let mut j = open(&fs);
        apply_user_env(&mut j, &p, &VARS[..1]);
        p.seed_env("HTTP_PROXY", "http://mine:1");
        assert_eq!(apply_user_env(&mut j, &p, &VARS[..1]), 0);
        assert_eq!(p.env_of("HTTP_PROXY"), Some("http://mine:1".into()));
        let rep = j.restore_all(&p);
        assert_eq!(rep.external(), 1);
        assert_eq!(p.env_of("HTTP_PROXY"), Some("http://mine:1".into()));
    }

    #[test]
    fn an_unreadable_variable_is_skipped_not_guessed() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        let mut j = open(&fs);
        p.fail_next(crate::sysproxy::platform::PlatOp::GetEnv);
        assert_eq!(apply_user_env(&mut j, &p, &VARS[..2]), 1);
        assert_eq!(p.env_of("HTTP_PROXY"), None);
    }
}
