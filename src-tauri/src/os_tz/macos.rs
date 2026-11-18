//! macOS OS timezone platform implementation (`systemsetup`, `osascript`, `defaults`).

use super::mapping::{canonicalize_iana_tz, validate_iana_tz};
use super::os_tz_effects_enabled;
use std::path::Path;

fn validate_macos_zoneinfo(iana: &str) -> Result<String, String> {
    let clean = validate_iana_tz(iana)?;
    let candidates = [clean.as_str(), canonicalize_iana_tz(&clean)];
    for cand in candidates {
        let p1 = Path::new("/usr/share/zoneinfo").join(cand);
        let p2 = Path::new("/var/db/timezone/zoneinfo").join(cand);
        if p1.is_file() || p2.is_file() {
            return Ok(cand.to_string());
        }
    }
    Err(format!(
        "Часовой пояс '{clean}' не найден в системной базе /usr/share/zoneinfo."
    ))
}

fn read_macos_localtime_symlink() -> Option<String> {
    let target = std::fs::read_link("/etc/localtime").ok()?;
    let s = target.to_string_lossy();
    let stripped = s
        .strip_prefix("/var/db/timezone/zoneinfo/")
        .or_else(|| s.strip_prefix("/usr/share/zoneinfo/"))?;
    crate::sysproxy::sanitize_timezone(stripped)
}

fn posix_single_quote(s: &str) -> Result<String, String> {
    if s.contains('\0') {
        return Err("Недопустимый нулевой символ в аргументе.".to_string());
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    Ok(out)
}

fn applescript_string_literal(s: &str) -> Result<String, String> {
    if s.chars().any(char::is_control) {
        return Err("Недопустимый управляющий символ в скрипте AppleScript.".to_string());
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

fn run_macos_privileged_script(shell_script: &str) -> Result<(), String> {
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    let osa_arg = format!(
        "do shell script {} with administrator privileges",
        applescript_string_literal(shell_script)?
    );
    let out = crate::sysproxy::silent_command("osascript")
        .args(["-e", &osa_arg])
        .output()
        .map_err(|e| format!("Не удалось запустить osascript: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let cancelled = crate::sysproxy::platform::is_admin_auth_error(&stdout, &stderr)
        || stderr.contains("(-128)")
        || stdout.contains("(-128)");
    if cancelled {
        return Err(
            "OS_TZ_ELEVATION_CANCELLED: Запрос прав администратора отменён пользователем."
                .to_string(),
        );
    }
    let detail = stderr.trim();
    Err(if detail.is_empty() {
        format!(
            "Не удалось изменить системный часовой пояс (код {:?}).",
            out.status.code()
        )
    } else {
        format!("Не удалось изменить системный часовой пояс: {detail}")
    })
}

pub(super) fn current_iana_timezone() -> Result<String, String> {
    if let Some(tz) = read_macos_localtime_symlink() {
        return Ok(tz);
    }
    iana_time_zone::get_timezone().map_err(|e| e.to_string())
}

pub(super) fn is_auto_tz_enabled() -> Result<Option<bool>, String> {
    if !os_tz_effects_enabled() {
        return Ok(None);
    }
    let out = crate::sysproxy::silent_command("/usr/bin/defaults")
        .args([
            "read",
            "/Library/Preferences/com.apple.timezone.auto",
            "Active",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match s.as_str() {
                "1" | "true" | "YES" => Ok(Some(true)),
                "0" | "false" | "NO" => Ok(Some(false)),
                _ => Ok(None),
            }
        }
        _ => Ok(Some(false)),
    }
}

pub(super) fn apply_timezone(target_iana: &str, disable_auto_tz: bool) -> Result<(), String> {
    let verified = validate_macos_zoneinfo(target_iana)?;
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    let q_tz = posix_single_quote(&verified)?;
    let script = if disable_auto_tz {
        format!(
            "/usr/sbin/systemsetup -settimezone {q_tz} && /usr/bin/defaults write /Library/Preferences/com.apple.timezone.auto Active -bool false"
        )
    } else {
        format!("/usr/sbin/systemsetup -settimezone {q_tz}")
    };
    run_macos_privileged_script(&script)
}

pub(super) fn restore_timezone(
    orig_iana: &str,
    orig_win_id: Option<&str>,
    restore_auto_tz: Option<bool>,
) -> Result<(), String> {
    let _ = orig_win_id;
    let verified = validate_macos_zoneinfo(orig_iana)?;
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    let q_tz = posix_single_quote(&verified)?;
    let script = if restore_auto_tz == Some(true) {
        format!(
            "/usr/sbin/systemsetup -settimezone {q_tz} && /usr/bin/defaults write /Library/Preferences/com.apple.timezone.auto Active -bool true"
        )
    } else {
        format!("/usr/sbin/systemsetup -settimezone {q_tz}")
    };
    run_macos_privileged_script(&script)
}
