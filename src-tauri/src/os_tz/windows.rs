//! Windows OS timezone platform implementation (`tzutil`, Win32 registry, PowerShell `RunAs`).

use super::mapping::{
    allowlisted_windows_tz_id, iana_to_windows_tz, validate_iana_tz, windows_to_iana_tz,
};
use super::os_tz_effects_enabled;

const WIN_TZ_REG_SUBKEY: &str = r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation";
const WIN_TZ_AUTO_SUBKEY: &str = r"SYSTEM\CurrentControlSet\Services\tzautoupdate";

fn run_windows_tzutil_set(win_tz_allowlisted: &str) -> Result<(), String> {
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    let out = crate::sysproxy::silent_command("tzutil.exe")
        .args(["/s", win_tz_allowlisted])
        .output()
        .map_err(|e| format!("Не удалось запустить tzutil.exe: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    Err(if detail.is_empty() {
        format!("tzutil.exe завершился с кодом {:?}", out.status.code())
    } else {
        detail
    })
}

fn run_windows_elevated_tz_ps(
    win_tz_allowlisted: &str,
    auto_tz_start: Option<u32>,
) -> Result<(), String> {
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    use base64::Engine;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // `win_tz_allowlisted` is guaranteed to come from our static WINDOWS_TO_IANA / IANA_TO_WINDOWS
    // allowlist, containing only ASCII letters, digits, spaces, dots, and parentheses.
    let reg_part = match auto_tz_start {
        Some(start_val) => format!(
            "; $reg='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\tzautoupdate'; \
             if (Test-Path $reg) {{ Set-ItemProperty -Path $reg -Name 'Start' -Value {start_val} -Type DWord }}"
        ),
        None => String::new(),
    };
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         & \"$env:SystemRoot\\System32\\tzutil.exe\" /s '{win_tz_allowlisted}'; \
         if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}{reg_part}"
    );
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let launcher = format!(
        "$p = Start-Process -FilePath \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \
         -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-EncodedCommand','{encoded}') \
         -Verb RunAs -WindowStyle Hidden -PassThru -Wait; exit $p.ExitCode"
    );

    let out = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &launcher,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Не удалось запустить PowerShell для смены часового пояса: {e}"))?;

    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let lower = stderr.to_ascii_lowercase();
    if stderr.is_empty()
        || lower.contains("canceled by the user")
        || lower.contains("cancelled by the user")
        || lower.contains("отменена пользователем")
        || lower.contains("операция была отменена")
    {
        return Err(
            "OS_TZ_ELEVATION_CANCELLED: Запрос прав администратора (UAC) отменён пользователем."
                .to_string(),
        );
    }
    Err(format!(
        "Не удалось изменить системный часовой пояс Windows: {stderr}"
    ))
}

pub(super) fn current_iana_timezone() -> Result<String, String> {
    if let Ok(Some(win_id)) = current_windows_tz_id() {
        if let Some(iana) = windows_to_iana_tz(&win_id) {
            return Ok(iana.to_string());
        }
    }
    iana_time_zone::get_timezone().map_err(|e| e.to_string())
}

pub(super) fn current_windows_tz_id() -> Result<Option<String>, String> {
    if let Ok(Some(id)) = crate::win_reg::get_string(
        crate::win_reg::RootKey::HkeyLocalMachine,
        WIN_TZ_REG_SUBKEY,
        "TimeZoneKeyName",
    ) {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }
    if !os_tz_effects_enabled() {
        return Ok(None);
    }
    let out = crate::sysproxy::silent_command("tzutil.exe")
        .args(["/g"])
        .output()
        .map_err(|e| format!("tzutil /g error: {e}"))?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Ok(Some(s));
        }
    }
    Ok(None)
}

pub(super) fn is_auto_tz_enabled() -> Result<Option<bool>, String> {
    match crate::win_reg::get_dword(
        crate::win_reg::RootKey::HkeyLocalMachine,
        WIN_TZ_AUTO_SUBKEY,
        "Start",
    ) {
        Ok(Some(4)) => Ok(Some(false)),
        Ok(Some(2 | 3)) => Ok(Some(true)),
        _ => Ok(None),
    }
}

pub(super) fn apply_timezone(target_iana: &str, disable_auto_tz: bool) -> Result<(), String> {
    let clean = validate_iana_tz(target_iana)?;
    let win_tz = iana_to_windows_tz(&clean).ok_or_else(|| {
        format!("Часовой пояс '{clean}' не имеет сопоставления в таблице Windows.")
    })?;
    let safe_win_tz = allowlisted_windows_tz_id(win_tz)
        .ok_or_else(|| format!("Windows TZ '{win_tz}' отсутствует в списке допустимых."))?;
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    let need_disable_auto = disable_auto_tz && matches!(is_auto_tz_enabled(), Ok(Some(true)));
    if !need_disable_auto && run_windows_tzutil_set(safe_win_tz).is_ok() {
        return Ok(());
    }
    let auto_start = if need_disable_auto { Some(4) } else { None };
    run_windows_elevated_tz_ps(safe_win_tz, auto_start)
}

pub(super) fn restore_timezone(
    orig_iana: &str,
    orig_win_id: Option<&str>,
    restore_auto_tz: Option<bool>,
) -> Result<(), String> {
    let win_tz = orig_win_id
        .and_then(allowlisted_windows_tz_id)
        .or_else(|| {
            validate_iana_tz(orig_iana)
                .ok()
                .and_then(|c| iana_to_windows_tz(&c))
                .and_then(allowlisted_windows_tz_id)
        })
        .ok_or_else(|| {
            format!("Не удалось определить Windows TZ для восстановления '{orig_iana}'.")
        })?;
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    let need_restore_auto = restore_auto_tz == Some(true);
    if !need_restore_auto && run_windows_tzutil_set(win_tz).is_ok() {
        return Ok(());
    }
    let auto_start = if need_restore_auto { Some(3) } else { None };
    run_windows_elevated_tz_ps(win_tz, auto_start)
}
