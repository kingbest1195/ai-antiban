//! Windows OS timezone platform implementation (native Win32 APIs, Zero-LOLBin).

use super::mapping::{
    allowlisted_windows_tz_id, iana_to_windows_tz, validate_iana_tz, windows_to_iana_tz,
};
use super::os_tz_effects_enabled;
use crate::win_native::timezone::{
    build_apply_os_tz_cli_params, current_windows_tz_id as win32_current_tz_id,
    is_process_elevated, run_elevated_self, set_auto_tz_enabled, set_windows_tz_id,
};

const WIN_TZ_REG_SUBKEY: &str = r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation";
const WIN_TZ_AUTO_SUBKEY: &str = r"SYSTEM\CurrentControlSet\Services\tzautoupdate";
const OS_TZ_ELEVATION_TIMEOUT_MS: u32 = 30_000;

struct TempErrorFile(std::path::PathBuf);

impl Drop for TempErrorFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn run_elevated_os_tz(win_tz_allowlisted: &str, auto_tz: Option<bool>) -> Result<(), String> {
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    if is_process_elevated() {
        set_windows_tz_id(win_tz_allowlisted)?;
        if let Some(auto) = auto_tz {
            set_auto_tz_enabled(auto)?;
        }
        return Ok(());
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к приложению: {e}"))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let err_path = std::env::temp_dir().join(format!(
        "zastava-os-tz-err-{}-{nanos}.txt",
        std::process::id()
    ));
    let _guard = TempErrorFile(err_path.clone());
    let _ = std::fs::remove_file(&err_path);

    let params = build_apply_os_tz_cli_params(win_tz_allowlisted, auto_tz, Some(&err_path));
    let exit_code = match run_elevated_self(&exe, &params, OS_TZ_ELEVATION_TIMEOUT_MS) {
        Ok(code) => code,
        Err(err) if err == "ELEVATION_CANCELLED" => {
            return Err(
                "OS_TZ_ELEVATION_CANCELLED: Запрос прав администратора (UAC) отменён пользователем."
                    .to_string(),
            );
        }
        Err(err) => {
            return Err(format!(
                "Не удалось изменить системный часовой пояс Windows: {err}"
            ));
        }
    };
    if exit_code == 0 {
        return Ok(());
    }
    let detail = std::fs::read_to_string(&err_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("код возврата {exit_code}"));
    Err(format!(
        "Не удалось изменить системный часовой пояс Windows: {detail}"
    ))
}

pub(super) fn current_iana_timezone() -> Result<String, String> {
    if let Ok(Some(win_id)) = current_windows_tz_id()
        && let Some(iana) = windows_to_iana_tz(&win_id)
    {
        return Ok(iana.to_string());
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
    win32_current_tz_id()
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
    if !need_disable_auto && set_windows_tz_id(safe_win_tz).is_ok() {
        return Ok(());
    }
    let auto_flag = if need_disable_auto { Some(false) } else { None };
    run_elevated_os_tz(safe_win_tz, auto_flag)
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
    if !need_restore_auto && set_windows_tz_id(win_tz).is_ok() {
        return Ok(());
    }
    let auto_flag = if need_restore_auto { Some(true) } else { None };
    run_elevated_os_tz(win_tz, auto_flag)
}
