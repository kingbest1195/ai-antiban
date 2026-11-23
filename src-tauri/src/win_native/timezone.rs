//! Native Win32 dynamic timezone, `SeTimeZonePrivilege`, `tzautoupdate`, and UAC elevation APIs.

use std::path::Path;

#[cfg(target_os = "windows")]
mod win {
    use super::Path;
    use crate::win_native::service::set_service_start_type;
    use crate::win_native::{decode_utf16_nul_slice, encode_wide_nul};
    use crate::win_reg::{RootKey, get_string, set_dword};
    use chrono::Datelike;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_CANCELLED, ERROR_NO_MORE_FILES, ERROR_NOT_ALL_ASSIGNED,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SUCCESS, GetLastError, HANDLE, LPARAM, LUID,
        SYSTEMTIME, WAIT_OBJECT_0, WAIT_TIMEOUT, WPARAM,
    };
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        SE_TIME_ZONE_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject,
    };
    use windows::Win32::System::Time::{
        DYNAMIC_TIME_ZONE_INFORMATION, EnumDynamicTimeZoneInformation,
        GetDynamicTimeZoneInformation, GetTimeZoneInformationForYear,
        SetDynamicTimeZoneInformation, TIME_ZONE_ID_INVALID, TIME_ZONE_INFORMATION,
    };
    use windows::Win32::UI::Shell::{
        IsUserAnAdmin, SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        ShellExecuteExW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SW_HIDE, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };
    use windows::core::PCWSTR;

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` is an owned Win32 handle.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub fn current_windows_tz_id() -> Result<Option<String>, String> {
        let mut dtzi = DYNAMIC_TIME_ZONE_INFORMATION::default();
        // SAFETY: `dtzi` is zero-initialized and writable.
        let rc = unsafe { GetDynamicTimeZoneInformation(&mut dtzi) };
        if rc != TIME_ZONE_ID_INVALID {
            let name = decode_utf16_nul_slice(&dtzi.TimeZoneKeyName);
            if !name.is_empty() {
                return Ok(Some(name));
            }
        }
        get_string(
            RootKey::HkeyLocalMachine,
            r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
            "TimeZoneKeyName",
        )
        .map(|opt| opt.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
    }

    pub fn local_utc_offset_secs() -> Option<i32> {
        let mut dtzi = DYNAMIC_TIME_ZONE_INFORMATION::default();
        // SAFETY: `dtzi` is zero-initialized and writable.
        let rc = unsafe { GetDynamicTimeZoneInformation(&mut dtzi) };
        if rc == TIME_ZONE_ID_INVALID {
            return None;
        }
        super::utc_offset_secs_from_dtzi(rc, dtzi.Bias, dtzi.StandardBias, dtzi.DaylightBias)
    }

    fn rule_from_systemtime(st: SYSTEMTIME) -> super::Win32SystemTimeRule {
        super::Win32SystemTimeRule {
            year: st.wYear,
            month: st.wMonth,
            day_of_week: st.wDayOfWeek,
            day: st.wDay,
            hour: st.wHour,
            minute: st.wMinute,
            second: st.wSecond,
        }
    }

    pub fn windows_zone_utc_offset_secs(iana_tz: &str) -> Option<i32> {
        let win_tz = crate::os_tz::iana_to_windows_tz(iana_tz)?;
        let dtzi = find_dynamic_tz_info(win_tz).ok()?;
        let now = chrono::Utc::now();
        let year = u16::try_from(now.year()).ok()?;
        let mut tzi = TIME_ZONE_INFORMATION::default();
        // SAFETY: `dtzi` and `tzi` are valid structs for the current year.
        unsafe { GetTimeZoneInformationForYear(year, Some(&dtzi), &mut tzi) }.ok()?;
        let info = super::Win32TzInfo {
            bias: tzi.Bias,
            standard_bias: tzi.StandardBias,
            daylight_bias: tzi.DaylightBias,
            standard_date: rule_from_systemtime(tzi.StandardDate),
            daylight_date: rule_from_systemtime(tzi.DaylightDate),
        };
        super::compute_win_tz_utc_offset_secs(info, now)
    }

    fn enable_time_zone_privilege() -> Result<(), String> {
        let mut token = HANDLE::default();
        // SAFETY: Opens current process token for privilege adjustment.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        }
        .map_err(|e| format!("OpenProcessToken failed: {e}"))?;
        let _guard = HandleGuard(token);

        let mut luid = LUID::default();
        // SAFETY: `SE_TIME_ZONE_NAME` is a valid static wide string constant.
        unsafe { LookupPrivilegeValueW(PCWSTR::null(), SE_TIME_ZONE_NAME, &mut luid) }
            .map_err(|e| format!("LookupPrivilegeValueW(SeTimeZonePrivilege) failed: {e}"))?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: `tp` has `PrivilegeCount == 1` matching `Privileges` array size.
        unsafe { AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None) }
            .map_err(|e| format!("AdjustTokenPrivileges failed: {e}"))?;
        // SAFETY: Thread-local Win32 error immediately after `AdjustTokenPrivileges`.
        if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
            return Err("ACCESS_DENIED: SeTimeZonePrivilege not assigned".to_string());
        }
        Ok(())
    }

    fn find_dynamic_tz_info(win_tz_id: &str) -> Result<DYNAMIC_TIME_ZONE_INFORMATION, String> {
        for idx in 0u32.. {
            let mut dtzi = DYNAMIC_TIME_ZONE_INFORMATION::default();
            // SAFETY: `dtzi` is zero-initialized and writable.
            let rc = unsafe { EnumDynamicTimeZoneInformation(idx, &mut dtzi) };
            if rc == ERROR_NO_MORE_FILES.0 {
                break;
            }
            if rc != ERROR_SUCCESS.0 {
                return Err(format!(
                    "EnumDynamicTimeZoneInformation({idx}) failed with Win32 error {rc}"
                ));
            }
            if decode_utf16_nul_slice(&dtzi.TimeZoneKeyName).eq_ignore_ascii_case(win_tz_id) {
                return Ok(dtzi);
            }
        }
        Err(format!(
            "Windows timezone '{win_tz_id}' not found via EnumDynamicTimeZoneInformation"
        ))
    }

    pub fn set_windows_tz_id(win_tz_id: &str) -> Result<(), String> {
        enable_time_zone_privilege()?;
        let dtzi = find_dynamic_tz_info(win_tz_id)?;
        // SAFETY: `dtzi` was populated by `EnumDynamicTimeZoneInformation`.
        unsafe { SetDynamicTimeZoneInformation(&dtzi) }
            .map_err(|e| format!("SetDynamicTimeZoneInformation({win_tz_id}) failed: {e}"))?;
        let intl_w = encode_wide_nul("intl");
        // SAFETY: `intl_w` is NUL-terminated UTF-16 and lives across the synchronous broadcast.
        unsafe {
            let _ = SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                WPARAM(0),
                LPARAM(intl_w.as_ptr() as isize),
                SMTO_ABORTIFHUNG,
                1000,
                None,
            );
        }
        Ok(())
    }

    pub fn set_auto_tz_enabled(enabled: bool) -> Result<(), String> {
        const WIN_TZ_AUTO_SUBKEY: &str = r"SYSTEM\CurrentControlSet\Services\tzautoupdate";
        let start_val = if enabled { 3 } else { 4 };
        set_dword(
            RootKey::HkeyLocalMachine,
            WIN_TZ_AUTO_SUBKEY,
            "Start",
            start_val,
        )?;
        match set_service_start_type("tzautoupdate", start_val) {
            Ok(()) => Ok(()),
            Err(err)
                if err.contains(&ERROR_SERVICE_DOES_NOT_EXIST.0.to_string())
                    || super::is_service_missing_error(&err) =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub fn is_process_elevated() -> bool {
        // SAFETY: `IsUserAnAdmin` takes no pointers and checks Administrators SID in active token.
        unsafe { IsUserAnAdmin().as_bool() }
    }

    pub fn run_elevated_self(
        exe_path: &Path,
        params: &str,
        timeout_ms: u32,
    ) -> Result<u32, String> {
        let verb = encode_wide_nul("runas");
        let file = encode_wide_nul(&exe_path.to_string_lossy());
        let params_w = encode_wide_nul(params);

        let mut info = SHELLEXECUTEINFOW {
            cbSize: core::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
            lpVerb: PCWSTR(verb.as_ptr()),
            lpFile: PCWSTR(file.as_ptr()),
            lpParameters: PCWSTR(params_w.as_ptr()),
            nShow: SW_HIDE.0,
            ..Default::default()
        };

        if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
            if e.code() == ERROR_CANCELLED.to_hresult() {
                return Err("ELEVATION_CANCELLED".to_string());
            }
            return Err(format!("ShellExecuteExW failed: {e}"));
        }
        if info.hProcess.is_invalid() {
            return Err("ShellExecuteExW did not return a process handle".to_string());
        }
        let proc_guard = HandleGuard(info.hProcess);
        let wait_rc = unsafe { WaitForSingleObject(proc_guard.0, timeout_ms) };
        if wait_rc == WAIT_TIMEOUT {
            return Err("Elevated helper timed out".to_string());
        }
        if wait_rc != WAIT_OBJECT_0 {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "WaitForSingleObject failed (Win32 error {})",
                err.0
            ));
        }
        let mut exit_code: u32 = 1;
        // SAFETY: `proc_guard.0` is signaled and `exit_code` is writable.
        unsafe { GetExitCodeProcess(proc_guard.0, &mut exit_code) }
            .map_err(|e| format!("GetExitCodeProcess failed: {e}"))?;
        Ok(exit_code)
    }
}

/// Returns `true` when an SCM error message indicates `ERROR_SERVICE_DOES_NOT_EXIST`
/// (`0x80070424` HRESULT / Win32 `1060` / localized English text).
pub fn is_service_missing_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("0x80070424") || lower.contains("1060") || lower.contains("does not exist")
}

pub use super::timezone_dst::{
    Win32SystemTimeRule, Win32TzInfo, compute_win_tz_utc_offset_secs, utc_offset_secs_from_dtzi,
};

pub fn local_utc_offset_secs() -> Option<i32> {
    #[cfg(target_os = "windows")]
    {
        win::local_utc_offset_secs()
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

pub fn windows_zone_utc_offset_secs(iana_tz: &str) -> Option<i32> {
    #[cfg(target_os = "windows")]
    {
        win::windows_zone_utc_offset_secs(iana_tz)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = iana_tz;
        None
    }
}

pub fn current_windows_tz_id() -> Result<Option<String>, String> {
    #[cfg(target_os = "windows")]
    {
        win::current_windows_tz_id()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(None)
    }
}

pub fn set_windows_tz_id(win_tz_id: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        win::set_windows_tz_id(win_tz_id)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = win_tz_id;
        Err("set_windows_tz_id is only supported on Windows".to_string())
    }
}

pub fn set_auto_tz_enabled(enabled: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        win::set_auto_tz_enabled(enabled)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = enabled;
        Err("set_auto_tz_enabled is only supported on Windows".to_string())
    }
}

pub fn is_process_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        win::is_process_elevated()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

pub fn run_elevated_self(exe_path: &Path, params: &str, timeout_ms: u32) -> Result<u32, String> {
    #[cfg(target_os = "windows")]
    {
        win::run_elevated_self(exe_path, params, timeout_ms)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (exe_path, params, timeout_ms);
        Err("run_elevated_self is only supported on Windows".to_string())
    }
}

pub const APPLY_OS_TZ_ARG: &str = "--apply-os-tz";
pub const OS_TZ_ERROR_FILE_ARG: &str = "--error-file";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOsTzCliArgs {
    pub win_tz_id: String,
    pub auto_tz: Option<bool>,
    pub error_file: Option<std::path::PathBuf>,
}

fn parse_auto_tz_flag(raw: &str) -> Option<Option<bool>> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "disable" | "off" | "false" | "0" | "4" => Some(Some(false)),
        "enable" | "on" | "true" | "1" | "3" => Some(Some(true)),
        "keep" | "none" | "unchanged" => Some(None),
        _ => None,
    }
}

/// Parses `--apply-os-tz <tz_id> [<auto_flag>] [--error-file <path>]` (excluding `argv[0]`).
pub fn parse_apply_os_tz_cli_args(args: &[String]) -> Option<ApplyOsTzCliArgs> {
    let idx = args.iter().position(|a| a == APPLY_OS_TZ_ARG)?;
    let win_tz_id = args
        .get(idx + 1)
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())?;
    let mut auto_tz: Option<bool> = None;
    let mut error_file: Option<std::path::PathBuf> = None;
    let mut i = idx + 2;
    while i < args.len() {
        let arg = &args[i];
        if let Some(val) = arg.strip_prefix(&format!("{OS_TZ_ERROR_FILE_ARG}=")) {
            let trimmed = val.trim().trim_matches('"');
            if !trimmed.is_empty() {
                error_file = Some(std::path::PathBuf::from(trimmed));
            }
        } else if arg == OS_TZ_ERROR_FILE_ARG {
            if let Some(next) = args.get(i + 1)
                && !next.trim().trim_matches('"').is_empty()
            {
                error_file = Some(std::path::PathBuf::from(next.trim().trim_matches('"')));
                i += 1;
            }
        } else if let Some(parsed) = parse_auto_tz_flag(arg) {
            auto_tz = parsed;
        }
        i += 1;
    }
    Some(ApplyOsTzCliArgs {
        win_tz_id,
        auto_tz,
        error_file,
    })
}

/// Formats CLI arguments for `ShellExecuteExW("runas")` invocation of `zastava.exe --apply-os-tz`.
pub fn build_apply_os_tz_cli_params(
    win_tz_id: &str,
    auto_tz: Option<bool>,
    error_file: Option<&Path>,
) -> String {
    let auto_flag = match auto_tz {
        Some(false) => "disable",
        Some(true) => "enable",
        None => "keep",
    };
    let quoted_tz = win_tz_id.replace('"', "");
    match error_file {
        Some(path) => format!(
            "{APPLY_OS_TZ_ARG} \"{quoted_tz}\" {auto_flag} {OS_TZ_ERROR_FILE_ARG} \"{}\"",
            path.to_string_lossy()
        ),
        None => format!("{APPLY_OS_TZ_ARG} \"{quoted_tz}\" {auto_flag}"),
    }
}

/// Executes `--apply-os-tz` strictly validating the target timezone ID against our allowlist.
pub fn run_apply_os_tz_cli(cli: ApplyOsTzCliArgs) -> i32 {
    if !crate::os_tz::os_tz_effects_enabled() {
        return 0;
    }
    let Some(safe_tz) = crate::os_tz::allowlisted_windows_tz_id(&cli.win_tz_id) else {
        if let Some(ref p) = cli.error_file {
            let _ = std::fs::write(p, "Недопустимый идентификатор часового пояса Windows.");
        }
        return 1;
    };
    let res = set_windows_tz_id(safe_tz).and_then(|()| {
        if let Some(auto) = cli.auto_tz {
            set_auto_tz_enabled(auto)?;
        }
        Ok(())
    });
    if let Err(err) = res {
        crate::diagnostics::record("os_tz", &err);
        if let Some(ref p) = cli.error_file {
            let _ = std::fs::write(p, err.as_bytes());
        }
        return 1;
    }
    0
}
