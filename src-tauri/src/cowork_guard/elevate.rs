//! Elevated CLI argument parsing, diagnostics error-file forwarding, and Windows UAC helper.

use super::{COWORK_ERROR_FILE_ARG, INSTALL_COWORK_GUARD_ARG};

/// Parses `--install-cowork-guard` and optional `--error-file <path>` (or `--error-file=<path>`)
/// from CLI arguments (excluding argv[0]). Returns `None` if `--install-cowork-guard` is absent.
pub fn parse_install_cli_args(args: &[String]) -> Option<Option<std::path::PathBuf>> {
    if !args.iter().any(|a| a == INSTALL_COWORK_GUARD_ARG) {
        return None;
    }
    let mut error_file: Option<std::path::PathBuf> = None;
    let mut idx = 0;
    while idx < args.len() {
        let arg = &args[idx];
        if let Some(val) = arg.strip_prefix(&format!("{COWORK_ERROR_FILE_ARG}=")) {
            let trimmed = val.trim().trim_matches('"');
            if !trimmed.is_empty() {
                error_file = Some(std::path::PathBuf::from(trimmed));
            }
        } else if arg == COWORK_ERROR_FILE_ARG
            && let Some(next) = args.get(idx + 1)
        {
            let trimmed = next.trim().trim_matches('"');
            if !trimmed.is_empty() {
                error_file = Some(std::path::PathBuf::from(trimmed));
            }
            idx += 1;
        }
        idx += 1;
    }
    Some(error_file)
}

/// Builds the parameter string passed to `ShellExecuteExW` for elevated execution.
pub fn build_elevated_cli_params(error_file: Option<&std::path::Path>) -> String {
    match error_file {
        Some(path) => format!(
            "{INSTALL_COWORK_GUARD_ARG} {COWORK_ERROR_FILE_ARG} \"{}\"",
            path.to_string_lossy()
        ),
        None => INSTALL_COWORK_GUARD_ARG.to_string(),
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(super) fn write_install_error_file(error_file: Option<&std::path::Path>, err: &str) {
    if let Some(path) = error_file {
        let _ = std::fs::write(path, err.as_bytes());
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(super) fn read_install_error_file(error_file: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(error_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "windows")]
pub(super) mod win_elevate {
    use super::{build_elevated_cli_params, read_install_error_file};
    use crate::win_reg::encode_utf16_nul;
    use core::ffi::c_void;
    use std::path::{Path, PathBuf};

    const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
    const SEE_MASK_NO_CONSOLE: u32 = 0x0000_8000;
    const SW_HIDE: i32 = 0;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const ERROR_CANCELLED: u32 = 1223;
    const ELEVATION_TIMEOUT_MS: u32 = 30_000;

    #[repr(C)]
    struct ShellExecuteInfoW {
        cb_size: u32,
        f_mask: u32,
        hwnd: *mut c_void,
        lp_verb: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show: i32,
        h_inst_app: *mut c_void,
        lp_id_list: *mut c_void,
        lp_class: *const u16,
        hkey_class: *mut c_void,
        dw_hot_key: u32,
        h_icon_or_monitor: *mut c_void,
        h_process: *mut c_void,
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteExW(p_exec_info: *mut ShellExecuteInfoW) -> i32;
        fn IsUserAnAdmin() -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
        fn GetExitCodeProcess(h_process: *mut c_void, lp_exit_code: *mut u32) -> i32;
        fn CloseHandle(h_object: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    struct ProcessHandle(*mut c_void);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was returned in `SHELLEXECUTEINFOW.hProcess`.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    struct TempFileGuard(PathBuf);

    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    pub fn is_current_process_elevated() -> bool {
        // SAFETY: `IsUserAnAdmin` takes no pointers and checks Administrators SID in active token.
        unsafe { IsUserAnAdmin() != 0 }
    }

    pub fn run_elevated_install(exe_path: &Path) -> Result<(), String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let error_path = std::env::temp_dir().join(format!(
            "zastava-cowork-err-{}-{nanos}.txt",
            std::process::id()
        ));
        let _err_guard = TempFileGuard(error_path.clone());
        let _ = std::fs::remove_file(&error_path);

        let verb = encode_utf16_nul("runas");
        let file = encode_utf16_nul(&exe_path.to_string_lossy());
        let params_str = build_elevated_cli_params(Some(&error_path));
        let params = encode_utf16_nul(&params_str);

        let mut info = ShellExecuteInfoW {
            cb_size: core::mem::size_of::<ShellExecuteInfoW>() as u32,
            f_mask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
            hwnd: core::ptr::null_mut(),
            lp_verb: verb.as_ptr(),
            lp_file: file.as_ptr(),
            lp_parameters: params.as_ptr(),
            lp_directory: core::ptr::null(),
            n_show: SW_HIDE,
            h_inst_app: core::ptr::null_mut(),
            lp_id_list: core::ptr::null_mut(),
            lp_class: core::ptr::null(),
            hkey_class: core::ptr::null_mut(),
            dw_hot_key: 0,
            h_icon_or_monitor: core::ptr::null_mut(),
            h_process: core::ptr::null_mut(),
        };

        // SAFETY: `verb`, `file`, and `params` remain alive and NUL-terminated across the call.
        let ok = unsafe { ShellExecuteExW(&mut info) };
        if ok == 0 {
            // SAFETY: thread-local Win32 error from the immediately preceding `ShellExecuteExW`.
            let err = unsafe { GetLastError() };
            return Err(if err == ERROR_CANCELLED {
                "Настройка задачи планировщика отменена или не хватило прав администратора."
                    .to_string()
            } else {
                format!("Не удалось запустить настройку задачи планировщика (Win32 error {err}).")
            });
        }

        if info.h_process.is_null() {
            return Err(
                "Не удалось дождаться завершения настройки задачи планировщика.".to_string(),
            );
        }
        let proc_handle = ProcessHandle(info.h_process);

        // SAFETY: `proc_handle.0` is a valid process handle from `ShellExecuteExW`.
        let wait_rc = unsafe { WaitForSingleObject(proc_handle.0, ELEVATION_TIMEOUT_MS) };
        if wait_rc == WAIT_TIMEOUT {
            return Err("Превышено время ожидания настройки задачи планировщика.".to_string());
        }
        if wait_rc != WAIT_OBJECT_0 {
            // SAFETY: thread-local Win32 error from `WaitForSingleObject`.
            let err = unsafe { GetLastError() };
            return Err(format!(
                "Ошибка ожидания процесса настройки задачи (Win32 error {err})."
            ));
        }

        let mut exit_code: u32 = 1;
        // SAFETY: `proc_handle.0` is signaled and `exit_code` is writable.
        if unsafe { GetExitCodeProcess(proc_handle.0, &mut exit_code) } == 0 {
            // SAFETY: thread-local Win32 error from `GetExitCodeProcess`.
            let err = unsafe { GetLastError() };
            return Err(format!(
                "Не удалось получить код возврата настройки задачи (Win32 error {err})."
            ));
        }
        if exit_code != 0 {
            if let Some(detail) = read_install_error_file(&error_path) {
                crate::diagnostics::record("cowork_guard", &detail);
                return Err(format!(
                    "Ошибка настройки задачи планировщика (код {exit_code}): {detail}"
                ));
            }
            return Err(format!(
                "Ошибка настройки задачи планировщика (код {exit_code})."
            ));
        }
        Ok(())
    }
}
