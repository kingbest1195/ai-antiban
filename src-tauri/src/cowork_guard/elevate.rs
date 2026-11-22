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
    use crate::win_native::timezone::{is_process_elevated, run_elevated_self};
    use std::path::{Path, PathBuf};

    const ELEVATION_TIMEOUT_MS: u32 = 30_000;

    struct TempFileGuard(PathBuf);

    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    pub fn is_current_process_elevated() -> bool {
        is_process_elevated()
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

        let params_str = build_elevated_cli_params(Some(&error_path));
        let exit_code = match run_elevated_self(exe_path, &params_str, ELEVATION_TIMEOUT_MS) {
            Ok(code) => code,
            Err(err) if err == "ELEVATION_CANCELLED" => {
                return Err(
                    "Настройка задачи планировщика отменена или не хватило прав администратора."
                        .to_string(),
                );
            }
            Err(err) => {
                return Err(format!(
                    "Не удалось запустить настройку задачи планировщика ({err})."
                ));
            }
        };

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
