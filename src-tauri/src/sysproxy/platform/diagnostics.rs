//! Sanitized OS error tracking, diagnostic snapshot collection, and native clipboard write.

use super::{
    macos::{classify_service, parse_nc_list, parse_scutil_proxy, parse_service_order},
    real::run_detailed,
};

static LAST_OS_ERROR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub(super) fn set_last_os_error(msg: Option<String>) {
    if let Ok(mut g) = LAST_OS_ERROR.lock() {
        *g = msg;
    }
}

/// Clears the last recorded OS command failure (e.g., before starting a new operation).
pub fn clear_last_os_error() {
    set_last_os_error(None);
}

/// Returns the most recent sanitized OS command failure recorded by `RealPlatform::run_stdout`,
/// containing only the operation name, tool exit code, and trimmed OS error line (never values).
pub fn last_os_error() -> Option<String> {
    LAST_OS_ERROR.lock().ok().and_then(|g| g.clone())
}

/// Collects a sanitized, read-only OS network diagnostic snapshot (macOS only; empty on other OS
/// or when OS effects are disabled in tests).
pub fn collect_os_diagnostic_snapshot() -> Vec<String> {
    if !cfg!(target_os = "macos") || !crate::sysproxy::os_effects_enabled() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    if let Ok((ok, _, ver, _)) = run_detailed("sw_vers", &["-productVersion"], "diag_sw_vers")
        && ok
    {
        let build = run_detailed("sw_vers", &["-buildVersion"], "diag_sw_build")
            .ok()
            .filter(|(ok, _, _, _)| *ok)
            .map(|(_, _, b, _)| b.trim().to_string())
            .unwrap_or_default();
        if build.is_empty() {
            lines.push(format!("macos_version: {}", ver.trim()));
        } else {
            lines.push(format!("macos_version: {} ({build})", ver.trim()));
        }
    }
    if let Ok((ok, code, stdout, stderr)) = run_detailed(
        "networksetup",
        &["-listnetworkserviceorder"],
        "diag_services",
    ) {
        if ok {
            let svcs = parse_service_order(&stdout);
            let nc = run_detailed("scutil", &["--nc", "list"], "diag_nc")
                .ok()
                .filter(|(ok, _, _, _)| *ok)
                .map(|(_, _, out, _)| parse_nc_list(&out));
            let summary: Vec<String> = svcs
                .iter()
                .map(|s| {
                    let kind = classify_service(s, nc.as_deref());
                    format!(
                        "{}(dev={}, enabled={}, kind={kind:?})",
                        s.name,
                        if s.device.is_empty() { "-" } else { &s.device },
                        s.enabled
                    )
                })
                .collect();
            lines.push(format!("services: {}", summary.join("; ")));
            if let Some(connections) = nc {
                let nc_summary: Vec<String> = connections
                    .iter()
                    .map(|c| {
                        format!(
                            "{}={}",
                            c.name,
                            if c.connected {
                                "connected"
                            } else {
                                "disconnected"
                            }
                        )
                    })
                    .collect();
                lines.push(format!(
                    "scutil_nc: {}",
                    if nc_summary.is_empty() {
                        "none".to_string()
                    } else {
                        nc_summary.join("; ")
                    }
                ));
            } else {
                lines.push("scutil_nc: unavailable".to_string());
            }
        } else {
            lines.push(format!("services_error: code={code:?} {}", stderr.trim()));
        }
    }
    if let Ok((ok, _, stdout, _)) = run_detailed("scutil", &["--proxy"], "diag_proxy")
        && ok
    {
        let eff = parse_scutil_proxy(&stdout);
        lines.push(format!(
            "scutil_proxy: pac_enabled={:?}, pac_url_present={}",
            eff.pac_enabled,
            eff.pac_url.is_some()
        ));
    }
    lines
}

/// Writes UTF-8 text to the OS clipboard natively without relying on WebView user activation.
pub fn write_text_to_clipboard(text: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        use std::process::Stdio;
        let mut child = crate::sysproxy::silent_command("/usr/bin/pbcopy")
            .env("LANG", "en_US.UTF-8")
            .env("LC_ALL", "en_US.UTF-8")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn pbcopy: {e}"))?;
        let write_res = if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes())
        } else {
            Ok(())
        };
        let out = child
            .wait_with_output()
            .map_err(|e| format!("pbcopy wait failed: {e}"))?;
        write_res.map_err(|e| format!("Failed to write clipboard payload: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(format!("pbcopy failed ({}): {}", out.status, err.trim()))
        }
    }
    #[cfg(target_os = "windows")]
    {
        super::windows::ffi::write_clipboard_unicode(text)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = text;
        Err("Native OS clipboard is not supported on this platform".to_string())
    }
}
