//! Native Win32 API wrappers replacing hidden Windows console utilities / LOLBins.
//!
//! All submodules expose cross-platform types and safe Rust APIs so non-Windows targets
//! compile and unit-test pure parsing/SDDL/address helpers cleanly.

pub mod network;
pub mod process;
pub mod service;
pub mod task_scheduler;
pub mod timezone;

/// Explicit SDDL granting Full Access to `SYSTEM` (`SY`) and `Administrators` (`BA`),
/// plus Generic Read/Execute (`GRGX`) to `Authenticated Users` (`AU`).
pub const COWORK_TASK_SDDL: &str = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;AU)";

/// Decodes a NUL-terminated UTF-16 slice (such as `PROCESSENTRY32W.szExeFile` or
/// `DYNAMIC_TIME_ZONE_INFORMATION.TimeZoneKeyName`).
pub fn decode_utf16_nul_slice(units: &[u16]) -> String {
    let len = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..len]).trim().to_string()
}

/// Extracts the file name from a Windows or POSIX path.
pub fn extract_exe_basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Splits a Task Scheduler task path like `Zastava\CoworkVMServiceManualGuard` or
/// `\Zastava\CoworkVMServiceManualGuard` into `(folder, task_name)`.
pub fn split_task_path(full_name: &str) -> (&str, &str) {
    let trimmed = full_name.trim_matches(['\\', '/']);
    match trimmed.rsplit_once(['\\', '/']) {
        Some((folder, name)) if !folder.is_empty() => (folder, name),
        _ => ("", trimmed),
    }
}

/// Returns `true` if `sddl` grants `Authenticated Users` (`AU`) either Full Access (`FA`)
/// or both Generic Read (`GR`) and Generic Execute (`GX`).
pub fn sddl_has_au_read_exec(sddl: &str) -> bool {
    let mut rest = sddl;
    while let Some(start) = rest.find('(') {
        let after = &rest[start + 1..];
        let Some(end) = after.find(')') else {
            break;
        };
        let ace = &after[..end];
        let parts: Vec<&str> = ace.split(';').collect();
        if parts.len() >= 6
            && parts[0].eq_ignore_ascii_case("A")
            && parts[5].eq_ignore_ascii_case("AU")
        {
            let rights = parts[2];
            if rights.contains("FA") || (rights.contains("GR") && rights.contains("GX")) {
                return true;
            }
        }
        rest = &after[end + 1..];
    }
    false
}

/// Ensures `(A;;GRGX;;;AU)` is present in `sddl`, upgrading `(A;;GR;;;AU)` or inserting
/// before any `S:` SACL section when missing.
pub fn ensure_au_read_exec_in_sddl(sddl: &str) -> String {
    if sddl_has_au_read_exec(sddl) {
        return sddl.to_string();
    }
    if sddl.contains("(A;;GR;;;AU)") {
        return sddl.replace("(A;;GR;;;AU)", "(A;;GRGX;;;AU)");
    }
    if let Some(idx) = sddl.find("S:") {
        let (dacl, sacl) = sddl.split_at(idx);
        format!("{dacl}(A;;GRGX;;;AU){sacl}")
    } else {
        format!("{sddl}(A;;GRGX;;;AU)")
    }
}

/// Converts a Win32 network-order IPv4 `u32` (as stored in `MIB_TCPROW_OWNER_PID` / `IN_ADDR`)
/// into `std::net::Ipv4Addr`.
pub fn ipv4_from_win32_u32(raw: u32) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(raw.to_ne_bytes())
}

/// Converts a Win32 TCP table `dwLocalPort` / `dwRemotePort` (`u32` containing network-order
/// `u16` in the low 16 bits) into a host-order `u16`.
pub fn port_from_win32_u32(raw: u32) -> u16 {
    u16::from_be_bytes((raw as u16).to_ne_bytes())
}

#[cfg(target_os = "windows")]
pub(crate) fn encode_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_utf16_nul_slice_and_basenames() {
        let mut units: Vec<u16> = "claude.exe".encode_utf16().collect();
        units.extend([0, 0x1234, 0]);
        assert_eq!(decode_utf16_nul_slice(&units), "claude.exe");
        assert_eq!(
            extract_exe_basename(r"C:\Program Files\Claude\claude.exe"),
            "claude.exe"
        );
        assert_eq!(extract_exe_basename("/usr/bin/claude"), "claude");
    }

    #[test]
    fn splits_task_paths_cleanly() {
        assert_eq!(
            split_task_path(r"Zastava\CoworkVMServiceManualGuard"),
            ("Zastava", "CoworkVMServiceManualGuard")
        );
        assert_eq!(
            split_task_path(r"\Zastava\CoworkVMServiceManualGuard"),
            ("Zastava", "CoworkVMServiceManualGuard")
        );
        assert_eq!(split_task_path("SimpleTask"), ("", "SimpleTask"));
    }

    #[test]
    fn sddl_au_read_exec_is_preserved_or_added() {
        assert!(sddl_has_au_read_exec(COWORK_TASK_SDDL));
        assert!(sddl_has_au_read_exec("D:(A;;FA;;;SY)(A;;FA;;;AU)"));
        assert!(!sddl_has_au_read_exec("D:(A;;FA;;;SY)(A;;GR;;;AU)"));

        assert_eq!(
            ensure_au_read_exec_in_sddl("D:(A;;FA;;;SY)(A;;GR;;;AU)"),
            "D:(A;;FA;;;SY)(A;;GRGX;;;AU)"
        );
        assert_eq!(
            ensure_au_read_exec_in_sddl("D:(A;;FA;;;SY)S:(AU;FA;;;WD)"),
            "D:(A;;FA;;;SY)(A;;GRGX;;;AU)S:(AU;FA;;;WD)"
        );
        assert_eq!(
            ensure_au_read_exec_in_sddl(COWORK_TASK_SDDL),
            COWORK_TASK_SDDL
        );
    }

    #[test]
    fn converts_win32_ipv4_and_port() {
        let raw_ip = u32::from_ne_bytes([127, 0, 0, 1]);
        assert_eq!(
            ipv4_from_win32_u32(raw_ip),
            std::net::Ipv4Addr::new(127, 0, 0, 1)
        );
        let raw_port = u16::from_ne_bytes(8899u16.to_be_bytes()) as u32;
        assert_eq!(port_from_win32_u32(raw_port), 8899);
    }

    #[test]
    fn parses_and_builds_apply_os_tz_cli_args() {
        assert_eq!(timezone::parse_apply_os_tz_cli_args(&[]), None);
        let parsed = timezone::parse_apply_os_tz_cli_args(&[
            "--apply-os-tz".to_string(),
            "W. Europe Standard Time".to_string(),
            "disable".to_string(),
            "--error-file".to_string(),
            r"C:\Temp\tz err.txt".to_string(),
        ])
        .unwrap();
        assert_eq!(parsed.win_tz_id, "W. Europe Standard Time");
        assert_eq!(parsed.auto_tz, Some(false));
        assert_eq!(
            parsed.error_file,
            Some(std::path::PathBuf::from(r"C:\Temp\tz err.txt"))
        );

        let params = timezone::build_apply_os_tz_cli_params(
            "Russian Standard Time",
            Some(true),
            Some(std::path::Path::new("/tmp/tz.err")),
        );
        assert_eq!(
            params,
            "--apply-os-tz \"Russian Standard Time\" enable --error-file \"/tmp/tz.err\""
        );
    }
}
