//! Windows registry parsing, Win32 registry access, and FFI for WinINet / clipboard.

use super::{PResult, PlatformError, RegKind, RegValue};

/// Registry keys below `HKEY_CURRENT_USER`, accessed through Win32 `advapi32` FFI (`crate::win_reg`).
pub(super) const INET_SUBKEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
pub(super) const ENV_SUBKEY: &str = "Environment";

/// `reg query <key> /v <name>` -> value with exact type. `None` = no such value.
/// Not used by `RealPlatform` any more (it reads the registry through the API, see
/// [`reg_read_outcome`]): `reg.exe` prints in the OEM code page.
pub fn parse_reg_query_value(output: &str, name: &str) -> Option<RegValue> {
    for line in output.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix(name) else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let rest = rest.trim_start();
        for (tag, kind) in [
            ("REG_EXPAND_SZ", RegKind::ExpandSz),
            ("REG_SZ", RegKind::Sz),
            ("REG_DWORD", RegKind::Dword),
        ] {
            if let Some(data) = rest.strip_prefix(tag) {
                if !(data.is_empty() || data.starts_with(char::is_whitespace)) {
                    continue;
                }
                let data = data
                    .strip_prefix("    ")
                    .unwrap_or_else(|| data.trim_start());
                return match kind {
                    RegKind::Dword => {
                        let d = data.trim();
                        let n = d
                            .strip_prefix("0x")
                            .or_else(|| d.strip_prefix("0X"))
                            .map(|h| u32::from_str_radix(h, 16))
                            .unwrap_or_else(|| d.parse::<u32>());
                        n.ok().map(RegValue::dword)
                    }
                    _ => Some(RegValue {
                        kind,
                        data: data.to_string(),
                    }),
                };
            }
        }
    }
    None
}

/// `reg query <key>` (all values) -> value names, whatever their type.
pub fn parse_reg_query_names(output: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in output.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        // Value lines are indented; key lines (`HKEY_...`) are not.
        if !line.starts_with(char::is_whitespace) {
            continue;
        }
        let t = line.trim_start();
        let mut it = t.split_whitespace();
        let (Some(name), Some(tag)) = (it.next(), it.next()) else {
            continue;
        };
        if tag.starts_with("REG_") {
            names.push(name.to_string());
        }
    }
    names
}

// Registry value types and status codes of the Windows API (winerror.h / winnt.h).
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const ERROR_SUCCESS: u32 = 0;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;

/// UTF-16LE bytes -> text. `None` for an odd length or an unpaired surrogate: such a string cannot
/// be written back unchanged, so it is never decoded lossily.
fn utf16le_to_string(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Turns the raw answer of the registry API (`RegGetValueW`: status, value type, data) into a
/// [`RegValue`] with its exact type. `Ok(None)` is "no such value" and only the two "not found"
/// codes mean that; any other failure is an error, so a failed read is never taken for an absent
/// value (a restore would delete what it should not). `REG_SZ` / `REG_EXPAND_SZ` / `REG_DWORD`
/// are the types Zastava can write back unchanged; everything else (`REG_BINARY`, `REG_MULTI_SZ`,
/// `REG_QWORD`, ...) is `Unsupported`.
pub fn reg_read_outcome(
    status: u32,
    kind: u32,
    data: &[u8],
    op: &'static str,
) -> PResult<Option<RegValue>> {
    match status {
        ERROR_SUCCESS => {}
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => return Ok(None),
        _ => return Err(PlatformError::Failed(op)),
    }
    match kind {
        REG_SZ | REG_EXPAND_SZ => {
            let text = utf16le_to_string(data).ok_or(PlatformError::Unsupported(op))?;
            // The API terminates strings with NUL; a stored value may carry extra ones.
            let text = text.trim_end_matches('\0').to_string();
            Ok(Some(RegValue {
                kind: if kind == REG_SZ {
                    RegKind::Sz
                } else {
                    RegKind::ExpandSz
                },
                data: text,
            }))
        }
        REG_DWORD => {
            let bytes: [u8; 4] = data
                .try_into()
                .map_err(|_| PlatformError::Unsupported(op))?;
            Ok(Some(RegValue::dword(u32::from_le_bytes(bytes))))
        }
        _ => Err(PlatformError::Unsupported(op)),
    }
}

/// One value of `HKEY_CURRENT_USER\<subkey>`, read through the registry API.
#[cfg(target_os = "windows")]
pub(super) fn registry_get(subkey: &str, name: &str, op: &'static str) -> PResult<Option<RegValue>> {
    let r = crate::win_reg::read_raw(crate::win_reg::RootKey::HkeyCurrentUser, subkey, name);
    reg_read_outcome(r.status, r.kind, &r.data, op)
}

#[cfg(not(target_os = "windows"))]
pub(super) fn registry_get(
    _subkey: &str,
    _name: &str,
    op: &'static str,
) -> PResult<Option<RegValue>> {
    Err(PlatformError::Unsupported(op))
}

/// Names of all values of `HKEY_CURRENT_USER\<subkey>`, whatever their type. A name that is not
/// valid UTF-16 is left out (it cannot be one of ours).
#[cfg(target_os = "windows")]
pub(super) fn registry_names(subkey: &str, op: &'static str) -> PResult<Vec<String>> {
    crate::win_reg::enum_value_names(crate::win_reg::RootKey::HkeyCurrentUser, subkey).map_err(
        |err| {
            let summary = format!("{op}: {err}");
            crate::diagnostics::record("sysproxy", &summary);
            super::diagnostics::set_last_os_error(Some(summary));
            PlatformError::Failed(op)
        },
    )
}

#[cfg(not(target_os = "windows"))]
pub(super) fn registry_names(_subkey: &str, op: &'static str) -> PResult<Vec<String>> {
    Err(PlatformError::Unsupported(op))
}

#[cfg(target_os = "windows")]
fn record_reg_error(op: &'static str, err: &str) -> PlatformError {
    let summary = format!("{op}: {err}");
    crate::diagnostics::record("sysproxy", &summary);
    super::diagnostics::set_last_os_error(Some(summary));
    PlatformError::Failed(op)
}

#[cfg(target_os = "windows")]
pub(super) fn registry_set_sz(
    subkey: &str,
    name: &str,
    value: &str,
    op: &'static str,
) -> PResult<()> {
    crate::win_reg::set_sz(
        crate::win_reg::RootKey::HkeyCurrentUser,
        subkey,
        name,
        value,
    )
    .map(|()| super::clear_last_os_error())
    .map_err(|err| record_reg_error(op, &err))
}

#[cfg(not(target_os = "windows"))]
pub(super) fn registry_set_sz(
    _subkey: &str,
    _name: &str,
    _value: &str,
    op: &'static str,
) -> PResult<()> {
    Err(PlatformError::Unsupported(op))
}

#[cfg(target_os = "windows")]
pub(super) fn registry_set_value(
    subkey: &str,
    name: &str,
    value: &RegValue,
    op: &'static str,
) -> PResult<()> {
    let root = crate::win_reg::RootKey::HkeyCurrentUser;
    let res = match value.kind {
        RegKind::Sz => crate::win_reg::set_sz(root, subkey, name, &value.data),
        RegKind::ExpandSz => crate::win_reg::set_expand_sz(root, subkey, name, &value.data),
        RegKind::Dword => {
            let n = value
                .data
                .trim()
                .parse::<u32>()
                .map_err(|e| format!("invalid REG_DWORD value for {name}: {e}"))
                .map_err(|err| record_reg_error(op, &err))?;
            crate::win_reg::set_dword(root, subkey, name, n)
        }
    };
    res.map(|()| super::clear_last_os_error())
        .map_err(|err| record_reg_error(op, &err))
}

#[cfg(not(target_os = "windows"))]
pub(super) fn registry_set_value(
    _subkey: &str,
    _name: &str,
    _value: &RegValue,
    op: &'static str,
) -> PResult<()> {
    Err(PlatformError::Unsupported(op))
}

#[cfg(target_os = "windows")]
pub(super) fn registry_delete(subkey: &str, name: &str, op: &'static str) -> PResult<()> {
    crate::win_reg::delete_value(crate::win_reg::RootKey::HkeyCurrentUser, subkey, name)
        .map(|()| super::clear_last_os_error())
        .map_err(|err| record_reg_error(op, &err))
}

#[cfg(not(target_os = "windows"))]
pub(super) fn registry_delete(_subkey: &str, _name: &str, op: &'static str) -> PResult<()> {
    Err(PlatformError::Unsupported(op))
}

/// Windows FFI: the WinINet refresh, the environment broadcast, and clipboard writes
/// (registry operations live in `crate::win_reg`). Compiled and verified only by the Windows CI job.
#[cfg(target_os = "windows")]
pub(super) mod ffi {
    pub fn inet_refresh() {
        #[link(name = "wininet")]
        unsafe extern "system" {
            fn InternetSetOptionW(
                hInternet: *mut core::ffi::c_void,
                dwOption: u32,
                lpBuffer: *mut core::ffi::c_void,
                dwBufferLength: u32,
            ) -> i32;
        }
        const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
        const INTERNET_OPTION_REFRESH: u32 = 37;
        unsafe {
            let _ = InternetSetOptionW(
                core::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                core::ptr::null_mut(),
                0,
            );
            let _ = InternetSetOptionW(
                core::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                core::ptr::null_mut(),
                0,
            );
        }
    }

    pub fn env_broadcast() {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn SendMessageTimeoutW(
                hWnd: *mut core::ffi::c_void,
                Msg: u32,
                wParam: usize,
                lParam: *const u16,
                fuFlags: u32,
                uTimeout: u32,
                lpdwResult: *mut usize,
            ) -> isize;
            fn SendMessageTimeoutA(
                hWnd: *mut core::ffi::c_void,
                Msg: u32,
                wParam: usize,
                lParam: *const u8,
                fuFlags: u32,
                uTimeout: u32,
                lpdwResult: *mut usize,
            ) -> isize;
        }
        const HWND_BROADCAST: *mut core::ffi::c_void = 0xffff as *mut core::ffi::c_void;
        const WM_SETTINGCHANGE: u32 = 0x001A;
        const SMTO_ABORTIFHUNG: u32 = 0x0002;
        let env_wide: Vec<u16> = "Environment\0".encode_utf16().collect();
        let env_ansi: &[u8] = b"Environment\0";
        let mut dw_result: usize = 0;
        unsafe {
            let _ = SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                env_wide.as_ptr(),
                SMTO_ABORTIFHUNG,
                2000,
                &mut dw_result,
            );
            let _ = SendMessageTimeoutA(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                env_ansi.as_ptr(),
                SMTO_ABORTIFHUNG,
                2000,
                &mut dw_result,
            );
        }
    }

    pub fn write_clipboard_unicode(text: &str) -> Result<(), String> {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn OpenClipboard(h_wnd_new_owner: *mut core::ffi::c_void) -> i32;
            fn EmptyClipboard() -> i32;
            fn SetClipboardData(
                u_format: u32,
                h_mem: *mut core::ffi::c_void,
            ) -> *mut core::ffi::c_void;
            fn CloseClipboard() -> i32;
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GlobalAlloc(u_flags: u32, dw_bytes: usize) -> *mut core::ffi::c_void;
            fn GlobalLock(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
            fn GlobalUnlock(h_mem: *mut core::ffi::c_void) -> i32;
            fn GlobalFree(h_mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        }
        const CF_UNICODETEXT: u32 = 13;
        const GMEM_MOVEABLE: u32 = 0x0002;

        let utf16: Vec<u16> = text.encode_utf16().chain(core::iter::once(0)).collect();
        let byte_len = utf16
            .len()
            .checked_mul(core::mem::size_of::<u16>())
            .ok_or_else(|| "Clipboard text too large".to_string())?;

        unsafe {
            let mut opened = false;
            for attempt in 0..3 {
                if OpenClipboard(core::ptr::null_mut()) != 0 {
                    opened = true;
                    break;
                }
                if attempt < 2 {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            if !opened {
                return Err("OpenClipboard failed".to_string());
            }
            if EmptyClipboard() == 0 {
                let _ = CloseClipboard();
                return Err("EmptyClipboard failed".to_string());
            }
            let h_mem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
            if h_mem.is_null() {
                let _ = CloseClipboard();
                return Err("GlobalAlloc failed".to_string());
            }
            let ptr = GlobalLock(h_mem) as *mut u16;
            if ptr.is_null() {
                let _ = GlobalFree(h_mem);
                let _ = CloseClipboard();
                return Err("GlobalLock failed".to_string());
            }
            core::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
            let _ = GlobalUnlock(h_mem);
            let res = SetClipboardData(CF_UNICODETEXT, h_mem);
            let _ = CloseClipboard();
            if res.is_null() {
                let _ = GlobalFree(h_mem);
                return Err("SetClipboardData failed".to_string());
            }
        }
        Ok(())
    }
}
