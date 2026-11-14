//! Safe Win32 Registry (`advapi32.dll`) wrappers replacing `reg` / `reg.exe` child processes.
//!
//! Spawning console `reg.exe` processes from a GUI-subsystem app during early Windows logon
//! triggers `0xc0000142` (STATUS_DLL_INIT_FAILED) and OEM-codepage corruption on Cyrillic paths.
//! All reads/writes here use Unicode (`*W`) `advapi32` APIs directly in-process.

/// Registry hive root supported by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKey {
    /// `HKEY_CURRENT_USER` (`0x80000001`).
    HkeyCurrentUser,
    /// `HKEY_LOCAL_MACHINE` (`0x80000002`).
    HkeyLocalMachine,
}

impl RootKey {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HkeyCurrentUser => "HKCU",
            Self::HkeyLocalMachine => "HKLM",
        }
    }
}

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;

pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;

/// Raw output of `RegGetValueW`: Win32 status code, value type, and raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegRead {
    pub status: u32,
    pub kind: u32,
    pub data: Vec<u8>,
}

/// Returns `true` when a Win32 registry status means the key or value does not exist.
pub fn is_not_found_status(status: u32) -> bool {
    status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
}

/// Encodes `s` as NUL-terminated UTF-16 code units for Win32 `*W` APIs.
pub fn encode_utf16_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Encodes `s` as NUL-terminated little-endian UTF-16 bytes for `RegSetValueExW` (`REG_SZ` / `REG_EXPAND_SZ`).
pub fn encode_utf16_le_bytes(s: &str) -> Vec<u8> {
    encode_utf16_nul(s)
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Decodes little-endian UTF-16 registry bytes into a `String`, stripping trailing NULs.
/// Rejects odd byte lengths and unpaired surrogates so malformed data is never silently repaired.
pub fn decode_utf16_le_string(bytes: &[u8]) -> Result<String, String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("invalid UTF-16 byte length {}", bytes.len()));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16(&units).map_err(|e| format!("invalid UTF-16 sequence: {e}"))?;
    Ok(text.trim_end_matches('\0').to_string())
}

/// Decodes `REG_MULTI_SZ` little-endian UTF-16 bytes into non-empty strings.
pub fn decode_multi_sz(bytes: &[u8]) -> Result<Vec<String>, String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("invalid REG_MULTI_SZ byte length {}", bytes.len()));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut out = Vec::new();
    for segment in units.split(|&u| u == 0) {
        if segment.is_empty() {
            continue;
        }
        let s = String::from_utf16(segment)
            .map_err(|e| format!("invalid UTF-16 in REG_MULTI_SZ: {e}"))?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

/// Decodes a 4-byte little-endian `REG_DWORD` value.
pub fn decode_dword(bytes: &[u8]) -> Result<u32, String> {
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| format!("invalid REG_DWORD byte length {}", bytes.len()))?;
    Ok(u32::from_le_bytes(arr))
}

#[cfg(target_os = "windows")]
mod win {
    use super::*;
    use core::ffi::c_void;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            hkey: *mut c_void,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut *mut c_void,
        ) -> i32;
        fn RegCreateKeyExW(
            hkey: *mut c_void,
            lp_sub_key: *const u16,
            reserved: u32,
            lp_class: *const u16,
            dw_options: u32,
            sam_desired: u32,
            lp_security_attributes: *mut c_void,
            phk_result: *mut *mut c_void,
            lpdw_disposition: *mut u32,
        ) -> i32;
        fn RegGetValueW(
            hkey: *mut c_void,
            lp_sub_key: *const u16,
            lp_value: *const u16,
            dw_flags: u32,
            pdw_type: *mut u32,
            pv_data: *mut c_void,
            pcb_data: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            hkey: *mut c_void,
            lp_value_name: *const u16,
            reserved: u32,
            dw_type: u32,
            lp_data: *const u8,
            cb_data: u32,
        ) -> i32;
        fn RegDeleteValueW(hkey: *mut c_void, lp_value_name: *const u16) -> i32;
        fn RegEnumValueW(
            hkey: *mut c_void,
            dw_index: u32,
            lp_value_name: *mut u16,
            lpcch_value_name: *mut u32,
            lp_reserved: *mut u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
        fn RegCloseKey(hkey: *mut c_void) -> i32;
    }

    // Sign-extended predefined handles matching Windows SDK `winreg.h`.
    const HKEY_CURRENT_USER: *mut c_void = (-2147483647_i32) as isize as *mut c_void;
    const HKEY_LOCAL_MACHINE: *mut c_void = (-2147483646_i32) as isize as *mut c_void;

    const RRF_RT_ANY: u32 = 0x0000_ffff;
    const RRF_NOEXPAND: u32 = 0x1000_0000;
    const KEY_READ: u32 = 0x0002_0019;
    const KEY_SET_VALUE: u32 = 0x0002;
    const REG_OPTION_NON_VOLATILE: u32 = 0;
    const MAX_VALUE_NAME: usize = 16384;

    struct KeyHandle(*mut c_void);

    impl Drop for KeyHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was opened by `RegOpenKeyExW` or `RegCreateKeyExW`.
                unsafe {
                    RegCloseKey(self.0);
                }
            }
        }
    }

    fn root_handle(root: RootKey) -> *mut c_void {
        match root {
            RootKey::HkeyCurrentUser => HKEY_CURRENT_USER,
            RootKey::HkeyLocalMachine => HKEY_LOCAL_MACHINE,
        }
    }

    fn open_key(root: RootKey, subkey: &str, sam_desired: u32) -> Result<KeyHandle, u32> {
        let sub = encode_utf16_nul(subkey);
        let mut handle: *mut c_void = core::ptr::null_mut();
        // SAFETY: `sub` is NUL-terminated; `handle` receives the opened key handle.
        let st = unsafe { RegOpenKeyExW(root_handle(root), sub.as_ptr(), 0, sam_desired, &mut handle) };
        if st == 0 {
            Ok(KeyHandle(handle))
        } else {
            Err(st as u32)
        }
    }

    fn create_key(root: RootKey, subkey: &str, sam_desired: u32) -> Result<KeyHandle, u32> {
        let sub = encode_utf16_nul(subkey);
        let mut handle: *mut c_void = core::ptr::null_mut();
        // SAFETY: `sub` is NUL-terminated; `handle` receives the opened/created key handle.
        let st = unsafe {
            RegCreateKeyExW(
                root_handle(root),
                sub.as_ptr(),
                0,
                core::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                sam_desired,
                core::ptr::null_mut(),
                &mut handle,
                core::ptr::null_mut(),
            )
        };
        if st == 0 {
            Ok(KeyHandle(handle))
        } else {
            Err(st as u32)
        }
    }

    fn set_raw_value(
        root: RootKey,
        subkey: &str,
        name: &str,
        reg_type: u32,
        bytes: &[u8],
    ) -> Result<(), String> {
        let key = create_key(root, subkey, KEY_SET_VALUE).map_err(|st| {
            format!(
                "RegCreateKeyExW({}\\{}) failed with Win32 error {}",
                root.as_str(),
                subkey,
                st
            )
        })?;
        let val_name = encode_utf16_nul(name);
        let cb_data = u32::try_from(bytes.len())
            .map_err(|_| format!("registry value too large ({} bytes)", bytes.len()))?;
        // SAFETY: `key.0` is an open handle, `val_name` is NUL-terminated, `bytes` has `cb_data` bytes.
        let st = unsafe {
            RegSetValueExW(
                key.0,
                val_name.as_ptr(),
                0,
                reg_type,
                bytes.as_ptr(),
                cb_data,
            )
        };
        if st == 0 {
            Ok(())
        } else {
            Err(format!(
                "RegSetValueExW({}\\{}\\{}) failed with Win32 error {}",
                root.as_str(),
                subkey,
                name,
                st as u32
            ))
        }
    }

    /// Reads raw registry value bytes and type via `RegGetValueW` (without expanding `REG_EXPAND_SZ`).
    pub fn read_raw(root: RootKey, subkey: &str, name: &str) -> RegRead {
        let hroot = root_handle(root);
        let sub = encode_utf16_nul(subkey);
        let nm = encode_utf16_nul(name);
        let flags = RRF_RT_ANY | RRF_NOEXPAND;
        let mut kind = 0u32;
        let mut size = 0u32;
        // SAFETY: both strings are NUL-terminated; null `pv_data` queries buffer size.
        let st = unsafe {
            RegGetValueW(
                hroot,
                sub.as_ptr(),
                nm.as_ptr(),
                flags,
                &mut kind,
                core::ptr::null_mut(),
                &mut size,
            )
        };
        if st != 0 {
            return RegRead {
                status: st as u32,
                kind: 0,
                data: Vec::new(),
            };
        }
        for _ in 0..4 {
            if size == 0 {
                return RegRead {
                    status: ERROR_SUCCESS,
                    kind,
                    data: Vec::new(),
                };
            }
            let mut buf = vec![0u8; size as usize];
            let mut cb = size;
            // SAFETY: `buf` has `cb` writable bytes; `sub` and `nm` are NUL-terminated.
            let st = unsafe {
                RegGetValueW(
                    hroot,
                    sub.as_ptr(),
                    nm.as_ptr(),
                    flags,
                    &mut kind,
                    buf.as_mut_ptr().cast(),
                    &mut cb,
                )
            };
            match st as u32 {
                ERROR_SUCCESS => {
                    buf.truncate(cb as usize);
                    return RegRead {
                        status: ERROR_SUCCESS,
                        kind,
                        data: buf,
                    };
                }
                ERROR_MORE_DATA => size = cb.max(size.saturating_add(2)),
                other => {
                    return RegRead {
                        status: other,
                        kind: 0,
                        data: Vec::new(),
                    };
                }
            }
        }
        RegRead {
            status: ERROR_MORE_DATA,
            kind: 0,
            data: Vec::new(),
        }
    }

    pub fn get_string(root: RootKey, subkey: &str, name: &str) -> Result<Option<String>, String> {
        let raw = read_raw(root, subkey, name);
        if is_not_found_status(raw.status) {
            return Ok(None);
        }
        if raw.status != ERROR_SUCCESS {
            return Err(format!(
                "RegGetValueW({}\\{}\\{}) failed with Win32 error {}",
                root.as_str(),
                subkey,
                name,
                raw.status
            ));
        }
        if raw.kind != REG_SZ && raw.kind != REG_EXPAND_SZ {
            return Err(format!(
                "RegGetValueW({}\\{}\\{}) unexpected type {}",
                root.as_str(),
                subkey,
                name,
                raw.kind
            ));
        }
        decode_utf16_le_string(&raw.data).map(Some)
    }

    pub fn get_dword(root: RootKey, subkey: &str, name: &str) -> Result<Option<u32>, String> {
        let raw = read_raw(root, subkey, name);
        if is_not_found_status(raw.status) {
            return Ok(None);
        }
        if raw.status != ERROR_SUCCESS {
            return Err(format!(
                "RegGetValueW({}\\{}\\{}) failed with Win32 error {}",
                root.as_str(),
                subkey,
                name,
                raw.status
            ));
        }
        if raw.kind != REG_DWORD {
            return Err(format!(
                "RegGetValueW({}\\{}\\{}) expected REG_DWORD, got type {}",
                root.as_str(),
                subkey,
                name,
                raw.kind
            ));
        }
        decode_dword(&raw.data).map(Some)
    }

    pub fn get_multi_sz(
        root: RootKey,
        subkey: &str,
        name: &str,
    ) -> Result<Option<Vec<String>>, String> {
        let raw = read_raw(root, subkey, name);
        if is_not_found_status(raw.status) {
            return Ok(None);
        }
        if raw.status != ERROR_SUCCESS {
            return Err(format!(
                "RegGetValueW({}\\{}\\{}) failed with Win32 error {}",
                root.as_str(),
                subkey,
                name,
                raw.status
            ));
        }
        match raw.kind {
            REG_MULTI_SZ => decode_multi_sz(&raw.data).map(Some),
            REG_SZ | REG_EXPAND_SZ => {
                let single = decode_utf16_le_string(&raw.data)?;
                let trimmed = single.trim();
                Ok(Some(if trimmed.is_empty() {
                    Vec::new()
                } else {
                    vec![trimmed.to_string()]
                }))
            }
            other => Err(format!(
                "RegGetValueW({}\\{}\\{}) expected REG_MULTI_SZ, got type {}",
                root.as_str(),
                subkey,
                name,
                other
            )),
        }
    }

    pub fn set_sz(root: RootKey, subkey: &str, name: &str, value: &str) -> Result<(), String> {
        let bytes = encode_utf16_le_bytes(value);
        set_raw_value(root, subkey, name, REG_SZ, &bytes)
    }

    pub fn set_expand_sz(
        root: RootKey,
        subkey: &str,
        name: &str,
        value: &str,
    ) -> Result<(), String> {
        let bytes = encode_utf16_le_bytes(value);
        set_raw_value(root, subkey, name, REG_EXPAND_SZ, &bytes)
    }

    pub fn set_dword(root: RootKey, subkey: &str, name: &str, value: u32) -> Result<(), String> {
        set_raw_value(root, subkey, name, REG_DWORD, &value.to_le_bytes())
    }

    pub fn delete_value(root: RootKey, subkey: &str, name: &str) -> Result<(), String> {
        let key = match open_key(root, subkey, KEY_SET_VALUE) {
            Ok(k) => k,
            Err(st) if is_not_found_status(st) => return Ok(()),
            Err(st) => {
                return Err(format!(
                    "RegOpenKeyExW({}\\{}) failed with Win32 error {}",
                    root.as_str(),
                    subkey,
                    st
                ));
            }
        };
        let val_name = encode_utf16_nul(name);
        // SAFETY: `key.0` is valid and `val_name` is NUL-terminated.
        let st = unsafe { RegDeleteValueW(key.0, val_name.as_ptr()) } as u32;
        if st == ERROR_SUCCESS || is_not_found_status(st) {
            Ok(())
        } else {
            Err(format!(
                "RegDeleteValueW({}\\{}\\{}) failed with Win32 error {}",
                root.as_str(),
                subkey,
                name,
                st
            ))
        }
    }

    pub fn enum_value_names(root: RootKey, subkey: &str) -> Result<Vec<String>, String> {
        let key = match open_key(root, subkey, KEY_READ) {
            Ok(k) => k,
            Err(st) => {
                return Err(format!(
                    "RegOpenKeyExW({}\\{}) failed with Win32 error {}",
                    root.as_str(),
                    subkey,
                    st
                ));
            }
        };
        let mut names = Vec::new();
        let mut buf = vec![0u16; MAX_VALUE_NAME];
        for index in 0u32.. {
            let mut len = buf.len() as u32;
            // SAFETY: `buf` has room for `len` UTF-16 code units; optional outputs are null.
            let st = unsafe {
                RegEnumValueW(
                    key.0,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            } as u32;
            match st {
                ERROR_SUCCESS => {
                    if let Ok(s) = String::from_utf16(&buf[..len as usize]) {
                        names.push(s);
                    }
                }
                ERROR_NO_MORE_ITEMS => break,
                other => {
                    return Err(format!(
                        "RegEnumValueW({}\\{}) failed with Win32 error {}",
                        root.as_str(),
                        subkey,
                        other
                    ));
                }
            }
        }
        Ok(names)
    }
}

#[cfg(target_os = "windows")]
pub use win::{
    delete_value, enum_value_names, get_dword, get_multi_sz, get_string, read_raw, set_dword,
    set_expand_sz, set_sz,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_round_trip_preserves_cyrillic_paths_and_nul_terminator() {
        let path = r#"file:///C:/Users/Иван Петров/AppData/Local/Zastava/proxy.pac"#;
        let units = encode_utf16_nul(path);
        assert_eq!(units.last(), Some(&0));

        let bytes = encode_utf16_le_bytes(path);
        assert_eq!(bytes.len(), units.len() * 2);
        assert_eq!(decode_utf16_le_string(&bytes).unwrap(), path);
    }

    #[test]
    fn decode_utf16_handles_empty_extra_nuls_and_rejects_malformed() {
        assert_eq!(decode_utf16_le_string(&[]).unwrap(), "");
        assert_eq!(decode_utf16_le_string(&[0, 0]).unwrap(), "");
        assert_eq!(decode_utf16_le_string(&[0x41, 0x00, 0, 0, 0, 0]).unwrap(), "A");
        // Odd byte length
        assert!(decode_utf16_le_string(&[0x41, 0x00, 0x42]).is_err());
        // Unpaired UTF-16 high surrogate
        assert!(decode_utf16_le_string(&[0x00, 0xD8, 0x00, 0x00]).is_err());
    }

    #[test]
    fn decode_multi_sz_extracts_items_and_skips_empty_terminators() {
        let mut bytes = Vec::new();
        for item in ["ru-RU", "en-US", "  ", "de-DE"] {
            bytes.extend(encode_utf16_le_bytes(item));
        }
        bytes.extend([0, 0]);
        assert_eq!(
            decode_multi_sz(&bytes).unwrap(),
            vec!["ru-RU".to_string(), "en-US".to_string(), "de-DE".to_string()]
        );
        assert!(decode_multi_sz(&[0x41]).is_err());
    }

    #[test]
    fn decode_dword_requires_four_bytes() {
        assert_eq!(decode_dword(&3u32.to_le_bytes()).unwrap(), 3);
        assert_eq!(decode_dword(&0xdead_beefu32.to_le_bytes()).unwrap(), 0xdead_beef);
        assert!(decode_dword(&[1, 2, 3]).is_err());
    }

    #[test]
    fn not_found_statuses_and_root_names() {
        assert!(is_not_found_status(ERROR_FILE_NOT_FOUND));
        assert!(is_not_found_status(ERROR_PATH_NOT_FOUND));
        assert!(!is_not_found_status(ERROR_SUCCESS));
        assert!(!is_not_found_status(5));
        assert_eq!(RootKey::HkeyCurrentUser.as_str(), "HKCU");
        assert_eq!(RootKey::HkeyLocalMachine.as_str(), "HKLM");
    }
}
