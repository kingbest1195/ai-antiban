//! Windows `advapi32.dll` registry FFI bindings and safe wrappers.

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
    let st =
        unsafe { RegOpenKeyExW(root_handle(root), sub.as_ptr(), 0, sam_desired, &mut handle) };
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

pub fn set_expand_sz(root: RootKey, subkey: &str, name: &str, value: &str) -> Result<(), String> {
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
