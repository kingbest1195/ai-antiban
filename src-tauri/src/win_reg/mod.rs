//! Safe Win32 Registry (`advapi32.dll`) wrappers replacing `reg` / `reg.exe` child processes.
//!
//! Spawning console `reg.exe` processes from a GUI-subsystem app during early Windows logon
//! triggers `0xc0000142` (STATUS_DLL_INIT_FAILED) and OEM-codepage corruption on Cyrillic paths.
//! All reads/writes here use Unicode (`*W`) `advapi32` APIs directly in-process.

#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "windows")]
pub use win::{
    delete_value, enum_value_names, get_dword, get_multi_sz, get_string, read_raw, set_dword,
    set_expand_sz, set_sz,
};

#[cfg(test)]
mod tests;

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
