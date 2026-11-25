//! Native Win32 process enumeration, image path, command line, and termination.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub exe_name: String,
}

#[cfg(target_os = "windows")]
mod win {
    use super::{ProcessEntry, validate_unicode_string_span};
    use crate::win_native::decode_utf16_nul_slice;
    use core::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH, NTSTATUS, UNICODE_STRING};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        QueryFullProcessImageNameW, TerminateProcess,
    };
    use windows::core::PWSTR;

    const PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;

    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        process_handle: HANDLE,
        process_information_class: i32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(lp_module_name: *const u16) -> *mut c_void;
        fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *const c_void;
    }

    /// Resolves `NtQueryInformationProcess` dynamically from already-loaded `ntdll.dll` on demand,
    /// avoiding a static WDK IAT import entry while keeping Clean Room behavior intact.
    fn resolve_nt_query_information_process() -> Result<NtQueryInformationProcessFn, String> {
        let ntdll_w = crate::win_native::encode_wide_nul("ntdll.dll");
        // SAFETY: `ntdll_w` is NUL-terminated and `ntdll.dll` is loaded in every Win32 process.
        let hmod = unsafe { GetModuleHandleW(ntdll_w.as_ptr()) };
        if hmod.is_null() {
            return Err("GetModuleHandleW(ntdll.dll) returned null".to_string());
        }
        // SAFETY: `hmod` is a valid module handle and the symbol name is NUL-terminated ASCII.
        let sym =
            unsafe { GetProcAddress(hmod, c"NtQueryInformationProcess".as_ptr().cast::<u8>()) };
        if sym.is_null() {
            return Err("GetProcAddress(NtQueryInformationProcess) returned null".to_string());
        }
        // SAFETY: `NtQueryInformationProcess` matches `NtQueryInformationProcessFn` on Windows.
        Ok(unsafe { core::mem::transmute::<*const c_void, NtQueryInformationProcessFn>(sym) })
    }

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` is an owned Win32 handle from `CreateToolhelp32Snapshot` or `OpenProcess`.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub fn list_processes() -> Result<Vec<ProcessEntry>, String> {
        // SAFETY: `TH32CS_SNAPPROCESS` with pid 0 snapshots all processes on the system.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|e| format!("CreateToolhelp32Snapshot failed: {e}"))?;
        let _guard = HandleGuard(snap);

        let mut entry = PROCESSENTRY32W {
            dwSize: core::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut out = Vec::new();
        // SAFETY: `entry.dwSize` is initialized to `size_of::<PROCESSENTRY32W>()`.
        if unsafe { Process32FirstW(snap, &mut entry) }.is_err() {
            return Ok(out);
        }
        loop {
            out.push(ProcessEntry {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
                exe_name: decode_utf16_nul_slice(&entry.szExeFile),
            });
            // SAFETY: `snap` is valid and `entry.dwSize` remains initialized.
            if unsafe { Process32NextW(snap, &mut entry) }.is_err() {
                break;
            }
        }
        Ok(out)
    }

    pub fn query_process_image_path(pid: u32) -> Result<String, String> {
        // SAFETY: Opens target process only for limited query rights (no VM read required).
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;
        let _guard = HandleGuard(handle);

        let mut buf = vec![0u16; MAX_PATH as usize * 4];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` has `len` writable UTF-16 code units.
        unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        }
        .map_err(|e| format!("QueryFullProcessImageNameW({pid}) failed: {e}"))?;
        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    }

    pub fn query_process_command_line(pid: u32) -> Result<Option<String>, String> {
        const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
        const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;
        const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;

        let nt_query = resolve_nt_query_information_process()?;

        // SAFETY: Opens target process only for limited query rights.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;
        let _guard = HandleGuard(handle);

        let mut needed: u32 = 0;
        // SAFETY: Null buffer query returns required byte length in `needed`.
        let st = unsafe {
            nt_query(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                core::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if st.0 != STATUS_INFO_LENGTH_MISMATCH
            && st.0 != STATUS_BUFFER_TOO_SMALL
            && st.0 != STATUS_BUFFER_OVERFLOW
        {
            if st.0 < 0 {
                return Err(format!(
                    "NtQueryInformationProcess({pid}) failed: 0x{:08X}",
                    st.0 as u32
                ));
            }
            return Ok(None);
        }
        if needed < core::mem::size_of::<UNICODE_STRING>() as u32 {
            return Ok(None);
        }

        let word_count = (needed as usize).div_ceil(core::mem::size_of::<usize>());
        let mut aligned_buf = vec![0usize; word_count];
        let byte_len = (word_count * core::mem::size_of::<usize>()) as u32;
        let mut ret_len: u32 = 0;
        // SAFETY: `aligned_buf` is pointer-aligned and `byte_len` bytes long.
        let st2 = unsafe {
            nt_query(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                aligned_buf.as_mut_ptr().cast::<c_void>(),
                byte_len,
                &mut ret_len,
            )
        };
        if st2.0 < 0 {
            return Err(format!(
                "NtQueryInformationProcess({pid}) read failed: 0x{:08X}",
                st2.0 as u32
            ));
        }

        // SAFETY: Buffer starts with `UNICODE_STRING` whose `Buffer` points inside `aligned_buf`.
        let us = unsafe { &*(aligned_buf.as_ptr().cast::<UNICODE_STRING>()) };
        if us.Buffer.is_null() || us.Length == 0 {
            return Ok(None);
        }
        let unit_count = validate_unicode_string_span(
            aligned_buf.as_ptr() as usize,
            byte_len as usize,
            us.Buffer.0 as usize,
            us.Length as usize,
        )?;
        // SAFETY: `us.Buffer` points within `aligned_buf` and has `unit_count` UTF-16 code units.
        let units = unsafe { core::slice::from_raw_parts(us.Buffer.0, unit_count) };
        Ok(Some(String::from_utf16_lossy(units)))
    }

    pub fn terminate_process_by_pid(pid: u32, exit_code: u32) -> Result<(), String> {
        // SAFETY: Opens target process for termination.
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }
            .map_err(|e| format!("OpenProcess(TERMINATE, {pid}) failed: {e}"))?;
        let _guard = HandleGuard(handle);
        // SAFETY: `handle` is valid and owned.
        unsafe { TerminateProcess(handle, exit_code) }
            .map_err(|e| format!("TerminateProcess({pid}) failed: {e}"))
    }
}

pub fn list_processes() -> Result<Vec<ProcessEntry>, String> {
    #[cfg(target_os = "windows")]
    {
        win::list_processes()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(Vec::new())
    }
}

pub fn find_pids_by_exe_name(exe_name: &str) -> Result<Vec<u32>, String> {
    let target = super::extract_exe_basename(exe_name);
    let list = list_processes()?;
    Ok(list
        .into_iter()
        .filter(|p| super::extract_exe_basename(&p.exe_name).eq_ignore_ascii_case(target))
        .map(|p| p.pid)
        .collect())
}

pub fn is_process_running_by_name(exe_name: &str) -> bool {
    find_pids_by_exe_name(exe_name).is_ok_and(|pids| !pids.is_empty())
}

pub fn query_process_image_path(pid: u32) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        win::query_process_image_path(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        Err("query_process_image_path is only supported on Windows".to_string())
    }
}

pub fn query_process_command_line(pid: u32) -> Result<Option<String>, String> {
    #[cfg(target_os = "windows")]
    {
        win::query_process_command_line(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        Ok(None)
    }
}

pub fn terminate_process_by_pid(pid: u32, exit_code: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        win::terminate_process_by_pid(pid, exit_code)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (pid, exit_code);
        Err("terminate_process_by_pid is only supported on Windows".to_string())
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn validate_unicode_string_span(
    buf_start: usize,
    byte_len: usize,
    str_ptr: usize,
    str_bytes: usize,
) -> Result<usize, String> {
    let Some(buf_end) = buf_start.checked_add(byte_len) else {
        return Err("NtQueryInformationProcess buffer span overflow".into());
    };
    let Some(str_end) = str_ptr.checked_add(str_bytes) else {
        return Err("NtQueryInformationProcess UNICODE_STRING span overflow".into());
    };
    if str_ptr < buf_start || str_end > buf_end {
        return Err("NtQueryInformationProcess returned out-of-bounds UNICODE_STRING".into());
    }
    Ok(str_bytes / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_unicode_string_command_line_spans() {
        assert_eq!(validate_unicode_string_span(1000, 64, 1016, 20), Ok(10));
        assert!(validate_unicode_string_span(1000, 64, 992, 16).is_err());
        assert!(validate_unicode_string_span(1000, 64, 1056, 16).is_err());
        assert!(validate_unicode_string_span(1000, 64, usize::MAX - 4, 16).is_err());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_command_line_query_is_noop() {
        assert_eq!(query_process_command_line(1234), Ok(None));
    }
}
