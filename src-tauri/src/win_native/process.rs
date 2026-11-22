//! Native Win32 process enumeration, image path, command line, and termination.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub exe_name: String,
}

#[cfg(target_os = "windows")]
mod win {
    use super::ProcessEntry;
    use crate::win_native::decode_utf16_nul_slice;
    use core::ffi::c_void;
    use windows::Wdk::System::Threading::{
        NtQueryInformationProcess, ProcessCommandLineInformation,
    };
    use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH, UNICODE_STRING};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        QueryFullProcessImageNameW, TerminateProcess,
    };
    use windows::core::PWSTR;

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

        // SAFETY: Opens target process only for limited query rights.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;
        let _guard = HandleGuard(handle);

        let mut needed: u32 = 0;
        // SAFETY: Null buffer query returns required byte length in `needed`.
        let st = unsafe {
            NtQueryInformationProcess(
                handle,
                ProcessCommandLineInformation,
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
            NtQueryInformationProcess(
                handle,
                ProcessCommandLineInformation,
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
        let buf_start = aligned_buf.as_ptr() as usize;
        let buf_end = buf_start + byte_len as usize;
        let str_ptr = us.Buffer.0 as usize;
        let str_bytes = us.Length as usize;
        if str_ptr < buf_start || str_ptr.saturating_add(str_bytes) > buf_end {
            return Err("NtQueryInformationProcess returned out-of-bounds UNICODE_STRING".into());
        }
        // SAFETY: `us.Buffer` points within `aligned_buf` and has `us.Length / 2` UTF-16 code units.
        let units = unsafe { core::slice::from_raw_parts(us.Buffer.0, str_bytes / 2) };
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
