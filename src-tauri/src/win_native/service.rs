//! Native Win32 Service Control Manager (SCM) wrappers.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinServiceStatus {
    pub exists: bool,
    pub running: bool,
    pub start_type: Option<u32>,
    pub current_state: Option<u32>,
}

#[cfg(target_os = "windows")]
mod win {
    use super::WinServiceStatus;
    use crate::win_native::encode_wide_nul;
    use windows::Win32::Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE};
    use windows::Win32::System::Services::{
        ChangeServiceConfigW, CloseServiceHandle, ControlService, ENUM_SERVICE_TYPE,
        OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
        QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
        SERVICE_CHANGE_CONFIG, SERVICE_CONTROL_STOP, SERVICE_ERROR, SERVICE_NO_CHANGE,
        SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_TYPE,
        SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
    };
    use windows::core::PCWSTR;

    struct ScHandleGuard(SC_HANDLE);

    impl Drop for ScHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` was returned by `OpenSCManagerW` or `OpenServiceW`.
                unsafe {
                    let _ = CloseServiceHandle(self.0);
                }
            }
        }
    }

    fn open_scm(access: u32) -> Result<ScHandleGuard, String> {
        // SAFETY: Null machine/database names connect to local active SCM database.
        let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
            .map_err(|e| format!("OpenSCManagerW failed: {e}"))?;
        Ok(ScHandleGuard(scm))
    }

    pub fn query_service_status(service_name: &str) -> Result<WinServiceStatus, String> {
        let scm = open_scm(SC_MANAGER_CONNECT)?;
        let name_w = encode_wide_nul(service_name);
        let svc = match unsafe {
            OpenServiceW(
                scm.0,
                PCWSTR(name_w.as_ptr()),
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            )
        } {
            Ok(h) => ScHandleGuard(h),
            Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => {
                return Ok(WinServiceStatus {
                    exists: false,
                    running: false,
                    start_type: None,
                    current_state: None,
                });
            }
            Err(e) => return Err(format!("OpenServiceW({service_name}) failed: {e}")),
        };

        let mut ssp = SERVICE_STATUS_PROCESS::default();
        let mut bytes_needed = 0u32;
        // SAFETY: `ssp` is stack-allocated and matches `size_of::<SERVICE_STATUS_PROCESS>()`.
        let ssp_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                (&raw mut ssp).cast::<u8>(),
                core::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )
        };
        // SAFETY: `svc.0` has `SERVICE_QUERY_STATUS`; buffer matches `SC_STATUS_PROCESS_INFO`.
        unsafe {
            QueryServiceStatusEx(
                svc.0,
                SC_STATUS_PROCESS_INFO,
                Some(ssp_bytes),
                &mut bytes_needed,
            )
        }
        .map_err(|e| format!("QueryServiceStatusEx({service_name}) failed: {e}"))?;

        let mut cfg_needed = 0u32;
        // SAFETY: Null buffer query returns required byte length for `QUERY_SERVICE_CONFIGW`.
        let _ = unsafe { QueryServiceConfigW(svc.0, None, 0, &mut cfg_needed) };
        let start_type = if cfg_needed >= core::mem::size_of::<QUERY_SERVICE_CONFIGW>() as u32 {
            let word_count = (cfg_needed as usize).div_ceil(core::mem::size_of::<usize>());
            let mut buf = vec![0usize; word_count];
            let ptr = buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
            let mut actual = 0u32;
            // SAFETY: `buf` is pointer-aligned and `cfg_needed`+ bytes long.
            if unsafe { QueryServiceConfigW(svc.0, Some(ptr), cfg_needed, &mut actual) }.is_ok() {
                // SAFETY: `ptr` was populated by `QueryServiceConfigW`.
                Some(unsafe { (*ptr).dwStartType.0 })
            } else {
                None
            }
        } else {
            None
        };

        Ok(WinServiceStatus {
            exists: true,
            running: ssp.dwCurrentState == SERVICE_RUNNING,
            start_type,
            current_state: Some(ssp.dwCurrentState.0),
        })
    }

    pub fn set_service_start_type(service_name: &str, start_type: u32) -> Result<(), String> {
        let scm = open_scm(SC_MANAGER_CONNECT)?;
        let name_w = encode_wide_nul(service_name);
        // SAFETY: `name_w` is NUL-terminated.
        let svc = unsafe { OpenServiceW(scm.0, PCWSTR(name_w.as_ptr()), SERVICE_CHANGE_CONFIG) }
            .map_err(|e| format!("OpenServiceW(CHANGE_CONFIG, {service_name}) failed: {e}"))?;
        let _guard = ScHandleGuard(svc);

        // SAFETY: `SERVICE_NO_CHANGE` leaves all other config fields untouched.
        unsafe {
            ChangeServiceConfigW(
                svc,
                ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                SERVICE_START_TYPE(start_type),
                SERVICE_ERROR(SERVICE_NO_CHANGE),
                PCWSTR::null(),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
        }
        .map_err(|e| format!("ChangeServiceConfigW({service_name}, {start_type}) failed: {e}"))
    }

    pub fn stop_service(service_name: &str) -> Result<(), String> {
        let scm = open_scm(SC_MANAGER_CONNECT)?;
        let name_w = encode_wide_nul(service_name);
        // SAFETY: `name_w` is NUL-terminated.
        let svc = unsafe {
            OpenServiceW(
                scm.0,
                PCWSTR(name_w.as_ptr()),
                SERVICE_STOP | SERVICE_QUERY_STATUS,
            )
        }
        .map_err(|e| format!("OpenServiceW(STOP, {service_name}) failed: {e}"))?;
        let _guard = ScHandleGuard(svc);

        let mut status = SERVICE_STATUS::default();
        // SAFETY: `svc` has `SERVICE_STOP` and `status` is writable.
        match unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut status) } {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERROR_SERVICE_NOT_ACTIVE.to_hresult() => Ok(()),
            Err(e) => Err(format!("ControlService(STOP, {service_name}) failed: {e}")),
        }
    }
}

pub fn query_service_status(service_name: &str) -> Result<WinServiceStatus, String> {
    #[cfg(target_os = "windows")]
    {
        win::query_service_status(service_name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = service_name;
        Ok(WinServiceStatus {
            exists: false,
            running: false,
            start_type: None,
            current_state: None,
        })
    }
}

pub fn set_service_start_type(service_name: &str, start_type: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        win::set_service_start_type(service_name, start_type)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (service_name, start_type);
        Err("set_service_start_type is only supported on Windows".to_string())
    }
}

pub fn stop_service(service_name: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        win::stop_service(service_name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = service_name;
        Err("stop_service is only supported on Windows".to_string())
    }
}
