//! In-process COM Task Scheduler 2.0 (`Schedule.Service`) wrappers.

/// `OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION` (0x7),
/// intentionally omitting `SACL_SECURITY_INFORMATION` (0x8) which requires `SeSecurityPrivilege`.
pub const SECURITY_INFO_NO_SACL: i32 = 0x7;

#[cfg(target_os = "windows")]
mod win {
    use crate::win_native::ensure_au_read_exec_in_sddl;
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, RPC_E_CHANGED_MODE,
        S_FALSE, S_OK,
    };
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{
        ITaskFolder, ITaskService, TASK_CREATE_OR_UPDATE, TASK_LOGON_SERVICE_ACCOUNT, TaskScheduler,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::core::BSTR;

    struct ComGuard {
        should_uninit: bool,
    }

    impl ComGuard {
        fn init() -> Result<Self, String> {
            // SAFETY: Initializes COM apartment for the current thread.
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if hr == S_OK || hr == S_FALSE {
                Ok(Self {
                    should_uninit: true,
                })
            } else if hr == RPC_E_CHANGED_MODE {
                Ok(Self {
                    should_uninit: false,
                })
            } else {
                Err(format!("CoInitializeEx failed: 0x{:08X}", hr.0 as u32))
            }
        }
    }

    impl Drop for ComGuard {
        fn drop(&mut self) {
            if self.should_uninit {
                // SAFETY: Matches successful `CoInitializeEx` on this thread.
                unsafe { CoUninitialize() };
            }
        }
    }

    fn is_not_found(err: &windows::core::Error) -> bool {
        let code = err.code();
        code == ERROR_FILE_NOT_FOUND.to_hresult() || code == ERROR_PATH_NOT_FOUND.to_hresult()
    }

    fn is_access_denied(err: &windows::core::Error) -> bool {
        err.code() == ERROR_ACCESS_DENIED.to_hresult()
    }

    fn normalize_folder_path(folder_path: &str) -> String {
        let trimmed = folder_path.trim().trim_matches(['\\', '/']);
        if trimmed.is_empty() {
            r"\".to_string()
        } else {
            format!(r"\{trimmed}")
        }
    }

    fn connect_service() -> Result<(ComGuard, ITaskService), String> {
        let guard = ComGuard::init()?;
        // SAFETY: `TaskScheduler` CLSID is an in-process COM server.
        let service: ITaskService =
            unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| format!("CoCreateInstance(TaskScheduler) failed: {e}"))?;
        let empty = VARIANT::default();
        // SAFETY: Empty VARIANTs connect to local Task Scheduler service.
        unsafe { service.Connect(&empty, &empty, &empty, &empty) }
            .map_err(|e| format!("ITaskService::Connect failed: {e}"))?;
        Ok((guard, service))
    }

    fn open_or_create_folder(
        service: &ITaskService,
        folder_path: &str,
    ) -> Result<ITaskFolder, String> {
        let norm = normalize_folder_path(folder_path);
        // SAFETY: `BSTR` is valid across the COM call.
        if let Ok(folder) = unsafe { service.GetFolder(&BSTR::from(norm.as_str())) } {
            return Ok(folder);
        }
        if norm == r"\" {
            return Err(r"ITaskService::GetFolder(\) failed".to_string());
        }
        // SAFETY: Open root folder to create missing subfolder.
        let root = unsafe { service.GetFolder(&BSTR::from(r"\")) }
            .map_err(|e| format!(r"ITaskService::GetFolder(\) failed: {e}"))?;
        let sub_name = norm.trim_start_matches('\\');
        // SAFETY: Creates subfolder with default inherited SDDL; explicit AU ACL applied below.
        unsafe { root.CreateFolder(&BSTR::from(sub_name), &VARIANT::default()) }
            .map_err(|e| format!("ITaskFolder::CreateFolder({norm}) failed: {e}"))
    }

    pub fn register_task_xml(
        folder_path: &str,
        task_name: &str,
        xml: &str,
        sddl: &str,
    ) -> Result<(), String> {
        let (_com, service) = connect_service()?;
        let folder = open_or_create_folder(&service, folder_path)?;

        let existing_folder_sd =
            unsafe { folder.GetSecurityDescriptor(super::SECURITY_INFO_NO_SACL) }
                .map(|b| b.to_string())
                .unwrap_or_default();
        if !existing_folder_sd.is_empty() {
            let updated_folder_sd = ensure_au_read_exec_in_sddl(&existing_folder_sd);
            if updated_folder_sd != existing_folder_sd {
                // SAFETY: Updates folder DACL so non-elevated callers can query task status.
                unsafe { folder.SetSecurityDescriptor(&BSTR::from(updated_folder_sd.as_str()), 0) }
                    .map_err(|e| format!("ITaskFolder::SetSecurityDescriptor failed: {e}"))?;
            }
        }

        let empty = VARIANT::default();
        let user_id = VARIANT::from("S-1-5-18");
        let sddl_var = VARIANT::from(sddl);
        // SAFETY: All `BSTR` and `VARIANT` arguments live across the COM call.
        let task = unsafe {
            folder.RegisterTask(
                &BSTR::from(task_name),
                &BSTR::from(xml),
                TASK_CREATE_OR_UPDATE.0,
                &user_id,
                &empty,
                TASK_LOGON_SERVICE_ACCOUNT,
                &sddl_var,
            )
        }
        .map_err(|e| format!("ITaskFolder::RegisterTask({task_name}) failed: {e}"))?;

        if let Ok(task_sd) = unsafe { task.GetSecurityDescriptor(super::SECURITY_INFO_NO_SACL) } {
            let cur = task_sd.to_string();
            let updated = ensure_au_read_exec_in_sddl(&cur);
            if updated != cur {
                // SAFETY: Ensures `(A;;GRGX;;;AU)` is present even if `RegisterTask` merged ACLs.
                unsafe { task.SetSecurityDescriptor(&BSTR::from(updated.as_str()), 0) }
                    .map_err(|e| format!("IRegisteredTask::SetSecurityDescriptor failed: {e}"))?;
            }
        }
        Ok(())
    }

    pub fn query_task_xml(folder_path: &str, task_name: &str) -> Result<Option<String>, String> {
        let (_com, service) = connect_service()?;
        let norm = normalize_folder_path(folder_path);
        let folder = match unsafe { service.GetFolder(&BSTR::from(norm.as_str())) } {
            Ok(f) => f,
            Err(e) if is_not_found(&e) => return Ok(None),
            Err(e) if is_access_denied(&e) => return Err(format!("ACCESS_DENIED: {e}")),
            Err(e) => return Err(format!("ITaskService::GetFolder({norm}) failed: {e}")),
        };
        let task = match unsafe { folder.GetTask(&BSTR::from(task_name)) } {
            Ok(t) => t,
            Err(e) if is_not_found(&e) => return Ok(None),
            Err(e) if is_access_denied(&e) => return Err(format!("ACCESS_DENIED: {e}")),
            Err(e) => return Err(format!("ITaskFolder::GetTask({task_name}) failed: {e}")),
        };
        match unsafe { task.Xml() } {
            Ok(xml) => Ok(Some(xml.to_string())),
            Err(e) if is_access_denied(&e) => Err(format!("ACCESS_DENIED: {e}")),
            Err(e) => Err(format!("IRegisteredTask::Xml({task_name}) failed: {e}")),
        }
    }

    pub fn run_task(folder_path: &str, task_name: &str) -> Result<(), String> {
        let (_com, service) = connect_service()?;
        let norm = normalize_folder_path(folder_path);
        // SAFETY: COM BSTR parameters remain valid across each call.
        let folder = unsafe { service.GetFolder(&BSTR::from(norm.as_str())) }
            .map_err(|e| format!("ITaskService::GetFolder({norm}) failed: {e}"))?;
        let task = unsafe { folder.GetTask(&BSTR::from(task_name)) }
            .map_err(|e| format!("ITaskFolder::GetTask({task_name}) failed: {e}"))?;
        unsafe { task.Run(&VARIANT::default()) }
            .map(|_| ())
            .map_err(|e| format!("IRegisteredTask::Run({task_name}) failed: {e}"))
    }

    pub fn delete_task(folder_path: &str, task_name: &str) -> Result<(), String> {
        let (_com, service) = connect_service()?;
        let norm = normalize_folder_path(folder_path);
        let folder = match unsafe { service.GetFolder(&BSTR::from(norm.as_str())) } {
            Ok(f) => f,
            Err(e) if is_not_found(&e) => return Ok(()),
            Err(e) => return Err(format!("ITaskService::GetFolder({norm}) failed: {e}")),
        };
        match unsafe { folder.DeleteTask(&BSTR::from(task_name), 0) } {
            Ok(()) => Ok(()),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(format!("ITaskFolder::DeleteTask({task_name}) failed: {e}")),
        }
    }
}

pub fn register_task_xml(
    folder_path: &str,
    task_name: &str,
    xml: &str,
    sddl: &str,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        win::register_task_xml(folder_path, task_name, xml, sddl)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (folder_path, task_name, xml, sddl);
        Err("register_task_xml is only supported on Windows".to_string())
    }
}

pub fn query_task_xml(folder_path: &str, task_name: &str) -> Result<Option<String>, String> {
    #[cfg(target_os = "windows")]
    {
        win::query_task_xml(folder_path, task_name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (folder_path, task_name);
        Ok(None)
    }
}

pub fn run_task(folder_path: &str, task_name: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        win::run_task(folder_path, task_name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (folder_path, task_name);
        Err("run_task is only supported on Windows".to_string())
    }
}

pub fn delete_task(folder_path: &str, task_name: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        win::delete_task(folder_path, task_name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (folder_path, task_name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SECURITY_INFO_NO_SACL;

    #[test]
    fn security_descriptor_mask_omits_sacl_privilege_bit() {
        const OWNER_SECURITY_INFORMATION: i32 = 0x1;
        const GROUP_SECURITY_INFORMATION: i32 = 0x2;
        const DACL_SECURITY_INFORMATION: i32 = 0x4;
        const SACL_SECURITY_INFORMATION: i32 = 0x8;
        assert_eq!(
            SECURITY_INFO_NO_SACL,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        );
        assert_eq!(SECURITY_INFO_NO_SACL & SACL_SECURITY_INFORMATION, 0);
    }
}
