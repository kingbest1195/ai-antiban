//! Windows-specific system proxy plumbing: WinINet registry values (PAC URL), the
//! WinINet refresh notification, and `HKCU\Environment` helpers.
//! Compiled only on `target_os = "windows"` (see `sysproxy/mod.rs`).

use super::{
    enable_sysproxy, get_chained_proxy, parse_gateway_port_from_pac_url, parse_reg_dword,
    parse_reg_sz, parse_windows_proxy_server, set_chained_proxy, silent_command, LAST_PAC_URL,
};

/// Reads `ProxyEnable` and `ProxyServer` from Windows Internet Settings.
/// If an active third-party proxy is found, saves it to `CHAINED_PROXY`.
pub(super) fn detect_and_save_windows_chained_proxy(gateway_port: Option<u16>) -> Option<String> {
    let enable_output = silent_command("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
        ])
        .output()
        .ok()?;
    let enable_stdout = String::from_utf8_lossy(&enable_output.stdout);
    let proxy_enable = parse_reg_dword(&enable_stdout, "ProxyEnable").unwrap_or(0);

    if proxy_enable == 1 {
        let server_output = silent_command("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyServer",
            ])
            .output()
            .ok()?;
        let server_stdout = String::from_utf8_lossy(&server_output.stdout);
        if let Some(raw_server) = parse_reg_sz(&server_stdout, "ProxyServer") {
            if let Some(target) = parse_windows_proxy_server(&raw_server, gateway_port) {
                set_chained_proxy(Some(target.clone()));
                return Some(target);
            }
        }
    }
    None
}

/// Removes the PAC URL and disables or restores third-party chained proxy in the WinINet registry values.
pub(super) fn disable_system_proxy() {
    let chained = get_chained_proxy();

    // On Windows remove HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL
    let _ = silent_command("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "AutoConfigURL",
            "/f",
        ])
        .output();

    if let Some(chained_target) = chained {
        let _ = silent_command("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                &chained_target,
                "/f",
            ])
            .output();
        let _ = silent_command("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();
    } else {
        let _ = silent_command("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ])
            .output();
    }
    notify_windows_inet_refresh();
}

/// Writes the PAC URL into the WinINet registry values and records it in `configured`.
pub(super) fn enable_system_proxy(pac_url: &str, configured: &mut Vec<String>) {
    let gateway_port = parse_gateway_port_from_pac_url(pac_url);

    // 1. Detect third-party proxy before overriding, chain it
    detect_and_save_windows_chained_proxy(gateway_port);

    // 2. Write AutoConfigURL
    let output = silent_command("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "AutoConfigURL",
            "/t",
            "REG_SZ",
            "/d",
            pac_url,
            "/f",
        ])
        .output();

    // 3. Set ProxyEnable = 0 so WinINet routes via AutoConfigURL (PAC)
    let _ = silent_command("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ])
        .output();

    if output.is_ok() {
        configured.push("Windows Internet Settings (WinINet)".to_string());
    }
    notify_windows_inet_refresh();
}

/// Windows branch of `refresh_if_services_changed`: re-applies the PAC URL when the registry value drifted
/// or when a third-party VPN client enabled an explicit ProxyServer.
pub(super) fn refresh_if_changed() -> bool {
    let pac = LAST_PAC_URL.lock().ok().and_then(|g| g.clone());
    if let Some(pac) = pac {
        let gateway_port = parse_gateway_port_from_pac_url(&pac);

        // Check if an external tool turned ProxyEnable back on
        if detect_and_save_windows_chained_proxy(gateway_port).is_some() {
            return enable_sysproxy(&pac).is_ok();
        }

        if let Ok(output) = silent_command("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "AutoConfigURL",
            ])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !output.status.success() || !stdout.contains(&pac) {
                return enable_sysproxy(&pac).is_ok();
            }
        }
    }
    false
}

pub(super) fn notify_windows_inet_refresh() {
    if !super::os_effects_enabled() {
        super::note_dry_run_blocked("InternetSetOptionW");
        return;
    }
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

pub fn set_windows_user_env_var(name: &str, value: &str) -> std::io::Result<()> {
    silent_command("reg")
        .args(["add", r"HKCU\Environment", "/v", name, "/t", "REG_SZ", "/d", value, "/f"])
        .output()?;
    Ok(())
}

pub fn delete_windows_user_env_var(name: &str) -> std::io::Result<()> {
    let _ = silent_command("reg")
        .args(["delete", r"HKCU\Environment", "/v", name, "/f"])
        .output();
    Ok(())
}

pub fn broadcast_windows_env_change() {
    if !super::os_effects_enabled() {
        super::note_dry_run_blocked("SendMessageTimeoutW");
        return;
    }
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
