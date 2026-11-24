//! System proxy and CLI/IDE protection.
//!
//! Layout: `platform` (the only code that talks to `networksetup` / `launchctl` / `reg` / `scutil`),
//! `journal` + `fs` (ownership journal: what Zastava changed and what was there before),
//! `macos` / `windows` (PAC, chained proxy and WinINet through the journal), `shell_rc`
//! (zsh/bash/PowerShell blocks), `ide` (editor settings.json), `ai_cli` (Claude Code / Gemini CLI
//! settings), `jsonc` (point editor for JSONC), `cli_protection` (enable/disable/status
//! orchestration), `cleanup` (exit guard, signals, restore of the journal, one-time legacy
//! migration).
//! Zastava restores only what it changed itself: every system setting and every key / block in a
//! user file goes through the journal. Files are reached through [`FileCtx`] (file system, home,
//! editor roots), runtime flags live in [`SysState`]; the no-argument public functions use the
//! process-wide instances of both.

mod ai_cli;
pub(crate) mod browser_policies;
mod cleanup;
mod cli_protection;
pub mod fs;
mod ide;
pub mod journal;
mod jsonc;
mod macos;
pub mod platform;
mod process_probe;
pub mod relaunch;
mod shell_rc;
mod windows;

pub use browser_policies::PolicyApplyReport;
pub use cleanup::{
    SHUTDOWN_PROGRESS_EVENT, SHUTDOWN_PROGRESS_TOTAL, ShutdownCleanupGuard,
    ShutdownProgressPayload, cleaned_components, cleanup_all_persistent_settings,
    cleanup_on_shutdown_after_step1, cleanup_on_shutdown_once, force_clean_all_os_proxy_traces,
    is_shutdown_cleanup_completed, legacy_env_plan, legacy_env_plan_with_gateway,
    record_gateway_launched_app, register_clean_exit_guard, reset_shutdown_cleanup_guard,
    spawn_signal_cleanup_watcher, try_claim_async_shutdown,
};
pub use cli_protection::{
    CliApplied, apply_cli_settings, disable_cli_and_ide_runtime_settings, disable_cli_protection,
    enable_cli_and_ide_protection, enable_cli_and_ide_protection_with, is_cli_protection_enabled,
    sync_ai_tz_active,
};
pub use ide::{candidate_ide_settings_paths, sanitize_jsonc};
pub use process_probe::{Os, RealProbe, SystemProbe};
pub use shell_rc::{
    build_powershell_guard_block_with_tz, build_shell_rc_guard_block,
    build_shell_rc_guard_block_with_tz, get_windows_powershell_profile_paths,
    remove_shell_rc_block, sanitize_timezone, upsert_powershell_profile_content_with_tz,
    upsert_shell_rc_content, upsert_shell_rc_content_with_tz,
};

mod orchestrator;
mod parsing;
mod state;

pub use orchestrator::{
    enable_sysproxy, enable_sysproxy_privileged, is_browser_pac_policy_active, is_os_pac_deferred,
    is_sysproxy_active, reapply_browser_policies, recover_ownership_on_start,
    refresh_if_services_changed, run_cleanup_cli, set_data_dir,
};
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub use parsing::{
    get_chained_proxy, is_gateway_host_port, is_gateway_target, parse_gateway_port_from_pac_url,
    parse_networksetup_webproxy_output, parse_reg_dword, parse_reg_sz,
    parse_windows_proxy_override, parse_windows_proxy_server, set_chained_proxy,
    windows_proxy_override_bypasses_all,
};
#[cfg(any(test, feature = "test-support"))]
pub use state::force_os_dry_run;
pub use state::{
    APP_IDENTIFIER, OS_DRY_RUN_ENV, default_app_data_dir, dry_run_blocked_calls,
    dry_run_blocked_programs, os_effects_enabled,
};

#[cfg(target_os = "windows")]
pub(crate) use orchestrator::real_user_env;
pub(crate) use orchestrator::{
    EnableReport, Run, journal_base_dir, journal_failure_text, restore_pass, with_files,
    with_journal,
};
#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub(crate) use state::user_appdata_dir;
#[allow(unused_imports)]
pub(crate) use state::{
    FileCtx, KNOWN_NO_PROXY_VALUES, NO_PROXY_VALUE, NO_PROXY_VALUE_2_0, SysState, ZASTAVA_RC_END,
    ZASTAVA_RC_START, is_known_no_proxy_value, note_dry_run_blocked, state, user_home_dir,
};

use orchestrator::data_dir;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, Ordering};

/// Spawns a Command configured on Windows with `CREATE_NO_WINDOW` (0x08000000)
/// to completely prevent cmd.exe / PowerShell / Terminal console windows flashing.
/// In dry-run mode (see [`os_effects_enabled`]) the real program is never started: the command
/// becomes `true` (`cmd /c exit 0` on Windows) and the call is counted.
pub fn silent_command<S: AsRef<std::ffi::OsStr>>(program: S) -> std::process::Command {
    if !os_effects_enabled() {
        note_dry_run_blocked(&program.as_ref().to_string_lossy());
        #[cfg(all(target_os = "windows", any(test, feature = "test-support")))]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            let mut cmd = std::process::Command::new("cmd");
            cmd.args(["/c", "exit", "0"])
                .creation_flags(CREATE_NO_WINDOW);
            return cmd;
        }
        #[cfg(all(target_os = "windows", not(any(test, feature = "test-support"))))]
        return std::process::Command::new("zastava-dry-run-noop");
        #[cfg(not(target_os = "windows"))]
        return std::process::Command::new("true");
    }
    #[allow(unused_mut)]
    let mut cmd = std::process::Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysproxyStatus {
    pub enabled: bool,
    pub pac_url: Option<String>,
    pub services_configured: Vec<String>,
    /// Connected (or unclassifiable) VPN services that were deliberately not changed.
    #[serde(default)]
    pub vpn_untouched: Vec<String>,
    /// `true` on macOS when system `networksetup` PAC was deferred due to temporary VPN DNS
    /// (browser PAC policies and CLI/IDE protection are active).
    #[serde(default)]
    pub os_pac_deferred: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliProtectionReport {
    /// `false` when nothing was switched on (e.g. the ownership journal could not be opened).
    pub enabled: bool,
    pub proxy_url: String,
    pub configured_targets: Vec<String>,
    pub shell_command: String,
    /// Notes for the user, Russian, no values (e.g. an old block that could not be removed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Why `enabled` is `false`, Russian, no values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Restores everything Zastava changed in the system (PAC, chained proxy, WinINet, user
/// environment) from the ownership journal and cleans the CLI/IDE files. Kept under its
/// historical name for existing callers; it is [`cleanup_all_persistent_settings`].
pub fn disable_all_sysproxy() {
    let _ = cleanup_all_persistent_settings();
}

/// Removes stale Zastava `127.0.0.1:<any>/proxy.pac` entries from non-running Chromium profile
/// `Preferences` files (used at startup when protection is OFF).
pub fn clear_stale_browser_pac_prefs() -> usize {
    if !os_effects_enabled() {
        note_dry_run_blocked("clear_stale_browser_pac_prefs");
        return 0;
    }
    let Some(ctx) = FileCtx::real() else {
        return 0;
    };
    browser_policies::clear_stale_browser_pac_prefs_in(
        &ctx,
        crate::sysproxy::Os::current(),
        &crate::sysproxy::RealProbe,
    )
}

/// Reconciles Chromium `Preferences` for browsers that have exited since protection was toggled:
/// when protection is ON, injects `"proxy"` into newly exited browsers; when protection is OFF,
/// restores any deferred journaled `BrowserPacPref` entries and clears stale Zastava PAC prefs.
pub fn reconcile_browser_pac_prefs(pac_url: Option<&str>) -> bool {
    if !os_effects_enabled() {
        note_dry_run_blocked("reconcile_browser_pac_prefs");
        return false;
    }
    let os = crate::sysproxy::Os::current();
    let probe = crate::sysproxy::RealProbe;
    let st = state();
    if st.sys_proxy_active() {
        let resolved_pac = pac_url
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(str::to_string)
            .or_else(|| st.last_pac_url());
        let Some(url) = resolved_pac else {
            return false;
        };
        let Some(ctx) = FileCtx::real() else {
            return false;
        };
        if !browser_policies::any_non_running_browser_needs_pac_sync_in(&ctx, os, &probe, &url) {
            return false;
        }
        matches!(
            with_files("reconcile_browser_pac_prefs", |j, p, file_ctx| {
                browser_policies::reconcile_browser_pac_prefs_in(
                    j,
                    p,
                    Some(&url),
                    file_ctx,
                    os,
                    &probe,
                )
            }),
            Run::Done(true)
        )
    } else {
        let has_journal_entries = data_dir().is_some_and(|dir| {
            journal_base_dir(&dir)
                .join("ownership")
                .join("journal.json")
                .exists()
        });
        if has_journal_entries {
            matches!(
                with_files("reconcile_browser_pac_prefs_off", |j, p, file_ctx| {
                    browser_policies::reconcile_browser_pac_prefs_in(
                        j, p, None, file_ctx, os, &probe,
                    )
                }),
                Run::Done(true)
            )
        } else {
            clear_stale_browser_pac_prefs() > 0
        }
    }
}

/// Gracefully quits running Chromium browsers that still need PAC, patches all their profile
/// `Preferences` files via the journal, and relaunches them with `--proxy-pac-url=<pac_url>`.
pub fn relaunch_browsers_with_pac(
    pac_url: &str,
) -> Result<browser_policies::RelaunchSummary, String> {
    let os = crate::sysproxy::Os::current();
    let timing = relaunch::QuitTiming {
        timeout: browser_policies::BROWSER_QUIT_TIMEOUT,
        interval: browser_policies::BROWSER_QUIT_POLL_INTERVAL,
    };
    match with_files("relaunch_browsers_with_pac", |j, p, ctx| {
        browser_policies::relaunch_browsers_with_pac_with(
            j,
            p,
            pac_url,
            ctx,
            os,
            &crate::sysproxy::RealProbe,
            &relaunch::RealLauncher,
            timing,
        )
    }) {
        Run::Blocked => Ok(browser_policies::RelaunchSummary::default()),
        Run::Failed(e) => Err(journal_failure_text(&e)),
        Run::Done(summary) => Ok(summary),
    }
}

/// Shown when Quit could not put the PAC back because of a VPN with temporary DNS settings.
/// No addresses, no values; no quotes either (it goes into an AppleScript string).
pub const RESTORE_DEFERRED_TEXT: &str = "Застава закрыта, но адрес автонастройки прокси вернётся при следующем запуске: сейчас активен VPN с временными настройками DNS. Запустите Заставу или отключите VPN.";

/// Tells the user that the restore was deferred (macOS: a dialog that disappears by itself after
/// a minute, started detached so it outlives the quitting process; other systems have no such
/// state). Goes through [`silent_command`], so dry-run mode starts nothing.
pub fn notify_restore_deferred() {
    // Quit goes through the tray handler and then through the exit events: tell the user once.
    #[cfg(target_os = "macos")]
    {
        static TOLD: AtomicBool = AtomicBool::new(false);
        if !TOLD.swap(true, Ordering::SeqCst) {
            let script = format!(
                "display dialog \"{RESTORE_DEFERRED_TEXT}\" with title \"Застава\" buttons {{\"OK\"}} default button \"OK\" with icon caution giving up after 60"
            );
            let _ = silent_command("osascript").args(["-e", &script]).spawn();
        }
    }
}

pub struct SysProxy;

impl SysProxy {
    pub fn enable(pac_url: &str) -> Result<SysproxyStatus, String> {
        enable_sysproxy(pac_url)
    }

    pub fn disable() {
        let _ = cleanup_all_persistent_settings();
    }

    pub fn is_active() -> bool {
        is_sysproxy_active()
    }
}

/// Spawns the native OS date and time settings panel.
pub fn open_os_datetime_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        silent_command("open")
            .arg("x-apple.systempreferences:com.apple.preference.datetime")
            .spawn()
            .map_err(|e| format!("Failed to open macOS date & time settings: {e}"))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        open_windows_settings_uri("ms-settings:dateandtime", "date & time")
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(())
    }
}

/// Opens the network page of the system settings (where DNS servers are set). macOS 13+ pane id and
/// the Windows `ms-settings` URI; other systems have no reliable link, so nothing is opened.
pub fn open_os_network_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        silent_command("open")
            .arg("x-apple.systempreferences:com.apple.Network-Settings.extension")
            .spawn()
            .map_err(|e| format!("Failed to open macOS network settings: {e}"))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        open_windows_settings_uri("ms-settings:network", "network")
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn open_windows_settings_uri(uri: &str, label: &str) -> Result<(), String> {
    use core::ffi::c_void;

    if !os_effects_enabled() {
        note_dry_run_blocked(uri);
        return Ok(());
    }

    const SW_SHOWNORMAL: i32 = 1;

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteW(
            hwnd: *mut c_void,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> isize;
    }

    let op = crate::win_reg::encode_utf16_nul("open");
    let file = crate::win_reg::encode_utf16_nul(uri);
    // SAFETY: `op` and `file` are NUL-terminated UTF-16 buffers valid for the duration of the call.
    let rc = unsafe {
        ShellExecuteW(
            core::ptr::null_mut(),
            op.as_ptr(),
            file.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if rc > 32 {
        Ok(())
    } else {
        Err(format!(
            "Failed to open Windows {label} settings (ShellExecuteW code {rc})"
        ))
    }
}

fn read_os_pac_deferred() -> bool {
    #[cfg(target_os = "macos")]
    {
        if !os_effects_enabled() || !is_sysproxy_active() {
            return false;
        }
        use platform::{Platform, RealPlatform};
        !matches!(RealPlatform.temp_dns_overrides(), Ok(false))
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

pub(crate) async fn read_runtime_protection_flags() -> crate::auditor::AuditProtectionFlags {
    tokio::task::spawn_blocking(|| crate::auditor::AuditProtectionFlags {
        sysproxy_active: is_sysproxy_active(),
        cli_or_sandbox_protection_active: is_cli_protection_enabled()
            || is_browser_pac_policy_active(),
        os_pac_deferred: read_os_pac_deferred(),
    })
    .await
    .unwrap_or_default()
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(unused_imports)]
use orchestrator::take_app_lock;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use orchestrator::{cleanup_cli_gate, hold_app_lock, local_journal_base};
#[cfg(test)]
#[allow(unused_imports)]
use orchestrator::{enable_with, recover_in, refresh_with};
#[cfg(test)]
#[allow(unused_imports)]
use std::path::PathBuf;
#[cfg(test)]
#[allow(unused_imports)]
use std::sync::Arc;
