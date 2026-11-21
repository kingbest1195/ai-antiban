//! Hardened Chromium sandbox launcher and stale-port process lifecycle manager.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use super::CleanProfileId;
use super::LaunchCleanBrowserResult;
pub use super::sandbox_prefs::{
    SANDBOX_META_FILENAME, SandboxMeta, accept_languages_for_country,
    cleanup_stale_singleton_files, ensure_private_dir, read_sandbox_meta,
    write_fail_closed_preferences, write_fail_closed_preferences_with_country,
    write_first_run_sentinel, write_sandbox_meta,
};
pub use super::sandbox_proc::{
    find_sandbox_pids_for_profile, is_sandbox_browser_cmdline, parse_ps_pids_for_profile,
    terminate_all_sandboxes, terminate_all_sandboxes_on_exit, terminate_sandbox_for_profile,
    terminate_sandbox_pid,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningSandboxProcess {
    pub pid: u32,
    pub alias_port: u16,
    pub browser_engine: String,
}

/// Tracks active Clean Room browser processes per `profile_id` so stale-port launches
/// cleanly terminate the old instance before restarting on the new alias port.
#[derive(Debug, Default)]
pub struct SandboxProcessRegistry {
    running: Mutex<HashMap<String, RunningSandboxProcess>>,
}

impl SandboxProcessRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, profile_id: &str) -> Option<RunningSandboxProcess> {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(profile_id)
            .cloned()
    }

    pub fn record(&self, profile_id: &str, info: RunningSandboxProcess) {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(profile_id.to_string(), info);
    }

    pub fn remove(&self, profile_id: &str) -> Option<RunningSandboxProcess> {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(profile_id)
    }

    /// Returns `Some(old_process)` if `profile_id` is currently tracked on a different `alias_port`.
    pub fn take_if_stale_port(
        &self,
        profile_id: &str,
        new_alias_port: u16,
    ) -> Option<RunningSandboxProcess> {
        let mut guard = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let is_stale = guard
            .get(profile_id)
            .is_some_and(|p| p.alias_port != new_alias_port);
        if is_stale {
            guard.remove(profile_id)
        } else {
            None
        }
    }

    pub fn drain_all(&self) -> Vec<(String, RunningSandboxProcess)> {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .collect()
    }
}

pub fn clean_profile_dir(app_data_dir: &Path, profile_id: &CleanProfileId) -> PathBuf {
    app_data_dir
        .join("clean-profiles")
        .join(profile_id.as_str())
}

/// Builds the mandatory hardened Chromium launch flags without overriding browser UI language.
/// Explicitly omits `--disable-features=WebRtcHideLocalIpsWithMdns` so mDNS local-IP hiding
/// remains enabled.
pub fn build_hardened_chromium_args(
    profile_dir: &Path,
    alias_port: u16,
    target_url: Option<&str>,
) -> Vec<String> {
    build_hardened_chromium_args_for_engine(profile_dir, alias_port, target_url, "chrome")
}

/// Builds hardened Chromium launch flags tailored to `browser_engine` (suppressing Edge FRE
/// without clobbering `DnsOverHttps`).
pub fn build_hardened_chromium_args_for_engine(
    profile_dir: &Path,
    alias_port: u16,
    target_url: Option<&str>,
    browser_engine: &str,
) -> Vec<String> {
    let disabled_features = if browser_engine.eq_ignore_ascii_case("edge") {
        "--disable-features=DnsOverHttps,msEdgeFRE".to_string()
    } else {
        "--disable-features=DnsOverHttps".to_string()
    };

    let mut args = vec![
        format!("--user-data-dir={}", profile_dir.display()),
        format!("--proxy-server=http://127.0.0.1:{alias_port}"),
        "--proxy-bypass-list=127.0.0.1;[::1]".to_string(),
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string(),
        "--disable-quic".to_string(),
        disabled_features,
        "--disable-background-networking".to_string(),
        "--disable-component-update".to_string(),
        "--simulate-outdated-no-au=Tue, 31 Dec 2099 23:59:59 GMT".to_string(),
        "--no-service-autorun".to_string(),
        "--no-pings".to_string(),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-sync".to_string(),
    ];

    #[cfg(target_os = "macos")]
    args.push("--use-mock-keychain".to_string());
    #[cfg(target_os = "linux")]
    args.push("--password-store=basic".to_string());

    if let Some(url) = target_url.map(str::trim).filter(|u| !u.is_empty())
        && (url.starts_with("https://") || url.starts_with("http://"))
    {
        args.push(url.to_string());
    }
    args
}

/// Prepares the sandbox directory + fail-closed `Preferences`, terminates any stale
/// sandbox browser processes first, and spawns the isolated Chromium process when
/// `os_effects_enabled()` is `true`.
#[allow(clippy::too_many_arguments)]
pub fn launch_hardened_sandbox(
    registry: &SandboxProcessRegistry,
    app_data_dir: &Path,
    profile_id: &CleanProfileId,
    browser_engine: &str,
    executable_path: &str,
    alias_port: u16,
    target_url: Option<&str>,
    tz_for_spawn: Option<&str>,
) -> Result<LaunchCleanBrowserResult, String> {
    launch_hardened_sandbox_with_country(
        registry,
        app_data_dir,
        profile_id,
        browser_engine,
        executable_path,
        alias_port,
        target_url,
        tz_for_spawn,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn launch_hardened_sandbox_with_country(
    registry: &SandboxProcessRegistry,
    app_data_dir: &Path,
    profile_id: &CleanProfileId,
    browser_engine: &str,
    executable_path: &str,
    alias_port: u16,
    target_url: Option<&str>,
    tz_for_spawn: Option<&str>,
    exit_country: Option<&str>,
) -> Result<LaunchCleanBrowserResult, String> {
    let profile_dir = clean_profile_dir(app_data_dir, profile_id);
    // 1. FIRST: find & terminate ALL live sandbox browser processes for this profile_dir
    //    (registry + .zastava-sandbox.json + live OS cmdline scan) and wait up to 1500ms.
    terminate_sandbox_for_profile(registry, &profile_dir, profile_id.as_str());
    // 2. SECOND: remove stale SingletonLock / SingletonSocket / SingletonCookie.
    cleanup_stale_singleton_files(&profile_dir);
    // 3. THIRD: write fail-closed Preferences after exiting browser can no longer overwrite them.
    write_fail_closed_preferences_with_country(&profile_dir, alias_port, exit_country)?;

    let args = build_hardened_chromium_args_for_engine(
        &profile_dir,
        alias_port,
        target_url,
        browser_engine,
    );
    let clean_url = target_url
        .map(str::trim)
        .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
        .map(str::to_string);

    let pid = if crate::sysproxy::os_effects_enabled() {
        let mut cmd = build_browser_command(executable_path, &args, tz_for_spawn);
        let child = cmd.spawn().map_err(|e| {
            format!("Не удалось запустить браузер {browser_engine} ({executable_path}): {e}")
        })?;
        let child_pid = child.id();
        registry.record(
            profile_id.as_str(),
            RunningSandboxProcess {
                pid: child_pid,
                alias_port,
                browser_engine: browser_engine.to_string(),
            },
        );
        let _ = write_sandbox_meta(
            &profile_dir,
            SandboxMeta {
                pid: child_pid,
                alias_port,
            },
        );
        Some(child_pid)
    } else {
        let _ = write_sandbox_meta(&profile_dir, SandboxMeta { pid: 0, alias_port });
        None
    };

    Ok(LaunchCleanBrowserResult {
        profile_id: profile_id.as_str().to_string(),
        browser_engine: browser_engine.to_string(),
        pid,
        alias_port,
        target_url: clean_url,
        tz_applied: tz_for_spawn.map(str::to_string),
        profile_dir: profile_dir.to_string_lossy().into_owned(),
    })
}

fn build_browser_command(
    executable_path: &str,
    args: &[String],
    tz_for_spawn: Option<&str>,
) -> Command {
    #[cfg(target_os = "windows")]
    let mut cmd = crate::sysproxy::silent_command(executable_path);
    #[cfg(not(target_os = "windows"))]
    let mut cmd = Command::new(executable_path);

    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(tz) = tz_for_spawn {
        cmd.env("TZ", tz);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_pid_verifier_rejects_reused_or_personal_browser_pids() {
        let profile_dir = Path::new("/tmp/zastava-clean/clean-profiles/cr-test-1");
        let matching_cmd = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/tmp/zastava-clean/clean-profiles/cr-test-1 --disable-quic";
        assert!(is_sandbox_browser_cmdline(matching_cmd, profile_dir));

        // Reused PID running an unrelated system/CLI process must NOT be killed.
        assert!(!is_sandbox_browser_cmdline(
            "/usr/sbin/syslogd",
            profile_dir
        ));
        assert!(!is_sandbox_browser_cmdline(
            "cat /tmp/zastava-clean/clean-profiles/cr-test-1/Preferences",
            profile_dir
        ));

        // Reused PID running user's personal Chrome profile must NOT be killed.
        let personal_chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/Users/alice/Library/Application Support/Google/Chrome";
        assert!(!is_sandbox_browser_cmdline(personal_chrome, profile_dir));

        // Empty profile_dir or empty cmdline must never match.
        assert!(!is_sandbox_browser_cmdline(matching_cmd, Path::new("")));
        assert!(!is_sandbox_browser_cmdline("", profile_dir));
    }
}
