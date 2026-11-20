//! Hardened Chromium sandbox launcher, fail-closed `Preferences` writer, and stale-port
//! process lifecycle manager.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use serde_json::{Map, Value, json};

use super::CleanProfileId;
use super::LaunchCleanBrowserResult;

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
}

pub fn clean_profile_dir(app_data_dir: &Path, profile_id: &CleanProfileId) -> PathBuf {
    app_data_dir
        .join("clean-profiles")
        .join(profile_id.as_str())
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create directory {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(dir, perms)
            .map_err(|e| format!("Failed to set 0700 on {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Atomically writes `<profile_dir>/Default/Preferences` with fail-closed proxy & DoH=off
/// settings so even a manual relaunch outside Zastava cannot leak traffic `DIRECT`.
pub fn write_fail_closed_preferences(
    profile_dir: &Path,
    alias_port: u16,
) -> Result<PathBuf, String> {
    if alias_port == 0 {
        return Err("Alias port must be non-zero for fail-closed Preferences".to_string());
    }
    ensure_private_dir(profile_dir)?;
    let default_dir = profile_dir.join("Default");
    ensure_private_dir(&default_dir)?;

    let prefs_path = default_dir.join("Preferences");
    let mut root = match fs::read_to_string(&prefs_path) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        },
        Err(_) => Map::new(),
    };

    root.insert(
        "proxy".to_string(),
        json!({
            "mode": "fixed_servers",
            "server": format!("http://127.0.0.1:{alias_port}")
        }),
    );
    root.insert(
        "dns_over_https".to_string(),
        json!({
            "mode": "off"
        }),
    );

    let serialized = serde_json::to_string_pretty(&Value::Object(root))
        .map_err(|e| format!("Failed to serialize Chromium Preferences: {e}"))?;

    let tmp_path = default_dir.join(format!("Preferences.tmp.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp_path).map_err(|e| {
            format!(
                "Failed to create temp Preferences {}: {e}",
                tmp_path.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        f.write_all(serialized.as_bytes())
            .map_err(|e| format!("Failed to write temp Preferences: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("Failed to sync temp Preferences: {e}"))?;
    }
    fs::rename(&tmp_path, &prefs_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("Failed to commit Preferences {}: {e}", prefs_path.display())
    })?;
    Ok(prefs_path)
}

/// Builds the mandatory hardened Chromium launch flags.
/// Explicitly omits `--disable-features=WebRtcHideLocalIpsWithMdns` so mDNS local-IP hiding
/// remains enabled.
pub fn build_hardened_chromium_args(
    profile_dir: &Path,
    alias_port: u16,
    target_url: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        format!("--user-data-dir={}", profile_dir.display()),
        format!("--proxy-server=http://127.0.0.1:{alias_port}"),
        "--proxy-bypass-list=127.0.0.1;[::1]".to_string(),
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string(),
        "--disable-quic".to_string(),
        "--disable-features=DnsOverHttps".to_string(),
        "--disable-background-networking".to_string(),
        "--no-pings".to_string(),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string(),
        "--lang=en-US".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-sync".to_string(),
    ];

    if let Some(url) = target_url.map(str::trim).filter(|u| !u.is_empty())
        && (url.starts_with("https://") || url.starts_with("http://"))
    {
        args.push(url.to_string());
    }
    args
}

/// Terminates a previously launched sandbox browser PID if OS effects are enabled.
pub fn terminate_sandbox_pid(pid: u32) {
    if pid == 0 || !crate::sysproxy::os_effects_enabled() {
        return;
    }
    #[cfg(target_os = "windows")]
    {
        let _ = crate::sysproxy::silent_command("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Prepares the sandbox directory + fail-closed `Preferences`, handles stale-port restart,
/// and spawns the isolated Chromium process when `os_effects_enabled()` is `true`.
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
    let profile_dir = clean_profile_dir(app_data_dir, profile_id);
    write_fail_closed_preferences(&profile_dir, alias_port)?;

    if let Some(old) = registry.take_if_stale_port(profile_id.as_str(), alias_port) {
        terminate_sandbox_pid(old.pid);
    }

    let args = build_hardened_chromium_args(&profile_dir, alias_port, target_url);
    let clean_url = target_url
        .map(str::trim)
        .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
        .map(str::to_string);

    let pid = if crate::sysproxy::os_effects_enabled() {
        let mut cmd = build_browser_command(executable_path, &args, tz_for_spawn);
        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to launch {browser_engine} ({executable_path}): {e}"))?;
        let child_pid = child.id();
        registry.record(
            profile_id.as_str(),
            RunningSandboxProcess {
                pid: child_pid,
                alias_port,
                browser_engine: browser_engine.to_string(),
            },
        );
        Some(child_pid)
    } else {
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
