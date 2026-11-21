//! Process discovery and clean lifecycle termination for Clean Room sandbox browsers.

use std::path::{Path, PathBuf};
#[cfg(not(target_os = "windows"))]
use std::process::Command;
use std::process::Stdio;
use std::time::{Duration, Instant};

use super::browser_sandbox::SandboxProcessRegistry;
use super::sandbox_prefs::read_sandbox_meta;

const TERMINATE_WAIT_TIMEOUT_MS: u64 = 1500;
const EXIT_TERMINATE_WAIT_TIMEOUT_MS: u64 = 250;
#[cfg(target_os = "windows")]
const TERMINATE_POLL_INTERVAL_MS: u64 = 200;
#[cfg(not(target_os = "windows"))]
const TERMINATE_POLL_INTERVAL_MS: u64 = 50;

/// Checks whether a live process command line belongs to a Zastava Clean Room sandbox
/// browser for `profile_dir` (requiring both a Chromium-family binary and `--user-data-dir=`
/// matching the exact normalized `profile_dir` path with a strict trailing boundary).
pub fn is_sandbox_browser_cmdline(cmdline: &str, profile_dir: &Path) -> bool {
    let raw_dir = profile_dir.to_string_lossy();
    let dir = raw_dir.trim();
    if dir.is_empty() || cmdline.trim().is_empty() {
        return false;
    }
    let cmd_lower = cmdline.to_ascii_lowercase();
    let has_browser = ["chrome", "chromium", "msedge", "brave"]
        .iter()
        .any(|b| cmd_lower.contains(b));
    if !has_browser {
        return false;
    }

    #[cfg(target_os = "windows")]
    let (haystack, needle) = {
        let h = cmd_lower.replace('/', "\\");
        let n = dir.replace('/', "\\").to_ascii_lowercase();
        let n = n.trim_end_matches('\\').to_string();
        (h, n)
    };
    #[cfg(not(target_os = "windows"))]
    let (haystack, needle) = {
        let n = dir.trim_end_matches('/').to_string();
        (cmdline.to_string(), n)
    };

    if needle.is_empty() {
        return false;
    }

    let flag = "--user-data-dir=";
    let haystack_lower = haystack.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(rel_idx) = haystack_lower[search_from..].find(flag) {
        let after_flag_idx = search_from + rel_idx + flag.len();
        let rest = &haystack[after_flag_idx..];
        let (opened_quote, after_quote) = if let Some(r) = rest.strip_prefix('"') {
            (Some('"'), r)
        } else if let Some(r) = rest.strip_prefix('\'') {
            (Some('\''), r)
        } else {
            (None, rest)
        };
        if let Some(after_dir) = after_quote.strip_prefix(&needle) {
            let after_sep = if cfg!(target_os = "windows") {
                after_dir.strip_prefix('\\').unwrap_or(after_dir)
            } else {
                after_dir.strip_prefix('/').unwrap_or(after_dir)
            };
            let next_char = after_sep.chars().next();
            let valid_boundary = match opened_quote {
                Some(q) => next_char.is_none() || next_char == Some(q),
                None => {
                    next_char.is_none()
                        || next_char.is_some_and(|c| c.is_whitespace() || c == '"' || c == '\'')
                }
            };
            if valid_boundary {
                return true;
            }
        }
        search_from = after_flag_idx;
    }
    false
}

/// Parses `<pid> <command>` lines (from `ps -axo pid=,command=` or Windows CIM output)
/// and returns unique PIDs whose command line belongs to `profile_dir`.
pub fn parse_ps_pids_for_profile(ps_output: &str, profile_dir: &Path) -> Vec<u32> {
    let raw_dir = profile_dir.to_string_lossy();
    if raw_dir.trim().is_empty() {
        return Vec::new();
    }
    let self_pid = std::process::id();
    let mut pids = Vec::new();
    for line in ps_output.lines() {
        let trimmed = line.trim_start();
        let Some((pid_str, cmdline)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        let Ok(pid) = pid_str.trim().parse::<u32>() else {
            continue;
        };
        if pid == 0 || pid == self_pid {
            continue;
        }
        if is_sandbox_browser_cmdline(cmdline.trim(), profile_dir) && !pids.contains(&pid) {
            pids.push(pid);
        }
    }
    pids
}

/// Scans live OS processes for any sandbox browser running with `profile_dir`.
pub fn find_sandbox_pids_for_profile(profile_dir: &Path) -> Vec<u32> {
    if !crate::sysproxy::os_effects_enabled() || profile_dir.to_string_lossy().trim().is_empty() {
        return Vec::new();
    }
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine } | Select-Object ProcessId,CommandLine | ForEach-Object { \"$($_.ProcessId) $($_.CommandLine)\" }";
        let Ok(out) = crate::sysproxy::silent_command("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_cmd])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }
        parse_ps_pids_for_profile(&String::from_utf8_lossy(&out.stdout), profile_dir)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let Ok(out) = Command::new("ps")
            .args(["-axo", "pid=,command="])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }
        parse_ps_pids_for_profile(&String::from_utf8_lossy(&out.stdout), profile_dir)
    }
}

pub(super) fn read_process_cmdline(pid: u32) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let ps_cmd =
            format!("(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").CommandLine");
        let out = crate::sysproxy::silent_command("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let out = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }
}

fn is_pid_alive_for_profile(pid: u32, profile_dir: &Path) -> bool {
    pid != 0
        && read_process_cmdline(pid)
            .is_some_and(|cmdline| is_sandbox_browser_cmdline(&cmdline, profile_dir))
}

/// Fast liveness check for a PID whose command line was already verified against `profile_dir`.
/// Avoids spawning `powershell.exe` every poll tick on Windows.
fn is_pid_alive_fast(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        let filter = format!("PID eq {pid}");
        let Ok(out) = crate::sysproxy::silent_command("tasklist")
            .args(["/FI", &filter, "/NH", "/FO", "CSV"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        else {
            return false;
        };
        if !out.status.success() {
            return false;
        }
        let needle = format!(",\"{pid}\",");
        String::from_utf8_lossy(&out.stdout).contains(&needle)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

fn send_term_to_pid(pid: u32) {
    #[cfg(target_os = "windows")]
    {
        let _ = crate::sysproxy::silent_command("taskkill")
            .args(["/PID", &pid.to_string(), "/T"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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

fn send_force_kill_to_pid(pid: u32) {
    #[cfg(target_os = "windows")]
    {
        let _ = crate::sysproxy::silent_command("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Terminates a previously launched sandbox browser PID if OS effects are enabled AND
/// the live process command line still matches `profile_dir` (preventing reused-PID kills).
pub fn terminate_sandbox_pid(pid: u32, profile_dir: &Path) {
    if pid == 0 || !crate::sysproxy::os_effects_enabled() {
        return;
    }
    if !is_pid_alive_for_profile(pid, profile_dir) {
        return;
    }
    send_term_to_pid(pid);
}

fn terminate_pids_and_wait(pids: &[u32], profile_dir: &Path, timeout_ms: u64) {
    if pids.is_empty() || !crate::sysproxy::os_effects_enabled() {
        return;
    }
    let mut live: Vec<u32> = pids
        .iter()
        .copied()
        .filter(|&pid| is_pid_alive_for_profile(pid, profile_dir))
        .collect();
    if live.is_empty() {
        return;
    }
    for &pid in &live {
        send_term_to_pid(pid);
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(TERMINATE_POLL_INTERVAL_MS));
        live.retain(|&pid| is_pid_alive_fast(pid));
        if live.is_empty() {
            return;
        }
    }
    for &pid in &live {
        send_force_kill_to_pid(pid);
    }
    if timeout_ms > TERMINATE_POLL_INTERVAL_MS {
        std::thread::sleep(Duration::from_millis(TERMINATE_POLL_INTERVAL_MS));
    }
}

/// Terminates ALL live sandbox browser processes for `profile_id` / `profile_dir`
/// (from in-memory registry, persisted `.zastava-sandbox.json`, AND live OS cmdline scan),
/// waiting up to 1500ms with `SIGKILL` / `taskkill /F` fallback.
pub fn terminate_sandbox_for_profile(
    registry: &SandboxProcessRegistry,
    profile_dir: &Path,
    profile_id: &str,
) {
    let mut pids = Vec::new();
    if let Some(proc_info) = registry.remove(profile_id)
        && proc_info.pid != 0
    {
        pids.push(proc_info.pid);
    }
    if let Some(meta) = read_sandbox_meta(profile_dir)
        && meta.pid != 0
        && !pids.contains(&meta.pid)
    {
        pids.push(meta.pid);
    }
    for pid in find_sandbox_pids_for_profile(profile_dir) {
        if !pids.contains(&pid) {
            pids.push(pid);
        }
    }
    terminate_pids_and_wait(&pids, profile_dir, TERMINATE_WAIT_TIMEOUT_MS);
}

/// Terminates all tracked sandbox browser processes across `registry` (and any persisted
/// `.zastava-sandbox.json` under `app_data_dir/clean-profiles/`) on app shutdown/upgrade.
pub fn terminate_all_sandboxes(registry: &SandboxProcessRegistry, app_data_dir: Option<&Path>) {
    let tracked = registry.drain_all();
    if !crate::sysproxy::os_effects_enabled() {
        return;
    }
    for (profile_id, proc_info) in tracked {
        let profile_dir = app_data_dir
            .map(|d| d.join("clean-profiles").join(&profile_id))
            .unwrap_or_default();
        if !profile_dir.as_os_str().is_empty() {
            let mut pids = Vec::new();
            if proc_info.pid != 0 {
                pids.push(proc_info.pid);
            }
            for pid in find_sandbox_pids_for_profile(&profile_dir) {
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
            terminate_pids_and_wait(&pids, &profile_dir, TERMINATE_WAIT_TIMEOUT_MS);
        }
    }
    if let Some(data_dir) = app_data_dir {
        let profiles_root = data_dir.join("clean-profiles");
        if let Ok(entries) = std::fs::read_dir(profiles_root) {
            for entry in entries.flatten() {
                let p: PathBuf = entry.path();
                if p.is_dir()
                    && let Some(meta) = read_sandbox_meta(&p)
                    && meta.pid != 0
                {
                    terminate_pids_and_wait(&[meta.pid], &p, TERMINATE_WAIT_TIMEOUT_MS);
                }
            }
        }
    }
}

/// Bounded (`<= 250ms`) app-exit termination of tracked and persisted sandbox browser PIDs.
/// Sends `SIGTERM` / `taskkill /T` across all verified PIDs in parallel, waits up to 250ms,
/// and force-kills any stragglers without blocking the UI thread for seconds per profile.
pub fn terminate_all_sandboxes_on_exit(
    registry: &SandboxProcessRegistry,
    app_data_dir: Option<&Path>,
) {
    let tracked = registry.drain_all();
    if !crate::sysproxy::os_effects_enabled() {
        return;
    }

    let mut targets: Vec<(u32, PathBuf)> = Vec::new();
    for (profile_id, proc_info) in tracked {
        if proc_info.pid == 0 {
            continue;
        }
        let profile_dir = app_data_dir
            .map(|d| d.join("clean-profiles").join(&profile_id))
            .unwrap_or_default();
        if !profile_dir.as_os_str().is_empty() && !targets.iter().any(|(p, _)| *p == proc_info.pid)
        {
            targets.push((proc_info.pid, profile_dir));
        }
    }

    if let Some(data_dir) = app_data_dir {
        let profiles_root = data_dir.join("clean-profiles");
        if let Ok(entries) = std::fs::read_dir(profiles_root) {
            for entry in entries.flatten() {
                let p: PathBuf = entry.path();
                if p.is_dir()
                    && let Some(meta) = read_sandbox_meta(&p)
                    && meta.pid != 0
                    && !targets.iter().any(|(pid, _)| *pid == meta.pid)
                {
                    targets.push((meta.pid, p));
                }
            }
        }
    }

    if targets.is_empty() {
        return;
    }

    let mut live: Vec<u32> = std::thread::scope(|s| {
        let handles: Vec<_> = targets
            .iter()
            .map(|(pid, dir)| {
                let pid = *pid;
                s.spawn(move || is_pid_alive_for_profile(pid, dir).then_some(pid))
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().ok().flatten())
            .collect()
    });

    if live.is_empty() {
        return;
    }

    for &pid in &live {
        send_term_to_pid(pid);
    }

    let deadline = Instant::now() + Duration::from_millis(EXIT_TERMINATE_WAIT_TIMEOUT_MS);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let step = remaining.min(Duration::from_millis(TERMINATE_POLL_INTERVAL_MS));
        if step.is_zero() {
            break;
        }
        std::thread::sleep(step);
        live.retain(|&pid| is_pid_alive_fast(pid));
        if live.is_empty() {
            return;
        }
    }

    for &pid in &live {
        send_force_kill_to_pid(pid);
    }
}
