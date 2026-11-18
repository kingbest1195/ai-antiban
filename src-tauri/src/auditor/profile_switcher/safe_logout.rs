//! Safe logout for Claude Desktop & Claude Code CLI: closes running Claude processes,
//! clears ONLY auth/session files (preserving device IDs and MCP/user configs), and starts the
//! 4-hour post-logout IP-change cooldown.

#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::device_registry::{
    default_claude_desktop_dir, get_user_home_dir, is_real_dir, is_regular_file, is_symlink,
    remove_entry_safe,
};
use super::session::{claude_cli_credentials_path, strip_cli_oauth_from_claude_json};
use crate::state::{AppState, DEFAULT_IP_CHANGE_COOLDOWN_SECS};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafeLogoutResult {
    pub closed_processes: usize,
    pub cleared_items: Vec<String>,
    pub preserved_device_id: bool,
    pub cooldown_until: i64,
    pub cooldown_secs: u64,
}

const PRESERVED_FILENAMES: &[&str] = &[
    "ant-device-registry.json",
    "ccd-ids.json",
    "claude_desktop_config.json",
    "settings.json",
];

const AUTH_FILES: &[&str] = &[
    "Cookies",
    "Cookies-journal",
    "Network/Cookies",
    "Network/Cookies-journal",
    "Network/Network Persistent State",
    "Network/Trust Tokens",
    "Network/Trust Tokens-journal",
    "SharedStorage",
    "SharedStorage-wal",
    "DIPS",
    "DIPS-wal",
    "DIPS-shm",
];

const AUTH_DIRS: &[&str] = &[
    "Local Storage",
    "Session Storage",
    "IndexedDB",
    "WebStorage",
    "SharedStorage",
];

fn is_preserved_name(name: &str) -> bool {
    PRESERVED_FILENAMES
        .iter()
        .any(|p| p.eq_ignore_ascii_case(name))
}

fn remove_prefixed_entries(
    base: &Path,
    rel_prefix: &str,
    prefixes: &[&str],
    cleared: &mut Vec<String>,
) {
    if !is_real_dir(base) {
        return;
    }
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|name| !is_preserved_name(name))
        .filter(|name| prefixes.iter().any(|p| name.starts_with(p)))
        .collect();
    names.sort();
    for name in names {
        let rel = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };
        if !cleared.contains(&rel) && remove_entry_safe(&base.join(&name)) {
            cleared.push(rel);
        }
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_claude_pids() -> Vec<String> {
    let mut pids = BTreeSet::new();
    for args in [
        vec!["-x", "Claude"],
        vec!["-f", "Claude\\.app/Contents/"],
        vec!["-x", "ShipIt"],
    ] {
        if let Ok(out) = crate::sysproxy::silent_command("pgrep").args(&args).output()
            && out.status.success()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let pid = line.trim();
                if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) {
                    // For `-x ShipIt`, double-check command path belongs to Claude.app to avoid
                    // touching unrelated Electron updaters.
                    if args == ["-x", "ShipIt"] {
                        let cmd_ok = crate::sysproxy::silent_command("ps")
                            .args(["-p", pid, "-o", "command="])
                            .output()
                            .ok()
                            .is_some_and(|ps_out| {
                                String::from_utf8_lossy(&ps_out.stdout).contains("Claude.app")
                            });
                        if !cmd_ok {
                            continue;
                        }
                    }
                    pids.insert(pid.to_string());
                }
            }
        }
    }
    pids.into_iter().collect()
}

#[cfg(target_os = "macos")]
fn close_claude_processes() -> usize {
    if !crate::sysproxy::os_effects_enabled() {
        return 0;
    }
    let initial = collect_macos_claude_pids();
    if initial.is_empty() {
        return 0;
    }
    let _ = crate::sysproxy::silent_command("osascript")
        .args(["-e", "tell application \"Claude\" to quit"])
        .output();

    for _ in 0..8 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if collect_macos_claude_pids().is_empty() {
            return initial.len();
        }
    }

    let remaining = collect_macos_claude_pids();
    if !remaining.is_empty() {
        let _ = crate::sysproxy::silent_command("kill")
            .arg("-TERM")
            .args(&remaining)
            .output();
        for _ in 0..5 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if collect_macos_claude_pids().is_empty() {
                break;
            }
        }
    }
    initial.len()
}

#[cfg(target_os = "windows")]
fn count_windows_claude_processes() -> usize {
    let Ok(out) = crate::sysproxy::silent_command("tasklist")
        .args(["/FI", "IMAGENAME eq claude.exe", "/FO", "CSV", "/NH"])
        .output()
    else {
        return 0;
    };
    if !out.status.success() {
        return 0;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.to_ascii_lowercase().contains("claude.exe"))
        .count()
}

#[cfg(target_os = "windows")]
fn close_claude_processes() -> usize {
    if !crate::sysproxy::os_effects_enabled() {
        return 0;
    }
    let initial = count_windows_claude_processes();
    if initial == 0 {
        return 0;
    }
    let _ = crate::sysproxy::silent_command("taskkill")
        .args(["/IM", "claude.exe", "/T"])
        .output();
    for _ in 0..8 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if count_windows_claude_processes() == 0 {
            return initial;
        }
    }
    let _ = crate::sysproxy::silent_command("taskkill")
        .args(["/IM", "claude.exe", "/T", "/F"])
        .output();
    initial
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn close_claude_processes() -> usize {
    let _ = crate::sysproxy::os_effects_enabled();
    0
}

/// Closes Claude processes (only when `os_effects_enabled()` is true) and removes ONLY auth/session
/// artifacts in `claude_dir` and `home_dir`, strictly preserving device IDs and user configs.
pub fn safe_logout_claude_fs_in(
    claude_dir: &Path,
    home_dir: Option<&Path>,
) -> Result<(usize, Vec<String>, bool), String> {
    let closed_processes = close_claude_processes();
    let mut cleared_items = Vec::new();

    if is_real_dir(claude_dir) {
        for rel in AUTH_FILES {
            let file_name = Path::new(rel)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if is_preserved_name(file_name) {
                continue;
            }
            let target = claude_dir.join(rel);
            if (is_regular_file(&target) || is_symlink(&target)) && remove_entry_safe(&target) {
                cleared_items.push((*rel).to_string());
            }
        }
        for rel in AUTH_DIRS {
            if is_preserved_name(rel) {
                continue;
            }
            let target = claude_dir.join(rel);
            if (is_real_dir(&target) || is_symlink(&target))
                && !cleared_items.iter().any(|x| x == rel)
                && remove_entry_safe(&target)
            {
                cleared_items.push((*rel).to_string());
            }
        }
        remove_prefixed_entries(
            &claude_dir.join("Network"),
            "Network",
            &["Cookies", "Trust Tokens"],
            &mut cleared_items,
        );
        remove_prefixed_entries(
            claude_dir,
            "",
            &["DIPS", "SharedStorage"],
            &mut cleared_items,
        );
    }

    if let Some(home) = home_dir {
        let creds = claude_cli_credentials_path(home);
        if (is_regular_file(&creds) || is_symlink(&creds)) && fs::remove_file(&creds).is_ok() {
            cleared_items.push(".claude/.credentials.json".to_string());
        }
        if strip_cli_oauth_from_claude_json(home)? {
            cleared_items.push(".claude.json (oauthAccount/userID)".to_string());
        }
    }

    let preserved_device_id = is_regular_file(&claude_dir.join("ant-device-registry.json"))
        || is_regular_file(&claude_dir.join("ccd-ids.json"));

    Ok((closed_processes, cleared_items, preserved_device_id))
}

/// Runs [`safe_logout_claude_fs_in`] against explicit directories and starts the 4h IP-change
/// cooldown in `state`.
pub async fn safe_logout_claude_with_dirs(
    state: &AppState,
    claude_dir: PathBuf,
    home_dir: Option<PathBuf>,
) -> Result<SafeLogoutResult, String> {
    let (closed_processes, cleared_items, preserved_device_id) =
        tokio::task::spawn_blocking(move || {
            safe_logout_claude_fs_in(&claude_dir, home_dir.as_deref())
        })
        .await
        .map_err(|e| e.to_string())??;

    let now = crate::auditor::network::current_timestamp() as i64;
    let cooldown_secs = DEFAULT_IP_CHANGE_COOLDOWN_SECS;
    let cooldown_until = state
        .record_safe_logout(now, cooldown_secs)
        .await
        .map_err(|e| e.to_string())?;

    Ok(SafeLogoutResult {
        closed_processes,
        cleared_items,
        preserved_device_id,
        cooldown_until,
        cooldown_secs,
    })
}

/// Safely logs out of Claude Desktop & Claude Code CLI in the default OS directories and starts
/// the 4-hour IP-change cooldown in `state`.
pub async fn safe_logout_claude(state: &AppState) -> Result<SafeLogoutResult, String> {
    let claude_dir = default_claude_desktop_dir().unwrap_or_else(|| PathBuf::from("mock_claude"));
    let home_dir = get_user_home_dir();
    safe_logout_claude_with_dirs(state, claude_dir, home_dir).await
}
