use crate::auditor::geo_matrix::ProviderId;

/// Returns `true` only when a Windows executable path belongs to Claude Desktop
/// (Microsoft Store MSIX `WindowsApps\Claude_*` or Classic `AnthropicClaude` / `Program Files\Claude`),
/// rejecting native Claude Code CLI (`claude.exe`) paths and bare unqualified names.
pub fn is_windows_claude_desktop_exe(executable_path: &str) -> bool {
    let normalized = executable_path
        .trim()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if !normalized.ends_with("/claude.exe") {
        return false;
    }
    const CLI_EXCLUSIONS: &[&str] = &[
        "/.local/bin/",
        "/.claude/",
        "/npm/",
        "/nodejs/",
        "/scoop/",
        "/cargo/",
        "/claude-code/",
        "/claude_code/",
        "/nvm/",
        "/volta/",
        "/fnm/",
    ];
    if CLI_EXCLUSIONS.iter().any(|m| normalized.contains(m)) {
        return false;
    }
    const DESKTOP_MARKERS: &[&str] = &[
        "/windowsapps/claude_",
        "/anthropicclaude/",
        "/claude desktop/",
        "/claude-desktop/",
        "/program files/claude/",
        "/program files (x86)/claude/",
        "/appdata/local/programs/claude/",
    ];
    DESKTOP_MARKERS.iter().any(|m| normalized.contains(m))
}

/// Parses `PID|ExecutablePath` lines (from Win32_Process) and returns only verified
/// Windows Claude Desktop PIDs, never Claude Code CLI PIDs.
pub fn filter_windows_claude_desktop_pids(process_lines: &str) -> Vec<u32> {
    let mut pids: Vec<u32> = process_lines
        .lines()
        .filter_map(|line| {
            let (pid_raw, exe_path) = line.trim().split_once('|')?;
            let pid = pid_raw.trim().parse::<u32>().ok()?;
            (pid > 0 && is_windows_claude_desktop_exe(exe_path)).then_some(pid)
        })
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// Returns `true` when a macOS process command line belongs to the Claude Desktop app bundle,
/// rejecting terminal Claude Code CLI invocations.
pub fn is_macos_claude_desktop_cmd(command_line: &str) -> bool {
    let lower = command_line.trim().to_ascii_lowercase();
    lower.contains("claude.app/contents/macos/claude")
        || lower.contains("claude.app/contents/frameworks/claude helper")
}

/// Soft-closes the running desktop client for `provider` (strictly respecting `os_effects_enabled()`),
/// never killing native Claude Code CLI processes.
pub fn soft_close_ai_client(provider: ProviderId) -> usize {
    if !crate::sysproxy::os_effects_enabled() {
        return 0;
    }
    match provider {
        ProviderId::Gemini => 0,
        ProviderId::Anthropic => soft_close_claude_desktop(),
        ProviderId::Openai => soft_close_chatgpt_desktop(),
    }
}

/// Soft-closes Antigravity desktop processes without touching unrelated terminals or LOLBins.
pub fn soft_close_antigravity() -> usize {
    if !crate::sysproxy::os_effects_enabled() {
        return 0;
    }
    soft_close_antigravity_impl()
}

#[cfg(target_os = "windows")]
fn query_windows_claude_desktop_pids() -> Vec<u32> {
    let Ok(entries) = crate::win_native::process::list_processes() else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = entries
        .into_iter()
        .filter(|p| p.pid > 0 && p.exe_name.eq_ignore_ascii_case("claude.exe"))
        .filter_map(|p| {
            let exe_path = crate::win_native::process::query_process_image_path(p.pid).ok()?;
            is_windows_claude_desktop_exe(&exe_path).then_some(p.pid)
        })
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(target_os = "windows")]
fn terminate_windows_pids_and_wait<F>(query_pids: F) -> usize
where
    F: Fn() -> Vec<u32>,
{
    let initial = query_pids();
    if initial.is_empty() {
        return 0;
    }
    for pid in &initial {
        let _ = crate::win_native::process::terminate_process_by_pid(*pid, 1);
    }
    for _ in 0..8 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if query_pids().is_empty() {
            return initial.len();
        }
    }
    for pid in query_pids() {
        let _ = crate::win_native::process::terminate_process_by_pid(pid, 1);
    }
    initial.len()
}

#[cfg(target_os = "windows")]
fn soft_close_claude_desktop() -> usize {
    terminate_windows_pids_and_wait(query_windows_claude_desktop_pids)
}

#[cfg(target_os = "windows")]
fn soft_close_chatgpt_desktop() -> usize {
    terminate_windows_pids_and_wait(|| {
        crate::win_native::process::find_pids_by_exe_name("ChatGPT.exe").unwrap_or_default()
    })
}

#[cfg(target_os = "windows")]
fn soft_close_antigravity_impl() -> usize {
    terminate_windows_pids_and_wait(|| {
        let Ok(entries) = crate::win_native::process::list_processes() else {
            return Vec::new();
        };
        entries
            .into_iter()
            .filter(|p| p.pid > 0 && p.exe_name.eq_ignore_ascii_case("antigravity.exe"))
            .filter(|p| {
                crate::win_native::process::query_process_image_path(p.pid)
                    .map(|path| path.to_ascii_lowercase().contains("antigravity"))
                    .unwrap_or(true)
            })
            .map(|p| p.pid)
            .collect()
    })
}

#[cfg(target_os = "macos")]
fn collect_macos_desktop_pids(app: &str) -> Vec<String> {
    let Ok(out) = crate::sysproxy::silent_command("ps")
        .args(["-axo", "pid=,command="])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (pid, cmd) = trimmed.split_once(char::is_whitespace)?;
            let matched = match app {
                "Claude" => is_macos_claude_desktop_cmd(cmd),
                "ChatGPT" => cmd
                    .to_ascii_lowercase()
                    .contains("chatgpt.app/contents/macos/chatgpt"),
                "Antigravity" => cmd
                    .to_ascii_lowercase()
                    .contains("antigravity.app/contents/macos/antigravity"),
                _ => false,
            };
            matched.then(|| pid.trim().to_string())
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn soft_close_macos_app(app: &str) -> usize {
    let initial = collect_macos_desktop_pids(app);
    if initial.is_empty() {
        return 0;
    }
    let script = format!("tell application \"{app}\" to quit");
    let _ = crate::sysproxy::silent_command("osascript")
        .args(["-e", &script])
        .output();
    for _ in 0..8 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if collect_macos_desktop_pids(app).is_empty() {
            return initial.len();
        }
    }
    let remaining = collect_macos_desktop_pids(app);
    if !remaining.is_empty() {
        let _ = crate::sysproxy::silent_command("kill")
            .arg("-TERM")
            .args(&remaining)
            .output();
    }
    initial.len()
}

#[cfg(target_os = "macos")]
fn soft_close_claude_desktop() -> usize {
    soft_close_macos_app("Claude")
}

#[cfg(target_os = "macos")]
fn soft_close_chatgpt_desktop() -> usize {
    soft_close_macos_app("ChatGPT")
}

#[cfg(target_os = "macos")]
fn soft_close_antigravity_impl() -> usize {
    soft_close_macos_app("Antigravity")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn soft_close_claude_desktop() -> usize {
    0
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn soft_close_chatgpt_desktop() -> usize {
    0
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn soft_close_antigravity_impl() -> usize {
    0
}
