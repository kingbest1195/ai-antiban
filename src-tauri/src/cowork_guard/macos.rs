//! macOS non-destructive inspection of running AI apps, helpers, and LaunchAgents.

#[cfg(target_os = "macos")]
use super::CoworkGuardStatus;
use super::DetectedAiProcess;

/// Parses `ps -axo comm=` output on macOS to find running AI apps/helpers.
pub fn parse_macos_ps_output(ps_stdout: &str) -> Vec<DetectedAiProcess> {
    let targets: &[(&str, &str, &str)] = &[
        ("Claude", "app", "Claude Desktop"),
        ("ChatGPT", "app", "ChatGPT Desktop"),
        ("Cursor", "app", "Cursor IDE"),
        ("Antigravity", "app", "Antigravity"),
        (
            "com.anthropic.claudefordesktop.ShipIt",
            "helper",
            "Claude Desktop Updater (ShipIt)",
        ),
        ("ShipIt", "helper", "Claude/Electron Updater (ShipIt)"),
    ];
    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in ps_stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        for &(needle, kind, label) in targets {
            let matched = if needle == "ShipIt" {
                trimmed.contains("Claude") && trimmed.contains("ShipIt")
            } else if needle == "Claude" {
                trimmed.ends_with("/MacOS/Claude")
                    || trimmed == "Claude"
                    || trimmed.contains("Claude.app/Contents/Helpers/")
            } else if needle == "ChatGPT" {
                trimmed.ends_with("/MacOS/ChatGPT")
                    || trimmed == "ChatGPT"
                    || trimmed.contains("ChatGPT.app/")
            } else if needle == "Cursor" {
                trimmed.ends_with("/MacOS/Cursor") || trimmed == "Cursor"
            } else if needle == "Antigravity" {
                trimmed.ends_with("/MacOS/Antigravity") || trimmed == "Antigravity"
            } else {
                trimmed.contains(needle)
            };

            if matched && seen.insert(label) {
                found.push(DetectedAiProcess {
                    name: label.to_string(),
                    kind: kind.to_string(),
                    running: true,
                    detail: trimmed.to_string(),
                });
            }
        }
    }
    found
}

/// Parses `launchctl list` output on macOS for known AI background LaunchAgents.
pub fn parse_launchctl_output(stdout: &str) -> Vec<DetectedAiProcess> {
    let mut found = Vec::new();
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        let label = cols[2];
        let lower = label.to_ascii_lowercase();
        if lower.starts_with("com.apple.") {
            continue;
        }
        let is_cursor_ide = (lower.contains("todesktop") && lower.contains("cursor"))
            || lower.contains("cursor.app")
            || lower.contains("com.cursor.");
        let interesting = lower.contains("claudefordesktop")
            || lower.contains("anthropic")
            || lower.contains("openai.chat")
            || lower.contains("chatgpt")
            || is_cursor_ide;
        if !interesting {
            continue;
        }
        let running = cols[0] != "-";
        found.push(DetectedAiProcess {
            name: label.to_string(),
            kind: "launch_agent".to_string(),
            running,
            detail: if running {
                format!("LaunchAgent активен (PID {})", cols[0])
            } else {
                "LaunchAgent зарегистрирован".to_string()
            },
        });
    }
    found
}

#[cfg(target_os = "macos")]
pub(super) fn query_macos_status() -> CoworkGuardStatus {
    let mut detected = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    if let Ok(out) = std::process::Command::new("ps")
        .args(["-axo", "comm="])
        .output()
        && out.status.success()
    {
        for item in parse_macos_ps_output(&String::from_utf8_lossy(&out.stdout)) {
            if seen_names.insert(item.name.clone()) {
                detected.push(item);
            }
        }
    }
    if let Ok(out) = std::process::Command::new("launchctl").arg("list").output()
        && out.status.success()
    {
        for item in parse_launchctl_output(&String::from_utf8_lossy(&out.stdout)) {
            if seen_names.insert(item.name.clone()) {
                detected.push(item);
            }
        }
    }

    let running_apps: Vec<&str> = detected
        .iter()
        .filter(|d| d.running && d.kind == "app")
        .map(|d| d.name.as_str())
        .collect();

    let summary = if !running_apps.is_empty() {
        format!(
            "На macOS активны: {}. Включите автозапуск Заставы в трей, чтобы локальный шлюз 127.0.0.1:8899 поднимался при входе раньше открытия ИИ-приложений.",
            running_apps.join(", ")
        )
    } else if !detected.is_empty() {
        "Зарегистрированы фоновые агенты ИИ-приложений (например, автообновление). Включите автозапуск Заставы в трей для защиты с момента входа в систему."
            .to_string()
    } else {
        "Фоновых ИИ-служб не обнаружено. На macOS Cowork запускается только внутри сессии Claude Desktop."
            .to_string()
    };

    CoworkGuardStatus {
        platform: "macos".to_string(),
        supported: true,
        service_present: false,
        start_type: None,
        service_running: false,
        task_installed: false,
        task_healthy: false,
        needs_repair: false,
        summary,
        detected_ai_apps: detected,
    }
}
