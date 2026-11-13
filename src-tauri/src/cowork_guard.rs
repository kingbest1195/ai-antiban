//! Protection against background AI service auto-start before Zastava:
//! - Windows: `CoworkVMService` (Microsoft Store Claude Desktop) boot-time Task Scheduler guard
//!   (`Start = 3` Manual, NEVER `4` Disabled) without executing any user-writable binaries.
//! - macOS: non-destructive inspection of running AI apps/helpers/LoginItems/LaunchAgents.
//!
//! All real OS probes/mutations respect [`crate::sysproxy::os_effects_enabled`] (`ZASTAVA_OS_DRY_RUN=1`).

use serde::{Deserialize, Serialize};

pub const COWORK_SERVICE_NAME: &str = "CoworkVMService";
pub const COWORK_SERVICE_REG_PATH: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\CoworkVMService";
pub const COWORK_TASK_PATH: &str = r"\Zastava\";
pub const COWORK_TASK_NAME: &str = "CoworkVMServiceManualGuard";
pub const COWORK_TASK_FULL_NAME: &str = r"Zastava\CoworkVMServiceManualGuard";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectedAiProcess {
    pub name: String,
    pub kind: String,
    pub running: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoworkGuardStatus {
    pub platform: String,
    pub supported: bool,
    pub service_present: bool,
    pub start_type: Option<u32>,
    pub service_running: bool,
    pub task_installed: bool,
    pub task_healthy: bool,
    pub needs_repair: bool,
    pub summary: String,
    #[serde(default)]
    pub detected_ai_apps: Vec<DetectedAiProcess>,
}

/// Parses `reg query ... /v Start` stdout and extracts the `REG_DWORD` value (e.g. `0x2` -> `2`).
pub fn parse_reg_start_dword(output: &str) -> Option<u32> {
    for line in output.lines() {
        let trimmed = line.trim();
        let mut parts = trimmed.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case("Start") {
            continue;
        }
        let Some(_reg_type) = parts.next() else {
            continue;
        };
        let Some(raw_val) = parts.next() else {
            continue;
        };
        if let Some(hex) = raw_val
            .strip_prefix("0x")
            .or_else(|| raw_val.strip_prefix("0X"))
        {
            if let Ok(v) = u32::from_str_radix(hex, 16) {
                return Some(v);
            }
        } else if let Ok(v) = raw_val.parse::<u32>() {
            return Some(v);
        }
    }
    None
}

/// Parses `sc query CoworkVMService` output to determine if `STATE` is `RUNNING`.
pub fn parse_sc_running(output: &str) -> bool {
    output.lines().any(|line| {
        let upper = line.to_ascii_uppercase();
        upper.contains("STATE") && upper.contains("RUNNING")
    })
}

/// Verifies `schtasks /Query /TN "Zastava\CoworkVMServiceManualGuard" /XML` output:
/// - Boot trigger (`<BootTrigger>`)
/// - Principal is `SYSTEM` (`S-1-5-18` or `NT AUTHORITY\SYSTEM`)
/// - Highest privileges (`<RunLevel>HighestAvailable</RunLevel>`)
/// - Does not execute anything inside user-writable `%LOCALAPPDATA%` / `AppData\Local`
pub fn is_task_xml_healthy(xml: &str) -> bool {
    let lower = xml.to_ascii_lowercase();
    let has_boot = lower.contains("<boottrigger>");
    let is_system = lower.contains("s-1-5-18") || lower.contains("nt authority\\system");
    let is_highest = lower.contains("<runlevel>highestavailable</runlevel>");
    let uses_powershell = lower.contains("powershell.exe");
    let no_user_writable = !lower.contains("appdata\\local")
        && !lower.contains("%localappdata%")
        && !lower.contains("zastava.exe");
    has_boot && is_system && is_highest && uses_powershell && no_user_writable
}

/// Fixed inline PowerShell payload executed by `\Zastava\CoworkVMServiceManualGuard` as SYSTEM.
/// Uses zero user-writable paths; sets `Start = 3` (Manual, NEVER 4 Disabled) and stops the
/// service if running while `claude.exe` is not running.
pub fn cowork_guard_inline_ps() -> &'static str {
    "$ErrorActionPreference='SilentlyContinue';\
     $names=@('CoworkVMService');\
     Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\*' |\
       Where-Object { $_.ImagePath -like '*WindowsApps\\Claude_*\\app\\resources\\cowork-svc.exe*' } |\
       ForEach-Object { if ($_.PSChildName -and ($names -notcontains $_.PSChildName)) { $names += $_.PSChildName } };\
     $claudeRunning = @(Get-Process -Name 'claude' -ErrorAction SilentlyContinue).Count -gt 0;\
     foreach ($n in $names) {\
       $reg=\"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n\";\
       if (Test-Path $reg) {\
         $cur=(Get-ItemProperty -Path $reg -Name 'Start').Start;\
         if ($cur -ne 3) {\
           Set-Service -Name $n -StartupType Manual;\
           Set-ItemProperty -Path $reg -Name 'Start' -Value 3 -Type DWord;\
         }\
         $svc=Get-Service -Name $n;\
         if ($svc -and $svc.Status -eq 'Running' -and -not $claudeRunning) {\
           Stop-Service -Name $n -Force;\
         }\
       }\
     }"
}

/// Builds the elevated PowerShell installer command that registers the `ONSTART` SYSTEM task
/// AND immediately enforces `Start = 3` + stops `CoworkVMService` if `claude.exe` is closed.
pub fn build_windows_install_ps() -> String {
    let guard_payload = cowork_guard_inline_ps().replace('\'', "''");
    let task_arg = format!(
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command '{guard_payload}'"
    );
    let task_arg_escaped = task_arg.replace('\'', "''");
    format!(
        "$ErrorActionPreference='Stop';\
         $psExe=\"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\";\
         $action=New-ScheduledTaskAction -Execute $psExe -Argument '{task_arg_escaped}';\
         $trigger=New-ScheduledTaskTrigger -AtStartup;\
         $principal=New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -LogonType ServiceAccount -RunLevel Highest;\
         $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2);\
         Register-ScheduledTask -TaskPath '{COWORK_TASK_PATH}' -TaskName '{COWORK_TASK_NAME}' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null;\
         {guard_inline}",
        guard_inline = cowork_guard_inline_ps()
    )
}

pub fn build_windows_summary(
    service_present: bool,
    start_type: Option<u32>,
    service_running: bool,
    task_installed: bool,
    task_healthy: bool,
) -> (bool, String) {
    let bad_start = start_type == Some(2) || start_type == Some(4);
    let task_ok = task_installed && task_healthy;
    let needs_repair = (service_present && (bad_start || !task_ok)) || (task_installed && !task_healthy);

    let summary = if !service_present && !task_installed {
        "Служба CoworkVMService не обнаружена (Microsoft Store версия Claude Desktop не установлена)."
            .to_string()
    } else if !service_present && task_ok {
        "Задача планировщика настроена. Служба CoworkVMService сейчас не установлена.".to_string()
    } else if start_type == Some(3) && task_ok {
        if service_running {
            "Защита активна: тип запуска «Вручную» (Start=3), задача планировщика исправна. Служба сейчас работает для открытого Claude."
                .to_string()
        } else {
            "Защита активна: тип запуска CoworkVMService — «Вручную» (Start=3), задача при старте Windows исправна."
                .to_string()
        }
    } else if start_type == Some(2) {
        "CoworkVMService стоит на автозапуске (Start=2) и стартует до входа в систему. Нажмите «Настроить / Восстановить» для перевода в «Вручную» (Start=3)."
            .to_string()
    } else if start_type == Some(4) {
        "CoworkVMService отключена (Start=4) — Cowork в Claude не запустится. Восстановите тип запуска «Вручную» (Start=3)."
            .to_string()
    } else if !task_ok {
        "Тип запуска пока «Вручную», но задача планировщика не настроена или повреждена: обновление Claude может вернуть автозапуск."
            .to_string()
    } else {
        "Состояние CoworkVMService определено частично. Нажмите «Настроить / Восстановить»."
            .to_string()
    };

    (needs_repair, summary)
}

#[cfg(target_os = "windows")]
fn run_hidden_cmd(program: &str, args: &[&str]) -> Option<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
}

#[cfg(target_os = "windows")]
fn query_windows_status() -> CoworkGuardStatus {
    let reg_out = run_hidden_cmd("reg.exe", &["query", COWORK_SERVICE_REG_PATH, "/v", "Start"]);
    let (service_present, start_type) = match reg_out {
        Some(ref out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            (true, parse_reg_start_dword(&text))
        }
        _ => (false, None),
    };

    let service_running = if service_present {
        run_hidden_cmd("sc.exe", &["query", COWORK_SERVICE_NAME])
            .filter(|o| o.status.success())
            .map(|o| parse_sc_running(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or(false)
    } else {
        false
    };

    let task_xml = run_hidden_cmd("schtasks.exe", &["/Query", "/TN", COWORK_TASK_FULL_NAME, "/XML"]);
    let (task_installed, task_healthy) = match task_xml {
        Some(ref out) if out.status.success() => {
            let xml = String::from_utf8_lossy(&out.stdout);
            (true, is_task_xml_healthy(&xml))
        }
        _ => (false, false),
    };

    let (needs_repair, summary) = build_windows_summary(
        service_present,
        start_type,
        service_running,
        task_installed,
        task_healthy,
    );

    CoworkGuardStatus {
        platform: "windows".to_string(),
        supported: true,
        service_present,
        start_type,
        service_running,
        task_installed,
        task_healthy,
        needs_repair,
        summary,
        detected_ai_apps: Vec::new(),
    }
}

#[cfg(target_os = "windows")]
pub fn trigger_cowork_guard_task() -> bool {
    if !crate::sysproxy::os_effects_enabled() {
        return false;
    }
    run_hidden_cmd("schtasks.exe", &["/Run", "/TN", COWORK_TASK_FULL_NAME])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
pub fn trigger_cowork_guard_task() -> bool {
    false
}

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
        let interesting = lower.contains("claudefordesktop")
            || lower.contains("anthropic")
            || lower.contains("openai.chat")
            || lower.contains("chatgpt")
            || lower.contains("cursor");
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
fn query_macos_status() -> CoworkGuardStatus {
    let mut detected = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    if let Ok(out) = std::process::Command::new("ps").args(["-axo", "comm="]).output() {
        if out.status.success() {
            for item in parse_macos_ps_output(&String::from_utf8_lossy(&out.stdout)) {
                if seen_names.insert(item.name.clone()) {
                    detected.push(item);
                }
            }
        }
    }
    if let Ok(out) = std::process::Command::new("launchctl").arg("list").output() {
        if out.status.success() {
            for item in parse_launchctl_output(&String::from_utf8_lossy(&out.stdout)) {
                if seen_names.insert(item.name.clone()) {
                    detected.push(item);
                }
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

pub fn get_cowork_guard_status() -> CoworkGuardStatus {
    if !crate::sysproxy::os_effects_enabled() {
        let platform = crate::autostart::current_platform_name().to_string();
        return CoworkGuardStatus {
            platform,
            supported: cfg!(any(target_os = "windows", target_os = "macos")),
            service_present: false,
            start_type: None,
            service_running: false,
            task_installed: false,
            task_healthy: false,
            needs_repair: false,
            summary: "Проверка фоновых ИИ-служб (dry-run).".to_string(),
            detected_ai_apps: Vec::new(),
        };
    }

    #[cfg(target_os = "windows")]
    {
        query_windows_status()
    }
    #[cfg(target_os = "macos")]
    {
        query_macos_status()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        CoworkGuardStatus {
            platform: "linux".to_string(),
            supported: false,
            service_present: false,
            start_type: None,
            service_running: false,
            task_installed: false,
            task_healthy: false,
            needs_repair: false,
            summary: "Защита от фонового запуска CoworkVMService требуется только на Windows."
                .to_string(),
            detected_ai_apps: Vec::new(),
        }
    }
}

/// User-triggered install/repair of `\Zastava\CoworkVMServiceManualGuard` on Windows
/// (requests UAC once via `Start-Process ... -Verb RunAs`), plus immediate `Start = 3` + stop fix.
pub fn install_or_repair_cowork_guard() -> Result<CoworkGuardStatus, String> {
    if !crate::sysproxy::os_effects_enabled() {
        return Ok(get_cowork_guard_status());
    }

    #[cfg(target_os = "windows")]
    {
        use base64::Engine;
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let script = build_windows_install_ps();
        let utf16: Vec<u8> = script
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);

        let launcher = format!(
            "$p = Start-Process -FilePath \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-EncodedCommand','{encoded}') -Verb RunAs -PassThru -Wait; exit $p.ExitCode"
        );
        let out = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &launcher,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Не удалось запустить PowerShell для настройки задачи: {e}"))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(if stderr.is_empty() {
                "Настройка задачи планировщика отменена или не хватило прав администратора."
                    .to_string()
            } else {
                format!("Ошибка настройки задачи планировщика: {stderr}")
            });
        }
        Ok(query_windows_status())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(get_cowork_guard_status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reg_start_dword_values() {
        let auto = "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CoworkVMService\r\n    Start    REG_DWORD    0x2\r\n";
        assert_eq!(parse_reg_start_dword(auto), Some(2));

        let manual = "    Start    REG_DWORD    0x3\n";
        assert_eq!(parse_reg_start_dword(manual), Some(3));

        let disabled = "    Start    REG_DWORD    0x4\n";
        assert_eq!(parse_reg_start_dword(disabled), Some(4));

        assert_eq!(parse_reg_start_dword("ERROR: The system was unable to find"), None);
    }

    #[test]
    fn parses_sc_query_state() {
        let running = "SERVICE_NAME: CoworkVMService\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n";
        assert!(parse_sc_running(running));

        let stopped = "SERVICE_NAME: CoworkVMService\n        STATE              : 1  STOPPED\n";
        assert!(!parse_sc_running(stopped));
    }

    #[test]
    fn validates_task_xml_security_and_triggers() {
        let good_xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-NoProfile -Command "..."</Arguments></Exec></Actions>
</Task>"#;
        assert!(is_task_xml_healthy(good_xml));

        // Reject user-writable %LOCALAPPDATA% execution (LPE guard)
        let lpe_xml = good_xml.replace(
            "powershell.exe",
            r"C:\Users\alice\AppData\Local\Zastava\zastava.exe",
        );
        assert!(!is_task_xml_healthy(&lpe_xml));

        // Reject missing BootTrigger
        let logon_only = good_xml.replace("BootTrigger", "LogonTrigger");
        assert!(!is_task_xml_healthy(&logon_only));
    }

    #[test]
    fn install_ps_uses_manual_never_disabled_and_no_localappdata() {
        let ps = build_windows_install_ps();
        assert!(ps.contains("Manual"));
        assert!(ps.contains("3"));
        assert!(!ps.contains("Disabled"));
        assert!(!ps.contains("LOCALAPPDATA"));
        assert!(ps.contains("CoworkVMService"));
        assert!(ps.contains("cowork-svc.exe"));
    }

    #[test]
    fn parses_macos_processes_and_launchctl() {
        let ps = "\
/sbin/launchd
/Applications/Claude.app/Contents/MacOS/Claude
/Applications/Claude.app/Contents/Frameworks/Squirrel.framework/Resources/ShipIt
/Applications/Antigravity.app/Contents/MacOS/Antigravity
";
        let apps = parse_macos_ps_output(ps);
        assert!(apps.iter().any(|a| a.name == "Claude Desktop" && a.running));
        assert!(apps.iter().any(|a| a.name == "Antigravity" && a.running));
        assert!(apps.iter().any(|a| a.kind == "helper"));

        let launchctl = "\
-\t0\tcom.apple.Finder
1234\t0\tcom.anthropic.claudefordesktop.ShipIt
";
        let agents = parse_launchctl_output(launchctl);
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "com.anthropic.claudefordesktop.ShipIt");
        assert!(agents[0].running);
    }

    #[test]
    fn dry_run_cowork_guard_is_safe() {
        crate::sysproxy::force_os_dry_run();
        let st = get_cowork_guard_status();
        assert!(!st.needs_repair);
        assert!(!trigger_cowork_guard_task());
        assert!(install_or_repair_cowork_guard().is_ok());
    }
}
