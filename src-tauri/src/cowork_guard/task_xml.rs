//! Task Scheduler XML generation, validation, and Windows CLI output parsing.

use super::COWORK_TASK_FULL_NAME;

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
       $reg='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\'+$n;\
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

fn xml_escape_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Builds the Task Scheduler 1.2 XML for `\Zastava\CoworkVMServiceManualGuard` (`AtStartup` as
/// `NT AUTHORITY\SYSTEM`, `HighestAvailable`). Uses `System32\WindowsPowerShell\v1.0\powershell.exe`
/// (no user-writable paths, no `-EncodedCommand`, no `-ExecutionPolicy Bypass`).
pub fn build_windows_task_xml_with_system_root(system_root: &str) -> String {
    let root = system_root.trim_end_matches(['\\', '/']);
    let ps_exe = xml_escape_text(&format!(
        r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe"
    ));
    let ps_args = xml_escape_text(&format!(
        "-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{}\"",
        cowork_guard_inline_ps()
    ));
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Zastava CoworkVMService Manual Guard</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{ps_exe}</Command>
      <Arguments>{ps_args}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// Builds the Task Scheduler XML using `%SystemRoot%` (defaulting to `C:\Windows`).
pub fn build_windows_task_xml() -> String {
    let sys_root = std::env::var("SystemRoot")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| r"C:\Windows".to_string());
    build_windows_task_xml_with_system_root(&sys_root)
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
    let needs_repair =
        (service_present && (bad_start || !task_ok)) || (task_installed && !task_healthy);

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

/// Parses `tasklist /FI "IMAGENAME eq claude.exe" /FO CSV /NH` output to check whether `claude.exe` is running.
pub fn parse_tasklist_has_claude(output: &str) -> bool {
    output.lines().any(|line| {
        let trimmed = line.trim();
        let Some(first) = trimmed.split(',').next() else {
            return false;
        };
        let exe = first.trim().trim_matches('"').trim();
        exe.eq_ignore_ascii_case("claude.exe")
    })
}

/// Builds the argument list for `schtasks.exe /Create` using a Task Scheduler XML file.
pub fn build_schtasks_create_args(xml_path: &str) -> [&str; 6] {
    ["/Create", "/TN", COWORK_TASK_FULL_NAME, "/XML", xml_path, "/F"]
}

/// Encodes XML text as little-endian UTF-16 with BOM (`0xFF, 0xFE`) for Windows `schtasks.exe /XML`.
pub fn encode_utf16_le_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + text.len() * 2);
    bytes.push(0xFF);
    bytes.push(0xFE);
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// Decodes stdout/stderr from Windows console tools (handling UTF-16 LE BOM as well as UTF-8).
pub fn decode_windows_cmd_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) && bytes.len() >= 2 {
        let payload = &bytes[2..];
        let units: Vec<u16> = payload
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .trim()
            .to_string();
    }
    String::from_utf8_lossy(bytes).trim().to_string()
}

/// Validates generated Task Scheduler 1.2 XML before passing it to `schtasks.exe /Create`.
///
/// Under the Task Scheduler 1.2 XSD (`http://schemas.microsoft.com/windows/2004/02/mit/task`),
/// `<LogonType>` only accepts `S4U`, `Password`, `InteractiveToken`, or
/// `InteractiveTokenOrPassword`; for built-in `S-1-5-18` (`NT AUTHORITY\SYSTEM`), `<LogonType>`
/// should be omitted (values like `ServiceAccount` are PowerShell-only and fail XSD validation).
pub fn validate_windows_task_xml(xml: &str) -> Result<(), String> {
    let lower = xml.to_ascii_lowercase();
    if !lower.contains("encoding=\"utf-16\"") {
        return Err("Task XML must declare encoding=\"UTF-16\"".to_string());
    }
    if !lower.contains("<task version=\"1.2\"")
        || !lower.contains("http://schemas.microsoft.com/windows/2004/02/mit/task")
    {
        return Err("Task XML must target Task Scheduler 1.2 schema".to_string());
    }
    if !lower.contains("<principals>") || !lower.contains("<userid>s-1-5-18</userid>") {
        return Err("Task XML must define S-1-5-18 Principal".to_string());
    }
    let mut search_from = 0;
    while let Some(rel_start) = lower[search_from..].find("<logontype>") {
        let content_start = search_from + rel_start + "<logontype>".len();
        let Some(rel_end) = lower[content_start..].find("</logontype>") else {
            return Err("Task XML contains unclosed <LogonType> element".to_string());
        };
        let logon_type = lower[content_start..content_start + rel_end].trim();
        let valid = matches!(
            logon_type,
            "s4u" | "password" | "interactivetoken" | "interactivetokenorpassword"
        );
        if !valid {
            return Err(format!(
                "Task XML contains invalid <LogonType>{logon_type}</LogonType> for Task Scheduler 1.2 schema"
            ));
        }
        search_from = content_start + rel_end + "</logontype>".len();
    }
    if !is_task_xml_healthy(xml) {
        return Err("Task XML failed security/trigger health check".to_string());
    }
    Ok(())
}
