//! Task Scheduler XML generation, validation, and Windows text decoding helpers.

use super::{APPLY_COWORK_GUARD_ONCE_ARG, COWORK_TASK_FULL_NAME};

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

/// Verifies Task Scheduler XML for `\Zastava\CoworkVMServiceManualGuard`:
/// - Boot trigger (`<BootTrigger>`)
/// - Principal is `SYSTEM` (`S-1-5-18`, `NT AUTHORITY\SYSTEM`, `NT AUTHORITY\СИСТЕМА`, `<UserId>SYSTEM</UserId>`)
/// - Highest privileges (`<RunLevel>HighestAvailable</RunLevel>`)
/// - Runs `zastava.exe` with `--apply-cowork-guard-once` (no unexpanded `%LOCALAPPDATA%` or shells)
pub fn is_task_xml_healthy(xml: &str) -> bool {
    let lower = xml.to_lowercase();
    let has_boot = lower.contains("<boottrigger>");
    let is_system = lower.contains("s-1-5-18")
        || lower.contains("nt authority\\system")
        || lower.contains("nt authority\\система")
        || lower.contains("<userid>system</userid>")
        || lower.contains("<userid>система</userid>");
    let is_highest = lower.contains("<runlevel>highestavailable</runlevel>");
    let uses_native_guard =
        lower.contains("zastava.exe") && lower.contains(APPLY_COWORK_GUARD_ONCE_ARG);
    let no_shell = !lower.contains("powershell")
        && !lower.contains("pwsh")
        && !lower.contains("cmd.exe")
        && !lower.contains("%localappdata%");
    has_boot && is_system && is_highest && uses_native_guard && no_shell
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchtasksQueryError {
    AccessDenied,
    NotFound,
    Other,
}

/// Classifies Task Scheduler error output across English and Russian Windows locales.
pub fn classify_schtasks_query_error(stderr: &str, stdout: &str) -> SchtasksQueryError {
    let combined = format!("{stderr}\n{stdout}").to_lowercase();
    if combined.contains("access is denied")
        || combined.contains("access denied")
        || combined.contains("отказано в доступе")
        || combined.contains("0x80070005")
        || combined.contains("e_accessdenied")
        || combined.contains("недостаточно прав")
    {
        return SchtasksQueryError::AccessDenied;
    }
    if combined.contains("cannot find")
        || combined.contains("не удается найти")
        || combined.contains("не удаётся найти")
        || combined.contains("does not exist")
        || combined.contains("не существует")
    {
        return SchtasksQueryError::NotFound;
    }
    SchtasksQueryError::Other
}

/// Validates task metadata text output when inspected as a list.
pub fn is_task_list_healthy(output: &str) -> bool {
    let lower = output.to_lowercase();
    let has_task_name = lower.contains("coworkvmservicemanualguard");
    let no_unexpanded = !lower.contains("%localappdata%");
    has_task_name && no_unexpanded
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
/// `NT AUTHORITY\SYSTEM`, `HighestAvailable`) invoking `exe_path --apply-cowork-guard-once`.
pub fn build_windows_task_xml_with_exe(exe_path: &str) -> String {
    let escaped_exe = xml_escape_text(exe_path.trim());
    let escaped_arg = xml_escape_text(APPLY_COWORK_GUARD_ONCE_ARG);
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
      <Command>{escaped_exe}</Command>
      <Arguments>{escaped_arg}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// Builds the Task Scheduler XML using the current `zastava.exe` path.
pub fn build_windows_task_xml() -> String {
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| r"C:\Program Files\Zastava\zastava.exe".to_string());
    build_windows_task_xml_with_exe(&exe)
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
        "Фоновая служба Claude не обнаружена — приложение из Microsoft Store не установлено."
            .to_string()
    } else if !service_present && task_ok {
        "Защита настроена. Фоновая служба Claude сейчас не установлена.".to_string()
    } else if start_type == Some(3) && task_ok {
        if service_running {
            "Защита активна: фоновая служба Claude запускается только вручную, задача защиты исправна. Сейчас служба работает для открытого Claude."
                .to_string()
        } else {
            "Защита активна: фоновая служба Claude переведена в ручной режим и не стартует до входа в систему."
                .to_string()
        }
    } else if start_type == Some(2) {
        "Фоновая служба Claude стоит на автозапуске и может стартовать до входа в систему и до запуска Заставы. Нажмите «Починить в 1 клик», чтобы перевести её в ручной режим."
            .to_string()
    } else if start_type == Some(4) {
        "Фоновая служба Claude полностью отключена — режим Cowork в приложении не запустится. Нажмите «Починить в 1 клик», чтобы вернуть ручной запуск."
            .to_string()
    } else if !task_ok {
        "Служба сейчас запускается вручную, но защитная задача планировщика не настроена или повреждена: обновление Claude может вернуть автозапуск."
            .to_string()
    } else {
        "Состояние фоновой службы Claude определено частично. Нажмите «Починить в 1 клик»."
            .to_string()
    };

    (needs_repair, summary)
}

/// Parses CSV process listing output to check whether `claude.exe` is running.
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

/// Legacy helper kept for argument-layout unit checks.
pub fn build_schtasks_create_args(xml_path: &str) -> [&str; 6] {
    [
        "/Create",
        "/TN",
        COWORK_TASK_FULL_NAME,
        "/XML",
        xml_path,
        "/F",
    ]
}

/// Encodes XML text as little-endian UTF-16 with BOM (`0xFF, 0xFE`).
pub fn encode_utf16_le_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + text.len() * 2);
    bytes.push(0xFF);
    bytes.push(0xFE);
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn is_likely_utf16_le_without_bom(bytes: &[u8]) -> bool {
    let mut len = bytes.len();
    while len >= 2 && bytes[len - 2] == 0 && bytes[len - 1] == 0 {
        len -= 2;
    }
    let trimmed = &bytes[..len];
    if trimmed.len() < 4 || !trimmed.len().is_multiple_of(2) {
        return false;
    }
    let pairs = trimmed.len() / 2;
    let mut odd_zeros = 0usize;
    let mut all_odd_ascii_or_cyrillic = true;
    for chunk in trimmed.as_chunks::<2>().0 {
        if chunk[0] == 0 && chunk[1] != 0 {
            return false;
        }
        if chunk[1] == 0 && chunk[0] != 0 {
            odd_zeros += 1;
        }
        if chunk[1] != 0 && chunk[1] != 0x04 {
            all_odd_ascii_or_cyrillic = false;
        }
    }
    (odd_zeros >= 2 && odd_zeros * 4 >= pairs) || (odd_zeros >= 1 && all_odd_ascii_or_cyrillic)
}

fn decode_utf16_le_payload(payload: &[u8]) -> String {
    let units: Vec<u16> = payload
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .trim()
        .to_string()
}

#[cfg(target_os = "windows")]
fn decode_oem_cp_windows(bytes: &[u8]) -> Option<String> {
    const CP_OEMCP: u32 = 1;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MultiByteToWideChar(
            code_page: u32,
            dw_flags: u32,
            lp_multi_byte_str: *const u8,
            cb_multi_byte: i32,
            lp_wide_char_str: *mut u16,
            cch_wide_char: i32,
        ) -> i32;
    }
    let len = i32::try_from(bytes.len()).ok()?;
    if len == 0 {
        return Some(String::new());
    }
    // SAFETY: `bytes` is valid for `len` bytes; null output pointer queries required UTF-16 buffer length.
    let wide_len =
        unsafe { MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), len, core::ptr::null_mut(), 0) };
    if wide_len <= 0 {
        return None;
    }
    let mut wide = vec![0u16; wide_len as usize];
    // SAFETY: `wide` has capacity `wide_len` UTF-16 code units.
    let written = unsafe {
        MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            len,
            wide.as_mut_ptr(),
            wide_len,
        )
    };
    if written <= 0 {
        return None;
    }
    wide.truncate(written as usize);
    Some(String::from_utf16_lossy(&wide))
}

#[rustfmt::skip]
const CP866_HIGH: [char; 128] = [
    'А','Б','В','Г','Д','Е','Ж','З','И','Й','К','Л','М','Н','О','П',
    'Р','С','Т','У','Ф','Х','Ц','Ч','Ш','Щ','Ъ','Ы','Ь','Э','Ю','Я',
    'а','б','в','г','д','е','ж','з','и','й','к','л','м','н','о','п',
    '░','▒','▓','│','┤','╡','╢','╖','╕','╣','║','╗','╝','╜','╛','┐',
    '└','┴','┬','├','─','┼','╞','╟','╚','╔','╩','╦','╠','═','╬','╧',
    '╨','╤','╥','╙','╘','╒','╓','╫','╪','┘','┌','█','▄','▌','▐','▀',
    'р','с','т','у','ф','х','ц','ч','ш','щ','ъ','ы','ь','э','ю','я',
    'Ё','ё','Є','є','Ї','ї','Ў','ў','°','∙','·','√','№','¤','■','\u{00A0}',
];

/// Decodes raw OEM CP866 bytes (Russian Windows console default) into UTF-8 `String`.
pub fn decode_cp866(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b < 0x80 {
            out.push(b as char);
        } else {
            out.push(CP866_HIGH[(b - 0x80) as usize]);
        }
    }
    out
}

/// Decodes Windows text buffers in strict order:
/// 1. UTF-16 LE (with BOM or heuristic without BOM),
/// 2. Valid UTF-8 (`std::str::from_utf8`),
/// 3. Windows `MultiByteToWideChar(CP_OEMCP)` on Windows / pure-Rust CP866 fallback cross-platform.
pub fn decode_windows_cmd_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) && bytes.len() >= 2 {
        return decode_utf16_le_payload(&bytes[2..]);
    }
    if is_likely_utf16_le_without_bom(bytes) {
        return decode_utf16_le_payload(bytes);
    }
    if let Ok(utf8) = std::str::from_utf8(bytes) {
        return utf8.trim_end_matches('\0').trim().to_string();
    }
    #[cfg(target_os = "windows")]
    if let Some(oem) = decode_oem_cp_windows(bytes) {
        return oem.trim_end_matches('\0').trim().to_string();
    }
    decode_cp866(bytes)
        .trim_end_matches('\0')
        .trim()
        .to_string()
}

/// Validates generated Task Scheduler 1.2 XML before COM registration.
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
