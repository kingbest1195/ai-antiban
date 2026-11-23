use super::*;

#[test]
fn parses_reg_start_dword_values() {
    let auto = "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CoworkVMService\r\n    Start    REG_DWORD    0x2\r\n";
    assert_eq!(parse_reg_start_dword(auto), Some(2));

    let manual = "    Start    REG_DWORD    0x3\n";
    assert_eq!(parse_reg_start_dword(manual), Some(3));

    let disabled = "    Start    REG_DWORD    0x4\n";
    assert_eq!(parse_reg_start_dword(disabled), Some(4));

    assert_eq!(
        parse_reg_start_dword("ERROR: The system was unable to find"),
        None
    );
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
  <Actions Context="Author"><Exec><Command>C:\Program Files\Zastava\zastava.exe</Command><Arguments>--apply-cowork-guard-once</Arguments></Exec></Actions>
</Task>"#;
    assert!(is_task_xml_healthy(good_xml));

    // Reject legacy PowerShell tasks so upgrades repair them to Zero-LOLBin
    let legacy_ps_xml = good_xml
        .replace(
            r"C:\Program Files\Zastava\zastava.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        .replace("--apply-cowork-guard-once", "-NoProfile -Command \"...\"");
    assert!(!is_task_xml_healthy(&legacy_ps_xml));

    // Reject unexpanded %LOCALAPPDATA% execution
    let lpe_xml = good_xml.replace(
        r"C:\Program Files\Zastava\zastava.exe",
        r"%LOCALAPPDATA%\Zastava\zastava.exe",
    );
    assert!(!is_task_xml_healthy(&lpe_xml));

    // Reject missing BootTrigger
    let logon_only = good_xml.replace("BootTrigger", "LogonTrigger");
    assert!(!is_task_xml_healthy(&logon_only));
    assert!(diagnose_task_xml(&logon_only).is_err());

    // Reject disabled BootTrigger
    let disabled_boot = good_xml.replace("<Enabled>true</Enabled>", "<Enabled>false</Enabled>");
    assert!(!is_task_xml_healthy(&disabled_boot));
    assert!(
        diagnose_task_xml(&disabled_boot)
            .unwrap_err()
            .contains("disabled")
    );

    // Accept real Windows COM task.Xml() output for S-1-5-18 (omits <RunLevel>, adds id attr)
    let win_com_xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <BootTrigger id="1">
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Program Files\Zastava\zastava.exe</Command>
      <Arguments>--apply-cowork-guard-once</Arguments>
    </Exec>
  </Actions>
</Task>"#;
    assert!(
        diagnose_task_xml(win_com_xml).is_ok(),
        "Windows COM XML without <RunLevel> must be healthy"
    );

    // Accept <UserId>SYSTEM</UserId>, <UserId>СИСТЕМА</UserId>, and localized NT AUTHORITY\СИСТЕМА
    let system_short = good_xml.replace("<UserId>S-1-5-18</UserId>", "<UserId>SYSTEM</UserId>");
    assert!(is_task_xml_healthy(&system_short));
    let system_short_ru = good_xml.replace("<UserId>S-1-5-18</UserId>", "<UserId>СИСТЕМА</UserId>");
    assert!(is_task_xml_healthy(&system_short_ru));
    let system_ru = good_xml.replace(
        "<UserId>S-1-5-18</UserId>",
        "<UserId>NT AUTHORITY\\СИСТЕМА</UserId>",
    );
    assert!(is_task_xml_healthy(&system_ru));

    // Reject task disabled at the <Settings><Enabled>false</Enabled></Settings> level
    // even when <BootTrigger><Enabled>true</Enabled></BootTrigger> remains enabled.
    let disabled_settings_xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><Enabled>false</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>C:\Program Files\Zastava\zastava.exe</Command><Arguments>--apply-cowork-guard-once</Arguments></Exec></Actions>
</Task>"#;
    assert!(!is_task_xml_healthy(disabled_settings_xml));
    assert!(
        diagnose_task_xml(disabled_settings_xml)
            .unwrap_err()
            .contains("<Settings> is disabled")
    );

    // Reject spoofed <Description>/<Author> containing S-1-5-18 or zastava.exe --apply-cowork-guard-once
    // when the actual <Principals> or <Exec> does not match.
    let spoofed_principal_xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>S-1-5-18 NT AUTHORITY\SYSTEM</Author>
    <Description>S-1-5-18 zastava.exe --apply-cowork-guard-once</Description>
  </RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-32-545</UserId></Principal></Principals>
  <Actions Context="Author"><Exec><Command>C:\Program Files\Zastava\zastava.exe</Command><Arguments>--apply-cowork-guard-once</Arguments></Exec></Actions>
</Task>"#;
    assert!(!is_task_xml_healthy(spoofed_principal_xml));
    assert!(
        diagnose_task_xml(spoofed_principal_xml)
            .unwrap_err()
            .contains("Principal is not SYSTEM")
    );

    let spoofed_exec_xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Runs zastava.exe --apply-cowork-guard-once as S-1-5-18</Description>
  </RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\notepad.exe</Command><Arguments>--noop</Arguments></Exec></Actions>
</Task>"#;
    assert!(!is_task_xml_healthy(spoofed_exec_xml));
    assert!(
        diagnose_task_xml(spoofed_exec_xml)
            .unwrap_err()
            .contains("Exec action must run zastava.exe")
    );
}

#[test]
fn task_xml_uses_native_cli_no_powershell_and_no_encoded_command() {
    let xml = build_windows_task_xml_with_exe(r"C:\Program Files\Zastava\zastava.exe");
    assert!(is_task_xml_healthy(&xml));
    assert!(xml.contains(APPLY_COWORK_GUARD_ONCE_ARG));
    assert!(!xml.contains("Disabled"));
    assert!(!xml.contains("LOCALAPPDATA"));
    assert!(!xml.to_ascii_lowercase().contains("powershell"));
    assert!(!xml.contains("-EncodedCommand"));
    assert!(!xml.contains("-ExecutionPolicy"));
    assert!(!xml.contains("Bypass"));
    assert!(xml.contains("CoworkVMService Manual Guard"));
    assert_eq!(
        build_schtasks_create_args(r"C:\Temp\task.xml"),
        [
            "/Create",
            "/TN",
            COWORK_TASK_FULL_NAME,
            "/XML",
            r"C:\Temp\task.xml",
            "/F"
        ]
    );
}

#[test]
fn parses_tasklist_for_claude_exe() {
    assert!(parse_tasklist_has_claude(
        "\"claude.exe\",\"1234\",\"Console\",\"1\",\"120,000 K\"\r\n"
    ));
    assert!(parse_tasklist_has_claude(
        "\"Claude.exe\",\"99\",\"Services\",\"0\",\"10 K\""
    ));
    assert!(!parse_tasklist_has_claude(
        "INFO: No tasks are running which match the specified criteria.\r\n"
    ));
    assert!(!parse_tasklist_has_claude(
        "\"chrome.exe\",\"555\",\"Console\",\"1\",\"50 K\""
    ));
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
-\t0\tcom.apple.TextInputUI.xpc.CursorUIViewService
42\t0\tcom.example.cursor-related
1234\t0\tcom.anthropic.claudefordesktop.ShipIt
-\t0\tcom.todesktop.cursor.ShipIt
";
    let agents = parse_launchctl_output(launchctl);
    assert_eq!(agents.len(), 2);
    assert_eq!(agents[0].name, "com.anthropic.claudefordesktop.ShipIt");
    assert!(agents[0].running);
    assert_eq!(agents[1].name, "com.todesktop.cursor.ShipIt");
    assert!(!agents[1].running);
    assert!(
        !agents
            .iter()
            .any(|a| a.name.contains("CursorUIViewService"))
    );
}

#[test]
fn dry_run_cowork_guard_is_safe() {
    crate::sysproxy::force_os_dry_run();
    let st = get_cowork_guard_status();
    assert!(!st.needs_repair);
    assert!(!trigger_cowork_guard_task());
    assert!(install_or_repair_cowork_guard().is_ok());
    assert_eq!(run_install_cowork_guard_cli(), 0);
    assert_eq!(run_install_cowork_guard_cli_with_error_file(None), 0);
}

#[test]
fn task_xml_has_utf16_encoding_and_omits_invalid_logontype() {
    let xml = build_windows_task_xml_with_exe(r"C:\Program Files\Zastava\zastava.exe");
    assert!(xml.starts_with(r#"<?xml version="1.0" encoding="UTF-16"?>"#));
    assert!(!xml.contains("<LogonType>"));
    assert!(!xml.to_ascii_lowercase().contains("serviceaccount"));
    assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
    assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
    assert!(validate_windows_task_xml(&xml).is_ok());

    let utf8_bad = xml.replace("encoding=\"UTF-16\"", "encoding=\"UTF-8\"");
    assert!(validate_windows_task_xml(&utf8_bad).is_err());

    // PowerShell's ServiceAccount enum is invalid in Task Scheduler 1.2 XML XSD.
    let invalid_logon = xml.replace(
        "<UserId>S-1-5-18</UserId>",
        "<UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType>",
    );
    assert!(validate_windows_task_xml(&invalid_logon).is_err());

    let missing_sid = xml.replace("<UserId>S-1-5-18</UserId>", "");
    assert!(validate_windows_task_xml(&missing_sid).is_err());

    // Valid XSD enum value (e.g. S4U) remains accepted if ever specified.
    let valid_enum = xml.replace(
        "<UserId>S-1-5-18</UserId>",
        "<UserId>S-1-5-18</UserId><LogonType>S4U</LogonType>",
    );
    assert!(validate_windows_task_xml(&valid_enum).is_ok());
}

#[test]
fn encodes_task_xml_as_utf16_le_with_bom() {
    let xml = build_windows_task_xml_with_exe(r"C:\Program Files\Zastava\zastava.exe");
    let bytes = encode_utf16_le_with_bom(&xml);
    assert!(bytes.len() > 2);
    assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
    assert_eq!((bytes.len() - 2) % 2, 0);
    assert_eq!(decode_windows_cmd_text(&bytes), xml.trim());
}

#[test]
fn parses_install_cli_args_and_error_file_roundtrip() {
    assert_eq!(parse_install_cli_args(&[]), None);
    assert_eq!(parse_install_cli_args(&["--cleanup".to_string()]), None);
    assert_eq!(
        parse_install_cli_args(&[INSTALL_COWORK_GUARD_ARG.to_string()]),
        Some(None)
    );
    assert_eq!(
        parse_install_cli_args(&[
            INSTALL_COWORK_GUARD_ARG.to_string(),
            COWORK_ERROR_FILE_ARG.to_string(),
            r"C:\Temp\err file.txt".to_string()
        ]),
        Some(Some(std::path::PathBuf::from(r"C:\Temp\err file.txt")))
    );
    assert_eq!(
        parse_install_cli_args(&[
            INSTALL_COWORK_GUARD_ARG.to_string(),
            format!("{COWORK_ERROR_FILE_ARG}=\"C:\\Temp\\err.txt\"")
        ]),
        Some(Some(std::path::PathBuf::from(r"C:\Temp\err.txt")))
    );

    let params = build_elevated_cli_params(Some(std::path::Path::new("/tmp/cowork.err")));
    assert_eq!(
        params,
        "--install-cowork-guard --error-file \"/tmp/cowork.err\""
    );

    let temp = tempfile::tempdir().unwrap();
    let err_path = temp.path().join("err.txt");
    assert_eq!(read_install_error_file(&err_path), None);
    write_install_error_file(
        Some(&err_path),
        "schtasks.exe /Create failed (code=Some(1))",
    );
    assert_eq!(
        read_install_error_file(&err_path).as_deref(),
        Some("schtasks.exe /Create failed (code=Some(1))")
    );
}

#[test]
fn decodes_utf16_le_without_bom_and_classifies_schtasks_errors() {
    let xml = build_windows_task_xml_with_exe(r"C:\Program Files\Zastava\zastava.exe");
    let no_bom_xml: Vec<u8> = xml.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    assert_eq!(decode_windows_cmd_text(&no_bom_xml), xml.trim());

    let ru_msg = "Ошибка: Отказано в доступе.";
    let no_bom_ru: Vec<u8> = ru_msg
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    assert_eq!(decode_windows_cmd_text(&no_bom_ru), ru_msg);

    // Valid UTF-8 Russian text must NOT be misdecoded as UTF-16 LE
    let utf8_ru = "Фоновая служба Claude работает нормально";
    assert_eq!(decode_windows_cmd_text(utf8_ru.as_bytes()), utf8_ru);

    assert_eq!(
        classify_schtasks_query_error("ERROR: Access is denied.", ""),
        SchtasksQueryError::AccessDenied
    );
    assert_eq!(
        classify_schtasks_query_error("ОШИБКА: Отказано в доступе.", ""),
        SchtasksQueryError::AccessDenied
    );
    assert_eq!(
        classify_schtasks_query_error("ERROR: The system cannot find the file specified.", ""),
        SchtasksQueryError::NotFound
    );
    assert!(is_task_list_healthy(
        "Имя задачи: \\Zastava\\CoworkVMServiceManualGuard\nВыполнить задачу: powershell.exe"
    ));
    assert!(!is_task_list_healthy(
        "TaskName: \\Zastava\\CoworkVMServiceManualGuard\nTask To Run: %LOCALAPPDATA%\\Zastava\\zastava.exe"
    ));

    let (_, summary_ok) = build_windows_summary(true, Some(3), false, true, true);
    let (_, summary_auto) = build_windows_summary(true, Some(2), true, true, true);
    assert!(!summary_ok.contains("Start="));
    assert!(!summary_auto.contains("Start="));
    assert!(!summary_ok.contains("CoworkVMService"));
    assert!(!summary_auto.contains("CoworkVMService"));
    assert!(summary_ok.contains("фоновая служба Claude"));
    assert!(summary_auto.contains("Фоновая служба Claude"));
}

fn encode_cp866(text: &str) -> Vec<u8> {
    text.chars()
        .map(|ch| match ch {
            '\u{0000}'..='\u{007F}' => ch as u8,
            'А'..='Я' => 0x80 + (ch as u32 - 'А' as u32) as u8,
            'а'..='п' => 0xA0 + (ch as u32 - 'а' as u32) as u8,
            'р'..='я' => 0xE0 + (ch as u32 - 'р' as u32) as u8,
            'Ё' => 0xF0,
            'ё' => 0xF1,
            other => panic!("unexpected char in CP866 test fixture: {other}"),
        })
        .collect()
}

#[test]
fn decodes_raw_cp866_access_denied_and_localized_system_xml() {
    let raw_cp866_err = encode_cp866("ОШИБКА: Отказано в доступе.");
    // Sanity-check raw bytes match OEM CP866 ("ОШИБКА" starts with 0x8E, 0x98, 0x88, 0x81, 0x8A, 0x80).
    assert_eq!(&raw_cp866_err[..6], &[0x8E, 0x98, 0x88, 0x81, 0x8A, 0x80]);
    let decoded_err = task_xml::decode_cp866(&raw_cp866_err);
    assert_eq!(decoded_err, "ОШИБКА: Отказано в доступе.");
    #[cfg(not(target_os = "windows"))]
    assert_eq!(
        decode_windows_cmd_text(&raw_cp866_err),
        "ОШИБКА: Отказано в доступе."
    );
    assert_eq!(
        classify_schtasks_query_error(&decoded_err, ""),
        SchtasksQueryError::AccessDenied
    );
    assert_eq!(
        classify_schtasks_query_error("", "Error: 0x80070005"),
        SchtasksQueryError::AccessDenied
    );

    let xml_ru = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>NT AUTHORITY\СИСТЕМА</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Actions Context="Author"><Exec><Command>C:\Program Files\Zastava\zastava.exe</Command><Arguments>--apply-cowork-guard-once</Arguments></Exec></Actions>
</Task>"#;
    let raw_cp866_xml = encode_cp866(xml_ru);
    let decoded_xml = task_xml::decode_cp866(&raw_cp866_xml);
    assert!(
        decoded_xml.contains(r"NT AUTHORITY\СИСТЕМА"),
        "{decoded_xml}"
    );
    #[cfg(not(target_os = "windows"))]
    assert!(
        decode_windows_cmd_text(&raw_cp866_xml).contains(r"NT AUTHORITY\СИСТЕМА"),
        "non-Windows fallback must decode raw CP866 XML"
    );
    assert!(is_task_xml_healthy(&decoded_xml));
    assert_eq!(
        decode_windows_cmd_text("ОШИБКА: Отказано в доступе.".as_bytes()),
        "ОШИБКА: Отказано в доступе."
    );
}

#[test]
fn post_install_check_returns_err_when_needs_repair_is_true() {
    let broken_status = CoworkGuardStatus {
        platform: "windows".to_string(),
        supported: true,
        service_present: true,
        start_type: Some(2),
        service_running: true,
        task_installed: false,
        task_healthy: false,
        needs_repair: true,
        summary: "Фоновая служба Claude стоит на автозапуске".to_string(),
        detected_ai_apps: Vec::new(),
    };
    let err = install_or_repair_cowork_guard_with(|| Ok(()), || broken_status.clone()).unwrap_err();
    assert!(err.contains("task_installed=false"), "{err}");
    assert!(err.contains("task_healthy=false"), "{err}");
    assert!(err.contains("start_type=2"), "{err}");
    assert!(err.contains("needs_repair=true"), "{err}");

    let healthy_status = CoworkGuardStatus {
        platform: "windows".to_string(),
        supported: true,
        service_present: true,
        start_type: Some(3),
        service_running: false,
        task_installed: true,
        task_healthy: true,
        needs_repair: false,
        summary: "Защита активна".to_string(),
        detected_ai_apps: Vec::new(),
    };
    let ok = install_or_repair_cowork_guard_with(|| Ok(()), || healthy_status.clone()).unwrap();
    assert_eq!(ok, healthy_status);
}
