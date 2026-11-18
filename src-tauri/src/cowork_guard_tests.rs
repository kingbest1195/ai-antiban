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
fn task_xml_uses_manual_never_disabled_no_encoded_command_and_no_localappdata() {
    let xml = build_windows_task_xml_with_system_root(r"C:\Windows");
    assert!(is_task_xml_healthy(&xml));
    assert!(xml.contains("Manual"));
    assert!(xml.contains("3"));
    assert!(!xml.contains("Disabled"));
    assert!(!xml.contains("LOCALAPPDATA"));
    assert!(!xml.contains("-EncodedCommand"));
    assert!(!xml.contains("-ExecutionPolicy"));
    assert!(!xml.contains("Bypass"));
    assert!(xml.contains("CoworkVMService"));
    assert!(xml.contains("cowork-svc.exe"));
    assert!(!cowork_guard_inline_ps().contains('"'));
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
    assert!(parse_tasklist_has_claude("\"Claude.exe\",\"99\",\"Services\",\"0\",\"10 K\""));
    assert!(!parse_tasklist_has_claude(
        "INFO: No tasks are running which match the specified criteria.\r\n"
    ));
    assert!(!parse_tasklist_has_claude("\"chrome.exe\",\"555\",\"Console\",\"1\",\"50 K\""));
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
    let xml = build_windows_task_xml_with_system_root(r"C:\Windows");
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
    let xml = build_windows_task_xml_with_system_root(r"C:\Windows");
    let bytes = encode_utf16_le_with_bom(&xml);
    assert!(bytes.len() > 2);
    assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
    assert_eq!((bytes.len() - 2) % 2, 0);
    assert_eq!(decode_windows_cmd_text(&bytes), xml.trim());
}

#[test]
fn parses_install_cli_args_and_error_file_roundtrip() {
    assert_eq!(parse_install_cli_args(&[]), None);
    assert_eq!(
        parse_install_cli_args(&["--cleanup".to_string()]),
        None
    );
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
    write_install_error_file(Some(&err_path), "schtasks.exe /Create failed (code=Some(1))");
    assert_eq!(
        read_install_error_file(&err_path).as_deref(),
        Some("schtasks.exe /Create failed (code=Some(1))")
    );
}
