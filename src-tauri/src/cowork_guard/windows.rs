//! Windows CoworkVMService status querying, Task Scheduler registration, and enforcement.

use super::task_xml::{
    build_schtasks_create_args, build_windows_summary, build_windows_task_xml,
    decode_windows_cmd_text, encode_utf16_le_with_bom, is_task_xml_healthy, parse_sc_running,
    parse_tasklist_has_claude, validate_windows_task_xml,
};
use super::{
    COWORK_SERVICE_NAME, COWORK_SERVICE_REG_SUBKEY, COWORK_TASK_FULL_NAME, CoworkGuardStatus,
};

fn run_hidden_cmd(program: &str, args: &[&str]) -> Option<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
}

pub(super) fn query_windows_status() -> CoworkGuardStatus {
    let (service_present, start_type) = match crate::win_reg::get_dword(
        crate::win_reg::RootKey::HkeyLocalMachine,
        COWORK_SERVICE_REG_SUBKEY,
        "Start",
    ) {
        Ok(Some(v)) => (true, Some(v)),
        _ => (false, None),
    };

    let service_running = if service_present {
        run_hidden_cmd("sc.exe", &["query", COWORK_SERVICE_NAME])
            .filter(|o| o.status.success())
            .map(|o| parse_sc_running(&decode_windows_cmd_text(&o.stdout)))
            .unwrap_or(false)
    } else {
        false
    };

    let task_xml = run_hidden_cmd(
        "schtasks.exe",
        &["/Query", "/TN", COWORK_TASK_FULL_NAME, "/XML"],
    );
    let (task_installed, task_healthy) = match task_xml {
        Some(ref out) if out.status.success() => {
            let xml = decode_windows_cmd_text(&out.stdout);
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

pub(super) fn trigger_cowork_guard_task() -> bool {
    if !crate::sysproxy::os_effects_enabled() {
        return false;
    }
    match run_hidden_cmd("schtasks.exe", &["/Run", "/TN", COWORK_TASK_FULL_NAME]) {
        Some(out) if out.status.success() => true,
        Some(out) => {
            let err = decode_windows_cmd_text(&out.stderr);
            let msg = if err.is_empty() {
                decode_windows_cmd_text(&out.stdout)
            } else {
                err
            };
            crate::diagnostics::record(
                "cowork_guard",
                &format!(
                    "schtasks.exe /Run failed (code={:?}): {msg}",
                    out.status.code()
                ),
            );
            false
        }
        None => {
            crate::diagnostics::record("cowork_guard", "failed to spawn schtasks.exe /Run");
            false
        }
    }
}

fn is_claude_process_running() -> bool {
    run_hidden_cmd(
        "tasklist.exe",
        &["/FI", "IMAGENAME eq claude.exe", "/FO", "CSV", "/NH"],
    )
    .filter(|o| o.status.success())
    .map(|o| parse_tasklist_has_claude(&decode_windows_cmd_text(&o.stdout)))
    .unwrap_or(false)
}

fn register_cowork_guard_task() -> Result<(), String> {
    let xml = build_windows_task_xml();
    validate_windows_task_xml(&xml)?;
    let xml_bytes = encode_utf16_le_with_bom(&xml);
    let xml_path = std::env::temp_dir().join(format!(
        "zastava-cowork-task-{}.xml",
        std::process::id()
    ));
    std::fs::write(&xml_path, &xml_bytes)
        .map_err(|e| format!("failed to write task XML: {e}"))?;
    let xml_path_str = xml_path.to_string_lossy().into_owned();
    let args = build_schtasks_create_args(&xml_path_str);
    let out = run_hidden_cmd("schtasks.exe", &args);
    let _ = std::fs::remove_file(&xml_path);

    let Some(out) = out else {
        return Err("failed to spawn schtasks.exe".to_string());
    };
    if !out.status.success() {
        let stderr = decode_windows_cmd_text(&out.stderr);
        let stdout = decode_windows_cmd_text(&out.stdout);
        let details = match (stderr.is_empty(), stdout.is_empty()) {
            (false, false) => format!("{stderr} | {stdout}"),
            (false, true) => stderr,
            (true, false) => stdout,
            (true, true) => "no output from schtasks.exe".to_string(),
        };
        return Err(format!(
            "schtasks.exe /Create failed (code={:?}): {details}",
            out.status.code()
        ));
    }
    Ok(())
}

/// Applies `Start = 3` (Manual) and stops `CoworkVMService` when `claude.exe` is not running.
/// Because the scheduled task runs as `NT AUTHORITY\SYSTEM`, any permission/ACL denial when
/// mutating `HKLM\...\CoworkVMService` or SCM under an Admin token is delegated to
/// `trigger_cowork_guard_task()` instead of failing installation.
fn enforce_cowork_service_manual_and_stop() -> Result<(), String> {
    use crate::win_reg::{RootKey, get_dword, set_dword};

    let mut need_system_task = false;
    match get_dword(RootKey::HkeyLocalMachine, COWORK_SERVICE_REG_SUBKEY, "Start") {
        Ok(None) => return Ok(()),
        Ok(Some(cur)) => {
            if cur != 3 {
                if let Err(err) = set_dword(
                    RootKey::HkeyLocalMachine,
                    COWORK_SERVICE_REG_SUBKEY,
                    "Start",
                    3,
                ) {
                    crate::diagnostics::record(
                        "cowork_guard",
                        &format!("Admin set_dword Start=3 fallback to SYSTEM task: {err}"),
                    );
                    need_system_task = true;
                } else {
                    match run_hidden_cmd(
                        "sc.exe",
                        &["config", COWORK_SERVICE_NAME, "start=", "demand"],
                    ) {
                        Some(out) if out.status.success() => {}
                        Some(out) => {
                            crate::diagnostics::record(
                                "cowork_guard",
                                &format!(
                                    "Admin sc config demand fallback to SYSTEM task (code={:?}): {}",
                                    out.status.code(),
                                    decode_windows_cmd_text(&out.stderr)
                                ),
                            );
                            need_system_task = true;
                        }
                        None => {
                            crate::diagnostics::record(
                                "cowork_guard",
                                "Admin sc config demand spawn failed; fallback to SYSTEM task",
                            );
                            need_system_task = true;
                        }
                    }
                }
            }
        }
        Err(err) => {
            crate::diagnostics::record(
                "cowork_guard",
                &format!("Admin get_dword Start fallback to SYSTEM task: {err}"),
            );
            need_system_task = true;
        }
    }

    let running = run_hidden_cmd("sc.exe", &["query", COWORK_SERVICE_NAME])
        .filter(|o| o.status.success())
        .map(|o| parse_sc_running(&decode_windows_cmd_text(&o.stdout)))
        .unwrap_or(false);
    if running && !is_claude_process_running() {
        match run_hidden_cmd("sc.exe", &["stop", COWORK_SERVICE_NAME]) {
            Some(out) if out.status.success() => {}
            Some(out) => {
                crate::diagnostics::record(
                    "cowork_guard",
                    &format!(
                        "Admin sc stop fallback to SYSTEM task (code={:?}): {}",
                        out.status.code(),
                        decode_windows_cmd_text(&out.stderr)
                    ),
                );
                need_system_task = true;
            }
            None => {
                crate::diagnostics::record(
                    "cowork_guard",
                    "Admin sc stop spawn failed; fallback to SYSTEM task",
                );
                need_system_task = true;
            }
        }
    }

    if need_system_task {
        if trigger_cowork_guard_task() {
            std::thread::sleep(std::time::Duration::from_millis(800));
            if let Ok(Some(cur)) =
                get_dword(RootKey::HkeyLocalMachine, COWORK_SERVICE_REG_SUBKEY, "Start")
                && cur != 3
            {
                let msg = format!(
                    "SYSTEM task ran, but CoworkVMService Start is still {cur} instead of 3"
                );
                crate::diagnostics::record("cowork_guard", &msg);
                eprintln!("Застава cowork_guard: {msg}");
            }
        } else {
            let msg = "Registry/SCM fallback required SYSTEM task, but trigger_cowork_guard_task() failed";
            crate::diagnostics::record("cowork_guard", msg);
            eprintln!("Застава cowork_guard: {msg}");
        }
    }
    Ok(())
}

pub(super) fn install_cowork_guard_direct() -> Result<(), String> {
    register_cowork_guard_task()?;
    enforce_cowork_service_manual_and_stop()
}
