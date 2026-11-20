use super::*;
use crate::cowork_guard::CoworkGuardStatus;

fn status_fixture() -> CoworkGuardStatus {
    CoworkGuardStatus {
        platform: "windows".to_string(),
        supported: true,
        service_present: true,
        start_type: Some(3),
        service_running: false,
        task_installed: true,
        task_healthy: true,
        needs_repair: false,
        summary: String::new(),
        detected_ai_apps: Vec::new(),
    }
}

#[test]
fn triggers_when_start_type_is_automatic_2_even_with_claude_open() {
    let mut st = status_fixture();
    st.start_type = Some(2);
    st.needs_repair = true;

    assert!(should_trigger_cowork_guard(&st, false, true));
    assert!(should_trigger_cowork_guard(&st, true, true));
}

#[test]
fn triggers_when_service_running_and_claude_closed_but_not_when_claude_open() {
    let mut st = status_fixture();
    st.start_type = Some(3);
    st.service_running = true;
    st.needs_repair = false;

    // Claude closed -> MUST trigger guard task to stop CoworkVMService.
    assert!(should_trigger_cowork_guard(&st, false, true));
    // Claude open -> MUST NOT interrupt running CoworkVMService.
    assert!(!should_trigger_cowork_guard(&st, true, true));
}

#[test]
fn never_triggers_when_task_not_installed_or_unsupported_or_dry_run() {
    let mut no_task = status_fixture();
    no_task.task_installed = false;
    no_task.start_type = Some(2);
    no_task.service_running = true;
    no_task.needs_repair = true;
    assert!(!should_trigger_cowork_guard(&no_task, false, true));

    let mut unsupported = status_fixture();
    unsupported.supported = false;
    unsupported.start_type = Some(2);
    unsupported.service_running = true;
    assert!(!should_trigger_cowork_guard(&unsupported, false, true));

    let mut automatic = status_fixture();
    automatic.start_type = Some(2);
    automatic.service_running = true;
    automatic.needs_repair = true;
    // os_effects_enabled == false -> never triggers.
    assert!(!should_trigger_cowork_guard(&automatic, false, false));
}

#[test]
fn needs_repair_combinations_behave_deterministically() {
    // Healthy Start=3, service stopped -> no trigger.
    let stopped = status_fixture();
    assert!(!should_trigger_cowork_guard(&stopped, false, true));
    assert!(!should_trigger_cowork_guard(&stopped, true, true));

    // Unhealthy task XML with Start=3 and service stopped -> does not trigger /Run;
    // wait for user repair via UI banner.
    let mut unhealthy_stopped = status_fixture();
    unhealthy_stopped.task_healthy = false;
    unhealthy_stopped.needs_repair = true;
    assert!(!should_trigger_cowork_guard(
        &unhealthy_stopped,
        false,
        true
    ));

    // Unhealthy task XML + service running while Claude closed -> triggers guard task.
    let mut unhealthy_running = unhealthy_stopped;
    unhealthy_running.service_running = true;
    assert!(should_trigger_cowork_guard(&unhealthy_running, false, true));
    assert!(!should_trigger_cowork_guard(&unhealthy_running, true, true));
}

#[test]
fn is_claude_process_running_respects_dry_run() {
    crate::sysproxy::force_os_dry_run();
    assert!(!crate::sysproxy::os_effects_enabled());
    assert!(!is_claude_process_running());
}
