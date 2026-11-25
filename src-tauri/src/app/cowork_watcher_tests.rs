use super::*;
use crate::cowork_guard::CoworkGuardStatus;
use std::sync::atomic::{AtomicUsize, Ordering};

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
fn skips_process_snapshot_when_service_absent_or_stopped() {
    let mut absent = status_fixture();
    absent.service_present = false;
    absent.service_running = false;
    assert!(!should_probe_claude_process(&absent, true));

    let stopped = status_fixture();
    assert!(!should_probe_claude_process(&stopped, true));

    let mut dry_run = status_fixture();
    dry_run.service_running = true;
    assert!(!should_probe_claude_process(&dry_run, false));

    let mut auto_start = status_fixture();
    auto_start.service_running = true;
    auto_start.start_type = Some(2);
    assert!(!should_probe_claude_process(&auto_start, true));

    let mut active = status_fixture();
    active.service_running = true;
    assert!(should_probe_claude_process(&active, true));
}

#[tokio::test]
async fn tick_never_probes_processes_when_cowork_service_inactive() {
    let mut stopped = status_fixture();
    stopped.service_present = false;
    stopped.service_running = false;

    let probe_calls = AtomicUsize::new(0);
    let trigger_calls = AtomicUsize::new(0);
    let out = evaluate_cowork_guard_tick(
        true,
        || async { Some(stopped.clone()) },
        || async {
            probe_calls.fetch_add(1, Ordering::SeqCst);
            false
        },
        || async {
            trigger_calls.fetch_add(1, Ordering::SeqCst);
            true
        },
        || async {},
    )
    .await
    .unwrap();

    assert_eq!(probe_calls.load(Ordering::SeqCst), 0);
    assert_eq!(trigger_calls.load(Ordering::SeqCst), 0);
    assert!(!out.triggered);
    assert!(!out.status.service_present);
}

#[tokio::test]
async fn tick_probes_processes_only_when_cowork_service_is_installed_and_running() {
    let mut active = status_fixture();
    active.service_running = true;

    let probe_calls = AtomicUsize::new(0);
    let trigger_calls = AtomicUsize::new(0);
    let out = evaluate_cowork_guard_tick(
        true,
        || async { Some(active.clone()) },
        || async {
            probe_calls.fetch_add(1, Ordering::SeqCst);
            false
        },
        || async {
            trigger_calls.fetch_add(1, Ordering::SeqCst);
            true
        },
        || async {},
    )
    .await
    .unwrap();

    assert_eq!(probe_calls.load(Ordering::SeqCst), 1);
    assert_eq!(trigger_calls.load(Ordering::SeqCst), 1);
    assert!(out.triggered);
    assert!(out.status.service_running);
}
