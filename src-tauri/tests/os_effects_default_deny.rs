//! Guard: a test that never calls `force_os_dry_run()` must still not reach the operating system.
//! Integration tests link the library without `cfg(test)`, so the protection has to come from the
//! `test-support` feature (default-deny), not from each test remembering to opt in.
//! Deliberately NO `force_os_dry_run()` anywhere in this file.

use zastava_lib::sysproxy;

#[test]
fn os_effects_are_off_without_any_opt_in() {
    // Checked first and on its own: if this ever fails, nothing below may run.
    assert!(
        !sysproxy::os_effects_enabled(),
        "a test build must never be allowed to touch the OS by default"
    );
}

#[test]
fn commands_are_replaced_by_a_counted_no_op() {
    assert!(!sysproxy::os_effects_enabled());
    let before = sysproxy::dry_run_blocked_calls();
    let mut cmd = sysproxy::silent_command("zastava-no-such-program-for-the-guard-test");
    // The real program does not exist; the stand-in (`true`) starts and succeeds.
    assert!(cmd.status().map(|s| s.success()).unwrap_or(false));
    assert!(sysproxy::dry_run_blocked_calls() > before);
}

#[test]
fn public_entry_points_touch_nothing_without_opt_in() {
    assert!(!sysproxy::os_effects_enabled());
    let before = sysproxy::dry_run_blocked_calls();
    let report = sysproxy::cleanup_all_persistent_settings();
    assert!(
        report.skipped_dry_run,
        "the cleanup must be skipped, not run"
    );
    assert!(sysproxy::dry_run_blocked_calls() > before);
    // `--cleanup` has no data directory here and must not guess one into the real home.
    let dir = std::env::temp_dir().join("zastava-default-deny-guard");
    let r = sysproxy::recover_ownership_on_start(&dir).expect("dry-run is not an error");
    assert!(r.skipped_dry_run);
    assert!(
        !dir.exists(),
        "dry-run must not create the data directory either"
    );
}
