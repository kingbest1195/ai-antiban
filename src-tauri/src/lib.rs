mod app;
pub mod auditor;
pub mod autostart;
pub mod bin_checker;
pub mod bunker;
pub mod clean_room;
pub mod commands;
pub mod core;
pub mod cowork_guard;
pub mod diagnostics;
pub mod os_tz;
pub mod popup;
pub mod proxy;
pub mod routing;
pub mod sanctions;
pub mod startup;
pub mod state;
pub mod sysproxy;
pub mod tray;
pub mod updater;
pub mod win_native;
pub mod win_reg;

// Backward-compatible re-exports: these used to live in the crate root.
#[cfg(any(test, feature = "test-support"))]
pub use app::reconcile_active_profile_binding_async;
pub use commands::AppContext;
pub use commands::coverage::get_coverage_snapshot;
pub use commands::crash_test::CrashTestStepResult;
pub use commands::deeplink::take_pending_deep_link;
pub use popup::show_and_position_alert_popup;
pub use sanctions::is_sanctioned_or_blocked_country;
pub use tray::{
    MAIN_TRAY_ID, TrayKillswitchMenuItem, TrayStatsMenuItem, TrayStatusMenuItem,
    update_tray_from_report, update_tray_status,
};

/// Handles non-GUI maintenance CLI flags before Tauri builder/tray/single-instance startup.
pub fn try_handle_early_cli_args(args: &[String]) -> Option<i32> {
    if args.iter().any(|a| a == "--cleanup") {
        return Some(sysproxy::run_cleanup_cli());
    }
    if let Some(error_file) = cowork_guard::parse_install_cli_args(args) {
        return Some(cowork_guard::run_install_cowork_guard_cli_with_error_file(
            error_file.as_deref(),
        ));
    }
    if args
        .iter()
        .any(|a| a == cowork_guard::APPLY_COWORK_GUARD_ONCE_ARG)
    {
        return Some(cowork_guard::run_apply_cowork_guard_once_cli());
    }
    if args
        .iter()
        .any(|a| a == cowork_guard::UNINSTALL_COWORK_GUARD_ARG)
    {
        return Some(cowork_guard::run_uninstall_cowork_guard_cli());
    }
    if let Some(cli) = win_native::timezone::parse_apply_os_tz_cli_args(args) {
        return Some(win_native::timezone::run_apply_os_tz_cli(cli));
    }
    None
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    app::run()
}
