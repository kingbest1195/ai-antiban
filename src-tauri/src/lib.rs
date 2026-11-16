mod app;
pub mod auditor;
pub mod autostart;
pub mod bin_checker;
pub mod commands;
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    app::run()
}
