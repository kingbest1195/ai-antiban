mod app;
pub mod auditor;
pub mod bin_checker;
pub mod commands;
pub mod popup;
pub mod proxy;
pub mod routing;
pub mod sanctions;
pub mod startup;
pub mod state;
pub mod sysproxy;
pub mod tray;
pub mod updater;

// Backward-compatible re-exports: these used to live in the crate root.
pub use commands::coverage::get_coverage_snapshot;
pub use commands::crash_test::CrashTestStepResult;
pub use commands::deeplink::take_pending_deep_link;
pub use commands::AppContext;
pub use popup::show_and_position_alert_popup;
pub use sanctions::is_sanctioned_or_blocked_country;
pub use tray::{
    update_tray_from_report, update_tray_status, TrayKillswitchMenuItem, TrayStatsMenuItem,
    TrayStatusMenuItem, MAIN_TRAY_ID,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    app::run()
}
