//! Alert popup window positioning.

use crate::state;
use std::time::Instant;
use tauri::Manager;

pub use crate::core::timing::{log_timing, timing_enabled};

/// Must match the alert-popup width in tauri.conf.json (440x360). Only the width matters here:
/// the window is anchored to the top edge, so the height does not affect the position.
const POPUP_WIDTH: f64 = 440.0;

/// Logical `(origin_x, origin_y, width)` of the primary monitor (falling back to the popup's
/// current monitor). Read on every show (inline on the main thread, so it is cheap) and never
/// cached: a display change must move the window on-screen at once.
fn monitor_bounds(popup: &tauri::WebviewWindow) -> Option<(f64, f64, f64)> {
    let monitor = popup
        .primary_monitor()
        .ok()
        .flatten()
        .or_else(|| popup.current_monitor().ok().flatten())?;
    let scale = monitor.scale_factor();
    let origin_x = monitor.position().x as f64 / scale;
    let origin_y = monitor.position().y as f64 / scale;
    let width = monitor.size().width as f64 / scale;
    Some((origin_x, origin_y, width))
}

/// Ensures `alert-popup` starts borderless, shadowless, always-on-top, and visible across Spaces.
pub fn init_alert_popup(app: &tauri::App) {
    if let Some(popup) = app.get_webview_window("alert-popup") {
        let _ = popup.set_shadow(false);
        let _ = popup.set_decorations(false);
        let _ = popup.set_always_on_top(true);
        #[cfg(target_os = "macos")]
        let _ = popup.set_visible_on_all_workspaces(true);
        #[cfg(target_os = "windows")]
        let _ = popup.set_skip_taskbar(true);
    }
}

/// Positions the alert-popup window directly under the notch or top-right of the screen
/// without stealing foreground focus from the user's active application.
pub fn show_and_position_alert_popup(app: &tauri::AppHandle) {
    show_and_position_alert_popup_timed(app, None);
}

/// Same as [`show_and_position_alert_popup`]; `timing` = `(alert id, detection instant)` adds the
/// `popup_shown` line to the `ZASTAVA_TIMING` log. Position and show run in ONE main-thread
/// closure; the caller does not wait for it.
pub fn show_and_position_alert_popup_timed(
    app: &tauri::AppHandle,
    timing: Option<(String, Instant)>,
) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        show_on_main(&handle);
        if let Some((id, t0)) = timing {
            log_timing(&id, "popup_shown", t0);
        }
    });
}

fn show_on_main(app: &tauri::AppHandle) {
    if let Some(popup) = app.get_webview_window("alert-popup") {
        let pos_setting = app
            .try_state::<state::AppState>()
            .map(|s| s.get_popup_position_sync())
            .unwrap_or(state::PopupPosition::TopRight);

        if let Some((origin_x, origin_y, mon_width)) = monitor_bounds(&popup) {
            let (x, y) = match pos_setting {
                state::PopupPosition::TopRight => {
                    let right_x = origin_x + (mon_width - POPUP_WIDTH - 24.0).max(0.0);
                    (right_x, origin_y + 24.0)
                }
                state::PopupPosition::TopCenter => {
                    let center_x = origin_x + ((mon_width - POPUP_WIDTH) / 2.0).max(0.0);
                    (center_x, origin_y)
                }
            };
            let _ = popup.set_position(tauri::Position::Logical(tauri::LogicalPosition::new(x, y)));
        }
        let _ = popup.unminimize();
        let _ = popup.set_always_on_top(true);
        #[cfg(target_os = "macos")]
        let _ = popup.set_visible_on_all_workspaces(true);
        let _ = popup.show();
    } else if let Some(main_win) = app.get_webview_window("main") {
        let _ = main_win.unminimize();
        let _ = main_win.show();
        let _ = main_win.set_focus();
    }
}

/// Hides the alert popup (main thread; the caller does not wait).
pub fn hide_alert_popup(app: &tauri::AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(popup) = handle.get_webview_window("alert-popup") {
            let _ = popup.hide();
        }
    });
}
