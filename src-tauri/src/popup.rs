//! Alert popup window positioning.

use crate::state;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tauri::Manager;

/// Must match the alert-popup width in tauri.conf.json (440x360). Only the width matters here:
/// the window is anchored to the top edge, so the height does not affect the position.
const POPUP_WIDTH: f64 = 440.0;
/// How long the primary monitor width is reused before it is read again (display changes).
const MONITOR_CACHE_TTL: Duration = Duration::from_secs(10);

/// Logical width of the primary monitor and when it was read.
static MONITOR_WIDTH: Mutex<Option<(f64, Instant)>> = Mutex::new(None);

/// True when `ZASTAVA_TIMING=1`: the guard logs detect -> emit -> show -> enriched to stderr.
pub fn timing_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("ZASTAVA_TIMING").is_ok_and(|v| v == "1"))
}

/// One stderr line `[zastava-timing] id=<id> <stage> +<ms>ms` (milliseconds since `t0`).
pub fn log_timing(id: &str, stage: &str, t0: Instant) {
    if timing_enabled() {
        eprintln!(
            "[zastava-timing] id={id} {stage} +{:.1}ms",
            t0.elapsed().as_secs_f64() * 1000.0
        );
    }
}

fn primary_monitor_width(popup: &tauri::WebviewWindow) -> Option<f64> {
    let cached = MONITOR_WIDTH.lock().ok().and_then(|cache| *cache);
    if let Some((width, _)) = cached.filter(|(_, at)| at.elapsed() < MONITOR_CACHE_TTL) {
        return Some(width);
    }
    let monitor = popup.primary_monitor().ok().flatten()?;
    let width = monitor.size().width as f64 / monitor.scale_factor();
    if let Ok(mut cache) = MONITOR_WIDTH.lock() {
        *cache = Some((width, Instant::now()));
    }
    Some(width)
}

/// Positions the alert-popup window directly under the notch or top-right of the screen
/// without stealing keyboard focus. Shadow and decorations are set once in `init_alert_popup`.
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

        if let Some(mon_width) = primary_monitor_width(&popup) {
            let (x, y) = match pos_setting {
                state::PopupPosition::TopRight => {
                    let right_x = (mon_width - POPUP_WIDTH - 24.0).max(0.0);
                    (right_x, 24.0)
                }
                state::PopupPosition::TopCenter => {
                    let center_x = ((mon_width - POPUP_WIDTH) / 2.0).max(0.0);
                    (center_x, 0.0)
                }
            };
            let _ = popup.set_position(tauri::Position::Logical(tauri::LogicalPosition::new(x, y)));
        }
        let _ = popup.show();
        let _ = popup.unminimize();
        let _ = popup.set_always_on_top(true);
        // Note: intentionally do NOT call popup.set_focus() so user's active editor/terminal does not lose focus
    } else if let Some(main_win) = app.get_webview_window("main") {
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
