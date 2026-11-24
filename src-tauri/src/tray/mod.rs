//! System tray: managed menu-item handles, icon/title/tooltip updates.
//! `menu` builds the tray and its menu, `events` handles menu clicks and tray icon clicks.

mod events;
pub mod menu;
mod view;

pub use menu::{build_tray, refresh_profiles_submenu};
pub(crate) use view::*;

#[cfg(all(feature = "tray-stress", debug_assertions))]
mod stress;

use crate::proxy::guard::GuardPauseStatus;
use crate::{auditor, proxy, state, sysproxy};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tauri::{
    Manager,
    menu::{IconMenuItem, MenuItem, Submenu},
    tray::TrayIcon,
};

/// Keeps a clone of the platform tray icon alive for the whole app lifetime.
/// Created on the main thread (in `build_tray`) so that the last reference to the
/// native status item is never dropped on a worker thread (AppKit asserts on that).
pub struct TrayHolder(pub TrayIcon<tauri::Wry>);

pub const MAIN_TRAY_ID: &str = "main-tray";

#[derive(Clone)]
pub struct TrayStatsMenuItem(pub MenuItem<tauri::Wry>);

#[derive(Clone)]
pub struct TrayKillswitchMenuItem(pub IconMenuItem<tauri::Wry>);

#[derive(Clone)]
pub struct TrayStatusMenuItem(pub IconMenuItem<tauri::Wry>);

#[derive(Clone)]
pub struct TrayProfilesSubmenu(pub Submenu<tauri::Wry>);

/// Single entry point for any work with `TrayIcon` / `MenuItem` (including dropping clones).
/// Always dispatches through `run_on_main_thread` (non-blocking; tauri runs it inline on main).
pub fn with_tray_on_main(
    app: &tauri::AppHandle,
    f: impl FnOnce(&tauri::AppHandle) + Send + 'static,
) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || f(&handle));
}

static PENDING: Mutex<Option<TrayView>> = Mutex::new(None);
static LAST_APPLIED: Mutex<Option<TrayView>> = Mutex::new(None);
static SCHEDULED: AtomicBool = AtomicBool::new(false);

/// Stores the newest state (merging with a not-yet-applied one) and schedules at most
/// one pending main-thread task, so frequent updates never pile up in the event queue.
fn submit(app: &tauri::AppHandle, view: TrayView) {
    {
        let mut slot = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(match slot.take() {
            Some(old) => old.merged_with(view),
            None => view,
        });
    }
    if !SCHEDULED.swap(true, Ordering::AcqRel) {
        with_tray_on_main(app, apply_pending);
    }
}

/// Runs on the main thread only.
fn apply_pending(app: &tauri::AppHandle) {
    SCHEDULED.store(false, Ordering::Release);
    let view = PENDING.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(view) = view {
        apply_view(app, &view);
    }
}

/// Runs on the main thread only: the only place that touches `TrayIcon` / `MenuItem`.
fn apply_view(app: &tauri::AppHandle, view: &TrayView) {
    let prev = LAST_APPLIED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default();

    if let Some(tray) = app.tray_by_id(MAIN_TRAY_ID) {
        if let Some(title) = &view.title
            && prev.title.as_ref() != Some(title)
        {
            let _ = tray.set_title(Some(title));
        }
        if let Some(tooltip) = &view.tooltip
            && prev.tooltip.as_ref() != Some(tooltip)
        {
            let _ = tray.set_tooltip(Some(tooltip));
        }
        if let Some(color) = view.icon
            && prev.icon != Some(color)
            && let Some(img) = color.image()
        {
            let _ = tray.set_icon(Some(img));
        }
    }
    if let (Some(text), Some(item)) = (&view.stats_text, app.try_state::<TrayStatsMenuItem>())
        && prev.stats_text.as_ref() != Some(text)
    {
        let _ = item.0.set_text(text);
    }
    if let (Some((text, color)), Some(item)) = (&view.header, app.try_state::<TrayStatusMenuItem>())
        && prev.header.as_ref() != Some(&(text.clone(), *color))
    {
        let _ = item.0.set_text(text);
        if let Some(img) = color.image() {
            let _ = item.0.set_icon(Some(img));
        }
    }
    if let (Some((text, color)), Some(item)) =
        (&view.killswitch, app.try_state::<TrayKillswitchMenuItem>())
        && prev.killswitch.as_ref() != Some(&(*text, *color))
    {
        let _ = item.0.set_text(*text);
        if let Some(img) = color.image() {
            let _ = item.0.set_icon(Some(img));
        }
    }

    let mut slot = LAST_APPLIED.lock().unwrap_or_else(|e| e.into_inner());
    *slot = Some(prev.merged_with(view.clone()));
}

fn current_icon_is_green() -> bool {
    let pending_icon = PENDING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|v| v.icon);
    let last_icon = LAST_APPLIED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|v| v.icon);
    pending_icon.or(last_icon) == Some(TrayColor::Green)
}

fn guard_priority_view_for_app(app: &tauri::AppHandle, has_blocked: bool) -> Option<TrayView> {
    let startup_ready = app
        .try_state::<Arc<crate::startup::StartupState>>()
        .is_none_or(|s| s.is_ready());
    let sysproxy_active = sysproxy::is_sysproxy_active();
    let status = app
        .try_state::<Arc<proxy::NetworkGuard>>()
        .map(|g| g.pause_status());
    match status {
        Some(ref st) => {
            TrayView::resolve_guard_priority(st, has_blocked, sysproxy_active, startup_ready)
        }
        None if has_blocked => Some(TrayView::from_status("red", None)),
        None if startup_ready && !sysproxy_active => {
            Some(TrayView::protection_off().merged_with(TrayView::from_killswitch(false)))
        }
        None => None,
    }
}

/// Updates the system tray icon, menu bar title (macOS), tooltip, and live menu stats based on current audit report.
/// Safe to call from any thread: the UI work is coalesced and executed on the main thread.
pub fn update_tray_from_report(
    app: &tauri::AppHandle,
    report: &auditor::RiskReport,
    is_pinned: bool,
    has_blocked: bool,
) {
    if let Some(priority_view) = guard_priority_view_for_app(app, has_blocked) {
        submit(app, priority_view);
        return;
    }
    let stats = app
        .try_state::<state::AppState>()
        .map(|s| s.stats().snapshot_sync())
        .unwrap_or_default();
    submit(
        app,
        TrayView::from_report(
            report.overall_status,
            &report.telemetry.country_code,
            &report.telemetry.ip,
            is_pinned,
            false,
            stats.protected_ai_requests,
            stats.intercepted_leaks,
            report.unknown_count,
        ),
    );
}

/// Immediately updates the tray icon, title, header, and killswitch directly from a
/// `NetworkGuard` state transition without waiting for the periodic audit watcher.
pub fn update_tray_from_guard_status(app: &tauri::AppHandle, status: &GuardPauseStatus) {
    let startup_ready = app
        .try_state::<Arc<crate::startup::StartupState>>()
        .is_none_or(|s| s.is_ready());
    let view = TrayView::resolve_guard_priority(
        status,
        false,
        sysproxy::is_sysproxy_active(),
        startup_ready,
    )
    .unwrap_or_else(|| TrayView::from_guard_status(status, true, current_icon_is_green()));
    submit(app, view);
}

/// The audit could not be completed: yellow icon and "Нет данных, проверено <время>".
/// `last_checked` = local time of the last successful audit. Safe to call from any thread.
pub fn update_tray_no_data(app: &tauri::AppHandle, last_checked: Option<&str>) {
    if let Some(priority_view) = guard_priority_view_for_app(app, false) {
        submit(app, priority_view);
        return;
    }
    submit(app, TrayView::from_audit_error(last_checked));
}

/// "Проверяем…": the first audit is still running. Safe to call from any thread.
pub fn update_tray_checking(app: &tauri::AppHandle) {
    if let Some(priority_view) = guard_priority_view_for_app(app, false) {
        submit(app, priority_view);
        return;
    }
    submit(app, TrayView::checking());
}

/// Updates the system tray icon, menu bar title (macOS), and tooltip with a simple color and status title.
/// Unknown color names degrade to yellow, never green.
pub fn update_tray_status(app: &tauri::AppHandle, color: &str, title_override: Option<&str>) {
    if let Some(priority_view) = guard_priority_view_for_app(app, false) {
        submit(app, priority_view);
        return;
    }
    submit(app, TrayView::from_status(color, title_override));
}

/// Protection was turned off by the user (`!sysproxy_active`): shows the 4th gray tray icon.
pub fn update_tray_protection_off(app: &tauri::AppHandle) {
    if let Some(priority_view) = guard_priority_view_for_app(app, false) {
        submit(app, priority_view);
        return;
    }
    submit(app, TrayView::protection_off());
}

/// Updates the killswitch menu item text/icon. Safe to call from any thread.
pub fn update_tray_killswitch(app: &tauri::AppHandle, frozen: bool) {
    submit(app, TrayView::from_killswitch(frozen));
}

/// Updates only the tray tooltip. Safe to call from any thread.
pub fn update_tray_tooltip(app: &tauri::AppHandle, tooltip: String) {
    submit(app, TrayView::from_tooltip(tooltip));
}

#[cfg(any(test, feature = "test-support"))]
pub fn inspect_tray_state_transition(
    has_blocked: bool,
    sysproxy_active: bool,
    status: auditor::OverallStatus,
) -> (&'static str, String, &'static [u8]) {
    let view = if !has_blocked && !sysproxy_active {
        TrayView::protection_off()
    } else {
        TrayView::from_report(status, "US", "198.51.100.1", true, has_blocked, 1, 0, 0)
    };
    let color_name = match view.icon {
        Some(TrayColor::Green) => "green",
        Some(TrayColor::Yellow) => "yellow",
        Some(TrayColor::Red) => "red",
        Some(TrayColor::Gray) => "gray",
        None => "none",
    };
    let bytes = view.icon.map_or(&[][..], |c| c.bytes());
    (color_name, view.title.unwrap_or_default(), bytes)
}

#[cfg(any(test, feature = "test-support"))]
pub fn resolve_tray_transition_for_test(
    status: &GuardPauseStatus,
    blocked_in_state: bool,
    sysproxy_active: bool,
    report: Option<&auditor::RiskReport>,
    is_pinned: bool,
) -> (&'static str, String) {
    let view = TrayView::resolve_guard_priority(status, blocked_in_state, sysproxy_active, true)
        .unwrap_or_else(|| match report {
            Some(r) => TrayView::from_report(
                r.overall_status,
                &r.telemetry.country_code,
                &r.telemetry.ip,
                is_pinned,
                false,
                0,
                0,
                r.unknown_count,
            ),
            None => TrayView::from_guard_status(status, sysproxy_active, false),
        });
    let color_name = match view.icon {
        Some(TrayColor::Green) => "green",
        Some(TrayColor::Yellow) => "yellow",
        Some(TrayColor::Red) => "red",
        Some(TrayColor::Gray) => "gray",
        None => "none",
    };
    (color_name, view.title.unwrap_or_default())
}

#[cfg(test)]
mod tests;
