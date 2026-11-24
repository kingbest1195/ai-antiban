//! Layer 2 -> Layer 3 port for alert popup and tray callbacks registered by `app`.

use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::auditor::RiskReport;
use crate::proxy::guard::GuardPauseStatus;

type ShowAlertFn = Arc<dyn Fn(&tauri::AppHandle, Option<(String, Instant)>) + Send + Sync>;
type HideAlertFn = Arc<dyn Fn(&tauri::AppHandle) + Send + Sync>;
type TrayReportFn = Arc<dyn Fn(&tauri::AppHandle, &RiskReport, bool, bool) + Send + Sync>;
type TrayStatusFn = Arc<dyn Fn(&tauri::AppHandle, &str, Option<&str>) + Send + Sync>;
type TrayGuardStatusFn = Arc<dyn Fn(&tauri::AppHandle, &GuardPauseStatus) + Send + Sync>;

struct UiHooks {
    show_popup: ShowAlertFn,
    hide_popup: HideAlertFn,
    tray_report: TrayReportFn,
    tray_status: TrayStatusFn,
}

static UI_HOOKS: RwLock<Option<UiHooks>> = RwLock::new(None);
static TRAY_GUARD_HOOK: RwLock<Option<TrayGuardStatusFn>> = RwLock::new(None);

/// Registers the Layer 3 alert-popup and tray handlers.
pub fn register_ui_hooks<S, H, R, T>(show_popup: S, hide_popup: H, tray_report: R, tray_status: T)
where
    S: Fn(&tauri::AppHandle, Option<(String, Instant)>) + Send + Sync + 'static,
    H: Fn(&tauri::AppHandle) + Send + Sync + 'static,
    R: Fn(&tauri::AppHandle, &RiskReport, bool, bool) + Send + Sync + 'static,
    T: Fn(&tauri::AppHandle, &str, Option<&str>) + Send + Sync + 'static,
{
    if let Ok(mut guard) = UI_HOOKS.write() {
        *guard = Some(UiHooks {
            show_popup: Arc::new(show_popup),
            hide_popup: Arc::new(hide_popup),
            tray_report: Arc::new(tray_report),
            tray_status: Arc::new(tray_status),
        });
    }
}

/// Registers the Layer 3 tray updater triggered on `NetworkGuard` state transitions.
pub fn register_tray_guard_hook<G>(tray_guard_status: G)
where
    G: Fn(&tauri::AppHandle, &GuardPauseStatus) + Send + Sync + 'static,
{
    if let Ok(mut guard) = TRAY_GUARD_HOOK.write() {
        *guard = Some(Arc::new(tray_guard_status));
    }
}

pub(crate) fn show_alert_popup(app: &tauri::AppHandle, timing: Option<(String, Instant)>) {
    let hook = UI_HOOKS
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|h| Arc::clone(&h.show_popup)));
    if let Some(show) = hook {
        show(app, timing);
    }
}

pub(crate) fn hide_alert_popup(app: &tauri::AppHandle) {
    let hook = UI_HOOKS
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|h| Arc::clone(&h.hide_popup)));
    if let Some(hide) = hook {
        hide(app);
    }
}

pub(crate) fn update_tray_from_report(
    app: &tauri::AppHandle,
    report: &RiskReport,
    is_pinned: bool,
    has_blocked: bool,
) {
    let hook = UI_HOOKS
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|h| Arc::clone(&h.tray_report)));
    if let Some(cb) = hook {
        cb(app, report, is_pinned, has_blocked);
    }
}

pub(crate) fn update_tray_status(app: &tauri::AppHandle, color: &str, title: Option<&str>) {
    let hook = UI_HOOKS
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|h| Arc::clone(&h.tray_status)));
    if let Some(cb) = hook {
        cb(app, color, title);
    }
}

pub(crate) fn update_tray_from_guard_status(app: &tauri::AppHandle, status: &GuardPauseStatus) {
    let hook = TRAY_GUARD_HOOK
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(Arc::clone));
    if let Some(cb) = hook {
        cb(app, status);
    }
}
