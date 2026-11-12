//! System tray: managed menu-item handles, icon/title/tooltip updates.
//! `menu` builds the tray and its menu, `events` handles menu clicks and tray icon clicks.

mod events;
mod menu;

pub use menu::build_tray;

#[cfg(all(feature = "tray-stress", debug_assertions))]
mod stress;

use crate::{auditor, state};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use tauri::{
    Manager,
    image::Image,
    menu::{IconMenuItem, MenuItem},
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

pub(crate) const TRAY_ICON_GREEN: &[u8] = include_bytes!("../../icons/tray-green.png");
pub(crate) const TRAY_ICON_YELLOW: &[u8] = include_bytes!("../../icons/tray-yellow.png");
pub(crate) const TRAY_ICON_RED: &[u8] = include_bytes!("../../icons/tray-red.png");

/// Single entry point for any work with `TrayIcon` / `MenuItem` (including dropping clones).
/// Always dispatches through `run_on_main_thread` (non-blocking; tauri runs it inline on main).
pub fn with_tray_on_main(
    app: &tauri::AppHandle,
    f: impl FnOnce(&tauri::AppHandle) + Send + 'static,
) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || f(&handle));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrayColor {
    Green,
    Yellow,
    Red,
}

impl TrayColor {
    pub(crate) fn bytes(self) -> &'static [u8] {
        match self {
            TrayColor::Green => TRAY_ICON_GREEN,
            TrayColor::Yellow => TRAY_ICON_YELLOW,
            TrayColor::Red => TRAY_ICON_RED,
        }
    }

    /// Unknown color names are never "green": they degrade to yellow (attention).
    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "green" => TrayColor::Green,
            "red" => TrayColor::Red,
            _ => TrayColor::Yellow,
        }
    }
}

const STOP_TITLE: &str = " СТОП СЕТИ";
const KS_UNFREEZE_TEXT: &str = "Снять СТОП СЕТИ — Возобновить работу ИИ";
const KS_FREEZE_TEXT: &str = "СТОП СЕТИ — Заморозить трафик ИИ";

/// Owned, pure description of what the tray should look like. Every field is optional so
/// partial updates (status only, tooltip only, killswitch only) can be merged/coalesced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TrayView {
    pub icon: Option<TrayColor>,
    pub title: Option<String>,
    pub tooltip: Option<String>,
    pub stats_text: Option<String>,
    pub header: Option<(String, TrayColor)>,
    pub killswitch: Option<(&'static str, TrayColor)>,
}

impl TrayView {
    pub(crate) fn from_report(
        status: auditor::OverallStatus,
        country: &str,
        ip: &str,
        is_pinned: bool,
        has_blocked: bool,
        protected: u64,
        leaks: u64,
    ) -> Self {
        let (color, title, header_suffix) = if has_blocked {
            (TrayColor::Red, STOP_TITLE.to_string(), "СТОП СЕТИ")
        } else {
            match status {
                auditor::OverallStatus::Green => {
                    let pin_mark = if is_pinned {
                        " · Закреплён"
                    } else {
                        ""
                    };
                    (
                        TrayColor::Green,
                        format!(" Защита · {country}{pin_mark}"),
                        "Шлюз активен",
                    )
                }
                auditor::OverallStatus::Yellow => (
                    TrayColor::Yellow,
                    format!(" Внимание · {country}"),
                    "Требуется внимание",
                ),
                auditor::OverallStatus::Red => {
                    (TrayColor::Red, STOP_TITLE.to_string(), "СТОП СЕТИ")
                }
            }
        };
        let killswitch = if has_blocked {
            (KS_UNFREEZE_TEXT, TrayColor::Green)
        } else {
            (KS_FREEZE_TEXT, TrayColor::Red)
        };
        TrayView {
            icon: Some(color),
            title: Some(title),
            tooltip: Some(format!(
                "Застава · IP: {ip} ({country}) · Защищено запросов: {protected} · Отражено сбоев: {leaks}"
            )),
            stats_text: Some(format!(
                "Защищено запросов: {protected} · Отражено сбоев: {leaks}"
            )),
            header: Some((
                format!("Застава v{} — {header_suffix}", env!("CARGO_PKG_VERSION")),
                color,
            )),
            killswitch: Some(killswitch),
        }
    }

    pub(crate) fn from_status(color: &str, title_override: Option<&str>) -> Self {
        let icon = TrayColor::from_name(color);
        let default_title = match icon {
            TrayColor::Red => STOP_TITLE,
            TrayColor::Yellow => " Внимание",
            TrayColor::Green => " Защита",
        };
        let title = title_override.unwrap_or(default_title);
        TrayView {
            icon: Some(icon),
            title: Some(title.to_string()),
            tooltip: Some(format!("Застава · {title}")),
            ..Default::default()
        }
    }

    pub(crate) fn from_killswitch(frozen: bool) -> Self {
        TrayView {
            killswitch: Some(if frozen {
                (KS_UNFREEZE_TEXT, TrayColor::Green)
            } else {
                (KS_FREEZE_TEXT, TrayColor::Red)
            }),
            ..Default::default()
        }
    }

    pub(crate) fn from_tooltip(tooltip: String) -> Self {
        TrayView {
            tooltip: Some(tooltip),
            ..Default::default()
        }
    }

    /// Fields set in `newer` override the ones in `self`; the rest are kept.
    pub(crate) fn merged_with(mut self, newer: TrayView) -> Self {
        macro_rules! take {
            ($f:ident) => {
                if newer.$f.is_some() {
                    self.$f = newer.$f;
                }
            };
        }
        take!(icon);
        take!(title);
        take!(tooltip);
        take!(stats_text);
        take!(header);
        take!(killswitch);
        self
    }
}

static PENDING: Mutex<Option<TrayView>> = Mutex::new(None);
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
    if let Some(tray) = app.tray_by_id(MAIN_TRAY_ID) {
        if let Some(title) = &view.title {
            let _ = tray.set_title(Some(title));
        }
        if let Some(tooltip) = &view.tooltip {
            let _ = tray.set_tooltip(Some(tooltip));
        }
        if let Some(img) = view.icon.and_then(|c| Image::from_bytes(c.bytes()).ok()) {
            let _ = tray.set_icon(Some(img));
        }
    }
    if let (Some(text), Some(item)) = (&view.stats_text, app.try_state::<TrayStatsMenuItem>()) {
        let _ = item.0.set_text(text);
    }
    if let (Some((text, color)), Some(item)) = (&view.header, app.try_state::<TrayStatusMenuItem>())
    {
        let _ = item.0.set_text(text);
        if let Ok(img) = Image::from_bytes(color.bytes()) {
            let _ = item.0.set_icon(Some(img));
        }
    }
    if let (Some((text, color)), Some(item)) =
        (&view.killswitch, app.try_state::<TrayKillswitchMenuItem>())
    {
        let _ = item.0.set_text(*text);
        if let Ok(img) = Image::from_bytes(color.bytes()) {
            let _ = item.0.set_icon(Some(img));
        }
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
            has_blocked,
            stats.protected_ai_requests,
            stats.intercepted_leaks,
        ),
    );
}

/// Updates the system tray icon, menu bar title (macOS), and tooltip with a simple color and status title.
/// Unknown color names degrade to yellow, never green.
pub fn update_tray_status(app: &tauri::AppHandle, color: &str, title_override: Option<&str>) {
    submit(app, TrayView::from_status(color, title_override));
}

/// Updates the killswitch menu item text/icon. Safe to call from any thread.
pub fn update_tray_killswitch(app: &tauri::AppHandle, frozen: bool) {
    submit(app, TrayView::from_killswitch(frozen));
}

/// Updates only the tray tooltip. Safe to call from any thread.
pub fn update_tray_tooltip(app: &tauri::AppHandle, tooltip: String) {
    submit(app, TrayView::from_tooltip(tooltip));
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditor::OverallStatus as S;

    fn report_view(s: S, pinned: bool, blocked: bool) -> TrayView {
        TrayView::from_report(s, "NL", "1.2.3.4", pinned, blocked, 5, 2)
    }

    #[test]
    fn green_pinned_shows_pin_mark() {
        let v = report_view(S::Green, true, false);
        assert_eq!(v.icon, Some(TrayColor::Green));
        assert_eq!(v.title.as_deref(), Some(" Защита · NL · Закреплён"));
        assert_eq!(v.killswitch, Some((KS_FREEZE_TEXT, TrayColor::Red)));
        let v = report_view(S::Green, false, false);
        assert_eq!(v.title.as_deref(), Some(" Защита · NL"));
    }

    #[test]
    fn yellow_and_red_by_report() {
        let y = report_view(S::Yellow, true, false);
        assert_eq!(y.icon, Some(TrayColor::Yellow));
        assert_eq!(y.title.as_deref(), Some(" Внимание · NL"));
        let r = report_view(S::Red, false, false);
        assert_eq!(r.icon, Some(TrayColor::Red));
        assert_eq!(r.title.as_deref(), Some(STOP_TITLE));
    }

    #[test]
    fn blocked_overrides_green_report() {
        let v = report_view(S::Green, true, true);
        assert_eq!(v.icon, Some(TrayColor::Red));
        assert_eq!(v.title.as_deref(), Some(STOP_TITLE));
        assert_eq!(v.killswitch, Some((KS_UNFREEZE_TEXT, TrayColor::Green)));
        assert!(v.header.unwrap().0.ends_with("СТОП СЕТИ"));
    }

    #[test]
    fn tooltip_and_stats_text() {
        let v = report_view(S::Green, false, false);
        assert_eq!(
            v.tooltip.as_deref(),
            Some("Застава · IP: 1.2.3.4 (NL) · Защищено запросов: 5 · Отражено сбоев: 2")
        );
        assert_eq!(
            v.stats_text.as_deref(),
            Some("Защищено запросов: 5 · Отражено сбоев: 2")
        );
    }

    #[test]
    fn unknown_status_is_never_green() {
        for name in ["", "GREEN", "purple", "unknown", "grey"] {
            let v = TrayView::from_status(name, None);
            assert_ne!(v.icon, Some(TrayColor::Green), "{name}");
            assert_eq!(v.icon, Some(TrayColor::Yellow));
        }
        assert_eq!(
            TrayView::from_status("green", None).icon,
            Some(TrayColor::Green)
        );
        assert_eq!(
            TrayView::from_status("red", None).icon,
            Some(TrayColor::Red)
        );
    }

    #[test]
    fn status_title_override_and_tooltip() {
        let v = TrayView::from_status("green", Some("Профиль: X"));
        assert_eq!(v.title.as_deref(), Some("Профиль: X"));
        assert_eq!(v.tooltip.as_deref(), Some("Застава · Профиль: X"));
        assert!(v.stats_text.is_none() && v.header.is_none() && v.killswitch.is_none());
    }

    #[test]
    fn merge_keeps_newest_and_preserves_untouched() {
        let old = report_view(S::Green, false, false);
        let newer = TrayView::from_status("red", Some("x"));
        let m = old.clone().merged_with(newer);
        assert_eq!(m.icon, Some(TrayColor::Red));
        assert_eq!(m.title.as_deref(), Some("x"));
        assert_eq!(m.stats_text, old.stats_text);
        assert_eq!(m.killswitch, old.killswitch);
        let m = m.merged_with(TrayView::from_killswitch(true));
        assert_eq!(m.killswitch, Some((KS_UNFREEZE_TEXT, TrayColor::Green)));
        assert_eq!(m.icon, Some(TrayColor::Red));
    }
}
