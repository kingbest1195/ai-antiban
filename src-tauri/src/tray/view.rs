//! Pure tray view-model (`TrayColor` and `TrayView`) and state transitions.

use crate::auditor;
use crate::proxy::guard::{GuardPauseStatus, PauseMode};
use std::sync::OnceLock;
use tauri::image::Image;

pub(crate) const TRAY_ICON_GREEN: &[u8] = include_bytes!("../../icons/tray-green.png");
pub(crate) const TRAY_ICON_YELLOW: &[u8] = include_bytes!("../../icons/tray-yellow.png");
pub(crate) const TRAY_ICON_RED: &[u8] = include_bytes!("../../icons/tray-red.png");
pub(crate) const TRAY_ICON_GRAY: &[u8] = include_bytes!("../../icons/tray-gray.png");

static IMG_GREEN: OnceLock<Option<Image<'static>>> = OnceLock::new();
static IMG_YELLOW: OnceLock<Option<Image<'static>>> = OnceLock::new();
static IMG_RED: OnceLock<Option<Image<'static>>> = OnceLock::new();
static IMG_GRAY: OnceLock<Option<Image<'static>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrayColor {
    Green,
    Yellow,
    Red,
    Gray,
}

impl TrayColor {
    pub(crate) fn bytes(self) -> &'static [u8] {
        match self {
            TrayColor::Green => TRAY_ICON_GREEN,
            TrayColor::Yellow => TRAY_ICON_YELLOW,
            TrayColor::Red => TRAY_ICON_RED,
            TrayColor::Gray => TRAY_ICON_GRAY,
        }
    }

    pub(crate) fn image(self) -> Option<Image<'static>> {
        let cell = match self {
            TrayColor::Green => &IMG_GREEN,
            TrayColor::Yellow => &IMG_YELLOW,
            TrayColor::Red => &IMG_RED,
            TrayColor::Gray => &IMG_GRAY,
        };
        cell.get_or_init(|| Image::from_bytes(self.bytes()).ok())
            .clone()
    }

    /// Unknown color names are never "green": they degrade to yellow (attention).
    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "green" => TrayColor::Green,
            "red" => TrayColor::Red,
            "gray" => TrayColor::Gray,
            _ => TrayColor::Yellow,
        }
    }
}

pub(crate) const STOP_TITLE: &str = " СТОП СЕТИ";
pub(crate) const PAUSED_TITLE: &str = " Пауза";
const PROTECTION_OFF_TITLE: &str = " Защита выключена";
const PROTECTION_OFF_HEADER: &str = "Защита выключена";
/// Menu bar title prefix when the audit finished, but some checks could not be performed.
const INCOMPLETE_TITLE: &str = " Проверено частично";
const INCOMPLETE_HEADER: &str = "Проверено частично";
/// Menu bar title prefix when no audit result is available at all.
const NO_DATA_TITLE: &str = " Нет данных";
const NO_DATA_HEADER: &str = "Нет данных";
/// Menu bar title and menu header while the first audit has not finished: not "protected", not
/// an error, just "not known yet".
pub(crate) const CHECKING_TITLE: &str = " Проверяем…";
pub(crate) const CHECKING_HEADER: &str = "Проверяем…";
const CHECKING_TOOLTIP: &str = "проверяем сеть и защиту";
const NO_DATA_TOOLTIP: &str = "не удалось выполнить проверку сети";
pub(crate) const KS_UNFREEZE_TEXT: &str = "Снять СТОП СЕТИ — Возобновить работу ИИ";
pub(crate) const KS_FREEZE_TEXT: &str = "СТОП СЕТИ — Заморозить трафик ИИ";

/// "1 проверку не удалось выполнить" / "3 проверки ..." / "5 проверок ...".
pub(crate) fn unfinished_checks_text(n: u8) -> String {
    let word = match (n % 100, n % 10) {
        (11..=14, _) => "проверок",
        (_, 1) => "проверку",
        (_, 2..=4) => "проверки",
        _ => "проверок",
    };
    format!("{n} {word} не удалось выполнить")
}

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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_report(
        status: auditor::OverallStatus,
        country: &str,
        ip: &str,
        is_pinned: bool,
        has_blocked: bool,
        protected: u64,
        leaks: u64,
        unknown_count: u8,
    ) -> Self {
        let incomplete = unknown_count > 0;
        let (color, title, header_suffix) = if has_blocked {
            (TrayColor::Red, STOP_TITLE.to_string(), "СТОП СЕТИ")
        } else {
            match status {
                // Green with unfinished checks is not "protected": yellow, never a green icon.
                auditor::OverallStatus::Green if incomplete => (
                    TrayColor::Yellow,
                    format!("{INCOMPLETE_TITLE} · {country}"),
                    INCOMPLETE_HEADER,
                ),
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
        let unfinished = if incomplete {
            format!(" · {}", unfinished_checks_text(unknown_count))
        } else {
            String::new()
        };
        TrayView {
            icon: Some(color),
            title: Some(title),
            tooltip: Some(format!(
                "Застава · IP: {ip} ({country}){unfinished} · Защищено запросов: {protected} · Отражено сбоев: {leaks}"
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

    /// Instant tray view derived directly from a `NetworkGuard` state transition (`GuardPauseStatus`),
    /// updating icon, title, tooltip, header, and killswitch item without waiting for an audit.
    pub(crate) fn from_guard_status(
        status: &GuardPauseStatus,
        sysproxy_active: bool,
        current_icon_is_green: bool,
    ) -> Self {
        let ver = env!("CARGO_PKG_VERSION");
        if status.manual_killswitch {
            return TrayView {
                icon: Some(TrayColor::Red),
                title: Some(STOP_TITLE.to_string()),
                tooltip: Some("Застава · СТОП СЕТИ (Ручная блокировка ИИ)".to_string()),
                header: Some((format!("Застава v{ver} — СТОП СЕТИ"), TrayColor::Red)),
                killswitch: Some((KS_UNFREEZE_TEXT, TrayColor::Green)),
                ..Default::default()
            };
        }
        if status.mode == PauseMode::UntilNetworkChange {
            let reason = status
                .gate_reason
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("Пауза до следующей смены сети");
            return TrayView {
                icon: Some(TrayColor::Gray),
                title: Some(PAUSED_TITLE.to_string()),
                tooltip: Some(format!("Застава · {reason}")),
                header: Some((
                    format!("Застава v{ver} — Пауза до смены сети"),
                    TrayColor::Gray,
                )),
                killswitch: Some((KS_UNFREEZE_TEXT, TrayColor::Green)),
                ..Default::default()
            };
        }
        if status.gate == "pending" || !status.pending_providers.is_empty() {
            let ks = if status.blocked_providers.is_empty() {
                (KS_FREEZE_TEXT, TrayColor::Red)
            } else {
                (KS_UNFREEZE_TEXT, TrayColor::Green)
            };
            let tip = status
                .gate_reason
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|r| format!("Застава · {r}"))
                .unwrap_or_else(|| format!("Застава · {CHECKING_TOOLTIP}"));
            return TrayView {
                icon: Some(TrayColor::Yellow),
                title: Some(CHECKING_TITLE.to_string()),
                tooltip: Some(tip),
                header: Some((
                    format!("Застава v{ver} — {CHECKING_HEADER}"),
                    TrayColor::Yellow,
                )),
                killswitch: Some(ks),
                ..Default::default()
            };
        }
        if status.gate == "blocked" || !status.blocked_providers.is_empty() {
            let tip = status
                .gate_reason
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|r| format!("Застава · {r}"))
                .unwrap_or_else(|| format!("Застава ·{STOP_TITLE}"));
            return TrayView {
                icon: Some(TrayColor::Red),
                title: Some(STOP_TITLE.to_string()),
                tooltip: Some(tip),
                header: Some((format!("Застава v{ver} — СТОП СЕТИ"), TrayColor::Red)),
                killswitch: Some((KS_UNFREEZE_TEXT, TrayColor::Green)),
                ..Default::default()
            };
        }
        if !sysproxy_active {
            return TrayView::protection_off().merged_with(TrayView::from_killswitch(false));
        }
        if current_icon_is_green {
            // Preserve the existing country/pin/IP report while ensuring killswitch state is open.
            return TrayView::from_killswitch(false);
        }
        TrayView {
            icon: Some(TrayColor::Green),
            title: Some(" Защита".to_string()),
            tooltip: Some("Застава · Шлюз активен".to_string()),
            header: Some((format!("Застава v{ver} — Шлюз активен"), TrayColor::Green)),
            killswitch: Some((KS_FREEZE_TEXT, TrayColor::Red)),
            ..Default::default()
        }
    }

    /// The audit failed: never keep showing the previous (possibly green) state.
    /// `last_checked` = local time of the last successful audit, if there was one.
    pub(crate) fn from_audit_error(last_checked: Option<&str>) -> Self {
        let title = match last_checked {
            Some(t) => format!("{NO_DATA_TITLE}, проверено {t}"),
            None => NO_DATA_TITLE.to_string(),
        };
        TrayView {
            icon: Some(TrayColor::Yellow),
            tooltip: Some(format!("Застава ·{title} · {NO_DATA_TOOLTIP}")),
            title: Some(title),
            header: Some((
                format!("Застава v{} — {NO_DATA_HEADER}", env!("CARGO_PKG_VERSION")),
                TrayColor::Yellow,
            )),
            ..Default::default()
        }
    }

    /// Nothing is known yet (the app has just started). Never green: a yellow icon with
    /// "Проверяем…" until the first audit result arrives.
    pub(crate) fn checking() -> Self {
        TrayView {
            icon: Some(TrayColor::Yellow),
            title: Some(CHECKING_TITLE.to_string()),
            tooltip: Some(format!("Застава · {CHECKING_TOOLTIP}")),
            header: Some((
                format!("Застава v{} — {CHECKING_HEADER}", env!("CARGO_PKG_VERSION")),
                TrayColor::Yellow,
            )),
            ..Default::default()
        }
    }

    pub(crate) fn from_status(color: &str, title_override: Option<&str>) -> Self {
        let icon = TrayColor::from_name(color);
        let default_title = match icon {
            TrayColor::Red => STOP_TITLE,
            TrayColor::Yellow => " Внимание",
            TrayColor::Green => " Защита",
            TrayColor::Gray => PROTECTION_OFF_TITLE,
        };
        let title = title_override.unwrap_or(default_title);
        TrayView {
            icon: Some(icon),
            title: Some(title.to_string()),
            tooltip: Some(format!("Застава · {title}")),
            ..Default::default()
        }
    }

    /// Protection was turned off by the user (`!sysproxy_active`): gray icon, never yellow/green.
    pub(crate) fn protection_off() -> Self {
        TrayView {
            icon: Some(TrayColor::Gray),
            title: Some(PROTECTION_OFF_TITLE.to_string()),
            tooltip: Some("Застава · Защита выключена пользователем".to_string()),
            header: Some((
                format!(
                    "Застава v{} — {PROTECTION_OFF_HEADER}",
                    env!("CARGO_PKG_VERSION")
                ),
                TrayColor::Gray,
            )),
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
