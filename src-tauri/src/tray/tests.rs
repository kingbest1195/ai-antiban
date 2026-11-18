use super::*;
use auditor::OverallStatus as S;

fn report_view(s: S, pinned: bool, blocked: bool) -> TrayView {
    TrayView::from_report(s, "NL", "1.2.3.4", pinned, blocked, 5, 2, 0)
}

fn incomplete_view(s: S, blocked: bool, unknown: u8) -> TrayView {
    TrayView::from_report(s, "NL", "1.2.3.4", false, blocked, 5, 2, unknown)
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
fn checking_state_is_never_green_and_never_an_error() {
    let v = TrayView::checking();
    assert_eq!(v.icon, Some(TrayColor::Yellow));
    assert_eq!(v.title.as_deref(), Some(" Проверяем…"));
    assert!(!v.title.as_deref().unwrap().contains("Нет данных"));
    let header = v.header.unwrap();
    assert!(header.0.ends_with("Проверяем…") && !header.0.contains("Шлюз активен"));
    assert_eq!(header.1, TrayColor::Yellow);
    // A later real state overrides it (merge keeps the newer fields).
    let merged = TrayView::checking().merged_with(report_view(S::Green, false, false));
    assert_eq!(merged.icon, Some(TrayColor::Green));
    assert_eq!(merged.title.as_deref(), Some(" Защита · NL"));
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

#[test]
fn incomplete_green_report_is_yellow_and_partial() {
    let v = incomplete_view(S::Green, false, 3);
    assert_eq!(v.icon, Some(TrayColor::Yellow));
    assert_eq!(v.title.as_deref(), Some(" Проверено частично · NL"));
    assert!(
        v.tooltip
            .as_deref()
            .unwrap()
            .contains("3 проверки не удалось выполнить")
    );
    assert!(v.header.unwrap().0.ends_with("Проверено частично"));
    // The complete report keeps its green state.
    assert_eq!(
        report_view(S::Green, false, false).icon,
        Some(TrayColor::Green)
    );
}

#[test]
fn incomplete_never_hides_red_or_a_block() {
    let r = incomplete_view(S::Red, false, 2);
    assert_eq!(r.icon, Some(TrayColor::Red));
    assert_eq!(r.title.as_deref(), Some(STOP_TITLE));
    let b = incomplete_view(S::Green, true, 2);
    assert_eq!(b.icon, Some(TrayColor::Red));
    // Warnings keep their own wording, the count is still in the tooltip.
    let y = incomplete_view(S::Yellow, false, 1);
    assert_eq!(y.title.as_deref(), Some(" Внимание · NL"));
    assert!(
        y.tooltip
            .unwrap()
            .contains("1 проверку не удалось выполнить")
    );
}

#[test]
fn unfinished_checks_plural_forms() {
    assert_eq!(unfinished_checks_text(1), "1 проверку не удалось выполнить");
    assert_eq!(unfinished_checks_text(2), "2 проверки не удалось выполнить");
    assert_eq!(unfinished_checks_text(5), "5 проверок не удалось выполнить");
    assert_eq!(
        unfinished_checks_text(11),
        "11 проверок не удалось выполнить"
    );
    assert_eq!(
        unfinished_checks_text(21),
        "21 проверку не удалось выполнить"
    );
}

#[test]
fn audit_error_is_yellow_with_time_of_last_check() {
    let v = TrayView::from_audit_error(Some("14:32"));
    assert_eq!(v.icon, Some(TrayColor::Yellow));
    assert_eq!(v.title.as_deref(), Some(" Нет данных, проверено 14:32"));
    assert!(v.tooltip.as_deref().unwrap().contains("проверено 14:32"));
    assert!(v.stats_text.is_none() && v.killswitch.is_none());
    let never = TrayView::from_audit_error(None);
    assert_eq!(never.title.as_deref(), Some(" Нет данных"));
    assert_eq!(never.icon, Some(TrayColor::Yellow));
    // It replaces a previous green state when merged.
    let m = report_view(S::Green, false, false).merged_with(v);
    assert_eq!(m.icon, Some(TrayColor::Yellow));
    assert_eq!(m.killswitch, Some((KS_FREEZE_TEXT, TrayColor::Red)));
}
