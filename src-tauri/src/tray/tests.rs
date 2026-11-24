use super::*;
use crate::proxy::guard::PauseMode;
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

#[test]
fn gray_state_represents_protection_off_and_embeds_valid_png() {
    assert!(!TRAY_ICON_GRAY.is_empty());
    assert_eq!(TrayColor::from_name("gray"), TrayColor::Gray);
    assert_eq!(TrayColor::Gray.bytes(), TRAY_ICON_GRAY);

    let off = TrayView::protection_off();
    assert_eq!(off.icon, Some(TrayColor::Gray));
    assert_eq!(off.title.as_deref(), Some(" Защита выключена"));
    assert_eq!(off.header.as_ref().map(|h| h.1), Some(TrayColor::Gray));

    let from_st = TrayView::from_status("gray", None);
    assert_eq!(from_st.icon, Some(TrayColor::Gray));
    assert_eq!(from_st.title.as_deref(), Some(" Защита выключена"));

    // Merging protection_off replaces previous green icon with gray.
    let merged = report_view(S::Green, false, false).merged_with(off);
    assert_eq!(merged.icon, Some(TrayColor::Gray));
}

#[test]
fn guard_status_drives_instant_tray_transitions_without_waiting_for_audit() {
    let ver = env!("CARGO_PKG_VERSION");

    // 1. Detecting / Pending -> Yellow "Проверяем…" + header + killswitch.
    let pending = GuardPauseStatus {
        paused: false,
        mode: PauseMode::None,
        gate: "pending".to_string(),
        gate_reason: Some("Смена сети — проверяем безопасность подключения".to_string()),
        manual_killswitch: false,
        pending_providers: vec!["anthropic".to_string()],
        blocked_providers: vec![],
    };
    let v_pending = TrayView::from_guard_status(&pending, true, true);
    assert_eq!(v_pending.icon, Some(TrayColor::Yellow));
    assert_eq!(v_pending.title.as_deref(), Some(CHECKING_TITLE));
    assert_eq!(
        v_pending.header,
        Some((
            format!("Застава v{ver} — {CHECKING_HEADER}"),
            TrayColor::Yellow
        ))
    );
    assert_eq!(v_pending.killswitch, Some((KS_FREEZE_TEXT, TrayColor::Red)));

    // 2. Paused until network change -> Gray "Пауза" + unfreeze action + gate_reason tooltip.
    let paused = GuardPauseStatus {
        paused: true,
        mode: PauseMode::UntilNetworkChange,
        gate: "blocked".to_string(),
        gate_reason: Some("Пауза до следующей смены сети".to_string()),
        manual_killswitch: false,
        pending_providers: vec![],
        blocked_providers: vec!["anthropic".to_string()],
    };
    let v_paused = TrayView::from_guard_status(&paused, true, false);
    assert_eq!(v_paused.icon, Some(TrayColor::Gray));
    assert_eq!(v_paused.title.as_deref(), Some(PAUSED_TITLE));
    assert_eq!(
        v_paused.header,
        Some((
            format!("Застава v{ver} — Пауза до смены сети"),
            TrayColor::Gray
        ))
    );
    assert_eq!(
        v_paused.killswitch,
        Some((KS_UNFREEZE_TEXT, TrayColor::Green))
    );
    assert!(
        v_paused
            .tooltip
            .as_deref()
            .unwrap()
            .contains("Пауза до следующей смены сети")
    );

    // 3. Manual kill-switch -> Red "СТОП СЕТИ" + unfreeze action.
    let manual = GuardPauseStatus {
        paused: true,
        mode: PauseMode::Manual,
        gate: "blocked".to_string(),
        gate_reason: None,
        manual_killswitch: true,
        pending_providers: vec![],
        blocked_providers: vec!["anthropic".to_string(), "openai".to_string()],
    };
    let v_manual = TrayView::from_guard_status(&manual, true, false);
    assert_eq!(v_manual.icon, Some(TrayColor::Red));
    assert_eq!(v_manual.title.as_deref(), Some(STOP_TITLE));
    assert_eq!(
        v_manual.header,
        Some((format!("Застава v{ver} — СТОП СЕТИ"), TrayColor::Red))
    );
    assert_eq!(
        v_manual.killswitch,
        Some((KS_UNFREEZE_TEXT, TrayColor::Green))
    );

    // 4. Open recovery from non-green -> Green "Защита" + freeze action.
    let open = GuardPauseStatus {
        paused: false,
        mode: PauseMode::None,
        gate: "open".to_string(),
        gate_reason: None,
        manual_killswitch: false,
        pending_providers: vec![],
        blocked_providers: vec![],
    };
    let v_open_from_red = TrayView::from_guard_status(&open, true, false);
    assert_eq!(v_open_from_red.icon, Some(TrayColor::Green));
    assert_eq!(v_open_from_red.title.as_deref(), Some(" Защита"));
    assert_eq!(
        v_open_from_red.killswitch,
        Some((KS_FREEZE_TEXT, TrayColor::Red))
    );

    // 5. Open steady-state when already green -> preserves country/pin title and only syncs killswitch.
    let v_open_steady = TrayView::from_guard_status(&open, true, true);
    assert!(v_open_steady.icon.is_none());
    assert!(v_open_steady.title.is_none());
    assert_eq!(
        v_open_steady.killswitch,
        Some((KS_FREEZE_TEXT, TrayColor::Red))
    );

    // 6. Open when sysproxy is OFF -> Gray protection_off.
    let v_off = TrayView::from_guard_status(&open, false, true);
    assert_eq!(v_off.icon, Some(TrayColor::Gray));
    assert_eq!(v_off.title.as_deref(), Some(" Защита выключена"));

    // 7. Strict 6-level priority: manual_killswitch > UntilNetworkChange > pending > blocked > !sysproxy > report.
    let paused_and_pending = GuardPauseStatus {
        paused: true,
        mode: PauseMode::UntilNetworkChange,
        gate: "pending".to_string(),
        gate_reason: Some("Пауза".to_string()),
        manual_killswitch: false,
        pending_providers: vec!["anthropic".to_string()],
        blocked_providers: vec!["openai".to_string()],
    };
    let p_view = TrayView::resolve_guard_priority(&paused_and_pending, true, false, true)
        .expect("paused must win");
    assert_eq!(p_view.icon, Some(TrayColor::Gray));
    assert_eq!(p_view.title.as_deref(), Some(PAUSED_TITLE));

    // Pending wins over blocked_in_state and !sysproxy_active (never flashes СТОП СЕТИ over Checking).
    let pending_and_blocked = GuardPauseStatus {
        paused: false,
        mode: PauseMode::None,
        gate: "open".to_string(),
        gate_reason: None,
        manual_killswitch: false,
        pending_providers: vec!["anthropic".to_string()],
        blocked_providers: vec!["openai".to_string()],
    };
    let pend_view = TrayView::resolve_guard_priority(&pending_and_blocked, true, false, true)
        .expect("pending must win");
    assert_eq!(pend_view.icon, Some(TrayColor::Yellow));
    assert_eq!(pend_view.title.as_deref(), Some(CHECKING_TITLE));

    // Blocked in state wins over !sysproxy_active.
    let blk_view =
        TrayView::resolve_guard_priority(&open, true, false, true).expect("blocked must win");
    assert_eq!(blk_view.icon, Some(TrayColor::Red));
    assert_eq!(blk_view.title.as_deref(), Some(STOP_TITLE));
}
