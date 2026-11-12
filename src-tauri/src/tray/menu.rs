//! Builds the tray menu (status header, kill-switch, submenus) and the tray icon itself.

use super::{events, TrayKillswitchMenuItem, TrayStatsMenuItem, TrayStatusMenuItem, MAIN_TRAY_ID, TRAY_ICON_RED, TRAY_ICON_YELLOW};
use crate::auditor;
use tauri::{
    image::Image,
    menu::{IconMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::TrayIconBuilder,
    Manager,
};

/// Native Russian tray menu with pro-utility typography & branded icons.
pub fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let status_i = IconMenuItem::with_id(
        app,
        "status_header",
        concat!("Застава v", env!("CARGO_PKG_VERSION"), " — Проверяем…"),
        false,
        Image::from_bytes(TRAY_ICON_YELLOW).ok(),
        None::<&str>,
    )?;
    app.manage(TrayStatusMenuItem(status_i.clone()));

    let stats_i = MenuItem::with_id(
        app,
        "stats_header",
        "Защищено запросов: 0 · Отражено сбоев: 0",
        false,
        None::<&str>,
    )?;
    app.manage(TrayStatsMenuItem(stats_i.clone()));
    let sep1 = PredefinedMenuItem::separator(app)?;
    let show_i = MenuItem::with_id(
        app,
        "show",
        "Открыть панель Заставы",
        true,
        None::<&str>,
    )?;
    let killswitch_i = IconMenuItem::with_id(
        app,
        "toggle_killswitch_tray",
        "СТОП СЕТИ — Заморозить трафик ИИ",
        true,
        Image::from_bytes(TRAY_ICON_RED).ok(),
        None::<&str>,
    )?;
    app.manage(TrayKillswitchMenuItem(killswitch_i.clone()));
    let sep2 = PredefinedMenuItem::separator(app)?;

    // Submenu 1: Профили Claude (Мульти-аккаунт)
    let profiles_res = auditor::profile_switcher::list_claude_profiles(None).ok();
    let mut profile_menu_items = Vec::new();
    if let Some(resp) = &profiles_res {
        for p in resp.profiles.iter().take(10) {
            let mark = if p.is_active { "● Активен: " } else { "○ " };
            let email_or_label = p.bound_ip.as_deref().or(p.bound_country.as_deref()).unwrap_or("Основной");
            let proxy_badge = if p.bound_upstream_key.is_some() { " [Прокси]" } else { "" };
            let label = format!("{mark}{} ({email_or_label}){proxy_badge}", p.name);
            if let Ok(item) = MenuItem::with_id(app, format!("switch_profile:{}", p.id), label, true, None::<&str>) {
                profile_menu_items.push(item);
            }
        }
    }
    let manage_profiles_i = MenuItem::with_id(
        app,
        "manage_profiles_tray",
        "Управление профилями и бэкапом...",
        true,
        None::<&str>,
    )?;
    let sep_profiles = PredefinedMenuItem::separator(app)?;
    let mut sub1_items: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = Vec::new();
    for item in &profile_menu_items {
        sub1_items.push(item);
    }
    if !profile_menu_items.is_empty() {
        sub1_items.push(&sep_profiles);
    }
    sub1_items.push(&manage_profiles_i);
    let submenu_profiles = Submenu::with_items(app, "Профили Claude (Мульти-аккаунт)", true, &sub1_items)?;

    // Submenu 2: Контур защиты и сеть
    let toggle_sysproxy_i = MenuItem::with_id(
        app,
        "toggle_sysproxy_tray",
        "Защита браузеров и Claude Desktop (PAC)",
        true,
        None::<&str>,
    )?;
    let toggle_cli_i = MenuItem::with_id(
        app,
        "toggle_cli_tray",
        "Защита терминала, VS Code и Cursor",
        true,
        None::<&str>,
    )?;
    let sync_tz_i = MenuItem::with_id(
        app,
        "sync_tz_tray",
        "Синхронизировать часовой пояс под VPN",
        true,
        None::<&str>,
    )?;
    let pin_i = MenuItem::with_id(
        app,
        "pin_ip",
        "Закрепить текущий IP как эталонный",
        true,
        None::<&str>,
    )?;
    let force_clean_proxy_i = MenuItem::with_id(
        app,
        "force_clean_proxy_tray",
        "Сбросить системные прокси и хвосты в ОС",
        true,
        None::<&str>,
    )?;
    let submenu_protection = Submenu::with_items(
        app,
        "Контур защиты и сеть",
        true,
        &[
            &toggle_sysproxy_i,
            &toggle_cli_i,
            &sync_tz_i,
            &pin_i,
            &force_clean_proxy_i,
        ],
    )?;

    // Submenu 3: Режим при обрыве VPN
    let behavior_ask_popup_i = MenuItem::with_id(
        app,
        "behavior_ask_popup",
        "Уведомление в правом верхнем углу",
        true,
        None::<&str>,
    )?;
    let behavior_auto_lock_i = MenuItem::with_id(
        app,
        "behavior_auto_lock",
        "Тихая авто-пауза (без всплывающих окон)",
        true,
        None::<&str>,
    )?;
    let behavior_auto_allow_i = MenuItem::with_id(
        app,
        "behavior_auto_allow",
        "Авто-пропуск безопасных стран (NL / DE / US)",
        true,
        None::<&str>,
    )?;
    let submenu_behavior = Submenu::with_items(
        app,
        "Режим при обрыве VPN",
        true,
        &[
            &behavior_ask_popup_i,
            &behavior_auto_lock_i,
            &behavior_auto_allow_i,
        ],
    )?;

    // Submenu 4: Диагностика и бэкап
    let crash_test_i = MenuItem::with_id(
        app,
        "crash_test_tray",
        "Запустить краш-тест обрыва VPN",
        true,
        None::<&str>,
    )?;
    let backup_claude_i = MenuItem::with_id(
        app,
        "backup_claude_tray",
        "Экспорт и бэкап данных Claude на Рабочий стол",
        true,
        None::<&str>,
    )?;
    let rescan_i = MenuItem::with_id(
        app,
        "rescan",
        "Перепроверить соединение и чистоту IP",
        true,
        None::<&str>,
    )?;
    let submenu_tools = Submenu::with_items(
        app,
        "Диагностика и бэкап",
        true,
        &[
            &crash_test_i,
            &backup_claude_i,
            &rescan_i,
        ],
    )?;

    // Submenu 5: Справка и обновления
    let guide_i = MenuItem::with_id(
        app,
        "open_guide",
        "Инструкция: Свой VPN за 15 минут",
        true,
        None::<&str>,
    )?;
    let support_i = MenuItem::with_id(
        app,
        "support",
        "Поддержка в Telegram (@nomadnocode)",
        true,
        None::<&str>,
    )?;
    let update_i = MenuItem::with_id(
        app,
        "check_updates",
        "Проверить обновления",
        true,
        None::<&str>,
    )?;
    let submenu_guides = Submenu::with_items(
        app,
        "Справка и обновления",
        true,
        &[
            &guide_i,
            &support_i,
            &update_i,
        ],
    )?;

    let sep3 = PredefinedMenuItem::separator(app)?;
    let quit_i = MenuItem::with_id(
        app,
        "quit",
        "Выйти и отключить защиту",
        true,
        None::<&str>,
    )?;

    let menu = Menu::with_items(
        app,
        &[
            &status_i,
            &stats_i,
            &sep1,
            &show_i,
            &killswitch_i,
            &sep2,
            &submenu_profiles,
            &submenu_protection,
            &submenu_behavior,
            &submenu_tools,
            &submenu_guides,
            &sep3,
            &quit_i,
        ],
    )?;

    let killswitch_i_for_event = killswitch_i.clone();
    let mut tray_builder = TrayIconBuilder::with_id(MAIN_TRAY_ID)
        .menu(&menu)
        .title(super::CHECKING_TITLE)
        .tooltip("Застава — проверяем сеть и защиту")
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| {
            events::handle_menu_event(app, event.id.as_ref(), &killswitch_i_for_event)
        })
        .on_tray_icon_event(events::handle_tray_icon_event);

    // Yellow until the first audit says otherwise: green would claim a verdict nobody made yet.
    if let Ok(initial_icon) = Image::from_bytes(TRAY_ICON_YELLOW) {
        tray_builder = tray_builder.icon(initial_icon);
    }

    let tray = tray_builder.build(app)?;
    // build_tray runs on the main thread (setup): keep a clone so the last reference to the
    // native status item is never dropped on a worker thread.
    app.manage(super::TrayHolder(tray));

    #[cfg(all(feature = "tray-stress", debug_assertions))]
    super::stress::maybe_start(app.handle());

    Ok(())
}
