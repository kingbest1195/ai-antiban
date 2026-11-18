//! Tray menu click handlers and tray icon click handler.

use super::update_tray_status;
use crate::{auditor, proxy, state, sysproxy};
use tauri::{
    Emitter, Manager,
    menu::IconMenuItem,
    tray::{MouseButton, MouseButtonState, TrayIconEvent},
};
use tauri_plugin_opener::OpenerExt;

/// Dispatches a tray menu item click by its id.
pub fn handle_menu_event(
    app: &tauri::AppHandle,
    id: &str,
    _killswitch_i_for_event: &IconMenuItem<tauri::Wry>,
) {
    match id {
        "quit" => {
            // What cannot be put back now stays in the ownership journal and is finished at the
            // next start (or after the VPN lets go of its temporary DNS). Quit does not wait for a
            // VPN with temporary DNS settings; the user is told, the behaviour itself is unchanged.
            crate::startup::note_shutdown(app);
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
            if !sysproxy::try_claim_async_shutdown() {
                return;
            }
            let _ = app.emit(
                sysproxy::SHUTDOWN_PROGRESS_EVENT,
                sysproxy::ShutdownProgressPayload::step("quit", 1),
            );
            let app_handle = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                if let Some(report) =
                    sysproxy::cleanup_on_shutdown_after_step1(Some(&app_handle), "quit")
                {
                    if report.has_failures() {
                        eprintln!(
                            "Застава: часть настроек будет восстановлена при следующем запуске"
                        );
                    }
                    if report.restore_deferred_by_vpn_dns() {
                        sysproxy::notify_restore_deferred();
                    }
                }
                app_handle.exit(0);
            });
        }
        "show" => {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
        }
        "toggle_killswitch_tray" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let (Some(guard), Some(st)) = (
                    app_handle.try_state::<std::sync::Arc<proxy::NetworkGuard>>(),
                    app_handle.try_state::<state::AppState>(),
                ) {
                    crate::commands::interception::toggle_killswitch_shared(
                        None,
                        &guard,
                        &st,
                        &app_handle,
                    )
                    .await;
                }
            });
        }
        "manage_profiles_tray" => {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
            let _ = app.emit("tray://open-profiles", ());
        }
        id if id.starts_with("switch_profile:") => {
            let profile_id = id.trim_start_matches("switch_profile:").to_string();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let _runtime_lock = crate::commands::claude::lock_profile_runtime().await;
                match auditor::profile_switcher::switch_claude_profile(&profile_id) {
                    Ok(res) => {
                        super::menu::refresh_profiles_submenu(&app_handle);
                        let runtime_res = match (
                            app_handle.try_state::<state::AppState>(),
                            app_handle.try_state::<std::sync::Arc<proxy::NetworkGuard>>(),
                        ) {
                            (Some(st), Some(guard)) => {
                                crate::commands::claude::sync_active_profile_binding_to_runtime(
                                    &st,
                                    &guard,
                                    res.pinned_ip_updated.clone(),
                                    res.bound_upstream_key_updated.as_deref(),
                                    res.active_profile.bound_route_id.as_deref(),
                                )
                                .await
                            }
                            (Some(st), None) => {
                                if let Err(e) = st
                                    .set_pinned_ip_for(
                                        state::PROVIDER_ANTHROPIC,
                                        res.pinned_ip_updated.clone(),
                                    )
                                    .await
                                {
                                    Err(e.to_string())
                                } else {
                                    crate::routing::apply_profile_binding(
                                        &st,
                                        res.bound_upstream_key_updated.as_deref(),
                                        res.active_profile.bound_route_id.as_deref(),
                                    )
                                    .await
                                }
                            }
                            _ => Ok(()),
                        };
                        match runtime_res {
                            Ok(()) => {
                                let has_blocks = app_handle
                                    .try_state::<std::sync::Arc<proxy::NetworkGuard>>()
                                    .is_some_and(|g| g.any_provider_gate_blocked());
                                let color = if has_blocks { "yellow" } else { "green" };
                                update_tray_status(
                                    &app_handle,
                                    color,
                                    Some(&format!("Профиль: {}", res.active_profile.name)),
                                );
                                let _ = app_handle.emit("tray://profile-switched", &res);
                            }
                            Err(err) => {
                                eprintln!(
                                    "Failed to apply runtime state for profile {profile_id}: {err}"
                                );
                                crate::diagnostics::record("tray_profile", &err);
                                update_tray_status(
                                    &app_handle,
                                    "red",
                                    Some(&format!("Ошибка профиля: {}", res.active_profile.name)),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to switch profile {profile_id}: {e}");
                        crate::diagnostics::record("tray_profile", &e);
                    }
                }
            });
        }
        "toggle_sysproxy_tray" => {
            let active = sysproxy::is_sysproxy_active();
            if active {
                crate::startup::note_user_off(app);
                let report = sysproxy::cleanup_all_persistent_settings();
                if report.has_failures() {
                    eprintln!("Застава: часть настроек будет восстановлена позже");
                }
            } else if let Some(proxy_mgr) = app.try_state::<proxy::ProxyManager>() {
                let pac_url = format!("http://{}/proxy.pac", proxy_mgr.server.bound_addr);
                let _ = sysproxy::enable_sysproxy(&pac_url);
            }
            let _ = app.emit("tray://sysproxy-toggled", !active);
        }
        "toggle_cli_tray" => {
            let active = sysproxy::is_cli_protection_enabled();
            // Whether the switch really changed: a refused journal leaves everything as it was.
            let mut now_active = active;
            if active {
                let report = sysproxy::disable_cli_protection();
                now_active = report.has_failures();
            } else if let Some(proxy_mgr) = app.try_state::<proxy::ProxyManager>() {
                let addr = proxy_mgr.server.bound_addr.to_string();
                let (mode, tz) = match app.try_state::<state::AppState>() {
                    Some(s) => {
                        let data = tauri::async_runtime::block_on(s.get_data());
                        (data.cli_mode, data.effective_sync_tz())
                    }
                    None => (state::CliMode::default(), None),
                };
                now_active =
                    sysproxy::enable_cli_and_ide_protection_with(&addr, mode, tz.as_deref())
                        .enabled;
            }
            let _ = app.emit("tray://cli-toggled", now_active);
        }
        "sync_tz_tray" => {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
            let _ = app.emit("tray://sync-tz", ());
            let _ = app.emit("tray://sync-timezone", ());
        }
        "pin_ip" => {
            let _ = app.emit("tray://pin-current-ip", ());
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
        }
        "force_clean_proxy_tray" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let _ = sysproxy::force_clean_all_os_proxy_traces();
                update_tray_status(&app_handle, "green", Some("Прокси и хвосты в ОС очищены"));
                let _ = app_handle.emit("tray://state-changed", ());
            });
        }
        "behavior_ask_popup" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(st) = app_handle.try_state::<state::AppState>() {
                    let _ = st
                        .set_interception_behavior(state::InterceptionBehavior::AskPopup)
                        .await;
                }
                update_tray_status(
                    &app_handle,
                    "green",
                    Some("Режим: Уведомление в правом верхнем углу"),
                );
                let _ = app_handle.emit("tray://state-changed", ());
            });
        }
        "behavior_auto_lock" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(st) = app_handle.try_state::<state::AppState>() {
                    let _ = st
                        .set_interception_behavior(state::InterceptionBehavior::AutoLockSilent)
                        .await;
                }
                update_tray_status(&app_handle, "red", Some("Режим: Тихая авто-пауза"));
                let _ = app_handle.emit("tray://state-changed", ());
            });
        }
        "behavior_auto_allow" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(st) = app_handle.try_state::<state::AppState>() {
                    let _ = st
                        .set_interception_behavior(state::InterceptionBehavior::AutoAllowTrusted)
                        .await;
                }
                update_tray_status(&app_handle, "green", Some("Режим: Авто-пропуск (NL/DE/US)"));
                let _ = app_handle.emit("tray://state-changed", ());
            });
        }
        "crash_test_tray" => {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
            let _ = app.emit("tray://open-crash-test", ());
        }
        "backup_claude_tray" => {
            let app_clone = app.clone();
            tauri::async_runtime::spawn(async move {
                let res =
                    tokio::task::spawn_blocking(auditor::claude_exporter::export_claude_local_data)
                        .await;
                if let Ok(Ok(export_res)) = res {
                    let _ = app_clone.emit("claude://backup-finished", &export_res);
                }
            });
        }
        "rescan" => {
            let _ = app.emit("tray://rescan", ());
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
        }
        "open_guide" => {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
                let _ = app.emit("interceptor://open-guide", "01-personal-vpn-15min");
            }
        }
        "support" => {
            let _ = app
                .opener()
                .open_url("https://t.me/nomadnocode", None::<&str>);
        }
        "check_updates" => {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
            let _ = app.emit("tray://check-updates", ());
        }
        _ => {}
    }
}

/// Left click on the tray icon toggles the main window.
pub fn handle_tray_icon_event(tray: &tauri::tray::TrayIcon, event: TrayIconEvent) {
    if let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
        ..
    } = event
    {
        let app = tray.app_handle();
        if let Some(win) = app.get_webview_window("main") {
            if win.is_visible().unwrap_or(false) {
                let _ = win.hide();
            } else {
                let _ = win.show();
                let _ = win.set_focus();
            }
        }
    }
}
