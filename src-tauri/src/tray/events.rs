//! Tray menu click handlers and tray icon click handler.

use super::{update_tray_killswitch, update_tray_status};
use crate::{auditor, proxy, state, sysproxy};
use tauri::{
    menu::IconMenuItem,
    tray::{MouseButton, MouseButtonState, TrayIconEvent},
    Emitter, Manager,
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
            // Quit does not wait for a VPN with temporary DNS settings (the PAC is then restored
            // at the next start); the user is told, the behaviour itself is unchanged.
            if sysproxy::cleanup_all_persistent_settings().restore_deferred_by_vpn_dns() {
                sysproxy::notify_restore_deferred();
            }
            app.exit(0);
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
                    let target_freeze = !guard.is_gate_blocked();
                    let now_frozen = guard.set_manual_killswitch(target_freeze, &st).await;
                    update_tray_killswitch(&app_handle, now_frozen);
                    let _ = app_handle.emit("tray://killswitch-toggled", now_frozen);
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
                match auditor::profile_switcher::switch_claude_profile(&profile_id) {
                    Ok(res) => {
                        if let Some(st) = app_handle.try_state::<state::AppState>() {
                            let _ = st.set_pinned_ip(res.pinned_ip_updated.clone()).await;
                            let _ = crate::routing::apply_profile_key(
                                &st,
                                res.bound_upstream_key_updated.as_deref(),
                            )
                            .await;
                        }
                        update_tray_status(&app_handle, "green", Some(&format!("Профиль: {}", res.active_profile.name)));
                        let _ = app_handle.emit("tray://profile-switched", &res);
                    }
                    Err(e) => {
                        eprintln!("Failed to switch profile {profile_id}: {e}");
                    }
                }
            });
        }
        "toggle_sysproxy_tray" => {
            let active = sysproxy::is_sysproxy_active();
            if active {
                sysproxy::disable_all_sysproxy();
            } else if let Some(proxy_mgr) = app.try_state::<proxy::ProxyManager>() {
                let pac_url = format!("http://{}/proxy.pac", proxy_mgr.server.bound_addr);
                let _ = sysproxy::enable_sysproxy(&pac_url);
            }
            let _ = app.emit("tray://sysproxy-toggled", !active);
        }
        "toggle_cli_tray" => {
            let active = sysproxy::is_cli_protection_enabled();
            if active {
                sysproxy::disable_cli_protection();
            } else if let Some(proxy_mgr) = app.try_state::<proxy::ProxyManager>() {
                let addr = proxy_mgr.server.bound_addr.to_string();
                let state = app.try_state::<state::AppState>();
                let tz = state.map(|s| tauri::async_runtime::block_on(s.get_synced_ai_timezone())).flatten();
                let _ = sysproxy::enable_cli_and_ide_protection_with_tz(&addr, tz.as_deref());
            }
            let _ = app.emit("tray://cli-toggled", !active);
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
                if let Some(st) = app_handle.try_state::<state::AppState>() {
                    let _ = st.set_sysproxy_enabled(false).await;
                    let _ = st.set_cli_protection_enabled(false).await;
                }
                update_tray_status(&app_handle, "green", Some("Прокси и хвосты в ОС очищены"));
                let _ = app_handle.emit("tray://state-changed", ());
            });
        }
        "behavior_ask_popup" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(st) = app_handle.try_state::<state::AppState>() {
                    let _ = st.set_interception_behavior(state::InterceptionBehavior::AskPopup).await;
                }
                update_tray_status(&app_handle, "green", Some("Режим: Уведомление в правом верхнем углу"));
                let _ = app_handle.emit("tray://state-changed", ());
            });
        }
        "behavior_auto_lock" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(st) = app_handle.try_state::<state::AppState>() {
                    let _ = st.set_interception_behavior(state::InterceptionBehavior::AutoLockSilent).await;
                }
                update_tray_status(&app_handle, "red", Some("Режим: Тихая авто-пауза"));
                let _ = app_handle.emit("tray://state-changed", ());
            });
        }
        "behavior_auto_allow" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(st) = app_handle.try_state::<state::AppState>() {
                    let _ = st.set_interception_behavior(state::InterceptionBehavior::AutoAllowTrusted).await;
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
                let res = tokio::task::spawn_blocking(auditor::claude_exporter::export_claude_local_data).await;
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
            let _ = app.opener().open_url("https://t.me/nomadnocode", None::<&str>);
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
