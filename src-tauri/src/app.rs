//! Application bootstrap: Tauri builder, setup sequence and background tasks.

use crate::tray::update_tray_from_report;
use crate::startup::{self, StartupSink, StartupSnapshot, StartupState, StartupSteps};
use crate::{auditor, bin_checker, commands, proxy, state, sysproxy, tray, updater};
use std::sync::Arc;
use std::time::Duration;
use tauri::{Emitter, Manager};

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            let mut found_deep_link = false;
            for arg in &argv {
                if arg.starts_with("zastava://") {
                    commands::deeplink::handle_deep_link(app, arg);
                    found_deep_link = true;
                }
            }
            if !found_deep_link {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.unminimize();
                    let _ = win.set_focus();
                }
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            // Register panic guard and OS termination signal watcher for systemic proxy clean-up
            sysproxy::register_clean_exit_guard();
            sysproxy::spawn_signal_cleanup_watcher();
            // Only the directory is pinned here (cheap). The ownership recovery pass, the
            // protection and the guard run in the background sequence below: the window and the
            // tray must answer at once, not after a dozen `networksetup` calls.
            let data_dir = match app.path().app_data_dir() {
                Ok(dir) => {
                    sysproxy::set_data_dir(dir.clone());
                    Some(dir)
                }
                Err(_) => None,
            };

            init_alert_popup(app);

            let (app_state, risk_auditor) = init_services(app)?;

            let (guard_for_watcher, pac_url) = start_proxy(app, &risk_auditor, &app_state);
            app.manage(guard_for_watcher.clone());

            let startup_state = Arc::new(StartupState::new());
            app.manage(startup_state.clone());

            tray::build_tray(app)?;

            spawn_tray_status_watcher(app, &risk_auditor, &app_state, guard_for_watcher.clone());
            spawn_update_checker(app, &app_state);

            // The gateway listens (`pac_url` exists only after the bind), so the sequence may
            // switch protection on: recovery -> protection -> guard, off the setup path.
            let steps = Arc::new(RealSteps {
                app: app.handle().clone(),
                data_dir,
                app_state: app_state.clone(),
                auditor: risk_auditor.clone(),
                guard: guard_for_watcher,
                pac_url,
            });
            let sink = Arc::new(TauriStartupSink(app.handle().clone()));
            if let Err(e) = startup::spawn(steps, startup_state.clone(), sink) {
                // Without the thread nothing would ever enable the protection or the guard.
                eprintln!("Застава: не удалось запустить фоновый старт: {e}");
            }

            #[cfg(any(target_os = "windows", target_os = "linux"))]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let _ = app.deep_link().register_all();
            }

            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let dl_handle = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        commands::deeplink::handle_deep_link(&dl_handle, url.as_str());
                    }
                });
            }

            for arg in std::env::args() {
                if arg.starts_with("zastava://") {
                    commands::deeplink::handle_deep_link(&app.handle(), &arg);
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::audit::get_state,
            commands::audit::get_startup_state,
            commands::audit::audit_connection,
            commands::claude::clean_app_cache,
            commands::claude::scan_claude_data_cmd,
            commands::claude::export_claude_data_cmd,
            commands::audit::pin_current_ip,
            commands::audit::unpin_ip,
            commands::audit::toggle_strict_pinning,
            commands::audit::allow_provider_session,
            commands::audit::unblock_provider_cmd,
            commands::audit::verify_and_unblock_provider,
            commands::interception::resolve_interception,
            commands::interception::simulate_interception,
            commands::interception::take_pending_alert,
            commands::sysproxy::toggle_sysproxy,
            commands::sysproxy::toggle_sysproxy_privileged,
            commands::sysproxy::enable_cli_protection,
            commands::sysproxy::disable_cli_protection,
            commands::sysproxy::check_cli_protection_status,
            commands::sysproxy::sync_ai_agents_timezone,
            commands::sysproxy::get_cli_settings,
            commands::sysproxy::set_cli_mode,
            commands::sysproxy::set_sync_ai_tz_enabled,
            commands::sysproxy::open_os_datetime_settings_cmd,
            commands::sysproxy::open_os_network_settings_cmd,
            commands::sysproxy::get_sysproxy_status,
            commands::payment::check_payment_bin,
            commands::updates::check_for_updates,
            commands::updates::install_update,
            commands::updates::toggle_auto_update,
            commands::claude::list_claude_profiles_cmd,
            commands::claude::create_claude_profile_cmd,
            commands::claude::switch_claude_profile_cmd,
            commands::claude::delete_claude_profile_cmd,
            commands::claude::bind_ip_to_claude_profile_cmd,
            commands::claude::bind_upstream_to_claude_profile_cmd,
            commands::interception::get_interception_behavior_cmd,
            commands::interception::set_interception_behavior_cmd,
            commands::interception::get_popup_position_cmd,
            commands::interception::set_popup_position_cmd,
            commands::domains::get_custom_ai_domains_cmd,
            commands::domains::add_custom_ai_domain_cmd,
            commands::domains::remove_custom_ai_domain_cmd,
            commands::crash_test::run_vpn_crash_test_step,
            commands::crash_test::trigger_crash_test_drop,
            commands::crash_test::reset_crash_test_drop,
            commands::upstream::set_upstream_proxy,
            commands::upstream::toggle_upstream_proxy,
            commands::upstream::clear_upstream_proxy,
            commands::routes::list_routes,
            commands::routes::add_route,
            commands::routes::remove_route,
            commands::routes::set_route_enabled,
            commands::routes::bind_provider_route,
            commands::routes::set_default_route,
            commands::routes::test_route,
            commands::payment::set_warmup_timer,
            commands::audit::get_gateway_stats,
            commands::sysproxy::force_clean_os_proxy_cmd,
            commands::interception::toggle_network_killswitch_cmd,
            commands::interception::get_network_killswitch_status_cmd,
            commands::coverage::get_coverage_snapshot,
            commands::coverage::recheck_coverage,
            commands::restart_app::restart_app_with_gateway,
            commands::deeplink::take_pending_deep_link
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| match event {
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Opened { urls } => {
                for url in urls {
                    commands::deeplink::handle_deep_link(app_handle, url.as_str());
                }
            }
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
                startup::note_shutdown(app_handle);
                // Cmd+Q / closing the last window: the same notice as a quit from the tray.
                if sysproxy::cleanup_all_persistent_settings().restore_deferred_by_vpn_dns() {
                    sysproxy::notify_restore_deferred();
                }
            }
            _ => {}
        });
}

/// Ensures alert-popup has no shadow/decorations and stays borderless.
fn init_alert_popup(app: &tauri::App) {
    // Ensure alert-popup has no shadow/decorations and stays borderless
    if let Some(popup) = app.get_webview_window("alert-popup") {
        let _ = popup.set_shadow(false);
        let _ = popup.set_decorations(false);
    }
}

/// Initializes persistent AppState, the Risk Auditor Engine and the Payment Geo Checker.
fn init_services(
    app: &tauri::App,
) -> Result<(state::AppState, auditor::Auditor), Box<dyn std::error::Error>> {
    // Initialize persistent AppState
    let app_state = state::init_app_state(app.handle())
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    app.manage(app_state.clone());

    // Initialize Risk Auditor Engine
    let risk_auditor = auditor::Auditor::new()
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error>)?;
    app.manage(risk_auditor.clone());

    // Initialize Payment Geo Checker
    let bin_checker = bin_checker::BinChecker::new();
    app.manage(bin_checker);

    Ok((app_state, risk_auditor))
}

/// Initializes and starts the local selective PAC + Hold Proxy. Returns the network guard and the PAC URL.
fn start_proxy(
    app: &tauri::App,
    risk_auditor: &auditor::Auditor,
    app_state: &state::AppState,
) -> (Arc<proxy::NetworkGuard>, String) {
    let handle_clone = app.handle().clone();
    let auditor_for_proxy = risk_auditor.clone();
    let state_for_proxy = app_state.clone();
    tauri::async_runtime::block_on(async {
        let proxy_mgr = proxy::ProxyManager::start(
            auditor_for_proxy,
            state_for_proxy,
            Some(handle_clone),
        )
        .await
        .expect("Failed to start proxy server");
        let guard = proxy_mgr.guard.clone();
        guard.restore_manual_killswitch(app_state).await;
        let pac_url = format!("http://{}/proxy.pac", proxy_mgr.server.bound_addr);
        app.manage(proxy_mgr);
        (guard, pac_url)
    })
}

/// Protection is ON by default: route AI domains through the local interceptor.
fn enable_default_protection(app_state: &state::AppState, pac_url: &str) {
    match sysproxy::enable_sysproxy(pac_url) {
        Ok(status) => println!(
            "Застава: сетевой контроль включен ({} сетевых служб)",
            status.services_configured.len()
        ),
        Err(e) => eprintln!("Застава: не удалось включить защиту при старте: {e}"),
    }
    let (mode, tz) = tauri::async_runtime::block_on(async {
        let data = app_state.get_data().await;
        (data.cli_mode, data.effective_sync_tz())
    });
    let cli_report = sysproxy::enable_cli_and_ide_protection_with(pac_url, mode, tz.as_deref());
    if cli_report.enabled {
        println!(
            "Застава: защита CLI/IDE включена ({})",
            cli_report.configured_targets.join(", ")
        );
    } else if let Some(err) = &cli_report.error {
        eprintln!("Застава: {err}");
    }
    for note in &cli_report.notes {
        eprintln!("Застава: {note}");
    }
}

/// The real steps of the background start (see [`startup`]).
struct RealSteps {
    app: tauri::AppHandle,
    data_dir: Option<std::path::PathBuf>,
    app_state: state::AppState,
    auditor: auditor::Auditor,
    guard: Arc<proxy::NetworkGuard>,
    pac_url: String,
}

impl StartupSteps for RealSteps {
    /// Restores only what the journal says Zastava changed in a previous run, then the one-time
    /// 1.3.x signature cleanup. Fail closed (logged, nothing is guessed).
    fn recover(&self) {
        match &self.data_dir {
            Some(dir) => match sysproxy::recover_ownership_on_start(dir) {
                Ok(report) => eprintln!("Застава: {}", report.summary()),
                Err(e) => eprintln!("Застава: восстановление отложено, {e}"),
            },
            None => eprintln!("Застава: каталог данных недоступен, восстановление отложено"),
        }
    }

    fn enable_protection(&self) {
        enable_default_protection(&self.app_state, &self.pac_url);
    }

    /// Network guard: detects sudden IP changes and freezes AI traffic until confirmed.
    fn start_guard(&self) {
        self.guard.start(proxy::GuardCtx {
            auditor: self.auditor.clone(),
            state: self.app_state.clone(),
            hold_queue: self.app.state::<proxy::ProxyManager>().hold_queue.clone(),
            app: self.app.clone(),
        });
    }

    fn undo_protection(&self) {
        let _ = sysproxy::cleanup_all_persistent_settings();
    }
}

/// Publishes the start phase to the interface.
struct TauriStartupSink(tauri::AppHandle);

impl StartupSink for TauriStartupSink {
    fn publish(&self, snapshot: &StartupSnapshot) {
        let _ = self.0.emit(startup::STARTUP_EVENT, snapshot);
    }
}

/// Failed audits in a row at start before the tray says "Нет данных" (about 3.6 s plus the audit time).
const STARTUP_FAILURES_BEFORE_NO_DATA: u32 = 3;

/// Background tray status updater (network changes are handled by the NetworkGuard).
fn spawn_tray_status_watcher(
    app: &tauri::App,
    risk_auditor: &auditor::Auditor,
    app_state: &state::AppState,
    guard: Arc<proxy::NetworkGuard>,
) {
    let watcher_handle = app.handle().clone();
    let watcher_auditor = risk_auditor.clone();
    let watcher_state = app_state.clone();
    let watcher_guard = guard;
    tauri::async_runtime::spawn(async move {
        let mut initial_synced = false;
        let mut failures: u32 = 0;
        // Local time (HH:MM) of the last audit that produced a report.
        let mut last_checked: Option<String> = None;
        loop {
            match watcher_auditor
                .evaluate_all(auditor::ProviderId::Anthropic, &watcher_state, false)
                .await
            {
                Ok(report) => {
                    failures = 0;
                    last_checked = Some(chrono::Local::now().format("%H:%M").to_string());
                    let st = watcher_state.get_data().await;
                    let is_pinned = st
                        .pinned_ip
                        .as_ref()
                        .map(|p| p.trim() == report.telemetry.ip.trim())
                        .unwrap_or(false);
                    let has_blocked = !st.blocked_providers.is_empty()
                        || watcher_guard.gate() != proxy::Gate::Open;

                    update_tray_from_report(&watcher_handle, &report, is_pinned, has_blocked);
                    let _ = watcher_handle.emit("audit://refreshed", &report);

                    if !initial_synced {
                        initial_synced = true;
                        let _ = watcher_handle.emit("network://changed", &report);
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
                Err(_) => {
                    // Never leave the previous (possibly green) state on screen after a failed
                    // audit. A stop/block state is more important than "no data": keep it.
                    let st = watcher_state.get_data().await;
                    let has_blocked = !st.blocked_providers.is_empty()
                        || watcher_guard.gate() != proxy::Gate::Open;
                    failures += 1;
                    if !has_blocked {
                        if !initial_synced && failures < STARTUP_FAILURES_BEFORE_NO_DATA {
                            // Cold start (network or PAC not up yet): still "checking", not an error.
                            crate::tray::update_tray_checking(&watcher_handle);
                        } else {
                            crate::tray::update_tray_no_data(&watcher_handle, last_checked.as_deref());
                        }
                    }
                    if !initial_synced {
                        tokio::time::sleep(Duration::from_millis(1200)).await;
                    } else {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
            }
        }
    });
}

/// Background periodic GitHub update checker (after 20s, then every 60m).
/// Strictly respects user opt-out setting (auto_update_enabled).
fn spawn_update_checker(app: &tauri::App, app_state: &state::AppState) {
    let updater_app_handle = app.handle().clone();
    let updater_state = app_state.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            if updater_state.get_data().await.auto_update_enabled {
                if let Ok(res) = updater::check_for_updates(&updater_app_handle).await {
                    if res.update_available {
                        let _ = updater_app_handle.emit("updater://available", &res);
                        crate::tray::update_tray_tooltip(
                            &updater_app_handle,
                            format!("Застава — Доступна новая версия v{}", res.latest_version),
                        );
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}
