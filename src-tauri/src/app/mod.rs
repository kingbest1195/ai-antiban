//! Application bootstrap: Tauri builder, setup sequence and background tasks.

mod deep_links;
mod rlimit;
mod watchers;

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub use deep_links::reconcile_active_profile_binding_async;
pub use rlimit::raise_nofile_limit;
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)]
pub use watchers::try_silent_paused_recovery;

use crate::startup::{self, StartupSink, StartupSnapshot, StartupState, StartupSteps};
use crate::{auditor, bin_checker, commands, os_tz, proxy, state, sysproxy, tray};
use deep_links::{
    handle_initial_deep_links, handle_single_instance_launch, reconcile_active_profile_on_startup,
    register_deep_link_handlers,
};
use std::sync::Arc;
use tauri::{Emitter, Manager};
use watchers::{
    spawn_bunker_scheduler, spawn_cowork_guard_watcher, spawn_route_subscription_refresher,
    spawn_tray_status_watcher, spawn_update_checker,
};

pub fn run() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = crate::try_handle_early_cli_args(&args) {
        std::process::exit(code);
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            handle_single_instance_launch(app, &argv);
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            // Register panic guard, Layer 0 shutdown/startup-drain hooks, and OS signal watcher
            crate::core::shutdown::register_shutdown_hook(|| {
                startup::note_shutdown_global();
            });
            crate::core::shutdown::register_startup_drain_hook(startup::wait_for_startup_drain);
            sysproxy::register_clean_exit_guard();
            sysproxy::spawn_signal_cleanup_watcher();
            // Only the directory is pinned here (cheap). The ownership recovery pass, the
            // protection and the guard run in the background sequence below: the window and the
            // tray must answer at once, not after a dozen `networksetup` calls.
            let data_dir = match app.path().app_data_dir() {
                Ok(dir) => {
                    sysproxy::set_data_dir(dir.clone());
                    os_tz::set_data_dir(dir.clone());
                    Some(dir)
                }
                Err(_) => None,
            };
            crate::popup::init_alert_popup(app);
            crate::proxy::popup_port::register_ui_hooks(
                crate::popup::show_and_position_alert_popup_timed,
                crate::popup::hide_alert_popup,
                crate::update_tray_from_report,
                crate::update_tray_status,
            );
            crate::proxy::popup_port::register_tray_guard_hook(
                crate::tray::update_tray_from_guard_status,
            );
            let (app_state, risk_auditor) = init_services(app)?;
            reconcile_active_profile_on_startup(&app_state);
            let (guard_for_watcher, pac_url) = start_proxy(app, &risk_auditor, &app_state);
            app.manage(guard_for_watcher.clone());

            let guard_for_shutdown = guard_for_watcher.clone();
            crate::core::shutdown::register_tunnel_abort_hook(move || {
                guard_for_shutdown.abort_all_tunnels_on_shutdown();
            });
            let app_for_sandbox_exit = app.handle().clone();
            crate::core::shutdown::register_sandbox_exit_hook(move || {
                terminate_sandboxes_once(&app_for_sandbox_exit);
            });

            let startup_state = Arc::new(StartupState::new());
            let startup_for_shutdown = startup_state.clone();
            crate::core::shutdown::register_shutdown_hook(move || {
                startup::note_shutdown_global();
                startup_for_shutdown.begin_shutdown();
            });
            app.manage(startup_state.clone());

            tray::build_tray(app)?;

            spawn_tray_status_watcher(app, &risk_auditor, &app_state, guard_for_watcher.clone());
            spawn_update_checker(app, &app_state);
            spawn_cowork_guard_watcher(app);
            spawn_bunker_scheduler(app, &app_state);
            spawn_route_subscription_refresher(app, &risk_auditor, &app_state);

            // Window starts hidden (`visible: false` in tauri.conf.json) so `--minimized`
            // keeps Zastava strictly in the tray; show it on interactive launches.
            let start_minimized = std::env::args().any(|a| a == "--minimized");
            if !start_minimized && let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }

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

            register_deep_link_handlers(app);
            handle_initial_deep_links(app);

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    let _ = window.hide();
                    api.prevent_close();
                } else if window.label() == "alert-popup" {
                    let _ = window.hide();
                    api.prevent_close();
                    let app = window.app_handle().clone();
                    tauri::async_runtime::spawn(async move {
                        if let Some(pm) = app.try_state::<proxy::ProxyManager>()
                            && pm.hold_queue.block_all_checkout_holds().await > 0
                        {
                            let _ = app.emit("interceptor://resolved", "");
                        }
                    });
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
            commands::audit::get_pinned_ips,
            commands::audit::get_onboarding_v2_2_done,
            commands::audit::set_onboarding_v2_2_done,
            commands::audit::get_hide_ip_mode,
            commands::audit::set_hide_ip_mode,
            commands::audit::toggle_strict_pinning,
            commands::audit::allow_provider_session,
            commands::audit::unblock_provider_cmd,
            commands::audit::verify_and_unblock_provider,
            commands::audit::set_provider_monitoring,
            commands::audit::remove_trusted_exception,
            commands::audit::clear_trusted_exceptions,
            commands::interception::resolve_interception,
            commands::interception::simulate_interception,
            commands::interception::take_pending_alert,
            commands::sysproxy::toggle_sysproxy,
            commands::sysproxy::toggle_sysproxy_privileged,
            commands::sysproxy::enable_cli_protection,
            commands::sysproxy::disable_cli_protection,
            commands::sysproxy::check_cli_protection_status,
            commands::sysproxy::sync_ai_agents_timezone,
            commands::sysproxy::sync_os_timezone_cmd,
            commands::sysproxy::restore_os_timezone_cmd,
            commands::sysproxy::get_os_timezone_sync_status_cmd,
            commands::sysproxy::get_cli_settings,
            commands::sysproxy::set_cli_mode,
            commands::sysproxy::set_sync_ai_tz_enabled,
            commands::sysproxy::get_keep_system_tz_on_exit,
            commands::sysproxy::set_keep_system_tz_on_exit,
            commands::sysproxy::open_os_datetime_settings_cmd,
            commands::sysproxy::open_os_network_settings_cmd,
            commands::sysproxy::get_sysproxy_status,
            commands::sysproxy::get_error_diagnostics,
            commands::sysproxy::copy_text_to_clipboard,
            commands::sysproxy::export_diagnostic_bundle_cmd,
            commands::sysproxy::preview_protection_changes_cmd,
            commands::payment::check_payment_bin,
            commands::payment::check_card_bin,
            commands::payment::evaluate_payment_readiness,
            commands::payment::cancel_and_inspect,
            commands::payment::allow_checkout_15m,
            commands::payment::activate_post_payment_quarantine,
            commands::payment::get_post_payment_quarantine_status,
            commands::payment::override_post_payment_quarantine,
            commands::payment::get_payment_advice,
            commands::payment::get_bin_radar_stats,
            commands::payment::get_providers_manifest,
            commands::payment::submit_bin_radar_report,
            commands::payment::set_bin_radar_opt_in,
            commands::updates::check_for_updates,
            commands::updates::install_update,
            commands::updates::toggle_auto_update,
            commands::updates::list_rollback_versions,
            commands::updates::install_rollback_version,
            commands::claude::list_claude_profiles_cmd,
            commands::claude::create_claude_profile_cmd,
            commands::claude::switch_claude_profile_cmd,
            commands::claude::delete_claude_profile_cmd,
            commands::claude::bind_ip_to_claude_profile_cmd,
            commands::claude::bind_upstream_to_claude_profile_cmd,
            commands::claude::bind_route_to_claude_profile,
            commands::claude::safe_logout_claude_cmd,
            commands::claude::clear_ip_change_cooldown_cmd,
            commands::autostart::get_autostart_status,
            commands::autostart::set_autostart_enabled,
            commands::autostart::get_cowork_guard_status,
            commands::autostart::install_or_repair_cowork_guard,
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
            commands::routes_sub::refresh_route_subscription,
            commands::payment::set_warmup_timer,
            commands::audit::get_gateway_stats,
            commands::audit::get_split_tunnel_mode,
            commands::audit::set_split_tunnel_mode,
            commands::sysproxy::force_clean_os_proxy_cmd,
            commands::interception::toggle_network_killswitch_cmd,
            commands::interception::get_network_killswitch_status_cmd,
            commands::interception::pause_until_network_change_cmd,
            commands::interception::set_guard_pause_mode_cmd,
            commands::interception::get_guard_pause_status_cmd,
            commands::coverage::get_coverage_snapshot,
            commands::coverage::recheck_coverage,
            commands::coverage::reapply_browser_policies_cmd,
            commands::coverage::relaunch_browsers_with_pac_cmd,
            commands::restart_app::restart_app_with_gateway,
            commands::deeplink::take_pending_deep_link,
            commands::clean_room::run_clean_room_audit,
            commands::clean_room::discover_clean_browsers,
            commands::clean_room::profiles::list_clean_profiles,
            commands::clean_room::profiles::create_clean_profile,
            commands::clean_room::profiles::update_clean_profile_step,
            commands::clean_room::profiles::update_clean_profile_route,
            commands::clean_room::profiles::start_clean_profile_warmup,
            commands::clean_room::profiles::launch_clean_browser,
            commands::clean_room::profiles::mark_clean_profile_tainted,
            commands::clean_room::profiles::delete_clean_profile,
            commands::clean_room::mark_ip_tainted,
            commands::clean_room::untaint_clean_room_ip,
            commands::state_v3::complete_onboarding_v3,
            commands::state_v3::mark_whats_new_v3_seen,
            commands::state_v3::dismiss_hint,
            commands::state_v3::reset_dismissed_hints,
            commands::bunker::get_bunker_status,
            commands::bunker::update_bunker_settings,
            commands::bunker::run_bunker_backup_now,
            commands::bunker::list_bunker_snapshots,
            commands::bunker::clear_bunker_snapshots,
            commands::bunker::open_bunker_folder,
            commands::bunker::convert_web_export,
            commands::bunker::generate_bunker_restore_prompt,
            commands::bunker::run_context_teleport,
            commands::bunker::get_payment_passport,
            commands::bunker::save_payment_passport,
            commands::bunker::verify_payment_passport,
            commands::sos::get_persona_risk_report,
            commands::sos::update_persona_self_check,
            commands::sos::clean_antigravity_auth_cache
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
                terminate_sandboxes_once(app_handle);
                // Cmd+Q / closing the last window / external OS exit: run shutdown cleanup only if
                // it has not already executed via the async tray-quit or updater flows.
                if let Some(report) = sysproxy::cleanup_on_shutdown_once(Some(app_handle), "quit") {
                    if report.has_failures() {
                        eprintln!(
                            "Застава: часть настроек будет восстановлена при следующем запуске"
                        );
                    }
                    if report.restore_deferred_by_vpn_dns() {
                        sysproxy::notify_restore_deferred();
                    }
                }
            }
            _ => {}
        });
}

/// Initializes persistent AppState, the Risk Auditor Engine and the Payment Geo Checker.
fn init_services(
    app: &tauri::App,
) -> Result<(state::AppState, auditor::Auditor), Box<dyn std::error::Error>> {
    let app_state = state::init_app_state(app.handle())
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    let keep_tz = tauri::async_runtime::block_on(app_state.get_keep_system_tz_on_exit());
    os_tz::set_keep_system_tz_on_exit(keep_tz);
    app.manage(app_state.clone());

    let risk_auditor = auditor::Auditor::new()
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error>)?;
    app.manage(risk_auditor.clone());

    let bin_checker = bin_checker::BinChecker::new();
    app.manage(bin_checker);

    app.manage(crate::clean_room::browser_sandbox::SandboxProcessRegistry::new());

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
        let proxy_mgr =
            proxy::ProxyManager::start(auditor_for_proxy, state_for_proxy, Some(handle_clone))
                .await
                .expect("Failed to start proxy server");
        let guard = proxy_mgr.guard.clone();
        guard.restore_manual_killswitch(app_state).await;
        let pac_url = format!("http://{}/proxy.pac", proxy_mgr.server.bound_addr);
        app.manage(proxy_mgr);
        (guard, pac_url)
    })
}

fn terminate_sandboxes_once(app_handle: &tauri::AppHandle) {
    static SANDBOX_SHUTDOWN_DONE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    if !SANDBOX_SHUTDOWN_DONE.swap(true, std::sync::atomic::Ordering::SeqCst)
        && let Some(sandbox_registry) =
            app_handle.try_state::<crate::clean_room::browser_sandbox::SandboxProcessRegistry>()
    {
        let data_dir = app_handle.path().app_data_dir().ok();
        crate::clean_room::browser_sandbox::terminate_all_sandboxes_on_exit(
            &sandbox_registry,
            data_dir.as_deref(),
        );
    }
}

fn run_default_protection_with(
    is_shutting_down: impl Fn() -> bool,
    enable_sys: impl FnOnce(),
    enable_cli: impl FnOnce(),
) {
    if is_shutting_down() {
        return;
    }
    enable_sys();
    if is_shutting_down() {
        return;
    }
    enable_cli();
}

/// Protection is ON by default: route AI domains through the local interceptor.
fn enable_default_protection(app: &tauri::AppHandle, app_state: &state::AppState, pac_url: &str) {
    run_default_protection_with(
        startup::is_shutting_down_global,
        || match sysproxy::enable_sysproxy(pac_url) {
            Ok(status) => println!(
                "Застава: сетевой контроль включен ({} сетевых служб)",
                status.services_configured.len()
            ),
            Err(e) => {
                crate::diagnostics::record("startup:sysproxy", &e);
                if e.starts_with("ADMIN_AUTH_REQUIRED:") {
                    let _ = app.emit("sysproxy://admin-auth-required", &e);
                }
                eprintln!("Застава: не удалось включить защиту при старте: {e}");
            }
        },
        || {
            let (mode, tz) = tauri::async_runtime::block_on(async {
                let data = app_state.get_data().await;
                (data.cli_mode, data.effective_sync_tz())
            });
            if startup::is_shutting_down_global() {
                return;
            }
            let cli_report =
                sysproxy::enable_cli_and_ide_protection_with(pac_url, mode, tz.as_deref());
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
        },
    );
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
            Some(dir) => {
                match sysproxy::recover_ownership_on_start(dir) {
                    Ok(report) => eprintln!("Застава: {}", report.summary()),
                    Err(e) => eprintln!("Застава: восстановление отложено, {e}"),
                }
                if !os_tz::keep_system_tz_on_exit() {
                    os_tz::recover_baseline_on_start(dir);
                }
            }
            None => eprintln!("Застава: каталог данных недоступен, восстановление отложено"),
        }
    }

    fn enable_protection(&self) {
        enable_default_protection(&self.app, &self.app_state, &self.pac_url);
    }

    /// Network guard: detects sudden IP changes and freezes AI traffic until confirmed.
    fn start_guard(&self) {
        if !sysproxy::is_sysproxy_active() {
            sysproxy::clear_stale_browser_pac_prefs();
        }
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
