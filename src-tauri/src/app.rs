//! Application bootstrap: Tauri builder, setup sequence and background tasks.

use crate::startup::{self, StartupSink, StartupSnapshot, StartupState, StartupSteps};
use crate::tray::update_tray_from_report;
use crate::{
    auditor, bin_checker, commands, cowork_guard, os_tz, proxy, state, sysproxy, tray, updater,
};
use std::sync::Arc;
use std::time::Duration;
use tauri::{Emitter, Manager};

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            let mut found_deep_link = false;
            let minimized = argv.iter().any(|arg| arg == "--minimized");
            for arg in &argv {
                if arg.starts_with("zastava://") {
                    commands::deeplink::handle_deep_link(app, arg);
                    found_deep_link = true;
                }
            }
            if !found_deep_link
                && !minimized
                && let Some(win) = app.get_webview_window("main")
            {
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
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
                    os_tz::set_data_dir(dir.clone());
                    Some(dir)
                }
                Err(_) => None,
            };

            init_alert_popup(app);

            let (app_state, risk_auditor) = init_services(app)?;
            reconcile_active_profile_on_startup(&app_state);

            let (guard_for_watcher, pac_url) = start_proxy(app, &risk_auditor, &app_state);
            app.manage(guard_for_watcher.clone());

            let startup_state = Arc::new(StartupState::new());
            app.manage(startup_state.clone());

            tray::build_tray(app)?;

            spawn_tray_status_watcher(app, &risk_auditor, &app_state, guard_for_watcher.clone());
            spawn_update_checker(app, &app_state);
            spawn_cowork_guard_watcher(app);

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
                    commands::deeplink::handle_deep_link(app.handle(), &arg);
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event
                && window.label() == "main"
            {
                let _ = window.hide();
                api.prevent_close();
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
            commands::sysproxy::open_os_datetime_settings_cmd,
            commands::sysproxy::open_os_network_settings_cmd,
            commands::sysproxy::get_sysproxy_status,
            commands::sysproxy::get_error_diagnostics,
            commands::sysproxy::copy_text_to_clipboard,
            commands::sysproxy::export_diagnostic_bundle_cmd,
            commands::sysproxy::preview_protection_changes_cmd,
            commands::payment::check_payment_bin,
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
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error>)?;
    app.manage(risk_auditor.clone());

    // Initialize Payment Geo Checker
    let bin_checker = bin_checker::BinChecker::new();
    app.manage(bin_checker);

    Ok((app_state, risk_auditor))
}

/// Reconciles the active Claude profile's route and `"anthropic"` pinned IP from
/// `profiles.json` into `state.json` before the proxy server and guard start.
pub async fn reconcile_active_profile_binding_async(
    app_state: &state::AppState,
    binding: auditor::profile_switcher::ActiveProfileBindingState,
) {
    let st = app_state.get_data().await;
    let current_anthropic_pin = st
        .pinned_ips
        .get(state::PROVIDER_ANTHROPIC)
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let target_pin = binding
        .bound_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if current_anthropic_pin != target_pin
        && let Err(err) = app_state
            .set_pinned_ip_for(state::PROVIDER_ANTHROPIC, target_pin.map(str::to_string))
            .await
    {
        crate::diagnostics::record("startup_profile", &err.to_string());
    }

    if let Some(ref key) = binding.bound_upstream_key {
        let route_matches = binding.bound_route_id.as_deref().is_some_and(|rid| {
            st.routes
                .iter()
                .any(|r| r.id == rid && r.raw_key == *key)
        });
        let needs_apply = st.profile_route_invalid.is_some()
            || st.profile_route_id.as_deref() != binding.bound_route_id.as_deref()
            || !route_matches;
        if needs_apply
            && let Err(err) = crate::routing::apply_profile_key(app_state, Some(key)).await
        {
            crate::diagnostics::record("startup_profile", &err);
        }
        // Clear any stale local-VPN block on Anthropic left from before restart when the active
        // profile has a valid Zastava key route (non-profile providers stay intact).
        let st_after = app_state.get_data().await;
        if st_after.profile_route_invalid.is_none()
            && st_after.profile_route_id.is_some()
            && st_after.blocked_providers.contains(state::PROVIDER_ANTHROPIC)
            && let Err(err) = app_state.unblock_provider(state::PROVIDER_ANTHROPIC).await
        {
            crate::diagnostics::record("startup_profile", &err.to_string());
        }
    } else if let Some(ref dangling_rid) = binding.bound_route_id {
        if st.profile_route_id.as_deref() != Some(dangling_rid.as_str())
            && let Err(err) = app_state
                .set_profile_route_dangling(dangling_rid.clone())
                .await
        {
            crate::diagnostics::record("startup_profile", &err.to_string());
        }
    } else if st.profile_route_id.is_some()
        && let Err(err) = crate::routing::apply_profile_key(app_state, None).await
    {
        crate::diagnostics::record("startup_profile", &err);
    }
}

fn reconcile_active_profile_on_startup(app_state: &state::AppState) {
    let binding = match auditor::profile_switcher::active_profile_binding_state() {
        Ok(Some(b)) => b,
        Ok(None) => return,
        Err(err) => {
            crate::diagnostics::record("startup_profile", &err);
            return;
        }
    };

    tauri::async_runtime::block_on(reconcile_active_profile_binding_async(app_state, binding));
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
            Some(dir) => {
                match sysproxy::recover_ownership_on_start(dir) {
                    Ok(report) => eprintln!("Застава: {}", report.summary()),
                    Err(e) => eprintln!("Застава: восстановление отложено, {e}"),
                }
                os_tz::recover_baseline_on_start(dir);
            }
            None => eprintln!("Застава: каталог данных недоступен, восстановление отложено"),
        }
    }

    fn enable_protection(&self) {
        enable_default_protection(&self.app_state, &self.pac_url);
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
        let mut last_synced_ip: Option<String> = None;
        let mut last_synced_status: Option<(auditor::OverallStatus, bool)> = None;
        let mut last_observed_ip: Option<String> = None;
        loop {
            if watcher_guard.any_provider_gate_pending() {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                continue;
            }
            let st_pre = watcher_state.get_data().await;
            let enabled_pids: Vec<auditor::ProviderId> = st_pre
                .enabled_providers()
                .into_iter()
                .filter_map(auditor::ProviderId::from_id)
                .collect();
            let Some(&pid) = enabled_pids.first() else {
                crate::tray::update_tray_status(
                    &watcher_handle,
                    "green",
                    Some("Мониторинг провайдеров отключён"),
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            };
            match watcher_auditor
                .evaluate_all(pid, &watcher_state, false)
                .await
            {
                Ok(mut report) => {
                    failures = 0;
                    last_checked = Some(chrono::Local::now().format("%H:%M").to_string());
                    if watcher_guard.any_provider_gate_pending() {
                        tokio::time::sleep(Duration::from_millis(1000)).await;
                        continue;
                    }
                    let st = watcher_state.get_data().await;
                    let is_pinned = commands::audit::is_ip_pinned_for_state(
                        &st,
                        pid,
                        &report.telemetry.ip,
                    );
                    auditor::history::apply_pinned_travel_grace(&mut report, is_pinned);
                    let has_blocked = !st.blocked_providers.is_empty()
                        || watcher_guard.any_provider_gate_closed();

                    let mut tray_report =
                        proxy::guard::effective_tray_report(&report, has_blocked, &st)
                            .into_owned();
                    let mut tray_is_pinned = is_pinned;
                    let _ = watcher_handle.emit("audit://refreshed", &report);

                    let cur_observed_ip = watcher_guard.current_observed_ip().await;
                    let ip_changed = last_synced_ip
                        .as_deref()
                        .is_some_and(|prev| prev != report.telemetry.ip.as_str());
                    let observed_changed =
                        last_observed_ip.is_some() && cur_observed_ip != last_observed_ip;

                    let mut sibling_status_changed = false;
                    if !initial_synced || ip_changed || observed_changed || has_blocked {
                        for &other_pid in enabled_pids.iter().skip(1) {
                            if watcher_guard.any_provider_gate_pending() {
                                break;
                            }
                            let is_routed =
                                crate::routing::select_route_id(&st, other_pid.as_str()).is_some();
                            if is_routed {
                                continue;
                            }
                            if let Ok(mut other_report) = watcher_auditor
                                .evaluate_all(other_pid, &watcher_state, false)
                                .await
                            {
                                let other_pinned = commands::audit::is_ip_pinned_for_state(
                                    &st,
                                    other_pid,
                                    &other_report.telemetry.ip,
                                );
                                auditor::history::apply_pinned_travel_grace(
                                    &mut other_report,
                                    other_pinned,
                                );
                                let _ = watcher_handle.emit("audit://refreshed", &other_report);
                                if !proxy::guard::report_allowed_for_state(
                                    &other_report,
                                    &st,
                                    false,
                                ) {
                                    let rank = |s: auditor::OverallStatus| match s {
                                        auditor::OverallStatus::Red => 2u8,
                                        auditor::OverallStatus::Yellow => 1u8,
                                        auditor::OverallStatus::Green => 0u8,
                                    };
                                    if rank(other_report.overall_status)
                                        > rank(tray_report.overall_status)
                                    {
                                        tray_report = proxy::guard::effective_tray_report(
                                            &other_report,
                                            has_blocked,
                                            &st,
                                        )
                                        .into_owned();
                                        tray_is_pinned = other_pinned;
                                        sibling_status_changed = true;
                                    }
                                }
                            }
                        }
                    }

                    update_tray_from_report(
                        &watcher_handle,
                        &tray_report,
                        tray_is_pinned,
                        has_blocked,
                    );

                    let cur_status = (tray_report.overall_status, has_blocked);
                    let status_changed = last_synced_status
                        .is_some_and(|prev| prev != cur_status)
                        || sibling_status_changed;

                    // If status changed on the same IP, still refresh sibling unrouted providers
                    // when they were not already refreshed above.
                    if initial_synced
                        && status_changed
                        && !ip_changed
                        && !observed_changed
                        && !has_blocked
                    {
                        for &other_pid in enabled_pids.iter().skip(1) {
                            if watcher_guard.any_provider_gate_pending() {
                                break;
                            }
                            if crate::routing::select_route_id(&st, other_pid.as_str()).is_some() {
                                continue;
                            }
                            if let Ok(mut other_report) = watcher_auditor
                                .evaluate_all(other_pid, &watcher_state, false)
                                .await
                            {
                                let other_pinned = commands::audit::is_ip_pinned_for_state(
                                    &st,
                                    other_pid,
                                    &other_report.telemetry.ip,
                                );
                                auditor::history::apply_pinned_travel_grace(
                                    &mut other_report,
                                    other_pinned,
                                );
                                let _ = watcher_handle.emit("audit://refreshed", &other_report);
                            }
                        }
                    }

                    last_synced_ip = Some(report.telemetry.ip.clone());
                    last_synced_status = Some(cur_status);
                    last_observed_ip = cur_observed_ip;

                    if !initial_synced {
                        initial_synced = true;
                        let _ = watcher_handle.emit("network://changed", &report);
                    } else if ip_changed || status_changed || observed_changed {
                        if ip_changed || observed_changed {
                            watcher_guard.wake();
                        }
                        let _ = watcher_handle.emit("network://changed", &report);
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
                Err(_) => {
                    if watcher_guard.any_provider_gate_pending() {
                        tokio::time::sleep(Duration::from_millis(1000)).await;
                        continue;
                    }
                    // Never leave the previous (possibly green) state on screen after a failed
                    // audit. A stop/block state is more important than "no data": keep it.
                    let st = watcher_state.get_data().await;
                    let has_blocked = !st.blocked_providers.is_empty()
                        || watcher_guard.any_provider_gate_closed();
                    failures += 1;
                    if !has_blocked {
                        if !initial_synced && failures < STARTUP_FAILURES_BEFORE_NO_DATA {
                            // Cold start (network or PAC not up yet): still "checking", not an error.
                            crate::tray::update_tray_checking(&watcher_handle);
                        } else {
                            crate::tray::update_tray_no_data(
                                &watcher_handle,
                                last_checked.as_deref(),
                            );
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
            if updater_state.get_data().await.auto_update_enabled
                && let Ok(res) = updater::check_for_updates(&updater_app_handle).await
                && res.update_available
            {
                let _ = updater_app_handle.emit("updater://available", &res);
                crate::tray::update_tray_tooltip(
                    &updater_app_handle,
                    format!("Застава — Доступна новая версия v{}", res.latest_version),
                );
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

/// Periodically verifies Windows `CoworkVMService` Start type / macOS AI helpers every 60s.
/// If a Windows Store update resets `CoworkVMService\Start` back to `2` (Automatic) while the
/// Task Scheduler guard is installed, triggers the guard task automatically and notifies the UI.
fn spawn_cowork_guard_watcher(app: &tauri::App) {
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            if let Ok(mut status) =
                tokio::task::spawn_blocking(cowork_guard::get_cowork_guard_status).await
            {
                if status.supported && status.task_installed && status.start_type == Some(2) {
                    let triggered =
                        tokio::task::spawn_blocking(cowork_guard::trigger_cowork_guard_task)
                            .await
                            .unwrap_or(false);
                    if triggered {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        if let Ok(refreshed) =
                            tokio::task::spawn_blocking(cowork_guard::get_cowork_guard_status).await
                        {
                            status = refreshed;
                        }
                    }
                }
                let _ = handle.emit("cowork-guard://status", &status);
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reconcile_active_profile_clears_stale_anthropic_pin_even_when_route_matches() {
        let app_state = state::AppState::new_in_memory();
        let route = crate::routing::parse_route_key("socks5://1.2.3.4:1080#nl", 1).unwrap();
        let route_id = route.id.clone();
        let raw_key = route.raw_key.clone();
        app_state.apply_profile_route(route).await.unwrap();
        app_state
            .set_pinned_ip_for(state::PROVIDER_ANTHROPIC, Some("9.9.9.9".to_string()))
            .await
            .unwrap();
        app_state
            .set_pinned_ip_for("default", Some("2.2.2.2".to_string()))
            .await
            .unwrap();

        // Active profile has matching bound_route_id and bound_ip = None -> stale anthropic pin
        // must still be cleared while preserving "default".
        reconcile_active_profile_binding_async(
            &app_state,
            auditor::profile_switcher::ActiveProfileBindingState {
                profile_id: "p1".to_string(),
                bound_ip: None,
                bound_upstream_key: Some(raw_key.clone()),
                bound_route_id: Some(route_id.clone()),
            },
        )
        .await;
        let st1 = app_state.get_data().await;
        assert!(!st1.pinned_ips.contains_key(state::PROVIDER_ANTHROPIC));
        assert_eq!(st1.pinned_ips.get("default").map(String::as_str), Some("2.2.2.2"));

        // Active profile sets bound_ip while route still matches -> anthropic pin updated cleanly.
        reconcile_active_profile_binding_async(
            &app_state,
            auditor::profile_switcher::ActiveProfileBindingState {
                profile_id: "p1".to_string(),
                bound_ip: Some("1.2.3.4".to_string()),
                bound_upstream_key: Some(raw_key),
                bound_route_id: Some(route_id),
            },
        )
        .await;
        let st2 = app_state.get_data().await;
        assert_eq!(
            st2.pinned_ips
                .get(state::PROVIDER_ANTHROPIC)
                .map(String::as_str),
            Some("1.2.3.4")
        );
        assert_eq!(st2.pinned_ips.get("default").map(String::as_str), Some("2.2.2.2"));
    }
}
