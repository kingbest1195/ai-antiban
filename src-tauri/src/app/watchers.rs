//! Background watchers: tray status polling, GitHub update check, and CoworkVMService guard.

use crate::tray::update_tray_from_report;
use crate::{auditor, bunker, commands, cowork_guard, proxy, state, sysproxy, updater};
use std::sync::Arc;
use std::time::Duration;
use tauri::{Emitter, Manager};

/// Failed audits in a row at start before the tray says "Нет данных" (about 3.6 s plus the audit time).
const STARTUP_FAILURES_BEFORE_NO_DATA: u32 = 3;

fn status_rank(s: auditor::OverallStatus) -> u8 {
    match s {
        auditor::OverallStatus::Red => 2,
        auditor::OverallStatus::Yellow => 1,
        auditor::OverallStatus::Green => 0,
    }
}

struct SiblingRefreshCtx<'a> {
    handle: &'a tauri::AppHandle,
    auditor: &'a auditor::Auditor,
    state: &'a state::AppState,
    guard: &'a proxy::NetworkGuard,
    st: &'a state::AppStateData,
    enabled_pids: &'a [auditor::ProviderId],
    has_blocked: bool,
    protection: auditor::AuditProtectionFlags,
}

async fn refresh_sibling_unrouted_providers(
    ctx: &SiblingRefreshCtx<'_>,
    tray_report: &mut auditor::RiskReport,
    tray_is_pinned: &mut bool,
    update_tray_on_worse: bool,
) -> bool {
    let mut sibling_status_changed = false;
    for &other_pid in ctx.enabled_pids.iter().skip(1) {
        if ctx.guard.any_provider_gate_pending() {
            break;
        }
        if crate::routing::select_route_id(ctx.st, other_pid.as_str()).is_some() {
            continue;
        }
        if let Ok(mut other_report) = ctx
            .auditor
            .evaluate_all_with_protection(other_pid, ctx.state, false, ctx.protection)
            .await
        {
            let other_pinned = commands::audit::is_ip_pinned_for_state(
                ctx.st,
                other_pid,
                &other_report.telemetry.ip,
            );
            auditor::history::apply_pinned_travel_grace(&mut other_report, other_pinned);
            let _ = ctx.handle.emit("audit://refreshed", &other_report);
            if update_tray_on_worse
                && !proxy::guard::report_allowed_for_state(&other_report, ctx.st, false)
                && status_rank(other_report.overall_status)
                    > status_rank(tray_report.overall_status)
            {
                *tray_report =
                    proxy::guard::effective_tray_report(&other_report, ctx.has_blocked, ctx.st)
                        .into_owned();
                *tray_is_pinned = other_pinned;
                sibling_status_changed = true;
            }
        }
    }
    sibling_status_changed
}

async fn wait_next_tray_tick(
    delay: Duration,
    gate_rx: &mut tokio::sync::watch::Receiver<proxy::Gate>,
    kill_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    tokio::select! {
        _ = tokio::time::sleep(delay) => {}
        res = gate_rx.changed(), if !gate_rx.has_changed().unwrap_or(true) => {
            if res.is_err() { tokio::time::sleep(delay).await; }
        }
        res = kill_rx.changed(), if !kill_rx.has_changed().unwrap_or(true) => {
            if res.is_err() { tokio::time::sleep(delay).await; }
        }
    }
}

fn sync_tray_if_guard_active(handle: &tauri::AppHandle, guard: &proxy::NetworkGuard) -> bool {
    let active = guard.is_paused() || guard.any_provider_gate_pending();
    if active {
        crate::tray::update_tray_from_guard_status(handle, &guard.pause_status());
    }
    active
}

/// Background tray status updater (network changes are handled by the NetworkGuard).
pub(super) fn spawn_tray_status_watcher(
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
        let mut gate_rx = watcher_guard.subscribe();
        let mut kill_rx = watcher_guard.subscribe_killswitch();
        let mut initial_synced = false;
        let mut failures: u32 = 0;
        // Local time (HH:MM) of the last audit that produced a report.
        let mut last_checked: Option<String> = None;
        let mut last_synced_ip: Option<String> = None;
        let mut last_synced_status: Option<(auditor::OverallStatus, bool)> = None;
        let mut last_observed_ip: Option<String> = None;
        loop {
            if sync_tray_if_guard_active(&watcher_handle, &watcher_guard) {
                let delay = if watcher_guard.any_provider_gate_pending() {
                    Duration::from_millis(1000)
                } else {
                    Duration::from_secs(10)
                };
                wait_next_tray_tick(delay, &mut gate_rx, &mut kill_rx).await;
                continue;
            }
            let st_pre = watcher_state.get_data().await;
            let enabled_pids: Vec<auditor::ProviderId> = st_pre
                .enabled_providers()
                .into_iter()
                .filter_map(auditor::ProviderId::from_id)
                .collect();
            let Some(&pid) = enabled_pids.first() else {
                if !sync_tray_if_guard_active(&watcher_handle, &watcher_guard) {
                    let startup_ready = watcher_handle
                        .try_state::<Arc<crate::startup::StartupState>>()
                        .is_none_or(|s| s.is_ready());
                    if startup_ready && !sysproxy::is_sysproxy_active() {
                        crate::tray::update_tray_protection_off(&watcher_handle);
                    } else {
                        crate::tray::update_tray_status(
                            &watcher_handle,
                            "green",
                            Some("Мониторинг провайдеров отключён"),
                        );
                    }
                }
                wait_next_tray_tick(Duration::from_secs(10), &mut gate_rx, &mut kill_rx).await;
                continue;
            };
            let protection = commands::audit::read_runtime_protection_flags().await;
            match watcher_auditor
                .evaluate_all_with_protection(pid, &watcher_state, false, protection)
                .await
            {
                Ok(mut report) => {
                    failures = 0;
                    last_checked = Some(chrono::Local::now().format("%H:%M").to_string());
                    if sync_tray_if_guard_active(&watcher_handle, &watcher_guard) {
                        wait_next_tray_tick(
                            Duration::from_millis(1000),
                            &mut gate_rx,
                            &mut kill_rx,
                        )
                        .await;
                        continue;
                    }
                    let reports_slice = std::slice::from_ref(&report);
                    if proxy::try_auto_unblock_pinned_providers(
                        &watcher_state,
                        &watcher_guard,
                        reports_slice,
                    )
                    .await
                    {
                        let _ = watcher_handle.emit("network://changed", &report);
                    }
                    let st = watcher_state.get_data().await;
                    let is_pinned =
                        commands::audit::is_ip_pinned_for_state(&st, pid, &report.telemetry.ip);
                    auditor::history::apply_pinned_travel_grace(&mut report, is_pinned);
                    let has_blocked = !st.blocked_providers.is_empty()
                        || watcher_guard.any_provider_gate_closed();

                    let mut tray_report =
                        proxy::guard::effective_tray_report(&report, has_blocked, &st).into_owned();
                    let mut tray_is_pinned = is_pinned;
                    let _ = watcher_handle.emit("audit://refreshed", &report);

                    let cur_observed_ip = watcher_guard.current_observed_ip().await;
                    let ip_changed = last_synced_ip
                        .as_deref()
                        .is_some_and(|prev| prev != report.telemetry.ip.as_str());
                    let observed_changed =
                        last_observed_ip.is_some() && cur_observed_ip != last_observed_ip;

                    let sibling_ctx = SiblingRefreshCtx {
                        handle: &watcher_handle,
                        auditor: &watcher_auditor,
                        state: &watcher_state,
                        guard: &watcher_guard,
                        st: &st,
                        enabled_pids: &enabled_pids,
                        has_blocked,
                        protection,
                    };
                    let sibling_status_changed =
                        if !initial_synced || ip_changed || observed_changed || has_blocked {
                            refresh_sibling_unrouted_providers(
                                &sibling_ctx,
                                &mut tray_report,
                                &mut tray_is_pinned,
                                true,
                            )
                            .await
                        } else {
                            false
                        };

                    if sync_tray_if_guard_active(&watcher_handle, &watcher_guard) {
                        wait_next_tray_tick(
                            Duration::from_millis(1000),
                            &mut gate_rx,
                            &mut kill_rx,
                        )
                        .await;
                        continue;
                    }
                    update_tray_from_report(
                        &watcher_handle,
                        &tray_report,
                        tray_is_pinned,
                        has_blocked,
                    );

                    let cur_status = (tray_report.overall_status, has_blocked);
                    let status_changed = last_synced_status.is_some_and(|prev| prev != cur_status)
                        || sibling_status_changed;

                    // If status changed on the same IP, still refresh sibling unrouted providers
                    // when they were not already refreshed above.
                    if initial_synced
                        && status_changed
                        && !ip_changed
                        && !observed_changed
                        && !has_blocked
                    {
                        refresh_sibling_unrouted_providers(
                            &sibling_ctx,
                            &mut tray_report,
                            &mut tray_is_pinned,
                            false,
                        )
                        .await;
                        if sync_tray_if_guard_active(&watcher_handle, &watcher_guard) {
                            wait_next_tray_tick(
                                Duration::from_millis(1000),
                                &mut gate_rx,
                                &mut kill_rx,
                            )
                            .await;
                            continue;
                        }
                    }

                    last_synced_ip = Some(report.telemetry.ip.clone());
                    last_synced_status = Some(cur_status);
                    last_observed_ip = cur_observed_ip;

                    if !initial_synced {
                        initial_synced = true;
                        let _ = watcher_handle.emit("network://changed", &report);
                    } else if (ip_changed || status_changed || observed_changed)
                        && !watcher_guard.is_paused()
                        && !watcher_guard.any_provider_gate_pending()
                    {
                        if ip_changed
                            && watcher_guard.current_observed_ip().await.as_deref()
                                != Some(report.telemetry.ip.as_str())
                        {
                            watcher_guard.wake_immediate_probe().await;
                        }
                        let _ = watcher_handle.emit("network://changed", &report);
                    }
                    wait_next_tray_tick(Duration::from_secs(10), &mut gate_rx, &mut kill_rx).await;
                }
                Err(_) => {
                    if sync_tray_if_guard_active(&watcher_handle, &watcher_guard) {
                        wait_next_tray_tick(
                            Duration::from_millis(1000),
                            &mut gate_rx,
                            &mut kill_rx,
                        )
                        .await;
                        continue;
                    }
                    // Never leave the previous (possibly green) state on screen after a failed
                    // audit. A stop/block state is more important than "no data": keep it.
                    let st = watcher_state.get_data().await;
                    let has_blocked = !st.blocked_providers.is_empty()
                        || watcher_guard.any_provider_gate_closed();
                    failures += 1;
                    if !has_blocked {
                        let startup_ready = watcher_handle
                            .try_state::<Arc<crate::startup::StartupState>>()
                            .is_none_or(|s| s.is_ready());
                        if startup_ready && !sysproxy::is_sysproxy_active() {
                            crate::tray::update_tray_protection_off(&watcher_handle);
                        } else if !initial_synced && failures < STARTUP_FAILURES_BEFORE_NO_DATA {
                            // Cold start (network or PAC not up yet): still "checking", not an error.
                            crate::tray::update_tray_checking(&watcher_handle);
                        } else {
                            crate::tray::update_tray_no_data(
                                &watcher_handle,
                                last_checked.as_deref(),
                            );
                        }
                    }
                    let delay = if !initial_synced {
                        Duration::from_millis(1200)
                    } else {
                        Duration::from_secs(10)
                    };
                    wait_next_tray_tick(delay, &mut gate_rx, &mut kill_rx).await;
                }
            }
        }
    });
}

/// Background periodic GitHub update checker (after 20s, then every 60m).
/// Strictly respects user opt-out setting (auto_update_enabled).
pub(super) fn spawn_update_checker(app: &tauri::App, app_state: &state::AppState) {
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

/// Pure trigger predicate for the Windows `CoworkVMService` guard watcher.
///
/// Triggers `\Zastava\CoworkVMServiceManualGuard` only when OS effects are enabled, the
/// platform supports the guard, the Task Scheduler task is installed, and either:
/// - `start_type == Some(2)` (Store update reset service startup back to Automatic), OR
/// - `service_running && !claude_process_running` (service is running while Claude is closed).
pub(crate) fn should_trigger_cowork_guard(
    status: &cowork_guard::CoworkGuardStatus,
    claude_process_running: bool,
    os_effects_enabled: bool,
) -> bool {
    if !os_effects_enabled || !status.supported || !status.task_installed {
        return false;
    }
    status.start_type == Some(2) || (status.service_running && !claude_process_running)
}

fn is_claude_process_running() -> bool {
    if !crate::sysproxy::os_effects_enabled() {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        crate::win_native::process::is_process_running_by_name("claude.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Periodically verifies Windows `CoworkVMService` Start type / macOS AI helpers every 60s.
/// If a Windows Store update resets `CoworkVMService\Start` back to `2` (Automatic) or the
/// service is left running with Claude closed while the Task Scheduler guard is installed,
/// triggers the guard task automatically and notifies the UI.
pub(super) fn spawn_cowork_guard_watcher(app: &tauri::App) {
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            if let Ok(mut status) =
                tokio::task::spawn_blocking(cowork_guard::get_cowork_guard_status).await
            {
                let os_effects = crate::sysproxy::os_effects_enabled();
                let claude_running = if os_effects
                    && status.supported
                    && status.service_present
                    && status.task_installed
                    && status.start_type != Some(2)
                    && status.service_running
                {
                    tokio::task::spawn_blocking(is_claude_process_running)
                        .await
                        .unwrap_or(false)
                } else {
                    false
                };
                if should_trigger_cowork_guard(&status, claude_running, os_effects) {
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

/// Periodically triggers Data Bunker automatic snapshot creation (default every 24h)
/// off the main thread when `bunker.auto_backup_enabled == true`.
pub(super) fn spawn_bunker_scheduler(app: &tauri::App, app_state: &state::AppState) {
    let handle = app.handle().clone();
    let bunker_state = app_state.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            if sysproxy::os_effects_enabled()
                && let (Ok(data_dir), Some(home_dir)) = (
                    handle.path().app_data_dir(),
                    auditor::claude_exporter::get_home_dir(),
                )
            {
                let settings = bunker_state.get_data().await.bunker;
                let now = auditor::network::current_timestamp();
                if let Ok(Ok(Some(res))) = tokio::task::spawn_blocking(move || {
                    bunker::scheduler::run_scheduled_backup_if_due(
                        &data_dir, &home_dir, &settings, now,
                    )
                })
                .await
                {
                    {
                        let mut w = bunker_state.write().await;
                        w.bunker.last_backup_at = Some(res.snapshot.created_at);
                        w.bunker.last_backup_size_bytes = Some(res.snapshot.total_bytes);
                    }
                    let _ = bunker_state.save_async().await;
                    let _ = handle.emit("bunker://backup-finished", &res);
                }
            }
            tokio::time::sleep(Duration::from_secs(900)).await;
        }
    });
}

/// Non-blocking startup refresh for routes that carry a `sub_url` subscription metadata link.
pub(super) fn spawn_route_subscription_refresher(
    app: &tauri::App,
    risk_auditor: &auditor::Auditor,
    app_state: &state::AppState,
) {
    let handle = app.handle().clone();
    let auditor = risk_auditor.clone();
    let state = app_state.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if commands::routes_sub::refresh_all_route_subscriptions_bg(&state, &auditor).await {
            let _ = handle.emit("routes://updated", ());
        }
    });
}

#[cfg(test)]
#[path = "watchers_tests.rs"]
mod tests;
