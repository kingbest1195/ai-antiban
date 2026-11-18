//! Background watchers: tray status polling, GitHub update check, and CoworkVMService guard.

use crate::tray::update_tray_from_report;
use crate::{auditor, commands, cowork_guard, proxy, state, updater};
use std::sync::Arc;
use std::time::Duration;
use tauri::Emitter;

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
        if let Ok(mut other_report) = ctx.auditor.evaluate_all(other_pid, ctx.state, false).await {
            let other_pinned = commands::audit::is_ip_pinned_for_state(
                ctx.st,
                other_pid,
                &other_report.telemetry.ip,
            );
            auditor::history::apply_pinned_travel_grace(&mut other_report, other_pinned);
            let _ = ctx.handle.emit("audit://refreshed", &other_report);
            if update_tray_on_worse
                && !proxy::guard::report_allowed_for_state(&other_report, ctx.st, false)
                && status_rank(other_report.overall_status) > status_rank(tray_report.overall_status)
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
                    let is_pinned =
                        commands::audit::is_ip_pinned_for_state(&st, pid, &report.telemetry.ip);
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

                    let sibling_ctx = SiblingRefreshCtx {
                        handle: &watcher_handle,
                        auditor: &watcher_auditor,
                        state: &watcher_state,
                        guard: &watcher_guard,
                        st: &st,
                        enabled_pids: &enabled_pids,
                        has_blocked,
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
                        refresh_sibling_unrouted_providers(
                            &sibling_ctx,
                            &mut tray_report,
                            &mut tray_is_pinned,
                            false,
                        )
                        .await;
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

/// Periodically verifies Windows `CoworkVMService` Start type / macOS AI helpers every 60s.
/// If a Windows Store update resets `CoworkVMService\Start` back to `2` (Automatic) while the
/// Task Scheduler guard is installed, triggers the guard task automatically and notifies the UI.
pub(super) fn spawn_cowork_guard_watcher(app: &tauri::App) {
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
