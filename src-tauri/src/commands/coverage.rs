//! Coverage snapshot inspection commands.

use crate::proxy::coverage::{CoverageEnv, JETBRAINS_XML_CONFIRMED, PacSource};
use crate::proxy::{CoverageSnapshot, ProxyManager};
use crate::state::{AppState, CliMode};
use crate::sysproxy;
use crate::sysproxy::FileCtx;
use crate::sysproxy::browser_policies::RealPolicyStore;
use crate::sysproxy::platform::RealPlatform;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};

static RELAUNCH_BROWSERS_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

struct RelaunchInFlightGuard;

impl Drop for RelaunchInFlightGuard {
    fn drop(&mut self) {
        RELAUNCH_BROWSERS_IN_FLIGHT.store(false, Ordering::SeqCst);
    }
}

/// Response returned by [`relaunch_browsers_with_pac_cmd`].
#[derive(Debug, Clone, Serialize)]
pub struct RelaunchBrowsersResult {
    pub restarted: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<String>,
    pub needs_automation_permission: bool,
    pub unsupported: bool,
    pub snapshot: CoverageSnapshot,
}

/// Reads the facts (OS, files) on the blocking pool and builds the snapshot.
pub(super) async fn build_snapshot(
    proxy_manager: &ProxyManager,
    cli_mode: CliMode,
    force: bool,
) -> Result<CoverageSnapshot, String> {
    let coverage = std::sync::Arc::clone(&proxy_manager.coverage);
    coverage.set_cli_mode(cli_mode);
    tokio::task::spawn_blocking(move || {
        if sysproxy::reconcile_browser_pac_prefs(None) {
            coverage.invalidate_facts();
        }
        let files = FileCtx::real();
        let env = CoverageEnv {
            platform: &RealPlatform,
            policy_store: &RealPolicyStore,
            files: files.as_ref(),
            pac_source: PacSource::current(),
            sysproxy_enabled: sysproxy::is_sysproxy_active(),
            cli_protection_enabled: sysproxy::is_cli_protection_enabled(),
            chained_proxy: sysproxy::get_chained_proxy(),
            jetbrains_xml_confirmed: JETBRAINS_XML_CONFIRMED,
        };
        coverage.snapshot(&env, force)
    })
    .await
    .map_err(|e| format!("coverage task failed: {e}"))
}

/// Returns current network protection coverage across installed applications and active socket
/// traffic. Configuration facts read from the OS are reused for a few seconds.
#[tauri::command]
pub async fn get_coverage_snapshot(
    proxy_manager: tauri::State<'_, ProxyManager>,
    state: tauri::State<'_, AppState>,
) -> Result<CoverageSnapshot, String> {
    build_snapshot(&proxy_manager, state.get_cli_mode().await, false).await
}

/// Forced re-check: reads the OS and the files again right now (no waiting for the cache), then
/// returns the fresh snapshot.
#[tauri::command]
pub async fn recheck_coverage(
    proxy_manager: tauri::State<'_, ProxyManager>,
    state: tauri::State<'_, AppState>,
) -> Result<CoverageSnapshot, String> {
    build_snapshot(&proxy_manager, state.get_cli_mode().await, true).await
}

/// Force-applies managed browser policies (QUIC off, DoH off, and Chromium `ProxyMode`/`ProxyPacUrl`
/// pointing at Zastava's live gateway PAC URL) and invalidates cached coverage facts.
#[tauri::command]
pub async fn reapply_browser_policies_cmd(
    proxy_manager: tauri::State<'_, ProxyManager>,
) -> Result<sysproxy::PolicyApplyReport, String> {
    let pac_url = format!(
        "http://{}/proxy.pac",
        proxy_manager
            .coverage
            .gateway_addr()
            .unwrap_or(proxy_manager.server.bound_addr)
    );
    let report =
        tokio::task::spawn_blocking(move || sysproxy::reapply_browser_policies(Some(&pac_url)))
            .await
            .map_err(|e| format!("reapply_browser_policies task failed: {e}"))??;
    proxy_manager.coverage.invalidate_facts();
    Ok(report)
}

/// Gracefully quits running Chromium browsers that still need PAC, injects `"proxy"` into all
/// their profile `Preferences` files (journaled), relaunches them with `--proxy-pac-url=<pac_url>`,
/// and returns the updated coverage snapshot plus restarted browser names.
#[tauri::command]
pub async fn relaunch_browsers_with_pac_cmd(
    _app: tauri::AppHandle,
    proxy_manager: tauri::State<'_, ProxyManager>,
    state: tauri::State<'_, AppState>,
) -> Result<RelaunchBrowsersResult, String> {
    if RELAUNCH_BROWSERS_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("Перезапуск браузеров уже выполняется".to_string());
    }
    let _guard = RelaunchInFlightGuard;

    let pac_url = format!(
        "http://{}/proxy.pac",
        proxy_manager
            .coverage
            .gateway_addr()
            .unwrap_or(proxy_manager.server.bound_addr)
    );
    let summary =
        tokio::task::spawn_blocking(move || sysproxy::relaunch_browsers_with_pac(&pac_url))
            .await
            .map_err(|e| format!("relaunch_browsers_with_pac task failed: {e}"))??;

    proxy_manager.coverage.invalidate_facts();
    let snapshot = build_snapshot(&proxy_manager, state.get_cli_mode().await, true).await?;

    Ok(RelaunchBrowsersResult {
        restarted: summary.restarted,
        skipped: summary.skipped,
        failed: summary.failed,
        needs_automation_permission: summary.needs_automation_permission,
        unsupported: summary.unsupported,
        snapshot,
    })
}
