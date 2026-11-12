//! Coverage snapshot inspection commands.

use crate::proxy::coverage::{CoverageEnv, JETBRAINS_XML_CONFIRMED, PacSource};
use crate::proxy::{CoverageSnapshot, ProxyManager};
use crate::sysproxy;
use crate::sysproxy::FileCtx;
use crate::sysproxy::platform::RealPlatform;

/// Reads the facts (OS, files) on the blocking pool and builds the snapshot.
async fn build_snapshot(
    proxy_manager: &ProxyManager,
    force: bool,
) -> Result<CoverageSnapshot, String> {
    let coverage = std::sync::Arc::clone(&proxy_manager.coverage);
    tokio::task::spawn_blocking(move || {
        let files = FileCtx::real();
        let env = CoverageEnv {
            platform: &RealPlatform,
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
) -> Result<CoverageSnapshot, String> {
    build_snapshot(&proxy_manager, false).await
}

/// Forced re-check: reads the OS and the files again right now (no waiting for the cache), then
/// returns the fresh snapshot.
#[tauri::command]
pub async fn recheck_coverage(
    proxy_manager: tauri::State<'_, ProxyManager>,
) -> Result<CoverageSnapshot, String> {
    build_snapshot(&proxy_manager, true).await
}
