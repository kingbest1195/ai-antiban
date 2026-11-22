//! System proxy (PAC), CLI/IDE protection, timezone sync and forced OS cleanup commands.

mod helpers;

use crate::{auditor, os_tz, proxy, state, sysproxy};
use helpers::{
    PARTIAL_RESTORE_TEXT, TEMP_DNS_DEFERRED_TEXT, enable_sysproxy_with, read_cli_settings,
    resolve_os_tz_target, sync_tz_for,
};
use std::collections::HashMap;
use std::time::Duration;

pub use crate::diagnostics::{
    DiagnosticBundle, DiagnosticCheckSummary, DiagnosticGatewayStats, DiagnosticProviderAudit,
    DiagnosticProviderRoute, ProtectionChangePreviewItem,
};
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use crate::diagnostics::{
    build_error_diagnostics_report, build_protection_changes_preview,
    build_sanitized_diagnostic_bundle, mask_ip_address, parse_windows_ipconfig_snapshot,
    sanitize_diagnostic_text,
};
#[cfg_attr(not(test), allow(unused_imports))]
use crate::{diagnostics, routing};

pub(crate) async fn restore_os_tz_on_disable_with(
    state: &state::AppState,
    data_dir: Option<&std::path::Path>,
    restore_fn: impl FnOnce(&std::path::Path) -> Result<bool, String> + Send + 'static,
) -> Result<bool, String> {
    if state.get_keep_system_tz_on_exit().await {
        return Ok(false);
    }
    let Some(dir) = data_dir.map(std::path::Path::to_path_buf) else {
        return Ok(false);
    };
    tokio::task::spawn_blocking(move || restore_fn(&dir))
        .await
        .map_err(|e| e.to_string())?
}

/// Shared system-proxy toggle used by both the `toggle_sysproxy` Tauri command and the tray menu.
pub(crate) async fn toggle_sysproxy_shared(
    enable: bool,
    state: &state::AppState,
    auditor: &auditor::Auditor,
    proxy_manager: &proxy::ProxyManager,
    app: &tauri::AppHandle,
) -> Result<bool, String> {
    if enable {
        let enabled = enable_sysproxy_with(false, state, auditor, proxy_manager).await?;
        if enabled {
            crate::tray::update_tray_checking(app);
        }
        auditor.set_protection_flags(crate::commands::audit::read_runtime_protection_flags().await);
        Ok(enabled)
    } else {
        crate::startup::note_user_off(app);
        let dir = os_tz::resolve_app_data_dir(Some(app));
        match restore_os_tz_on_disable_with(state, dir.as_deref(), |d| {
            os_tz::restore_if_synced_on_disable(d)
        })
        .await
        {
            Ok(true) => {
                eprintln!("Застава: системный часовой пояс ОС восстановлен при выключении защиты.");
            }
            Ok(false) => {}
            Err(err) => {
                crate::diagnostics::record("cmd:os_tz_restore_on_disable", &err);
                eprintln!(
                    "Застава: не удалось восстановить часовой пояс ОС при выключении защиты: {err}"
                );
            }
        }
        let report = sysproxy::cleanup_all_persistent_settings();
        proxy_manager.coverage.invalidate_facts();
        auditor.set_protection_flags(crate::commands::audit::read_runtime_protection_flags().await);
        if !sysproxy::is_sysproxy_active() {
            crate::tray::update_tray_protection_off(app);
        }
        if report.has_failures() {
            crate::diagnostics::record(
                "cmd:toggle_sysproxy_off",
                &format!("partial restore: {}", report.summary()),
            );
            if report.is_only_vpn_dns_deferred() {
                return Err(TEMP_DNS_DEFERRED_TEXT.to_string());
            }
            return Err(PARTIAL_RESTORE_TEXT.to_string());
        }
        Ok(false)
    }
}

#[tauri::command]
pub async fn toggle_sysproxy(
    enable: bool,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    toggle_sysproxy_shared(enable, &state, &auditor, &proxy_manager, &app).await
}

/// User-triggered retry of enabling the macOS system proxy via administrator authorization
/// (`osascript ... with administrator privileges`) after `toggle_sysproxy(true)` failed with
/// `ADMIN_AUTH_REQUIRED:`. On non-macOS systems this delegates to normal `toggle_sysproxy(true)`.
#[tauri::command]
pub async fn toggle_sysproxy_privileged(
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<bool, String> {
    let enabled =
        enable_sysproxy_with(cfg!(target_os = "macos"), &state, &auditor, &proxy_manager).await?;
    auditor.set_protection_flags(crate::commands::audit::read_runtime_protection_flags().await);
    Ok(enabled)
}

#[tauri::command]
pub async fn enable_cli_protection(
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<sysproxy::CliProtectionReport, String> {
    let addr = proxy_manager.server.bound_addr.to_string();
    let data = state.get_data().await;
    let tz = sync_tz_for(data.sync_ai_tz_enabled, &state, &auditor).await;
    let report = sysproxy::enable_cli_and_ide_protection_with(&addr, data.cli_mode, tz.as_deref());
    if !report.enabled {
        return Err(report.error.unwrap_or_else(|| {
            "Защита CLI/IDE не включена: журнал настроек недоступен. Системные настройки не менялись."
                .to_string()
        }));
    }
    auditor.resolver.check_cache().os.clear().await;
    auditor.set_protection_flags(crate::commands::audit::read_runtime_protection_flags().await);
    Ok(report)
}

/// Reads shell profiles and IDE files: off the main thread, so a slow disk never stalls the window.
#[tauri::command]
pub async fn check_cli_protection_status() -> Result<bool, String> {
    tokio::task::spawn_blocking(sysproxy::is_cli_protection_enabled)
        .await
        .map_err(|e| format!("cli status task failed: {e}"))
}

#[tauri::command]
pub async fn disable_cli_protection(
    auditor: tauri::State<'_, auditor::Auditor>,
) -> Result<bool, String> {
    let report = tokio::task::spawn_blocking(sysproxy::disable_cli_protection)
        .await
        .map_err(|e| format!("cli disable task failed: {e}"))?;
    if report.has_failures() {
        return Err(PARTIAL_RESTORE_TEXT.to_string());
    }
    auditor.resolver.check_cache().os.clear().await;
    auditor.set_protection_flags(crate::commands::audit::read_runtime_protection_flags().await);
    Ok(false)
}

/// The settings of the CLI protection and of the time zone / locale switch, as the interface
/// shows them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CliSettings {
    /// `"ai_only"` (default) or `"global_terminal"`.
    pub cli_mode: state::CliMode,
    /// The independent switch "replace the time zone and locale for the AI tools".
    pub sync_ai_tz_enabled: bool,
    /// Whether the CLI / IDE (proxy) protection is on.
    pub cli_protection_enabled: bool,
    /// The stored zone (IANA name) the switch applies; `None` while none is known.
    pub synced_ai_timezone: Option<String>,
}

/// Current CLI mode, time zone switch, protection status and stored zone.
#[tauri::command]
pub async fn get_cli_settings(
    state: tauri::State<'_, state::AppState>,
) -> Result<CliSettings, String> {
    read_cli_settings(&state).await
}

/// Switches the CLI mode and applies it at once: `global_terminal` -> `ai_only` gives the shell
/// profile blocks back (through the journal; 2.0.0 blocks by their exact markers), `ai_only` ->
/// `global_terminal` writes them. Returns the settings after the change; an error (journal busy)
/// leaves the mode as it was.
#[tauri::command]
pub async fn set_cli_mode(
    mode: state::CliMode,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
) -> Result<CliSettings, String> {
    let tz = state.effective_sync_tz().await;
    let applied = sysproxy::apply_cli_settings(mode, tz.as_deref());
    if let Some(err) = applied.error {
        return Err(err);
    }
    state.set_cli_mode(mode).await.map_err(|e| e.to_string())?;
    auditor.resolver.check_cache().os.clear().await;
    read_cli_settings(&state).await
}

/// Flips the independent time zone / locale switch and applies it at once: on writes `TZ`, `LANG`,
/// `LC_TIME` (the zone is detected once when none is stored), off gives them back through the
/// journal. The proxy protection is not touched. Returns the settings after the change.
#[tauri::command]
pub async fn set_sync_ai_tz_enabled(
    enabled: bool,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
) -> Result<CliSettings, String> {
    let tz = sync_tz_for(enabled, &state, &auditor).await;
    let mode = state.get_cli_mode().await;
    let applied = sysproxy::apply_cli_settings(mode, tz.as_deref());
    if let Some(err) = applied.error {
        return Err(err);
    }
    state
        .set_sync_ai_tz_enabled(enabled)
        .await
        .map_err(|e| e.to_string())?;
    auditor.resolver.check_cache().os.clear().await;
    read_cli_settings(&state).await
}

/// Returns whether Zastava keeps the synced OS system timezone across exit, update, and disable.
#[tauri::command]
pub async fn get_keep_system_tz_on_exit(
    state: tauri::State<'_, state::AppState>,
) -> Result<bool, String> {
    Ok(state.get_keep_system_tz_on_exit().await)
}

/// Updates `keep_system_tz_on_exit` in persistent state and in the lock-free `os_tz` cache.
#[tauri::command]
pub async fn set_keep_system_tz_on_exit(
    enabled: bool,
    state: tauri::State<'_, state::AppState>,
) -> Result<bool, String> {
    state
        .set_keep_system_tz_on_exit(enabled)
        .await
        .map_err(|e| e.to_string())?;
    Ok(enabled)
}

/// Stores the zone and, while the time zone switch is on, writes only the time zone / locale keys
/// (`TZ`, `LANG`, `LC_TIME`). It never turns the proxy protection on.
#[tauri::command]
pub async fn sync_ai_agents_timezone(
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    timezone: String,
) -> Result<String, String> {
    let tz_clean = timezone.trim();
    if tz_clean.is_empty() {
        return Err("Указан пустой часовой пояс".to_string());
    }
    let Some(zone) = sysproxy::sanitize_timezone(tz_clean) else {
        return Err("Указан недопустимый часовой пояс".to_string());
    };

    state
        .set_synced_ai_timezone(Some(zone.clone()))
        .await
        .map_err(|e| e.to_string())?;
    auditor.resolver.check_cache().os.clear().await;

    let data = state.get_data().await;
    if !data.sync_ai_tz_enabled {
        return Ok(format!(
            "Часовой пояс {zone} сохранён. Подмена часового пояса и локали выключена: включите её, чтобы применить."
        ));
    }
    let applied = sysproxy::apply_cli_settings(data.cli_mode, Some(&zone));
    if let Some(err) = applied.error {
        return Err(err);
    }
    auditor.resolver.check_cache().os.clear().await;

    let targets = if applied.targets.is_empty() {
        "терминала и редакторов кода".to_string()
    } else {
        applied.targets.join(", ")
    };

    Ok(format!(
        "Таймзона {zone} и английская локаль (en_US.UTF-8) синхронизированы для: {targets}."
    ))
}

#[tauri::command]
pub async fn sync_os_timezone_cmd(
    app: tauri::AppHandle,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    target_tz: Option<String>,
) -> Result<os_tz::OsTzSyncStatus, String> {
    let resolved_tz = resolve_os_tz_target(&state, &auditor, target_tz).await?;
    let data_dir = os_tz::resolve_app_data_dir(Some(&app))
        .ok_or_else(|| "Не удалось определить каталог данных приложения.".to_string())?;

    let status =
        tokio::task::spawn_blocking(move || os_tz::sync_os_timezone(&data_dir, &resolved_tz))
            .await
            .map_err(|e| format!("os_tz sync task failed: {e}"))??;
    auditor.resolver.check_cache().os.clear().await;

    Ok(status)
}

#[tauri::command]
pub async fn restore_os_timezone_cmd(
    app: tauri::AppHandle,
    auditor: tauri::State<'_, auditor::Auditor>,
) -> Result<os_tz::OsTzSyncStatus, String> {
    let data_dir = os_tz::resolve_app_data_dir(Some(&app))
        .ok_or_else(|| "Не удалось определить каталог данных приложения.".to_string())?;

    let status = tokio::task::spawn_blocking(move || os_tz::restore_os_timezone(&data_dir))
        .await
        .map_err(|e| format!("os_tz restore task failed: {e}"))??;
    auditor.resolver.check_cache().os.clear().await;
    Ok(status)
}

#[tauri::command]
pub async fn get_os_timezone_sync_status_cmd(
    app: tauri::AppHandle,
) -> Result<os_tz::OsTzSyncStatus, String> {
    let data_dir = os_tz::resolve_app_data_dir(Some(&app))
        .ok_or_else(|| "Не удалось определить каталог данных приложения.".to_string())?;

    tokio::task::spawn_blocking(move || os_tz::get_os_timezone_sync_status(&data_dir))
        .await
        .map_err(|e| format!("os_tz status task failed: {e}"))?
}

#[tauri::command]
pub fn open_os_datetime_settings_cmd() -> Result<(), String> {
    sysproxy::open_os_datetime_settings()
}

#[tauri::command]
pub fn open_os_network_settings_cmd() -> Result<(), String> {
    sysproxy::open_os_network_settings()
}

#[tauri::command]
pub fn get_sysproxy_status() -> Result<bool, String> {
    Ok(sysproxy::is_sysproxy_active())
}

#[tauri::command]
pub fn force_clean_os_proxy_cmd(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    crate::startup::note_user_off(&app);
    let report = sysproxy::cleanup_all_persistent_settings();
    if report.has_failures() {
        crate::diagnostics::record(
            "cmd:force_clean_os_proxy",
            &format!("partial restore: {}", report.summary()),
        );
        if report.is_only_vpn_dns_deferred() {
            return Err(TEMP_DNS_DEFERRED_TEXT.to_string());
        }
        // Nothing is lost: what could not be restored stays recorded and is finished later.
        return Err(PARTIAL_RESTORE_TEXT.to_string());
    }
    Ok(sysproxy::cleaned_components())
}

/// Builds a sanitized, copyable diagnostic bundle when the user clicks "Скопировать лог" on an error.
#[tauri::command]
pub async fn get_error_diagnostics(
    error_title: Option<String>,
    error_message: Option<String>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<String, String> {
    let chained_proxy_set = sysproxy::get_chained_proxy().is_some();
    let os_lines = tokio::task::spawn_blocking(move || {
        let mut lines = sysproxy::platform::collect_os_diagnostic_snapshot();
        if !chained_proxy_set {
            lines.extend(diagnostics::collect_unproxied_os_network_snapshot());
        }
        lines
    })
    .await
    .unwrap_or_default();
    let entries = diagnostics::dump();
    Ok(diagnostics::build_error_diagnostics_report(
        error_title.as_deref(),
        error_message.as_deref(),
        proxy_manager.server.bound_addr.port(),
        &os_lines,
        &entries,
    ))
}

/// Writes diagnostic or error log text directly to the OS clipboard natively (immune to WebView async activation limits).
#[tauri::command]
pub async fn copy_text_to_clipboard(text: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || sysproxy::platform::write_text_to_clipboard(&text))
        .await
        .map_err(|e| format!("Clipboard task failed: {e}"))?
}

/// Exports a sanitized diagnostic bundle as pretty-printed JSON for support/issue reports.
/// Masks all IPv4/IPv6 addresses and strips all proxy URLs, credentials, and `zastava://` keys.
#[tauri::command]
pub async fn export_diagnostic_bundle_cmd(
    reports: Option<HashMap<String, auditor::RiskReport>>,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<String, String> {
    let data = state.get_data().await;
    let stats = state.get_gateway_stats().await;
    let sysproxy_enabled = sysproxy::is_sysproxy_active();
    let (cli_protection_enabled, os_lines) = tokio::task::spawn_blocking(|| {
        (
            sysproxy::is_cli_protection_enabled(),
            sysproxy::platform::collect_os_diagnostic_snapshot(),
        )
    })
    .await
    .map_err(|e| format!("diagnostic probe task failed: {e}"))?;

    let os_version = diagnostics::extract_os_version_from_snapshot(&os_lines);
    let mut provider_reports: HashMap<String, Result<auditor::RiskReport, String>> = HashMap::new();

    for provider in state::KNOWN_PROVIDERS {
        if let Some(provided) = reports.as_ref().and_then(|m| m.get(provider)) {
            provider_reports.insert(provider.to_string(), Ok(provided.clone()));
            continue;
        }
        if let Some(pid) = auditor::ProviderId::from_id(provider) {
            let res = match tokio::time::timeout(
                Duration::from_millis(2500),
                auditor.evaluate_all(pid, &state, false),
            )
            .await
            {
                Ok(inner) => inner,
                Err(_) => Err("audit evaluation timed out".to_string()),
            };
            provider_reports.insert(provider.to_string(), res);
        }
    }

    let diag_entries = diagnostics::dump();
    let bundle = diagnostics::build_sanitized_diagnostic_bundle(
        &data,
        &stats,
        &provider_reports,
        sysproxy_enabled,
        cli_protection_enabled,
        proxy_manager.server.bound_addr.port(),
        os_version,
        &diag_entries,
    );
    serde_json::to_string_pretty(&bundle)
        .map_err(|e| format!("Failed to serialize diagnostic bundle: {e}"))
}

/// Returns a structured preview of all system, browser, shell RC, CLI, and IDE settings
/// Zastava configures or monitors (all Zastava-managed changes are journaled and reversible).
#[tauri::command]
pub async fn preview_protection_changes_cmd(
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
    state: tauri::State<'_, state::AppState>,
) -> Result<Vec<ProtectionChangePreviewItem>, String> {
    let data = state.get_data().await;
    let detected_ides = tokio::task::spawn_blocking(sysproxy::candidate_ide_settings_paths)
        .await
        .unwrap_or_default();
    Ok(diagnostics::build_protection_changes_preview(
        proxy_manager.server.bound_addr.port(),
        data.cli_mode,
        data.sync_ai_tz_enabled,
        &detected_ides,
    ))
}

#[cfg(test)]
#[path = "../sysproxy_tests.rs"]
mod tests;
