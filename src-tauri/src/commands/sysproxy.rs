//! System proxy (PAC), CLI/IDE protection, timezone sync and forced OS cleanup commands.

use crate::sanctions::is_sanctioned_or_blocked_country;
use crate::{auditor, proxy, state, sysproxy};

/// Text for a failed (partial) restore: nothing is lost, the records stay in the journal.
const PARTIAL_RESTORE_TEXT: &str = "Часть системных настроек сейчас восстановить нельзя (например, активный VPN \
держит временные настройки DNS, или журнал занят). Они сохранены и будут восстановлены при \
следующем запуске Заставы или после отключения VPN.";

/// The zone to put into the AI tools' environment, for `enabled == true`: the stored one, or - when
/// none is stored - the zone of the exit IP of the Anthropic provider (kept in the state), unless
/// the exit country is blocked. `None` when the switch is off or no zone is known.
async fn sync_tz_for(
    enabled: bool,
    state: &state::AppState,
    auditor: &auditor::Auditor,
) -> Option<String> {
    if !enabled {
        return None;
    }
    if let Some(tz) = state.get_data().await.synced_ai_timezone.as_deref()
        && let Some(clean) = sysproxy::sanitize_timezone(tz)
    {
        return Some(clean);
    }
    let tel = auditor
        .resolve_for_provider(auditor::ProviderId::Anthropic, state, false)
        .await
        .ok()?;
    if is_sanctioned_or_blocked_country(&tel.country_code) {
        return None;
    }
    let detected = tel
        .timezone
        .as_deref()
        .and_then(sysproxy::sanitize_timezone)?;
    let _ = state.set_synced_ai_timezone(Some(detected.clone())).await;
    Some(detected)
}

#[tauri::command]
pub async fn toggle_sysproxy(
    enable: bool,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<bool, String> {
    if enable {
        let pac_url = format!("http://{}/proxy.pac", proxy_manager.server.bound_addr);
        sysproxy::enable_sysproxy(&pac_url)?;
        let data = state.get_data().await;
        let tz = sync_tz_for(data.sync_ai_tz_enabled, &state, &auditor).await;
        let report =
            sysproxy::enable_cli_and_ide_protection_with(&pac_url, data.cli_mode, tz.as_deref());
        if let Some(err) = report.error {
            eprintln!("Застава: {err}");
        }
        Ok(true)
    } else {
        let report = sysproxy::cleanup_all_persistent_settings();
        if report.has_failures() {
            return Err(PARTIAL_RESTORE_TEXT.to_string());
        }
        Ok(false)
    }
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
    Ok(report)
}

#[tauri::command]
pub fn check_cli_protection_status() -> Result<bool, String> {
    Ok(sysproxy::is_cli_protection_enabled())
}

#[tauri::command]
pub fn disable_cli_protection() -> Result<bool, String> {
    let report = sysproxy::disable_cli_protection();
    if report.has_failures() {
        return Err(PARTIAL_RESTORE_TEXT.to_string());
    }
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

async fn read_cli_settings(state: &state::AppState) -> Result<CliSettings, String> {
    let data = state.get_data().await;
    let enabled = tokio::task::spawn_blocking(sysproxy::is_cli_protection_enabled)
        .await
        .map_err(|e| format!("cli status task failed: {e}"))?;
    Ok(CliSettings {
        cli_mode: data.cli_mode,
        sync_ai_tz_enabled: data.sync_ai_tz_enabled,
        cli_protection_enabled: enabled,
        synced_ai_timezone: data.synced_ai_timezone,
    })
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
) -> Result<CliSettings, String> {
    let tz = state.effective_sync_tz().await;
    let applied = sysproxy::apply_cli_settings(mode, tz.as_deref());
    if let Some(err) = applied.error {
        return Err(err);
    }
    state.set_cli_mode(mode).await.map_err(|e| e.to_string())?;
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
    read_cli_settings(&state).await
}

/// Stores the zone and, while the time zone switch is on, writes only the time zone / locale keys
/// (`TZ`, `LANG`, `LC_TIME`). It never turns the proxy protection on.
#[tauri::command]
pub async fn sync_ai_agents_timezone(
    state: tauri::State<'_, state::AppState>,
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
pub fn open_os_datetime_settings_cmd() -> Result<(), String> {
    sysproxy::open_os_datetime_settings()
}

#[tauri::command]
pub fn get_sysproxy_status() -> Result<bool, String> {
    Ok(sysproxy::is_sysproxy_active())
}

#[tauri::command]
pub fn force_clean_os_proxy_cmd() -> Result<Vec<String>, String> {
    let report = sysproxy::cleanup_all_persistent_settings();
    if report.has_failures() {
        // Nothing is lost: what could not be restored stays recorded and is finished later.
        return Err(PARTIAL_RESTORE_TEXT.to_string());
    }
    Ok(sysproxy::cleaned_components())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_settings_has_the_four_fields_the_interface_reads_in_snake_case() {
        let settings = CliSettings {
            cli_mode: state::CliMode::GlobalTerminal,
            sync_ai_tz_enabled: false,
            cli_protection_enabled: true,
            synced_ai_timezone: Some("Europe/Berlin".to_string()),
        };
        let json = serde_json::to_value(&settings).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "cli_mode": "global_terminal",
                "sync_ai_tz_enabled": false,
                "cli_protection_enabled": true,
                "synced_ai_timezone": "Europe/Berlin",
            })
        );
        let none = serde_json::to_value(CliSettings {
            cli_mode: state::CliMode::AiOnly,
            sync_ai_tz_enabled: true,
            cli_protection_enabled: false,
            synced_ai_timezone: None,
        })
        .unwrap();
        assert_eq!(none["cli_mode"], "ai_only");
        assert!(none["synced_ai_timezone"].is_null());
    }
}
