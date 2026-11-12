//! System proxy (PAC), CLI/IDE protection, timezone sync and forced OS cleanup commands.

use crate::sanctions::is_sanctioned_or_blocked_country;
use crate::{auditor, proxy, state, sysproxy};

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
        let state_data = state.get_data().await;
        let tz = if let Some(ref synced) = state_data.synced_ai_timezone {
            Some(synced.clone())
        } else {
            if let Ok(tel) = auditor
                .resolve_for_provider(auditor::ProviderId::Anthropic, &state, false)
                .await
            {
                if !is_sanctioned_or_blocked_country(&tel.country_code) && tel.timezone.is_some() {
                    let detected = tel.timezone.unwrap();
                    let _ = state.set_synced_ai_timezone(Some(detected.clone())).await;
                    Some(detected)
                } else {
                    None
                }
            } else {
                None
            }
        };
        let _ = sysproxy::enable_cli_and_ide_protection_with_tz(&pac_url, tz.as_deref());
        Ok(true)
    } else {
        sysproxy::cleanup_all_persistent_settings();
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
    let state_data = state.get_data().await;
    let tz = if let Some(ref synced) = state_data.synced_ai_timezone {
        Some(synced.clone())
    } else {
        if let Ok(tel) = auditor
            .resolve_for_provider(auditor::ProviderId::Anthropic, &state, false)
            .await
        {
            if !is_sanctioned_or_blocked_country(&tel.country_code) && tel.timezone.is_some() {
                let detected = tel.timezone.unwrap();
                let _ = state.set_synced_ai_timezone(Some(detected.clone())).await;
                Some(detected)
            } else {
                None
            }
        } else {
            None
        }
    };
    Ok(sysproxy::enable_cli_and_ide_protection_with_tz(&addr, tz.as_deref()))
}

#[tauri::command]
pub fn check_cli_protection_status() -> Result<bool, String> {
    Ok(sysproxy::is_cli_protection_enabled())
}

#[tauri::command]
pub fn disable_cli_protection() -> Result<bool, String> {
    sysproxy::disable_cli_protection();
    Ok(false)
}

#[tauri::command]
pub async fn sync_ai_agents_timezone(
    state: tauri::State<'_, state::AppState>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
    timezone: String,
) -> Result<String, String> {
    let tz_clean = timezone.trim().to_string();
    if tz_clean.is_empty() {
        return Err("Указан пустой часовой пояс".to_string());
    }

    state
        .set_synced_ai_timezone(Some(tz_clean.clone()))
        .await
        .map_err(|e| e.to_string())?;

    let addr = proxy_manager.server.bound_addr.to_string();
    let report = sysproxy::enable_cli_and_ide_protection_with_tz(&addr, Some(&tz_clean));

    let targets = if report.configured_targets.is_empty() {
        "терминала и редакторов кода".to_string()
    } else {
        report.configured_targets.join(", ")
    };

    Ok(format!(
        "Таймзона {} и английская локаль (en_US.UTF-8) синхронизированы для: {}.",
        tz_clean, targets
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
        return Err("Часть системных настроек сейчас восстановить нельзя (например, активный VPN \
держит временные настройки DNS, или журнал занят). Они сохранены и будут восстановлены при \
следующем запуске Заставы или после отключения VPN."
            .to_string());
    }
    Ok(sysproxy::cleaned_components())
}
