//! Internal helpers for system proxy, CLI/IDE protection, and timezone sync commands.

use super::CliSettings;
use crate::sanctions::is_sanctioned_or_blocked_country;
use crate::{auditor, os_tz, proxy, state, sysproxy};

/// Text for a failed (partial) restore: nothing is lost, the records stay in the journal.
pub(super) const PARTIAL_RESTORE_TEXT: &str = "Часть системных настроек сейчас восстановить нельзя (например, активный VPN \
держит временные настройки DNS, или журнал занят). Они сохранены и будут восстановлены при \
следующем запуске Заставы или после отключения VPN.";

/// Returned when turning protection off stopped all Zastava routing and the only un-restored
/// OS items are physical PAC/chain entries deferred solely because an active VPN holds temp DNS.
pub(super) const TEMP_DNS_DEFERRED_TEXT: &str = "TEMP_DNS_DEFERRED:Системный прокси вернётся к прежним \
настройкам после отключения VPN, чтобы не сбросить его DNS. Защита Заставы отключена.";

/// Detects a safe (non-sanctioned, non-RU/BY) IANA timezone across providers, falling back from
/// `Anthropic` to `Openai` and `Gemini` when earlier providers have no telemetry or timezone yet.
/// Returns `Err(blocked_cc)` only when no safe provider timezone was found and at least one
/// provider reported a sanctioned/blocked country.
pub(super) async fn detect_safe_provider_timezone(
    state: &state::AppState,
    auditor: &auditor::Auditor,
) -> Result<Option<String>, String> {
    const PROVIDERS: [auditor::ProviderId; 3] = [
        auditor::ProviderId::Anthropic,
        auditor::ProviderId::Openai,
        auditor::ProviderId::Gemini,
    ];
    let mut saw_blocked_country: Option<String> = None;
    for pid in PROVIDERS {
        let Ok(tel) = auditor.resolve_for_provider(pid, state, false).await else {
            continue;
        };
        if is_sanctioned_or_blocked_country(&tel.country_code) {
            saw_blocked_country.get_or_insert(tel.country_code);
            continue;
        }
        if let Some(raw_tz) = tel.timezone.as_deref()
            && let Some(clean) = sysproxy::sanitize_timezone(raw_tz)
            && os_tz::validate_iana_tz(&clean).is_ok()
            && !auditor::os_env::is_russian_or_belarusian_timezone(&clean)
        {
            return Ok(Some(clean));
        }
    }
    if let Some(cc) = saw_blocked_country {
        return Err(cc);
    }
    Ok(None)
}

/// The zone to put into the AI tools' environment, for `enabled == true`: the stored one, or - when
/// none is stored - the zone of the first healthy provider's exit IP (kept in the state), unless
/// the exit country is blocked. `None` when the switch is off or no zone is known.
pub(super) async fn sync_tz_for(
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
    let detected = detect_safe_provider_timezone(state, auditor)
        .await
        .ok()
        .flatten()?;
    let _ = state.set_synced_ai_timezone(Some(detected.clone())).await;
    Some(detected)
}

pub(super) async fn enable_sysproxy_with(
    privileged: bool,
    state: &state::AppState,
    auditor: &auditor::Auditor,
    proxy_manager: &proxy::ProxyManager,
) -> Result<bool, String> {
    let pac_url = format!("http://{}/proxy.pac", proxy_manager.server.bound_addr);
    let res = if privileged {
        sysproxy::enable_sysproxy_privileged(&pac_url)
    } else {
        sysproxy::enable_sysproxy(&pac_url)
    };
    match res {
        Ok(status) => {
            if status.os_pac_deferred {
                crate::diagnostics::record(
                    if privileged {
                        "cmd:toggle_sysproxy_privileged"
                    } else {
                        "cmd:toggle_sysproxy"
                    },
                    "enabled with os_pac_deferred=true (browser policies & CLI active)",
                );
            }
        }
        Err(err) => {
            crate::diagnostics::record(
                if privileged {
                    "cmd:toggle_sysproxy_privileged"
                } else {
                    "cmd:toggle_sysproxy"
                },
                &err,
            );
            return Err(err);
        }
    }
    let data = state.get_data().await;
    let tz = sync_tz_for(data.sync_ai_tz_enabled, state, auditor).await;
    let report =
        sysproxy::enable_cli_and_ide_protection_with(&pac_url, data.cli_mode, tz.as_deref());
    if let Some(err) = report.error {
        crate::diagnostics::record("cmd:cli_follow_up", &err);
    }
    proxy_manager.coverage.invalidate_facts();
    Ok(true)
}

pub(super) async fn read_cli_settings(state: &state::AppState) -> Result<CliSettings, String> {
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

pub(super) async fn resolve_os_tz_target(
    state: &state::AppState,
    auditor: &auditor::Auditor,
    target_tz: Option<String>,
) -> Result<String, String> {
    if let Some(raw) = target_tz
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return os_tz::validate_iana_tz(raw);
    }

    match detect_safe_provider_timezone(state, auditor).await {
        Ok(Some(clean)) => return Ok(clean),
        Err(cc) => {
            return Err(format!(
                "Текущий выходной IP относится к заблокированной стране ({cc}). Подключите безопасный VPN перед синхронизацией системного часового пояса."
            ));
        }
        Ok(None) => {}
    }

    if let Some(stored) = state.get_data().await.synced_ai_timezone
        && let Ok(clean) = os_tz::validate_iana_tz(&stored)
        && !auditor::os_env::is_russian_or_belarusian_timezone(&clean)
    {
        return Ok(clean);
    }

    Err("Не удалось определить часовой пояс выходного IP. Проверьте подключение или обновите аудит.".to_string())
}
