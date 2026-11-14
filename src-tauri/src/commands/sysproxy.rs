//! System proxy (PAC), CLI/IDE protection, timezone sync and forced OS cleanup commands.

use crate::sanctions::is_sanctioned_or_blocked_country;
use crate::{auditor, os_tz, proxy, routing, state, sysproxy};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Text for a failed (partial) restore: nothing is lost, the records stay in the journal.
const PARTIAL_RESTORE_TEXT: &str = "Часть системных настроек сейчас восстановить нельзя (например, активный VPN \
держит временные настройки DNS, или журнал занят). Они сохранены и будут восстановлены при \
следующем запуске Заставы или после отключения VPN.";

/// Returned when turning protection off stopped all Zastava routing and the only un-restored
/// OS items are physical PAC/chain entries deferred solely because an active VPN holds temp DNS.
const TEMP_DNS_DEFERRED_TEXT: &str = "TEMP_DNS_DEFERRED:Системный прокси вернётся к прежним \
настройкам после отключения VPN, чтобы не сбросить его DNS. Защита Заставы отключена.";

/// Detects a safe (non-sanctioned, non-RU/BY) IANA timezone across providers, falling back from
/// `Anthropic` to `Openai` and `Gemini` when earlier providers have no telemetry or timezone yet.
/// Returns `Err(blocked_cc)` only when no safe provider timezone was found and at least one
/// provider reported a sanctioned/blocked country.
async fn detect_safe_provider_timezone(
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
    let detected = detect_safe_provider_timezone(state, auditor)
        .await
        .ok()
        .flatten()?;
    let _ = state.set_synced_ai_timezone(Some(detected.clone())).await;
    Some(detected)
}

async fn enable_sysproxy_with(
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

#[tauri::command]
pub async fn toggle_sysproxy(
    enable: bool,
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    if enable {
        enable_sysproxy_with(false, &state, &auditor, &proxy_manager).await
    } else {
        crate::startup::note_user_off(&app);
        if let Some(dir) = os_tz::resolve_app_data_dir(Some(&app)) {
            let restore_res =
                tokio::task::spawn_blocking(move || os_tz::restore_if_synced_on_disable(&dir))
                    .await;
            match restore_res {
                Ok(Ok(true)) => {
                    eprintln!(
                        "Застава: системный часовой пояс ОС восстановлен при выключении защиты."
                    );
                }
                Ok(Ok(false)) => {}
                Ok(Err(err)) => {
                    crate::diagnostics::record("cmd:os_tz_restore_on_disable", &err);
                    eprintln!(
                        "Застава: не удалось восстановить часовой пояс ОС при выключении защиты: {err}"
                    );
                }
                Err(err) => {
                    crate::diagnostics::record("cmd:os_tz_restore_on_disable", &err.to_string());
                }
            }
        }
        let report = sysproxy::cleanup_all_persistent_settings();
        proxy_manager.coverage.invalidate_facts();
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

/// User-triggered retry of enabling the macOS system proxy via administrator authorization
/// (`osascript ... with administrator privileges`) after `toggle_sysproxy(true)` failed with
/// `ADMIN_AUTH_REQUIRED:`. On non-macOS systems this delegates to normal `toggle_sysproxy(true)`.
#[tauri::command]
pub async fn toggle_sysproxy_privileged(
    state: tauri::State<'_, state::AppState>,
    auditor: tauri::State<'_, auditor::Auditor>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<bool, String> {
    enable_sysproxy_with(cfg!(target_os = "macos"), &state, &auditor, &proxy_manager).await
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

async fn resolve_os_tz_target(
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

pub(crate) fn build_error_diagnostics_report(
    error_title: Option<&str>,
    error_message: Option<&str>,
    gateway_port: u16,
    os_lines: &[String],
    entries: &[String],
) -> String {
    let mut out = Vec::new();
    out.push(format!(
        "Zastava v{} ({}/{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    if let Some(title) = error_title.map(str::trim).filter(|s| !s.is_empty()) {
        out.push(format!("Error title: {title}"));
    }
    if let Some(msg) = error_message.map(str::trim).filter(|s| !s.is_empty()) {
        out.push(format!("Error text: {msg}"));
    }
    out.push(format!(
        "State: sysproxy_active={}, cli_active={}, gateway_port={}, chained_proxy_set={}",
        sysproxy::is_sysproxy_active(),
        sysproxy::is_cli_protection_enabled(),
        gateway_port,
        sysproxy::get_chained_proxy().is_some()
    ));

    if !os_lines.is_empty() {
        out.push("--- OS Network Snapshot ---".to_string());
        out.extend(os_lines.iter().cloned());
    }

    out.push("--- Diagnostic Log ---".to_string());
    if entries.is_empty() {
        out.push("(no recorded events in this session)".to_string());
    } else {
        out.extend(entries.iter().cloned());
    }

    out.join("\n")
}

/// Builds a sanitized, copyable diagnostic bundle when the user clicks "Скопировать лог" on an error.
#[tauri::command]
pub async fn get_error_diagnostics(
    error_title: Option<String>,
    error_message: Option<String>,
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<String, String> {
    let os_lines = tokio::task::spawn_blocking(sysproxy::platform::collect_os_diagnostic_snapshot)
        .await
        .unwrap_or_default();
    let entries = crate::diagnostics::dump();
    Ok(build_error_diagnostics_report(
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

const MASKED_IPV4: &str = "xxx.xxx.xxx.xxx";
const MASKED_IPV6: &str = "xxxx:xxxx::xxxx";

/// Masks a single IPv4 or IPv6 address literal. Non-IP or empty inputs return `"***"`.
pub(crate) fn mask_ip_address(ip: &str) -> String {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => MASKED_IPV4.to_string(),
        Ok(IpAddr::V6(_)) => MASKED_IPV6.to_string(),
        Err(_) => sanitize_diagnostic_text(trimmed),
    }
}

fn mask_ip_token(core: &str) -> Option<String> {
    if core.is_empty() {
        return None;
    }
    // CIDR notation (e.g. `185.220.101.0/24` or `2001:db8::/32`).
    if let Some((addr, prefix)) = core.split_once('/')
        && !prefix.is_empty()
        && prefix.chars().all(|c| c.is_ascii_digit())
        && let Ok(ip) = addr.parse::<IpAddr>()
    {
        let masked = match ip {
            IpAddr::V4(_) => MASKED_IPV4,
            IpAddr::V6(_) => MASKED_IPV6,
        };
        return Some(format!("{masked}/{prefix}"));
    }
    // Bracketed IPv6 with optional port: `[2001:db8::1]:443` or `[2001:db8::1]`.
    if let Some(after_open) = core.strip_prefix('[') {
        if let Some((inside, port)) = after_open.split_once("]:")
            && inside.parse::<Ipv6Addr>().is_ok()
            && !port.is_empty()
            && port.chars().all(|c| c.is_ascii_digit())
        {
            return Some(format!("[{MASKED_IPV6}]:xxx"));
        }
        if let Some(inside) = after_open.strip_suffix(']')
            && inside.parse::<Ipv6Addr>().is_ok()
        {
            return Some(format!("[{MASKED_IPV6}]"));
        }
    }
    // Plain IPv4:port.
    if let Some((host, port)) = core.rsplit_once(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
        && host.parse::<Ipv4Addr>().is_ok()
    {
        return Some(format!("{MASKED_IPV4}:xxx"));
    }
    match core.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Some(MASKED_IPV4.to_string()),
        Ok(IpAddr::V6(_)) => Some(MASKED_IPV6.to_string()),
        Err(_) => None,
    }
}

fn redact_scheme_urls(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut cursor = 0usize;

    while let Some(rel) = lower[cursor..].find("://") {
        let sep = cursor + rel;
        let mut scheme_start = sep;
        while scheme_start > cursor {
            let prev = bytes[scheme_start - 1];
            if prev.is_ascii_alphanumeric() || prev == b'+' || prev == b'-' {
                scheme_start -= 1;
            } else {
                break;
            }
        }
        let scheme = &lower[scheme_start..sep];
        let mut url_end = sep + 3;
        while url_end < raw.len() {
            let ch = raw[url_end..].chars().next().unwrap();
            if ch.is_whitespace() || matches!(ch, '"' | '\'' | ')' | ']' | '>' | ',' | ';') {
                break;
            }
            url_end += ch.len_utf8();
        }
        let full_url = &raw[scheme_start..url_end];
        let should_redact = !scheme.is_empty()
            && (scheme == "zastava"
                || scheme.starts_with("socks")
                || full_url.contains('@')
                || matches!(scheme, "http" | "https" | "ws" | "wss"));

        if should_redact {
            out.push_str(&raw[cursor..scheme_start]);
            out.push_str(scheme);
            out.push_str("://[REDACTED]");
            cursor = url_end;
        } else {
            out.push_str(&raw[cursor..sep + 3]);
            cursor = sep + 3;
        }
    }
    out.push_str(&raw[cursor..]);
    out
}

fn redact_sensitive_kv(token: &str, prev_was_bearer: bool) -> String {
    if prev_was_bearer && !token.is_empty() {
        return "[REDACTED]".to_string();
    }
    const SENSITIVE_KEYS: [&str; 9] = [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "proxy_url",
        "raw_key",
    ];
    for sep in ['=', ':'] {
        if let Some((k, _)) = token.split_once(sep) {
            let kl = k
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .to_ascii_lowercase();
            if SENSITIVE_KEYS.contains(&kl.as_str()) {
                return format!("{k}{sep}[REDACTED]");
            }
        }
    }
    token.to_string()
}

/// Masks IPv4/IPv6 addresses, raw proxy URLs, `zastava://` keys, and credential tokens in
/// diagnostic strings before export.
pub(crate) fn sanitize_diagnostic_text(raw: &str) -> String {
    let url_redacted = redact_scheme_urls(raw);
    let mut out = String::with_capacity(url_redacted.len());
    let mut i = 0usize;
    let mut prev_was_bearer = false;

    while i < url_redacted.len() {
        let ch = url_redacted[i..].chars().next().unwrap();
        let is_delim = ch.is_whitespace()
            || matches!(
                ch,
                '(' | ')' | ',' | ';' | '<' | '>' | '"' | '\'' | '«' | '»'
            );
        if is_delim {
            out.push(ch);
            i += ch.len_utf8();
            if !ch.is_whitespace() {
                prev_was_bearer = false;
            }
            continue;
        }
        let start = i;
        while i < url_redacted.len() {
            let c = url_redacted[i..].chars().next().unwrap();
            if c.is_whitespace()
                || matches!(
                    c,
                    '(' | ')' | ',' | ';' | '<' | '>' | '"' | '\'' | '«' | '»'
                )
            {
                break;
            }
            i += c.len_utf8();
        }
        let tok = &url_redacted[start..i];
        let kv_cleaned = redact_sensitive_kv(tok, prev_was_bearer);
        prev_was_bearer = tok.trim_end_matches(':').eq_ignore_ascii_case("bearer");

        // Handle sentence trailing periods (`185.220.101.5.`) without losing valid IPv6 `::`.
        let (core, trailing_dots) = if kv_cleaned.ends_with('.') {
            let stripped = kv_cleaned.trim_end_matches('.');
            (stripped, &kv_cleaned[stripped.len()..])
        } else {
            (kv_cleaned.as_str(), "")
        };
        if let Some(masked) = mask_ip_token(core) {
            out.push_str(&masked);
            out.push_str(trailing_dots);
        } else if let Some((k, v)) = core.split_once(':')
            && let Some(masked) = mask_ip_token(v)
        {
            // Cases like `ip:185.220.101.5` (while leaving full IPv6 literals caught above).
            out.push_str(k);
            out.push(':');
            out.push_str(&masked);
            out.push_str(trailing_dots);
        } else {
            out.push_str(&kv_cleaned);
        }
    }

    out
}

/// Sanitized route binding summary for a provider (never contains URLs, hosts, ports, or keys).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticProviderRoute {
    pub mode: String,
    pub route_id: Option<String>,
    pub name: Option<String>,
    pub country: Option<String>,
    pub enabled: bool,
    pub is_default: bool,
    pub is_profile_route: bool,
}

/// Sanitized check entry inside [`DiagnosticProviderAudit`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticCheckSummary {
    pub code: String,
    pub status: auditor::CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<auditor::UnknownReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_via: Option<String>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_addrs_masked: Vec<String>,
}

/// Sanitized audit status per AI provider (`anthropic`, `openai`, `gemini`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticProviderAudit {
    pub status: String,
    pub trust_score: Option<u8>,
    pub incomplete: bool,
    pub unknown_count: u8,
    pub applicable_count: u8,
    pub exit_ip_masked: Option<String>,
    pub exit_country: Option<String>,
    pub asn: Option<u32>,
    pub checks: Vec<DiagnosticCheckSummary>,
    pub last_history_country: Option<String>,
    pub last_history_ip_masked: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Sanitized gateway counters included in [`DiagnosticBundle`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticGatewayStats {
    pub protected_ai_requests: u64,
    pub intercepted_leaks: u64,
    pub direct_bypassed_requests: u64,
    pub active_ai_tunnels: u64,
    pub uptime_seconds: u64,
}

/// Sanitized, shareable diagnostic report produced by `export_diagnostic_bundle_cmd`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticBundle {
    pub app_version: String,
    pub os: String,
    pub arch: String,
    pub os_version: Option<String>,
    pub sysproxy_enabled: bool,
    pub cli_protection_enabled: bool,
    pub cli_mode: state::CliMode,
    pub split_tunnel_mode: bool,
    pub sync_ai_tz_enabled: bool,
    pub synced_ai_timezone: Option<String>,
    pub hide_ip_mode: bool,
    pub strict_pinning_enabled: bool,
    pub manual_killswitch: bool,
    pub interception_behavior: state::InterceptionBehavior,
    pub gateway_port: u16,
    pub blocked_providers: Vec<String>,
    pub session_allowed_providers: Vec<String>,
    pub provider_routes: BTreeMap<String, DiagnosticProviderRoute>,
    pub audit_reports: BTreeMap<String, DiagnosticProviderAudit>,
    pub gateway_stats: DiagnosticGatewayStats,
    pub recent_diagnostics: Vec<String>,
}

fn sanitize_report_entry(
    report: &auditor::RiskReport,
    last_history: Option<&state::IpHistoryEntry>,
) -> DiagnosticProviderAudit {
    let status = match report.overall_status {
        auditor::OverallStatus::Green => "green",
        auditor::OverallStatus::Yellow => "yellow",
        auditor::OverallStatus::Red => "red",
    }
    .to_string();

    let exit_ip_masked =
        (!report.telemetry.ip.trim().is_empty()).then(|| mask_ip_address(&report.telemetry.ip));
    let exit_country = (!report.telemetry.country_code.trim().is_empty())
        .then(|| report.telemetry.country_code.trim().to_uppercase());

    let checks = report
        .checks
        .iter()
        .map(|c| {
            let source_addrs_masked = c
                .detail
                .as_ref()
                .map(|d| {
                    d.sources
                        .iter()
                        .filter_map(|s| s.addr.as_deref())
                        .map(mask_ip_address)
                        .collect()
                })
                .unwrap_or_default();
            DiagnosticCheckSummary {
                code: c.code.clone(),
                status: c.status,
                reason: c.reason,
                measured_via: c.measured_via.as_deref().map(sanitize_diagnostic_text),
                message: sanitize_diagnostic_text(&c.message),
                source_addrs_masked,
            }
        })
        .collect();

    DiagnosticProviderAudit {
        status,
        trust_score: Some(report.trust_score),
        incomplete: report.incomplete,
        unknown_count: report.unknown_count,
        applicable_count: report.applicable_count,
        exit_ip_masked,
        exit_country,
        asn: report.telemetry.asn,
        checks,
        last_history_country: last_history.map(|h| h.country_code.clone()),
        last_history_ip_masked: last_history.map(|h| mask_ip_address(&h.ip)),
        error: None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_sanitized_diagnostic_bundle(
    data: &state::AppStateData,
    stats: &state::GatewayStatsSnapshot,
    provider_reports: &HashMap<String, Result<auditor::RiskReport, String>>,
    sysproxy_enabled: bool,
    cli_protection_enabled: bool,
    gateway_port: u16,
    os_version: Option<String>,
    diag_entries: &[String],
) -> DiagnosticBundle {
    let mut blocked_providers: Vec<String> = data.blocked_providers.iter().cloned().collect();
    blocked_providers.sort();
    let mut session_allowed_providers: Vec<String> =
        data.session_allowed_providers.iter().cloned().collect();
    session_allowed_providers.sort();

    let mut provider_routes = BTreeMap::new();
    let mut audit_reports = BTreeMap::new();

    for provider in state::KNOWN_PROVIDERS {
        let selection = routing::select_route(data, provider);
        let route_summary = match selection {
            routing::RouteSelection::Direct => DiagnosticProviderRoute {
                mode: "direct".to_string(),
                route_id: None,
                name: None,
                country: None,
                enabled: true,
                is_default: false,
                is_profile_route: false,
            },
            routing::RouteSelection::Route(r) => DiagnosticProviderRoute {
                mode: "route".to_string(),
                route_id: Some(r.id.clone()),
                name: Some(sanitize_diagnostic_text(&r.label)),
                country: r.country.clone(),
                enabled: r.enabled,
                is_default: data.default_route_id.as_deref() == Some(r.id.as_str()),
                is_profile_route: data.profile_route_id.as_deref() == Some(r.id.as_str()),
            },
            routing::RouteSelection::Missing(id) => DiagnosticProviderRoute {
                mode: "missing".to_string(),
                route_id: Some(sanitize_diagnostic_text(&id)),
                name: None,
                country: None,
                enabled: false,
                is_default: false,
                is_profile_route: false,
            },
            routing::RouteSelection::Invalid(_) => DiagnosticProviderRoute {
                mode: "invalid".to_string(),
                route_id: Some(routing::INVALID_PROFILE_ROUTE_ID.to_string()),
                name: None,
                country: None,
                enabled: false,
                is_default: false,
                is_profile_route: true,
            },
        };
        provider_routes.insert(provider.to_string(), route_summary);

        let scoped_key = data.ip_history_key_for_provider(provider);
        let last_history = data
            .ip_history
            .get(&scoped_key)
            .and_then(|h| h.last())
            .or_else(|| data.ip_history.get(provider).and_then(|h| h.last()));
        let audit_summary = match provider_reports.get(provider) {
            Some(Ok(report)) => sanitize_report_entry(report, last_history),
            Some(Err(err)) => DiagnosticProviderAudit {
                status: "unavailable".to_string(),
                trust_score: None,
                incomplete: true,
                unknown_count: 0,
                applicable_count: 0,
                exit_ip_masked: None,
                exit_country: None,
                asn: last_history.and_then(|h| h.asn),
                checks: Vec::new(),
                last_history_country: last_history.map(|h| h.country_code.clone()),
                last_history_ip_masked: last_history.map(|h| mask_ip_address(&h.ip)),
                error: Some(sanitize_diagnostic_text(err)),
            },
            None => DiagnosticProviderAudit {
                status: "unavailable".to_string(),
                trust_score: None,
                incomplete: true,
                unknown_count: 0,
                applicable_count: 0,
                exit_ip_masked: None,
                exit_country: None,
                asn: last_history.and_then(|h| h.asn),
                checks: Vec::new(),
                last_history_country: last_history.map(|h| h.country_code.clone()),
                last_history_ip_masked: last_history.map(|h| mask_ip_address(&h.ip)),
                error: None,
            },
        };
        audit_reports.insert(provider.to_string(), audit_summary);
    }

    DiagnosticBundle {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        os_version: os_version.map(|v| sanitize_diagnostic_text(&v)),
        sysproxy_enabled,
        cli_protection_enabled,
        cli_mode: data.cli_mode,
        split_tunnel_mode: data.split_tunnel_mode,
        sync_ai_tz_enabled: data.sync_ai_tz_enabled,
        synced_ai_timezone: data.synced_ai_timezone.clone(),
        hide_ip_mode: data.hide_ip_mode,
        strict_pinning_enabled: data.strict_pinning_enabled,
        manual_killswitch: data.manual_killswitch,
        interception_behavior: data.interception_behavior,
        gateway_port,
        blocked_providers,
        session_allowed_providers,
        provider_routes,
        audit_reports,
        gateway_stats: DiagnosticGatewayStats {
            protected_ai_requests: stats.protected_ai_requests,
            intercepted_leaks: stats.intercepted_leaks,
            direct_bypassed_requests: stats.direct_bypassed_requests,
            active_ai_tunnels: stats.active_ai_tunnels,
            uptime_seconds: stats.uptime_seconds,
        },
        recent_diagnostics: diag_entries
            .iter()
            .map(|line| sanitize_diagnostic_text(line))
            .collect(),
    }
}

fn extract_os_version_from_snapshot(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .find_map(|l| l.strip_prefix("macos_version: "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
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

    let os_version = extract_os_version_from_snapshot(&os_lines);
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

    let diag_entries = crate::diagnostics::dump();
    let bundle = build_sanitized_diagnostic_bundle(
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

/// Preview entry describing one OS or editor configuration target Zastava manages.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtectionChangePreviewItem {
    pub category: String,
    pub target: String,
    pub action: String,
    pub description: String,
    pub reversible: bool,
}

/// Builds the list of OS/browser/shell/IDE settings Zastava configures or monitors.
pub(crate) fn build_protection_changes_preview(
    gateway_port: u16,
    cli_mode: state::CliMode,
    sync_ai_tz_enabled: bool,
    detected_ides: &[(&'static str, std::path::PathBuf)],
) -> Vec<ProtectionChangePreviewItem> {
    let pac_url = format!("http://127.0.0.1:{gateway_port}/proxy.pac");
    let tz_note = if sync_ai_tz_enabled {
        " и TZ/LANG/LC_TIME для согласования часового пояса"
    } else {
        ""
    };

    let sysproxy_target = if cfg!(target_os = "windows") {
        "Системный PAC (WinINet AutoConfigURL)"
    } else {
        "Системный PAC на физических интерфейсах (Wi-Fi, Ethernet)"
    };
    let sysproxy_desc = if cfg!(target_os = "windows") {
        format!(
            "Устанавливает AutoConfigURL={pac_url} в настройках WinINet текущего пользователя. Предыдущее значение сохраняется в журнале и восстанавливается при отключении или выходе."
        )
    } else {
        format!(
            "Назначает PAC {pac_url} только на физические сетевые интерфейсы macOS (виртуальные VPN-туннели utun/tun не затрагиваются). Прежнее состояние сохраняется в журнале."
        )
    };

    let specs = sysproxy::browser_policies::policy_specs_with_pac(Some(&pac_url));
    let mut domains: Vec<&str> = specs.iter().map(|s| s.domain.as_str()).collect();
    domains.sort_unstable();
    domains.dedup();
    let policy_keys = format!(
        "{}, {}, {}, {}",
        sysproxy::browser_policies::KEY_PROXY_MODE,
        sysproxy::browser_policies::KEY_PROXY_PAC_URL,
        sysproxy::browser_policies::KEY_QUIC_ALLOWED,
        sysproxy::browser_policies::KEY_DOH_MODE,
    );

    let (shell_target, shell_action, shell_desc) = if cfg!(target_os = "windows") {
        let action = match cli_mode {
            state::CliMode::GlobalTerminal => "upsert_managed_block",
            state::CliMode::AiOnly => "restore_or_skip",
        };
        (
            "Профили PowerShell (Microsoft.PowerShell_profile.ps1)",
            action,
            format!(
                "В режиме global_terminal добавляет маркерный блок # >>> zastava ... # <<< zastava (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY на http://127.0.0.1:{gateway_port}{tz_note}); в режиме ai_only блок снимается без потери завершающего переноса строки."
            ),
        )
    } else {
        let action = match cli_mode {
            state::CliMode::GlobalTerminal => "upsert_managed_block",
            state::CliMode::AiOnly => "restore_or_skip",
        };
        (
            "~/.zshrc, ~/.bash_profile",
            action,
            format!(
                "В режиме global_terminal добавляет изолированный блок # >>> zastava ... # <<< zastava (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY на http://127.0.0.1:{gateway_port}{tz_note}); в безопасном режиме ai_only оболочка не меняется и старый блок удаляется с сохранением завершающего переноса строки."
            ),
        )
    };

    let mut detected_names: Vec<&str> = detected_ides.iter().map(|(label, _)| *label).collect();
    detected_names.sort_unstable();
    detected_names.dedup();
    let detected_note = if detected_names.is_empty() {
        "обнаруженных в системе редакторов".to_string()
    } else {
        format!("обнаруженных редакторов ({})", detected_names.join(", "))
    };

    vec![
        ProtectionChangePreviewItem {
            category: "system_proxy".to_string(),
            target: sysproxy_target.to_string(),
            action: "set_pac_url".to_string(),
            description: sysproxy_desc,
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "browser_policies".to_string(),
            target: format!("Политики браузеров Chromium ({policy_keys})"),
            action: "apply_browser_policies".to_string(),
            description: format!(
                "Задаёт ProxyMode=pac_script, ProxyPacUrl={pac_url}, отключает QUIC (QuicAllowed) и DoH (DnsOverHttpsMode) для Chromium-браузеров ({} целей). Все прежние политики возвращаются через журнал.",
                domains.len().max(1)
            ),
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "shell_rc".to_string(),
            target: shell_target.to_string(),
            action: shell_action.to_string(),
            description: shell_desc,
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "cli_settings".to_string(),
            target: "~/.claude/settings.json, ~/.gemini/settings.json".to_string(),
            action: "update_env_keys".to_string(),
            description: format!(
                "Точечно обновляет переменные окружения внутри объекта env (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY на http://127.0.0.1:{gateway_port}{tz_note}) без перезаписи остальных настроек."
            ),
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "ide_settings".to_string(),
            target: "VS Code, Cursor, Windsurf, VSCodium, Antigravity (User/settings.json)"
                .to_string(),
            action: "update_jsonc_keys".to_string(),
            description: format!(
                "Точечно задаёт http.proxy и terminal.integrated.env.*{tz_note} в User/settings.json {detected_note} через JSONC-редактор с сохранением комментариев и откатом в журнале."
            ),
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "ide_settings".to_string(),
            target: "JetBrains IDE (options/proxy.settings.xml)".to_string(),
            action: "monitor_only".to_string(),
            description: format!(
                "Проверяется в разделе «Покрытие» и по живому трафику шлюза; файл proxy.settings.xml автоматически не изменяется (при необходимости укажите PAC {pac_url} в настройках HTTP Proxy IDE)."
            ),
            reversible: true,
        },
    ]
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
    Ok(build_protection_changes_preview(
        proxy_manager.server.bound_addr.port(),
        data.cli_mode,
        data.sync_ai_tz_enabled,
        &detected_ides,
    ))
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

    #[test]
    fn diagnostic_report_includes_error_os_snapshot_and_logs() {
        let report = build_error_diagnostics_report(
            Some("Не удалось переключить защиту"),
            Some("Command failed"),
            8899,
            &["services: Wi-Fi(dev=en0, enabled=true)".to_string()],
            &["[+1s] [sysproxy] set_pac failed".to_string()],
        );
        assert!(report.contains("Zastava v"));
        assert!(report.contains("Error title: Не удалось переключить защиту"));
        assert!(report.contains("gateway_port=8899"));
        assert!(report.contains("services: Wi-Fi(dev=en0, enabled=true)"));
        assert!(report.contains("[+1s] [sysproxy] set_pac failed"));
    }

    #[tokio::test]
    async fn resolve_os_tz_and_sync_tz_fall_back_across_providers_when_anthropic_lacks_tz() {
        use crate::routing::{Entry, EntryProto, Route};

        let state = state::AppState::new_in_memory();
        let fr_route = Route {
            id: "fr-fallback".into(),
            label: "France".into(),
            country: Some("FR".into()),
            exit_ip: Some("136.244.114.42".into()),
            expires_at: None,
            entries: vec![Entry {
                proto: EntryProto::Http,
                host: "136.244.114.42".into(),
                port: 8443,
                username: None,
                password: None,
                sni: None,
            }],
            raw_key: String::new(),
            enabled: true,
            added_at: 0,
        };
        state.upsert_route(fr_route).await.unwrap();
        state
            .bind_provider_route("gemini", Some("fr-fallback"))
            .await
            .unwrap();

        let auditor = auditor::Auditor::new().unwrap();
        let now = auditor::network::current_timestamp();
        // Anthropic is Direct and has trace-only telemetry without timezone.
        auditor
            .resolver
            .set_cached(auditor::NetworkTelemetry {
                ip: "145.241.193.245".into(),
                country_code: "GB".into(),
                hostname: None,
                asn: None,
                org: None,
                isp: None,
                timezone: None,
                resolved_at: now,
            })
            .await;
        // Gemini is routed and has a valid French timezone.
        auditor
            .resolver
            .set_cached_for_route(
                Some("fr-fallback".into()),
                auditor::NetworkTelemetry {
                    ip: "136.244.114.42".into(),
                    country_code: "FR".into(),
                    hostname: None,
                    asn: None,
                    org: None,
                    isp: None,
                    timezone: Some("Europe/Paris".into()),
                    resolved_at: now,
                },
            )
            .await;

        let resolved = resolve_os_tz_target(&state, &auditor, None).await.unwrap();
        assert_eq!(resolved, "Europe/Paris");

        let synced = sync_tz_for(true, &state, &auditor).await;
        assert_eq!(synced.as_deref(), Some("Europe/Paris"));
    }

    #[test]
    fn sanitize_diagnostic_text_masks_ipv4_ipv6_urls_and_secrets() {
        assert_eq!(mask_ip_address("185.220.101.5"), "xxx.xxx.xxx.xxx");
        assert_eq!(mask_ip_address("2001:db8::1"), "xxxx:xxxx::xxxx");

        let msg = "Нарушение Strict Pinning: текущий IP (185.220.101.5) не совпадает с 136.244.114.42; \
                   v6 [2001:db8:85a3::8a2e:370:7334]:443 и ключ zastava://secret-key@node.example:443?token=abc, \
                   proxy socks5://alice:supersecret@198.51.100.7:1080 password=topsecret Bearer tok_live_123 v2.1.2.";
        let clean = sanitize_diagnostic_text(msg);

        assert!(!clean.contains("185.220.101.5"), "{clean}");
        assert!(!clean.contains("136.244.114.42"), "{clean}");
        assert!(!clean.contains("198.51.100.7"), "{clean}");
        assert!(!clean.contains("2001:db8"), "{clean}");
        assert!(!clean.contains("secret-key"), "{clean}");
        assert!(!clean.contains("supersecret"), "{clean}");
        assert!(!clean.contains("alice"), "{clean}");
        assert!(!clean.contains("topsecret"), "{clean}");
        assert!(!clean.contains("tok_live_123"), "{clean}");
        assert!(clean.contains("xxx.xxx.xxx.xxx"), "{clean}");
        assert!(clean.contains("xxxx:xxxx::xxxx"), "{clean}");
        assert!(clean.contains("zastava://[REDACTED]"), "{clean}");
        assert!(clean.contains("socks5://[REDACTED]"), "{clean}");
        assert!(clean.contains("v2.1.2"), "versions must survive: {clean}");
    }

    #[test]
    fn diagnostic_bundle_serializes_routes_and_checks_without_secrets_or_ips() {
        let mut data = state::AppStateData {
            cli_mode: state::CliMode::GlobalTerminal,
            split_tunnel_mode: true,
            sync_ai_tz_enabled: true,
            synced_ai_timezone: Some("Europe/Amsterdam".to_string()),
            ..Default::default()
        };
        data.routes.push(routing::Route {
            id: "route-nl".to_string(),
            label: "NL Fast socks5://u:pw123@198.51.100.9:1080".to_string(),
            country: Some("NL".to_string()),
            exit_ip: Some("185.10.20.30".to_string()),
            expires_at: None,
            entries: vec![routing::Entry {
                proto: routing::EntryProto::Socks5,
                host: "198.51.100.9".to_string(),
                port: 1080,
                username: Some("secretuser".to_string()),
                password: Some("verysecretpassword".to_string()),
                sni: None,
            }],
            raw_key: "zastava://top-secret-raw-key".to_string(),
            enabled: true,
            added_at: 1_700_000_000,
        });
        data.provider_routes
            .insert("gemini".to_string(), "route-nl".to_string());
        data.ip_history.insert(
            "anthropic".to_string(),
            vec![state::IpHistoryEntry::new(
                "203.0.113.55".to_string(),
                "DE".to_string(),
                Some(24940),
                1_700_000_000,
            )],
        );

        let check = auditor::CheckResult::critical(
            "PINNED_IP_MISMATCH",
            "Текущий IP (203.0.113.55) не совпадает с 198.51.100.44",
            None,
        );
        let tel = auditor::NetworkTelemetry {
            ip: "203.0.113.55".to_string(),
            country_code: "DE".to_string(),
            hostname: Some("secret-host.internal".to_string()),
            asn: Some(24940),
            org: Some("Hetzner".to_string()),
            isp: Some("Hetzner".to_string()),
            timezone: Some("Europe/Berlin".to_string()),
            resolved_at: 1_700_000_000,
        };
        let report = auditor::RiskReport {
            provider: auditor::ProviderId::Anthropic,
            overall_status: auditor::OverallStatus::Red,
            trust_score: 40,
            telemetry: tel,
            geo_result: auditor::CheckResult::ok("GEO_OK", "OK"),
            pinning_result: check.clone(),
            travel_result: auditor::CheckResult::ok("TRAVEL_OK", "OK"),
            dnsbl_result: auditor::CheckResult::ok("DNSBL_CLEAN", "4/4"),
            dnsbl_clean_count: "4/4".to_string(),
            asn_result: auditor::CheckResult::ok("ASN_CLEAN", "OK"),
            ipv6_result: auditor::CheckResult::ok("IPV6_SAFE", "OK"),
            timezone_result: auditor::CheckResult::ok("TZ_OK", "OK"),
            ipv6_exit: false,
            checks: vec![check],
            unknown_count: 0,
            applicable_count: 1,
            incomplete: false,
        };

        let mut reports = HashMap::new();
        reports.insert("anthropic".to_string(), Ok(report));
        let stats = state::GatewayStatsSnapshot {
            protected_ai_requests: 5,
            intercepted_leaks: 1,
            direct_bypassed_requests: 2,
            active_ai_tunnels: 0,
            uptime_seconds: 120,
            last_protected_host: Some("api.anthropic.com".to_string()),
            recent_events: Vec::new(),
        };

        let bundle = build_sanitized_diagnostic_bundle(
            &data,
            &stats,
            &reports,
            true,
            true,
            8899,
            Some("15.2 (24C101)".to_string()),
            &["proxy connect socks5://user:pass@198.51.100.9:1080 failed".to_string()],
        );
        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["app_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(parsed["os"], std::env::consts::OS);
        assert_eq!(parsed["arch"], std::env::consts::ARCH);
        assert_eq!(parsed["sysproxy_enabled"], true);
        assert_eq!(parsed["cli_protection_enabled"], true);
        assert_eq!(parsed["cli_mode"], "global_terminal");
        assert_eq!(parsed["split_tunnel_mode"], true);
        assert_eq!(parsed["sync_ai_tz_enabled"], true);

        assert_eq!(parsed["provider_routes"]["gemini"]["route_id"], "route-nl");
        assert_eq!(parsed["provider_routes"]["gemini"]["country"], "NL");
        assert_eq!(parsed["provider_routes"]["anthropic"]["mode"], "direct");
        assert_eq!(
            parsed["audit_reports"]["anthropic"]["exit_ip_masked"],
            "xxx.xxx.xxx.xxx"
        );
        assert_eq!(
            parsed["audit_reports"]["anthropic"]["checks"][0]["code"],
            "PINNED_IP_MISMATCH"
        );

        for secret in [
            "185.10.20.30",
            "198.51.100.9",
            "198.51.100.44",
            "203.0.113.55",
            "secretuser",
            "verysecretpassword",
            "top-secret-raw-key",
            "pw123",
            "secret-host.internal",
        ] {
            assert!(!json.contains(secret), "leaked `{secret}` in {json}");
        }
    }

    #[test]
    fn preview_protection_changes_covers_all_layers_and_marks_all_reversible() {
        let items = build_protection_changes_preview(
            8899,
            state::CliMode::GlobalTerminal,
            true,
            &[(
                "VS Code",
                std::path::PathBuf::from("/tmp/Code/User/settings.json"),
            )],
        );
        assert!(!items.is_empty());
        for item in &items {
            assert!(!item.category.is_empty());
            assert!(!item.target.is_empty());
            assert!(!item.action.is_empty());
            assert!(!item.description.is_empty());
            assert!(item.reversible, "expected reversible=true for {item:?}");
        }
        assert!(items.iter().any(|i| i.category == "system_proxy"));
        assert!(items.iter().any(|i| {
            i.category == "browser_policies"
                && i.target.contains("ProxyMode")
                && i.target.contains("ProxyPacUrl")
                && i.target.contains("QuicAllowed")
                && i.target.contains("DnsOverHttpsMode")
        }));
        assert!(items.iter().any(|i| i.category == "shell_rc"));
        assert!(items.iter().any(|i| {
            i.category == "ide_settings"
                && i.target.contains("VS Code")
                && i.target.contains("Cursor")
                && i.target.contains("Antigravity")
        }));
        assert!(
            items
                .iter()
                .any(|i| i.category == "ide_settings" && i.target.contains("JetBrains"))
        );
    }
}
