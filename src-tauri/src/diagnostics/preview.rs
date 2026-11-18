//! Structured preview of OS, browser, shell RC, CLI, and IDE configuration targets.

use crate::{state, sysproxy};

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
pub fn build_protection_changes_preview(
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
