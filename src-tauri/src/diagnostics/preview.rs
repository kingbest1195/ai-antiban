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
        " и часовой пояс с локалью для согласования региона"
    } else {
        ""
    };

    let (sysproxy_title, sysproxy_target, sysproxy_desc) = if cfg!(target_os = "windows") {
        (
            "Системные настройки прокси Windows",
            format!("WinINet AutoConfigURL → {pac_url}"),
            "Направляет трафик ИИ-сервисов через локальный шлюз Заставы без вмешательства в обычные сайты. Прежнее значение сохраняется и возвращается при выходе.".to_string(),
        )
    } else {
        (
            "Системный прокси для Wi-Fi и Ethernet",
            format!("PAC {pac_url}"),
            "Назначает правило маршрутизации только на обычные сетевые подключения macOS, не затрагивая виртуальные VPN-туннели. Прежние настройки восстанавливаются при выходе.".to_string(),
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

    let (shell_target, shell_title, shell_desc) = if cfg!(target_os = "windows") {
        let title = match cli_mode {
            state::CliMode::GlobalTerminal => "Прокси для терминала PowerShell",
            state::CliMode::AiOnly => "Оболочка терминала не изменяется",
        };
        (
            "Microsoft.PowerShell_profile.ps1",
            title,
            format!(
                "В режиме «Весь терминал» добавляет в профиль PowerShell адрес локального шлюза (порт {gateway_port}{tz_note}). В режиме «Только ИИ-приложения» этот блок аккуратно удаляется."
            ),
        )
    } else {
        let title = match cli_mode {
            state::CliMode::GlobalTerminal => "Прокси для терминала (zsh / bash)",
            state::CliMode::AiOnly => "Оболочка терминала не изменяется",
        };
        (
            "~/.zshrc, ~/.bash_profile",
            title,
            format!(
                "В режиме «Весь терминал» добавляет в профиль оболочки адрес локального шлюза (порт {gateway_port}{tz_note}). В безопасном режиме «Только ИИ-приложения» оболочка не трогается, а старый блок удаляется."
            ),
        )
    };

    let mut detected_names: Vec<&str> = detected_ides.iter().map(|(label, _)| *label).collect();
    detected_names.sort_unstable();
    detected_names.dedup();
    let detected_note = if detected_names.is_empty() {
        "найденных на компьютере редакторов".to_string()
    } else {
        format!("найденных редакторов ({})", detected_names.join(", "))
    };

    vec![
        ProtectionChangePreviewItem {
            category: "system_proxy".to_string(),
            target: sysproxy_target,
            action: sysproxy_title.to_string(),
            description: sysproxy_desc,
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "browser_policies".to_string(),
            target: format!("Chromium: {policy_keys}"),
            action: "Защита браузеров от сетевых утечек".to_string(),
            description: format!(
                "Включает маршрут Заставы для ИИ и отключает обходные протоколы QUIC и встроенный DoH в браузерах ({} целей). Все прежние политики возвращаются при выходе.",
                domains.len().max(1)
            ),
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "shell_rc".to_string(),
            target: shell_target.to_string(),
            action: shell_title.to_string(),
            description: shell_desc,
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "cli_settings".to_string(),
            target: "~/.claude/settings.json, ~/.gemini/settings.json".to_string(),
            action: "Настройки терминальных агентов ИИ".to_string(),
            description: format!(
                "Точечно задаёт адрес локального шлюза (порт {gateway_port}{tz_note}) в переменных окружения CLI-инструментов, не затрагивая остальные параметры."
            ),
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "ide_settings".to_string(),
            target: "VS Code, Cursor, Windsurf, VSCodium, Antigravity (User/settings.json)"
                .to_string(),
            action: "Прокси для редакторов кода и ИИ-расширений".to_string(),
            description: format!(
                "Точечно прописывает локальный шлюз{tz_note} в настройках {detected_note}, сохраняя комментарии и возвращая исходный файл при отключении."
            ),
            reversible: true,
        },
        ProtectionChangePreviewItem {
            category: "ide_settings".to_string(),
            target: "JetBrains IDE (options/proxy.settings.xml)".to_string(),
            action: "Контроль сетевых настроек JetBrains IDE".to_string(),
            description: format!(
                "Застава проверяет покрытие редакторов JetBrains по живому трафику и не меняет их файлы автоматически (при необходимости укажите адрес автонастройки {pac_url})."
            ),
            reversible: true,
        },
    ]
}
