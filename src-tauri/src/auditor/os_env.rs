use crate::auditor::geo_matrix::{CheckResult, UnknownReason, GUIDE_OS_PRIVACY};

pub const RUSSIAN_TIMEZONES: &[&str] = &[
    "Europe/Moscow",
    "Europe/Kaliningrad",
    "Europe/Kirov",
    "Europe/Samara",
    "Europe/Saratov",
    "Europe/Ulyanovsk",
    "Europe/Volgograd",
    "Europe/Astrakhan",
    "Europe/Minsk",
    "Asia/Yekaterinburg",
    "Asia/Omsk",
    "Asia/Novosibirsk",
    "Asia/Barnaul",
    "Asia/Tomsk",
    "Asia/Novokuznetsk",
    "Asia/Krasnoyarsk",
    "Asia/Irkutsk",
    "Asia/Chita",
    "Asia/Yakutsk",
    "Asia/Khandyga",
    "Asia/Vladivostok",
    "Asia/Ust-Nera",
    "Asia/Magadan",
    "Asia/Sakhalin",
    "Asia/Srednekolymsk",
    "Asia/Kamchatka",
    "Asia/Anadyr",
];

pub fn is_russian_or_belarusian_timezone(tz: &str) -> bool {
    RUSSIAN_TIMEZONES.iter().any(|&item| item.eq_ignore_ascii_case(tz))
}

/// Evaluates whether system timezone exposes user's actual location.
/// Gate 8: If the OS system timezone mismatches the IP country, but `synced_ai_tz` matches
/// the exit IP's timezone, CLI and IDE requests are fully protected.
pub fn evaluate_system_timezone(
    ip_timezone: Option<&str>,
    synced_ai_tz: Option<&str>,
) -> CheckResult {
    let system_tz = match iana_time_zone::get_timezone() {
        Ok(tz) => tz,
        Err(_) => {
            return CheckResult::unknown(
                "TIMEZONE_UNKNOWN",
                "Часовой пояс не проверен: системный часовой пояс ОС не определен.",
                UnknownReason::NoData,
            );
        }
    };

    // If synced_ai_tz matches ip_timezone, AI agents in CLI/IDE have TZ and LANG overridden
    if let (Some(target_tz), Some(synced)) = (ip_timezone, synced_ai_tz) {
        let t_clean = target_tz.trim();
        let s_clean = synced.trim();
        if !t_clean.is_empty() && (s_clean.eq_ignore_ascii_case(t_clean) || s_clean.replace('_', " ") == t_clean.replace('_', " ")) {
            if system_tz != t_clean {
                return CheckResult::ok(
                    "TIMEZONE_SYNCED_AI",
                    format!(
                        "Таймзона для ИИ-агентов (CLI/IDE) синхронизирована через Заставу ({t_clean}). Для браузеров рекомендуем также переключить системные часы ОС."
                    ),
                );
            }
        }
    }

    // 1. Check if system timezone is in Russia or Belarus
    if is_russian_or_belarusian_timezone(&system_tz) {
        return CheckResult::warning(
            "TIMEZONE_LEAK_RU",
            format!(
                "Системный часовой пояс ОС ({system_tz}) указывает на РФ/РБ. Браузеры и десктопный Claude видят эту зону даже через VPN.",
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        );
    }

    // 2. Compare against IP timezone if available
    if let Some(target_tz) = ip_timezone {
        let t_clean = target_tz.trim();
        if !t_clean.is_empty() && system_tz != t_clean {
            return CheckResult::warning(
                "TIMEZONE_MISMATCH",
                format!(
                    "Часовой пояс ОС ({system_tz}) отличается от таймзоны IP ({t_clean}). Для максимального траста рекомендуется синхронизировать пояс с локацией сервера.",
                ),
                Some(GUIDE_OS_PRIVACY.to_string()),
            );
        }
    }

    // Nothing to compare with: the geolocation source gave no time zone for the exit IP.
    if ip_timezone.is_none_or(|t| t.trim().is_empty()) {
        return CheckResult::unknown(
            "TZ_NO_IP_DATA",
            format!(
                "Часовой пояс не сопоставлен: источник геолокации не передал часовой пояс IP (системный: {system_tz})."
            ),
            UnknownReason::NoData,
        );
    }

    CheckResult::ok(
        "TIMEZONE_MATCH",
        format!("Системный часовой пояс ({system_tz}) совпадает с локацией IP."),
    )
}

/// Evaluates Gate 12: Locale & Environment Hygiene (`LANG` and `LC_ALL`).
/// Checks if host/process environment contains Russian/Belarusian locale indicators
/// without Zastava's clean `en_US.UTF-8` override.
pub fn evaluate_locale_env_hygiene(synced_ai_tz: Option<&str>) -> CheckResult {
    if synced_ai_tz.is_some() {
        return CheckResult::ok(
            "LOCALE_HYGIENE_CLEAN",
            "Окружение CLI/IDE защищено: локаль синхронизирована (en_US.UTF-8) через Заставу.",
        );
    }

    let lang = std::env::var("LANG").unwrap_or_default();
    let lc_all = std::env::var("LC_ALL").unwrap_or_default();
    evaluate_locale_values(lang, lc_all)
}

/// The decision of [`evaluate_locale_env_hygiene`] for already read `LANG` / `LC_ALL` values.
fn evaluate_locale_values(lang: String, lc_all: String) -> CheckResult {
    if lang.trim().is_empty() && lc_all.trim().is_empty() {
        return CheckResult::unknown(
            "LOCALE_ENV_NOT_SET",
            "Локаль не проверена: в окружении Заставы не заданы LANG и LC_ALL, системная локаль не читалась.",
            UnknownReason::NoData,
        );
    }

    let is_sanctioned = |val: &str| {
        let v = val.to_ascii_uppercase();
        v.contains("RU_RU") || v.contains("BE_BY") || v.starts_with("RU-") || v.starts_with("BE-")
    };

    if is_sanctioned(&lang) || is_sanctioned(&lc_all) {
        let bad_val = if is_sanctioned(&lang) { lang } else { lc_all };
        return CheckResult::warning(
            "LOCALE_ENV_SANCTIONED_MARKER",
            format!(
                "В окружении обнаружена локаль «{bad_val}». ИИ-агенты в терминале могут передавать этот заголовок. Нажмите «Авто-настройка TZ/локали» для безопасной синхронизации (en_US.UTF-8)."
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        );
    }

    CheckResult::ok(
        "LOCALE_HYGIENE_CLEAN",
        "Переменные окружения LANG/LC_ALL не содержат маркеров риска.",
    )
}

/// Checks OS Location Services status (BSSID Wi-Fi triangulation).
/// Only Windows exposes a setting that can be read; elsewhere the check does not apply.
#[cfg(not(target_os = "windows"))]
pub fn check_os_location_services() -> CheckResult {
    CheckResult::unknown(
        "OS_LOCATION_NOT_APPLICABLE",
        "Геолокация ОС по Wi-Fi (BSSID) на этой системе не проверяется: состояние службы геолокации не читается.",
        UnknownReason::NotApplicable,
    )
}

/// Checks OS Location Services status (BSSID Wi-Fi triangulation).
#[cfg(target_os = "windows")]
pub fn check_os_location_services() -> CheckResult {
    {
        // 1. Check machine-wide policy first in HKLM.
        // If Deny, location services are globally disabled for the entire machine.
        let mut registry_read = false;
        if let Ok(hklm_output) = crate::sysproxy::silent_command("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
                "/v",
                "Value",
            ])
            .output()
        {
            registry_read = true;
            let hklm_text = String::from_utf8_lossy(&hklm_output.stdout);
            if hklm_text.contains("Deny") {
                return CheckResult::ok(
                    "OS_LOCATION_SAFE",
                    "Геолокация Windows отключена. Утечек по Wi-Fi (BSSID) нет.",
                );
            }
            if hklm_text.contains("Allow") {
                // 2. Only if HKLM is Allow AND HKCU is Allow, return the warning
                if let Ok(hkcu_output) = crate::sysproxy::silent_command("reg")
                    .args([
                        "query",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
                        "/v",
                        "Value",
                    ])
                    .output()
                {
                    let hkcu_text = String::from_utf8_lossy(&hkcu_output.stdout);
                    if hkcu_text.contains("Allow") {
                        return CheckResult::warning(
                            "OS_LOCATION_ENABLED",
                            "Службы геолокации Windows активны. Отключите их в настройках конфиденциальности ОС.",
                            Some(GUIDE_OS_PRIVACY.to_string()),
                        );
                    }
                }
            }
        }
        if !registry_read {
            return CheckResult::unknown(
                "OS_LOCATION_UNREADABLE",
                "Геолокация Windows не проверена: не удалось прочитать настройку службы геолокации.",
                UnknownReason::InternalError,
            );
        }
    }

    CheckResult::ok(
        "OS_LOCATION_SAFE",
        "Геолокация по Wi-Fi безопасна: MAC-адреса роутеров (BSSID) не передаются.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_russian_timezone_detection() {
        assert!(is_russian_or_belarusian_timezone("Europe/Moscow"));
        assert!(is_russian_or_belarusian_timezone("europe/moscow"));
        assert!(is_russian_or_belarusian_timezone("Asia/Vladivostok"));
        assert!(is_russian_or_belarusian_timezone("Europe/Minsk"));
        assert!(!is_russian_or_belarusian_timezone("Europe/Amsterdam"));
        assert!(!is_russian_or_belarusian_timezone("America/New_York"));
    }

    #[test]
    fn test_timezone_evaluation_synced_ai_bypass() {
        // If synced_ai_tz matches IP timezone, it returns OK even if OS timezone is different
        let res = evaluate_system_timezone(Some("Europe/Amsterdam"), Some("Europe/Amsterdam"));
        assert_eq!(res.status, crate::auditor::geo_matrix::CheckStatus::Ok);
        assert!(res.code == "TIMEZONE_SYNCED_AI" || res.code == "TIMEZONE_MATCH");
    }

    #[test]
    fn test_locale_hygiene_evaluation() {
        // When synced_ai_tz is active, locale hygiene is always OK
        let res_synced = evaluate_locale_env_hygiene(Some("Europe/London"));
        assert_eq!(res_synced.status, crate::auditor::geo_matrix::CheckStatus::Ok);
        assert_eq!(res_synced.code, "LOCALE_HYGIENE_CLEAN");
    }

    #[test]
    fn test_os_location_services_check() {
        let res = check_os_location_services();
        assert!(res.message.contains("Wi-Fi"));
        #[cfg(not(target_os = "windows"))]
        {
            assert!(res.is_not_applicable());
            assert_eq!(res.code, "OS_LOCATION_NOT_APPLICABLE");
        }
        #[cfg(target_os = "windows")]
        assert!(
            res.code == "OS_LOCATION_SAFE"
                || res.code == "OS_LOCATION_ENABLED"
                || res.code == "OS_LOCATION_UNREADABLE"
        );
    }

    #[test]
    fn test_locale_values() {
        use crate::auditor::geo_matrix::CheckStatus;
        let r = evaluate_locale_values(String::new(), "  ".to_string());
        assert_eq!(r.status, CheckStatus::Unknown);
        assert_eq!(r.reason, Some(UnknownReason::NoData));
        assert_eq!(
            evaluate_locale_values("ru_RU.UTF-8".into(), String::new()).status,
            CheckStatus::Warning
        );
        assert_eq!(
            evaluate_locale_values("en_US.UTF-8".into(), String::new()).status,
            CheckStatus::Ok
        );
    }

    #[test]
    fn test_timezone_without_ip_timezone_is_never_a_match() {
        use crate::auditor::geo_matrix::CheckStatus;
        let r = evaluate_system_timezone(None, None);
        // Depends on the host zone: a Russian zone is a legitimate Warning, anything else has
        // nothing to compare with.
        assert_ne!(r.status, CheckStatus::Ok);
        assert!(r.code != "TIMEZONE_MATCH");
    }
}
