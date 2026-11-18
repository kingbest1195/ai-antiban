use crate::auditor::geo_matrix::{CheckResult, GUIDE_OS_PRIVACY, UnknownReason};
use crate::auditor::seams::{RealSystem, SystemInfo, SystemReadError};

/// Two zones whose current UTC offsets differ by no more than this are the same "time" for the
/// purpose of the check (the same offset under different IANA names, a neighbouring zone).
pub const TZ_OFFSET_TOLERANCE_SECS: i32 = 3600;

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
    RUSSIAN_TIMEZONES
        .iter()
        .any(|&item| item.eq_ignore_ascii_case(tz))
}

/// `"+01:00"` style label of an offset.
fn format_offset(secs: i32) -> String {
    let sign = if secs < 0 { '-' } else { '+' };
    let abs = secs.abs();
    format!("UTC{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60)
}

/// Whether the system zone and the zone of the exit IP are close enough: the same name, or
/// current UTC offsets within [`TZ_OFFSET_TOLERANCE_SECS`]. `None`: the offsets are not known and
/// the names differ, so nothing can be claimed.
fn zones_match(
    system: &dyn SystemInfo,
    system_tz: &str,
    ip_tz: &str,
) -> (bool, Option<(i32, i32)>) {
    if system_tz.eq_ignore_ascii_case(ip_tz)
        || system_tz.replace('_', " ") == ip_tz.replace('_', " ")
    {
        return (true, None);
    }
    let local = system
        .local_utc_offset_secs()
        .or_else(|| system.zone_utc_offset_secs(system_tz));
    match (local, system.zone_utc_offset_secs(ip_tz)) {
        (Some(a), Some(b)) => ((a - b).abs() <= TZ_OFFSET_TOLERANCE_SECS, Some((a, b))),
        // Offsets unknown (no time zone database on this OS): different names count as different.
        _ => (false, None),
    }
}

fn format_ai_tz_synced_message(
    system_tz: &str,
    synced_clean: Option<&str>,
    ip_tz: Option<&str>,
) -> String {
    match (synced_clean, ip_tz) {
        (Some(synced), Some(target)) if !synced.eq_ignore_ascii_case(target) => format!(
            "Часовой пояс для AI-окружения ({synced}) и локаль синхронизированы для CLI, IDE и десктопных приложений (пояс узла провайдера: {target}); системный пояс ОС ({system_tz}) требуется менять только опционально для веб-браузеров."
        ),
        (Some(synced), _) => format!(
            "Часовой пояс для AI-окружения ({synced}) и локаль синхронизированы для CLI, IDE и десктопных приложений; системный пояс ОС ({system_tz}) требуется менять только опционально для веб-браузеров."
        ),
        (None, _) => format!(
            "Часовой пояс для AI-окружения и локаль синхронизированы для CLI, IDE и десктопных приложений; системный пояс ОС ({system_tz}) требуется менять только опционально для веб-браузеров."
        ),
    }
}

/// Evaluates whether system timezone exposes user's actual location.
pub fn evaluate_system_timezone(
    ip_timezone: Option<&str>,
    synced_ai_tz: Option<&str>,
) -> CheckResult {
    evaluate_system_timezone_with(&RealSystem, ip_timezone, synced_ai_tz)
}

/// [`evaluate_system_timezone`] through `system` (injectable for tests).
pub fn evaluate_system_timezone_with(
    system: &dyn SystemInfo,
    ip_timezone: Option<&str>,
    synced_ai_tz: Option<&str>,
) -> CheckResult {
    evaluate_system_timezone_with_sync(system, ip_timezone, synced_ai_tz, false)
}

/// Evaluates OS timezone vs provider exit IP timezone, treating active AI environment timezone
/// sync (`cli_synced_to_ip`, or `sync_ai_tz_enabled && system.sync_ai_tz_active()`) as `Ok`
/// (`TIMEZONE_SYNCED_AI`) for CLI, IDE, and desktop apps even when providers use different routes.
pub fn evaluate_system_timezone_with_sync(
    system: &dyn SystemInfo,
    ip_timezone: Option<&str>,
    synced_ai_tz: Option<&str>,
    sync_ai_tz_enabled: bool,
) -> CheckResult {
    let system_tz = match system.system_timezone() {
        Ok(tz) if !tz.trim().is_empty() => tz,
        _ => {
            return CheckResult::unknown(
                "TIMEZONE_UNKNOWN",
                "Часовой пояс не проверен: системный часовой пояс ОС не определен.",
                UnknownReason::NoData,
            );
        }
    };
    let ip_tz = ip_timezone.map(str::trim).filter(|t| !t.is_empty());
    let synced_clean = synced_ai_tz.map(str::trim).filter(|t| !t.is_empty());

    let cli_synced_to_ip = match (ip_tz, synced_clean) {
        (Some(target), Some(synced)) => {
            let synced_matches_ip = synced.eq_ignore_ascii_case(target)
                || synced.replace('_', " ") == target.replace('_', " ");
            synced_matches_ip && system.sync_ai_tz_active()
        }
        _ => false,
    };
    let ai_tz_synced = cli_synced_to_ip || (sync_ai_tz_enabled && system.sync_ai_tz_active());

    // 1. Check if OS system timezone is in Russia or Belarus.
    if is_russian_or_belarusian_timezone(&system_tz) {
        if ai_tz_synced {
            return CheckResult::ok(
                "TIMEZONE_SYNCED_AI",
                format_ai_tz_synced_message(&system_tz, synced_clean, ip_tz),
            );
        }
        return CheckResult::warning(
            "TIMEZONE_LEAK_RU",
            format!(
                "Системный часовой пояс ОС ({system_tz}) указывает на РФ/РБ. Браузеры и десктопный Claude видят эту зону даже через VPN.",
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        );
    }

    // 2. Nothing to compare with: the geolocation source gave no time zone for the exit IP.
    let Some(target) = ip_tz else {
        return CheckResult::unknown(
            "TZ_NO_IP_DATA",
            format!(
                "Часовой пояс не сопоставлен: источник геолокации не передал часовой пояс IP (системный: {system_tz})."
            ),
            UnknownReason::NoData,
        );
    };

    // 3. Compare the real OS timezone against the IP time zone.
    match zones_match(system, &system_tz, target) {
        (true, offsets) => {
            let detail = match offsets {
                Some((a, b)) => format!(
                    "{system_tz} ({}) и пояс IP {target} ({}) различаются не более чем на 1 ч",
                    format_offset(a),
                    format_offset(b)
                ),
                None => format!("{system_tz} совпадает с поясом IP ({target})"),
            };
            CheckResult::ok(
                "TIMEZONE_MATCH",
                format!("Системный часовой пояс: {detail}."),
            )
        }
        (false, offsets) => {
            if ai_tz_synced {
                return CheckResult::ok(
                    "TIMEZONE_SYNCED_AI",
                    format_ai_tz_synced_message(&system_tz, synced_clean, Some(target)),
                );
            }
            let detail = match offsets {
                Some((a, b)) => format!(" ({} против {})", format_offset(a), format_offset(b)),
                None => String::new(),
            };
            CheckResult::warning(
                "TIMEZONE_MISMATCH",
                format!(
                    "Часовой пояс ОС ({system_tz}) отличается от таймзоны IP ({target}){detail}. Для максимального траста рекомендуется синхронизировать пояс с локацией сервера.",
                ),
                Some(GUIDE_OS_PRIVACY.to_string()),
            )
        }
    }
}

use crate::core::sanctions::is_sanctioned_locale;

/// Locale variables of this process that are read to look for a Russian / Belarusian marker
/// (detection only: Zastava never exports `LC_ALL`, see `sysproxy`).
const LOCALE_ENV_READ: [&str; 2] = ["LANG", "LC_ALL"];

/// Evaluates Gate 12: Locale & Environment Hygiene.
/// Looks at the locale variables of this process (read only: Zastava never exports `LC_ALL`) and at
/// the locale of the OS user settings (macOS `AppleLocale` / `AppleLanguages`, Windows regional
/// settings): an application started from the Dock has no `LANG`, so the environment alone says
/// nothing.
///
/// The override Zastava puts into the AI tools' environment (`LANG` and `LC_TIME` =
/// `en_US.UTF-8`) counts only while the independent time zone / locale switch is on and applied;
/// with the switch off the host locale decides, as if Zastava did nothing.
pub fn evaluate_locale_env_hygiene(synced_ai_tz: Option<&str>) -> CheckResult {
    evaluate_locale_env_hygiene_with(&RealSystem, synced_ai_tz)
}

/// [`evaluate_locale_env_hygiene`] through `system` (injectable for tests).
pub fn evaluate_locale_env_hygiene_with(
    system: &dyn SystemInfo,
    synced_ai_tz: Option<&str>,
) -> CheckResult {
    // The override of the AI tools' environment is real only while the switch is on and applied.
    if synced_ai_tz.is_some() && system.sync_ai_tz_active() {
        return CheckResult::ok(
            "LOCALE_HYGIENE_CLEAN",
            "Окружение ИИ-инструментов (Claude, Gemini, терминал IDE): Застава задаёт LANG и LC_TIME = en_US.UTF-8 (подмена часового пояса и локали включена). Локаль ОС для браузеров и приложений не менялась.",
        );
    }

    let env_values: Vec<(String, String)> = LOCALE_ENV_READ
        .iter()
        .filter_map(|name| {
            system
                .env_var(name)
                .map(|v| (name.to_string(), v))
                .filter(|(_, v)| !v.trim().is_empty())
        })
        .collect();
    let os_locales = system.os_locales();
    evaluate_locale_values(&env_values, os_locales)
}

/// The decision of [`evaluate_locale_env_hygiene`] for already read values.
fn evaluate_locale_values(
    env_values: &[(String, String)],
    os_locales: Result<Vec<String>, SystemReadError>,
) -> CheckResult {
    let os_list: &[String] = os_locales.as_deref().unwrap_or(&[]);
    if env_values.is_empty() && os_list.is_empty() {
        let (code, text, reason) = match os_locales {
            Err(SystemReadError::Unsupported) => (
                "LOCALE_ENV_NOT_SET",
                "Локаль не проверена: в окружении Заставы не задана локаль (LANG), а языковые настройки ОС на этой системе не читаются.",
                UnknownReason::NoData,
            ),
            _ => (
                "LOCALE_NOT_READ",
                "Локаль не проверена: переменная LANG не задана, языковые настройки ОС прочитать не удалось.",
                UnknownReason::NoData,
            ),
        };
        return CheckResult::unknown(code, text, reason);
    }

    let bad = env_values
        .iter()
        .map(|(name, v)| (format!("{name}={v}"), v.as_str()))
        .chain(os_list.iter().map(|v| (format!("язык ОС {v}"), v.as_str())))
        .find(|(_, v)| is_sanctioned_locale(v));
    if let Some((label, _)) = bad {
        return CheckResult::warning(
            "LOCALE_ENV_SANCTIONED_MARKER",
            format!(
                "Обнаружена локаль РФ/РБ ({label}). ИИ-агенты в терминале могут передавать этот заголовок. Нажмите «Авто-настройка TZ/локали» для безопасной синхронизации (en_US.UTF-8)."
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        );
    }

    let mut read = Vec::new();
    if !env_values.is_empty() {
        read.push("локаль процесса (LANG, LC_*)".to_string());
    }
    if !os_list.is_empty() {
        read.push(format!("языковые настройки ОС ({})", os_list.join(", ")));
    }
    CheckResult::ok(
        "LOCALE_HYGIENE_CLEAN",
        format!(
            "Маркеров РФ/РБ нет в проверенных источниках: {}.",
            read.join("; ")
        ),
    )
}

/// Checks OS Location Services status (BSSID Wi-Fi triangulation).
/// Only Windows exposes a setting that can be read; elsewhere the check does not apply.
pub fn check_os_location_services() -> CheckResult {
    check_os_location_services_with(&RealSystem)
}

/// [`check_os_location_services`] through `system` (injectable for tests).
pub fn check_os_location_services_with(system: &dyn SystemInfo) -> CheckResult {
    let machine = match system.location_consent(true) {
        Ok(text) => text,
        Err(SystemReadError::Unsupported) => {
            return CheckResult::unknown(
                "OS_LOCATION_NOT_APPLICABLE",
                "Геолокация ОС по Wi-Fi (BSSID) на этой системе не проверяется: состояние службы геолокации не читается.",
                UnknownReason::NotApplicable,
            );
        }
        Err(SystemReadError::Failed) => return location_unreadable(),
    };

    // Machine-wide policy first: Deny turns the location services off for everybody.
    if machine.contains("Deny") {
        return CheckResult::ok(
            "OS_LOCATION_SAFE",
            "Геолокация Windows запрещена на уровне компьютера (ConsentStore HKLM = Deny).",
        );
    }
    if !machine.contains("Allow") {
        return CheckResult::unknown(
            "OS_LOCATION_NO_DATA",
            "Геолокация Windows не проверена: настройка компьютера не содержит значения Allow или Deny.",
            UnknownReason::NoData,
        );
    }

    // The computer allows it: the user's own switch decides.
    match system.location_consent(false) {
        Ok(user) if user.contains("Allow") => CheckResult::warning(
            "OS_LOCATION_ENABLED",
            "Службы геолокации Windows активны. Отключите их в настройках конфиденциальности ОС.",
            Some(GUIDE_OS_PRIVACY.to_string()),
        ),
        Ok(user) if user.contains("Deny") => CheckResult::ok(
            "OS_LOCATION_SAFE",
            "Геолокация Windows запрещена в настройках пользователя (ConsentStore HKCU = Deny).",
        ),
        Ok(_) => CheckResult::unknown(
            "OS_LOCATION_NO_DATA",
            "Геолокация Windows не проверена: настройка пользователя не содержит значения Allow или Deny.",
            UnknownReason::NoData,
        ),
        Err(_) => location_unreadable(),
    }
}

fn location_unreadable() -> CheckResult {
    CheckResult::unknown(
        "OS_LOCATION_UNREADABLE",
        "Геолокация Windows не проверена: не удалось прочитать настройку службы геолокации.",
        UnknownReason::InternalError,
    )
}

#[cfg(test)]
#[path = "os_env_tests.rs"]
mod tests;
