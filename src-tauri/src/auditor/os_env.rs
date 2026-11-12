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
    RUSSIAN_TIMEZONES.iter().any(|&item| item.eq_ignore_ascii_case(tz))
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
    if system_tz.eq_ignore_ascii_case(ip_tz) || system_tz.replace('_', " ") == ip_tz.replace('_', " ")
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

/// Evaluates whether system timezone exposes user's actual location.
pub fn evaluate_system_timezone(
    ip_timezone: Option<&str>,
    synced_ai_tz: Option<&str>,
) -> CheckResult {
    evaluate_system_timezone_with(&RealSystem, ip_timezone, synced_ai_tz)
}

/// [`evaluate_system_timezone`] through `system` (injectable for tests).
///
/// The OS zone is compared with the zone of the exit IP by UTC offset (1 h tolerance). If the OS
/// zone differs, but the zone synced for the AI tools equals the IP zone *and* the CLI/IDE
/// protection that applies it is active, requests of those tools are covered.
pub fn evaluate_system_timezone_with(
    system: &dyn SystemInfo,
    ip_timezone: Option<&str>,
    synced_ai_tz: Option<&str>,
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

    // The synced zone counts only when it is actually applied (the protection is on), not merely
    // remembered in the settings.
    if let (Some(target), Some(synced)) = (ip_tz, synced_ai_tz.map(str::trim)) {
        let synced_matches_ip =
            synced.eq_ignore_ascii_case(target) || synced.replace('_', " ") == target.replace('_', " ");
        if synced_matches_ip
            && !zones_match(system, &system_tz, target).0
            && system.cli_protection_active()
        {
            return CheckResult::ok(
                "TIMEZONE_SYNCED_AI",
                format!(
                    "Таймзона для ИИ-агентов (CLI/IDE) = {target}: применена через Заставу (защита терминала и IDE включена). Системный пояс ОС ({system_tz}) не менялся: браузеры и десктопные приложения видят его."
                ),
            );
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

    // 3. Compare against the IP time zone.
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

/// Whether a locale tag (`ru_RU.UTF-8`, `ru-RU`, `en_RU`, `en_US@rg=ruzzzz`) points at Russia or
/// Belarus.
fn is_sanctioned_locale(raw: &str) -> bool {
    let v = raw.trim().to_ascii_uppercase();
    if v.is_empty() {
        return false;
    }
    if v.contains("RU_RU") || v.contains("BE_BY") || v.starts_with("RU-") || v.starts_with("BE-") {
        return true;
    }
    // macOS region override: "en_US@rg=ruzzzz".
    if v.contains("@RG=RU") || v.contains("@RG=BY") {
        return true;
    }
    // Language with a Russian or Belarusian region: "en_RU", "en-RU", "de-BY.UTF-8".
    let base = v.split(['.', '@']).next().unwrap_or_default();
    let mut parts = base.split(['_', '-']);
    let _language = parts.next();
    matches!(parts.next(), Some("RU" | "BY"))
}

/// Evaluates Gate 12: Locale & Environment Hygiene.
/// Looks at `LANG` / `LC_ALL` of this process and at the locale of the OS user settings
/// (macOS `AppleLocale` / `AppleLanguages`, Windows regional settings): an application started
/// from the Dock has no `LANG`, so the environment alone says nothing.
pub fn evaluate_locale_env_hygiene(synced_ai_tz: Option<&str>) -> CheckResult {
    evaluate_locale_env_hygiene_with(&RealSystem, synced_ai_tz)
}

/// [`evaluate_locale_env_hygiene`] through `system` (injectable for tests).
pub fn evaluate_locale_env_hygiene_with(
    system: &dyn SystemInfo,
    synced_ai_tz: Option<&str>,
) -> CheckResult {
    // The override of the CLI/IDE environment is real only while the protection is active.
    if synced_ai_tz.is_some() && system.cli_protection_active() {
        return CheckResult::ok(
            "LOCALE_HYGIENE_CLEAN",
            "Окружение CLI/IDE: Застава переопределяет локаль на en_US.UTF-8 (защита терминала и IDE включена). Локаль ОС для браузеров и приложений не менялась.",
        );
    }

    let env_values: Vec<(String, String)> = ["LANG", "LC_ALL"]
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
                "Локаль не проверена: в окружении Заставы не заданы LANG и LC_ALL, а языковые настройки ОС на этой системе не читаются.",
                UnknownReason::NoData,
            ),
            _ => (
                "LOCALE_NOT_READ",
                "Локаль не проверена: LANG и LC_ALL не заданы, языковые настройки ОС прочитать не удалось.",
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
        read.push("LANG/LC_ALL процесса".to_string());
    }
    if !os_list.is_empty() {
        read.push(format!("языковые настройки ОС ({})", os_list.join(", ")));
    }
    CheckResult::ok(
        "LOCALE_HYGIENE_CLEAN",
        format!("Маркеров РФ/РБ нет в проверенных источниках: {}.", read.join("; ")),
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
mod tests {
    use super::*;
    use crate::auditor::geo_matrix::CheckStatus;
    use crate::auditor::seams::fakes::FakeSystem;
    use std::collections::HashMap;

    fn sys() -> FakeSystem {
        FakeSystem::healthy()
    }

    #[test]
    fn test_russian_timezone_detection() {
        assert!(is_russian_or_belarusian_timezone("Europe/Moscow"));
        assert!(is_russian_or_belarusian_timezone("europe/moscow"));
        assert!(is_russian_or_belarusian_timezone("Asia/Vladivostok"));
        assert!(is_russian_or_belarusian_timezone("Europe/Minsk"));
        assert!(!is_russian_or_belarusian_timezone("Europe/Amsterdam"));
        assert!(!is_russian_or_belarusian_timezone("America/New_York"));
    }

    // ---- time zone ----

    #[test]
    fn tz_err_from_the_os_is_unknown() {
        let s = FakeSystem {
            timezone: Err("boom".into()),
            ..sys()
        };
        let r = evaluate_system_timezone_with(&s, Some("Europe/Amsterdam"), None);
        assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(UnknownReason::NoData)));
        assert_eq!(r.code, "TIMEZONE_UNKNOWN");
    }

    #[test]
    fn tz_without_ip_zone_is_unknown_never_a_match() {
        for none in [None, Some(""), Some("  ")] {
            let r = evaluate_system_timezone_with(&sys(), none, None);
            assert_eq!(r.status, CheckStatus::Unknown, "{none:?}");
            assert_eq!(r.code, "TZ_NO_IP_DATA");
        }
        // A Russian system zone is still a finding without IP data.
        let ru = FakeSystem {
            timezone: Ok("Europe/Moscow".into()),
            ..sys()
        };
        assert_eq!(
            evaluate_system_timezone_with(&ru, None, None).status,
            CheckStatus::Warning
        );
    }

    #[test]
    fn tz_aliases_with_the_same_offset_are_ok() {
        // Europe/Amsterdam vs Europe/Berlin: different names, the same offset (regression: false Warning).
        let r = evaluate_system_timezone_with(&sys(), Some("Europe/Berlin"), None);
        assert_eq!(r.status, CheckStatus::Ok);
        assert_eq!(r.code, "TIMEZONE_MATCH");
        assert!(r.message.contains("UTC+01:00"), "{}", r.message);
        // The same name needs no offsets at all.
        let no_offsets = FakeSystem {
            local_offset: None,
            zone_offsets: HashMap::new(),
            ..sys()
        };
        assert_eq!(
            evaluate_system_timezone_with(&no_offsets, Some("europe/amsterdam"), None).status,
            CheckStatus::Ok
        );
    }

    #[test]
    fn tz_tolerance_is_one_hour() {
        let mut s = sys();
        s.zone_offsets.insert("Europe/London".into(), 0); // 1 h away: inside
        s.zone_offsets.insert("Europe/Helsinki".into(), 7200); // 1 h away: inside
        s.zone_offsets.insert("Asia/Dubai".into(), 4 * 3600); // 3 h away: outside
        assert_eq!(evaluate_system_timezone_with(&s, Some("Europe/London"), None).status, CheckStatus::Ok);
        assert_eq!(evaluate_system_timezone_with(&s, Some("Europe/Helsinki"), None).status, CheckStatus::Ok);
        let r = evaluate_system_timezone_with(&s, Some("Asia/Dubai"), None);
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Warning, "TIMEZONE_MISMATCH"));
        assert!(r.message.contains("UTC+04:00"), "{}", r.message);
    }

    #[test]
    fn tz_unknown_offsets_and_different_names_stay_a_warning() {
        let s = FakeSystem {
            local_offset: None,
            zone_offsets: HashMap::new(),
            ..sys()
        };
        let r = evaluate_system_timezone_with(&s, Some("Europe/Berlin"), None);
        assert_eq!(r.status, CheckStatus::Warning);
    }

    #[test]
    fn tz_synced_zone_counts_only_when_applied() {
        let far = |applied: bool| FakeSystem {
            timezone: Ok("Asia/Tokyo".into()),
            local_offset: Some(9 * 3600),
            cli_protection: applied,
            ..sys()
        };
        // Applied: Ok, even though the OS zone is far from the IP zone.
        let r = evaluate_system_timezone_with(&far(true), Some("Europe/Amsterdam"), Some("Europe/Amsterdam"));
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "TIMEZONE_SYNCED_AI"));
        // Only remembered in the settings, the protection is off: a plain mismatch.
        let r = evaluate_system_timezone_with(&far(false), Some("Europe/Amsterdam"), Some("Europe/Amsterdam"));
        assert_eq!(r.status, CheckStatus::Warning);
        // Synced to a zone that is not the IP zone: no cover.
        let r = evaluate_system_timezone_with(&far(true), Some("Europe/Amsterdam"), Some("America/New_York"));
        assert_eq!(r.status, CheckStatus::Warning);
        // A Russian OS zone is covered only by an applied sync too.
        let ru = |applied: bool| FakeSystem {
            timezone: Ok("Europe/Moscow".into()),
            local_offset: Some(3 * 3600),
            cli_protection: applied,
            ..sys()
        };
        assert_eq!(
            evaluate_system_timezone_with(&ru(true), Some("Europe/Amsterdam"), Some("Europe/Amsterdam")).status,
            CheckStatus::Ok
        );
        assert_eq!(
            evaluate_system_timezone_with(&ru(false), Some("Europe/Amsterdam"), Some("Europe/Amsterdam")).code,
            "TIMEZONE_LEAK_RU"
        );
    }

    // ---- locale ----

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn locale_nothing_readable_is_unknown() {
        let r = evaluate_locale_values(&[], Err(SystemReadError::Failed));
        assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(UnknownReason::NoData)));
        assert_eq!(r.code, "LOCALE_NOT_READ");
        let r = evaluate_locale_values(&[], Err(SystemReadError::Unsupported));
        assert_eq!(r.code, "LOCALE_ENV_NOT_SET");
        assert_eq!(r.status, CheckStatus::Unknown);
    }

    #[test]
    fn locale_empty_env_with_apple_locale_ru_is_a_warning() {
        // The Dock-launched app has no LANG, but the macOS user locale is Russian.
        let s = FakeSystem {
            env: HashMap::new(),
            os_locales: Ok(vec!["ru_RU".into(), "ru-RU".into(), "en-RU".into()]),
            ..sys()
        };
        let r = evaluate_locale_env_hygiene_with(&s, None);
        assert_eq!(r.status, CheckStatus::Warning);
        assert_eq!(r.code, "LOCALE_ENV_SANCTIONED_MARKER");
        assert!(r.message.contains("язык ОС"), "{}", r.message);
        // Only the region says Russia.
        let en_ru = FakeSystem {
            env: HashMap::new(),
            os_locales: Ok(vec!["en_RU".into()]),
            ..sys()
        };
        assert_eq!(evaluate_locale_env_hygiene_with(&en_ru, None).status, CheckStatus::Warning);
    }

    #[test]
    fn locale_env_and_os_both_clean_is_ok_and_names_its_sources() {
        let r = evaluate_locale_env_hygiene_with(&sys(), None);
        assert_eq!(r.status, CheckStatus::Ok);
        assert!(r.message.contains("LANG/LC_ALL") && r.message.contains("en_US"), "{}", r.message);
        // The OS source alone is enough to say something, and the text says only that.
        let s = FakeSystem {
            env: HashMap::new(),
            ..sys()
        };
        let r = evaluate_locale_env_hygiene_with(&s, None);
        assert_eq!(r.status, CheckStatus::Ok);
        assert!(!r.message.contains("LANG/LC_ALL"), "{}", r.message);
        // A Russian LANG in the environment is still a warning.
        let ru = evaluate_locale_values(&env(&[("LANG", "ru_RU.UTF-8")]), Ok(vec![]));
        assert_eq!(ru.status, CheckStatus::Warning);
    }

    #[test]
    fn locale_synced_override_is_ok_only_when_applied() {
        let ru_host = |applied: bool| FakeSystem {
            env: HashMap::new(),
            os_locales: Ok(vec!["ru_RU".into()]),
            cli_protection: applied,
            ..sys()
        };
        let r = evaluate_locale_env_hygiene_with(&ru_host(true), Some("Europe/Amsterdam"));
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "LOCALE_HYGIENE_CLEAN"));
        // Remembered, but not applied: the system locale decides.
        let r = evaluate_locale_env_hygiene_with(&ru_host(false), Some("Europe/Amsterdam"));
        assert_eq!(r.status, CheckStatus::Warning);
        // Nothing synced: the system locale decides.
        assert_eq!(evaluate_locale_env_hygiene_with(&ru_host(true), None).status, CheckStatus::Warning);
    }

    #[test]
    fn locale_tag_recognition() {
        for yes in ["ru_RU.UTF-8", "RU-ru", "be_BY", "be-BY", "en_RU", "en-RU", "en_US@rg=ruzzzz", "de_BY.UTF-8"] {
            assert!(is_sanctioned_locale(yes), "{yes}");
        }
        for no in ["en_US.UTF-8", "en-US", "C", "POSIX", "", "  ", "de_DE", "pt_BR", "ru_UA"] {
            assert!(!is_sanctioned_locale(no), "{no}");
        }
    }

    // ---- OS location ----

    #[test]
    fn location_is_not_applicable_where_nothing_can_be_read() {
        let r = check_os_location_services_with(&sys());
        assert!(r.is_not_applicable());
        assert_eq!(r.code, "OS_LOCATION_NOT_APPLICABLE");
        assert!(r.message.contains("Wi-Fi"));
    }

    #[test]
    fn location_windows_branches() {
        let win = |m: &str, u: Result<&str, SystemReadError>| FakeSystem {
            consent_machine: Ok(m.to_string()),
            consent_user: u.map(str::to_string),
            ..sys()
        };
        let allow = "    Value    REG_SZ    Allow";
        let deny = "    Value    REG_SZ    Deny";
        let r = check_os_location_services_with(&win(deny, Ok(allow)));
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "OS_LOCATION_SAFE"));
        let r = check_os_location_services_with(&win(allow, Ok(allow)));
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Warning, "OS_LOCATION_ENABLED"));
        let r = check_os_location_services_with(&win(allow, Ok(deny)));
        assert_eq!(r.status, CheckStatus::Ok);
        assert!(r.message.contains("HKCU"));
        // Unreadable pieces are never "safe".
        let r = check_os_location_services_with(&win(allow, Err(SystemReadError::Failed)));
        assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(UnknownReason::InternalError)));
        let r = check_os_location_services_with(&win("garbage", Ok(allow)));
        assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(UnknownReason::NoData)));
        let failed = FakeSystem {
            consent_machine: Err(SystemReadError::Failed),
            ..sys()
        };
        assert_eq!(check_os_location_services_with(&failed).reason, Some(UnknownReason::InternalError));
    }
}
