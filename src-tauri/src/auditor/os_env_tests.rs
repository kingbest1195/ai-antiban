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
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::NoData))
    );
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
    assert_eq!(
        evaluate_system_timezone_with(&s, Some("Europe/London"), None).status,
        CheckStatus::Ok
    );
    assert_eq!(
        evaluate_system_timezone_with(&s, Some("Europe/Helsinki"), None).status,
        CheckStatus::Ok
    );
    let r = evaluate_system_timezone_with(&s, Some("Asia/Dubai"), None);
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "TIMEZONE_MISMATCH")
    );
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
fn tz_synced_ai_env_returns_ok_for_cli_ide_and_desktop_even_with_mismatched_or_ru_os_tz() {
    let far = |applied: bool| FakeSystem {
        timezone: Ok("Asia/Tokyo".into()),
        local_offset: Some(9 * 3600),
        sync_ai_tz: applied,
        ..sys()
    };
    // Applied AI env TZ sync while OS TZ is still mismatched: Ok (OS TZ is optional for web).
    let r = evaluate_system_timezone_with(
        &far(true),
        Some("Europe/Amsterdam"),
        Some("Europe/Amsterdam"),
    );
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Ok, "TIMEZONE_SYNCED_AI")
    );
    assert!(r.message.contains("Asia/Tokyo"), "{}", r.message);
    assert!(
        r.message.contains("CLI, IDE и десктопных приложений"),
        "{}",
        r.message
    );
    assert!(r.message.contains("веб-браузеров"), "{}", r.message);

    // Only remembered in settings, active sync is false: plain mismatch.
    let r = evaluate_system_timezone_with(
        &far(false),
        Some("Europe/Amsterdam"),
        Some("Europe/Amsterdam"),
    );
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "TIMEZONE_MISMATCH")
    );
    // Synced to a different zone without sync_ai_tz_enabled flag: plain mismatch.
    let r = evaluate_system_timezone_with(
        &far(true),
        Some("Europe/Amsterdam"),
        Some("America/New_York"),
    );
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "TIMEZONE_MISMATCH")
    );

    // With sync_ai_tz_enabled=true & sync_ai_tz_active=true: cross-route provider ip_tz (Paris vs London)
    // or None synced_ai_tz still yields Ok("TIMEZONE_SYNCED_AI").
    let r_cross = evaluate_system_timezone_with_sync(
        &far(true),
        Some("Europe/Paris"),
        Some("Europe/London"),
        true,
    );
    assert_eq!(
        (r_cross.status, r_cross.code.as_str()),
        (CheckStatus::Ok, "TIMEZONE_SYNCED_AI")
    );
    let r_no_hint =
        evaluate_system_timezone_with_sync(&far(true), Some("Europe/Paris"), None, true);
    assert_eq!(
        (r_no_hint.status, r_no_hint.code.as_str()),
        (CheckStatus::Ok, "TIMEZONE_SYNCED_AI")
    );

    // OS TZ is RU + AI TZ synced -> Ok("TIMEZONE_SYNCED_AI"), never Warning.
    let ru = |applied: bool| FakeSystem {
        timezone: Ok("Europe/Moscow".into()),
        local_offset: Some(3 * 3600),
        sync_ai_tz: applied,
        ..sys()
    };
    let ru_synced = evaluate_system_timezone_with(
        &ru(true),
        Some("Europe/Amsterdam"),
        Some("Europe/Amsterdam"),
    );
    assert_eq!(
        (ru_synced.status, ru_synced.code.as_str()),
        (CheckStatus::Ok, "TIMEZONE_SYNCED_AI")
    );
    assert!(
        ru_synced.message.contains("Europe/Moscow"),
        "{}",
        ru_synced.message
    );
    assert!(
        ru_synced.message.contains("веб-браузеров"),
        "{}",
        ru_synced.message
    );

    let ru_cross = evaluate_system_timezone_with_sync(
        &ru(true),
        Some("Europe/Paris"),
        Some("Europe/London"),
        true,
    );
    assert_eq!(
        (ru_cross.status, ru_cross.code.as_str()),
        (CheckStatus::Ok, "TIMEZONE_SYNCED_AI")
    );

    assert_eq!(
        evaluate_system_timezone_with(
            &ru(false),
            Some("Europe/Amsterdam"),
            Some("Europe/Amsterdam")
        )
        .code,
        "TIMEZONE_LEAK_RU"
    );
    assert_eq!(
        evaluate_system_timezone_with_sync(
            &ru(false),
            Some("Europe/Amsterdam"),
            Some("Europe/Amsterdam"),
            true
        )
        .code,
        "TIMEZONE_LEAK_RU"
    );

    // OS TZ itself matches IP TZ -> Ok!
    let matched = evaluate_system_timezone_with(
        &sys(),
        Some("Europe/Amsterdam"),
        Some("Europe/Amsterdam"),
    );
    assert_eq!(
        (matched.status, matched.code.as_str()),
        (CheckStatus::Ok, "TIMEZONE_MATCH")
    );
}

// ---- locale ----

fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn locale_nothing_readable_is_unknown() {
    let r = evaluate_locale_values(&[], Err(SystemReadError::Failed));
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::NoData))
    );
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
    assert_eq!(
        evaluate_locale_env_hygiene_with(&en_ru, None).status,
        CheckStatus::Warning
    );
}

#[test]
fn locale_env_and_os_both_clean_is_ok_and_names_its_sources() {
    let r = evaluate_locale_env_hygiene_with(&sys(), None);
    assert_eq!(r.status, CheckStatus::Ok);
    assert!(
        r.message.contains("локаль процесса") && r.message.contains("en_US"),
        "{}",
        r.message
    );
    // The OS source alone is enough to say something, and the text says only that.
    let s = FakeSystem {
        env: HashMap::new(),
        ..sys()
    };
    let r = evaluate_locale_env_hygiene_with(&s, None);
    assert_eq!(r.status, CheckStatus::Ok);
    assert!(!r.message.contains("локаль процесса"), "{}", r.message);
    // A Russian LANG in the environment is still a warning.
    let ru = evaluate_locale_values(&env(&[("LANG", "ru_RU.UTF-8")]), Ok(vec![]));
    assert_eq!(ru.status, CheckStatus::Warning);
}

#[test]
fn locale_synced_override_is_ok_only_when_applied() {
    let ru_host = |applied: bool| FakeSystem {
        env: HashMap::new(),
        os_locales: Ok(vec!["ru_RU".into()]),
        sync_ai_tz: applied,
        ..sys()
    };
    let r = evaluate_locale_env_hygiene_with(&ru_host(true), Some("Europe/Amsterdam"));
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Ok, "LOCALE_HYGIENE_CLEAN")
    );
    // Remembered, but not applied: the system locale decides.
    let r = evaluate_locale_env_hygiene_with(&ru_host(false), Some("Europe/Amsterdam"));
    assert_eq!(r.status, CheckStatus::Warning);
    // Nothing synced: the system locale decides.
    assert_eq!(
        evaluate_locale_env_hygiene_with(&ru_host(true), None).status,
        CheckStatus::Warning
    );
}

#[test]
fn locale_tag_recognition() {
    for yes in [
        "ru_RU.UTF-8",
        "RU-ru",
        "be_BY",
        "be-BY",
        "en_RU",
        "en-RU",
        "en_US@rg=ruzzzz",
        "de_BY.UTF-8",
    ] {
        assert!(is_sanctioned_locale(yes), "{yes}");
    }
    for no in [
        "en_US.UTF-8",
        "en-US",
        "C",
        "POSIX",
        "",
        "  ",
        "de_DE",
        "pt_BR",
        "ru_UA",
    ] {
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
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Ok, "OS_LOCATION_SAFE")
    );
    let r = check_os_location_services_with(&win(allow, Ok(allow)));
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "OS_LOCATION_ENABLED")
    );
    let r = check_os_location_services_with(&win(allow, Ok(deny)));
    assert_eq!(r.status, CheckStatus::Ok);
    assert!(r.message.contains("HKCU"));
    // Unreadable pieces are never "safe".
    let r = check_os_location_services_with(&win(allow, Err(SystemReadError::Failed)));
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::InternalError))
    );
    let r = check_os_location_services_with(&win("garbage", Ok(allow)));
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::NoData))
    );
    let failed = FakeSystem {
        consent_machine: Err(SystemReadError::Failed),
        ..sys()
    };
    assert_eq!(
        check_os_location_services_with(&failed).reason,
        Some(UnknownReason::InternalError)
    );
}

// ---- time zone / locale switch (independent of the proxy protection) ----

fn ru_host(sync: bool) -> FakeSystem {
    FakeSystem {
        env: HashMap::new(),
        os_locales: Ok(vec!["ru_RU".into()]),
        sync_ai_tz: sync,
        ..sys()
    }
}

#[test]
fn locale_branches_of_the_synced_override() {
    // On and applied (LANG + LC_TIME): Ok, and the text says what was checked.
    let r = evaluate_locale_env_hygiene_with(&ru_host(true), Some("Europe/Amsterdam"));
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Ok, "LOCALE_HYGIENE_CLEAN")
    );
    assert!(
        r.message.contains("LANG") && r.message.contains("LC_TIME"),
        "{}",
        r.message
    );
    // Switch off or not applied (the seam says no): the host locale decides, with no credit.
    let r = evaluate_locale_env_hygiene_with(&ru_host(false), Some("Europe/Amsterdam"));
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Warning, "LOCALE_ENV_SANCTIONED_MARKER")
    );
    // No zone synced at all: the same.
    assert_eq!(
        evaluate_locale_env_hygiene_with(&ru_host(true), None).status,
        CheckStatus::Warning
    );
    // A clean host stays Ok with the switch off, and says what it read.
    let clean = FakeSystem {
        sync_ai_tz: false,
        ..sys()
    };
    let r = evaluate_locale_env_hygiene_with(&clean, Some("Europe/Amsterdam"));
    assert_eq!(r.status, CheckStatus::Ok);
    // Nothing readable is Unknown, not Ok.
    let offline = FakeSystem::offline();
    let r = evaluate_locale_env_hygiene_with(&offline, Some("Europe/Amsterdam"));
    assert_eq!(r.status, CheckStatus::Unknown);
}

#[test]
fn no_text_of_the_locale_or_time_zone_checks_mentions_lc_all_or_the_proxy_protection() {
    let mut texts = Vec::new();
    for sync in [true, false] {
        for host in [
            ru_host(sync),
            FakeSystem {
                sync_ai_tz: sync,
                ..sys()
            },
            FakeSystem::offline(),
        ] {
            texts.push(
                evaluate_locale_env_hygiene_with(&host, Some("Europe/Amsterdam")).message,
            );
            texts.push(evaluate_locale_env_hygiene_with(&host, None).message);
        }
    }
    let far = FakeSystem {
        timezone: Ok("Asia/Tokyo".into()),
        local_offset: Some(9 * 3600),
        sync_ai_tz: true,
        ..sys()
    };
    texts.push(
        evaluate_system_timezone_with(&far, Some("Europe/Amsterdam"), Some("Europe/Amsterdam"))
            .message,
    );
    for t in texts {
        assert!(!t.contains("LC_ALL"), "{t}");
        assert!(!t.contains("защита терминала и IDE"), "{t}");
    }
}

#[test]
fn the_synced_zone_note_follows_the_switch_and_returns_ok_when_active() {
    let far = |sync: bool| FakeSystem {
        timezone: Ok("Asia/Tokyo".into()),
        local_offset: Some(9 * 3600),
        sync_ai_tz: sync,
        ..sys()
    };
    let synced_ai = evaluate_system_timezone_with(
        &far(true),
        Some("Europe/Amsterdam"),
        Some("Europe/Amsterdam"),
    );
    assert_eq!(
        (synced_ai.status, synced_ai.code.as_str()),
        (CheckStatus::Ok, "TIMEZONE_SYNCED_AI")
    );
    assert!(
        synced_ai.message.contains("синхронизированы"),
        "{}",
        synced_ai.message
    );
    let off = evaluate_system_timezone_with(
        &far(false),
        Some("Europe/Amsterdam"),
        Some("Europe/Amsterdam"),
    );
    assert_eq!(
        (off.status, off.code.as_str()),
        (CheckStatus::Warning, "TIMEZONE_MISMATCH")
    );
}
