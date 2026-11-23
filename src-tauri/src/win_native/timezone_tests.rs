use super::timezone::{
    Win32SystemTimeRule, Win32TzInfo, compute_win_tz_utc_offset_secs, is_service_missing_error,
    utc_offset_secs_from_dtzi,
};
use chrono::{TimeZone, Utc};

#[test]
fn detects_missing_service_from_hresult_hex_decimal_and_english_text() {
    assert!(is_service_missing_error("ERROR (0x80070424)"));
    assert!(is_service_missing_error("ERROR (0X80070424)"));
    assert!(is_service_missing_error(
        "OpenServiceW(CHANGE_CONFIG, tzautoupdate) failed: Указанная служба не установлена. (0x80070424)"
    ));
    assert!(is_service_missing_error("Win32 error 1060"));
    assert!(is_service_missing_error(
        "The specified service does not exist as an installed service."
    ));
    assert!(!is_service_missing_error("Access is denied. (0x80070005)"));
}

#[test]
fn computes_win32_dtzi_utc_offsets_with_correct_sign() {
    // Europe/Berlin: Bias = -60, StandardBias = 0, DaylightBias = -60
    assert_eq!(utc_offset_secs_from_dtzi(1, -60, 0, -60), Some(3600));
    assert_eq!(utc_offset_secs_from_dtzi(2, -60, 0, -60), Some(7200));
    // America/New_York: Bias = +300, StandardBias = 0, DaylightBias = -60
    assert_eq!(utc_offset_secs_from_dtzi(1, 300, 0, -60), Some(-18000));
    assert_eq!(utc_offset_secs_from_dtzi(2, 300, 0, -60), Some(-14400));
    // No DST / unknown
    assert_eq!(utc_offset_secs_from_dtzi(0, -180, 0, 0), Some(10800));
    assert_eq!(utc_offset_secs_from_dtzi(u32::MAX, -60, 0, -60), None);
}

#[test]
fn computes_win32_zone_offsets_across_northern_southern_and_no_dst() {
    let no_dst_rule = Win32SystemTimeRule {
        year: 0,
        month: 0,
        day_of_week: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
    };
    // W. Europe Standard Time (Berlin / Amsterdam): last Sun Mar 02:00 -> last Sun Oct 03:00
    let berlin = Win32TzInfo {
        bias: -60,
        standard_bias: 0,
        daylight_bias: -60,
        daylight_date: Win32SystemTimeRule {
            year: 0,
            month: 3,
            day_of_week: 0,
            day: 5,
            hour: 2,
            minute: 0,
            second: 0,
        },
        standard_date: Win32SystemTimeRule {
            year: 0,
            month: 10,
            day_of_week: 0,
            day: 5,
            hour: 3,
            minute: 0,
            second: 0,
        },
    };
    // 2026-03-29 00:59:59 UTC is 1s before DST starts -> +3600
    assert_eq!(
        compute_win_tz_utc_offset_secs(
            berlin,
            Utc.with_ymd_and_hms(2026, 3, 29, 0, 59, 59).unwrap()
        ),
        Some(3600)
    );
    // 2026-03-29 01:00:00 UTC is DST -> +7200
    assert_eq!(
        compute_win_tz_utc_offset_secs(berlin, Utc.with_ymd_and_hms(2026, 3, 29, 1, 0, 0).unwrap()),
        Some(7200)
    );
    // 2026-10-25 00:59:59 UTC is still DST -> +7200
    assert_eq!(
        compute_win_tz_utc_offset_secs(
            berlin,
            Utc.with_ymd_and_hms(2026, 10, 25, 0, 59, 59).unwrap()
        ),
        Some(7200)
    );
    // 2026-10-25 01:00:00 UTC is back to standard -> +3600
    assert_eq!(
        compute_win_tz_utc_offset_secs(
            berlin,
            Utc.with_ymd_and_hms(2026, 10, 25, 1, 0, 0).unwrap()
        ),
        Some(3600)
    );

    // Southern Hemisphere: Australia/Sydney (1st Sun Oct -> 1st Sun Apr)
    let sydney = Win32TzInfo {
        bias: -600,
        standard_bias: 0,
        daylight_bias: -60,
        daylight_date: Win32SystemTimeRule {
            year: 0,
            month: 10,
            day_of_week: 0,
            day: 1,
            hour: 2,
            minute: 0,
            second: 0,
        },
        standard_date: Win32SystemTimeRule {
            year: 0,
            month: 4,
            day_of_week: 0,
            day: 1,
            hour: 3,
            minute: 0,
            second: 0,
        },
    };
    assert_eq!(
        compute_win_tz_utc_offset_secs(
            sydney,
            Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap()
        ),
        Some(11 * 3600)
    );
    assert_eq!(
        compute_win_tz_utc_offset_secs(
            sydney,
            Utc.with_ymd_and_hms(2026, 7, 15, 12, 0, 0).unwrap()
        ),
        Some(10 * 3600)
    );

    // No-DST zone (Europe/Moscow: UTC+03:00)
    let moscow = Win32TzInfo {
        bias: -180,
        standard_bias: 0,
        daylight_bias: 0,
        standard_date: no_dst_rule,
        daylight_date: no_dst_rule,
    };
    assert_eq!(
        compute_win_tz_utc_offset_secs(
            moscow,
            Utc.with_ymd_and_hms(2026, 7, 15, 12, 0, 0).unwrap()
        ),
        Some(3 * 3600)
    );
}
