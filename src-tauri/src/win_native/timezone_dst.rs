//! Pure-Rust Win32 `TIME_ZONE_INFORMATION` / `DYNAMIC_TIME_ZONE_INFORMATION` UTC offset and DST math.
//!
//! Separated from Win32 FFI calls in [`super::timezone`] so Northern/Southern hemisphere DST
//! transitions and bias sign conversions are unit-tested across all host platforms.

/// Win32 `SYSTEMTIME` transition rule fields used in `TIME_ZONE_INFORMATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32SystemTimeRule {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
}

/// Win32 `TIME_ZONE_INFORMATION` numeric fields for pure-Rust DST and UTC offset evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32TzInfo {
    pub bias: i32,
    pub standard_bias: i32,
    pub daylight_bias: i32,
    pub standard_date: Win32SystemTimeRule,
    pub daylight_date: Win32SystemTimeRule,
}

/// Computes seconds east of UTC from Win32 `GetDynamicTimeZoneInformation` return code and biases.
/// Win32 defines `UTC = local + bias`, so `utc_offset_secs = -(Bias + active_bias) * 60`.
pub fn utc_offset_secs_from_dtzi(
    zone_id: u32,
    bias: i32,
    standard_bias: i32,
    daylight_bias: i32,
) -> Option<i32> {
    const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
    const TIME_ZONE_ID_STANDARD: u32 = 1;
    const TIME_ZONE_ID_INVALID: u32 = u32::MAX;
    if zone_id == TIME_ZONE_ID_INVALID {
        return None;
    }
    let active_bias = match zone_id {
        TIME_ZONE_ID_DAYLIGHT => daylight_bias,
        TIME_ZONE_ID_STANDARD => standard_bias,
        _ => 0,
    };
    bias.checked_add(active_bias)?
        .checked_neg()?
        .checked_mul(60)
}

fn win32_weekday_from_u16(dow: u16) -> Option<chrono::Weekday> {
    match dow {
        0 => Some(chrono::Weekday::Sun),
        1 => Some(chrono::Weekday::Mon),
        2 => Some(chrono::Weekday::Tue),
        3 => Some(chrono::Weekday::Wed),
        4 => Some(chrono::Weekday::Thu),
        5 => Some(chrono::Weekday::Fri),
        6 => Some(chrono::Weekday::Sat),
        _ => None,
    }
}

fn resolve_win32_transition_local(
    rule: Win32SystemTimeRule,
    target_year: i32,
) -> Option<chrono::NaiveDateTime> {
    use chrono::{Datelike, NaiveDate, NaiveTime};

    let month = u32::from(rule.month);
    if !(1..=12).contains(&month) {
        return None;
    }
    let date = if rule.year != 0 {
        NaiveDate::from_ymd_opt(i32::from(rule.year), month, u32::from(rule.day))?
    } else {
        let want_wd = win32_weekday_from_u16(rule.day_of_week)?;
        let mut matches = Vec::with_capacity(5);
        for d in 1..=31 {
            let Some(cand) = NaiveDate::from_ymd_opt(target_year, month, d) else {
                break;
            };
            if cand.weekday() == want_wd {
                matches.push(cand);
            }
        }
        if matches.is_empty() || rule.day == 0 {
            return None;
        }
        if rule.day >= 5 {
            *matches.last()?
        } else {
            let idx = usize::from(rule.day - 1);
            *matches.get(idx).or_else(|| matches.last())?
        }
    };
    let time = NaiveTime::from_hms_opt(
        u32::from(rule.hour),
        u32::from(rule.minute),
        u32::from(rule.second),
    )?;
    Some(chrono::NaiveDateTime::new(date, time))
}

/// Computes the active UTC offset (seconds east) for `info` at `now_utc`, respecting Win32
/// Northern/Southern hemisphere DST transition rules (`StandardDate` / `DaylightDate`).
pub fn compute_win_tz_utc_offset_secs(
    info: Win32TzInfo,
    now_utc: chrono::DateTime<chrono::Utc>,
) -> Option<i32> {
    use chrono::{Datelike, TimeDelta};

    if info.standard_date.month == 0 || info.daylight_date.month == 0 {
        return info
            .bias
            .checked_add(info.standard_bias)?
            .checked_neg()?
            .checked_mul(60);
    }
    let year = now_utc.year();
    let daylight_local = resolve_win32_transition_local(info.daylight_date, year)?;
    let standard_local = resolve_win32_transition_local(info.standard_date, year)?;
    let std_total_mins = info.bias.checked_add(info.standard_bias)?;
    let dst_total_mins = info.bias.checked_add(info.daylight_bias)?;
    let daylight_start_utc = daylight_local + TimeDelta::minutes(i64::from(std_total_mins));
    let standard_start_utc = standard_local + TimeDelta::minutes(i64::from(dst_total_mins));
    let now_naive = now_utc.naive_utc();
    let is_daylight = if daylight_start_utc < standard_start_utc {
        now_naive >= daylight_start_utc && now_naive < standard_start_utc
    } else if standard_start_utc < daylight_start_utc {
        now_naive >= daylight_start_utc || now_naive < standard_start_utc
    } else {
        false
    };
    let active_bias = if is_daylight {
        dst_total_mins
    } else {
        std_total_mins
    };
    active_bias.checked_neg()?.checked_mul(60)
}
