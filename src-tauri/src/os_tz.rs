//! OS system timezone synchronization and automatic baseline restore.
//!
//! Browsers (Chrome, Safari, Edge, Firefox) and Electron apps (Claude Desktop) ignore `TZ` env
//! vars in shell/IDE settings and read the OS system timezone directly. This module allows users
//! to sync the OS timezone to the VPN/exit IP timezone (via UAC on Windows or administrator
//! privileges on macOS), while durably persisting the original timezone in `os_tz_baseline.json`
//! so it can be restored manually, when disabling protection, on app quit, or after a crash.

use crate::sysproxy::fs::{Fs, RealFs, WriteMode};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

pub const BASELINE_FILE_NAME: &str = "os_tz_baseline.json";

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
static OS_TZ_OPS: Mutex<()> = Mutex::new(());
static EXIT_RESTORE_RAN: AtomicBool = AtomicBool::new(false);

/// Pins the app data directory where `os_tz_baseline.json` lives.
pub fn set_data_dir(dir: PathBuf) {
    let _ = DATA_DIR.set(dir);
}

/// Resolves the app data directory from an optional `AppHandle`, pinned `DATA_DIR`, or OS default.
pub fn resolve_app_data_dir(app: Option<&tauri::AppHandle>) -> Option<PathBuf> {
    if let Some(handle) = app {
        use tauri::Manager;
        if let Ok(dir) = handle.path().app_data_dir() {
            return Some(dir);
        }
    }
    DATA_DIR
        .get()
        .cloned()
        .or_else(crate::sysproxy::default_app_data_dir)
}

/// Whether real OS timezone reads/writes via external tools (`tzutil`, `systemsetup`, `osascript`)
/// are allowed. Always `false` in tests (`cfg!(test)`, `test-support`), dry-run mode, or when
/// `ZASTAVA_TEST_MODE=1`/`true`.
pub fn os_tz_effects_enabled() -> bool {
    if !crate::sysproxy::os_effects_enabled() {
        return false;
    }
    !std::env::var("ZASTAVA_TEST_MODE")
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// Durable backup of the user's pre-Zastava OS timezone state (`os_tz_baseline.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsTzBaseline {
    pub original_iana: String,
    pub original_windows_id: Option<String>,
    pub original_auto_tz: Option<bool>,
    pub synced_iana: String,
    pub synced_at_utc: String,
}

/// Status returned to the frontend / callers describing current OS timezone sync state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsTzSyncStatus {
    pub synced: bool,
    pub current_os_tz: Option<String>,
    pub original_os_tz: Option<String>,
    pub synced_target_tz: Option<String>,
    pub auto_restore_pending: bool,
}

/// Platform abstraction for reading/setting the OS system timezone without running real OS
/// commands during tests.
pub trait OsTzPlatform: Send + Sync {
    /// Returns the current OS system timezone as an IANA identifier (e.g. `"Europe/Moscow"`).
    fn current_iana_timezone(&self) -> Result<String, String>;

    /// Returns the current Windows time zone ID (e.g. `"Russian Standard Time"`), or `None` on
    /// non-Windows systems.
    fn current_windows_tz_id(&self) -> Result<Option<String>, String>;

    /// Returns whether OS automatic timezone detection (`tzautoupdate` on Windows,
    /// `com.apple.timezone.auto` on macOS) is currently enabled (`Some(true)`), disabled
    /// (`Some(false)`), or unknown (`None`).
    fn is_auto_tz_enabled(&self) -> Result<Option<bool>, String>;

    /// Applies `target_iana` to the OS system timezone and optionally disables automatic timezone.
    fn apply_timezone(&self, target_iana: &str, disable_auto_tz: bool) -> Result<(), String>;

    /// Restores `orig_iana` (or `orig_win_id` on Windows) and restores automatic timezone if
    /// `restore_auto_tz == Some(true)`.
    fn restore_timezone(
        &self,
        orig_iana: &str,
        orig_win_id: Option<&str>,
        restore_auto_tz: Option<bool>,
    ) -> Result<(), String>;
}

/// Real OS implementation (macOS `systemsetup`/`osascript` + `defaults`; Windows `tzutil`/Win32
/// registry + PowerShell `RunAs`). Every mutation respects [`os_tz_effects_enabled`].
pub struct RealOsTzPlatform;

// -------------------------------------------------------------------------------------------------
// IANA <-> Windows Time Zone ID Mapping & Aliases
// -------------------------------------------------------------------------------------------------

/// Canonicalizes legacy or alias IANA timezone identifiers to their modern CLDR canonical name.
pub fn canonicalize_iana_tz(iana: &str) -> &str {
    let trimmed = iana.trim();
    match trimmed {
        "Asia/Calcutta" => "Asia/Kolkata",
        "Asia/Katmandu" => "Asia/Kathmandu",
        "Asia/Rangoon" => "Asia/Yangon",
        "Asia/Saigon" => "Asia/Ho_Chi_Minh",
        "Asia/Istanbul" => "Europe/Istanbul",
        "Asia/Nicosia" => "Europe/Nicosia",
        "Europe/Kiev" => "Europe/Kyiv",
        "America/Buenos_Aires" => "America/Argentina/Buenos_Aires",
        "US/Eastern" => "America/New_York",
        "US/Central" => "America/Chicago",
        "US/Mountain" => "America/Denver",
        "US/Pacific" => "America/Los_Angeles",
        "Etc/UTC" | "Etc/GMT" | "GMT" => "UTC",
        _ => trimmed,
    }
}

/// Static IANA -> Windows Standard Time Zone ID table (CLDR `windowsZones.xml`).
const IANA_TO_WINDOWS: &[(&str, &str)] = &[
    // UTC
    ("UTC", "UTC"),
    // Western & Central Europe
    ("Europe/London", "GMT Standard Time"),
    ("Europe/Dublin", "GMT Standard Time"),
    ("Europe/Lisbon", "GMT Standard Time"),
    ("Atlantic/Reykjavik", "Greenwich Standard Time"),
    ("Europe/Berlin", "W. Europe Standard Time"),
    ("Europe/Amsterdam", "W. Europe Standard Time"),
    ("Europe/Stockholm", "W. Europe Standard Time"),
    ("Europe/Rome", "W. Europe Standard Time"),
    ("Europe/Vienna", "W. Europe Standard Time"),
    ("Europe/Zurich", "W. Europe Standard Time"),
    ("Europe/Oslo", "W. Europe Standard Time"),
    ("Europe/Luxembourg", "W. Europe Standard Time"),
    ("Europe/Malta", "W. Europe Standard Time"),
    ("Europe/Monaco", "W. Europe Standard Time"),
    ("Europe/Andorra", "W. Europe Standard Time"),
    ("Europe/Vaduz", "W. Europe Standard Time"),
    ("Europe/San_Marino", "W. Europe Standard Time"),
    ("Europe/Vatican", "W. Europe Standard Time"),
    ("Europe/Paris", "Romance Standard Time"),
    ("Europe/Madrid", "Romance Standard Time"),
    ("Europe/Brussels", "Romance Standard Time"),
    ("Europe/Copenhagen", "Romance Standard Time"),
    ("Europe/Ceuta", "Romance Standard Time"),
    ("Europe/Warsaw", "Central European Standard Time"),
    ("Europe/Sarajevo", "Central European Standard Time"),
    ("Europe/Skopje", "Central European Standard Time"),
    ("Europe/Zagreb", "Central European Standard Time"),
    ("Europe/Prague", "Central Europe Standard Time"),
    ("Europe/Budapest", "Central Europe Standard Time"),
    ("Europe/Belgrade", "Central Europe Standard Time"),
    ("Europe/Bratislava", "Central Europe Standard Time"),
    ("Europe/Ljubljana", "Central Europe Standard Time"),
    ("Europe/Podgorica", "Central Europe Standard Time"),
    ("Europe/Tirane", "Central Europe Standard Time"),
    // Eastern Europe & Baltic & Turkey
    ("Europe/Helsinki", "FLE Standard Time"),
    ("Europe/Tallinn", "FLE Standard Time"),
    ("Europe/Riga", "FLE Standard Time"),
    ("Europe/Vilnius", "FLE Standard Time"),
    ("Europe/Kyiv", "FLE Standard Time"),
    ("Europe/Sofia", "FLE Standard Time"),
    ("Europe/Uzhgorod", "FLE Standard Time"),
    ("Europe/Zaporozhye", "FLE Standard Time"),
    ("Europe/Bucharest", "GTB Standard Time"),
    ("Europe/Athens", "GTB Standard Time"),
    ("Europe/Nicosia", "GTB Standard Time"),
    ("Europe/Chisinau", "E. Europe Standard Time"),
    ("Europe/Istanbul", "Turkey Standard Time"),
    // Russia & Belarus
    ("Europe/Moscow", "Russian Standard Time"),
    ("Europe/Kirov", "Russian Standard Time"),
    ("Europe/Simferopol", "Russian Standard Time"),
    ("Europe/Kaliningrad", "Kaliningrad Standard Time"),
    ("Europe/Samara", "Russia Time Zone 3"),
    ("Europe/Ulyanovsk", "Russia Time Zone 3"),
    ("Europe/Saratov", "Saratov Standard Time"),
    ("Europe/Volgograd", "Volgograd Standard Time"),
    ("Europe/Astrakhan", "Astrakhan Standard Time"),
    ("Europe/Minsk", "Belarus Standard Time"),
    ("Asia/Yekaterinburg", "Ekaterinburg Standard Time"),
    ("Asia/Omsk", "Omsk Standard Time"),
    ("Asia/Novosibirsk", "N. Central Asia Standard Time"),
    ("Asia/Barnaul", "Altai Standard Time"),
    ("Asia/Tomsk", "Tomsk Standard Time"),
    ("Asia/Krasnoyarsk", "North Asia Standard Time"),
    ("Asia/Novokuznetsk", "North Asia Standard Time"),
    ("Asia/Irkutsk", "North Asia East Standard Time"),
    ("Asia/Yakutsk", "Yakutsk Standard Time"),
    ("Asia/Khandyga", "Yakutsk Standard Time"),
    ("Asia/Chita", "Transbaikal Standard Time"),
    ("Asia/Vladivostok", "Vladivostok Standard Time"),
    ("Asia/Ust-Nera", "Vladivostok Standard Time"),
    ("Asia/Magadan", "Magadan Standard Time"),
    ("Asia/Sakhalin", "Sakhalin Standard Time"),
    ("Asia/Srednekolymsk", "Russia Time Zone 10"),
    ("Asia/Kamchatka", "Russia Time Zone 11"),
    ("Asia/Anadyr", "Russia Time Zone 11"),
    // Middle East & Caucasus & Central Asia
    ("Asia/Dubai", "Arabian Standard Time"),
    ("Asia/Muscat", "Arabian Standard Time"),
    ("Asia/Riyadh", "Arab Standard Time"),
    ("Asia/Kuwait", "Arab Standard Time"),
    ("Asia/Qatar", "Arab Standard Time"),
    ("Asia/Bahrain", "Arab Standard Time"),
    ("Asia/Jerusalem", "Israel Standard Time"),
    ("Asia/Tel_Aviv", "Israel Standard Time"),
    ("Asia/Amman", "Jordan Standard Time"),
    ("Asia/Beirut", "Middle East Standard Time"),
    ("Asia/Baghdad", "Arabic Standard Time"),
    ("Asia/Tehran", "Iran Standard Time"),
    ("Asia/Tbilisi", "Georgian Standard Time"),
    ("Asia/Yerevan", "Caucasus Standard Time"),
    ("Asia/Baku", "Azerbaijan Standard Time"),
    ("Asia/Almaty", "West Asia Standard Time"),
    ("Asia/Qyzylorda", "West Asia Standard Time"),
    ("Asia/Aqtobe", "West Asia Standard Time"),
    ("Asia/Aqtau", "West Asia Standard Time"),
    ("Asia/Atyrau", "West Asia Standard Time"),
    ("Asia/Oral", "West Asia Standard Time"),
    ("Asia/Qostanay", "West Asia Standard Time"),
    ("Asia/Tashkent", "West Asia Standard Time"),
    ("Asia/Samarkand", "West Asia Standard Time"),
    ("Asia/Ashgabat", "West Asia Standard Time"),
    ("Asia/Dushanbe", "West Asia Standard Time"),
    ("Asia/Bishkek", "Central Asia Standard Time"),
    ("Asia/Dhaka", "Bangladesh Standard Time"),
    // South, East & Southeast Asia
    ("Asia/Kolkata", "India Standard Time"),
    ("Asia/Colombo", "Sri Lanka Standard Time"),
    ("Asia/Kathmandu", "Nepal Standard Time"),
    ("Asia/Karachi", "Pakistan Standard Time"),
    ("Asia/Kabul", "Afghanistan Standard Time"),
    ("Asia/Yangon", "Myanmar Standard Time"),
    ("Asia/Bangkok", "SE Asia Standard Time"),
    ("Asia/Ho_Chi_Minh", "SE Asia Standard Time"),
    ("Asia/Jakarta", "SE Asia Standard Time"),
    ("Asia/Phnom_Penh", "SE Asia Standard Time"),
    ("Asia/Vientiane", "SE Asia Standard Time"),
    ("Asia/Singapore", "Singapore Standard Time"),
    ("Asia/Kuala_Lumpur", "Singapore Standard Time"),
    ("Asia/Manila", "Singapore Standard Time"),
    ("Asia/Shanghai", "China Standard Time"),
    ("Asia/Hong_Kong", "China Standard Time"),
    ("Asia/Macau", "China Standard Time"),
    ("Asia/Chongqing", "China Standard Time"),
    ("Asia/Taipei", "Taipei Standard Time"),
    ("Asia/Tokyo", "Tokyo Standard Time"),
    ("Asia/Seoul", "Korea Standard Time"),
    // Oceania
    ("Australia/Sydney", "AUS Eastern Standard Time"),
    ("Australia/Melbourne", "AUS Eastern Standard Time"),
    ("Australia/Canberra", "AUS Eastern Standard Time"),
    ("Australia/Brisbane", "E. Australia Standard Time"),
    ("Australia/Adelaide", "Cen. Australia Standard Time"),
    ("Australia/Darwin", "AUS Central Standard Time"),
    ("Australia/Perth", "W. Australia Standard Time"),
    ("Australia/Hobart", "Tasmania Standard Time"),
    ("Pacific/Auckland", "New Zealand Standard Time"),
    // Americas
    ("America/New_York", "Eastern Standard Time"),
    ("America/Toronto", "Eastern Standard Time"),
    ("America/Detroit", "Eastern Standard Time"),
    ("America/Indiana/Indianapolis", "US Eastern Standard Time"),
    ("America/Chicago", "Central Standard Time"),
    ("America/Winnipeg", "Central Standard Time"),
    ("America/Mexico_City", "Central Standard Time (Mexico)"),
    ("America/Monterrey", "Central Standard Time (Mexico)"),
    ("America/Denver", "Mountain Standard Time"),
    ("America/Edmonton", "Mountain Standard Time"),
    ("America/Boise", "Mountain Standard Time"),
    ("America/Phoenix", "US Mountain Standard Time"),
    ("America/Los_Angeles", "Pacific Standard Time"),
    ("America/Vancouver", "Pacific Standard Time"),
    ("America/Tijuana", "Pacific Standard Time (Mexico)"),
    ("America/Anchorage", "Alaskan Standard Time"),
    ("Pacific/Honolulu", "Hawaiian Standard Time"),
    ("America/Halifax", "Atlantic Standard Time"),
    ("America/St_Johns", "Newfoundland Standard Time"),
    ("America/Sao_Paulo", "E. South America Standard Time"),
    ("America/Argentina/Buenos_Aires", "Argentina Standard Time"),
    ("America/Santiago", "Pacific SA Standard Time"),
    ("America/Bogota", "SA Pacific Standard Time"),
    ("America/Lima", "SA Pacific Standard Time"),
    ("America/Panama", "SA Pacific Standard Time"),
    ("America/Caracas", "Venezuela Standard Time"),
    // Africa
    ("Africa/Cairo", "Egypt Standard Time"),
    ("Africa/Johannesburg", "South Africa Standard Time"),
    ("Africa/Casablanca", "Morocco Standard Time"),
    ("Africa/Lagos", "W. Central Africa Standard Time"),
    ("Africa/Nairobi", "E. Africa Standard Time"),
];

/// Primary canonical IANA zone for each Windows Standard Time Zone ID.
const WINDOWS_TO_IANA: &[(&str, &str)] = &[
    ("UTC", "UTC"),
    ("GMT Standard Time", "Europe/London"),
    ("Greenwich Standard Time", "Atlantic/Reykjavik"),
    ("W. Europe Standard Time", "Europe/Berlin"),
    ("Romance Standard Time", "Europe/Paris"),
    ("Central European Standard Time", "Europe/Warsaw"),
    ("Central Europe Standard Time", "Europe/Prague"),
    ("FLE Standard Time", "Europe/Helsinki"),
    ("GTB Standard Time", "Europe/Bucharest"),
    ("E. Europe Standard Time", "Europe/Chisinau"),
    ("Turkey Standard Time", "Europe/Istanbul"),
    ("Russian Standard Time", "Europe/Moscow"),
    ("Kaliningrad Standard Time", "Europe/Kaliningrad"),
    ("Russia Time Zone 3", "Europe/Samara"),
    ("Saratov Standard Time", "Europe/Saratov"),
    ("Volgograd Standard Time", "Europe/Volgograd"),
    ("Astrakhan Standard Time", "Europe/Astrakhan"),
    ("Belarus Standard Time", "Europe/Minsk"),
    ("Ekaterinburg Standard Time", "Asia/Yekaterinburg"),
    ("Omsk Standard Time", "Asia/Omsk"),
    ("N. Central Asia Standard Time", "Asia/Novosibirsk"),
    ("Altai Standard Time", "Asia/Barnaul"),
    ("Tomsk Standard Time", "Asia/Tomsk"),
    ("North Asia Standard Time", "Asia/Krasnoyarsk"),
    ("North Asia East Standard Time", "Asia/Irkutsk"),
    ("Yakutsk Standard Time", "Asia/Yakutsk"),
    ("Transbaikal Standard Time", "Asia/Chita"),
    ("Vladivostok Standard Time", "Asia/Vladivostok"),
    ("Magadan Standard Time", "Asia/Magadan"),
    ("Sakhalin Standard Time", "Asia/Sakhalin"),
    ("Russia Time Zone 10", "Asia/Srednekolymsk"),
    ("Russia Time Zone 11", "Asia/Kamchatka"),
    ("Arabian Standard Time", "Asia/Dubai"),
    ("Arab Standard Time", "Asia/Riyadh"),
    ("Israel Standard Time", "Asia/Jerusalem"),
    ("Jordan Standard Time", "Asia/Amman"),
    ("Middle East Standard Time", "Asia/Beirut"),
    ("Arabic Standard Time", "Asia/Baghdad"),
    ("Iran Standard Time", "Asia/Tehran"),
    ("Georgian Standard Time", "Asia/Tbilisi"),
    ("Caucasus Standard Time", "Asia/Yerevan"),
    ("Azerbaijan Standard Time", "Asia/Baku"),
    ("West Asia Standard Time", "Asia/Tashkent"),
    ("Central Asia Standard Time", "Asia/Bishkek"),
    ("Bangladesh Standard Time", "Asia/Dhaka"),
    ("India Standard Time", "Asia/Kolkata"),
    ("Sri Lanka Standard Time", "Asia/Colombo"),
    ("Nepal Standard Time", "Asia/Kathmandu"),
    ("Pakistan Standard Time", "Asia/Karachi"),
    ("Afghanistan Standard Time", "Asia/Kabul"),
    ("Myanmar Standard Time", "Asia/Yangon"),
    ("SE Asia Standard Time", "Asia/Bangkok"),
    ("Singapore Standard Time", "Asia/Singapore"),
    ("China Standard Time", "Asia/Shanghai"),
    ("Taipei Standard Time", "Asia/Taipei"),
    ("Tokyo Standard Time", "Asia/Tokyo"),
    ("Korea Standard Time", "Asia/Seoul"),
    ("AUS Eastern Standard Time", "Australia/Sydney"),
    ("E. Australia Standard Time", "Australia/Brisbane"),
    ("Cen. Australia Standard Time", "Australia/Adelaide"),
    ("AUS Central Standard Time", "Australia/Darwin"),
    ("W. Australia Standard Time", "Australia/Perth"),
    ("Tasmania Standard Time", "Australia/Hobart"),
    ("New Zealand Standard Time", "Pacific/Auckland"),
    ("Eastern Standard Time", "America/New_York"),
    ("US Eastern Standard Time", "America/Indiana/Indianapolis"),
    ("Central Standard Time", "America/Chicago"),
    ("Central Standard Time (Mexico)", "America/Mexico_City"),
    ("Mountain Standard Time", "America/Denver"),
    ("US Mountain Standard Time", "America/Phoenix"),
    ("Pacific Standard Time", "America/Los_Angeles"),
    ("Pacific Standard Time (Mexico)", "America/Tijuana"),
    ("Alaskan Standard Time", "America/Anchorage"),
    ("Hawaiian Standard Time", "Pacific/Honolulu"),
    ("Atlantic Standard Time", "America/Halifax"),
    ("Newfoundland Standard Time", "America/St_Johns"),
    ("E. South America Standard Time", "America/Sao_Paulo"),
    ("Argentina Standard Time", "America/Argentina/Buenos_Aires"),
    ("Pacific SA Standard Time", "America/Santiago"),
    ("SA Pacific Standard Time", "America/Bogota"),
    ("Venezuela Standard Time", "America/Caracas"),
    ("Egypt Standard Time", "Africa/Cairo"),
    ("South Africa Standard Time", "Africa/Johannesburg"),
    ("Morocco Standard Time", "Africa/Casablanca"),
    ("W. Central Africa Standard Time", "Africa/Lagos"),
    ("E. Africa Standard Time", "Africa/Nairobi"),
];

/// Maps an IANA time zone (case-insensitive, resolving common aliases) to its Windows Standard
/// Time Zone ID.
pub fn iana_to_windows_tz(iana: &str) -> Option<&'static str> {
    let canonical = canonicalize_iana_tz(iana.trim());
    IANA_TO_WINDOWS
        .iter()
        .find(|(zone, _)| zone.eq_ignore_ascii_case(canonical))
        .map(|(_, win)| *win)
}

/// Maps a Windows Standard Time Zone ID (case-insensitive) to its primary canonical IANA zone.
pub fn windows_to_iana_tz(win: &str) -> Option<&'static str> {
    let trimmed = win.trim();
    WINDOWS_TO_IANA
        .iter()
        .find(|(w, _)| w.eq_ignore_ascii_case(trimmed))
        .map(|(_, iana)| *iana)
}

/// Returns the canonical static Windows TZ ID if `win` is in the strict allowlist (zero shell
/// injection risk).
pub fn allowlisted_windows_tz_id(win: &str) -> Option<&'static str> {
    let trimmed = win.trim();
    WINDOWS_TO_IANA
        .iter()
        .find(|(w, _)| w.eq_ignore_ascii_case(trimmed))
        .map(|(w, _)| *w)
        .or_else(|| {
            IANA_TO_WINDOWS
                .iter()
                .find(|(_, w)| w.eq_ignore_ascii_case(trimmed))
                .map(|(_, w)| *w)
        })
}

/// Validates and sanitizes an IANA timezone name for safe use.
pub fn validate_iana_tz(raw: &str) -> Result<String, String> {
    let clean = crate::sysproxy::sanitize_timezone(raw)
        .ok_or_else(|| format!("Недопустимое имя часового пояса: {}", raw.trim()))?;
    // Allowlist characters already enforced by sanitize_timezone; verify no dots in path segments
    if clean.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
        return Err(format!("Недопустимый формат часового пояса: {clean}"));
    }
    Ok(clean)
}

fn zones_equivalent(a: &str, b: &str) -> bool {
    let ca = canonicalize_iana_tz(a);
    let cb = canonicalize_iana_tz(b);
    ca.eq_ignore_ascii_case(cb) || ca.replace('_', " ").eq_ignore_ascii_case(&cb.replace('_', " "))
}

// -------------------------------------------------------------------------------------------------
// Atomic Baseline Storage (`os_tz_baseline.json`)
// -------------------------------------------------------------------------------------------------

pub fn baseline_path(data_dir: &Path) -> PathBuf {
    data_dir.join(BASELINE_FILE_NAME)
}

pub fn read_baseline(data_dir: &Path) -> Result<Option<OsTzBaseline>, String> {
    let path = baseline_path(data_dir);
    let bytes = RealFs
        .read(&path)
        .map_err(|e| format!("Не удалось прочитать os_tz_baseline.json: {e}"))?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let parsed: OsTzBaseline = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Повреждённый os_tz_baseline.json: {e}"))?;
    Ok(Some(parsed))
}

pub fn write_baseline_atomic(data_dir: &Path, baseline: &OsTzBaseline) -> Result<(), String> {
    RealFs
        .create_private_dir_all(data_dir)
        .map_err(|e| format!("Не удалось создать каталог данных: {e}"))?;
    let path = baseline_path(data_dir);
    let json = serde_json::to_vec_pretty(baseline)
        .map_err(|e| format!("Ошибка сериализации os_tz_baseline.json: {e}"))?;
    RealFs
        .write_atomic(&path, &json, WriteMode::Private)
        .map_err(|e| format!("Не удалось сохранить os_tz_baseline.json: {e}"))
}

pub fn remove_baseline(data_dir: &Path) -> Result<(), String> {
    let path = baseline_path(data_dir);
    match RealFs.remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Не удалось удалить os_tz_baseline.json: {e}")),
    }
}

// -------------------------------------------------------------------------------------------------
// RealOsTzPlatform Implementation
// -------------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn validate_macos_zoneinfo(iana: &str) -> Result<String, String> {
    let clean = validate_iana_tz(iana)?;
    let candidates = [clean.as_str(), canonicalize_iana_tz(&clean)];
    for cand in candidates {
        let p1 = Path::new("/usr/share/zoneinfo").join(cand);
        let p2 = Path::new("/var/db/timezone/zoneinfo").join(cand);
        if p1.is_file() || p2.is_file() {
            return Ok(cand.to_string());
        }
    }
    Err(format!(
        "Часовой пояс '{clean}' не найден в системной базе /usr/share/zoneinfo."
    ))
}

#[cfg(target_os = "macos")]
fn read_macos_localtime_symlink() -> Option<String> {
    let target = std::fs::read_link("/etc/localtime").ok()?;
    let s = target.to_string_lossy();
    let stripped = s
        .strip_prefix("/var/db/timezone/zoneinfo/")
        .or_else(|| s.strip_prefix("/usr/share/zoneinfo/"))?;
    crate::sysproxy::sanitize_timezone(stripped)
}

#[cfg(target_os = "macos")]
fn posix_single_quote(s: &str) -> Result<String, String> {
    if s.contains('\0') {
        return Err("Недопустимый нулевой символ в аргументе.".to_string());
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    Ok(out)
}

#[cfg(target_os = "macos")]
fn applescript_string_literal(s: &str) -> Result<String, String> {
    if s.chars().any(char::is_control) {
        return Err("Недопустимый управляющий символ в скрипте AppleScript.".to_string());
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

#[cfg(target_os = "macos")]
fn run_macos_privileged_script(shell_script: &str) -> Result<(), String> {
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    let osa_arg = format!(
        "do shell script {} with administrator privileges",
        applescript_string_literal(shell_script)?
    );
    let out = crate::sysproxy::silent_command("osascript")
        .args(["-e", &osa_arg])
        .output()
        .map_err(|e| format!("Не удалось запустить osascript: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let cancelled = crate::sysproxy::platform::is_admin_auth_error(&stdout, &stderr)
        || stderr.contains("(-128)")
        || stdout.contains("(-128)");
    if cancelled {
        return Err(
            "OS_TZ_ELEVATION_CANCELLED: Запрос прав администратора отменён пользователем."
                .to_string(),
        );
    }
    let detail = stderr.trim();
    Err(if detail.is_empty() {
        format!(
            "Не удалось изменить системный часовой пояс (код {:?}).",
            out.status.code()
        )
    } else {
        format!("Не удалось изменить системный часовой пояс: {detail}")
    })
}

#[cfg(target_os = "windows")]
const WIN_TZ_REG_SUBKEY: &str = r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation";
#[cfg(target_os = "windows")]
const WIN_TZ_AUTO_SUBKEY: &str = r"SYSTEM\CurrentControlSet\Services\tzautoupdate";

#[cfg(target_os = "windows")]
fn run_windows_tzutil_set(win_tz_allowlisted: &str) -> Result<(), String> {
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    let out = crate::sysproxy::silent_command("tzutil.exe")
        .args(["/s", win_tz_allowlisted])
        .output()
        .map_err(|e| format!("Не удалось запустить tzutil.exe: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    Err(if detail.is_empty() {
        format!("tzutil.exe завершился с кодом {:?}", out.status.code())
    } else {
        detail
    })
}

#[cfg(target_os = "windows")]
fn run_windows_elevated_tz_ps(
    win_tz_allowlisted: &str,
    auto_tz_start: Option<u32>,
) -> Result<(), String> {
    if !os_tz_effects_enabled() {
        return Ok(());
    }
    use base64::Engine;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // `win_tz_allowlisted` is guaranteed to come from our static WINDOWS_TO_IANA / IANA_TO_WINDOWS
    // allowlist, containing only ASCII letters, digits, spaces, dots, and parentheses.
    let reg_part = match auto_tz_start {
        Some(start_val) => format!(
            "; $reg='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\tzautoupdate'; \
             if (Test-Path $reg) {{ Set-ItemProperty -Path $reg -Name 'Start' -Value {start_val} -Type DWord }}"
        ),
        None => String::new(),
    };
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         & \"$env:SystemRoot\\System32\\tzutil.exe\" /s '{win_tz_allowlisted}'; \
         if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}{reg_part}"
    );
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let launcher = format!(
        "$p = Start-Process -FilePath \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \
         -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-EncodedCommand','{encoded}') \
         -Verb RunAs -WindowStyle Hidden -PassThru -Wait; exit $p.ExitCode"
    );

    let out = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &launcher,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Не удалось запустить PowerShell для смены часового пояса: {e}"))?;

    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let lower = stderr.to_ascii_lowercase();
    if stderr.is_empty()
        || lower.contains("canceled by the user")
        || lower.contains("cancelled by the user")
        || lower.contains("отменена пользователем")
        || lower.contains("операция была отменена")
    {
        return Err(
            "OS_TZ_ELEVATION_CANCELLED: Запрос прав администратора (UAC) отменён пользователем."
                .to_string(),
        );
    }
    Err(format!(
        "Не удалось изменить системный часовой пояс Windows: {stderr}"
    ))
}

impl OsTzPlatform for RealOsTzPlatform {
    fn current_iana_timezone(&self) -> Result<String, String> {
        #[cfg(target_os = "macos")]
        {
            if let Some(tz) = read_macos_localtime_symlink() {
                return Ok(tz);
            }
            iana_time_zone::get_timezone().map_err(|e| e.to_string())
        }
        #[cfg(target_os = "windows")]
        {
            if let Ok(Some(win_id)) = self.current_windows_tz_id() {
                if let Some(iana) = windows_to_iana_tz(&win_id) {
                    return Ok(iana.to_string());
                }
            }
            iana_time_zone::get_timezone().map_err(|e| e.to_string())
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            iana_time_zone::get_timezone().map_err(|e| e.to_string())
        }
    }

    fn current_windows_tz_id(&self) -> Result<Option<String>, String> {
        #[cfg(target_os = "windows")]
        {
            if let Ok(Some(id)) = crate::win_reg::get_string(
                crate::win_reg::RootKey::HkeyLocalMachine,
                WIN_TZ_REG_SUBKEY,
                "TimeZoneKeyName",
            ) {
                let trimmed = id.trim();
                if !trimmed.is_empty() {
                    return Ok(Some(trimmed.to_string()));
                }
            }
            if !os_tz_effects_enabled() {
                return Ok(None);
            }
            let out = crate::sysproxy::silent_command("tzutil.exe")
                .args(["/g"])
                .output()
                .map_err(|e| format!("tzutil /g error: {e}"))?;
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    return Ok(Some(s));
                }
            }
            Ok(None)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(None)
        }
    }

    fn is_auto_tz_enabled(&self) -> Result<Option<bool>, String> {
        #[cfg(target_os = "macos")]
        {
            if !os_tz_effects_enabled() {
                return Ok(None);
            }
            let out = crate::sysproxy::silent_command("/usr/bin/defaults")
                .args(["read", "/Library/Preferences/com.apple.timezone.auto", "Active"])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    match s.as_str() {
                        "1" | "true" | "YES" => Ok(Some(true)),
                        "0" | "false" | "NO" => Ok(Some(false)),
                        _ => Ok(None),
                    }
                }
                _ => Ok(Some(false)),
            }
        }
        #[cfg(target_os = "windows")]
        {
            match crate::win_reg::get_dword(
                crate::win_reg::RootKey::HkeyLocalMachine,
                WIN_TZ_AUTO_SUBKEY,
                "Start",
            ) {
                Ok(Some(4)) => Ok(Some(false)),
                Ok(Some(2 | 3)) => Ok(Some(true)),
                _ => Ok(None),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Ok(None)
        }
    }

    fn apply_timezone(&self, target_iana: &str, disable_auto_tz: bool) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            let verified = validate_macos_zoneinfo(target_iana)?;
            if !os_tz_effects_enabled() {
                return Ok(());
            }
            let q_tz = posix_single_quote(&verified)?;
            let script = if disable_auto_tz {
                format!(
                    "/usr/sbin/systemsetup -settimezone {q_tz} && /usr/bin/defaults write /Library/Preferences/com.apple.timezone.auto Active -bool false"
                )
            } else {
                format!("/usr/sbin/systemsetup -settimezone {q_tz}")
            };
            run_macos_privileged_script(&script)
        }
        #[cfg(target_os = "windows")]
        {
            let clean = validate_iana_tz(target_iana)?;
            let win_tz = iana_to_windows_tz(&clean).ok_or_else(|| {
                format!("Часовой пояс '{clean}' не имеет сопоставления в таблице Windows.")
            })?;
            let safe_win_tz = allowlisted_windows_tz_id(win_tz)
                .ok_or_else(|| format!("Windows TZ '{win_tz}' отсутствует в списке допустимых."))?;
            if !os_tz_effects_enabled() {
                return Ok(());
            }
            let need_disable_auto = disable_auto_tz
                && matches!(self.is_auto_tz_enabled(), Ok(Some(true)));
            if !need_disable_auto && run_windows_tzutil_set(safe_win_tz).is_ok() {
                return Ok(());
            }
            let auto_start = if need_disable_auto { Some(4) } else { None };
            run_windows_elevated_tz_ps(safe_win_tz, auto_start)
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = (target_iana, disable_auto_tz);
            Err("Синхронизация системного часового пояса поддерживается только на Windows и macOS.".to_string())
        }
    }

    fn restore_timezone(
        &self,
        orig_iana: &str,
        orig_win_id: Option<&str>,
        restore_auto_tz: Option<bool>,
    ) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            let _ = orig_win_id;
            let verified = validate_macos_zoneinfo(orig_iana)?;
            if !os_tz_effects_enabled() {
                return Ok(());
            }
            let q_tz = posix_single_quote(&verified)?;
            let script = if restore_auto_tz == Some(true) {
                format!(
                    "/usr/sbin/systemsetup -settimezone {q_tz} && /usr/bin/defaults write /Library/Preferences/com.apple.timezone.auto Active -bool true"
                )
            } else {
                format!("/usr/sbin/systemsetup -settimezone {q_tz}")
            };
            run_macos_privileged_script(&script)
        }
        #[cfg(target_os = "windows")]
        {
            let win_tz = orig_win_id
                .and_then(allowlisted_windows_tz_id)
                .or_else(|| {
                    validate_iana_tz(orig_iana)
                        .ok()
                        .and_then(|c| iana_to_windows_tz(&c))
                        .and_then(allowlisted_windows_tz_id)
                })
                .ok_or_else(|| {
                    format!("Не удалось определить Windows TZ для восстановления '{orig_iana}'.")
                })?;
            if !os_tz_effects_enabled() {
                return Ok(());
            }
            let need_restore_auto = restore_auto_tz == Some(true);
            if !need_restore_auto && run_windows_tzutil_set(win_tz).is_ok() {
                return Ok(());
            }
            let auto_start = if need_restore_auto { Some(3) } else { None };
            run_windows_elevated_tz_ps(win_tz, auto_start)
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = (orig_iana, orig_win_id, restore_auto_tz);
            Err("Восстановление системного часового пояса поддерживается только на Windows и macOS.".to_string())
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Core Orchestration (injectable over `OsTzPlatform` and `data_dir`)
// -------------------------------------------------------------------------------------------------

fn build_status(platform: &dyn OsTzPlatform, baseline: Option<&OsTzBaseline>) -> OsTzSyncStatus {
    let current_os_tz = platform.current_iana_timezone().ok();
    match baseline {
        Some(b) => OsTzSyncStatus {
            synced: true,
            current_os_tz,
            original_os_tz: Some(b.original_iana.clone()),
            synced_target_tz: Some(b.synced_iana.clone()),
            auto_restore_pending: true,
        },
        None => OsTzSyncStatus {
            synced: false,
            current_os_tz,
            original_os_tz: None,
            synced_target_tz: None,
            auto_restore_pending: false,
        },
    }
}

/// Returns the current OS timezone sync status using `RealOsTzPlatform`.
pub fn get_os_timezone_sync_status(data_dir: &Path) -> Result<OsTzSyncStatus, String> {
    get_os_timezone_sync_status_with(&RealOsTzPlatform, data_dir)
}

/// Returns the current OS timezone sync status using an injectable `OsTzPlatform`.
pub fn get_os_timezone_sync_status_with(
    platform: &dyn OsTzPlatform,
    data_dir: &Path,
) -> Result<OsTzSyncStatus, String> {
    let _guard = OS_TZ_OPS.lock().unwrap_or_else(|e| e.into_inner());
    let baseline = read_baseline(data_dir)?;
    Ok(build_status(platform, baseline.as_ref()))
}

/// Syncs the OS system timezone to `target_iana`, saving the original baseline atomically before
/// modifying the OS. Subsequent syncs preserve the original baseline.
pub fn sync_os_timezone(data_dir: &Path, target_iana: &str) -> Result<OsTzSyncStatus, String> {
    sync_os_timezone_with(&RealOsTzPlatform, data_dir, target_iana)
}

/// Injectable version of [`sync_os_timezone`] for unit tests.
pub fn sync_os_timezone_with(
    platform: &dyn OsTzPlatform,
    data_dir: &Path,
    target_iana: &str,
) -> Result<OsTzSyncStatus, String> {
    let _guard = OS_TZ_OPS.lock().unwrap_or_else(|e| e.into_inner());
    let clean_target = validate_iana_tz(target_iana)?;
    if crate::auditor::os_env::is_russian_or_belarusian_timezone(&clean_target) {
        return Err(format!(
            "Отказ синхронизации: часовой пояс '{clean_target}' относится к РФ/РБ."
        ));
    }

    let existing = read_baseline(data_dir)?;
    let current_iana = platform.current_iana_timezone()?;

    // If no baseline exists yet and the OS is already on the target timezone, no elevation is needed.
    if existing.is_none() && zones_equivalent(&current_iana, &clean_target) {
        return Ok(OsTzSyncStatus {
            synced: false,
            current_os_tz: Some(current_iana),
            original_os_tz: None,
            synced_target_tz: None,
            auto_restore_pending: false,
        });
    }

    let mut baseline = match existing.as_ref() {
        Some(prev) => {
            let mut b = prev.clone();
            b.synced_iana = clean_target.clone();
            b.synced_at_utc = Utc::now().to_rfc3339();
            b
        }
        None => {
            let orig_win = platform.current_windows_tz_id()?;
            let orig_auto = platform.is_auto_tz_enabled()?;
            OsTzBaseline {
                original_iana: current_iana,
                original_windows_id: orig_win,
                original_auto_tz: orig_auto,
                synced_iana: clean_target.clone(),
                synced_at_utc: Utc::now().to_rfc3339(),
            }
        }
    };

    // Persist baseline atomically BEFORE touching the OS, so a crash never loses the original TZ.
    write_baseline_atomic(data_dir, &baseline)?;

    if let Err(err) = platform.apply_timezone(&clean_target, true) {
        match existing {
            Some(prev) => {
                // Keep the prior baseline intact since the new target was not applied.
                let _ = write_baseline_atomic(data_dir, &prev);
            }
            None => {
                // Newly created baseline, OS was not changed: remove baseline.
                let _ = remove_baseline(data_dir);
            }
        }
        return Err(err);
    }

    // Re-stamp UTC after apply if needed (already fresh).
    baseline.synced_at_utc = Utc::now().to_rfc3339();
    let _ = write_baseline_atomic(data_dir, &baseline);

    Ok(build_status(platform, Some(&baseline)))
}

/// Restores the OS system timezone from `os_tz_baseline.json` and removes the baseline file on
/// success.
pub fn restore_os_timezone(data_dir: &Path) -> Result<OsTzSyncStatus, String> {
    restore_os_timezone_with(&RealOsTzPlatform, data_dir)
}

/// Injectable version of [`restore_os_timezone`] for unit tests.
pub fn restore_os_timezone_with(
    platform: &dyn OsTzPlatform,
    data_dir: &Path,
) -> Result<OsTzSyncStatus, String> {
    let _guard = OS_TZ_OPS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(baseline) = read_baseline(data_dir)? else {
        return Ok(build_status(platform, None));
    };

    let current_iana = platform.current_iana_timezone().ok();
    let already_original = current_iana
        .as_deref()
        .is_some_and(|cur| zones_equivalent(cur, &baseline.original_iana));

    if !already_original || baseline.original_auto_tz == Some(true) {
        platform.restore_timezone(
            &baseline.original_iana,
            baseline.original_windows_id.as_deref(),
            baseline.original_auto_tz,
        )?;
    }

    remove_baseline(data_dir)?;
    Ok(build_status(platform, None))
}

/// Restores the baseline OS timezone on startup if a previous run crashed while synced.
/// Never panics; keeps `os_tz_baseline.json` intact if restoration fails/is cancelled.
pub fn recover_baseline_on_start(data_dir: &Path) {
    recover_baseline_on_start_with(&RealOsTzPlatform, data_dir);
}

pub fn recover_baseline_on_start_with(platform: &dyn OsTzPlatform, data_dir: &Path) {
    let Ok(Some(baseline)) = read_baseline(data_dir) else {
        return;
    };
    eprintln!(
        "Застава: обнаружен незавершённый синхронизированный часовой пояс ОС ({} -> {}), выполняется восстановление {}",
        baseline.synced_iana, baseline.original_iana, BASELINE_FILE_NAME
    );
    match restore_os_timezone_with(platform, data_dir) {
        Ok(_) => eprintln!(
            "Застава: системный часовой пояс ОС восстановлен до {}",
            baseline.original_iana
        ),
        Err(err) => {
            crate::diagnostics::record("startup:os_tz_recover", &err);
            eprintln!("Застава: не удалось автоматически восстановить часовой пояс ОС: {err}");
        }
    }
}

/// Best-effort restore when disabling system proxy protection (`toggle_sysproxy(false)`).
pub fn restore_if_synced_on_disable(data_dir: &Path) -> Result<bool, String> {
    restore_if_synced_on_disable_with(&RealOsTzPlatform, data_dir)
}

pub fn restore_if_synced_on_disable_with(
    platform: &dyn OsTzPlatform,
    data_dir: &Path,
) -> Result<bool, String> {
    if read_baseline(data_dir)?.is_none() {
        return Ok(false);
    }
    restore_os_timezone_with(platform, data_dir)?;
    Ok(true)
}

/// Best-effort non-panicking restore on application quit. Guarded so `ExitRequested` + `Exit`
/// cannot prompt twice in the same process exit.
pub fn restore_on_exit_once(app: Option<&tauri::AppHandle>) {
    if EXIT_RESTORE_RAN.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(dir) = resolve_app_data_dir(app) else {
        return;
    };
    let Ok(Some(baseline)) = read_baseline(&dir) else {
        return;
    };
    if let Err(err) = restore_os_timezone(&dir) {
        crate::diagnostics::record("exit:os_tz_restore", &err);
        eprintln!(
            "Застава: не удалось восстановить часовой пояс ОС ({}) при выходе: {err}",
            baseline.original_iana
        );
    }
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    struct FakeOsTzPlatform {
        current_iana: Mutex<String>,
        current_win: Mutex<Option<String>>,
        auto_tz: Mutex<Option<bool>>,
        apply_calls: Mutex<Vec<(String, bool)>>,
        restore_calls: Mutex<Vec<(String, Option<String>, Option<bool>)>>,
        fail_apply: Mutex<Option<String>>,
        fail_restore: Mutex<Option<String>>,
    }

    impl FakeOsTzPlatform {
        fn new(iana: &str, win: Option<&str>, auto_tz: Option<bool>) -> Self {
            Self {
                current_iana: Mutex::new(iana.to_string()),
                current_win: Mutex::new(win.map(str::to_string)),
                auto_tz: Mutex::new(auto_tz),
                apply_calls: Mutex::new(Vec::new()),
                restore_calls: Mutex::new(Vec::new()),
                fail_apply: Mutex::new(None),
                fail_restore: Mutex::new(None),
            }
        }
    }

    impl OsTzPlatform for FakeOsTzPlatform {
        fn current_iana_timezone(&self) -> Result<String, String> {
            Ok(self.current_iana.lock().unwrap().clone())
        }

        fn current_windows_tz_id(&self) -> Result<Option<String>, String> {
            Ok(self.current_win.lock().unwrap().clone())
        }

        fn is_auto_tz_enabled(&self) -> Result<Option<bool>, String> {
            Ok(*self.auto_tz.lock().unwrap())
        }

        fn apply_timezone(&self, target_iana: &str, disable_auto_tz: bool) -> Result<(), String> {
            if let Some(err) = self.fail_apply.lock().unwrap().clone() {
                return Err(err);
            }
            self.apply_calls
                .lock()
                .unwrap()
                .push((target_iana.to_string(), disable_auto_tz));
            *self.current_iana.lock().unwrap() = target_iana.to_string();
            if let Some(win) = iana_to_windows_tz(target_iana) {
                *self.current_win.lock().unwrap() = Some(win.to_string());
            }
            if disable_auto_tz {
                *self.auto_tz.lock().unwrap() = Some(false);
            }
            Ok(())
        }

        fn restore_timezone(
            &self,
            orig_iana: &str,
            orig_win_id: Option<&str>,
            restore_auto_tz: Option<bool>,
        ) -> Result<(), String> {
            if let Some(err) = self.fail_restore.lock().unwrap().clone() {
                return Err(err);
            }
            self.restore_calls.lock().unwrap().push((
                orig_iana.to_string(),
                orig_win_id.map(str::to_string),
                restore_auto_tz,
            ));
            *self.current_iana.lock().unwrap() = orig_iana.to_string();
            *self.current_win.lock().unwrap() = orig_win_id.map(str::to_string);
            if let Some(auto) = restore_auto_tz {
                *self.auto_tz.lock().unwrap() = Some(auto);
            }
            Ok(())
        }
    }

    #[test]
    fn iana_windows_mapping_covers_common_zones_and_aliases() {
        assert_eq!(iana_to_windows_tz("Europe/Paris"), Some("Romance Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Madrid"), Some("Romance Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Warsaw"), Some("Central European Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Berlin"), Some("W. Europe Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Amsterdam"), Some("W. Europe Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/London"), Some("GMT Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Helsinki"), Some("FLE Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Kyiv"), Some("FLE Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Kiev"), Some("FLE Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Bucharest"), Some("GTB Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Moscow"), Some("Russian Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Minsk"), Some("Belarus Standard Time"));
        assert_eq!(iana_to_windows_tz("Europe/Istanbul"), Some("Turkey Standard Time"));
        assert_eq!(iana_to_windows_tz("Asia/Dubai"), Some("Arabian Standard Time"));
        assert_eq!(iana_to_windows_tz("Asia/Tbilisi"), Some("Georgian Standard Time"));
        assert_eq!(iana_to_windows_tz("Asia/Yerevan"), Some("Caucasus Standard Time"));
        assert_eq!(iana_to_windows_tz("Asia/Almaty"), Some("West Asia Standard Time"));
        assert_eq!(iana_to_windows_tz("Asia/Calcutta"), Some("India Standard Time"));
        assert_eq!(iana_to_windows_tz("Asia/Tokyo"), Some("Tokyo Standard Time"));
        assert_eq!(iana_to_windows_tz("Asia/Singapore"), Some("Singapore Standard Time"));
        assert_eq!(iana_to_windows_tz("Asia/Hong_Kong"), Some("China Standard Time"));
        assert_eq!(iana_to_windows_tz("America/New_York"), Some("Eastern Standard Time"));
        assert_eq!(iana_to_windows_tz("America/Chicago"), Some("Central Standard Time"));
        assert_eq!(iana_to_windows_tz("America/Denver"), Some("Mountain Standard Time"));
        assert_eq!(iana_to_windows_tz("America/Los_Angeles"), Some("Pacific Standard Time"));
        assert_eq!(iana_to_windows_tz("America/Sao_Paulo"), Some("E. South America Standard Time"));
        assert_eq!(iana_to_windows_tz("Australia/Sydney"), Some("AUS Eastern Standard Time"));
        assert_eq!(iana_to_windows_tz("UTC"), Some("UTC"));
        assert_eq!(iana_to_windows_tz("Etc/UTC"), Some("UTC"));

        assert_eq!(windows_to_iana_tz("Romance Standard Time"), Some("Europe/Paris"));
        assert_eq!(windows_to_iana_tz("Russian Standard Time"), Some("Europe/Moscow"));
        assert_eq!(windows_to_iana_tz("W. Europe Standard Time"), Some("Europe/Berlin"));
        assert_eq!(windows_to_iana_tz("Eastern Standard Time"), Some("America/New_York"));
        assert!(allowlisted_windows_tz_id("Romance Standard Time").is_some());
        assert!(allowlisted_windows_tz_id("Romance Standard Time; rm -rf").is_none());
    }

    #[test]
    fn dry_run_prevents_real_os_effects_in_tests() {
        assert!(!os_tz_effects_enabled());
    }

    #[test]
    fn sync_writes_atomic_baseline_preserves_original_on_resync_and_restores() {
        let dir = TempDir::new().unwrap();
        let fake = FakeOsTzPlatform::new("Europe/Moscow", Some("Russian Standard Time"), Some(true));

        let status = sync_os_timezone_with(&fake, dir.path(), "Europe/Amsterdam").unwrap();
        assert!(status.synced);
        assert!(status.auto_restore_pending);
        assert_eq!(status.current_os_tz.as_deref(), Some("Europe/Amsterdam"));
        assert_eq!(status.original_os_tz.as_deref(), Some("Europe/Moscow"));
        assert_eq!(status.synced_target_tz.as_deref(), Some("Europe/Amsterdam"));

        let saved = read_baseline(dir.path()).unwrap().unwrap();
        assert_eq!(saved.original_iana, "Europe/Moscow");
        assert_eq!(saved.original_windows_id.as_deref(), Some("Russian Standard Time"));
        assert_eq!(saved.original_auto_tz, Some(true));
        assert_eq!(saved.synced_iana, "Europe/Amsterdam");

        #[cfg(unix)]
        {
            let mode = RealFs.mode(&baseline_path(dir.path())).unwrap().unwrap();
            assert_eq!(mode, 0o600);
        }

        // Re-syncing to another exit node must keep the original Moscow baseline intact.
        let status2 = sync_os_timezone_with(&fake, dir.path(), "Europe/Paris").unwrap();
        assert_eq!(status2.original_os_tz.as_deref(), Some("Europe/Moscow"));
        assert_eq!(status2.synced_target_tz.as_deref(), Some("Europe/Paris"));
        let saved2 = read_baseline(dir.path()).unwrap().unwrap();
        assert_eq!(saved2.original_iana, "Europe/Moscow");
        assert_eq!(saved2.original_auto_tz, Some(true));
        assert_eq!(saved2.synced_iana, "Europe/Paris");

        // Restoring returns to Moscow + restores auto_tz = true, and removes baseline.
        let restored = restore_os_timezone_with(&fake, dir.path()).unwrap();
        assert!(!restored.synced);
        assert!(!restored.auto_restore_pending);
        assert_eq!(restored.current_os_tz.as_deref(), Some("Europe/Moscow"));
        assert!(read_baseline(dir.path()).unwrap().is_none());
        assert_eq!(*fake.auto_tz.lock().unwrap(), Some(true));
    }

    #[test]
    fn sync_refuses_sanctioned_tz_and_cleans_up_on_elevation_cancel() {
        let dir = TempDir::new().unwrap();
        let fake = FakeOsTzPlatform::new("Europe/Moscow", Some("Russian Standard Time"), Some(false));

        // Refuse syncing TO a Russian/Belarusian timezone.
        let err = sync_os_timezone_with(&fake, dir.path(), "Europe/Minsk").unwrap_err();
        assert!(err.contains("РФ/РБ"), "{err}");
        assert!(read_baseline(dir.path()).unwrap().is_none());

        // Elevation cancelled leaves OS unchanged and removes newly created baseline.
        *fake.fail_apply.lock().unwrap() =
            Some("OS_TZ_ELEVATION_CANCELLED: cancelled".to_string());
        let err = sync_os_timezone_with(&fake, dir.path(), "Europe/Berlin").unwrap_err();
        assert!(err.starts_with("OS_TZ_ELEVATION_CANCELLED:"), "{err}");
        assert!(read_baseline(dir.path()).unwrap().is_none());
        assert_eq!(fake.current_iana_timezone().unwrap(), "Europe/Moscow");
    }

    #[test]
    fn restore_failure_preserves_baseline_for_retry_and_startup_recovery() {
        let dir = TempDir::new().unwrap();
        let fake = FakeOsTzPlatform::new("Europe/Moscow", Some("Russian Standard Time"), Some(false));

        sync_os_timezone_with(&fake, dir.path(), "Europe/London").unwrap();

        // Simulate user cancelling restore prompt on quit / disable.
        *fake.fail_restore.lock().unwrap() =
            Some("OS_TZ_ELEVATION_CANCELLED: cancelled".to_string());
        assert!(restore_if_synced_on_disable_with(&fake, dir.path()).is_err());
        assert!(read_baseline(dir.path()).unwrap().is_some());

        // Next startup recovery succeeds once elevation is permitted.
        *fake.fail_restore.lock().unwrap() = None;
        recover_baseline_on_start_with(&fake, dir.path());
        assert!(read_baseline(dir.path()).unwrap().is_none());
        assert_eq!(fake.current_iana_timezone().unwrap(), "Europe/Moscow");
    }

    #[test]
    fn validates_iana_names_strictly() {
        assert!(validate_iana_tz("Europe/Berlin").is_ok());
        assert!(validate_iana_tz("America/Argentina/Buenos_Aires").is_ok());
        assert!(validate_iana_tz("Etc/GMT+3").is_ok());
        assert!(validate_iana_tz("Europe/Berlin; rm -rf /").is_err());
        assert!(validate_iana_tz("../etc/passwd").is_err());
        assert!(validate_iana_tz("/usr/share/zoneinfo/UTC").is_err());
        assert!(validate_iana_tz("").is_err());
    }
}
