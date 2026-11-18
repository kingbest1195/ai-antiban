//! IANA <-> Windows Time Zone ID mapping, aliases, and validation.

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
    ("Europe/Prague", "Central European Standard Time"),
    ("Europe/Budapest", "Central European Standard Time"),
    ("Europe/Belgrade", "Central European Standard Time"),
    ("Europe/Bratislava", "Central European Standard Time"),
    ("Europe/Ljubljana", "Central European Standard Time"),
    ("Europe/Podgorica", "Central European Standard Time"),
    ("Europe/Tirane", "Central European Standard Time"),
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
    if clean
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(format!("Недопустимый формат часового пояса: {clean}"));
    }
    Ok(clean)
}

pub(super) fn zones_equivalent(a: &str, b: &str) -> bool {
    let ca = canonicalize_iana_tz(a);
    let cb = canonicalize_iana_tz(b);
    ca.eq_ignore_ascii_case(cb)
        || ca
            .replace('_', " ")
            .eq_ignore_ascii_case(&cb.replace('_', " "))
}
