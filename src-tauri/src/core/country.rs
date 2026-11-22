//! Human-readable Russian country names and formatting helpers (Layer 0).

/// Normalizes an ISO-3166-1 alpha-2 country code (`uk` -> `GB`, uppercase, trimmed).
pub fn normalize_country_code(code: &str) -> String {
    let upper = code.trim().to_ascii_uppercase();
    if upper.is_empty() || upper == "--" {
        return String::new();
    }
    if upper == "UK" {
        "GB".to_string()
    } else {
        upper
    }
}

/// Maps an ISO-3166-1 alpha-2 code to its Russian country name.
pub fn country_name_ru(code: &str) -> Option<&'static str> {
    match normalize_country_code(code).as_str() {
        "US" => Some("США"),
        "GB" => Some("Великобритания"),
        "DE" => Some("Германия"),
        "NL" => Some("Нидерланды"),
        "SE" => Some("Швеция"),
        "FR" => Some("Франция"),
        "FI" => Some("Финляндия"),
        "SG" => Some("Сингапур"),
        "KZ" => Some("Казахстан"),
        "KG" => Some("Кыргызстан"),
        "AM" => Some("Армения"),
        "GE" => Some("Грузия"),
        "UZ" => Some("Узбекистан"),
        "RU" => Some("Россия"),
        "BY" => Some("Беларусь"),
        "HK" => Some("Гонконг"),
        "CN" => Some("Китай"),
        "MO" => Some("Макао"),
        "PR" => Some("Пуэрто-Рико"),
        "TR" => Some("Турция"),
        "AE" => Some("ОАЭ"),
        "PL" => Some("Польша"),
        "LT" => Some("Литва"),
        "LV" => Some("Латвия"),
        "EE" => Some("Эстония"),
        "CH" => Some("Швейцария"),
        "AT" => Some("Австрия"),
        "IE" => Some("Ирландия"),
        "ES" => Some("Испания"),
        "IT" => Some("Италия"),
        "PT" => Some("Португалия"),
        "CA" => Some("Канада"),
        "AU" => Some("Австралия"),
        "JP" => Some("Япония"),
        "KR" => Some("Южная Корея"),
        "NO" => Some("Норвегия"),
        "DK" => Some("Дания"),
        "BE" => Some("Бельгия"),
        "CZ" => Some("Чехия"),
        "UA" => Some("Украина"),
        "MD" => Some("Молдова"),
        "AZ" => Some("Азербайджан"),
        "TJ" => Some("Таджикистан"),
        "TM" => Some("Туркменистан"),
        "IR" => Some("Иран"),
        "KP" => Some("КНДР"),
        "SY" => Some("Сирия"),
        "CU" => Some("Куба"),
        "VE" => Some("Венесуэла"),
        "AF" => Some("Афганистан"),
        "MM" => Some("Мьянма"),
        "SD" => Some("Судан"),
        "YE" => Some("Йемен"),
        "IL" => Some("Израиль"),
        "IN" => Some("Индия"),
        "MX" => Some("Мексика"),
        "BR" => Some("Бразилия"),
        "AR" => Some("Аргентина"),
        "CY" => Some("Кипр"),
        "RS" => Some("Сербия"),
        "RO" => Some("Румыния"),
        "BG" => Some("Болгария"),
        "GR" => Some("Греция"),
        "HU" => Some("Венгрия"),
        "SK" => Some("Словакия"),
        "SI" => Some("Словения"),
        "HR" => Some("Хорватия"),
        "LU" => Some("Люксембург"),
        "MT" => Some("Мальта"),
        "IS" => Some("Исландия"),
        "TW" => Some("Тайвань"),
        "TH" => Some("Таиланд"),
        "VN" => Some("Вьетнам"),
        "ID" => Some("Индонезия"),
        "MY" => Some("Малайзия"),
        "PH" => Some("Филиппины"),
        _ => None,
    }
}

/// Formats a country code as `"Название (CC)"`, e.g. `"Германия (DE)"`.
pub fn format_country_ru(code: &str) -> String {
    let cc = normalize_country_code(code);
    if cc.is_empty() {
        return String::new();
    }
    match country_name_ru(&cc) {
        Some(name) => format!("{name} ({cc})"),
        None => format!("страна ({cc})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_and_unknown_countries_in_russian() {
        assert_eq!(format_country_ru("de"), "Германия (DE)");
        assert_eq!(format_country_ru("SE"), "Швеция (SE)");
        assert_eq!(format_country_ru("SG"), "Сингапур (SG)");
        assert_eq!(format_country_ru("uk"), "Великобритания (GB)");
        assert_eq!(format_country_ru("zz"), "страна (ZZ)");
        assert_eq!(format_country_ru(" "), "");
    }
}
