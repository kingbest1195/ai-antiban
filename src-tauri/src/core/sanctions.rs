//! Sanctioned/blocked country codes, geo-blocking predicates, and locale hygiene matching.

/// Checks whether a country code is sanctioned/high-risk and must NEVER be auto-pinned as AI timezone.
pub fn is_sanctioned_or_blocked_country(country_code: &str) -> bool {
    const BLOCKED: &[&str] = &["RU", "BY", "IR", "KP", "SY", "CU"];
    BLOCKED
        .iter()
        .any(|c| c.eq_ignore_ascii_case(country_code.trim()))
}

/// Returns `true` when `country_code` is sanctioned or geo-blocked for AI provider access
/// (includes sanctioned countries plus `HK`, `CN`, and `MO`).
pub fn is_blocked_geo_code(country_code: &str) -> bool {
    let cc = country_code.trim();
    is_sanctioned_or_blocked_country(cc)
        || cc.eq_ignore_ascii_case("HK")
        || cc.eq_ignore_ascii_case("CN")
        || cc.eq_ignore_ascii_case("MO")
}

/// Whether a locale tag (`ru_RU.UTF-8`, `ru-RU`, `en_RU`, `en_US@rg=ruzzzz`) points at Russia or
/// Belarus.
pub fn is_sanctioned_locale(raw: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanctioned_country_and_geo_block_checks() {
        for cc in ["RU", "ru", " BY ", "IR", "KP", "SY", "CU"] {
            assert!(is_sanctioned_or_blocked_country(cc), "{cc}");
            assert!(is_blocked_geo_code(cc), "{cc}");
        }
        for cc in ["HK", "cn", " MO "] {
            assert!(!is_sanctioned_or_blocked_country(cc), "{cc}");
            assert!(is_blocked_geo_code(cc), "{cc}");
        }
        for cc in ["NL", "GB", "US", "DE", "SE", "PL"] {
            assert!(!is_sanctioned_or_blocked_country(cc), "{cc}");
            assert!(!is_blocked_geo_code(cc), "{cc}");
        }
    }

    #[test]
    fn sanctioned_locale_checks() {
        for yes in ["ru_RU.UTF-8", "be_BY", "ru-RU", "en_RU", "en_US@rg=ruzzzz"] {
            assert!(is_sanctioned_locale(yes), "{yes}");
        }
        for no in ["", "en_US.UTF-8", "de_DE", "en_GB@rg=nlzzzz"] {
            assert!(!is_sanctioned_locale(no), "{no}");
        }
    }
}
