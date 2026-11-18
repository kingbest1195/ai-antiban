pub use crate::core::sanctions::{
    is_blocked_geo_code, is_sanctioned_locale, is_sanctioned_or_blocked_country,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanctioned_or_blocked_country_detection() {
        assert!(is_sanctioned_or_blocked_country("RU"));
        assert!(is_sanctioned_or_blocked_country("ru"));
        assert!(is_sanctioned_or_blocked_country(" BY "));
        assert!(is_sanctioned_or_blocked_country("IR"));
        assert!(is_sanctioned_or_blocked_country("KP"));
        assert!(is_sanctioned_or_blocked_country("SY"));
        assert!(is_sanctioned_or_blocked_country("CU"));

        // Clean countries are not sanctioned
        assert!(!is_sanctioned_or_blocked_country("NL"));
        assert!(!is_sanctioned_or_blocked_country("GB"));
        assert!(!is_sanctioned_or_blocked_country("US"));
        assert!(!is_sanctioned_or_blocked_country("DE"));
        assert!(!is_sanctioned_or_blocked_country("SE"));
        assert!(!is_sanctioned_or_blocked_country("PL"));
    }
}
