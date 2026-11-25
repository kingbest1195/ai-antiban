use super::*;

#[test]
fn test_load_bundled_rules() {
    let rules = RuleSet::load_bundled().expect("bundled rules should parse successfully");
    let matrix = rules.provider_matrix.blocking_read();
    assert_eq!(matrix.version, "1.1.0");
    assert!(matrix.global_blocked_countries.contains(&"RU".to_string()));
    assert!(matrix.global_blocked_countries.contains(&"HK".to_string()));
    assert!(matrix.providers.contains_key("anthropic"));
    assert!(matrix.providers.contains_key("openai"));
    assert!(matrix.providers.contains_key("gemini"));

    let asns = rules.dangerous_asns.blocking_read();
    assert_eq!(asns.version, "1.3.0");
    assert_eq!(asns.dnsbl_zones.len(), 5);
    assert_eq!(asns.asn_entry(9009).map(|e| e.kind), Some(NetworkKind::Vpn));
    assert_eq!(
        asns.asn_entry(13335).map(|e| e.kind),
        Some(NetworkKind::Vpn)
    );
    assert_eq!(
        asns.asn_entry(24940).map(|e| e.kind),
        Some(NetworkKind::Hosting)
    );
    assert_eq!(
        asns.matches_russian_isp("Rostelecom broadband"),
        Some("Rostelecom")
    );
}

/// Every record of the type lists is traceable: a non-empty source that names a licence.
/// A record without a source (or without a licence) must not be in the file.
#[test]
fn dangerous_asns_schema_every_record_has_source_and_license() {
    let raw: serde_json::Value =
        serde_json::from_str(DEFAULT_DANGEROUS_ASNS_JSON).expect("valid JSON");
    // Strict shape: the typed parse rejects a record with a missing field or an unknown type.
    let asns = DangerousAsns::load_bundled().expect("schema");
    assert!(!asns.asns.is_empty() && !asns.isp_keyword_groups.is_empty());

    let has_source = |s: &str| {
        let t = s.trim();
        !t.is_empty() && t.to_lowercase().contains("license:")
    };
    for e in &asns.asns {
        assert!(
            has_source(&e.source),
            "AS{} has no source with a licence",
            e.asn
        );
        assert!(!e.name.trim().is_empty(), "AS{} has no name", e.asn);
        assert!(
            e.kind != NetworkKind::Residential,
            "AS{}: an ASN is hosting or vpn, residential is keyword-only",
            e.asn
        );
        if e.kind == NetworkKind::Vpn {
            assert!(
                !e.reason.trim().is_empty(),
                "AS{}: a vpn entry needs a reason",
                e.asn
            );
        }
    }
    for g in &asns.isp_keyword_groups {
        assert!(
            has_source(&g.source),
            "keyword group {:?} has no source",
            g.kind
        );
        assert!(!g.keywords.is_empty() && g.keywords.iter().all(|k| !k.trim().is_empty()));
    }
    // No ASN twice (the first would silently win).
    let mut seen = std::collections::HashSet::new();
    for e in &asns.asns {
        assert!(seen.insert(e.asn), "AS{} is listed twice", e.asn);
    }
    // The raw file has no record of the type lists that the typed parse would have dropped.
    assert_eq!(raw["asns"].as_array().map(Vec::len), Some(asns.asns.len()));
    assert_eq!(
        raw["isp_keyword_groups"].as_array().map(Vec::len),
        Some(asns.isp_keyword_groups.len())
    );
}

#[test]
fn a_record_without_source_is_rejected_by_the_schema() {
    let bad = DEFAULT_DANGEROUS_ASNS_JSON.replacen("\"source\"", "\"src\"", 1);
    assert!(serde_json::from_str::<DangerousAsns>(&bad).is_err());
    let bad_type =
        DEFAULT_DANGEROUS_ASNS_JSON.replacen("\"type\": \"vpn\"", "\"type\": \"magic\"", 1);
    assert!(serde_json::from_str::<DangerousAsns>(&bad_type).is_err());
}

#[test]
fn provider_matrix_is_valid() {
    let m = ProviderMatrix::load_bundled().expect("provider_matrix.json");
    assert!(!m.providers.is_empty());
    let bytes1 = m.canonical_payload_bytes().unwrap();
    let bytes2 = m.canonical_payload_bytes().unwrap();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn keyword_kind_hosting_wins_over_residential() {
    let asns = DangerousAsns::load_bundled().unwrap();
    assert_eq!(
        asns.keyword_kind("Example Cloud Communications"),
        Some(NetworkKind::Hosting)
    );
    assert_eq!(
        asns.keyword_kind("Example Broadband Ltd"),
        Some(NetworkKind::Residential)
    );
    assert_eq!(asns.keyword_kind("Example Net"), None);
}

#[test]
fn keyword_kind_uses_word_boundaries_and_vpn_wins() {
    let asns = DangerousAsns::load_bundled().unwrap();
    assert_eq!(
        asns.keyword_kind("Example VPN Hosting"),
        Some(NetworkKind::Vpn)
    );
    assert_eq!(asns.keyword_kind("NordVPN Server"), Some(NetworkKind::Vpn));
    // Substrings inside larger words must not falsely trigger VPN or hosting.
    assert_eq!(
        asns.keyword_kind("Vector Telecom"),
        Some(NetworkKind::Residential)
    );
    assert_eq!(asns.keyword_kind("Subvpnware Ltd"), None);
    assert_eq!(asns.keyword_kind("Cloudflare Inc."), None);
}
