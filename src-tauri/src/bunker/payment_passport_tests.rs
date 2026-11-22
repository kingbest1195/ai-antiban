use super::payment_passport::{
    PassportChannel, PaymentPassport, RenewalCheckInput, load_payment_passport_in,
    save_payment_passport_in, validate_and_normalize_passport, verify_renewal_against_passport,
};

#[test]
fn payment_passport_enforces_zero_pan_and_bin_prefix_bounds() {
    let dir = tempfile::tempdir().unwrap();

    // Reject bin_prefix > 8 digits
    let too_long = PaymentPassport {
        profile_id: "cr-test1".to_string(),
        bin_prefix: "493724123".to_string(),
        card_country: "SG".to_string(),
        channel: PassportChannel::DirectCard,
        billing_country: "SG".to_string(),
        exit_ip: "1.2.3.4".to_string(),
        exit_asn: Some(13335),
        paid_at: 1_760_000_000,
    };
    let err = save_payment_passport_in(dir.path(), too_long).unwrap_err();
    assert!(err.contains("6–8") || err.contains("16-значный"));

    // Reject unknown sensitive fields like pan / cvv / last4 / expiry during deserialization
    for bad_field in [
        r#""pan":"4111111111111111""#,
        r#""cvv":"123""#,
        r#""last4":"1111""#,
        r#""expiry":"12/28""#,
    ] {
        let json = format!(
            r#"{{"profileId":"cr-test1","binPrefix":"446614","cardCountry":"US","channel":"directCard","billingCountry":"US","exitIp":"23.45.67.89","exitAsn":20473,"paidAt":1760000000,{bad_field}}}"#
        );
        assert!(
            serde_json::from_str::<PaymentPassport>(&json).is_err(),
            "must reject forbidden field {bad_field}"
        );
    }

    // Valid save & load + verify serialization contains zero PAN/CVV/last4/expiry keys
    let valid = PaymentPassport {
        profile_id: "cr-test1".to_string(),
        bin_prefix: "446614".to_string(),
        card_country: "us".to_string(),
        channel: PassportChannel::DirectCard,
        billing_country: "us".to_string(),
        exit_ip: "23.45.67.89".to_string(),
        exit_asn: Some(20473),
        paid_at: 1_760_000_000,
    };
    let saved = save_payment_passport_in(dir.path(), valid).unwrap();
    let serialized = serde_json::to_string(&saved).unwrap();
    for forbidden in ["pan", "cvv", "last4", "expiry"] {
        assert!(
            !serialized.to_ascii_lowercase().contains(forbidden),
            "serialized passport must not contain {forbidden}"
        );
    }

    let loaded = load_payment_passport_in(dir.path(), "cr-test1")
        .unwrap()
        .expect("passport exists");
    assert_eq!(loaded, saved);
    assert_eq!(loaded.card_country, "US");
    assert_eq!(loaded.billing_country, "US");
}

#[test]
fn payment_passport_verifies_renewal_consistency() {
    let passport = validate_and_normalize_passport(PaymentPassport {
        profile_id: "cr-renew".to_string(),
        bin_prefix: "44661412".to_string(),
        card_country: "US".to_string(),
        channel: PassportChannel::DirectCard,
        billing_country: "US".to_string(),
        exit_ip: "23.45.67.89".to_string(),
        exit_asn: Some(20473),
        paid_at: 1_760_000_000,
    })
    .unwrap();

    let ok = verify_renewal_against_passport(
        &passport,
        &RenewalCheckInput {
            bin_prefix: Some("44661412".to_string()),
            card_country: Some("US".to_string()),
            channel: Some(PassportChannel::DirectCard),
            billing_country: Some("US".to_string()),
            exit_ip: Some("23.45.67.89".to_string()),
            exit_asn: Some(20473),
        },
    );
    assert!(ok.matched);
    assert!(ok.mismatches.is_empty());

    let mismatch = verify_renewal_against_passport(
        &passport,
        &RenewalCheckInput {
            bin_prefix: Some("493724".to_string()),
            card_country: Some("SG".to_string()),
            channel: Some(PassportChannel::DirectCard),
            billing_country: Some("DE".to_string()),
            exit_ip: Some("185.10.20.30".to_string()),
            exit_asn: Some(24940),
        },
    );
    assert!(!mismatch.matched);
    assert!(mismatch.mismatches.len() >= 4);
    assert!(!mismatch.warnings.is_empty());
}

#[test]
fn payment_passport_errors_are_calm_russian_without_technical_jargon() {
    let bad_card_country = PaymentPassport {
        profile_id: "cr-err".to_string(),
        bin_prefix: "446614".to_string(),
        card_country: "--".to_string(),
        channel: PassportChannel::DirectCard,
        billing_country: "US".to_string(),
        exit_ip: "23.45.67.89".to_string(),
        exit_asn: None,
        paid_at: 1_760_000_000,
    };
    let bad_billing_country = PaymentPassport {
        card_country: "US".to_string(),
        billing_country: "123".to_string(),
        ..bad_card_country.clone()
    };
    let bad_bin = PaymentPassport {
        bin_prefix: "4111222233334444".to_string(),
        card_country: "US".to_string(),
        ..bad_card_country.clone()
    };

    for passport in [bad_card_country, bad_billing_country, bad_bin] {
        let err = validate_and_normalize_passport(passport).unwrap_err();
        for forbidden in [
            "!",
            "BIN",
            "ISO",
            "(For your privacy)",
            "НЕ ",
            "cardCountry",
            "billingCountry",
        ] {
            assert!(
                !err.contains(forbidden),
                "PaymentPassport error must not contain '{forbidden}': {err}"
            );
        }
    }
}
