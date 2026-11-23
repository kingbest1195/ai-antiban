use super::*;
use crate::auditor::geo_matrix::CheckStatus;

#[test]
fn evaluate_params_deserialize_account_age_confirmed_96h_camel_case() {
    let json = r#"{"accountAgeConfirmed96h":true,"inCleanRoom":true,"plan":"max","targetService":"gemini"}"#;
    let parsed: EvaluatePaymentReadinessParams = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.account_age_confirmed_96h, Some(true));
    assert!(parsed.in_clean_room);
    assert_eq!(parsed.plan, SubscriptionPlan::Max);
    assert_eq!(parsed.target_service, Some(AiPaymentService::Gemini));

    let empty: EvaluatePaymentReadinessParams = serde_json::from_str("{}").unwrap();
    assert_eq!(empty.account_age_confirmed_96h, None);
    assert_eq!(empty.target_service, None);
}

#[tokio::test]
async fn check_card_bin_ignores_placeholder_or_invalid_country_codes() {
    let checker = bin_checker::BinChecker::new();
    for invalid in ["", "--", " -- ", "12", "USA", "ru1"] {
        let report = check_card_bin_with("485953", Some(invalid), None, &checker)
            .await
            .unwrap();
        assert_eq!(report.status, CheckStatus::Ok, "raw={invalid}");
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.contains("текущее подключение — .")),
            "empty country placeholder leaked into warnings for '{invalid}': {:?}",
            report.warnings
        );
    }
}
