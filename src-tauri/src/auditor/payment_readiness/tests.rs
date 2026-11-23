use super::*;
use crate::bin_checker::{BinChecker, BinSource, CardFunding, ClaudeWebVerdict};
use crate::state::AppStateData;

fn bin_report_from_overlay(bin: &str, vpn_cc: Option<&str>) -> BinReport {
    let checker = BinChecker::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(checker.check_bin_report_with_cache_dir(bin, vpn_cc, None))
        .unwrap()
}

#[test]
fn andrew_incident_sg_bin_de_vpn_de_billing_gpay_is_red_below_50() {
    let bin = bin_report_from_overlay("493724", Some("DE"));
    let input = PaymentReadinessInput {
        exit_ip: Some("185.10.20.30".to_string()),
        exit_country: Some("DE".to_string()),
        exit_asn: Some(24940),
        is_pinned: true,
        is_datacenter_or_vpn: false,
        is_tor_or_mass_vpn: false,
        has_network_leaks: false,
        has_recent_jump_lt_4h: false,
        split_ip_checkout_risk: false,
        bin_report: Some(bin),
        billing_country: Some("DE".to_string()),
        google_profile_country: Some("RU".to_string()),
        apple_id_country: None,
        channel: PaymentChannel::GooglePayWeb,
        in_clean_room: true,
        warmup_hours: Some(120),
        account_age_confirmed_96h: None,
        plan: SubscriptionPlan::Pro,
        target_service: None,
        evaluated_at: 1_700_000_000,
    };

    let report = evaluate_payment_readiness(&input);
    assert_eq!(report.tier, ReadinessTier::Red);
    assert!(
        report.score < 50,
        "expected score < 50, got {}",
        report.score
    );
    assert!(!report.blockers.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("Google Pay") && w.contains("реальную страну")),
        "expected Google Pay trap warning, got {:?}",
        report.warnings
    );
    assert!(report.requires_matching_billing);
}

#[test]
fn ru_or_by_bin_forces_hard_zero_and_red() {
    let mut bin = bin_report_from_overlay("220012", Some("DE"));
    bin.country_code = Some("RU".to_string());
    let input = PaymentReadinessInput {
        exit_ip: Some("1.2.3.4".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        bin_report: Some(bin),
        billing_country: Some("US".to_string()),
        channel: PaymentChannel::DirectCard,
        in_clean_room: true,
        warmup_hours: Some(120),
        account_age_confirmed_96h: None,
        plan: SubscriptionPlan::Pro,
        ..Default::default()
    };

    let report = evaluate_payment_readiness(&input);
    assert_eq!(report.score, 0);
    assert_eq!(report.tier, ReadinessTier::Red);
    assert!(!report.blockers.is_empty());
}

#[test]
fn fail_closed_fallback_unknown_forbids_green_tier() {
    let unknown_bin = BinReport {
        bin_prefix: "599999".to_string(),
        status: CheckStatus::Unknown,
        scheme: None,
        funding: CardFunding::Unknown,
        is_prepaid: None,
        is_commercial: None,
        is_reloadable: None,
        card_category: None,
        country_code: Some("US".to_string()),
        issuer_name: None,
        known_fintech_label: None,
        source: BinSource::FallbackUnknown,
        claude_web_verdict: ClaudeWebVerdict::HighKycRisk,
        warnings: vec!["Не удалось проверить BIN".to_string()],
    };

    let input = PaymentReadinessInput {
        exit_ip: Some("1.2.3.4".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        bin_report: Some(unknown_bin),
        billing_country: Some("US".to_string()),
        channel: PaymentChannel::DirectCard,
        in_clean_room: true,
        warmup_hours: Some(120),
        account_age_confirmed_96h: None,
        plan: SubscriptionPlan::Pro,
        ..Default::default()
    };

    let report = evaluate_payment_readiness(&input);
    assert!(report.fail_closed_bin);
    assert_ne!(report.tier, ReadinessTier::Green);
    assert!(report.score <= 79);
}

#[test]
fn apple_iap_us_context_removes_stripe_radar_risk_and_scores_green() {
    let input = PaymentReadinessInput {
        exit_ip: Some("23.45.67.89".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        bin_report: None,
        billing_country: None,
        apple_id_country: Some("US".to_string()),
        channel: PaymentChannel::AppleIAP,
        in_clean_room: false,
        warmup_hours: Some(12),
        plan: SubscriptionPlan::Max,
        ..Default::default()
    };

    let report = evaluate_payment_readiness(&input);
    assert_eq!(report.tier, ReadinessTier::Green);
    assert_eq!(report.score, 100);
    assert!(!report.requires_matching_billing);
    assert!(report.blockers.is_empty());
}

#[test]
fn max_plan_under_96h_penalized_and_flagged() {
    let clean_us_bin = BinReport {
        bin_prefix: "411111".to_string(),
        status: CheckStatus::Ok,
        scheme: Some("VISA".to_string()),
        funding: CardFunding::Debit,
        is_prepaid: Some(false),
        is_commercial: Some(false),
        is_reloadable: Some(true),
        card_category: Some("CLASSIC".to_string()),
        country_code: Some("US".to_string()),
        issuer_name: Some("Chase".to_string()),
        known_fintech_label: None,
        source: BinSource::ProxyApi,
        claude_web_verdict: ClaudeWebVerdict::SafeAligned,
        warnings: vec![],
    };

    let input = PaymentReadinessInput {
        exit_ip: Some("23.45.67.89".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        bin_report: Some(clean_us_bin),
        billing_country: Some("US".to_string()),
        channel: PaymentChannel::DirectCard,
        in_clean_room: true,
        warmup_hours: Some(24),
        plan: SubscriptionPlan::Max,
        ..Default::default()
    };

    let report = evaluate_payment_readiness(&input);
    assert_ne!(report.tier, ReadinessTier::Green);
    assert!(report.score <= 79);
    assert!(
        report
            .blockers
            .iter()
            .any(|b| b.contains("Max") && b.contains("96"))
    );
}

#[test]
fn clean_us_debit_in_clean_room_after_96h_scores_green() {
    let clean_us_bin = BinReport {
        bin_prefix: "411111".to_string(),
        status: CheckStatus::Ok,
        scheme: Some("VISA".to_string()),
        funding: CardFunding::Debit,
        is_prepaid: Some(false),
        is_commercial: Some(false),
        is_reloadable: Some(true),
        card_category: Some("CLASSIC".to_string()),
        country_code: Some("US".to_string()),
        issuer_name: Some("Chase".to_string()),
        known_fintech_label: None,
        source: BinSource::ProxyApi,
        claude_web_verdict: ClaudeWebVerdict::SafeAligned,
        warnings: vec![],
    };

    let state = AppStateData::default();
    let input = PaymentReadinessInput::from_runtime(
        &state,
        None,
        Some(clean_us_bin),
        Some("US".to_string()),
        None,
        None,
        PaymentChannel::DirectCard,
        true,
        SubscriptionPlan::Pro,
        false,
        None,
    );
    // Inject clean pinned US exit + 120h warmup.
    let input = PaymentReadinessInput {
        exit_ip: Some("23.45.67.89".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        warmup_hours: Some(120),
        ..input
    };
    let report = evaluate_payment_readiness(&input);
    assert_eq!(report.tier, ReadinessTier::Green);
    assert_eq!(report.score, 100);
}

#[test]
fn bin_report_with_missing_country_forces_fail_closed_and_forbids_green() {
    let missing_country_bin = BinReport {
        bin_prefix: "411111".to_string(),
        status: CheckStatus::Ok,
        scheme: Some("VISA".to_string()),
        funding: CardFunding::Debit,
        is_prepaid: Some(false),
        is_commercial: Some(false),
        is_reloadable: None,
        card_category: None,
        country_code: None,
        issuer_name: Some("Opaque Issuer".to_string()),
        known_fintech_label: None,
        source: BinSource::FallbackPublicApi,
        claude_web_verdict: ClaudeWebVerdict::SafeAligned,
        warnings: vec![],
    };
    let input = PaymentReadinessInput {
        exit_ip: Some("23.45.67.89".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        bin_report: Some(missing_country_bin),
        billing_country: Some("US".to_string()),
        channel: PaymentChannel::DirectCard,
        in_clean_room: true,
        warmup_hours: Some(120),
        account_age_confirmed_96h: None,
        plan: SubscriptionPlan::Pro,
        ..Default::default()
    };

    let report = evaluate_payment_readiness(&input);
    assert!(report.fail_closed_bin);
    assert_ne!(report.tier, ReadinessTier::Green);
}

#[test]
fn non_ru_by_blocked_bin_hk_redotpay_forces_red_even_with_matching_ip_and_billing() {
    let hk_redot = bin_report_from_overlay("40403812", Some("HK"));
    assert_eq!(hk_redot.country_code.as_deref(), Some("HK"));
    assert_eq!(hk_redot.claude_web_verdict, ClaudeWebVerdict::Blocked);

    let input = PaymentReadinessInput {
        exit_ip: Some("45.64.240.10".to_string()),
        exit_country: Some("HK".to_string()),
        is_pinned: true,
        bin_report: Some(hk_redot),
        billing_country: Some("HK".to_string()),
        channel: PaymentChannel::DirectCard,
        in_clean_room: true,
        warmup_hours: Some(120),
        account_age_confirmed_96h: None,
        plan: SubscriptionPlan::Pro,
        ..Default::default()
    };

    let report = evaluate_payment_readiness(&input);
    assert_eq!(report.tier, ReadinessTier::Red);
    assert_eq!(report.score, 0);
    assert!(!report.blockers.is_empty());
}

fn assert_no_banned_jargon(text: &str) {
    let lower = text.to_lowercase();
    for term in [
        "payshield",
        "stripe",
        "bin-рентген",
        "финтех-bin",
        "fail-closed",
        "fallbackunknown",
        "persona",
        "kyc",
        "apple iap",
        "directcard",
        "биллинг",
        "чекаут",
        "split-ip",
        "is_pinned",
        "tainted",
        "webrtc",
        "stun",
        "пост-платёжный карантин",
        "vc.ru",
        "prepaid",
        "commercial",
        "business",
        "coworkvmservice",
    ] {
        assert!(!lower.contains(term), "banned term '{term}' in: {text}");
    }
    for word in text.split(|c: char| !c.is_alphanumeric() && c != '_') {
        assert!(
            !word.eq_ignore_ascii_case("bin") && !word.eq_ignore_ascii_case("asn"),
            "banned standalone acronym '{word}' in: {text}"
        );
    }
    for cc in ["SE", "DE", "SG", "US", "GB", "RU", "BY", "KZ", "HK"] {
        for (idx, _) in text.match_indices(cc) {
            let before_ok = idx == 0 || !text.as_bytes()[idx - 1].is_ascii_alphabetic();
            let after_ok = text
                .as_bytes()
                .get(idx + cc.len())
                .is_none_or(|b| !b.is_ascii_alphabetic());
            if before_ok && after_ok {
                let before = idx
                    .checked_sub(1)
                    .and_then(|i| text.as_bytes().get(i).copied());
                let after = text.as_bytes().get(idx + cc.len()).copied();
                assert!(
                    before == Some(b'(') && after == Some(b')'),
                    "bare country code '{cc}' outside parentheses in: {text}"
                );
            }
        }
    }
}

#[test]
fn all_payment_readiness_user_strings_are_free_of_banned_jargon() {
    let sg_bin = bin_report_from_overlay("493724", Some("DE"));
    let ru_bin = bin_report_from_overlay("220012", Some("DE"));
    let commercial_bin = bin_report_from_overlay("446614", Some("SG"));
    let unknown_bin = BinReport {
        bin_prefix: "599999".to_string(),
        status: CheckStatus::Unknown,
        scheme: None,
        funding: CardFunding::Unknown,
        is_prepaid: None,
        is_commercial: None,
        is_reloadable: None,
        card_category: None,
        country_code: None,
        issuer_name: None,
        known_fintech_label: None,
        source: BinSource::FallbackUnknown,
        claude_web_verdict: ClaudeWebVerdict::HighKycRisk,
        warnings: vec![],
    };

    let scenarios = [
        PaymentReadinessInput {
            exit_ip: None,
            exit_country: Some("RU".to_string()),
            is_pinned: false,
            is_datacenter_or_vpn: true,
            is_tor_or_mass_vpn: true,
            has_network_leaks: true,
            has_recent_jump_lt_4h: true,
            split_ip_checkout_risk: true,
            bin_report: Some(sg_bin),
            billing_country: Some("DE".to_string()),
            google_profile_country: Some("SE".to_string()),
            channel: PaymentChannel::GooglePayWeb,
            in_clean_room: false,
            warmup_hours: Some(12),
            plan: SubscriptionPlan::Max,
            ..Default::default()
        },
        PaymentReadinessInput {
            exit_ip: Some("1.2.3.4".to_string()),
            exit_country: Some("SE".to_string()),
            is_pinned: false,
            is_datacenter_or_vpn: true,
            bin_report: Some(commercial_bin),
            billing_country: None,
            channel: PaymentChannel::DirectCard,
            in_clean_room: false,
            warmup_hours: Some(48),
            plan: SubscriptionPlan::Pro,
            ..Default::default()
        },
        PaymentReadinessInput {
            exit_ip: Some("1.2.3.4".to_string()),
            exit_country: Some("DE".to_string()),
            is_pinned: true,
            bin_report: Some(unknown_bin),
            channel: PaymentChannel::DirectCard,
            in_clean_room: true,
            warmup_hours: Some(120),
            plan: SubscriptionPlan::Pro,
            ..Default::default()
        },
        PaymentReadinessInput {
            exit_ip: Some("1.2.3.4".to_string()),
            exit_country: Some("DE".to_string()),
            is_pinned: true,
            bin_report: Some(ru_bin),
            apple_id_country: Some("KZ".to_string()),
            channel: PaymentChannel::AppleIAP,
            ..Default::default()
        },
        PaymentReadinessInput {
            exit_ip: Some("1.2.3.4".to_string()),
            exit_country: Some("US".to_string()),
            is_pinned: true,
            channel: PaymentChannel::Api,
            ..Default::default()
        },
    ];

    for input in &scenarios {
        let report = evaluate_payment_readiness(input);
        for axis in [
            &report.axes.network_base,
            &report.axes.card_bin,
            &report.axes.geo_billing_parity,
            &report.axes.channel_env_warmup,
        ] {
            assert_no_banned_jargon(&axis.label);
            for note in &axis.notes {
                assert_no_banned_jargon(note);
            }
        }
        for msg in report
            .warnings
            .iter()
            .chain(report.blockers.iter())
            .chain(report.recommended_action.iter())
        {
            assert_no_banned_jargon(msg);
        }
    }
}

#[test]
fn account_age_confirmed_96h_removes_warmup_and_max_penalties_and_advice() {
    let clean_us_bin = BinReport {
        bin_prefix: "411111".to_string(),
        status: CheckStatus::Ok,
        scheme: Some("VISA".to_string()),
        funding: CardFunding::Debit,
        is_prepaid: Some(false),
        is_commercial: Some(false),
        is_reloadable: Some(true),
        card_category: Some("CLASSIC".to_string()),
        country_code: Some("US".to_string()),
        issuer_name: Some("Chase".to_string()),
        known_fintech_label: None,
        source: BinSource::ProxyApi,
        claude_web_verdict: ClaudeWebVerdict::SafeAligned,
        warnings: vec![],
    };

    // Unconfirmed without warmup timer: penalized & Max blocker & warmup advice
    let unconfirmed = evaluate_payment_readiness(&PaymentReadinessInput {
        exit_ip: Some("23.45.67.89".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        bin_report: Some(clean_us_bin.clone()),
        billing_country: Some("US".to_string()),
        channel: PaymentChannel::DirectCard,
        in_clean_room: true,
        warmup_hours: None,
        account_age_confirmed_96h: None,
        plan: SubscriptionPlan::Max,
        ..Default::default()
    });
    assert_eq!(unconfirmed.tier, ReadinessTier::Yellow);
    assert!(unconfirmed.score < 100);
    assert!(!unconfirmed.blockers.is_empty());

    // Confirmed >= 96h without running warmup timer: full score, Green, no warmup warning/advice
    let confirmed_max = evaluate_payment_readiness(&PaymentReadinessInput {
        exit_ip: Some("23.45.67.89".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        bin_report: Some(clean_us_bin.clone()),
        billing_country: Some("US".to_string()),
        channel: PaymentChannel::DirectCard,
        in_clean_room: true,
        warmup_hours: Some(12),
        account_age_confirmed_96h: Some(true),
        plan: SubscriptionPlan::Max,
        ..Default::default()
    });
    assert_eq!(confirmed_max.tier, ReadinessTier::Green);
    assert_eq!(confirmed_max.score, 100);
    assert!(confirmed_max.blockers.is_empty());
    assert!(!confirmed_max.warnings.iter().any(|w| w.contains("96 ч")));

    // When Yellow for another reason (e.g. prepaid card + outside clean room), confirmed 96h suppresses warmup advice
    let mut prepaid_us_bin = clean_us_bin;
    prepaid_us_bin.is_prepaid = Some(true);
    let yellow_other = evaluate_payment_readiness(&PaymentReadinessInput {
        exit_ip: Some("23.45.67.89".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        bin_report: Some(prepaid_us_bin),
        billing_country: Some("US".to_string()),
        channel: PaymentChannel::DirectCard,
        in_clean_room: false,
        warmup_hours: None,
        account_age_confirmed_96h: Some(true),
        plan: SubscriptionPlan::Pro,
        ..Default::default()
    });
    assert_eq!(yellow_other.tier, ReadinessTier::Yellow);
    assert!(
        !yellow_other
            .recommended_action
            .as_deref()
            .unwrap_or("")
            .contains("выдержите 96 ч прогрева")
    );
}
