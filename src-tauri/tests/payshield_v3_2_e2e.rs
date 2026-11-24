use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use zastava_lib::auditor::bin_radar_verify::{
    DEFAULT_BIN_RADAR_SNAPSHOT_JSON, DEFAULT_PROVIDERS_MANIFEST_JSON, LocalBinRadarReportRecord,
    MANIFEST_CACHE_FILE_NAME, MANIFEST_FILE_NAME, SNAPSHOT_CACHE_FILE_NAME, SNAPSHOT_FILE_NAME,
    load_bin_radar_snapshot, load_local_bin_radar_reports, load_providers_manifest,
    payshield_data_dir, save_verified_manifest, save_verified_snapshot,
    submit_local_bin_radar_report, verify_bin_radar_snapshot_json, verify_providers_manifest_json,
};
use zastava_lib::auditor::payment_advisor::{
    evaluate_advisor_plan, get_bin_radar_stats_for, get_evaluated_providers_manifest,
    merge_local_bin_radar_reports_at,
};
use zastava_lib::auditor::payment_readiness::{
    PaymentChannel, PaymentReadinessInput, ReadinessTier, evaluate_payment_readiness,
};
use zastava_lib::bunker::payment_passport::{PassportChannel, PaymentPassport};
use zastava_lib::core::bin_radar::{
    AiPaymentService, BinRadarEntry, BinRadarReport, BinRadarSnapshot, BinRadarStatus,
    BinRadarWindowStats, GeoMatchClass, PaymentChannel as RadarChannel, PaymentOutcome,
    TimestampedOutcome, WINDOW_14D_DAYS, WINDOW_14D_HALF_LIFE_DAYS, WINDOW_30D_DAYS,
    WINDOW_30D_HALF_LIFE_DAYS, WarmupBucket, compute_window_stats, decay_weight,
    lookup_bin_radar_stats, parse_bin_radar_report_json,
};
use zastava_lib::core::payment_advisor::{
    AdvisorNetworkContext, AdvisorQuery, KycRiskTier, PaymentRail,
};
use zastava_lib::core::providers_manifest::{
    ProviderCategory, ProviderEntry, ProviderStatus, ProviderTier, ProvidersManifest,
    evaluate_manifest_auto_demote, evaluate_provider_auto_demote,
};
use zastava_lib::state::AppStateData;

#[test]
fn e2e_1_ed25519_tamper_and_offline_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let app_dir = dir.path();

    // Bundled signed snapshot & manifest must verify against embedded Ed25519 public key.
    let bundled_snap = verify_bin_radar_snapshot_json(DEFAULT_BIN_RADAR_SNAPSHOT_JSON).unwrap();
    let bundled_manifest = verify_providers_manifest_json(DEFAULT_PROVIDERS_MANIFEST_JSON).unwrap();
    assert!(!bundled_snap.entries.is_empty());
    assert!(bundled_manifest.providers.len() >= 5);

    // Offline startup without local files uses embedded bundle safely.
    assert_eq!(load_bin_radar_snapshot(Some(app_dir)), bundled_snap);
    assert_eq!(load_providers_manifest(Some(app_dir)), bundled_manifest);

    // Save verified bundles to app_data_dir cache.
    save_verified_snapshot(app_dir, DEFAULT_BIN_RADAR_SNAPSHOT_JSON).unwrap();
    save_verified_manifest(app_dir, DEFAULT_PROVIDERS_MANIFEST_JSON).unwrap();

    // Tamper 1 byte in snapshot & manifest -> rejected without overwriting .cache.json.
    let tampered_snap = DEFAULT_BIN_RADAR_SNAPSHOT_JSON.replacen("14.7", "99.7", 1);
    assert!(verify_bin_radar_snapshot_json(&tampered_snap).is_err());
    assert!(save_verified_snapshot(app_dir, &tampered_snap).is_err());

    let tampered_man = DEFAULT_PROVIDERS_MANIFEST_JSON.replacen("WantToPay", "FakePay", 1);
    assert!(verify_providers_manifest_json(&tampered_man).is_err());
    assert!(save_verified_manifest(app_dir, &tampered_man).is_err());

    // Even if primary file on disk is tampered or corrupted, loader falls back to .cache.json.
    let ps_dir = payshield_data_dir(app_dir);
    fs::write(ps_dir.join(SNAPSHOT_FILE_NAME), &tampered_snap).unwrap();
    fs::write(ps_dir.join(MANIFEST_FILE_NAME), "{corrupt json").unwrap();
    assert!(ps_dir.join(SNAPSHOT_CACHE_FILE_NAME).is_file());
    assert!(ps_dir.join(MANIFEST_CACHE_FILE_NAME).is_file());
    assert_eq!(load_bin_radar_snapshot(Some(app_dir)), bundled_snap);
    assert_eq!(load_providers_manifest(Some(app_dir)), bundled_manifest);

    // If even cache is corrupted, loader safely falls back to embedded compile-time bundle.
    fs::write(ps_dir.join(SNAPSHOT_CACHE_FILE_NAME), "tampered").unwrap();
    fs::write(ps_dir.join(MANIFEST_CACHE_FILE_NAME), "tampered").unwrap();
    assert_eq!(load_bin_radar_snapshot(Some(app_dir)), bundled_snap);
    assert_eq!(load_providers_manifest(Some(app_dir)), bundled_manifest);
}

#[test]
fn e2e_2_zero_pii_zero_pci_opt_in_and_v3_compatibility() {
    let dir = tempfile::tempdir().unwrap();
    let app_dir = dir.path();

    // Legacy v3.1.1 state.json without bin_radar_opt_in must default to false.
    let legacy_state: AppStateData =
        serde_json::from_str(r#"{"schema_version":3,"strict_pinning_enabled":true}"#).unwrap();
    assert!(!legacy_state.bin_radar_opt_in);

    // Backward-compatible PassportChannel & PaymentChannel including GooglePlayIap.
    let p_legacy: PassportChannel = serde_json::from_str(r#""AppleIAP""#).unwrap();
    assert_eq!(p_legacy, PassportChannel::AppleIAP);
    let p_gplay: PassportChannel = serde_json::from_str(r#""google_play_iap""#).unwrap();
    assert_eq!(p_gplay, PassportChannel::GooglePlayIap);
    let p_gpay_alias: PassportChannel = serde_json::from_str(r#""GooglePayments""#).unwrap();
    assert_eq!(p_gpay_alias, PassportChannel::GooglePlayIap);
    let c_gplay: PaymentChannel = serde_json::from_str(r#""google_play_iap""#).unwrap();
    assert_eq!(c_gplay, PaymentChannel::GooglePlayIap);
    let passport_gplay = PaymentPassport {
        profile_id: "default".to_string(),
        bin_prefix: String::new(),
        card_country: "US".to_string(),
        channel: PassportChannel::GooglePlayIap,
        billing_country: "US".to_string(),
        exit_ip: "1.2.3.4".to_string(),
        exit_asn: None,
        paid_at: 1_760_000_000,
    };
    assert!(serde_json::to_string(&passport_gplay).is_ok());

    let valid_json = r#"{
        "bin_prefix":"49372400",
        "service":"claude_pro",
        "channel":"stripe_web_card",
        "geo_match":"triple_mismatch",
        "warmup_bucket":"lt_24h",
        "outcome":"instant_kyc",
        "client_version":"3.2.0"
    }"#;
    let parsed = parse_bin_radar_report_json(valid_json).unwrap();
    assert_eq!(parsed.channel, RadarChannel::StripeWebCard);
    assert_eq!(parsed.geo_match, GeoMatchClass::TripleMismatch);
    assert_eq!(parsed.warmup_bucket, WarmupBucket::Lt24h);

    // Opt-in disabled -> rejected.
    assert!(submit_local_bin_radar_report(app_dir, false, valid_json).is_err());

    // Extra PII/PCI fields or PAN > 8 digits -> rejected even when opt-in enabled.
    for bad_extra in [
        r#""email":"a@b.com""#,
        r#""ip":"1.2.3.4""#,
        r#""last4":"1234""#,
        r#""pan":"4937240012345678""#,
        r#""account_id":"acc_1""#,
    ] {
        let bad = format!(
            r#"{{"bin_prefix":"49372400","service":"claude_pro","channel":"stripe_web_card","geo_match":"full_match","warmup_bucket":"gt_96h","outcome":"success","client_version":"3.2.0",{bad_extra}}}"#
        );
        assert!(submit_local_bin_radar_report(app_dir, true, &bad).is_err());
    }
    for bad_bin in ["493724", "493724001", "4937240012345678", "4937240a"] {
        let bad = format!(
            r#"{{"bin_prefix":"{bad_bin}","service":"claude_pro","channel":"stripe_web_card","geo_match":"full_match","warmup_bucket":"gt_96h","outcome":"success","client_version":"3.2.0"}}"#
        );
        assert!(submit_local_bin_radar_report(app_dir, true, &bad).is_err());
    }

    // Valid opt-in submission persists locally with 0o600 permissions & zero PII.
    let saved = submit_local_bin_radar_report(app_dir, true, valid_json).unwrap();
    assert_eq!(saved.bin_prefix, "49372400");
    let records = load_local_bin_radar_reports(app_dir);
    assert_eq!(records.len(), 1);
    #[cfg(unix)]
    {
        let mode = fs::metadata(payshield_data_dir(app_dir).join("local_reports.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn e2e_3_statistical_hygiene_and_per_service_auto_demote() {
    assert!((decay_weight(0.0, WINDOW_14D_HALF_LIFE_DAYS) - 1.0).abs() < 1e-9);
    assert!((decay_weight(5.0, WINDOW_14D_HALF_LIFE_DAYS) - 0.5).abs() < 1e-6);

    let samples = vec![
        TimestampedOutcome {
            age_days: 0.5,
            outcome: PaymentOutcome::InstantKyc,
            weight_multiplier: 1.0,
        },
        TimestampedOutcome {
            age_days: 10.0,
            outcome: PaymentOutcome::Success,
            weight_multiplier: 1.0,
        },
        TimestampedOutcome {
            age_days: 20.0,
            outcome: PaymentOutcome::Success,
            weight_multiplier: 1.0,
        },
    ];
    let w14 = compute_window_stats(&samples, WINDOW_14D_DAYS, WINDOW_14D_HALF_LIFE_DAYS);
    let w30 = compute_window_stats(&samples, WINDOW_30D_DAYS, WINDOW_30D_HALF_LIFE_DAYS);
    assert_eq!(w14.n, 2);
    assert_eq!(w30.n, 3);
    assert!(w14.instant_kyc_pct > 75.0);

    // Bundled n < 5 entry must return insufficient_data without misleading percentages.
    let bundled_n3 = get_bin_radar_stats_for(None, "53787200", AiPaymentService::Cursor);
    assert_eq!(bundled_n3.status, BinRadarStatus::InsufficientData);
    assert!(bundled_n3.window_14d.is_none());

    // Synthetic n = 4 also returns insufficient_data.
    let snapshot_base = BinRadarSnapshot {
        schema_version: 1,
        generated_at_utc: "2026-11-23T00:00:00Z".to_string(),
        ttl_seconds: 86400,
        entries: vec![
            BinRadarEntry {
                bin_prefix: "48331200".to_string(),
                service: AiPaymentService::Gemini,
                window_14d: BinRadarWindowStats {
                    n: 15,
                    success_pct: 40.0,
                    soft_decline_pct: 13.3,
                    instant_kyc_pct: 33.4,
                    instant_ban_pct: 13.3, // 46.7% > 40%
                },
                window_30d: BinRadarWindowStats {
                    n: 15,
                    success_pct: 40.0,
                    soft_decline_pct: 13.3,
                    instant_kyc_pct: 33.4,
                    instant_ban_pct: 13.3,
                },
            },
            BinRadarEntry {
                bin_prefix: "48331200".to_string(),
                service: AiPaymentService::ClaudePro,
                window_14d: BinRadarWindowStats {
                    n: 20,
                    success_pct: 80.0,
                    soft_decline_pct: 10.0,
                    instant_kyc_pct: 5.0,
                    instant_ban_pct: 5.0,
                },
                window_30d: BinRadarWindowStats {
                    n: 20,
                    success_pct: 80.0,
                    soft_decline_pct: 10.0,
                    instant_kyc_pct: 5.0,
                    instant_ban_pct: 5.0,
                },
            },
        ],
        signature_ed25519_b64: String::new(),
    };
    let mut n4_snap = snapshot_base.clone();
    n4_snap.entries[0].window_14d.n = 4;
    n4_snap.entries[0].window_30d.n = 4;
    assert_eq!(
        lookup_bin_radar_stats(&n4_snap, "48331200", AiPaymentService::Gemini).status,
        BinRadarStatus::InsufficientData
    );

    // Affiliate link + auto_demote_exempt=true MUST STILL auto-demote when rate > 40% at n >= 15.
    let affiliate_provider = ProviderEntry {
        id: "wanttopay".to_string(),
        name: "WantToPay".to_string(),
        category: ProviderCategory::VirtualCard,
        tier: ProviderTier::Tier2Conditional,
        status: ProviderStatus::Active,
        known_bin_prefixes: vec!["48331200".to_string()],
        supported_rails: vec!["rub_sbp".to_string()],
        supported_services: vec![],
        fees_summary: "test".to_string(),
        warnings_ru: vec![],
        affiliate_url: Some("https://telegram.me/WantToPayBot?start=ref".to_string()),
        auto_demote_exempt: true,
    };
    let eval1 = evaluate_provider_auto_demote(&affiliate_provider, &snapshot_base);
    assert_eq!(
        eval1
            .per_service
            .iter()
            .find(|s| s.service == AiPaymentService::Gemini)
            .unwrap()
            .status,
        ProviderStatus::DemotedWarning
    );
    assert_eq!(
        eval1
            .per_service
            .iter()
            .find(|s| s.service == AiPaymentService::ClaudePro)
            .unwrap()
            .status,
        ProviderStatus::Active
    );
    assert!(!eval1.global_demoted);

    // >65% on a second service -> Blacklist + global_demoted.
    let mut snap2 = snapshot_base;
    snap2.entries[1].window_14d.instant_kyc_pct = 50.0;
    snap2.entries[1].window_14d.instant_ban_pct = 20.0;
    let manifest = ProvidersManifest {
        schema_version: 1,
        generated_at_utc: "2026-11-23T00:00:00Z".to_string(),
        ttl_seconds: 86400,
        providers: vec![affiliate_provider],
        blacklist: vec![],
        signature_ed25519_b64: String::new(),
    };
    let evaluated = evaluate_manifest_auto_demote(&manifest, &snap2);
    assert!(evaluated.providers[0].global_demoted);
    assert_eq!(
        evaluated.providers[0].effective_status,
        ProviderStatus::Blacklist
    );

    // Bundled manifest evaluates cleanly with all 5 providers active initially.
    let bundled_eval = get_evaluated_providers_manifest(None);
    assert_eq!(bundled_eval.providers.len(), 5);
}

#[test]
fn e2e_4_safe_payment_advisor_five_scenarios() {
    let clean_net = AdvisorNetworkContext {
        exit_country: Some("US".to_string()),
        trust_score: 95,
        clean_room_ready: true,
        is_zastava_key_active: true,
    };

    // Scenario 1: Apple IAP (ClaudePro + iPhone)
    let s1 = evaluate_advisor_plan(
        &AdvisorQuery {
            target_service: AiPaymentService::ClaudePro,
            has_iphone_apple_id: true,
            available_bin_prefix: None,
            payment_rails: vec![PaymentRail::RubSbp],
            willing_to_warmup_96h: true,
            google_payments_country: None,
            is_new_google_account: None,
            network_state: clean_net.clone(),
        },
        None,
    );
    assert_eq!(s1.primary.route_id, "apple_iap_us_gift");
    assert_eq!(s1.primary.kyc_risk_tier, KycRiskTier::Minimal);
    assert_eq!(
        s1.primary.provider_ids,
        vec!["tbank", "sberbank", "kupikod"]
    );
    let s1_text = s1.primary.checklist.join("\n");
    assert!(
        s1_text.contains("Т-Банк") && s1_text.contains("СберБанк") && s1_text.contains("Kupikod")
    );
    assert!(
        s1_text.contains("Kupicoin")
            && s1_text.contains("2 часа")
            && s1_text.contains("Пропуск Kupikod")
    );

    // Scenario 2: Direct Stripe Web (ClaudeMax without iPhone, clean US card)
    let s2 = evaluate_advisor_plan(
        &AdvisorQuery {
            target_service: AiPaymentService::ClaudeMax,
            has_iphone_apple_id: false,
            available_bin_prefix: Some("44661400".to_string()),
            payment_rails: vec![PaymentRail::RubSbp],
            willing_to_warmup_96h: true,
            google_payments_country: None,
            is_new_google_account: None,
            network_state: clean_net.clone(),
        },
        None,
    );
    assert_eq!(s2.primary.route_id, "direct_web_card");
    assert!(s2.primary.provider_ids.contains(&"wanttopay".to_string()));
    assert!(s2.primary.provider_ids.contains(&"platipomiru".to_string()));
    let s2_text = s2.primary.checklist.join("\n");
    assert!(
        s2_text.contains("96")
            && s2_text.contains("72")
            && s2_text.contains("Easy")
            && s2_text.contains("Для подписок")
    );

    // Scenario 3: Rescue Flow (SG Nium 493724xx under DE IP)
    let s3 = evaluate_advisor_plan(
        &AdvisorQuery {
            target_service: AiPaymentService::ClaudePro,
            has_iphone_apple_id: false,
            available_bin_prefix: Some("49372412".to_string()),
            payment_rails: vec![PaymentRail::CryptoUsdt],
            willing_to_warmup_96h: true,
            google_payments_country: None,
            is_new_google_account: None,
            network_state: AdvisorNetworkContext {
                exit_country: Some("DE".to_string()),
                ..clean_net.clone()
            },
        },
        None,
    );
    assert_eq!(s3.primary.route_id, "apple_iap_us_gift");
    assert!(
        s3.blocked_red_flags.iter().any(
            |w| w.route_id == "blocked_web_card_rescue" && w.explanation.contains("Google Pay")
        )
    );

    // Scenario 4: Gemini Ecosystem (Google Payments Profile Lock & OR-CCSEH-21)
    let s4 = evaluate_advisor_plan(
        &AdvisorQuery {
            target_service: AiPaymentService::Gemini,
            has_iphone_apple_id: false,
            available_bin_prefix: Some("44661400".to_string()),
            payment_rails: vec![PaymentRail::RubSbp],
            willing_to_warmup_96h: true,
            google_payments_country: Some("RU".to_string()),
            is_new_google_account: Some(true),
            network_state: clean_net.clone(),
        },
        None,
    );
    assert_eq!(s4.primary.route_id, "gemini_google_ecosystem");
    assert_eq!(s4.primary.kyc_risk_tier, KycRiskTier::Critical);
    assert!(
        s4.blocked_red_flags
            .iter()
            .any(|w| w.route_id == "google_payments_country_lock"
                && w.reason.contains("OR-CCSEH-21"))
    );
    let s4_text = format!(
        "{}\n{}",
        s4.primary.checklist.join("\n"),
        s4.primary.warnings.join("\n")
    );
    assert!(s4_text.contains("24-часовом холде") && s4_text.contains("Google Cloud"));

    // Also test readiness engine for Gemini with GooglePayments mismatch.
    let readiness_gemini = evaluate_payment_readiness(&PaymentReadinessInput {
        exit_country: Some("US".to_string()),
        google_profile_country: Some("RU".to_string()),
        channel: PaymentChannel::GooglePlayIap,
        target_service: Some(AiPaymentService::Gemini),
        ..Default::default()
    });
    assert_eq!(readiness_gemini.tier, ReadinessTier::Red);

    // Scenario 5: ChatGPT (Apple IAP) & Cursor (Web only + machineId warning) + Blacklist
    let s5_gpt = evaluate_advisor_plan(
        &AdvisorQuery {
            target_service: AiPaymentService::Chatgpt,
            has_iphone_apple_id: true,
            available_bin_prefix: None,
            payment_rails: vec![PaymentRail::RubSbp],
            willing_to_warmup_96h: true,
            google_payments_country: None,
            is_new_google_account: None,
            network_state: clean_net.clone(),
        },
        None,
    );
    assert_eq!(s5_gpt.primary.route_id, "apple_iap_us_gift");

    let s5_cursor = evaluate_advisor_plan(
        &AdvisorQuery {
            target_service: AiPaymentService::Cursor,
            has_iphone_apple_id: true,
            available_bin_prefix: Some("44661400".to_string()),
            payment_rails: vec![PaymentRail::RubSbp],
            willing_to_warmup_96h: true,
            google_payments_country: None,
            is_new_google_account: None,
            network_state: clean_net,
        },
        None,
    );
    assert_eq!(s5_cursor.primary.route_id, "direct_web_card");
    assert!(
        s5_cursor
            .primary
            .checklist
            .iter()
            .any(|c| c.contains("machineId"))
    );
    let blacklist_text = s5_cursor
        .blocked_red_flags
        .iter()
        .map(|b| format!("{} {}", b.title, b.reason))
        .collect::<Vec<_>>()
        .join(" ");
    for banned in [
        "Antarctic Wallet",
        "Altyn Wallet",
        "Wayment",
        "e.pn",
        "RedotPay",
        "PST.net",
        "FlexCard",
        "Plati.market",
    ] {
        assert!(blacklist_text.contains(banned), "missing {banned}");
    }
}

#[test]
fn e2e_5_local_bin_radar_overlay_stats_and_auto_demote() {
    let dir = tempfile::tempdir().unwrap();
    let app_dir = dir.path();

    // 1. Brand-new BIN below n=5 stays InsufficientData, and reaches Sufficient at n=5.
    let report_json = |bin: &str, svc: &str, outcome: &str| {
        format!(
            r#"{{"bin_prefix":"{bin}","service":"{svc}","channel":"stripe_web_card","geo_match":"full_match","warmup_bucket":"gt_96h","outcome":"{outcome}","client_version":"3.2.0"}}"#
        )
    };
    for _ in 0..4 {
        submit_local_bin_radar_report(app_dir, true, &report_json("55551200", "cursor", "success"))
            .unwrap();
    }
    let n4 = get_bin_radar_stats_for(Some(app_dir), "55551200", AiPaymentService::Cursor);
    assert_eq!(n4.status, BinRadarStatus::InsufficientData);
    assert_eq!(n4.sample_size_14d, 4);

    submit_local_bin_radar_report(app_dir, true, &report_json("55551200", "cursor", "success"))
        .unwrap();
    let n5 = get_bin_radar_stats_for(Some(app_dir), "55551200", AiPaymentService::Cursor);
    assert_eq!(n5.status, BinRadarStatus::Sufficient);
    assert_eq!(n5.sample_size_14d, 5);

    // 2. Bundled 53787200 (Cursor, n=3 in 14d) + 2 local reports -> immediately reaches n=5 Sufficient.
    assert_eq!(
        get_bin_radar_stats_for(Some(app_dir), "53787200", AiPaymentService::Cursor).status,
        BinRadarStatus::InsufficientData
    );
    for _ in 0..2 {
        submit_local_bin_radar_report(
            app_dir,
            true,
            &report_json("53787211", "cursor", "instant_kyc"),
        )
        .unwrap();
    }
    let merged_537 = get_bin_radar_stats_for(Some(app_dir), "53787211", AiPaymentService::Cursor);
    assert_eq!(merged_537.status, BinRadarStatus::Sufficient);
    assert_eq!(merged_537.sample_size_14d, 5);
    assert!(merged_537.risk_pct_14d.unwrap() > 35.0);

    // 3. Exponential time-decay & 14d/30d window boundaries are preserved in overlay merge.
    let base_snap = load_bin_radar_snapshot(None);
    let mk_rec = |reported_day: u64, outcome: PaymentOutcome| LocalBinRadarReportRecord {
        reported_day,
        report: BinRadarReport {
            bin_prefix: "59990000".to_string(),
            service: AiPaymentService::ClaudePro,
            channel: RadarChannel::StripeWebCard,
            geo_match: GeoMatchClass::FullMatch,
            warmup_bucket: WarmupBucket::Gt96h,
            outcome,
            client_version: "3.2.0".to_string(),
        },
    };
    let records = vec![
        mk_rec(100, PaymentOutcome::InstantKyc),
        mk_rec(100, PaymentOutcome::InstantKyc),
        mk_rec(100, PaymentOutcome::InstantKyc),
        mk_rec(95, PaymentOutcome::Success),
        mk_rec(95, PaymentOutcome::Success),
        mk_rec(80, PaymentOutcome::Success), // 20 days old -> excluded from 14d, included in 30d
    ];
    let merged_decay = merge_local_bin_radar_reports_at(&base_snap, &records, 100);
    let decay_stats =
        lookup_bin_radar_stats(&merged_decay, "59990000", AiPaymentService::ClaudePro);
    assert_eq!(decay_stats.sample_size_14d, 5);
    assert_eq!(decay_stats.sample_size_30d, 6);
    // 3 * 1.0 / (3 * 1.0 + 2 * 0.5) = 75.0%
    assert!((decay_stats.risk_pct_14d.unwrap() - 75.0).abs() < 0.2);

    // 4. Local high-risk reports on WantToPay's BIN (48331200) immediately trigger Per-Service Auto-Demote.
    for _ in 0..35 {
        submit_local_bin_radar_report(
            app_dir,
            true,
            &report_json("48331200", "claude_pro", "instant_kyc"),
        )
        .unwrap();
    }
    let evaluated = get_evaluated_providers_manifest(Some(app_dir));
    let wanttopay = evaluated
        .providers
        .iter()
        .find(|p| p.entry.id == "wanttopay")
        .unwrap();
    let claude_status = wanttopay
        .per_service
        .iter()
        .find(|s| s.service == AiPaymentService::ClaudePro)
        .unwrap();
    assert_ne!(claude_status.status, ProviderStatus::Active);
    assert!(claude_status.rate_14d > 0.40);
}
