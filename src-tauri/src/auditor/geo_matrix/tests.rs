use super::*;

#[test]
fn test_provider_geo_matrix_russia_blocked() {
    let matrix = ProviderMatrix::load_bundled().unwrap();
    for &provider in &[
        ProviderId::Anthropic,
        ProviderId::Openai,
        ProviderId::Gemini,
    ] {
        let res = evaluate_provider_geo(&matrix, provider, "RU");
        assert_eq!(res.status, CheckStatus::Critical);
        assert_eq!(res.code, "GLOBAL_SANCTIONED_COUNTRY");
    }
}

#[test]
fn test_provider_geo_non_country_codes_are_never_allowed() {
    let matrix = ProviderMatrix::load_bundled().unwrap();
    for &provider in &[
        ProviderId::Anthropic,
        ProviderId::Openai,
        ProviderId::Gemini,
    ] {
        for raw in ["", "  ", "XX", "xx", "ZZ", "N", "NLD", "1A"] {
            let res = evaluate_provider_geo(&matrix, provider, raw);
            assert_eq!(res.status, CheckStatus::Unknown, "{raw:?}");
            assert_eq!(res.reason, Some(UnknownReason::NoData), "{raw:?}");
            assert_ne!(res.code, "GEO_ALLOWED");
        }
        // Cloudflare's marker of a Tor exit.
        for raw in ["T1", "t1"] {
            let res = evaluate_provider_geo(&matrix, provider, raw);
            assert_eq!(res.status, CheckStatus::Critical);
            assert_eq!(res.code, "TOR_EXIT_NODE");
        }
    }
}

#[test]
fn test_provider_geo_ok_text_states_the_verified_fact() {
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let res = evaluate_provider_geo(&matrix, ProviderId::Anthropic, "NL");
    assert_eq!(res.code, "GEO_ALLOWED");
    assert!(res.message.contains("не входит в списки ограничений"));
    assert!(!res.message.contains("полностью") && !res.message.contains("безопасна"));
}

#[test]
fn test_provider_geo_matrix_hongkong_blocked() {
    let matrix = ProviderMatrix::load_bundled().unwrap();
    for &provider in &[
        ProviderId::Anthropic,
        ProviderId::Openai,
        ProviderId::Gemini,
    ] {
        let res = evaluate_provider_geo(&matrix, provider, "HK");
        assert_eq!(res.status, CheckStatus::Critical);
        assert_eq!(res.code, "GLOBAL_SANCTIONED_COUNTRY");
        assert!(res.message.contains("HK") || res.message.contains("Гонконг"));
    }
}

#[test]
fn test_provider_geo_matrix_turkey_gemini_allowed() {
    let matrix = ProviderMatrix::load_bundled().unwrap();

    // Gemini in Turkey -> Ok (Turkey is officially supported by Gemini web & API)
    let res_gemini = evaluate_provider_geo(&matrix, ProviderId::Gemini, "TR");
    assert_eq!(res_gemini.status, CheckStatus::Ok);
    assert_eq!(res_gemini.code, "GEO_ALLOWED");

    // Anthropic in Turkey -> Warning
    let res_anthropic = evaluate_provider_geo(&matrix, ProviderId::Anthropic, "TR");
    assert_eq!(res_anthropic.status, CheckStatus::Warning);

    // OpenAI in Turkey -> Ok
    let res_openai = evaluate_provider_geo(&matrix, ProviderId::Openai, "TR");
    assert_eq!(res_openai.status, CheckStatus::Ok);
}

#[test]
fn test_provider_geo_matrix_venezuela_and_anthropic_sanctioned_countries() {
    let matrix = ProviderMatrix::load_bundled().unwrap();

    // Venezuela (VE) blocked for Anthropic & OpenAI, allowed for Gemini
    let ve_anthropic = evaluate_provider_geo(&matrix, ProviderId::Anthropic, "VE");
    assert_eq!(ve_anthropic.status, CheckStatus::Critical);
    assert_eq!(ve_anthropic.code, "ANTHROPIC_GEO_BLOCKED");

    let ve_openai = evaluate_provider_geo(&matrix, ProviderId::Openai, "VE");
    assert_eq!(ve_openai.status, CheckStatus::Critical);
    assert_eq!(ve_openai.code, "OPENAI_GEO_BLOCKED");

    let ve_gemini = evaluate_provider_geo(&matrix, ProviderId::Gemini, "VE");
    assert_eq!(ve_gemini.status, CheckStatus::Ok);

    // AF, MM, SD, YE blocked for Anthropic
    for &country in &["AF", "MM", "SD", "YE"] {
        let res = evaluate_provider_geo(&matrix, ProviderId::Anthropic, country);
        assert_eq!(
            res.status,
            CheckStatus::Critical,
            "expected {country} blocked for Anthropic"
        );
        assert_eq!(res.code, "ANTHROPIC_GEO_BLOCKED");
    }
}

#[test]
fn test_provider_geo_matrix_global_sanctioned_and_regional_notes() {
    let matrix = ProviderMatrix::load_bundled().unwrap();

    for &country in &["RU", "BY", "CN", "IR", "HK", "MO"] {
        for &provider in &[
            ProviderId::Anthropic,
            ProviderId::Openai,
            ProviderId::Gemini,
        ] {
            let res = evaluate_provider_geo(&matrix, provider, country);
            assert_eq!(
                res.status,
                CheckStatus::Critical,
                "{country} for {provider:?}"
            );
            assert_eq!(res.code, "GLOBAL_SANCTIONED_COUNTRY");
        }
    }

    // HK / MO / CN Gemini messages note Gemini web vs AI Studio API
    for &country in &["HK", "MO", "CN"] {
        let res = evaluate_provider_geo(&matrix, ProviderId::Gemini, country);
        assert!(
            res.message.contains("AI Studio API"),
            "{country}: {}",
            res.message
        );
        assert!(res.message.contains("Gemini"), "{country}: {}", res.message);
    }

    // UA has partial restriction warnings for all providers
    for &provider in &[
        ProviderId::Anthropic,
        ProviderId::Openai,
        ProviderId::Gemini,
    ] {
        let res = evaluate_provider_geo(&matrix, provider, "UA");
        assert_eq!(res.status, CheckStatus::Warning, "UA for {provider:?}");
        assert!(
            res.message.contains("оккупированных"),
            "UA: {}",
            res.message
        );
    }
}

#[test]
fn test_provider_geo_matrix_transit_hubs_and_no_dead_warnings() {
    let matrix = ProviderMatrix::load_bundled().unwrap();

    // Single source of truth in provider_matrix.json: transit hubs warn for Anthropic & Gemini, Ok for OpenAI
    for &country in &["KZ", "AM", "GE", "UZ", "KG", "RS", "AE"] {
        let a = evaluate_provider_geo(&matrix, ProviderId::Anthropic, country);
        assert_eq!(a.status, CheckStatus::Warning, "Anthropic {country}");
        let g = evaluate_provider_geo(&matrix, ProviderId::Gemini, country);
        assert_eq!(g.status, CheckStatus::Warning, "Gemini {country}");
        let o = evaluate_provider_geo(&matrix, ProviderId::Openai, country);
        assert_eq!(o.status, CheckStatus::Ok, "OpenAI {country}");
    }

    // Dead warnings already covered by global_blocked_countries must not remain
    let openai = matrix.get_provider_rules("openai").unwrap();
    assert!(!openai.warning_countries.contains_key("IR"));
    assert!(!openai.warning_countries.contains_key("HK"));
    let gemini = matrix.get_provider_rules("gemini").unwrap();
    assert!(!gemini.warning_countries.contains_key("BY"));
    assert!(!gemini.blocked_countries.contains(&"TR".to_string()));
}

#[test]
fn test_provider_geo_matrix_netherlands_allowed() {
    let matrix = ProviderMatrix::load_bundled().unwrap();
    for &country in &["NL", "DE", "US", "FI"] {
        for &provider in &[
            ProviderId::Anthropic,
            ProviderId::Openai,
            ProviderId::Gemini,
        ] {
            let res = evaluate_provider_geo(&matrix, provider, country);
            assert_eq!(res.status, CheckStatus::Ok);
            assert_eq!(res.code, "GEO_ALLOWED");
        }
    }
}

#[test]
fn test_provider_from_host_matching() {
    assert_eq!(
        ProviderId::from_host("claude.ai:443"),
        Some(ProviderId::Anthropic)
    );
    assert_eq!(
        ProviderId::from_host("api.anthropic.com"),
        Some(ProviderId::Anthropic)
    );
    assert_eq!(
        ProviderId::from_host("chatgpt.com"),
        Some(ProviderId::Openai)
    );
    assert_eq!(
        ProviderId::from_host("gemini.google.com:443"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("aistudio.google.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(ProviderId::from_host("example.com"), None);
}

#[test]
fn test_antigravity_and_cloudcode_endpoints_match_gemini() {
    assert_eq!(
        ProviderId::from_host("daily-cloudcode-pa.googleapis.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("cloudcode-pa.googleapis.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("daily-cloudcode-pa.sandbox.googleapis.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("autopush-cloudcode-pa.sandbox.googleapis.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("preprod-daily-cloudcode-pa.sandbox.googleapis.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("aicode.googleapis.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("autopush-aicode.sandbox.googleapis.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("preprod-aicode.sandbox.googleapis.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("alkalimakersuiteapplets.pa.googleapis.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("antigravity.google"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("antigravity.google.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("share.gemini.google"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("notebooklm.google"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("notebooklm.google.com"),
        Some(ProviderId::Gemini)
    );
    assert_eq!(
        ProviderId::from_host("idx.google.com"),
        Some(ProviderId::Gemini)
    );
}

#[test]
fn test_gemini_full_domain_coverage_and_subdomains() {
    for host in [
        "gemini.google.com",
        "gemini.google",
        "clients6.google.com",
        "waa-pa.clients6.google.com",
        "signaler-pa.clients6.google.com",
        "peoplestack-pa.clients6.google.com",
        "proactivebackend-pa.clients6.google.com",
        "alkalimakersuite-pa.clients6.google.com",
        "generativelanguage.googleapis.com",
        "aisandbox-pa.googleapis.com",
        "aistudio.google.com",
        "makersuite.google.com",
        "ai.google.dev",
        "bard.google.com",
        "deepmind.google",
        "jules.google.com",
        "accounts.google.com",
        "oauth2.googleapis.com",
        "iamcredentials.googleapis.com",
        "jnn-pa.googleapis.com",
        "signaler-pa.googleapis.com",
        "apis.google.com",
    ] {
        assert_eq!(
            ProviderId::from_host(host),
            Some(ProviderId::Gemini),
            "expected {host} to match Gemini"
        );
        assert_eq!(
            ProviderId::from_host_with_custom(host, &["custom-ai.corp".to_string()]),
            Some(ProviderId::Gemini),
            "expected {host} with custom domains to match Gemini"
        );
    }
    for noisy in [
        "www.google.com",
        "play.google.com",
        "ogs.google.com",
        "footprints-pa.googleapis.com",
        "people-pa.googleapis.com",
        "myactivity.google.com",
        "myaccount.google.com",
    ] {
        assert_eq!(
            ProviderId::from_host(noisy),
            None,
            "noisy non-AI domain {noisy} must bypass AI proxy"
        );
    }
}

#[test]
fn test_extended_domains_and_custom_domains_matching() {
    // Anthropic / Cursor / Perplexity
    assert_eq!(
        ProviderId::from_host("cursor.sh"),
        Some(ProviderId::Anthropic)
    );
    assert_eq!(
        ProviderId::from_host("api2.cursor.sh:443"),
        Some(ProviderId::Anthropic)
    );
    assert_eq!(
        ProviderId::from_host("perplexity.ai"),
        Some(ProviderId::Anthropic)
    );
    assert_eq!(
        ProviderId::from_host("openrouter.ai"),
        Some(ProviderId::Anthropic)
    );

    // OpenAI / Copilot / DeepSeek / Mistral
    assert_eq!(
        ProviderId::from_host("copilot.microsoft.com:443"),
        Some(ProviderId::Openai)
    );
    assert_eq!(
        ProviderId::from_host("githubcopilot.com"),
        Some(ProviderId::Openai)
    );
    assert_eq!(
        ProviderId::from_host("api.githubcopilot.com"),
        Some(ProviderId::Openai)
    );
    assert_eq!(
        ProviderId::from_host("deepseek.com"),
        Some(ProviderId::Openai)
    );
    assert_eq!(
        ProviderId::from_host("api.deepseek.com"),
        Some(ProviderId::Openai)
    );
    assert_eq!(
        ProviderId::from_host("mistral.ai"),
        Some(ProviderId::Openai)
    );

    // Custom domain matching
    let custom = vec![
        "internal-ai.corp".to_string(),
        "custom-agent.dev".to_string(),
    ];
    assert_eq!(
        ProviderId::from_host_with_custom("internal-ai.corp:8443", &custom),
        Some(ProviderId::Anthropic)
    );
    assert_eq!(
        ProviderId::from_host_with_custom("api.custom-agent.dev", &custom),
        Some(ProviderId::Anthropic)
    );
    assert_eq!(
        ProviderId::from_host_with_custom("unknown-service.com", &custom),
        None
    );
}

#[test]
fn test_check_result_json_without_new_fields_reads() {
    let r: CheckResult =
        serde_json::from_str(r#"{"status":"ok","code":"X","message":"m","guide_ref":null}"#)
            .unwrap();
    assert_eq!(r.status, CheckStatus::Ok);
    assert!(r.reason.is_none() && r.checked_at.is_none() && r.measured_via.is_none());
    // Without optional guide_ref at all, too.
    let r: CheckResult =
        serde_json::from_str(r#"{"status":"warning","code":"X","message":"m"}"#).unwrap();
    assert_eq!(r.status, CheckStatus::Warning);
}

#[test]
fn test_status_unknown_and_random_string_read_as_unknown() {
    let r: CheckResult = serde_json::from_str(
        r#"{"status":"unknown","code":"X","message":"m","guide_ref":null,"reason":"timeout"}"#,
    )
    .unwrap();
    assert_eq!(r.status, CheckStatus::Unknown);
    assert_eq!(r.reason, Some(UnknownReason::Timeout));

    let r: CheckResult = serde_json::from_str(
        r#"{"status":"definitely-not-a-status","code":"X","message":"m","guide_ref":null}"#,
    )
    .unwrap();
    assert_eq!(r.status, CheckStatus::Unknown);
    assert!(!r.status.is_ok());
}

#[test]
fn test_unknown_constructor_and_serialization() {
    let r = CheckResult::unknown("C", "m", UnknownReason::NotApplicable);
    assert!(r.is_unknown() && r.is_not_applicable());
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["status"], "unknown");
    assert_eq!(v["reason"], "not_applicable");
    // Optional fields that are not set are omitted for ordinary results.
    let ok = serde_json::to_value(CheckResult::ok("C", "m")).unwrap();
    assert!(ok.get("reason").is_none() && ok.get("measured_via").is_none());
    let t = CheckResult::unknown("C", "m", UnknownReason::Timeout);
    assert!(t.is_unknown() && !t.is_not_applicable());
}

#[test]
fn test_payment_and_kyc_host_matching() {
    for host in [
        "stripe.com",
        "checkout.stripe.com:443",
        "m.stripe.network.",
        "sub.stripe.com",
        "withpersona.com",
        "inquiry.withpersona.com",
        "challenges.cloudflare.com",
        "js.hcaptcha.com",
        "api.arkoselabs.com",
        "pay.google.com",
        "payments.google.com",
    ] {
        assert!(
            is_payment_or_kyc_host(host),
            "expected payment/kyc match for {host}"
        );
    }
    for non_payment in [
        "example.com",
        "notstripe.com",
        "google.com",
        "cloudflare.com",
    ] {
        assert!(
            !is_payment_or_kyc_host(non_payment),
            "did not expect payment/kyc match for {non_payment}"
        );
    }
}

#[test]
fn test_v3_2_1_expanded_ai_and_payment_kyc_domains() {
    for host in [
        "clau.de",
        "cursorapi.com",
        "statsigapi.net",
        "featuregates.org",
        "ingest.sentry.io",
        "ingest.us.sentry.io",
        "ingest.de.sentry.io",
        "api.segment.io",
        "api-iam.intercom.io",
        "workos.com",
        "authkit.com",
    ] {
        assert_eq!(
            ProviderId::from_host(host),
            Some(ProviderId::Anthropic),
            "{host}"
        );
    }
    for host in [
        "sora.com",
        "featureassets.org",
        "prodregistryv2.org",
        "livekit.cloud",
        "exafunction.com",
    ] {
        assert_eq!(
            ProviderId::from_host(host),
            Some(ProviderId::Openai),
            "{host}"
        );
    }
    for host in [
        "jnn-pa.googleapis.com",
        "signaler-pa.googleapis.com",
        "apis.google.com",
        "autopush-cloudcode-pa.googleapis.com",
        "geller-pa.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "serviceusage.googleapis.com",
        "daily-antigravity.sandbox.googleapis.com",
        "antigravity-unleash.goog",
        "stitch.withgoogle.com",
        "firebase.studio",
    ] {
        assert_eq!(
            ProviderId::from_host(host),
            Some(ProviderId::Gemini),
            "{host}"
        );
    }
    for host in [
        "paddle.com",
        "vendors.paddle.com",
        "stripe.network",
        "stripecdn.com",
        "funcaptcha.com",
        "recaptcha.net",
        "lemonsqueezy.com",
        "veriff.com",
        "veriff.me",
        "sumsub.com",
        "onfido.com",
    ] {
        assert!(
            is_payment_or_kyc_host(host),
            "expected payment/kyc match for {host}"
        );
    }
}

#[test]
fn runtime_provider_matrix_snapshot_updates_from_host_and_payment_lookup() {
    use crate::auditor::rules::{
        RUNTIME_MATRIX_TEST_LOCK, clear_runtime_provider_matrix_for_test,
        publish_runtime_provider_matrix,
    };
    use std::sync::Arc;

    struct RestoreGuard;
    impl Drop for RestoreGuard {
        fn drop(&mut self) {
            if let Ok(bundled) = ProviderMatrix::load_bundled() {
                publish_runtime_provider_matrix(Arc::new(bundled));
            } else {
                clear_runtime_provider_matrix_for_test();
            }
        }
    }

    let _lock = RUNTIME_MATRIX_TEST_LOCK.blocking_lock();
    let _restore = RestoreGuard;

    // Uninitialized snapshot safely falls back to compile-time slices.
    clear_runtime_provider_matrix_for_test();
    assert_eq!(
        ProviderId::from_host("claude.ai"),
        Some(ProviderId::Anthropic)
    );
    assert!(is_payment_or_kyc_host("checkout.stripe.com"));
    assert_eq!(ProviderId::from_host("dynamic-claude-edge.example"), None);
    assert!(!is_payment_or_kyc_host("dynamic-pay-edge.example"));

    // Publishing a live ProviderMatrix snapshot immediately updates both lookups.
    let mut matrix = ProviderMatrix::load_bundled().unwrap();
    matrix
        .providers
        .get_mut("anthropic")
        .unwrap()
        .domains
        .push("dynamic-claude-edge.example".to_string());
    matrix
        .payment_kyc_domains
        .push("dynamic-pay-edge.example".to_string());
    publish_runtime_provider_matrix(Arc::new(matrix));

    assert_eq!(
        ProviderId::from_host("sub.dynamic-claude-edge.example"),
        Some(ProviderId::Anthropic)
    );
    assert!(is_payment_or_kyc_host("checkout.dynamic-pay-edge.example"));
    assert_eq!(
        ProviderId::from_host("canary-test.anthropic.zastava.local"),
        Some(ProviderId::Anthropic)
    );
}
