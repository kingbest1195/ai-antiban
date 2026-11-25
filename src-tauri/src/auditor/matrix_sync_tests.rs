use super::*;
use crate::auditor::rules::{RUNTIME_MATRIX_TEST_LOCK, clear_runtime_provider_matrix_for_test};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn test_keypair() -> (Ed25519KeyPair, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key = pair.public_key().as_ref().to_vec();
    (pair, pub_key)
}

fn sign_matrix(mut matrix: ProviderMatrix, pair: &Ed25519KeyPair) -> (ProviderMatrix, String) {
    matrix.signature_ed25519_b64.clear();
    let payload = matrix.canonical_payload_bytes().unwrap();
    let sig = pair.sign(&payload);
    matrix.signature_ed25519_b64 = B64.encode(sig.as_ref());
    let json = serde_json::to_string_pretty(&matrix).unwrap();
    (matrix, json)
}

struct SnapshotRestoreGuard;
impl Drop for SnapshotRestoreGuard {
    fn drop(&mut self) {
        if let Ok(bundled) = ProviderMatrix::load_bundled() {
            publish_runtime_provider_matrix(Arc::new(bundled));
        } else {
            clear_runtime_provider_matrix_for_test();
        }
    }
}

#[test]
fn signed_matrix_verifies_loads_3tier_and_rejects_tampered_or_downgraded() {
    let (pair, pub_key) = test_keypair();
    let dir = tempfile::tempdir().unwrap();
    let app_dir = dir.path();

    // Tier 3 fallback when nothing exists on disk
    let initial = load_provider_matrix_with_key(Some(app_dir), &pub_key);
    assert_eq!(initial.version, "1.1.0");

    // Prepare valid signed update v1.2.0
    let mut updated = initial.clone();
    updated.schema_version = 1;
    updated.version = "1.2.0".to_string();
    updated.updated_at = "2026-11-25".to_string();
    updated.generated_at_utc = "2026-11-25T18:00:00Z".to_string();
    updated.ttl_seconds = 21_600;
    updated
        .providers
        .get_mut("anthropic")
        .unwrap()
        .domains
        .push("hot-claude-edge.example".to_string());
    let (signed_v120, signed_v120_json) = sign_matrix(updated.clone(), &pair);

    let saved = save_verified_provider_matrix_with_key(app_dir, &signed_v120_json, None, &pub_key)
        .expect("valid signed matrix should save");
    assert_eq!(saved.version, "1.2.0");
    assert_eq!(
        load_provider_matrix_with_key(Some(app_dir), &pub_key),
        signed_v120
    );

    // Tamper 1 domain without re-signing -> rejected & disk cache intact
    let tampered_json = signed_v120_json.replacen("hot-claude-edge.example", "evil.example", 1);
    assert!(verify_provider_matrix_json_with_key(&tampered_json, &pub_key).is_err());
    assert!(
        save_verified_provider_matrix_with_key(
            app_dir,
            &tampered_json,
            Some(&signed_v120),
            &pub_key
        )
        .is_err()
    );

    // Unsigned payload -> rejected
    let mut unsigned = updated.clone();
    unsigned.version = "1.3.0".to_string();
    unsigned.signature_ed25519_b64.clear();
    let unsigned_json = serde_json::to_string(&unsigned).unwrap();
    assert!(
        save_verified_provider_matrix_with_key(
            app_dir,
            &unsigned_json,
            Some(&signed_v120),
            &pub_key
        )
        .is_err()
    );

    // Signed version downgrade (1.1.5 < 1.2.0) -> rejected before writing
    let mut downgrade = updated.clone();
    downgrade.version = "1.1.5".to_string();
    let (_d_mat, downgrade_json) = sign_matrix(downgrade, &pair);
    assert!(
        save_verified_provider_matrix_with_key(
            app_dir,
            &downgrade_json,
            Some(&signed_v120),
            &pub_key
        )
        .is_err()
    );

    // Signed timestamp downgrade on same version (1.2.0, 17:00 < 18:00) -> rejected
    let mut older_ts = updated.clone();
    older_ts.generated_at_utc = "2026-11-25T17:00:00Z".to_string();
    let (_o_mat, older_ts_json) = sign_matrix(older_ts, &pair);
    assert!(
        save_verified_provider_matrix_with_key(
            app_dir,
            &older_ts_json,
            Some(&signed_v120),
            &pub_key
        )
        .is_err()
    );

    // Tier 1 primary corrupted on disk -> falls back to Tier 2 `.cache.json`
    let rdir = rules_data_dir(app_dir);
    fs::write(rdir.join(MATRIX_FILE_NAME), &tampered_json).unwrap();
    assert_eq!(
        load_provider_matrix_with_key(Some(app_dir), &pub_key),
        signed_v120
    );

    // Tier 2 cache also corrupted -> falls back to Tier 3 embedded bundled matrix
    fs::write(rdir.join(MATRIX_CACHE_FILE_NAME), "{corrupt").unwrap();
    let fallback = load_provider_matrix_with_key(Some(app_dir), &pub_key);
    assert_eq!(fallback.version, "1.1.0");
}

#[tokio::test]
async fn apply_signed_matrix_update_hot_refreshes_ruleset_and_runtime_snapshot() {
    let _lock = RUNTIME_MATRIX_TEST_LOCK.lock().await;
    let _restore = SnapshotRestoreGuard;

    let (pair, pub_key) = test_keypair();
    let dir = tempfile::tempdir().unwrap();
    let rules = RuleSet::load_bundled().unwrap();

    let mut next = ProviderMatrix::load_bundled().unwrap();
    next.schema_version = 1;
    next.version = "1.2.0".to_string();
    next.generated_at_utc = "2026-11-25T19:00:00Z".to_string();
    next.providers
        .get_mut("openai")
        .unwrap()
        .domains
        .push("hot-openai-new.example".to_string());
    next.payment_kyc_domains
        .push("hot-checkout-new.example".to_string());
    let (_signed, signed_json) = sign_matrix(next, &pair);

    let applied =
        apply_signed_matrix_update_with_key(Some(dir.path()), &rules, &signed_json, &pub_key)
            .await
            .expect("signed update should apply");
    assert_eq!(applied.version, "1.2.0");

    assert_eq!(
        crate::auditor::geo_matrix::ProviderId::from_host("hot-openai-new.example"),
        Some(crate::auditor::geo_matrix::ProviderId::Openai)
    );
    assert!(crate::auditor::geo_matrix::is_payment_or_kyc_host(
        "sub.hot-checkout-new.example"
    ));

    // Tampered second update fails and preserves the live v1.2.0 snapshot
    let bad_json = signed_json.replacen("hot-openai-new.example", "tampered.example", 1);
    assert!(
        apply_signed_matrix_update_with_key(Some(dir.path()), &rules, &bad_json, &pub_key)
            .await
            .is_err()
    );
    assert_eq!(
        crate::auditor::geo_matrix::ProviderId::from_host("hot-openai-new.example"),
        Some(crate::auditor::geo_matrix::ProviderId::Openai)
    );
    assert_eq!(rules.provider_matrix.read().await.version, "1.2.0");
}

#[test]
fn signed_matrix_with_empty_required_domains_or_payment_kyc_is_rejected() {
    let (pair, pub_key) = test_keypair();
    let dir = tempfile::tempdir().unwrap();
    let app_dir = dir.path();
    let bundled = ProviderMatrix::load_bundled().unwrap();

    // Missing/empty domains for any required provider must be rejected even with a valid signature.
    for required in ["anthropic", "openai", "gemini"] {
        let mut empty_provider_domains = bundled.clone();
        empty_provider_domains.version = "1.2.0".to_string();
        empty_provider_domains
            .providers
            .get_mut(required)
            .unwrap()
            .domains
            .clear();
        let (_m, json) = sign_matrix(empty_provider_domains, &pair);
        let err = verify_provider_matrix_json_with_key(&json, &pub_key)
            .expect_err("empty provider domains must be rejected");
        assert!(err.contains(required), "{err}");
        assert!(
            save_verified_provider_matrix_with_key(app_dir, &json, None, &pub_key).is_err(),
            "must not save matrix with empty {required}.domains"
        );
    }

    // Empty payment_kyc_domains must be rejected even with a valid signature.
    let mut empty_payment = bundled.clone();
    empty_payment.version = "1.2.0".to_string();
    empty_payment.payment_kyc_domains.clear();
    let (_m, empty_payment_json) = sign_matrix(empty_payment, &pair);
    assert!(
        verify_provider_matrix_json_with_key(&empty_payment_json, &pub_key).is_err(),
        "empty payment_kyc_domains must be rejected"
    );

    // If disk has a signed-but-structurally-invalid cache, loader falls back to bundled.
    let rdir = rules_data_dir(app_dir);
    fs::create_dir_all(&rdir).unwrap();
    fs::write(rdir.join(MATRIX_FILE_NAME), &empty_payment_json).unwrap();
    let loaded = load_provider_matrix_with_key(Some(app_dir), &pub_key);
    assert_eq!(loaded.version, bundled.version);
    assert!(!loaded.payment_kyc_domains.is_empty());
}
