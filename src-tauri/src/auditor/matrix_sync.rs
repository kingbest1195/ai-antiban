//! Offline-first Ed25519 signed 3-tier hot-update loader for `provider_matrix.json`.
//!
//! Priority order:
//! 1. Verified `<app_data_dir>/rules/provider_matrix.json`
//! 2. Verified `<app_data_dir>/rules/provider_matrix.cache.json`
//! 3. Embedded `rules/provider_matrix.json` (`DEFAULT_PROVIDER_MATRIX_JSON`)

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::auditor::bin_radar_verify::{PAYSHIELD_ED25519_PUBLIC_KEY, verify_ed25519_signature};
use crate::auditor::rules::{
    DEFAULT_PROVIDER_MATRIX_JSON, ProviderMatrix, RuleSet, publish_runtime_provider_matrix,
};
use crate::core::sanitize::{ensure_private_dir, write_private_file};

pub const MATRIX_FILE_NAME: &str = "provider_matrix.json";
pub const MATRIX_CACHE_FILE_NAME: &str = "provider_matrix.cache.json";
pub const DEFAULT_MATRIX_UPDATE_URL: &str =
    "https://raw.githubusercontent.com/kingbest1195/ai-antiban/main/rules/provider_matrix.json";
const MATRIX_FETCH_TIMEOUT: Duration = Duration::from_secs(8);
const MATRIX_MAX_BODY_BYTES: usize = 512 * 1024;

static LOGGED_MATRIX_EVENTS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn record_once(key: &str, message: &str) {
    let mut guard = LOGGED_MATRIX_EVENTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let set = guard.get_or_insert_with(HashSet::new);
    if set.insert(key.to_string()) {
        crate::diagnostics::record("rules:matrix", message);
    }
}

pub fn rules_data_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("rules")
}

fn parse_semver(ver: &str) -> Option<(u64, u64, u64)> {
    let clean = ver.trim().trim_start_matches(['v', 'V']);
    let core = clean.split('-').next().unwrap_or(clean);
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    Some((major, minor, patch))
}

fn is_older_timestamp(candidate: &str, baseline: &str) -> bool {
    let c = candidate.trim();
    let b = baseline.trim();
    if c.is_empty() || b.is_empty() {
        return false;
    }
    if let (Ok(cd), Ok(bd)) = (
        chrono::DateTime::parse_from_rfc3339(c),
        chrono::DateTime::parse_from_rfc3339(b),
    ) {
        return cd < bd;
    }
    c < b
}

/// Rejects version, `schema_version`, or timestamp downgrades relative to `baseline`.
pub fn check_not_downgrade(
    candidate: &ProviderMatrix,
    baseline: &ProviderMatrix,
) -> Result<(), String> {
    if candidate.schema_version != 0
        && baseline.schema_version != 0
        && candidate.schema_version < baseline.schema_version
    {
        return Err(format!(
            "Отклонён откат schema_version матрицы ({} < {})",
            candidate.schema_version, baseline.schema_version
        ));
    }
    match (
        parse_semver(&candidate.version),
        parse_semver(&baseline.version),
    ) {
        (Some(cv), Some(bv)) => {
            if cv < bv {
                return Err(format!(
                    "Отклонён откат версии матрицы ({} < {})",
                    candidate.version, baseline.version
                ));
            }
            if cv == bv {
                if !candidate.generated_at_utc.trim().is_empty()
                    && !baseline.generated_at_utc.trim().is_empty()
                {
                    if is_older_timestamp(&candidate.generated_at_utc, &baseline.generated_at_utc) {
                        return Err(format!(
                            "Отклонён откат времени генерации матрицы ({} < {})",
                            candidate.generated_at_utc, baseline.generated_at_utc
                        ));
                    }
                } else if is_older_timestamp(&candidate.updated_at, &baseline.updated_at) {
                    return Err(format!(
                        "Отклонён откат даты матрицы ({} < {})",
                        candidate.updated_at, baseline.updated_at
                    ));
                }
            }
        }
        _ => {
            if is_older_timestamp(&candidate.updated_at, &baseline.updated_at) {
                return Err(format!(
                    "Отклонён откат даты матрицы ({} < {})",
                    candidate.updated_at, baseline.updated_at
                ));
            }
        }
    }
    Ok(())
}

fn validate_matrix_structure(matrix: &ProviderMatrix) -> Result<(), String> {
    for required in ["anthropic", "openai", "gemini"] {
        let Some(rules) = matrix.providers.get(required) else {
            return Err("Матрица провайдеров не содержит обязательных провайдеров.".to_string());
        };
        if rules.domains.is_empty() {
            return Err(format!(
                "Матрица провайдеров содержит пустой список доменов для '{required}'."
            ));
        }
    }
    if matrix.payment_kyc_domains.is_empty() {
        return Err("Матрица провайдеров не содержит payment_kyc_domains.".to_string());
    }
    if matrix.global_blocked_countries.is_empty() {
        return Err("Матрица провайдеров не содержит global_blocked_countries.".to_string());
    }
    Ok(())
}

/// Parses and verifies an Ed25519-signed `provider_matrix.json` payload against `public_key`.
pub fn verify_provider_matrix_json_with_key(
    raw: &str,
    public_key: &[u8],
) -> Result<ProviderMatrix, String> {
    let matrix: ProviderMatrix = serde_json::from_str(raw)
        .map_err(|e| format!("Некорректный JSON матрицы провайдеров: {e}"))?;
    if matrix.signature_ed25519_b64.trim().is_empty() {
        return Err("Отсутствует подпись Ed25519 матрицы провайдеров.".to_string());
    }
    let payload = matrix.canonical_payload_bytes()?;
    verify_ed25519_signature(public_key, &payload, &matrix.signature_ed25519_b64)?;
    validate_matrix_structure(&matrix)?;
    Ok(matrix)
}

pub fn verify_provider_matrix_json(raw: &str) -> Result<ProviderMatrix, String> {
    verify_provider_matrix_json_with_key(raw, &PAYSHIELD_ED25519_PUBLIC_KEY)
}

fn try_load_verified_matrix(
    path: &Path,
    bundled: &ProviderMatrix,
    public_key: &[u8],
) -> Option<ProviderMatrix> {
    let raw = fs::read_to_string(path).ok()?;
    match verify_provider_matrix_json_with_key(&raw, public_key)
        .and_then(|m| check_not_downgrade(&m, bundled).map(|()| m))
    {
        Ok(matrix) => Some(matrix),
        Err(err) => {
            record_once(
                &format!("load:{}", path.display()),
                &format!("rejected {}: {err}", path.display()),
            );
            None
        }
    }
}

/// Offline-first 3-tier loader:
/// verified `app_data_dir/rules/provider_matrix.json` -> verified `.cache.json` -> embedded fallback.
pub fn load_provider_matrix_with_key(
    app_data_dir: Option<&Path>,
    public_key: &[u8],
) -> ProviderMatrix {
    let bundled: ProviderMatrix = serde_json::from_str(DEFAULT_PROVIDER_MATRIX_JSON)
        .expect("embedded rules/provider_matrix.json must parse");
    if let Some(dir) = app_data_dir.map(rules_data_dir) {
        if let Some(primary) =
            try_load_verified_matrix(&dir.join(MATRIX_FILE_NAME), &bundled, public_key)
        {
            return primary;
        }
        if let Some(cached) =
            try_load_verified_matrix(&dir.join(MATRIX_CACHE_FILE_NAME), &bundled, public_key)
        {
            return cached;
        }
    }
    bundled
}

pub fn load_provider_matrix(app_data_dir: Option<&Path>) -> ProviderMatrix {
    load_provider_matrix_with_key(app_data_dir, &PAYSHIELD_ED25519_PUBLIC_KEY)
}

/// Loads the 3-tier `ProviderMatrix` synchronously at startup and publishes it to both
/// `RuleSet` and the fast runtime snapshot.
pub fn init_provider_matrix_sync(app_data_dir: Option<&Path>, rules: &RuleSet) -> ProviderMatrix {
    let matrix = load_provider_matrix(app_data_dir);
    publish_runtime_provider_matrix(Arc::new(matrix.clone()));
    if let Ok(mut w) = rules.provider_matrix.try_write() {
        *w = matrix.clone();
    }
    matrix
}

/// Verifies signature and anti-downgrade BEFORE writing; keeps existing cache/embedded intact on failure.
pub fn save_verified_provider_matrix_with_key(
    app_data_dir: &Path,
    raw_json: &str,
    current_active: Option<&ProviderMatrix>,
    public_key: &[u8],
) -> Result<ProviderMatrix, String> {
    let parsed = match verify_provider_matrix_json_with_key(raw_json, public_key) {
        Ok(m) => m,
        Err(err) => {
            record_once(&format!("verify:{err}"), &format!("rejected update: {err}"));
            return Err(err);
        }
    };
    let bundled = ProviderMatrix::load_bundled()
        .map_err(|e| format!("Failed to load bundled matrix: {e}"))?;
    if let Err(err) = check_not_downgrade(&parsed, &bundled) {
        record_once(&format!("downgrade:{err}"), &err);
        return Err(err);
    }
    if let Some(active) = current_active
        && let Err(err) = check_not_downgrade(&parsed, active)
    {
        record_once(&format!("downgrade:{err}"), &err);
        return Err(err);
    }
    let dir = rules_data_dir(app_data_dir);
    ensure_private_dir(&dir)?;
    write_private_file(&dir.join(MATRIX_FILE_NAME), raw_json.as_bytes())?;
    write_private_file(&dir.join(MATRIX_CACHE_FILE_NAME), raw_json.as_bytes())?;
    Ok(parsed)
}

pub fn save_verified_provider_matrix(
    app_data_dir: &Path,
    raw_json: &str,
    current_active: Option<&ProviderMatrix>,
) -> Result<ProviderMatrix, String> {
    save_verified_provider_matrix_with_key(
        app_data_dir,
        raw_json,
        current_active,
        &PAYSHIELD_ED25519_PUBLIC_KEY,
    )
}

/// Verifies, saves (if `app_data_dir` is given), and hot-applies a signed matrix JSON update
/// into `RuleSet` and the runtime snapshot.
pub async fn apply_signed_matrix_update_with_key(
    app_data_dir: Option<&Path>,
    rules: &RuleSet,
    raw_json: &str,
    public_key: &[u8],
) -> Result<ProviderMatrix, String> {
    let current = rules.provider_matrix.read().await.clone();
    let updated = if let Some(dir) = app_data_dir {
        save_verified_provider_matrix_with_key(dir, raw_json, Some(&current), public_key)?
    } else {
        let parsed = verify_provider_matrix_json_with_key(raw_json, public_key)?;
        check_not_downgrade(&parsed, &current)?;
        parsed
    };
    rules.set_provider_matrix(updated.clone()).await;
    Ok(updated)
}

/// Fetches a signed `provider_matrix.json` from `url` (no proxy), verifies Ed25519 + anti-downgrade,
/// writes to disk, and hot-updates `RuleSet` + the runtime snapshot.
pub async fn refresh_provider_matrix_from_url_with_key(
    app_data_dir: Option<&Path>,
    rules: &RuleSet,
    url: &str,
    public_key: &[u8],
) -> Result<ProviderMatrix, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(MATRIX_FETCH_TIMEOUT)
        .build()
        .map_err(|e| format!("matrix fetch client init failed: {e}"))?;
    let resp = client.get(url).send().await.map_err(|e| {
        let msg = format!("matrix refresh network error: {e}");
        record_once("fetch:network", &msg);
        msg
    })?;
    if !resp.status().is_success() {
        let msg = format!("matrix refresh HTTP {}", resp.status());
        record_once(&format!("fetch:status:{}", resp.status()), &msg);
        return Err(msg);
    }
    let bytes = resp.bytes().await.map_err(|e| {
        let msg = format!("matrix refresh read failed: {e}");
        record_once("fetch:read", &msg);
        msg
    })?;
    if bytes.len() > MATRIX_MAX_BODY_BYTES {
        let msg = format!("matrix payload too large ({} bytes)", bytes.len());
        record_once("fetch:size", &msg);
        return Err(msg);
    }
    let raw_json = String::from_utf8(bytes.to_vec()).map_err(|_| {
        let msg = "matrix payload is not valid UTF-8".to_string();
        record_once("fetch:utf8", &msg);
        msg
    })?;
    apply_signed_matrix_update_with_key(app_data_dir, rules, &raw_json, public_key).await
}

/// Non-blocking background refresh entry point called from `app/watchers.rs` (every 6h).
pub async fn refresh_provider_matrix_bg(app_data_dir: Option<&Path>, rules: &RuleSet) -> bool {
    let url = std::env::var("ZASTAVA_MATRIX_UPDATE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_MATRIX_UPDATE_URL.to_string());
    refresh_provider_matrix_from_url_with_key(
        app_data_dir,
        rules,
        &url,
        &PAYSHIELD_ED25519_PUBLIC_KEY,
    )
    .await
    .is_ok()
}

#[cfg(test)]
#[path = "matrix_sync_tests.rs"]
mod tests;
