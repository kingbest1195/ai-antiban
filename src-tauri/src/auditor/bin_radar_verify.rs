//! Layer 2 Ed25519 signature verification (via `ring`) and Offline-First bundle storage
//! for `bin_radar_snapshot.json`, `providers_manifest.json`, and opt-in Zero-PII reports.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::auditor::network::current_timestamp;
use crate::core::bin_radar::{BinRadarReport, BinRadarSnapshot, parse_bin_radar_report_json};
use crate::core::providers_manifest::ProvidersManifest;
use crate::core::sanitize::{ensure_private_dir, write_private_file};

pub const DEFAULT_BIN_RADAR_SNAPSHOT_JSON: &str =
    include_str!("../../../rules/bin_radar_snapshot.json");
pub const DEFAULT_PROVIDERS_MANIFEST_JSON: &str =
    include_str!("../../../rules/providers_manifest.json");

pub const SNAPSHOT_FILE_NAME: &str = "bin_radar_snapshot.json";
pub const SNAPSHOT_CACHE_FILE_NAME: &str = "bin_radar_snapshot.cache.json";
pub const MANIFEST_FILE_NAME: &str = "providers_manifest.json";
pub const MANIFEST_CACHE_FILE_NAME: &str = "providers_manifest.cache.json";
pub const LOCAL_REPORTS_FILE_NAME: &str = "local_reports.json";
const MAX_LOCAL_REPORTS: usize = 500;

/// Embedded Ed25519 public key (32 bytes) verifying PayShield Phase 2 signed bundles.
pub const PAYSHIELD_ED25519_PUBLIC_KEY: [u8; 32] = [
    100, 15, 3, 166, 65, 2, 93, 40, 152, 104, 91, 74, 25, 69, 43, 214, 47, 7, 89, 115, 135, 6, 183,
    98, 101, 152, 243, 255, 61, 21, 172, 27,
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalBinRadarReportRecord {
    pub reported_day: u64,
    pub report: BinRadarReport,
}

pub fn payshield_data_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("payshield")
}

pub fn verify_ed25519_signature(
    public_key: &[u8],
    payload: &[u8],
    signature_b64: &str,
) -> Result<(), String> {
    let sig_bytes = B64
        .decode(signature_b64.trim())
        .map_err(|_| "Некорректная подпись Ed25519 (base64).".to_string())?;
    let verifier = UnparsedPublicKey::new(&ED25519, public_key);
    verifier
        .verify(payload, &sig_bytes)
        .map_err(|_| "Подпись Ed25519 не прошла проверку целостности.".to_string())
}

pub fn verify_bin_radar_snapshot_json_with_key(
    raw: &str,
    public_key: &[u8],
) -> Result<BinRadarSnapshot, String> {
    let snapshot: BinRadarSnapshot = serde_json::from_str(raw)
        .map_err(|e| format!("Некорректный JSON снимка BIN Radar: {e}"))?;
    let payload = snapshot.canonical_payload_bytes()?;
    verify_ed25519_signature(public_key, &payload, &snapshot.signature_ed25519_b64)?;
    Ok(snapshot)
}

pub fn verify_bin_radar_snapshot_json(raw: &str) -> Result<BinRadarSnapshot, String> {
    verify_bin_radar_snapshot_json_with_key(raw, &PAYSHIELD_ED25519_PUBLIC_KEY)
}

pub fn verify_providers_manifest_json_with_key(
    raw: &str,
    public_key: &[u8],
) -> Result<ProvidersManifest, String> {
    let manifest: ProvidersManifest = serde_json::from_str(raw)
        .map_err(|e| format!("Некорректный JSON манифеста провайдеров: {e}"))?;
    let payload = manifest.canonical_payload_bytes()?;
    verify_ed25519_signature(public_key, &payload, &manifest.signature_ed25519_b64)?;
    Ok(manifest)
}

pub fn verify_providers_manifest_json(raw: &str) -> Result<ProvidersManifest, String> {
    verify_providers_manifest_json_with_key(raw, &PAYSHIELD_ED25519_PUBLIC_KEY)
}

fn try_load_verified_snapshot(path: &Path, public_key: &[u8]) -> Option<BinRadarSnapshot> {
    let raw = fs::read_to_string(path).ok()?;
    verify_bin_radar_snapshot_json_with_key(&raw, public_key).ok()
}

fn try_load_verified_manifest(path: &Path, public_key: &[u8]) -> Option<ProvidersManifest> {
    let raw = fs::read_to_string(path).ok()?;
    verify_providers_manifest_json_with_key(&raw, public_key).ok()
}

/// Offline-First loader for `bin_radar_snapshot.json`:
/// primary in `app_data_dir/payshield` -> verified `.cache.json` -> compile-time embedded bundle.
pub fn load_bin_radar_snapshot_with_key(
    app_data_dir: Option<&Path>,
    public_key: &[u8],
) -> BinRadarSnapshot {
    if let Some(dir) = app_data_dir.map(payshield_data_dir) {
        if let Some(snap) = try_load_verified_snapshot(&dir.join(SNAPSHOT_FILE_NAME), public_key) {
            return snap;
        }
        if let Some(cached) =
            try_load_verified_snapshot(&dir.join(SNAPSHOT_CACHE_FILE_NAME), public_key)
        {
            return cached;
        }
    }
    serde_json::from_str(DEFAULT_BIN_RADAR_SNAPSHOT_JSON)
        .expect("embedded rules/bin_radar_snapshot.json must parse")
}

pub fn load_bin_radar_snapshot(app_data_dir: Option<&Path>) -> BinRadarSnapshot {
    load_bin_radar_snapshot_with_key(app_data_dir, &PAYSHIELD_ED25519_PUBLIC_KEY)
}

/// Offline-First loader for `providers_manifest.json`:
/// primary in `app_data_dir/payshield` -> verified `.cache.json` -> compile-time embedded bundle.
pub fn load_providers_manifest_with_key(
    app_data_dir: Option<&Path>,
    public_key: &[u8],
) -> ProvidersManifest {
    if let Some(dir) = app_data_dir.map(payshield_data_dir) {
        if let Some(m) = try_load_verified_manifest(&dir.join(MANIFEST_FILE_NAME), public_key) {
            return m;
        }
        if let Some(cached) =
            try_load_verified_manifest(&dir.join(MANIFEST_CACHE_FILE_NAME), public_key)
        {
            return cached;
        }
    }
    serde_json::from_str(DEFAULT_PROVIDERS_MANIFEST_JSON)
        .expect("embedded rules/providers_manifest.json must parse")
}

pub fn load_providers_manifest(app_data_dir: Option<&Path>) -> ProvidersManifest {
    load_providers_manifest_with_key(app_data_dir, &PAYSHIELD_ED25519_PUBLIC_KEY)
}

/// Verifies signature BEFORE writing; rejects tampered input without touching the existing cache.
pub fn save_verified_snapshot_with_key(
    app_data_dir: &Path,
    raw_json: &str,
    public_key: &[u8],
) -> Result<BinRadarSnapshot, String> {
    let parsed = verify_bin_radar_snapshot_json_with_key(raw_json, public_key)?;
    let dir = payshield_data_dir(app_data_dir);
    ensure_private_dir(&dir)?;
    write_private_file(&dir.join(SNAPSHOT_FILE_NAME), raw_json.as_bytes())?;
    write_private_file(&dir.join(SNAPSHOT_CACHE_FILE_NAME), raw_json.as_bytes())?;
    Ok(parsed)
}

pub fn save_verified_snapshot(
    app_data_dir: &Path,
    raw_json: &str,
) -> Result<BinRadarSnapshot, String> {
    save_verified_snapshot_with_key(app_data_dir, raw_json, &PAYSHIELD_ED25519_PUBLIC_KEY)
}

/// Verifies signature BEFORE writing; rejects tampered input without touching the existing cache.
pub fn save_verified_manifest_with_key(
    app_data_dir: &Path,
    raw_json: &str,
    public_key: &[u8],
) -> Result<ProvidersManifest, String> {
    let parsed = verify_providers_manifest_json_with_key(raw_json, public_key)?;
    let dir = payshield_data_dir(app_data_dir);
    ensure_private_dir(&dir)?;
    write_private_file(&dir.join(MANIFEST_FILE_NAME), raw_json.as_bytes())?;
    write_private_file(&dir.join(MANIFEST_CACHE_FILE_NAME), raw_json.as_bytes())?;
    Ok(parsed)
}

pub fn save_verified_manifest(
    app_data_dir: &Path,
    raw_json: &str,
) -> Result<ProvidersManifest, String> {
    save_verified_manifest_with_key(app_data_dir, raw_json, &PAYSHIELD_ED25519_PUBLIC_KEY)
}

/// Persists a strictly Zero-PII/Zero-PCI opt-in report locally (`0o600`, day-bucketed timestamp).
pub fn submit_local_bin_radar_report(
    app_data_dir: &Path,
    opt_in_enabled: bool,
    raw_json: &str,
) -> Result<BinRadarReport, String> {
    if !opt_in_enabled {
        return Err("Участие в анонимной статистике отключено в настройках.".to_string());
    }
    let report = parse_bin_radar_report_json(raw_json)?;
    let dir = payshield_data_dir(app_data_dir);
    ensure_private_dir(&dir)?;
    let path = dir.join(LOCAL_REPORTS_FILE_NAME);
    let mut records = load_local_bin_radar_reports(app_data_dir);
    let day_bucket = current_timestamp() / 86_400;
    records.push(LocalBinRadarReportRecord {
        reported_day: day_bucket,
        report: report.clone(),
    });
    if records.len() > MAX_LOCAL_REPORTS {
        let excess = records.len() - MAX_LOCAL_REPORTS;
        records.drain(..excess);
    }
    let serialized = serde_json::to_string_pretty(&records)
        .map_err(|e| format!("Не удалось сериализовать локальные отчёты: {e}"))?;
    write_private_file(&path, serialized.as_bytes())?;
    Ok(report)
}

pub fn load_local_bin_radar_reports(app_data_dir: &Path) -> Vec<LocalBinRadarReportRecord> {
    let path = payshield_data_dir(app_data_dir).join(LOCAL_REPORTS_FILE_NAME);
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}
