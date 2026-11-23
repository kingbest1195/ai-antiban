//! Layer 0 provider manifest schema and Per-Service Auto-Demote (Brand Integrity Guard).

use crate::core::bin_radar::{AiPaymentService, BinRadarEntry, BinRadarSnapshot};
use serde::{Deserialize, Serialize};

pub const AUTO_DEMOTE_MIN_SAMPLES: u32 = 15;
pub const AUTO_DEMOTE_WARNING_RATE: f64 = 0.40;
pub const AUTO_DEMOTE_BLACKLIST_RATE: f64 = 0.65;
pub const GLOBAL_DEMOTE_MIN_SERVICES: usize = 2;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCategory {
    AppleGiftCard,
    VirtualCard,
    ForeignBank,
    Marketplace,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTier {
    Tier1Iap,
    Tier2Conditional,
    Blacklist,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Active,
    DemotedWarning,
    Blacklist,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderEntry {
    pub id: String,
    pub name: String,
    pub category: ProviderCategory,
    pub tier: ProviderTier,
    pub status: ProviderStatus,
    #[serde(default)]
    pub known_bin_prefixes: Vec<String>,
    #[serde(default)]
    pub supported_rails: Vec<String>,
    #[serde(default)]
    pub supported_services: Vec<AiPaymentService>,
    pub fees_summary: String,
    #[serde(default)]
    pub warnings_ru: Vec<String>,
    #[serde(default)]
    pub affiliate_url: Option<String>,
    /// Retained for JSON schema compatibility only; IGNORED by Auto-Demote for affiliate integrity.
    #[serde(default)]
    pub auto_demote_exempt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlacklistedProviderEntry {
    pub id: String,
    pub name: String,
    pub reason_ru: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvidersManifest {
    pub schema_version: u32,
    pub generated_at_utc: String,
    pub ttl_seconds: u64,
    pub providers: Vec<ProviderEntry>,
    #[serde(default)]
    pub blacklist: Vec<BlacklistedProviderEntry>,
    pub signature_ed25519_b64: String,
}

#[derive(Serialize)]
struct CanonicalManifestPayload<'a> {
    schema_version: u32,
    generated_at_utc: &'a str,
    ttl_seconds: u64,
    providers: &'a [ProviderEntry],
    blacklist: &'a [BlacklistedProviderEntry],
}

impl ProvidersManifest {
    /// Deterministic canonical bytes covered by `signature_ed25519_b64`.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, String> {
        let payload = CanonicalManifestPayload {
            schema_version: self.schema_version,
            generated_at_utc: &self.generated_at_utc,
            ttl_seconds: self.ttl_seconds,
            providers: &self.providers,
            blacklist: &self.blacklist,
        };
        serde_json::to_vec(&payload)
            .map_err(|e| format!("Failed to serialize canonical manifest payload: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDemoteStatus {
    pub service: AiPaymentService,
    pub status: ProviderStatus,
    pub rate_14d: f64,
    pub sample_size_14d: u32,
    pub reason_ru: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EvaluatedProvider {
    pub entry: ProviderEntry,
    pub effective_status: ProviderStatus,
    pub global_demoted: bool,
    pub per_service: Vec<ServiceDemoteStatus>,
    pub demote_reason_ru: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EvaluatedProvidersManifest {
    pub schema_version: u32,
    pub generated_at_utc: String,
    pub providers: Vec<EvaluatedProvider>,
    pub blacklist: Vec<BlacklistedProviderEntry>,
}

fn bin_matches_provider_prefix(snapshot_bin: &str, provider_prefix: &str) -> bool {
    let s = snapshot_bin.trim();
    let p = provider_prefix.trim();
    if s.len() < 6 || p.len() < 6 {
        return false;
    }
    if p.len() == 8 && s.len() == 8 {
        if p == s {
            return true;
        }
        if p.ends_with("00") && s.starts_with(&p[..6]) {
            return true;
        }
        if s.ends_with("00") && p.starts_with(&s[..6]) {
            return true;
        }
        return false;
    }
    s.starts_with(&p[..6]) && p.starts_with(&s[..6])
}

fn collect_matching_entries<'a>(
    entry: &ProviderEntry,
    snapshot: &'a BinRadarSnapshot,
    service: AiPaymentService,
) -> Vec<&'a BinRadarEntry> {
    snapshot
        .entries
        .iter()
        .filter(|item| {
            item.service == service
                && entry
                    .known_bin_prefixes
                    .iter()
                    .any(|p| bin_matches_provider_prefix(&item.bin_prefix, p))
        })
        .collect()
}

/// Evaluates Per-Service Auto-Demote (`(instant_kyc + instant_ban) / n > 0.40` at `n >= 15`).
///
/// Security invariant: `auto_demote_exempt` is ALWAYS ignored (especially for affiliate links).
pub fn evaluate_provider_auto_demote(
    entry: &ProviderEntry,
    snapshot: &BinRadarSnapshot,
) -> EvaluatedProvider {
    let _exempt_ignored = entry.auto_demote_exempt;
    let mut per_service = Vec::new();
    let mut degraded_count: usize = 0;
    let mut worst_auto_status = entry.status;

    for service in AiPaymentService::ALL {
        if !entry.supported_services.is_empty() && !entry.supported_services.contains(&service) {
            continue;
        }
        let matched = collect_matching_entries(entry, snapshot, service);
        let mut worst_rate = 0.0_f64;
        let mut total_n: u32 = 0;
        let mut weighted_risk_num = 0.0_f64;

        for m in &matched {
            if m.window_14d.n == 0 {
                continue;
            }
            let rate = (m.window_14d.instant_kyc_pct + m.window_14d.instant_ban_pct) / 100.0;
            total_n = total_n.saturating_add(m.window_14d.n);
            weighted_risk_num += rate * (m.window_14d.n as f64);
            if m.window_14d.n >= AUTO_DEMOTE_MIN_SAMPLES && rate > worst_rate {
                worst_rate = rate;
            }
        }

        let aggregate_rate = if total_n > 0 {
            weighted_risk_num / (total_n as f64)
        } else {
            0.0
        };
        let effective_rate = worst_rate.max(if total_n >= AUTO_DEMOTE_MIN_SAMPLES {
            aggregate_rate
        } else {
            0.0
        });

        let auto_status = if total_n >= AUTO_DEMOTE_MIN_SAMPLES {
            if effective_rate > AUTO_DEMOTE_BLACKLIST_RATE {
                ProviderStatus::Blacklist
            } else if effective_rate > AUTO_DEMOTE_WARNING_RATE {
                ProviderStatus::DemotedWarning
            } else {
                ProviderStatus::Active
            }
        } else {
            ProviderStatus::Active
        };

        let combined_status = entry.status.max(auto_status);
        let is_degraded = combined_status != ProviderStatus::Active;
        if auto_status != ProviderStatus::Active {
            degraded_count += 1;
        }
        if combined_status > worst_auto_status {
            worst_auto_status = combined_status;
        }

        let reason_ru = if is_degraded {
            Some(format!(
                "Автоматически понижен по статистике пользователей для {}: высокий риск запроса паспорта или блокировки за последние 14 дней ({:.0}% при n={})",
                service.label_ru(),
                effective_rate * 100.0,
                total_n
            ))
        } else {
            None
        };

        per_service.push(ServiceDemoteStatus {
            service,
            status: combined_status,
            rate_14d: (effective_rate * 1000.0).round() / 1000.0,
            sample_size_14d: total_n,
            reason_ru,
        });
    }

    let global_demoted =
        entry.status != ProviderStatus::Active || degraded_count >= GLOBAL_DEMOTE_MIN_SERVICES;
    let effective_status = if global_demoted {
        worst_auto_status
    } else {
        entry.status
    };

    let demote_reason_ru = if global_demoted || degraded_count > 0 {
        per_service
            .iter()
            .find_map(|s| s.reason_ru.clone())
            .or_else(|| {
                Some("Автоматически понижен по статистике пользователей: высокий риск запроса паспорта или блокировки за последние 14 дней".to_string())
            })
    } else {
        None
    };

    EvaluatedProvider {
        entry: entry.clone(),
        effective_status,
        global_demoted,
        per_service,
        demote_reason_ru,
    }
}

pub fn evaluate_manifest_auto_demote(
    manifest: &ProvidersManifest,
    snapshot: &BinRadarSnapshot,
) -> EvaluatedProvidersManifest {
    let providers = manifest
        .providers
        .iter()
        .map(|p| evaluate_provider_auto_demote(p, snapshot))
        .collect();
    EvaluatedProvidersManifest {
        schema_version: manifest.schema_version,
        generated_at_utc: manifest.generated_at_utc.clone(),
        providers,
        blacklist: manifest.blacklist.clone(),
    }
}
