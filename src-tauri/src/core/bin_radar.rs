//! Layer 0 domain models, Zero-PII/Zero-PCI validation, and exponential time-decay math
//! for BIN Radar (PayShield Phase 2).

use serde::{Deserialize, Serialize};

pub const WINDOW_14D_DAYS: f64 = 14.0;
pub const WINDOW_30D_DAYS: f64 = 30.0;
pub const WINDOW_14D_HALF_LIFE_DAYS: f64 = 5.0;
pub const WINDOW_30D_HALF_LIFE_DAYS: f64 = 12.0;
pub const MIN_PUBLICATION_SAMPLE_SIZE: u32 = 5;
pub const CRITICAL_RISK_MIN_SAMPLES: u32 = 15;
pub const CRITICAL_RISK_PCT_THRESHOLD: f64 = 40.0;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AiPaymentService {
    #[serde(alias = "claudePro")]
    ClaudePro,
    #[serde(alias = "claudeMax")]
    ClaudeMax,
    #[serde(alias = "ChatGPT")]
    Chatgpt,
    Cursor,
    Gemini,
}

impl AiPaymentService {
    pub const ALL: [AiPaymentService; 5] = [
        AiPaymentService::ClaudePro,
        AiPaymentService::ClaudeMax,
        AiPaymentService::Chatgpt,
        AiPaymentService::Cursor,
        AiPaymentService::Gemini,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AiPaymentService::ClaudePro => "claude_pro",
            AiPaymentService::ClaudeMax => "claude_max",
            AiPaymentService::Chatgpt => "chatgpt",
            AiPaymentService::Cursor => "cursor",
            AiPaymentService::Gemini => "gemini",
        }
    }

    pub fn label_ru(self) -> &'static str {
        match self {
            AiPaymentService::ClaudePro => "Claude Pro",
            AiPaymentService::ClaudeMax => "Claude Max",
            AiPaymentService::Chatgpt => "ChatGPT",
            AiPaymentService::Cursor => "Cursor",
            AiPaymentService::Gemini => "Gemini / AI Studio",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PaymentChannel {
    StripeWebCard,
    StripeGooglePay,
    StripeApplePay,
    AppleIap,
    GooglePlayIap,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GeoMatchClass {
    FullMatch,
    IpMismatch,
    BillingMismatch,
    TripleMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WarmupBucket {
    #[serde(rename = "lt_24h", alias = "lt24h")]
    Lt24h,
    #[serde(rename = "24_96h")]
    Between24And96h,
    #[serde(rename = "gt_96h", alias = "gt96h")]
    Gt96h,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentOutcome {
    Success,
    SoftDecline,
    InstantKyc,
    InstantBan,
}

/// Strictly Zero-PII / Zero-PCI report payload. Unknown fields (email, ip, last4, pan) are rejected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BinRadarReport {
    pub bin_prefix: String,
    pub service: AiPaymentService,
    pub channel: PaymentChannel,
    pub geo_match: GeoMatchClass,
    pub warmup_bucket: WarmupBucket,
    pub outcome: PaymentOutcome,
    pub client_version: String,
}

impl BinRadarReport {
    /// Validates strict 8-digit prefix (`^[0-9]{8}$`) and non-empty client version.
    pub fn validate(&self) -> Result<(), String> {
        validate_bin_prefix_8(&self.bin_prefix)?;
        let ver = self.client_version.trim();
        if ver.is_empty() || ver.len() > 32 {
            return Err("Некорректная версия клиента в отчёте.".to_string());
        }
        Ok(())
    }
}

/// Validates an exact 8-digit numeric card prefix (`^[0-9]{8}$`), rejecting PAN > 8 digits.
pub fn validate_bin_prefix_8(raw: &str) -> Result<String, String> {
    if raw.len() != 8 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(
            "Требуются ровно 8 первых цифр карты без пробелов и остального номера.".to_string(),
        );
    }
    Ok(raw.to_string())
}

/// Parses and validates a `BinRadarReport` from JSON, rejecting extra fields or PAN > 8 digits.
pub fn parse_bin_radar_report_json(raw: &str) -> Result<BinRadarReport, String> {
    let report: BinRadarReport = serde_json::from_str(raw)
        .map_err(|e| format!("Отклонён некорректный формат отчёта: {e}"))?;
    report.validate()?;
    Ok(report)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinRadarWindowStats {
    pub n: u32,
    pub success_pct: f64,
    pub soft_decline_pct: f64,
    pub instant_kyc_pct: f64,
    pub instant_ban_pct: f64,
}

impl BinRadarWindowStats {
    pub fn risk_pct(&self) -> f64 {
        self.instant_kyc_pct + self.instant_ban_pct
    }

    pub fn is_critical_risk(&self) -> bool {
        self.n >= CRITICAL_RISK_MIN_SAMPLES && self.risk_pct() > CRITICAL_RISK_PCT_THRESHOLD
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinRadarEntry {
    pub bin_prefix: String,
    pub service: AiPaymentService,
    pub window_14d: BinRadarWindowStats,
    pub window_30d: BinRadarWindowStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinRadarSnapshot {
    pub schema_version: u32,
    pub generated_at_utc: String,
    pub ttl_seconds: u64,
    pub entries: Vec<BinRadarEntry>,
    pub signature_ed25519_b64: String,
}

#[derive(Serialize)]
struct CanonicalSnapshotPayload<'a> {
    schema_version: u32,
    generated_at_utc: &'a str,
    ttl_seconds: u64,
    entries: &'a [BinRadarEntry],
}

impl BinRadarSnapshot {
    /// Deterministic canonical bytes covered by `signature_ed25519_b64`.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, String> {
        let payload = CanonicalSnapshotPayload {
            schema_version: self.schema_version,
            generated_at_utc: &self.generated_at_utc,
            ttl_seconds: self.ttl_seconds,
            entries: &self.entries,
        };
        serde_json::to_vec(&payload)
            .map_err(|e| format!("Failed to serialize canonical snapshot payload: {e}"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TimestampedOutcome {
    pub age_days: f64,
    pub outcome: PaymentOutcome,
    pub weight_multiplier: f64,
}

/// Exponential time decay weight `exp(-ln(2) / half_life * age_days)`.
pub fn decay_weight(age_days: f64, half_life_days: f64) -> f64 {
    if !age_days.is_finite() || !half_life_days.is_finite() || half_life_days <= 0.0 {
        return 0.0;
    }
    if age_days <= 0.0 {
        return 1.0;
    }
    let lambda = std::f64::consts::LN_2 / half_life_days;
    (-lambda * age_days).exp()
}

fn round1(val: f64) -> f64 {
    (val * 10.0).round() / 10.0
}

/// Computes exponential-decay window stats over samples with `0.0 <= age_days <= window_days`.
pub fn compute_window_stats(
    samples: &[TimestampedOutcome],
    window_days: f64,
    half_life_days: f64,
) -> BinRadarWindowStats {
    let mut n: u32 = 0;
    let mut w_total = 0.0_f64;
    let mut w_success = 0.0_f64;
    let mut w_soft_decline = 0.0_f64;
    let mut w_instant_kyc = 0.0_f64;
    let mut w_instant_ban = 0.0_f64;

    for s in samples {
        if !s.age_days.is_finite() || s.age_days < 0.0 || s.age_days > window_days {
            continue;
        }
        let mult = if s.weight_multiplier.is_finite() && s.weight_multiplier > 0.0 {
            s.weight_multiplier
        } else {
            continue;
        };
        let w = decay_weight(s.age_days, half_life_days) * mult;
        if w <= 0.0 {
            continue;
        }
        n = n.saturating_add(1);
        w_total += w;
        match s.outcome {
            PaymentOutcome::Success => w_success += w,
            PaymentOutcome::SoftDecline => w_soft_decline += w,
            PaymentOutcome::InstantKyc => w_instant_kyc += w,
            PaymentOutcome::InstantBan => w_instant_ban += w,
        }
    }

    if n == 0 || w_total <= 0.0 {
        return BinRadarWindowStats {
            n: 0,
            success_pct: 0.0,
            soft_decline_pct: 0.0,
            instant_kyc_pct: 0.0,
            instant_ban_pct: 0.0,
        };
    }

    BinRadarWindowStats {
        n,
        success_pct: round1(w_success * 100.0 / w_total),
        soft_decline_pct: round1(w_soft_decline * 100.0 / w_total),
        instant_kyc_pct: round1(w_instant_kyc * 100.0 / w_total),
        instant_ban_pct: round1(w_instant_ban * 100.0 / w_total),
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BinRadarStatus {
    Sufficient,
    InsufficientData,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BinRadarLookupStats {
    pub bin_prefix: String,
    pub service: AiPaymentService,
    pub status: BinRadarStatus,
    pub sample_size_14d: u32,
    pub sample_size_30d: u32,
    pub window_14d: Option<BinRadarWindowStats>,
    pub window_30d: Option<BinRadarWindowStats>,
    pub risk_pct_14d: Option<f64>,
    pub critical_warning: bool,
    pub summary_ru: String,
}

/// Finds a snapshot entry matching an 8-digit (or 6-digit range base `XXXXXX00`) prefix.
pub fn find_snapshot_entry<'a>(
    snapshot: &'a BinRadarSnapshot,
    bin_prefix: &str,
    service: AiPaymentService,
) -> Option<&'a BinRadarEntry> {
    let clean = bin_prefix.trim();
    if clean.len() < 6 || !clean.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if clean.len() == 8
        && let Some(exact) = snapshot
            .entries
            .iter()
            .find(|e| e.service == service && e.bin_prefix == clean)
    {
        return Some(exact);
    }
    let six = &clean[..6];
    snapshot
        .entries
        .iter()
        .find(|e| {
            e.service == service && e.bin_prefix.starts_with(six) && e.bin_prefix.ends_with("00")
        })
        .or_else(|| {
            snapshot
                .entries
                .iter()
                .find(|e| e.service == service && e.bin_prefix.starts_with(six))
        })
}

/// Evaluates `BinRadarLookupStats` enforcing the `n >= 5` statistical hygiene floor.
pub fn lookup_bin_radar_stats(
    snapshot: &BinRadarSnapshot,
    bin_prefix: &str,
    service: AiPaymentService,
) -> BinRadarLookupStats {
    let Some(entry) = find_snapshot_entry(snapshot, bin_prefix, service) else {
        return BinRadarLookupStats {
            bin_prefix: bin_prefix.to_string(),
            service,
            status: BinRadarStatus::InsufficientData,
            sample_size_14d: 0,
            sample_size_30d: 0,
            window_14d: None,
            window_30d: None,
            risk_pct_14d: None,
            critical_warning: false,
            summary_ru: "Статистика оплат: недостаточно данных (меньше 5 отзывов)".to_string(),
        };
    };

    let has_14d = entry.window_14d.n >= MIN_PUBLICATION_SAMPLE_SIZE;
    let has_30d = entry.window_30d.n >= MIN_PUBLICATION_SAMPLE_SIZE;

    if !has_14d && !has_30d {
        return BinRadarLookupStats {
            bin_prefix: bin_prefix.to_string(),
            service,
            status: BinRadarStatus::InsufficientData,
            sample_size_14d: entry.window_14d.n,
            sample_size_30d: entry.window_30d.n,
            window_14d: None,
            window_30d: None,
            risk_pct_14d: None,
            critical_warning: false,
            summary_ru: "Статистика оплат: недостаточно данных (меньше 5 отзывов)".to_string(),
        };
    }

    let critical_warning = entry.window_14d.is_critical_risk();
    let status = if critical_warning {
        BinRadarStatus::Critical
    } else {
        BinRadarStatus::Sufficient
    };
    let primary_win = if has_14d {
        (&entry.window_14d, "14 дн.")
    } else {
        (&entry.window_30d, "30 дн.")
    };
    let risk_pct = round1(primary_win.0.risk_pct());
    let summary_ru = format!(
        "Успех {:.0}% · Проверка паспорта/отказ {:.0}% · Отклонено {:.0}% · За {}, n={}",
        primary_win.0.success_pct,
        risk_pct,
        primary_win.0.soft_decline_pct,
        primary_win.1,
        primary_win.0.n
    );

    BinRadarLookupStats {
        bin_prefix: bin_prefix.to_string(),
        service,
        status,
        sample_size_14d: entry.window_14d.n,
        sample_size_30d: entry.window_30d.n,
        window_14d: has_14d.then(|| entry.window_14d.clone()),
        window_30d: has_30d.then(|| entry.window_30d.clone()),
        risk_pct_14d: has_14d.then(|| round1(entry.window_14d.risk_pct())),
        critical_warning,
        summary_ru,
    }
}
