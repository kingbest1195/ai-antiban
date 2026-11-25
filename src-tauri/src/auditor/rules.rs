use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock, RwLock as StdRwLock};
use tokio::sync::RwLock;

pub const DEFAULT_PROVIDER_MATRIX_JSON: &str = include_str!("../../../rules/provider_matrix.json");
pub const DEFAULT_DANGEROUS_ASNS_JSON: &str = include_str!("../../../rules/dangerous_asns.json");

static RUNTIME_PROVIDER_MATRIX: OnceLock<StdRwLock<Option<Arc<ProviderMatrix>>>> = OnceLock::new();

fn runtime_matrix_slot() -> &'static StdRwLock<Option<Arc<ProviderMatrix>>> {
    RUNTIME_PROVIDER_MATRIX.get_or_init(|| StdRwLock::new(None))
}

/// Publishes a live `ProviderMatrix` snapshot for synchronous fast-path domain lookups and PAC builds.
pub fn publish_runtime_provider_matrix(matrix: Arc<ProviderMatrix>) {
    let mut w = runtime_matrix_slot()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    *w = Some(matrix);
}

/// Seeds the runtime snapshot only if it has not been initialized yet.
pub fn publish_runtime_provider_matrix_if_unset(matrix: Arc<ProviderMatrix>) {
    let mut w = runtime_matrix_slot()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if w.is_none() {
        *w = Some(matrix);
    }
}

/// Returns an `Arc` clone of the active runtime `ProviderMatrix` snapshot, if initialized.
pub fn runtime_provider_matrix_snapshot() -> Option<Arc<ProviderMatrix>> {
    let slot = RUNTIME_PROVIDER_MATRIX.get()?;
    let r = slot.read().unwrap_or_else(|e| e.into_inner());
    r.clone()
}

/// Runs `f` against the active runtime `ProviderMatrix` snapshot without cloning it.
pub fn with_runtime_provider_matrix<R>(f: impl FnOnce(Option<&ProviderMatrix>) -> R) -> R {
    let Some(slot) = RUNTIME_PROVIDER_MATRIX.get() else {
        return f(None);
    };
    let r = slot.read().unwrap_or_else(|e| e.into_inner());
    f(r.as_deref())
}

#[cfg(any(test, feature = "test-support"))]
pub static RUNTIME_MATRIX_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(any(test, feature = "test-support"))]
pub fn clear_runtime_provider_matrix_for_test() {
    if let Some(slot) = RUNTIME_PROVIDER_MATRIX.get() {
        let mut w = slot.write().unwrap_or_else(|e| e.into_inner());
        *w = None;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecommendedCountry {
    pub code: String,
    pub name_ru: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderRules {
    pub id: String,
    pub display_name: String,
    pub domains: Vec<String>,
    pub blocked_countries: Vec<String>,
    #[serde(default)]
    pub country_block_reasons: HashMap<String, String>,
    #[serde(default)]
    pub warning_countries: HashMap<String, String>,
    #[serde(default)]
    pub strict_impossible_travel: bool,
    #[serde(default)]
    pub max_country_switches_per_12h: u32,
    #[serde(default)]
    pub session_ip_stability_for_studio: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderMatrix {
    pub version: String,
    pub updated_at: String,
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub generated_at_utc: String,
    #[serde(default)]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub payment_kyc_domains: Vec<String>,
    pub global_blocked_countries: Vec<String>,
    #[serde(default)]
    pub recommended_vps_countries: Vec<RecommendedCountry>,
    pub providers: HashMap<String, ProviderRules>,
    #[serde(default)]
    pub signature_ed25519_b64: String,
}

#[derive(Serialize)]
struct CanonicalProviderRules<'a> {
    id: &'a str,
    display_name: &'a str,
    domains: &'a [String],
    blocked_countries: &'a [String],
    country_block_reasons: BTreeMap<&'a String, &'a String>,
    warning_countries: BTreeMap<&'a String, &'a String>,
    strict_impossible_travel: bool,
    max_country_switches_per_12h: u32,
    session_ip_stability_for_studio: bool,
}

#[derive(Serialize)]
struct CanonicalProviderMatrixPayload<'a> {
    schema_version: u32,
    version: &'a str,
    updated_at: &'a str,
    generated_at_utc: &'a str,
    ttl_seconds: u64,
    payment_kyc_domains: &'a [String],
    global_blocked_countries: &'a [String],
    recommended_vps_countries: &'a [RecommendedCountry],
    providers: BTreeMap<&'a String, CanonicalProviderRules<'a>>,
}

impl ProviderMatrix {
    pub fn load_bundled() -> Result<Self, serde_json::Error> {
        serde_json::from_str(DEFAULT_PROVIDER_MATRIX_JSON)
    }

    pub fn get_provider_rules(&self, provider_id: &str) -> Option<&ProviderRules> {
        self.providers.get(provider_id)
    }

    /// Deterministic canonical JSON bytes covered by `signature_ed25519_b64`.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, String> {
        let mut providers = BTreeMap::new();
        for (k, v) in &self.providers {
            providers.insert(
                k,
                CanonicalProviderRules {
                    id: &v.id,
                    display_name: &v.display_name,
                    domains: &v.domains,
                    blocked_countries: &v.blocked_countries,
                    country_block_reasons: v.country_block_reasons.iter().collect(),
                    warning_countries: v.warning_countries.iter().collect(),
                    strict_impossible_travel: v.strict_impossible_travel,
                    max_country_switches_per_12h: v.max_country_switches_per_12h,
                    session_ip_stability_for_studio: v.session_ip_stability_for_studio,
                },
            );
        }
        let payload = CanonicalProviderMatrixPayload {
            schema_version: self.schema_version,
            version: &self.version,
            updated_at: &self.updated_at,
            generated_at_utc: &self.generated_at_utc,
            ttl_seconds: self.ttl_seconds,
            payment_kyc_domains: &self.payment_kyc_domains,
            global_blocked_countries: &self.global_blocked_countries,
            recommended_vps_countries: &self.recommended_vps_countries,
            providers,
        };
        serde_json::to_vec(&payload)
            .map_err(|e| format!("Failed to serialize canonical provider matrix payload: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsblZoneConfig {
    pub zone: String,
    pub name: String,
    pub severity: String,
    pub reason: String,
}

/// Kind of network an ASN or an ISP keyword points to (see `auditor/ip_type.rs`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    /// Data center / cloud: a personal VPS lives here, not penalised.
    Hosting,
    /// Mass VPN pool: many people share the address, a warning.
    Vpn,
    /// Home or mobile access provider (only for keyword groups).
    Residential,
}

/// One ASN with its kind. `source` names where the record comes from and under which licence;
/// a record without a source is not allowed in the file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsnEntry {
    pub asn: u32,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: NetworkKind,
    pub source: String,
    #[serde(default)]
    pub reason: String,
}

/// Words of an ISP / organisation name that point to a kind of network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IspKeywordGroup {
    #[serde(rename = "type")]
    pub kind: NetworkKind,
    pub keywords: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DangerousAsns {
    pub version: String,
    pub description: String,
    pub dnsbl_zones: Vec<DnsblZoneConfig>,
    pub asns: Vec<AsnEntry>,
    #[serde(default)]
    pub isp_keyword_groups: Vec<IspKeywordGroup>,
    pub russian_isp_keywords: Vec<String>,
}

impl DangerousAsns {
    pub fn load_bundled() -> Result<Self, serde_json::Error> {
        serde_json::from_str(DEFAULT_DANGEROUS_ASNS_JSON)
    }

    pub fn asn_entry(&self, asn: u32) -> Option<&AsnEntry> {
        self.asns.iter().find(|item| item.asn == asn)
    }

    /// Kind of network the words of `text` point to (first matching group in file order).
    pub fn keyword_kind(&self, text: &str) -> Option<NetworkKind> {
        let lower = text.to_lowercase();
        self.isp_keyword_groups
            .iter()
            .find(|g| {
                g.keywords
                    .iter()
                    .any(|k| contains_word_boundary(&lower, &k.to_lowercase()))
            })
            .map(|g| g.kind)
    }

    pub fn matches_russian_isp(&self, text: &str) -> Option<&str> {
        let text_lower = text.to_lowercase();
        for keyword in &self.russian_isp_keywords {
            if text_lower.contains(&keyword.to_lowercase()) {
                return Some(keyword.as_str());
            }
        }
        None
    }
}

fn contains_word_boundary(haystack_lower: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return false;
    }
    let mut offset = 0;
    while let Some(pos) = haystack_lower[offset..].find(needle_lower) {
        let start = offset + pos;
        let end = start + needle_lower.len();
        let left_ok = haystack_lower[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let right_ok = haystack_lower[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if left_ok && right_ok {
            return true;
        }
        let step = haystack_lower[start..]
            .chars()
            .next()
            .map_or(1, char::len_utf8);
        offset = start + step;
    }
    false
}

/// Unified RuleSet wrapped in thread-safe memory storage
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub provider_matrix: Arc<RwLock<ProviderMatrix>>,
    pub dangerous_asns: Arc<RwLock<DangerousAsns>>,
}

impl RuleSet {
    pub fn load_bundled() -> Result<Self, serde_json::Error> {
        let provider_matrix = ProviderMatrix::load_bundled()?;
        let dangerous_asns = DangerousAsns::load_bundled()?;
        publish_runtime_provider_matrix_if_unset(Arc::new(provider_matrix.clone()));
        Ok(Self {
            provider_matrix: Arc::new(RwLock::new(provider_matrix)),
            dangerous_asns: Arc::new(RwLock::new(dangerous_asns)),
        })
    }

    pub async fn set_provider_matrix(&self, matrix: ProviderMatrix) {
        publish_runtime_provider_matrix(Arc::new(matrix.clone()));
        let mut w = self.provider_matrix.write().await;
        *w = matrix;
    }

    pub async fn update_provider_matrix_from_json(
        &self,
        json: &str,
    ) -> Result<(), serde_json::Error> {
        let matrix: ProviderMatrix = serde_json::from_str(json)?;
        self.set_provider_matrix(matrix).await;
        Ok(())
    }

    pub async fn update_dangerous_asns_from_json(
        &self,
        json: &str,
    ) -> Result<(), serde_json::Error> {
        let asns: DangerousAsns = serde_json::from_str(json)?;
        let mut w = self.dangerous_asns.write().await;
        *w = asns;
        Ok(())
    }
}

#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;
