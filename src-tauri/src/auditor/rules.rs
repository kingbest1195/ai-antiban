use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const DEFAULT_PROVIDER_MATRIX_JSON: &str =
    include_str!("../../../rules/provider_matrix.json");
pub const DEFAULT_DANGEROUS_ASNS_JSON: &str =
    include_str!("../../../rules/dangerous_asns.json");

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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderMatrix {
    pub version: String,
    pub updated_at: String,
    pub global_blocked_countries: Vec<String>,
    #[serde(default)]
    pub recommended_vps_countries: Vec<RecommendedCountry>,
    pub providers: HashMap<String, ProviderRules>,
}

impl ProviderMatrix {
    pub fn load_bundled() -> Result<Self, serde_json::Error> {
        serde_json::from_str(DEFAULT_PROVIDER_MATRIX_JSON)
    }

    pub fn get_provider_rules(&self, provider_id: &str) -> Option<&ProviderRules> {
        self.providers.get(provider_id)
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
            .find(|g| g.keywords.iter().any(|k| lower.contains(&k.to_lowercase())))
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
        Ok(Self {
            provider_matrix: Arc::new(RwLock::new(provider_matrix)),
            dangerous_asns: Arc::new(RwLock::new(dangerous_asns)),
        })
    }

    pub async fn update_provider_matrix_from_json(&self, json: &str) -> Result<(), serde_json::Error> {
        let matrix: ProviderMatrix = serde_json::from_str(json)?;
        let mut w = self.provider_matrix.write().await;
        *w = matrix;
        Ok(())
    }

    pub async fn update_dangerous_asns_from_json(&self, json: &str) -> Result<(), serde_json::Error> {
        let asns: DangerousAsns = serde_json::from_str(json)?;
        let mut w = self.dangerous_asns.write().await;
        *w = asns;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_bundled_rules() {
        let rules = RuleSet::load_bundled().expect("bundled rules should parse successfully");
        let matrix = rules.provider_matrix.blocking_read();
        assert_eq!(matrix.version, "1.0.0");
        assert!(matrix.global_blocked_countries.contains(&"RU".to_string()));
        assert!(matrix.global_blocked_countries.contains(&"HK".to_string()));
        assert!(matrix.providers.contains_key("anthropic"));
        assert!(matrix.providers.contains_key("openai"));
        assert!(matrix.providers.contains_key("gemini"));

        let asns = rules.dangerous_asns.blocking_read();
        assert_eq!(asns.version, "1.2.0");
        assert_eq!(asns.dnsbl_zones.len(), 5);
        assert_eq!(asns.asn_entry(9009).map(|e| e.kind), Some(NetworkKind::Vpn));
        assert_eq!(asns.asn_entry(24940).map(|e| e.kind), Some(NetworkKind::Hosting));
        assert_eq!(asns.matches_russian_isp("Rostelecom broadband"), Some("Rostelecom"));
    }
    /// Every record of the type lists is traceable: a non-empty source that names a licence.
    /// A record without a source (or without a licence) must not be in the file.
    #[test]
    fn dangerous_asns_schema_every_record_has_source_and_license() {
        let raw: serde_json::Value =
            serde_json::from_str(DEFAULT_DANGEROUS_ASNS_JSON).expect("valid JSON");
        // Strict shape: the typed parse rejects a record with a missing field or an unknown type.
        let asns = DangerousAsns::load_bundled().expect("schema");
        assert!(!asns.asns.is_empty() && !asns.isp_keyword_groups.is_empty());

        let has_source = |s: &str| {
            let t = s.trim();
            !t.is_empty() && t.to_lowercase().contains("license:")
        };
        for e in &asns.asns {
            assert!(has_source(&e.source), "AS{} has no source with a licence", e.asn);
            assert!(!e.name.trim().is_empty(), "AS{} has no name", e.asn);
            assert!(
                e.kind != NetworkKind::Residential,
                "AS{}: an ASN is hosting or vpn, residential is keyword-only",
                e.asn
            );
            if e.kind == NetworkKind::Vpn {
                assert!(!e.reason.trim().is_empty(), "AS{}: a vpn entry needs a reason", e.asn);
            }
        }
        for g in &asns.isp_keyword_groups {
            assert!(has_source(&g.source), "keyword group {:?} has no source", g.kind);
            assert!(!g.keywords.is_empty() && g.keywords.iter().all(|k| !k.trim().is_empty()));
        }
        // No ASN twice (the first would silently win).
        let mut seen = std::collections::HashSet::new();
        for e in &asns.asns {
            assert!(seen.insert(e.asn), "AS{} is listed twice", e.asn);
        }
        // The raw file has no record of the type lists that the typed parse would have dropped.
        assert_eq!(raw["asns"].as_array().map(Vec::len), Some(asns.asns.len()));
        assert_eq!(
            raw["isp_keyword_groups"].as_array().map(Vec::len),
            Some(asns.isp_keyword_groups.len())
        );
    }

    #[test]
    fn a_record_without_source_is_rejected_by_the_schema() {
        let bad = DEFAULT_DANGEROUS_ASNS_JSON.replacen("\"source\"", "\"src\"", 1);
        assert!(serde_json::from_str::<DangerousAsns>(&bad).is_err());
        let bad_type = DEFAULT_DANGEROUS_ASNS_JSON.replacen("\"type\": \"vpn\"", "\"type\": \"magic\"", 1);
        assert!(serde_json::from_str::<DangerousAsns>(&bad_type).is_err());
    }

    #[test]
    fn provider_matrix_is_valid() {
        let m = ProviderMatrix::load_bundled().expect("provider_matrix.json");
        assert!(!m.providers.is_empty());
    }

    #[test]
    fn keyword_kind_hosting_wins_over_residential() {
        let asns = DangerousAsns::load_bundled().unwrap();
        assert_eq!(asns.keyword_kind("Example Cloud Communications"), Some(NetworkKind::Hosting));
        assert_eq!(asns.keyword_kind("Example Broadband Ltd"), Some(NetworkKind::Residential));
        assert_eq!(asns.keyword_kind("Example Net"), None);
    }
}
