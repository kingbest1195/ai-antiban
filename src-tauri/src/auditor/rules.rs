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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HighRiskAsnConfig {
    pub asn: u32,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DangerousAsns {
    pub version: String,
    pub description: String,
    pub dnsbl_zones: Vec<DnsblZoneConfig>,
    pub high_risk_asns: Vec<HighRiskAsnConfig>,
    pub russian_isp_keywords: Vec<String>,
}

impl DangerousAsns {
    pub fn load_bundled() -> Result<Self, serde_json::Error> {
        serde_json::from_str(DEFAULT_DANGEROUS_ASNS_JSON)
    }

    pub fn is_high_risk_asn(&self, asn: u32) -> Option<&HighRiskAsnConfig> {
        self.high_risk_asns.iter().find(|item| item.asn == asn)
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
        assert_eq!(asns.version, "1.1.0");
        assert_eq!(asns.dnsbl_zones.len(), 5);
        assert!(asns.is_high_risk_asn(9009).is_some());
        assert_eq!(asns.matches_russian_isp("Rostelecom broadband"), Some("Rostelecom"));
    }
}
