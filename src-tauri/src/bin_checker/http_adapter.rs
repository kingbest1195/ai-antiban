//! HTTP adapter for `BinLookupPort`: optional `ZASTAVA_BIN_PROXY_URL` (Neutrino/BINLookupAPI
//! compatible) and fallback public HandyAPI endpoint.

use super::model::{BinSource, CardFunding};
use super::port::{BinLookupError, BinLookupFuture, BinLookupPort, RawBinInfo};
use serde::Deserialize;
use std::time::Duration;

const DEFAULT_HANDY_BASE_URL: &str = "https://data.handyapi.com/bin";
const LOOKUP_TIMEOUT_MS: u64 = 2500;

#[derive(Debug, Deserialize)]
struct HandyApiResponse {
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "Scheme")]
    scheme: Option<String>,
    #[serde(rename = "Type")]
    card_type: Option<String>,
    #[serde(rename = "Country")]
    country: Option<HandyCountry>,
    #[serde(rename = "Issuer")]
    issuer: Option<String>,
    #[serde(rename = "CardTier")]
    card_tier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HandyCountry {
    #[serde(rename = "A2")]
    a2: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProxyApiResponse {
    valid: Option<bool>,
    #[serde(alias = "country-code", alias = "countryCode", alias = "country")]
    country_code: Option<String>,
    #[serde(alias = "card-brand", alias = "scheme")]
    scheme: Option<String>,
    #[serde(alias = "card-type", alias = "funding", alias = "type")]
    card_type: Option<String>,
    #[serde(alias = "card-category", alias = "cardCategory", alias = "category")]
    card_category: Option<String>,
    #[serde(alias = "issuer", alias = "issuerName", alias = "bank")]
    issuer: Option<String>,
    #[serde(alias = "is-prepaid", alias = "isPrepaid")]
    is_prepaid: Option<bool>,
    #[serde(alias = "is-commercial", alias = "isCommercial")]
    is_commercial: Option<bool>,
    #[serde(alias = "is-reloadable", alias = "isReloadable")]
    is_reloadable: Option<bool>,
}

pub struct HttpBinLookupAdapter {
    client: reqwest::Client,
    proxy_url: Option<String>,
    handy_base_url: String,
}

impl Default for HttpBinLookupAdapter {
    fn default() -> Self {
        Self::from_env()
    }
}

impl HttpBinLookupAdapter {
    pub fn from_env() -> Self {
        let proxy_url = std::env::var("ZASTAVA_BIN_PROXY_URL")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        Self::with_endpoints(
            proxy_url,
            DEFAULT_HANDY_BASE_URL.to_string(),
            LOOKUP_TIMEOUT_MS,
        )
    }

    pub fn with_endpoints(
        proxy_url: Option<String>,
        handy_base_url: String,
        timeout_ms: u64,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            proxy_url: proxy_url
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            handy_base_url,
        }
    }

    async fn fetch_proxy_api(
        &self,
        base_url: &str,
        bin_prefix: &str,
    ) -> Result<RawBinInfo, BinLookupError> {
        let url = if base_url.contains("{bin}") {
            base_url.replace("{bin}", bin_prefix)
        } else {
            format!("{}/{bin_prefix}", base_url.trim_end_matches('/'))
        };
        let resp = self.send_get(&url).await?;
        let parsed: ProxyApiResponse = resp
            .json()
            .await
            .map_err(|e| BinLookupError::InvalidPayload(e.to_string()))?;
        if parsed.valid == Some(false) {
            return Err(BinLookupError::NotFound);
        }
        let funding = parsed
            .card_type
            .as_deref()
            .map(CardFunding::parse_loose)
            .unwrap_or(CardFunding::Unknown);
        let category = parsed.card_category.map(|c| c.trim().to_uppercase());
        let has_funding_info = funding != CardFunding::Unknown || category.is_some();
        let is_prepaid = parsed.is_prepaid.or_else(|| {
            has_funding_info.then(|| {
                let cat = category.as_deref().unwrap_or("");
                funding == CardFunding::Prepaid
                    || cat.contains("PREPAID")
                    || cat.contains("VIRTUAL")
            })
        });
        let is_commercial = parsed.is_commercial.or_else(|| {
            has_funding_info.then(|| {
                let cat = category.as_deref().unwrap_or("");
                cat.contains("BUSINESS")
                    || cat.contains("CORPORATE")
                    || cat.contains("COMMERCIAL")
                    || cat.contains("PURCHASING")
            })
        });
        let country_code = normalize_country(parsed.country_code);
        if country_code.is_none() {
            return Err(BinLookupError::NotFound);
        }
        Ok(RawBinInfo {
            scheme: parsed.scheme.map(|s| s.trim().to_uppercase()),
            funding,
            is_prepaid,
            is_commercial,
            is_reloadable: parsed.is_reloadable,
            card_category: category,
            country_code,
            issuer_name: clean_opt_str(parsed.issuer),
            source: BinSource::ProxyApi,
        })
    }

    async fn fetch_handy_api(&self, bin_prefix: &str) -> Result<RawBinInfo, BinLookupError> {
        let url = format!("{}/{bin_prefix}", self.handy_base_url.trim_end_matches('/'));
        let resp = self.send_get(&url).await?;
        let data: HandyApiResponse = resp
            .json()
            .await
            .map_err(|e| BinLookupError::InvalidPayload(e.to_string()))?;
        if data.status.as_deref() != Some("SUCCESS") {
            return Err(BinLookupError::NotFound);
        }
        let country_code = normalize_country(data.country.and_then(|c| c.a2));
        if country_code.is_none() {
            return Err(BinLookupError::NotFound);
        }
        let funding = data
            .card_type
            .as_deref()
            .map(CardFunding::parse_loose)
            .unwrap_or(CardFunding::Unknown);
        let category = data
            .card_tier
            .map(|t| t.trim().to_uppercase())
            .filter(|t| !t.is_empty());
        let has_funding_info = funding != CardFunding::Unknown || category.is_some();
        let cat_ref = category.as_deref().unwrap_or("");
        let is_prepaid = has_funding_info.then(|| {
            funding == CardFunding::Prepaid
                || cat_ref.contains("PREPAID")
                || cat_ref.contains("VIRTUAL")
        });
        let is_commercial = has_funding_info.then(|| {
            cat_ref.contains("BUSINESS")
                || cat_ref.contains("CORPORATE")
                || cat_ref.contains("COMMERCIAL")
        });
        Ok(RawBinInfo {
            scheme: data
                .scheme
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty()),
            funding,
            is_prepaid,
            is_commercial,
            is_reloadable: None,
            card_category: category,
            country_code,
            issuer_name: clean_opt_str(data.issuer),
            source: BinSource::FallbackPublicApi,
        })
    }

    async fn send_get(&self, url: &str) -> Result<reqwest::Response, BinLookupError> {
        let resp = self.client.get(url).send().await.map_err(|e| {
            if e.is_timeout() {
                BinLookupError::Timeout
            } else {
                BinLookupError::Network(e.to_string())
            }
        })?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Err(BinLookupError::NotFound);
        }
        if !status.is_success() {
            return Err(BinLookupError::HttpStatus(status.as_u16()));
        }
        Ok(resp)
    }
}

impl BinLookupPort for HttpBinLookupAdapter {
    fn lookup<'a>(&'a self, bin_prefix: &'a str) -> BinLookupFuture<'a> {
        Box::pin(async move {
            if let Some(proxy_url) = &self.proxy_url {
                self.fetch_proxy_api(proxy_url, bin_prefix).await
            } else {
                self.fetch_handy_api(bin_prefix).await
            }
        })
    }
}

fn normalize_country(raw: Option<String>) -> Option<String> {
    raw.map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
}

fn clean_opt_str(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
