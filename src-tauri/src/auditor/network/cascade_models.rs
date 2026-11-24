//! Serde response models and AS-org parser for geo-telemetry cascades.

use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct IpWhoIsResponse {
    pub(crate) ip: Option<String>,
    pub(crate) country_code: Option<String>,
    pub(crate) connection: Option<IpWhoIsConnection>,
    pub(crate) timezone: Option<IpWhoIsTimezone>,
}

#[derive(Deserialize)]
pub(crate) struct IpWhoIsConnection {
    pub(crate) asn: Option<u32>,
    pub(crate) org: Option<String>,
    pub(crate) isp: Option<String>,
    pub(crate) domain: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct IpWhoIsTimezone {
    pub(crate) id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct IpInfoResponse {
    pub(crate) ip: Option<String>,
    pub(crate) hostname: Option<String>,
    pub(crate) country: Option<String>,
    pub(crate) org: Option<String>,
    pub(crate) timezone: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FreeIpApiResponse {
    pub(super) ip_address: Option<String>,
    pub(super) country_code: Option<String>,
    pub(super) asn: Option<String>,
    pub(super) asn_organization: Option<String>,
    pub(super) time_zones: Option<Vec<String>>,
}

pub(crate) fn parse_as_org(org_str: &str) -> (Option<u32>, Option<String>) {
    let trimmed = org_str.trim();
    if trimmed.len() >= 2 && trimmed[..2].eq_ignore_ascii_case("AS") {
        let rest = &trimmed[2..];
        let digits_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits_len > 0 {
            let asn = rest[..digits_len].parse::<u32>().ok();
            let name = rest[digits_len..].trim();
            let org_name = (!name.is_empty()).then(|| name.to_string());
            return (asn, org_name);
        }
    }
    let org_name = (!trimmed.is_empty()).then(|| trimmed.to_string());
    (None, org_name)
}
