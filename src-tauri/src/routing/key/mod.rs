//! Key parsing and strict validation.
//!
//! Accepted forms:
//! * `zastava://<base64 JSON v2>` — `{"v":2,"id":…,"label":…,"country":…,"exit_ip":…,"expires_at":…,"entry":[…]}`;
//! * `zastava://<base64 JSON v1>` — flat `{"protocol","host","port","username","password","label"}`;
//! * `zastava://<base64 URL>` or a bare URL: `socks5://`, `socks5h://`, `http://`, `https://`
//!   `[user:pass@]host[:port][#Label]`.
//!
//! Address policy: `zastava://` keys (they come from outside) may only point to public hosts. Keys
//! the user typed in URL form (`socks5://`, `http://`, `https://`) may also point to the user's own
//! local proxy (loopback / private addresses), except for the gateway itself. See [`super::net`].
//!
//! Error messages never contain credentials or the raw key.

mod validate;

#[cfg(test)]
mod tests;

use std::net::IpAddr;

use serde::Deserialize;
use url::Url;

use super::{Entry, EntryProto, MAX_ENTRIES, Route, route_id_for_raw_key};
use crate::proxy::server::is_forbidden_ip;
use validate::{
    build_entry, clean_label, decode_base64_flexible, json_error, percent_decode_clean, validate_id,
};

/// Prefix of keys that come from outside.
pub const ZASTAVA_SCHEME: &str = "zastava://";
pub const MAX_KEY_LEN: usize = 16 * 1024;
pub const MAX_LABEL_LEN: usize = 64;
pub const MAX_ID_LEN: usize = 64;
pub const MAX_HOST_LEN: usize = 253;
pub const MAX_CRED_LEN: usize = 255;
pub const SUPPORTED_KEY_VERSION: u64 = 2;

#[derive(Deserialize)]
struct KeyV1 {
    protocol: String,
    host: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
struct EntryV2 {
    proto: String,
    host: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    sni: Option<String>,
}

#[derive(Deserialize)]
struct KeyV2 {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    exit_ip: Option<String>,
    #[serde(default)]
    expires_at: Option<u64>,
    entry: Vec<EntryV2>,
}

fn single_entry_route(
    entry: Entry,
    label: Option<String>,
    raw_key: &str,
    now: u64,
) -> Result<Route, String> {
    let label = clean_label(label, &entry.host)?;
    Ok(Route {
        id: route_id_for_raw_key(raw_key),
        label,
        country: None,
        exit_ip: None,
        expires_at: None,
        entries: vec![entry],
        raw_key: raw_key.to_string(),
        enabled: true,
        added_at: now,
    })
}

fn parse_v2(value: serde_json::Value, raw_key: &str, now: u64) -> Result<Route, String> {
    let key: KeyV2 = serde_json::from_value(value).map_err(|e| json_error(&e))?;
    if key.entry.is_empty() {
        return Err("Key v2 must contain at least one entry".to_string());
    }
    if key.entry.len() > MAX_ENTRIES {
        return Err(format!("Key v2 has more than {MAX_ENTRIES} entries"));
    }
    let mut entries = Vec::with_capacity(key.entry.len());
    for (i, e) in key.entry.into_iter().enumerate() {
        let proto = EntryProto::from_scheme(&e.proto).ok_or_else(|| {
            format!(
                "Entry #{}: unsupported proto (expected https, socks5 or http)",
                i + 1
            )
        })?;
        let entry = build_entry(proto, &e.host, e.port, e.username, e.password, e.sni, false)
            .map_err(|err| format!("Entry #{}: {err}", i + 1))?;
        entries.push(entry);
    }
    let id = match key
        .id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(id) => {
            validate_id(&id)?;
            id
        }
        None => route_id_for_raw_key(raw_key),
    };
    let country = match key
        .country
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| !c.is_empty())
    {
        None => None,
        Some(c) if c.len() == 2 && c.chars().all(|ch| ch.is_ascii_uppercase()) => Some(c),
        Some(_) => return Err("Key country must be a 2-letter ISO code".to_string()),
    };
    let exit_ip = match key
        .exit_ip
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(s) => {
            let ip: IpAddr = s
                .parse()
                .map_err(|_| "Key exit_ip is not a valid IP address".to_string())?;
            if is_forbidden_ip(&ip) {
                return Err("Key exit_ip must be a public IP".to_string());
            }
            Some(ip.to_string())
        }
    };
    let label = clean_label(key.label, &entries[0].host)?;
    Ok(Route {
        id,
        label,
        country,
        exit_ip,
        expires_at: key.expires_at,
        entries,
        raw_key: raw_key.to_string(),
        enabled: true,
        added_at: now,
    })
}

fn parse_v1(value: serde_json::Value, raw_key: &str, now: u64) -> Result<Route, String> {
    let key: KeyV1 = serde_json::from_value(value).map_err(|e| json_error(&e))?;
    let proto = EntryProto::from_scheme(&key.protocol).ok_or_else(|| {
        "Unsupported protocol in key (expected https, socks5 or http)".to_string()
    })?;
    let entry = build_entry(
        proto,
        &key.host,
        key.port,
        key.username,
        key.password,
        None,
        false,
    )?;
    single_entry_route(entry, key.label, raw_key, now)
}

fn parse_json_key(json_str: &str, raw_key: &str, now: u64) -> Result<Route, String> {
    let value: serde_json::Value = serde_json::from_str(json_str).map_err(|e| json_error(&e))?;
    if !value.is_object() {
        return Err("Key JSON must be an object".to_string());
    }
    match value.get("v") {
        None => parse_v1(value, raw_key, now),
        Some(v) => match v.as_u64() {
            Some(SUPPORTED_KEY_VERSION) => parse_v2(value, raw_key, now),
            Some(n) => Err(format!(
                "Unsupported key version v={n}: this Zastava understands v1 and v{SUPPORTED_KEY_VERSION}, update the app"
            )),
            None => Err("Key field 'v' must be a positive integer".to_string()),
        },
    }
}

fn parse_proxy_url(
    url_str: &str,
    raw_key: &str,
    now: u64,
    allow_local: bool,
) -> Result<Route, String> {
    let trimmed = url_str.trim();
    // Support unescaped spaces or Cyrillic text in the fragment (#Label)
    let (url_part, raw_fragment) = match trimmed.split_once('#') {
        Some((u, f)) => (u.trim(), Some(f.trim())),
        None => (trimmed, None),
    };

    let scheme = url_part.split_once("://").map(|(s, _)| s).unwrap_or("");
    let proto = EntryProto::from_scheme(scheme).ok_or_else(|| {
        "Unsupported key format: expected zastava://, socks5://, socks5h://, http:// or https://".to_string()
    })?;

    // url::ParseError does not echo the input, so no credentials leak through it.
    let parsed = Url::parse(url_part).map_err(|e| format!("Invalid proxy URL: {e}"))?;
    if !matches!(parsed.path(), "" | "/") || parsed.query().is_some() {
        return Err("Proxy URL must not contain a path or query".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "Proxy URL is missing a host".to_string())?;
    let port = parsed.port().unwrap_or(proto.default_port());
    let username = (!parsed.username().is_empty()).then(|| percent_decode_clean(parsed.username()));
    let password = parsed.password().map(percent_decode_clean);
    let label = raw_fragment
        .filter(|f| !f.is_empty())
        .map(percent_decode_clean);

    let entry = build_entry(proto, host, port, username, password, None, allow_local)?;
    single_entry_route(entry, label, raw_key, now)
}

/// Parses and validates any supported key into a [`Route`] (enabled, `added_at = now`).
pub fn parse_route_key(input: &str, now: u64) -> Result<Route, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Key cannot be empty".to_string());
    }
    if trimmed.len() > MAX_KEY_LEN {
        return Err("Key is too long".to_string());
    }

    if let Some(rest) = trimmed.strip_prefix(ZASTAVA_SCHEME) {
        let bytes = decode_base64_flexible(rest)
            .map_err(|e| format!("Invalid zastava:// base64 payload: {e}"))?;
        let decoded = String::from_utf8(bytes)
            .map_err(|_| "zastava:// payload is not valid UTF-8".to_string())?;
        let decoded = decoded.trim();
        if decoded.starts_with('{') {
            parse_json_key(decoded, trimmed, now)
        } else {
            // A URL wrapped into zastava:// still comes from outside: public hosts only.
            parse_proxy_url(decoded, trimmed, now, false)
        }
    } else {
        // Typed by the user: the user's own local proxy is allowed.
        parse_proxy_url(trimmed, trimmed, now, true)
    }
}
