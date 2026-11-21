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

mod proxy_url;
mod validate;

#[cfg(test)]
mod tests;

use std::net::IpAddr;

use serde::Deserialize;

use super::{Entry, EntryProto, MAX_ENTRIES, Route, route_id_for_raw_key};
use crate::proxy::server::is_forbidden_ip;
use proxy_url::parse_proxy_url;
use validate::{build_entry, clean_label, decode_base64_flexible, json_error, validate_id};

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
        return Err("Ключ v2 должен содержать хотя бы одну точку входа".to_string());
    }
    if key.entry.len() > MAX_ENTRIES {
        return Err(format!("Ключ v2 содержит более {MAX_ENTRIES} точек входа"));
    }
    let mut entries = Vec::with_capacity(key.entry.len());
    for (i, e) in key.entry.into_iter().enumerate() {
        let proto = EntryProto::from_scheme(&e.proto).ok_or_else(|| {
            format!(
                "Точка входа #{}: неподдерживаемый протокол (ожидается https, socks5 или http)",
                i + 1
            )
        })?;
        let entry = build_entry(proto, &e.host, e.port, e.username, e.password, e.sni, false)
            .map_err(|err| format!("Точка входа #{}: {err}", i + 1))?;
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
        Some(_) => {
            return Err("Поле country в ключе должно быть 2-буквенным ISO-кодом".to_string());
        }
    };
    let exit_ip = match key
        .exit_ip
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(s) => {
            let ip: IpAddr = s.parse().map_err(|_| {
                "Поле exit_ip в ключе не является корректным IP-адресом".to_string()
            })?;
            if is_forbidden_ip(&ip) {
                return Err("Поле exit_ip в ключе должно быть публичным IP-адресом".to_string());
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
        "Неподдерживаемый протокол в ключе (ожидается https, socks5 или http)".to_string()
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
        return Err("JSON ключа должен быть объектом".to_string());
    }
    match value.get("v") {
        None => parse_v1(value, raw_key, now),
        Some(v) => match v.as_u64() {
            Some(SUPPORTED_KEY_VERSION) => parse_v2(value, raw_key, now),
            Some(n) => Err(format!(
                "Неподдерживаемая версия ключа v={n}: эта версия Заставы поддерживает v1 и v{SUPPORTED_KEY_VERSION}, обновите приложение"
            )),
            None => Err("Поле 'v' в ключе должно быть положительным целым числом".to_string()),
        },
    }
}

/// Parses and validates any supported key into a [`Route`] (enabled, `added_at = now`).
pub fn parse_route_key(input: &str, now: u64) -> Result<Route, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(
            "Ключ не может быть пустым. Примеры: zastava://..., socks5://user:pass@host:1080 или host:1080:user:pass"
                .to_string(),
        );
    }
    if trimmed.len() > MAX_KEY_LEN {
        return Err("Ключ слишком длинный".to_string());
    }

    if trimmed
        .get(..ZASTAVA_SCHEME.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(ZASTAVA_SCHEME))
    {
        let rest = &trimmed[ZASTAVA_SCHEME.len()..];
        let bytes = decode_base64_flexible(rest)
            .map_err(|e| format!("Некорректный ключ zastava:// (ошибка base64): {e}"))?;
        let decoded = String::from_utf8(bytes)
            .map_err(|_| "Содержимое ключа zastava:// не является корректным UTF-8".to_string())?;
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
