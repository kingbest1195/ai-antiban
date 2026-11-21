//! Validation, decoding, and normalization helpers for route key parsing.

use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

use super::super::net::{is_gateway_loop, is_user_local_ip};
use super::super::{Entry, EntryProto};
use super::{MAX_CRED_LEN, MAX_HOST_LEN, MAX_ID_LEN, MAX_LABEL_LEN};
use crate::proxy::server::{is_forbidden_ip, is_internal_hostname};

/// Decodes base64 with standard or URL-safe engines, tolerating absent padding.
pub(super) fn decode_base64_flexible(input: &str) -> Result<Vec<u8>, String> {
    let clean = input.trim().trim_matches('"');
    if clean.is_empty() {
        return Err("Пустое содержимое base64 в ключе".to_string());
    }
    for engine in [&URL_SAFE_NO_PAD, &URL_SAFE, &STANDARD, &STANDARD_NO_PAD] {
        if let Ok(bytes) = engine.decode(clean) {
            return Ok(bytes);
        }
    }
    let rem = clean.len() % 4;
    if rem > 0 {
        let padded = format!("{}{}", clean, "=".repeat(4 - rem));
        for engine in [&STANDARD, &URL_SAFE] {
            if let Ok(bytes) = engine.decode(&padded) {
                return Ok(bytes);
            }
        }
    }
    Err("Не удалось декодировать base64-строку ключа".to_string())
}

/// serde errors can quote offending values (possibly a password), so only the position is kept.
pub(super) fn json_error(e: &serde_json::Error) -> String {
    let kind = match e.classify() {
        serde_json::error::Category::Io => "ошибка ввода-вывода",
        serde_json::error::Category::Syntax => "синтаксическая ошибка",
        serde_json::error::Category::Data => "отсутствующее или неверное поле",
        serde_json::error::Category::Eof => "неожиданный конец данных",
    };
    format!(
        "Некорректный JSON ключа: {kind} (строка {}, столбец {})",
        e.line(),
        e.column()
    )
}

fn has_control(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

pub(super) fn clean_label(label: Option<String>, fallback: &str) -> Result<String, String> {
    match label
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
    {
        None => Ok(fallback.chars().take(MAX_LABEL_LEN).collect()),
        Some(l) => {
            if has_control(&l) {
                return Err(
                    "Название маршрута содержит недопустимые управляющие символы".to_string(),
                );
            }
            if l.chars().count() > MAX_LABEL_LEN {
                return Err(format!(
                    "Название маршрута длиннее {MAX_LABEL_LEN} символов"
                ));
            }
            Ok(l)
        }
    }
}

pub(super) fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(format!(
            "Идентификатор ключа должен быть длиной 1..={MAX_ID_LEN} символов"
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(
            "Идентификатор ключа может содержать только латинские буквы, цифры, '-' и '_'"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_domain(h: &str) -> Result<(), String> {
    if h.len() > MAX_HOST_LEN {
        return Err("Имя хоста прокси слишком длинное".to_string());
    }
    if is_internal_hostname(h) {
        return Err(
            "Хост прокси должен быть публичным доменом, а не локальным или внутренним именем"
                .to_string(),
        );
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 {
        return Err(
            "Хост прокси должен быть полным доменом (FQDN) или публичным IP-адресом".to_string(),
        );
    }
    for label in labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err("Некорректное доменное имя сервера прокси".to_string());
        }
        // `127.1`, `2130706433`, `0x7f.1`: resolvers read these as IPv4 literals, so a text check
        // for "public host" is meaningless. (The resolved address is verified at connect time too.)
        if is_numeric_or_hex_label(label) {
            return Err("Хост прокси не должен содержать числовых или hex-меток: укажите обычный домен или IP-адрес".to_string());
        }
    }
    Ok(())
}

fn is_numeric_or_hex_label(label: &str) -> bool {
    if label.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    match label.strip_prefix("0x") {
        Some(rest) => !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()),
        None => false,
    }
}

/// Normalizes and validates an entry host: a public IP literal or a public domain name. With
/// `allow_local` (user-typed URL key) loopback / private IP literals and `localhost` are accepted.
fn validate_host(raw: &str, allow_local: bool) -> Result<String, String> {
    let h = raw
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.is_empty() {
        return Err("Хост прокси не может быть пустым".to_string());
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        if is_forbidden_ip(&ip) && !(allow_local && is_user_local_ip(&ip)) {
            return Err(if allow_local {
                "Хост прокси должен быть публичным или локальным IP-адресом (служебные, link-local и metadata-диапазоны запрещены)"
                    .to_string()
            } else {
                "Хост прокси должен быть публичным IP-адресом (локальные и зарезервированные диапазоны запрещены)"
                    .to_string()
            });
        }
        return Ok(ip.to_string());
    }
    if allow_local && h == "localhost" {
        return Ok(h);
    }
    validate_domain(&h)?;
    Ok(h)
}

fn validate_cred(
    value: Option<String>,
    what: &str,
    proto: EntryProto,
) -> Result<Option<String>, String> {
    let Some(v) = value.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let what_ru = if what == "username" {
        "Логин"
    } else {
        "Пароль"
    };
    if v.len() > MAX_CRED_LEN {
        return Err(format!("{what_ru} длиннее {MAX_CRED_LEN} байт"));
    }
    if has_control(&v) {
        return Err(format!(
            "{what_ru} содержит недопустимые управляющие символы"
        ));
    }
    if what == "username" && proto != EntryProto::Socks5 && v.contains(':') {
        return Err("Логин для HTTP(S)-прокси не должен содержать символ ':'".to_string());
    }
    Ok(Some(v))
}

pub(super) fn build_entry(
    proto: EntryProto,
    host: &str,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    sni: Option<String>,
    allow_local: bool,
) -> Result<Entry, String> {
    let host = validate_host(host, allow_local)?;
    if port == 0 {
        return Err("Порт прокси не может быть равен 0".to_string());
    }
    // A local proxy is fine, the gateway itself (a loop) is not.
    let loopback_ip = if host == "localhost" {
        Some(IpAddr::from([127, 0, 0, 1]))
    } else {
        host.parse::<IpAddr>().ok()
    };
    if loopback_ip
        .map(|ip| is_gateway_loop(&ip, port, 0))
        .unwrap_or(false)
    {
        return Err("Указанный адрес совпадает с локальным шлюзом самой Заставы".to_string());
    }
    let username = validate_cred(username, "username", proto)?;
    let password = validate_cred(password, "password", proto)?;
    if password.is_some() && username.is_none() {
        return Err("Указан пароль прокси без имени пользователя (логина)".to_string());
    }
    let sni = match sni
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(s) => {
            if proto != EntryProto::Https {
                return Err("Параметр 'sni' поддерживается только для HTTPS-прокси".to_string());
            }
            if s.parse::<IpAddr>().is_ok() {
                return Err(
                    "Параметр 'sni' должен быть доменным именем, а не IP-адресом".to_string(),
                );
            }
            validate_domain(&s).map_err(|_| {
                "Параметр 'sni' не является корректным публичным доменом".to_string()
            })?;
            Some(s)
        }
    };
    Ok(Entry {
        proto,
        host,
        port,
        username,
        password,
        sni,
    })
}

/// Percent-decoding as in RFC 3986: `+` stays `+` (this is not `application/x-www-form-urlencoded`).
pub(super) fn percent_decode_clean(input: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
