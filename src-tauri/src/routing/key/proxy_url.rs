//! Flexible proxy URL & commercial `host:port:user:pass` parser (no credentials in errors).

use super::super::{EntryProto, Route};
use super::single_entry_route;
use super::validate::{build_entry, percent_decode_clean};

const FORMAT_HINT: &str = "Неверный формат ключа или прокси. Примеры: zastava://..., socks5://user:pass@host:1080, socks5://host:1080:user:pass или host:1080:user:pass";

fn split_fragment(input: &str) -> (&str, Option<&str>) {
    let Some(hash_idx) = input.rfind('#') else {
        return (input, None);
    };
    // If `#` appears before the last `@`, it belongs to user:password, not a #Label fragment.
    if let Some(at_idx) = input.rfind('@')
        && hash_idx < at_idx
    {
        return (input, None);
    }
    let (u, f) = input.split_at(hash_idx);
    (u.trim(), Some(f[1..].trim()))
}

fn parse_port(port_str: &str) -> Result<u16, String> {
    if port_str.is_empty() || !port_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("Некорректный номер порта. {FORMAT_HINT}"));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("Номер порта вне диапазона 1–65535. {FORMAT_HINT}"))?;
    if port == 0 {
        return Err("Порт прокси не может быть равен 0.".to_string());
    }
    Ok(port)
}

fn parse_host_port(hp: &str, default_port: u16) -> Result<(&str, u16), String> {
    let trimmed = hp.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(format!("Не указан адрес сервера прокси. {FORMAT_HINT}"));
    }
    if trimmed.contains('/') || trimmed.contains('?') {
        return Err("Адрес прокси не должен содержать путь или параметры запроса.".to_string());
    }
    if let Some(inside) = trimmed.strip_prefix('[') {
        let Some((host, after)) = inside.split_once(']') else {
            return Err(format!("Незакрытая скобка IPv6-адреса. {FORMAT_HINT}"));
        };
        if host.is_empty() {
            return Err(format!("Пустой IPv6-адрес сервера. {FORMAT_HINT}"));
        }
        if after.is_empty() {
            return Ok((host, default_port));
        }
        let Some(port_str) = after.strip_prefix(':') else {
            return Err(FORMAT_HINT.to_string());
        };
        return Ok((host, parse_port(port_str)?));
    }
    if let Some((host, port_str)) = trimmed.rsplit_once(':') {
        if host.is_empty() || host.contains(':') {
            return Err(FORMAT_HINT.to_string());
        }
        return Ok((host, parse_port(port_str)?));
    }
    Ok((trimmed, default_port))
}

fn split_user_pass(creds: &str) -> (Option<String>, Option<String>) {
    if creds.is_empty() {
        return (None, None);
    }
    match creds.split_once(':') {
        Some((u, p)) => (
            (!u.is_empty()).then(|| percent_decode_clean(u)),
            Some(percent_decode_clean(p)),
        ),
        None => (Some(percent_decode_clean(creds)), None),
    }
}

struct ParsedAuthority<'a> {
    host: &'a str,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

fn parse_authority(rest: &str, default_port: u16) -> Result<ParsedAuthority<'_>, String> {
    let body = rest.trim();
    if body.is_empty() {
        return Err(FORMAT_HINT.to_string());
    }

    if let Some((left, right)) = body.rsplit_once('@') {
        if let Ok((host, port)) = parse_host_port(right, default_port) {
            let (username, password) = split_user_pass(left);
            return Ok(ParsedAuthority {
                host,
                port,
                username,
                password,
            });
        }
        if left.contains(':')
            && let Ok((host, port)) = parse_host_port(left, default_port)
        {
            let (username, password) = split_user_pass(right);
            return Ok(ParsedAuthority {
                host,
                port,
                username,
                password,
            });
        }
        return Err(FORMAT_HINT.to_string());
    }

    // No `@`: handle `[ipv6]:port[:user:pass]`, `host:port:user:pass`, `host:port`, or `host`.
    // Only strip trailing `/` when there are no `user:pass` segments after `host:port`
    // (so passwords ending with `/` are preserved intact).
    if let Some(inside) = body.strip_prefix('[') {
        if let Some((host, after)) = inside.split_once(']')
            && let Some(after_colon) = after.strip_prefix(':')
            && let Some((port_str, creds)) = after_colon.split_once(':')
        {
            let port = parse_port(port_str)?;
            let (username, password) = split_user_pass(creds);
            return Ok(ParsedAuthority {
                host,
                port,
                username,
                password,
            });
        }
        let (host, port) = parse_host_port(body, default_port)?;
        return Ok(ParsedAuthority {
            host,
            port,
            username: None,
            password: None,
        });
    }

    let parts: Vec<&str> = body.splitn(4, ':').collect();
    match parts.as_slice() {
        [host, port_str, user, pass] => {
            if host.contains('/') || host.contains('?') {
                return Err(
                    "Адрес прокси не должен содержать путь или параметры запроса.".to_string(),
                );
            }
            let port = parse_port(port_str)?;
            Ok(ParsedAuthority {
                host,
                port,
                username: (!user.is_empty()).then(|| percent_decode_clean(user)),
                password: Some(percent_decode_clean(pass)),
            })
        }
        [host, port_str, user] => {
            let port = parse_port(port_str)?;
            Ok(ParsedAuthority {
                host,
                port,
                username: (!user.is_empty()).then(|| percent_decode_clean(user)),
                password: None,
            })
        }
        _ => {
            let (host, port) = parse_host_port(body, default_port)?;
            Ok(ParsedAuthority {
                host,
                port,
                username: None,
                password: None,
            })
        }
    }
}

pub(super) fn parse_proxy_url(
    url_str: &str,
    raw_key: &str,
    now: u64,
    allow_local: bool,
) -> Result<Route, String> {
    let trimmed = url_str.trim();
    let (url_part, raw_fragment) = split_fragment(trimmed);

    let (proto, rest) = if let Some((scheme, rest)) = url_part.split_once("://") {
        let proto = EntryProto::from_scheme(scheme).ok_or_else(|| {
            format!(
                "Неподдерживаемый протокол «{scheme}». Ожидается zastava://, socks5://, socks5h://, http:// или https://. {FORMAT_HINT}"
            )
        })?;
        (proto, rest)
    } else {
        (EntryProto::Socks5, url_part)
    };

    let auth = parse_authority(rest, proto.default_port())?;
    let label = raw_fragment
        .filter(|f| !f.is_empty())
        .map(percent_decode_clean);

    let entry = build_entry(
        proto,
        auth.host,
        auth.port,
        auth.username,
        auth.password,
        None,
        allow_local,
    )?;
    single_entry_route(entry, label, raw_key, now)
}
