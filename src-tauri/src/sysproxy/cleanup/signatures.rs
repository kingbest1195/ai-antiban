use super::super::{is_known_no_proxy_value, state};
use std::collections::BTreeMap;

/// Proxy variables that older Zastava versions wrote into `HKCU\Environment`.
const LEGACY_PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

/// Whether `value` is a Zastava gateway address (`127.0.0.1`/`localhost` on 8899, 8900 or the
/// current gateway port), with or without a scheme, trailing slash or `/proxy.pac`.
pub(crate) fn is_zastava_env_signature(value: &str, gateway_port: Option<u16>) -> bool {
    let v = value.trim();
    let v = v
        .strip_prefix("http://")
        .or_else(|| v.strip_prefix("https://"))
        .unwrap_or(v);
    let host_port = v.split('/').next().unwrap_or("");
    let Some((host, port)) = host_port.rsplit_once(':') else {
        return false;
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    let host = host.trim().to_ascii_lowercase();
    if host != "127.0.0.1" && host != "localhost" {
        return false;
    }
    port == 8899 || port == 8900 || gateway_port.is_some_and(|gp| gp > 0 && port == gp)
}

/// Whether the raw JSON text of a value (`"http://127.0.0.1:8899"`, quotes included) is a Zastava
/// gateway address by the strict parse of [`is_zastava_env_signature`]: userinfo, another host
/// (`my-localhost:8900`) or a foreign port are not. The one parse used for `settings.json`
/// cleanup and for the protection status.
pub(crate) fn is_zastava_proxy_json(raw: &str, gateway_port: Option<u16>) -> bool {
    serde_json::from_str::<String>(raw.trim())
        .is_ok_and(|v| is_zastava_env_signature(&v, gateway_port))
}

/// Whether `url` is a PAC address of Zastava's own gateway: exactly
/// `http://127.0.0.1|localhost:<our port>/proxy.pac` (8899, 8900 or the current gateway port).
/// Nothing else (another path, `https`, a query, another host or port) counts as ours.
pub(crate) fn is_zastava_pac_signature(url: &str, gateway_port: Option<u16>) -> bool {
    let Some(rest) = url.trim().strip_prefix("http://") else {
        return false;
    };
    let Some((host_port, path)) = rest.split_once('/') else {
        return false;
    };
    path == "proxy.pac" && is_zastava_env_signature(host_port, gateway_port)
}

/// Whether `value` is a locale Zastava itself wrote (`en_US.UTF-8`).
fn is_zastava_locale_value(value: &str) -> bool {
    value.trim() == "en_US.UTF-8"
}

/// Decides which user-environment values (launchd / `HKCU\Environment`) were written by an
/// older Zastava and may be deleted.
///
/// The set counts as written by Zastava only when at least one of `HTTP(S)_PROXY` / `ALL_PROXY`
/// carries the Zastava gateway signature (`127.0.0.1:8899`, `:8900`, the gateway port): this is
/// the "co-signature". Then are returned:
/// * the proxy variables that carry the signature themselves,
/// * `NO_PROXY` with a value a Zastava build wrote (old or new),
/// * `TZ` (co-signed),
/// * `LANG` / `LC_*` only when the value is `en_US.UTF-8`, the one Zastava wrote.
///
/// Otherwise nothing is: a user's own `HTTPS_PROXY=http://corp:3128`, `TZ=Europe/Berlin` or
/// `LANG=ru_RU.UTF-8` stays, even next to a signed proxy variable.
pub fn legacy_env_plan(env: &BTreeMap<String, String>) -> Vec<String> {
    legacy_env_plan_with_gateway(env, state().gateway_port())
}

/// Same as [`legacy_env_plan`] with an explicit current gateway port.
pub fn legacy_env_plan_with_gateway(
    env: &BTreeMap<String, String>,
    gateway_port: Option<u16>,
) -> Vec<String> {
    let is_proxy_var = |name: &str| {
        LEGACY_PROXY_VARS
            .iter()
            .any(|v| v.eq_ignore_ascii_case(name))
    };
    let signed = env
        .iter()
        .any(|(k, v)| is_proxy_var(k) && is_zastava_env_signature(v, gateway_port));
    if !signed {
        return Vec::new();
    }
    env.iter()
        .filter(|(k, v)| {
            let k = k.as_str();
            if is_proxy_var(k) {
                is_zastava_env_signature(v, gateway_port)
            } else if k.eq_ignore_ascii_case("NO_PROXY") {
                is_known_no_proxy_value(v)
            } else if k.eq_ignore_ascii_case("TZ") {
                true
            } else if k.eq_ignore_ascii_case("LANG") || k.to_ascii_uppercase().starts_with("LC_") {
                is_zastava_locale_value(v)
            } else {
                false
            }
        })
        .map(|(k, _)| k.clone())
        .collect()
}
