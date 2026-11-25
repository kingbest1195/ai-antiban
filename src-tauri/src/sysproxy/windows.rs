//! WinINet system proxy settings of the current user (Windows): `AutoConfigURL` (the PAC) and
//! `ProxyEnable`.
//!
//! Everything goes through the ownership journal and `Platform`: the exact previous value (type
//! and data, or "no value") is recorded before the first write and only Zastava's own writes are
//! reverted. `ProxyServer` and `ProxyOverride` are never written, so they are never touched; the
//! third-party explicit proxy is chained through the PAC and survives in the registry.
//! The logic only talks to `Platform`, so it is tested with `FakePlatform` on every OS; the
//! registry access and the WinINet notification live in `RealPlatform`.

use super::journal::{ApplyOutcome, EntryState, Journal, Resource, Value};
use super::macos::HealGuard;
use super::parsing::{
    is_local_proxy_reachable, strip_proxy_scheme, windows_proxy_override_bypasses_all,
};
use super::platform::{PResult, Platform, RegKind, RegValue};
use super::{
    EnableReport, os_effects_enabled, parse_gateway_port_from_pac_url, parse_windows_proxy_server,
    set_chained_proxy,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub(super) const AUTO_CONFIG_URL: &str = "AutoConfigURL";
pub(super) const PROXY_ENABLE: &str = "ProxyEnable";
const PROXY_SERVER: &str = "ProxyServer";
const PROXY_OVERRIDE: &str = "ProxyOverride";
const LOOPBACK_PROBE_TIMEOUT: Duration = Duration::from_millis(150);

fn inet(name: &str) -> Resource {
    Resource::Inet {
        name: name.to_string(),
    }
}

/// `ProxyEnable` is an explicit "on" when it is a non-zero DWORD.
fn is_enabled_dword(v: &Option<RegValue>) -> bool {
    matches!(v, Some(RegValue { kind: RegKind::Dword, data }) if data != "0")
}

fn read_proxy_server(p: &dyn Platform, gateway_port: Option<u16>) -> PResult<Option<String>> {
    let bypass = match p.get_inet(PROXY_OVERRIDE)? {
        Some(RegValue {
            kind: RegKind::Sz | RegKind::ExpandSz,
            data,
        }) => windows_proxy_override_bypasses_all(Some(&data)),
        _ => false,
    };
    if bypass {
        return Ok(None);
    }
    Ok(match p.get_inet(PROXY_SERVER)? {
        Some(RegValue {
            kind: RegKind::Sz | RegKind::ExpandSz,
            data,
        }) => parse_windows_proxy_server(&data, gateway_port),
        _ => None,
    })
}

/// Reads the third-party explicit proxy (when switched on) so the PAC can chain through it.
/// Read-only; `ProxyServer` itself is never rewritten.
fn detect_chained(p: &dyn Platform, gateway_port: Option<u16>) -> PResult<Option<String>> {
    if !is_enabled_dword(&p.get_inet(PROXY_ENABLE)?) {
        return Ok(None);
    }
    read_proxy_server(p, gateway_port)
}

/// Computes the effective chained proxy for Windows: active `ProxyEnable=1` + `ProxyServer`, or
/// a journaled `ProxyEnable` whose `ProxyServer` is still valid and reachable. Returns `None` when
/// no external upstream exists so stale `chained_proxy` is always cleared.
fn resolve_chained_target(
    j: &Journal,
    p: &dyn Platform,
    gateway_port: Option<u16>,
) -> PResult<Option<String>> {
    if let Some(active) = detect_chained(p, gateway_port)? {
        return Ok(Some(active));
    }
    if j.entry(&inet(PROXY_ENABLE)).is_some()
        && let Some(target) = read_proxy_server(p, gateway_port)?
        && (!os_effects_enabled() || is_local_proxy_reachable(&target))
    {
        return Ok(Some(target));
    }
    Ok(None)
}

/// Writes the PAC URL and switches the explicit proxy off so the PAC decides. Used for the first
/// enable and for self-healing; a repeated call changes nothing that is already in place.
pub(super) fn enable_inet(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
) -> Result<EnableReport, String> {
    enable_inet_with_heal(j, p, pac_url, None)
}

/// Self-heal-aware Windows WinINet PAC configuration with [`HealGuard`] loop-breaking so external
/// proxy overrides (`iNCY` / `v2rayN`) do not trigger an endless 5s tug-of-war.
pub(super) fn enable_inet_with_heal(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: Option<(&HealGuard, Instant)>,
) -> Result<EnableReport, String> {
    let gateway_port = parse_gateway_port_from_pac_url(pac_url);
    let chained = resolve_chained_target(j, p, gateway_port)
        .map_err(|_| "Не удалось прочитать системные настройки прокси.".to_string())?;
    set_chained_proxy(chained.clone());

    let mut report = EnableReport::default();
    if let Some((guard, now)) = heal {
        let fp = vec![chained.unwrap_or_default()];
        guard.network(fp);
        if guard.is_suspended_at("wininet", now) {
            return Ok(report);
        }
    }

    let mut note = |o: ApplyOutcome| {
        if o != ApplyOutcome::Unchanged {
            report.changed = true;
        }
    };

    let pac_res = inet(AUTO_CONFIG_URL);
    let was_in_place = j
        .entry(&pac_res)
        .is_some_and(|e| e.state == EntryState::Applied);

    // PAC first: the explicit proxy is switched off only when the PAC is in place.
    match j.apply(p, &pac_res, Value::Reg(Some(RegValue::sz(pac_url)))) {
        Ok(o) => note(o),
        Err(e) => {
            crate::diagnostics::record(
                "sysproxy:windows",
                &format!("{} write failed: {e}", pac_res.id()),
            );
            eprintln!("Застава: {} не включён: {e}", pac_res.id());
            return Err("Не удалось включить защиту в настройках Windows.".to_string());
        }
    }

    // A value that is absent or already 0 needs no change, so it gets no record either. An
    // existing record is always kept in step (it may have been rebased onto a foreign value).
    let has_record = j.entry(&inet(PROXY_ENABLE)).is_some();
    let cur = p
        .get_inet(PROXY_ENABLE)
        .map_err(|_| "Не удалось прочитать системные настройки прокси.".to_string())?;
    if has_record || is_enabled_dword(&cur) {
        match j.apply(p, &inet(PROXY_ENABLE), Value::Reg(Some(RegValue::dword(0)))) {
            Ok(o) => note(o),
            Err(e) => {
                crate::diagnostics::record(
                    "sysproxy:windows",
                    &format!("{} write failed: {e}", inet(PROXY_ENABLE).id()),
                );
                eprintln!("Застава: {} не изменён: {e}", inet(PROXY_ENABLE).id());
            }
        }
    }

    if let Some((guard, now)) = heal
        && was_in_place
        && report.changed
        && guard.note_rewrite("wininet", now)
    {
        eprintln!(
            "Застава: настройки системного прокси Windows постоянно переписывает другое приложение; самолечение приостановлено на время ожидания"
        );
    }

    report
        .configured
        .push("Windows Internet Settings (WinINet)".to_string());
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedProxyHost {
    LoopbackV4(u16),
    LoopbackV6(u16),
    Localhost(u16),
    Remote,
}

fn parse_proxy_server_endpoint(raw: &str) -> Option<ParsedProxyHost> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (_, rest) = strip_proxy_scheme(trimmed);
    let clean = rest.trim().trim_end_matches('/');
    let clean = clean.rsplit_once('@').map_or(clean, |(_, hp)| hp);
    let (host, port_str) = clean.rsplit_once(':')?;
    let port = port_str.trim().parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    let clean_host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if clean_host.is_empty() {
        return None;
    }
    match clean_host.as_str() {
        "127.0.0.1" => Some(ParsedProxyHost::LoopbackV4(port)),
        "::1" => Some(ParsedProxyHost::LoopbackV6(port)),
        "localhost" => Some(ParsedProxyHost::Localhost(port)),
        _ => Some(ParsedProxyHost::Remote),
    }
}

fn parse_windows_proxy_server_hosts(raw: &str) -> Vec<ParsedProxyHost> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    if raw.contains('=') {
        raw.split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|part| {
                let (_, val) = part.split_once('=')?;
                parse_proxy_server_endpoint(val)
            })
            .collect()
    } else {
        parse_proxy_server_endpoint(raw).into_iter().collect()
    }
}

fn probe_loopback_addr(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, LOOPBACK_PROBE_TIMEOUT).is_ok()
}

fn is_parsed_loopback_reachable(endpoint: &ParsedProxyHost) -> bool {
    match *endpoint {
        ParsedProxyHost::LoopbackV4(port) => {
            probe_loopback_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        }
        ParsedProxyHost::LoopbackV6(port) => {
            probe_loopback_addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port))
        }
        ParsedProxyHost::Localhost(port) => {
            probe_loopback_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
                || probe_loopback_addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port))
        }
        ParsedProxyHost::Remote => true,
    }
}

/// Returns `true` when restoring a `ProxyEnable=1` baseline would point WinINet at a dead
/// loopback `ProxyServer` (all parsed endpoints are loopback and none accept a 150ms TCP
/// connect). Callers must restore `ProxyEnable=0` instead so non-AI apps are not stranded.
pub(crate) fn should_fallback_dead_loopback_proxy_enable(
    platform: &dyn Platform,
    res: &Resource,
    baseline: &Value,
    journal_proxy_server: Option<&RegValue>,
) -> bool {
    let Resource::Inet { name } = res else {
        return false;
    };
    if name != PROXY_ENABLE
        || !matches!(baseline, Value::Reg(Some(r)) if r.kind == RegKind::Dword && r.data != "0")
    {
        return false;
    }
    let proxy_server = match platform.get_inet(PROXY_SERVER) {
        Ok(Some(v)) => Some(v),
        Ok(None) => journal_proxy_server.cloned(),
        Err(_) => return false,
    };
    let Some(RegValue {
        kind: RegKind::Sz | RegKind::ExpandSz,
        data,
    }) = proxy_server
    else {
        return false;
    };
    let hosts = parse_windows_proxy_server_hosts(&data);
    if hosts.is_empty() || hosts.iter().any(|h| matches!(h, ParsedProxyHost::Remote)) {
        return false;
    }
    let mut seen: Vec<&ParsedProxyHost> = Vec::with_capacity(hosts.len());
    for h in &hosts {
        if !seen.contains(&h) {
            seen.push(h);
        }
    }
    if seen.into_iter().any(is_parsed_loopback_reachable) {
        return false;
    }
    crate::diagnostics::record(
        "sysproxy:windows",
        "ProxyEnable=1 baseline suppressed to 0: loopback ProxyServer is unreachable",
    );
    true
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
