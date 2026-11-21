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
use super::parsing::{is_local_proxy_reachable, windows_proxy_override_bypasses_all};
use super::platform::{PResult, Platform, RegKind, RegValue};
use super::{
    EnableReport, os_effects_enabled, parse_gateway_port_from_pac_url, parse_windows_proxy_server,
    set_chained_proxy,
};
use std::time::Instant;

pub(super) const AUTO_CONFIG_URL: &str = "AutoConfigURL";
pub(super) const PROXY_ENABLE: &str = "ProxyEnable";
const PROXY_SERVER: &str = "ProxyServer";
const PROXY_OVERRIDE: &str = "ProxyOverride";

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

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
