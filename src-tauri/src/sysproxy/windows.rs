//! WinINet system proxy settings of the current user (Windows): `AutoConfigURL` (the PAC) and
//! `ProxyEnable`.
//!
//! Everything goes through the ownership journal and `Platform`: the exact previous value (type
//! and data, or "no value") is recorded before the first write and only Zastava's own writes are
//! reverted. `ProxyServer` and `ProxyOverride` are never written, so they are never touched; the
//! third-party explicit proxy is chained through the PAC and survives in the registry.
//! The logic only talks to `Platform`, so it is tested with `FakePlatform` on every OS; the
//! registry access and the WinINet notification live in `RealPlatform`.

use super::journal::{ApplyOutcome, Journal, Resource, Value};
use super::platform::{PResult, Platform, RegKind, RegValue};
use super::{
    EnableReport, parse_gateway_port_from_pac_url, parse_windows_proxy_server, set_chained_proxy,
};

pub(super) const AUTO_CONFIG_URL: &str = "AutoConfigURL";
pub(super) const PROXY_ENABLE: &str = "ProxyEnable";
const PROXY_SERVER: &str = "ProxyServer";

fn inet(name: &str) -> Resource {
    Resource::Inet {
        name: name.to_string(),
    }
}

/// `ProxyEnable` is an explicit "on" when it is a non-zero DWORD.
fn is_enabled_dword(v: &Option<RegValue>) -> bool {
    matches!(v, Some(RegValue { kind: RegKind::Dword, data }) if data != "0")
}

/// Reads the third-party explicit proxy (when switched on) so the PAC can chain through it.
/// Read-only; `ProxyServer` itself is never rewritten.
fn detect_chained(p: &dyn Platform, gateway_port: Option<u16>) -> PResult<Option<String>> {
    if !is_enabled_dword(&p.get_inet(PROXY_ENABLE)?) {
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

/// Writes the PAC URL and switches the explicit proxy off so the PAC decides. Used for the first
/// enable and for self-healing; a repeated call changes nothing that is already in place.
pub(super) fn enable_inet(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
) -> Result<EnableReport, String> {
    let gateway_port = parse_gateway_port_from_pac_url(pac_url);
    let chained = detect_chained(p, gateway_port)
        .map_err(|_| "Не удалось прочитать системные настройки прокси.".to_string())?;
    // Chained before the explicit proxy is switched off, so the PAC already routes through it.
    if let Some(target) = chained {
        set_chained_proxy(Some(target));
    }

    let mut report = EnableReport::default();
    let mut note = |o: ApplyOutcome| {
        if o != ApplyOutcome::Unchanged {
            report.changed = true;
        }
    };

    // PAC first: the explicit proxy is switched off only when the PAC is in place.
    match j.apply(
        p,
        &inet(AUTO_CONFIG_URL),
        Value::Reg(Some(RegValue::sz(pac_url))),
    ) {
        Ok(o) => note(o),
        Err(e) => {
            crate::diagnostics::record(
                "sysproxy:windows",
                &format!("{} write failed: {e}", inet(AUTO_CONFIG_URL).id()),
            );
            eprintln!("Застава: {} не включён: {e}", inet(AUTO_CONFIG_URL).id());
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
    report
        .configured
        .push("Windows Internet Settings (WinINet)".to_string());
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysproxy::fs::FakeFs;
    use crate::sysproxy::journal::{Journal, Outcome, recover_with};
    use crate::sysproxy::platform::{FakePlatform, PlatOp};
    use std::path::Path;
    use std::sync::Arc;

    const DIR: &str = "/data";
    const PAC: &str = "http://127.0.0.1:8899/proxy.pac";

    fn open(fs: &FakeFs) -> Journal {
        Journal::open(Arc::new(fs.clone()), Path::new(DIR)).unwrap()
    }

    #[test]
    fn enable_and_restore_return_exact_types_and_absence() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        p.seed_inet(PROXY_SERVER, RegValue::sz("corp.example:3128"));
        let mut j = open(&fs);
        enable_inet(&mut j, &p, PAC).unwrap();
        assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz(PAC)));
        assert_eq!(p.inet_of(PROXY_ENABLE), Some(RegValue::dword(0)));
        j.restore_all(&p);
        assert_eq!(
            p.inet_of(AUTO_CONFIG_URL),
            None,
            "absent is deleted, not blanked"
        );
        assert_eq!(p.inet_of(PROXY_ENABLE), Some(RegValue::dword(1)));
        assert_eq!(
            p.inet_of(PROXY_SERVER),
            Some(RegValue::sz("corp.example:3128")),
            "ProxyServer is never rewritten"
        );
    }

    #[test]
    fn third_party_pac_url_with_expand_type_comes_back_exactly() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_inet(AUTO_CONFIG_URL, RegValue::expand_sz("%CORP%/p.pac"));
        let mut j = open(&fs);
        enable_inet(&mut j, &p, PAC).unwrap();
        j.restore_all(&p);
        assert_eq!(
            p.inet_of(AUTO_CONFIG_URL),
            Some(RegValue::expand_sz("%CORP%/p.pac"))
        );
    }

    #[test]
    fn proxy_enable_that_is_already_off_gets_no_record() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        let mut j = open(&fs);
        enable_inet(&mut j, &p, PAC).unwrap();
        assert!(j.entry(&inet(PROXY_ENABLE)).is_none());
        assert_eq!(
            p.inet_of(PROXY_ENABLE),
            None,
            "no value is not turned into 0"
        );
        p.seed_inet(PROXY_ENABLE, RegValue::dword(0));
        enable_inet(&mut j, &p, PAC).unwrap();
        assert!(j.entry(&inet(PROXY_ENABLE)).is_none());
    }

    #[test]
    fn external_pac_change_does_not_switch_off_a_foreign_proxy_enable() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        let mut j = open(&fs);
        enable_inet(&mut j, &p, PAC).unwrap();
        // The user's own PAC replaces ours; the user also turns the explicit proxy on again.
        p.seed_inet(AUTO_CONFIG_URL, RegValue::sz("http://mine/p.pac"));
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        let rep = j.restore_all(&p);
        let pac_item = rep
            .items
            .iter()
            .find(|i| i.resource == "inet:AutoConfigURL")
            .unwrap();
        assert_eq!(pac_item.outcome, Outcome::ExternalChange);
        assert_eq!(
            p.inet_of(AUTO_CONFIG_URL),
            Some(RegValue::sz("http://mine/p.pac"))
        );
        assert_eq!(
            p.inet_of(PROXY_ENABLE),
            Some(RegValue::dword(1)),
            "only our own 0 is ever reverted, the foreign 1 stays"
        );
    }

    #[test]
    fn the_two_values_are_independent() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        let mut j = open(&fs);
        enable_inet(&mut j, &p, PAC).unwrap();
        // A foreign change of ProxyEnable must not stop the PAC value from being restored.
        p.seed_inet(PROXY_ENABLE, RegValue::dword(2));
        let rep = j.restore_all(&p);
        assert_eq!(rep.restored(), 1);
        assert_eq!(rep.external(), 1);
        assert_eq!(p.inet_of(AUTO_CONFIG_URL), None);
    }

    #[test]
    fn notification_failure_keeps_the_record_and_the_restore_retries_it() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        let mut j = open(&fs);
        enable_inet(&mut j, &p, PAC).unwrap();
        // The value is restored but WinINet could not be told: the record stays for a retry.
        p.fail_next(PlatOp::NotifyInet);
        let rep = j.restore_all(&p);
        assert_eq!(rep.failed(), 1);
        assert_eq!(p.inet_of(AUTO_CONFIG_URL), None);
        assert!(!j.is_empty());
        p.clear_calls();
        let rep = j.restore_all(&p);
        assert_eq!(rep.failed(), 0);
        assert!(j.is_empty());
        assert!(
            p.calls()
                .iter()
                .any(|c| c.starts_with("notify_inet_refresh"))
        );
    }

    #[test]
    fn notification_failure_while_enabling_keeps_the_record_and_is_repeated() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        let mut j = open(&fs);
        p.fail_next(PlatOp::NotifyInet);
        enable_inet(&mut j, &p, PAC).unwrap();
        assert!(j.entry(&inet(AUTO_CONFIG_URL)).unwrap().notify_pending);
        p.clear_calls();
        let r = enable_inet(&mut j, &p, PAC).unwrap();
        assert!(!r.changed);
        assert!(!j.entry(&inet(AUTO_CONFIG_URL)).unwrap().notify_pending);
        assert!(
            p.calls()
                .iter()
                .any(|c| c.starts_with("notify_inet_refresh"))
        );
    }

    #[test]
    fn crash_between_intent_and_write_loses_nothing() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_inet(AUTO_CONFIG_URL, RegValue::sz("http://corp/p.pac"));
        {
            let mut j = open(&fs);
            p.fail_next(PlatOp::SetInet);
            assert!(enable_inet(&mut j, &p, PAC).is_err());
        }
        recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert_eq!(
            p.inet_of(AUTO_CONFIG_URL),
            Some(RegValue::sz("http://corp/p.pac"))
        );
    }

    #[test]
    fn explicit_proxy_is_detected_for_the_chain_but_never_rewritten() {
        let p = FakePlatform::new();
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        p.seed_inet(
            PROXY_SERVER,
            RegValue::sz("http=127.0.0.1:2080;https=127.0.0.1:2080"),
        );
        assert_eq!(
            detect_chained(&p, Some(8899)).unwrap().as_deref(),
            Some("127.0.0.1:2080")
        );
        p.seed_inet(PROXY_SERVER, RegValue::sz("127.0.0.1:8899"));
        assert_eq!(
            detect_chained(&p, Some(8899)).unwrap(),
            None,
            "our own gateway is no upstream"
        );
        p.seed_inet(PROXY_ENABLE, RegValue::dword(0));
        assert_eq!(detect_chained(&p, None).unwrap(), None);

        // ExpandSz ProxyServer is also recognized.
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        p.seed_inet(PROXY_SERVER, RegValue::expand_sz("127.0.0.1:10808"));
        assert_eq!(
            detect_chained(&p, Some(8899)).unwrap().as_deref(),
            Some("127.0.0.1:10808")
        );
    }

    #[test]
    fn vpn_override_on_windows_rechains_and_heals_pac_and_proxy_enable() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        let mut j = open(&fs);
        enable_inet(&mut j, &p, PAC).unwrap();
        assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz(PAC)));
        p.clear_calls();

        // A VPN client (e.g. Throne/v2rayN/Happ) blanks AutoConfigURL and sets ProxyEnable=1.
        p.seed_inet(AUTO_CONFIG_URL, RegValue::sz(""));
        p.seed_inet(PROXY_ENABLE, RegValue::dword(1));
        p.seed_inet(PROXY_SERVER, RegValue::sz("127.0.0.1:10808"));
        assert_eq!(
            detect_chained(&p, Some(8899)).unwrap().as_deref(),
            Some("127.0.0.1:10808")
        );

        let rep = enable_inet(&mut j, &p, PAC).unwrap();
        assert!(rep.changed);
        assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz(PAC)));
        assert_eq!(p.inet_of(PROXY_ENABLE), Some(RegValue::dword(0)));
        assert!(p.calls().iter().any(|c| c.starts_with("notify_inet_refresh")));

        // Clean restore brings back the VPN's empty AutoConfigURL and ProxyEnable=1 without
        // touching ProxyServer.
        j.restore_all(&p);
        assert_eq!(p.inet_of(AUTO_CONFIG_URL), Some(RegValue::sz("")));
        assert_eq!(p.inet_of(PROXY_ENABLE), Some(RegValue::dword(1)));
        assert_eq!(p.inet_of(PROXY_SERVER), Some(RegValue::sz("127.0.0.1:10808")));
    }
}
