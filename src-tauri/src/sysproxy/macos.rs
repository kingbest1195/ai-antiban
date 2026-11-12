//! System PAC and the chained upstream proxy of every network service (macOS).
//!
//! Everything goes through the ownership journal and `Platform`: before a service's PAC or
//! explicit proxy is touched, its exact previous state is recorded durably; the restore puts back
//! only what Zastava itself wrote. The logic is platform-neutral (it only talks to `Platform`),
//! so it is tested with `FakePlatform` on every OS; `RealPlatform` implements `networksetup`.

use super::journal::{ApplyOutcome, Journal, Resource, Value};
use super::platform::{ChainState, PacState, Platform, ProxyEndpoint, ServiceId};
use super::{EnableReport, is_gateway_target, parse_gateway_port_from_pac_url, set_chained_proxy};

/// Shown when an active VPN keeps temporary DNS settings: applying proxy settings could reset
/// them. Contains no DNS values.
pub(super) const MSG_TEMP_DNS: &str = "Защита не включена: активный VPN держит временные настройки DNS, \
и их применение могло бы сбросить DNS этого VPN. Отключите VPN (или подключите его заново \
после включения защиты) и повторите.";

/// The DNS state could not be checked, so nothing is written.
pub(super) const MSG_DNS_UNKNOWN: &str = "Защита не включена: не удалось проверить временные \
настройки DNS активного VPN. Системные настройки не менялись.";

fn msg_incompatible_service(service: &str) -> String {
    format!(
        "Защита не включена: прокси на сетевой службе «{service}» нельзя безопасно объединить с \
Заставой (разные HTTP- и HTTPS-серверы либо прокси с авторизацией). Системные настройки не \
менялись. Отключите этот прокси или используйте один адрес для HTTP и HTTPS."
    )
}

const MSG_INCOMPATIBLE_ACROSS: &str = "Защита не включена: на разных сетевых службах настроены \
разные прокси-серверы, и Застава не может объединить их в одну цепочку. Системные настройки не \
менялись. Оставьте прокси только на одной службе или используйте один адрес.";

/// An enabled, non-Zastava explicit proxy on a service.
struct Upstream {
    /// `host:port` for the chained PAC.
    target: String,
    /// What the service holds after the explicit proxy is switched off (everything else kept).
    chain_off: ChainState,
}

enum Detect {
    None,
    Found(Upstream),
    Incompatible,
}

fn endpoint_target(ep: &ProxyEndpoint, gateway_port: Option<u16>) -> Option<(String, u16)> {
    if ep.enabled != Some(true) {
        return None;
    }
    let server = ep.server.as_deref().filter(|s| !s.is_empty())?;
    let port = ep.port.filter(|p| *p > 0)?;
    if is_gateway_target(server, port, gateway_port) {
        return None;
    }
    Some((server.to_string(), port))
}

/// Looks at the explicit HTTP / HTTPS proxy of one service. Different HTTP and HTTPS upstreams
/// are never flattened into one: they are refused. So is an upstream that needs credentials.
fn detect_upstream(chain: &ChainState, gateway_port: Option<u16>) -> Detect {
    let http = endpoint_target(&chain.http, gateway_port);
    let https = endpoint_target(&chain.https, gateway_port);
    let target = match (&http, &https) {
        (None, None) => return Detect::None,
        (Some(a), Some(b)) if a != b => return Detect::Incompatible,
        (Some(a), _) | (_, Some(a)) => a.clone(),
    };
    let needs_login = (http.is_some() && chain.http.authenticated == Some(true))
        || (https.is_some() && chain.https.authenticated == Some(true));
    if needs_login {
        return Detect::Incompatible;
    }
    let mut off = chain.clone();
    if http.is_some() {
        off.http.enabled = Some(false);
    }
    if https.is_some() {
        off.https.enabled = Some(false);
    }
    Detect::Found(Upstream {
        target: format!("{}:{}", target.0, target.1),
        chain_off: off,
    })
}

struct Plan {
    svc: ServiceId,
    upstream: Option<Upstream>,
}

fn note_changed(outcome: ApplyOutcome, changed: &mut bool) {
    if outcome != ApplyOutcome::Unchanged {
        *changed = true;
    }
}

/// Puts the PAC on every enabled network service and switches a third-party explicit proxy off
/// (it is chained through the PAC instead). Used for the first enable and for self-healing: a
/// repeated call changes nothing that already is as it should be.
///
/// Refuses before ANY write when a VPN keeps temporary DNS settings or when an upstream cannot be
/// chained safely. Disabled services are not touched; services that appeared since the last
/// call are picked up.
pub(super) fn enable_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
) -> Result<EnableReport, String> {
    match p.temp_dns_overrides() {
        Ok(false) => {}
        Ok(true) => return Err(MSG_TEMP_DNS.to_string()),
        Err(_) => return Err(MSG_DNS_UNKNOWN.to_string()),
    }
    let services: Vec<ServiceId> = p
        .list_services()
        .map_err(|_| "Не удалось получить список сетевых служб.".to_string())?
        .into_iter()
        .filter(|s| s.enabled)
        .collect();
    let gateway_port = parse_gateway_port_from_pac_url(pac_url);

    // Phase 1: read and validate everything. Nothing is written yet.
    let mut plans: Vec<Plan> = Vec::new();
    let mut unreadable = 0usize;
    for svc in services {
        let chain = match p.get_chain(&svc) {
            Ok(c) => c,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let upstream = match detect_upstream(&chain, gateway_port) {
            Detect::None => None,
            Detect::Found(u) => Some(u),
            Detect::Incompatible => return Err(msg_incompatible_service(&svc.name)),
        };
        plans.push(Plan { svc, upstream });
    }
    let mut chosen: Option<&str> = None;
    for plan in &plans {
        if let Some(u) = &plan.upstream {
            match chosen {
                None => chosen = Some(&u.target),
                Some(t) if t != u.target => return Err(MSG_INCOMPATIBLE_ACROSS.to_string()),
                Some(_) => {}
            }
        }
    }
    if plans.is_empty() && unreadable > 0 {
        return Err("Не удалось прочитать настройки сетевых служб.".to_string());
    }
    // The PAC served by the gateway must chain through the upstream before it is switched off.
    // Without a new finding the in-memory value stays: the explicit proxy is already off.
    if let Some(target) = chosen {
        set_chained_proxy(Some(target.to_string()));
    }

    // Phase 2: write, service by service; one failure does not stop the others.
    let want = Value::Pac(PacState {
        url: Some(pac_url.to_string()),
        enabled: Some(true),
    });
    let mut report = EnableReport::default();
    let mut failed = 0usize;
    for plan in &plans {
        let pac_res = Resource::Pac {
            service: plan.svc.clone(),
        };
        match j.apply(p, &pac_res, want.clone()) {
            Ok(o) => {
                note_changed(o, &mut report.changed);
                report.configured.push(plan.svc.name.clone());
            }
            Err(e) => {
                failed += 1;
                eprintln!("Застава: {} не включён: {e}", pac_res.id());
                continue; // keep the user's explicit proxy while the PAC is not in place
            }
        }
        if let Some(u) = &plan.upstream {
            let chain_res = Resource::Chain {
                service: plan.svc.clone(),
            };
            match j.apply(p, &chain_res, Value::Chain(u.chain_off.clone())) {
                Ok(o) => note_changed(o, &mut report.changed),
                Err(e) => eprintln!("Застава: {} не изменён: {e}", chain_res.id()),
            }
        }
    }
    if report.configured.is_empty() && (failed > 0 || unreadable > 0) {
        return Err("Не удалось включить защиту ни на одной сетевой службе.".to_string());
    }
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
    fn wifi() -> ServiceId {
        ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
    }
    fn usb() -> ServiceId {
        ServiceId::new("en5", "USB 10/100 LAN", "USB LAN")
    }
    fn setup() -> (FakeFs, FakePlatform) {
        let p = FakePlatform::new();
        p.add_service(wifi());
        (FakeFs::new(), p)
    }
    fn pac(url: Option<&str>, on: Option<bool>) -> PacState {
        PacState {
            url: url.map(str::to_string),
            enabled: on,
        }
    }
    fn ep(on: bool, host: &str, port: u16) -> ProxyEndpoint {
        ProxyEndpoint {
            enabled: Some(on),
            server: Some(host.into()),
            port: Some(port),
            authenticated: Some(false),
        }
    }
    fn recover(fs: &FakeFs, p: &FakePlatform) {
        recover_with(Arc::new(fs.clone()), p, Path::new(DIR)).unwrap();
    }

    #[test]
    fn enable_records_the_baseline_and_restore_brings_it_back() {
        let (fs, p) = setup();
        p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(false)));
        let mut j = open(&fs);
        let r = enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(r.configured, vec!["Wi-Fi".to_string()]);
        assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
        j.restore_all(&p);
        assert_eq!(
            p.pac_of(&wifi()),
            pac(Some("http://corp/p.pac"), Some(false))
        );
    }

    #[test]
    fn services_are_independent_and_disabled_ones_are_not_captured() {
        let (fs, p) = setup();
        let mut off = usb();
        off.enabled = false;
        p.add_service(off.clone());
        p.seed_pac(&off, pac(Some("http://user/p.pac"), Some(true)));
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        assert!(
            j.entry(&Resource::Pac {
                service: off.clone()
            })
            .is_none()
        );
        assert_eq!(
            p.pac_of(&off),
            pac(Some("http://user/p.pac"), Some(true)),
            "a disabled service is left alone"
        );
        // One failing restore does not block the other service.
        p.add_service(usb());
        enable_pac(&mut j, &p, PAC).unwrap();
        p.fail_next(PlatOp::SetPac);
        let rep = j.restore_all(&p);
        assert_eq!(rep.failed(), 1);
        assert_eq!(rep.restored(), 1);
    }

    #[test]
    fn repeated_enable_keeps_baseline_and_writes_nothing() {
        let (fs, p) = setup();
        p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(true)));
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        let writes = p.os_writes();
        let r = enable_pac(&mut j, &p, PAC).unwrap();
        assert!(!r.changed);
        assert_eq!(p.os_writes(), writes);
        assert_eq!(
            j.entry(&Resource::Pac { service: wifi() })
                .unwrap()
                .baseline,
            Value::Pac(pac(Some("http://corp/p.pac"), Some(true)))
        );
    }

    #[test]
    fn own_pac_url_update_keeps_the_original_flag_and_survives_a_crash() {
        let (fs, p) = setup();
        p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(false)));
        {
            let mut j = open(&fs);
            enable_pac(&mut j, &p, PAC).unwrap();
            // The gateway moved to another port; the update's OS write is lost to a crash.
            p.fail_next(PlatOp::SetPac);
            let _ = enable_pac(&mut j, &p, "http://127.0.0.1:9100/proxy.pac");
        }
        recover(&fs, &p);
        assert_eq!(
            p.pac_of(&wifi()),
            pac(Some("http://corp/p.pac"), Some(false))
        );
    }

    #[test]
    fn a_foreign_pac_after_us_is_adopted_as_baseline_and_not_rolled_back_later() {
        let (fs, p) = setup();
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        // A VPN client replaces the PAC after us; the self-heal puts ours back on top.
        p.seed_pac(&wifi(), pac(Some("http://vpn/p.pac"), Some(true)));
        let r = enable_pac(&mut j, &p, PAC).unwrap();
        assert!(r.changed);
        assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
        // Then the user changes it again by hand: the restore leaves that alone.
        p.seed_pac(&wifi(), pac(Some("http://mine/p.pac"), Some(true)));
        let rep = j.restore_all(&p);
        assert_eq!(rep.external(), 1);
        assert_eq!(
            p.pac_of(&wifi()),
            pac(Some("http://mine/p.pac"), Some(true))
        );
    }

    #[test]
    fn foreign_pac_flag_is_not_switched_off_when_only_the_url_changed() {
        let (fs, p) = setup();
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        // Somebody else keeps the flag on but points it at their own URL.
        p.seed_pac(&wifi(), pac(Some("http://theirs/p.pac"), Some(true)));
        let rep = j.restore_all(&p);
        assert_eq!(rep.external(), 1);
        assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
    }

    #[test]
    fn absent_key_empty_string_and_off_are_kept_apart() {
        let (fs, p) = setup();
        // Empty string with the flag key missing is different from "no URL at all".
        p.seed_pac(&wifi(), pac(Some(""), None));
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(
            j.entry(&Resource::Pac { service: wifi() })
                .unwrap()
                .baseline,
            Value::Pac(pac(Some(""), None))
        );
    }

    #[test]
    fn new_service_between_enable_and_restore_is_not_touched_and_removed_one_is_skipped() {
        let (fs, p) = setup();
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        // A service that appeared afterwards has no record, so the restore never touches it.
        p.add_service(usb());
        p.seed_pac(&usb(), pac(Some("http://other/p.pac"), Some(true)));
        // The enabled service disappears before the restore.
        p.remove_service(&wifi().key());
        let rep = j.restore_all(&p);
        assert_eq!(rep.count(|o| matches!(o, Outcome::TargetGone)), 1);
        assert_eq!(
            p.pac_of(&usb()),
            pac(Some("http://other/p.pac"), Some(true))
        );
        assert!(j.is_empty());
        // The self-heal picks the new service up.
        let r = enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(r.configured, vec!["USB LAN".to_string()]);
    }

    #[test]
    fn renamed_service_is_still_the_same_service() {
        let (fs, p) = setup();
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        p.rename_service(&wifi().key(), "Беспроводная сеть");
        let rep = j.restore_all(&p);
        assert_eq!(rep.restored(), 1);
    }

    #[test]
    fn temporary_vpn_dns_refuses_before_any_write_and_the_text_has_no_values() {
        let (fs, p) = setup();
        p.set_temp_dns(true);
        p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(true)));
        let mut j = open(&fs);
        let err = enable_pac(&mut j, &p, PAC).unwrap_err();
        assert_eq!(err, MSG_TEMP_DNS);
        assert_eq!(p.os_writes(), 0);
        assert!(j.is_empty(), "no intent either");
        assert!(!err.contains("1.1.1.1") && !err.contains("://"));
    }

    #[test]
    fn unknown_dns_state_also_refuses_before_any_write() {
        let (fs, p) = setup();
        p.fail_next(PlatOp::TempDns);
        let mut j = open(&fs);
        assert_eq!(enable_pac(&mut j, &p, PAC).unwrap_err(), MSG_DNS_UNKNOWN);
        assert_eq!(p.os_writes(), 0);
    }

    #[test]
    fn third_party_explicit_proxy_is_chained_and_returned_after_a_crash() {
        let (fs, p) = setup();
        let both = ChainState {
            http: ep(true, "127.0.0.1", 2080),
            https: ep(true, "127.0.0.1", 2080),
        };
        p.seed_chain(&wifi(), both.clone());
        {
            let mut j = open(&fs);
            enable_pac(&mut j, &p, PAC).unwrap();
            let now = p.chain_of(&wifi());
            assert_eq!(now.http.enabled, Some(false));
            assert_eq!(now.https.enabled, Some(false));
            assert_eq!(now.http.server.as_deref(), Some("127.0.0.1"));
            // "kill -9": the journal object is gone, only the file is left.
        }
        recover(&fs, &p);
        assert_eq!(p.chain_of(&wifi()), both);
        assert_eq!(p.pac_of(&wifi()).url, None);
    }

    #[test]
    fn different_http_and_https_upstreams_are_refused_before_any_write() {
        let (fs, p) = setup();
        p.seed_chain(
            &wifi(),
            ChainState {
                http: ep(true, "10.0.0.1", 1080),
                https: ep(true, "10.0.0.2", 2080),
            },
        );
        let mut j = open(&fs);
        let err = enable_pac(&mut j, &p, PAC).unwrap_err();
        assert!(err.contains("Wi-Fi") && !err.contains("10.0.0."));
        assert_eq!(p.os_writes(), 0);
        assert!(j.is_empty());
    }

    #[test]
    fn upstream_with_authentication_is_refused() {
        let (fs, p) = setup();
        let mut web = ep(true, "10.0.0.1", 1080);
        web.authenticated = Some(true);
        p.seed_chain(
            &wifi(),
            ChainState {
                http: web,
                https: ProxyEndpoint::default(),
            },
        );
        let mut j = open(&fs);
        assert!(enable_pac(&mut j, &p, PAC).is_err());
        assert_eq!(p.os_writes(), 0);
    }

    #[test]
    fn only_the_active_endpoint_is_switched_off_and_the_other_stays_as_it_was() {
        let (fs, p) = setup();
        let https_off = ep(false, "old.example", 8443);
        p.seed_chain(
            &wifi(),
            ChainState {
                http: ep(true, "127.0.0.1", 2080),
                https: https_off.clone(),
            },
        );
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        let now = p.chain_of(&wifi());
        assert_eq!(now.http.enabled, Some(false));
        assert_eq!(
            now.https, https_off,
            "the HTTPS side is not flattened or rewritten"
        );
    }

    #[test]
    fn explicit_proxy_pointing_at_our_own_gateway_is_not_a_third_party() {
        let (fs, p) = setup();
        let ours = ChainState {
            http: ep(true, "127.0.0.1", 8899),
            https: ep(true, "127.0.0.1", 8899),
        };
        p.seed_chain(&wifi(), ours.clone());
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(p.chain_of(&wifi()), ours);
        assert!(j.entry(&Resource::Chain { service: wifi() }).is_none());
    }

    #[test]
    fn different_upstreams_on_different_services_are_refused() {
        let (fs, p) = setup();
        p.add_service(usb());
        p.seed_chain(
            &wifi(),
            ChainState {
                http: ep(true, "10.0.0.1", 1080),
                https: ProxyEndpoint::default(),
            },
        );
        p.seed_chain(
            &usb(),
            ChainState {
                http: ep(true, "10.0.0.9", 1080),
                https: ProxyEndpoint::default(),
            },
        );
        let mut j = open(&fs);
        assert_eq!(
            enable_pac(&mut j, &p, PAC).unwrap_err(),
            MSG_INCOMPATIBLE_ACROSS
        );
        assert_eq!(p.os_writes(), 0);
    }

    #[test]
    fn throne_enabling_its_proxy_after_us_is_chained_by_the_self_heal() {
        let (fs, p) = setup();
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        let throne = ChainState {
            http: ep(true, "127.0.0.1", 2080),
            https: ep(true, "127.0.0.1", 2080),
        };
        p.seed_chain(&wifi(), throne.clone());
        let r = enable_pac(&mut j, &p, PAC).unwrap();
        assert!(r.changed);
        assert_eq!(p.chain_of(&wifi()).http.enabled, Some(false));
        j.restore_all(&p);
        assert_eq!(
            p.chain_of(&wifi()),
            throne,
            "their proxy comes back, not ours"
        );
    }

    #[test]
    fn a_failing_service_does_not_block_the_others_and_keeps_its_explicit_proxy() {
        let (fs, p) = setup();
        p.add_service(usb());
        p.fail_next(PlatOp::SetPac);
        let mut j = open(&fs);
        let r = enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(r.configured, vec!["USB LAN".to_string()]);
    }
}
