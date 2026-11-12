//! System PAC and the chained upstream proxy of every network service (macOS).
//!
//! Everything goes through the ownership journal and `Platform`: before a service's PAC or
//! explicit proxy is touched, its exact previous state is recorded durably; the restore puts back
//! only what Zastava itself wrote. The logic is platform-neutral (it only talks to `Platform`),
//! so it is tested with `FakePlatform` on every OS; `RealPlatform` implements `networksetup`.

use super::journal::{ApplyOutcome, EntryState, Journal, Resource, Value};
use super::platform::{
    ChainState, PacState, Platform, ProxyEndpoint, ServiceId, ServiceKind, classify_services,
};
use super::{EnableReport, is_gateway_target, parse_gateway_port_from_pac_url, set_chained_proxy};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

/// Shown when every enabled network service is a VPN: nothing is written into those.
pub(super) const MSG_ONLY_VPN: &str = "Защита не включена: все активные сетевые службы - VPN, а \
Застава не меняет настройки VPN-служб (подключённый VPN мог бы разорваться). Включите Wi-Fi или \
Ethernet либо настройте системный прокси в самом VPN-клиенте. Системные настройки не менялись.";

/// The type of the services could not be established, so nothing is written (a VPN service could
/// be among them).
pub(super) const MSG_KIND_UNKNOWN: &str = "Защита не включена: не удалось определить тип сетевых \
служб (список VPN-подключений недоступен), а менять VPN-службы нельзя. Системные настройки не \
менялись.";

/// How far back a foreign rewrite still counts for the self-heal.
pub(super) const HEAL_WINDOW: Duration = Duration::from_secs(120);
/// Foreign rewrites of one service within [`HEAL_WINDOW`] after which the self-heal leaves it.
pub(super) const HEAL_MAX_REWRITES: usize = 3;

/// Keeps the self-heal from fighting a VPN client (or any tool) that keeps rewriting the PAC of a
/// service: after [`HEAL_MAX_REWRITES`] foreign rewrites within [`HEAL_WINDOW`] that service is
/// left alone until the set of services changes or the protection is switched on again.
pub(super) struct HealGuard {
    st: Mutex<HealState>,
}

struct HealState {
    seen: BTreeMap<String, Vec<Instant>>,
    suspended: BTreeSet<String>,
    /// Keys of the services the last pass looked at: a change means another network.
    fingerprint: Vec<String>,
}

impl HealGuard {
    pub(super) const fn new() -> Self {
        Self {
            st: Mutex::new(HealState {
                seen: BTreeMap::new(),
                suspended: BTreeSet::new(),
                fingerprint: Vec::new(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HealState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Forgets everything (the protection was switched on explicitly).
    pub(super) fn reset(&self) {
        let mut st = self.lock();
        st.seen.clear();
        st.suspended.clear();
        st.fingerprint.clear();
    }

    fn is_suspended(&self, key: &str) -> bool {
        self.lock().suspended.contains(key)
    }

    /// A different set of services is another network: start over.
    fn network(&self, fingerprint: Vec<String>) {
        let mut st = self.lock();
        if st.fingerprint != fingerprint {
            st.seen.clear();
            st.suspended.clear();
            st.fingerprint = fingerprint;
        }
    }

    /// Records a foreign rewrite; `true` when this one makes the service suspended.
    fn note_rewrite(&self, key: &str, now: Instant) -> bool {
        let mut st = self.lock();
        let list = st.seen.entry(key.to_string()).or_default();
        list.retain(|t| now.saturating_duration_since(*t) < HEAL_WINDOW);
        list.push(now);
        if list.len() >= HEAL_MAX_REWRITES {
            return st.suspended.insert(key.to_string());
        }
        false
    }
}

/// The last set of VPN names that was announced, so the log line is not repeated every pass.
static LAST_VPN_NOTE: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn note_untouched_vpn(names: &[String]) {
    if names.is_empty() {
        return;
    }
    let mut last = LAST_VPN_NOTE.lock().unwrap_or_else(|e| e.into_inner());
    if *last != names {
        eprintln!("Застава: {}", vpn_untouched_line(names));
        *last = names.to_vec();
    }
}

/// The one line the log and the coverage screen show when a connected VPN service was skipped.
/// Names of services only, no values.
pub(crate) fn vpn_untouched_line(names: &[String]) -> String {
    format!("VPN-службы не изменялись: {}", names.join(", "))
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
    apply_pac(j, p, pac_url, None)
}

/// The self-heal pass: the same as [`enable_pac`], but a service that something else keeps
/// rewriting is given up on (see [`HealGuard`]).
pub(super) fn refresh_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: &HealGuard,
    now: Instant,
) -> Result<EnableReport, String> {
    apply_pac(j, p, pac_url, Some((heal, now)))
}

fn apply_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: Option<(&HealGuard, Instant)>,
) -> Result<EnableReport, String> {
    match p.temp_dns_overrides() {
        Ok(false) => {}
        Ok(true) => return Err(MSG_TEMP_DNS.to_string()),
        Err(_) => return Err(MSG_DNS_UNKNOWN.to_string()),
    }
    let enabled: Vec<ServiceId> = p
        .list_services()
        .map_err(|_| "Не удалось получить список сетевых служб.".to_string())?
        .into_iter()
        .filter(|s| s.enabled)
        .collect();
    // Only physical services are written (or even read for a write). A VPN service, connected or
    // not, is left alone: the system reconfigures it on any write and a connected tunnel can drop.
    let mut services: Vec<ServiceId> = Vec::new();
    let mut vpn_untouched: Vec<String> = Vec::new();
    let mut unclassified = false;
    for (svc, kind) in classify_services(p, &enabled) {
        match kind {
            ServiceKind::Physical => services.push(svc),
            ServiceKind::Vpn { connected: false } => {}
            ServiceKind::Vpn { connected: true } => vpn_untouched.push(svc.name),
            ServiceKind::Unknown => {
                unclassified = true;
                vpn_untouched.push(svc.name);
            }
        }
    }
    note_untouched_vpn(&vpn_untouched);
    if services.is_empty() && !enabled.is_empty() {
        return Err(if unclassified {
            MSG_KIND_UNKNOWN
        } else {
            MSG_ONLY_VPN
        }
        .to_string());
    }
    if let Some((guard, _)) = heal {
        guard.network(services.iter().map(ServiceId::key).collect());
        services.retain(|s| !guard.is_suspended(&s.key()));
    }
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
    let mut report = EnableReport {
        skipped_vpn: vpn_untouched,
        ..EnableReport::default()
    };
    let mut failed = 0usize;
    for plan in &plans {
        let pac_res = Resource::Pac {
            service: plan.svc.clone(),
        };
        // A service we already had in place that needs a write again was rewritten by somebody.
        let was_in_place = j
            .entry(&pac_res)
            .is_some_and(|e| e.state == EntryState::Applied);
        match j.apply(p, &pac_res, want.clone()) {
            Ok(o) => {
                note_changed(o, &mut report.changed);
                report.configured.push(plan.svc.name.clone());
                if let Some((guard, now)) = heal
                    && was_in_place
                    && o != ApplyOutcome::Unchanged
                    && guard.note_rewrite(&plan.svc.key(), now)
                {
                    // Names only, no values.
                    eprintln!(
                        "Застава: настройки службы «{}» постоянно переписывает другое приложение; самолечение для неё остановлено до смены сети или перезапуска защиты",
                        plan.svc.name
                    );
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("Застава: {} не включён: {e}", pac_res.id());
                continue; // keep the user's explicit proxy while the PAC is not in place
            }
        }
        if let Some(u) = &plan.upstream {
            // The bypass list of this service is recorded before its explicit proxy is touched,
            // so it can be put back exactly. Services without an upstream are not touched at all.
            let bypass_res = Resource::Bypass {
                service: plan.svc.clone(),
            };
            match p.get_proxy_bypass_domains(&plan.svc) {
                Ok(list) => {
                    if let Err(e) = j.apply(p, &bypass_res, Value::Bypass(list)) {
                        eprintln!("Застава: {} не записан: {e}", bypass_res.id());
                    }
                }
                Err(_) => eprintln!("Застава: {} не прочитан", bypass_res.id()),
            }
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

    // --- WP-23: PAC off clears the URL; explicit proxy returns per service, with bypass -------

    #[test]
    fn switching_the_pac_off_also_clears_our_url() {
        let (fs, p) = setup();
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
        j.restore_all(&p);
        assert_eq!(p.pac_of(&wifi()), pac(None, Some(false)));
    }

    #[test]
    fn a_foreign_pac_url_and_its_state_come_back_as_they_were() {
        for on in [true, false] {
            let (fs, p) = setup();
            p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(on)));
            let mut j = open(&fs);
            enable_pac(&mut j, &p, PAC).unwrap();
            j.restore_all(&p);
            assert_eq!(p.pac_of(&wifi()), pac(Some("http://corp/p.pac"), Some(on)));
        }
    }

    #[test]
    fn the_explicit_proxy_returns_on_its_own_service_with_the_original_bypass_list() {
        let (fs, p) = setup();
        p.add_service(usb());
        let mut quiet = usb();
        quiet.enabled = true;
        // Wi-Fi: a third-party web proxy (enabled) with its own bypass list.
        let both = ChainState {
            http: ep(true, "127.0.0.1", 2080),
            https: ep(true, "127.0.0.1", 2080),
        };
        p.seed_chain(&wifi(), both.clone());
        p.seed_bypass(&wifi(), &["*.corp.example", "10.1.0.0/16"]);
        // USB: a proxy that is configured but off, and a bypass list the user has.
        let off = ChainState {
            http: ep(false, "old.example", 3128),
            https: ep(false, "old.example", 3128),
        };
        p.seed_chain(&usb(), off.clone());
        p.seed_bypass(&usb(), &["usb.local"]);
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(p.chain_of(&wifi()).http.enabled, Some(false));
        assert_eq!(
            j.entry(&Resource::Bypass { service: wifi() })
                .unwrap()
                .baseline,
            Value::Bypass(vec!["*.corp.example".into(), "10.1.0.0/16".into()]),
            "the baseline holds the bypass list"
        );
        assert!(
            j.entry(&Resource::Bypass { service: usb() }).is_none()
                && j.entry(&Resource::Chain { service: usb() }).is_none(),
            "the service whose proxy was off is not recorded"
        );
        p.clear_calls();
        j.restore_all(&p);
        assert_eq!(p.chain_of(&wifi()), both);
        assert_eq!(p.bypass_of(&wifi()), vec!["*.corp.example", "10.1.0.0/16"]);
        assert_eq!(p.chain_of(&usb()), off);
        assert_eq!(p.bypass_of(&usb()), vec!["usb.local"]);
        assert!(
            !p.calls()
                .iter()
                .any(|c| c.contains("set_chain") && c.contains("en5")),
            "no chain write on USB: {:?}",
            p.calls()
        );
        assert!(
            !p.calls()
                .iter()
                .any(|c| c.starts_with("set_proxy_bypass_domains:dev:en5"))
        );
    }

    #[test]
    fn a_service_zastava_did_not_touch_gets_no_call_at_all() {
        let (fs, p) = setup();
        let mut off_svc = usb();
        off_svc.enabled = false;
        p.add_service(off_svc.clone());
        p.seed_chain(
            &off_svc,
            ChainState {
                http: ep(true, "192.168.1.5", 3128),
                https: ep(true, "192.168.1.5", 3128),
            },
        );
        p.seed_bypass(&off_svc, &["x.local"]);
        p.seed_pac(&off_svc, pac(Some("http://user/p.pac"), Some(true)));
        p.seed_chain(
            &wifi(),
            ChainState {
                http: ep(true, "127.0.0.1", 2080),
                https: ep(true, "127.0.0.1", 2080),
            },
        );
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        j.restore_all(&p);
        let key = off_svc.key();
        assert!(
            !p.calls().iter().any(|c| c.contains(&key)),
            "{:?}",
            p.calls()
        );
        assert_eq!(
            p.pac_of(&off_svc),
            pac(Some("http://user/p.pac"), Some(true))
        );
    }

    #[test]
    fn a_bypass_list_the_user_changed_after_us_is_left_and_the_proxy_still_returns() {
        let (fs, p) = setup();
        let both = ChainState {
            http: ep(true, "127.0.0.1", 2080),
            https: ep(true, "127.0.0.1", 2080),
        };
        p.seed_chain(&wifi(), both.clone());
        p.seed_bypass(&wifi(), &["a.example"]);
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        p.seed_bypass(&wifi(), &["a.example", "b.example"]); // the user edits it meanwhile
        let rep = j.restore_all(&p);
        assert_eq!(
            rep.external(),
            1,
            "only the bypass list is a foreign change"
        );
        assert_eq!(p.bypass_of(&wifi()), vec!["a.example", "b.example"]);
        assert_eq!(p.chain_of(&wifi()), both);
    }

    #[test]
    fn an_unreadable_bypass_list_does_not_stop_the_chain() {
        let (fs, p) = setup();
        p.seed_chain(
            &wifi(),
            ChainState {
                http: ep(true, "127.0.0.1", 2080),
                https: ep(true, "127.0.0.1", 2080),
            },
        );
        p.fail_next(PlatOp::GetBypass);
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(p.chain_of(&wifi()).http.enabled, Some(false));
        assert!(j.entry(&Resource::Bypass { service: wifi() }).is_none());
    }

    // --- WP-28: VPN services are never written; no pointless writes; no ping-pong ------------

    fn leftover() -> PacState {
        pac(Some(PAC), Some(true))
    }
    fn touched(p: &FakePlatform, svc: &ServiceId) -> bool {
        let key = svc.key();
        p.calls().iter().any(|c| c.contains(&key))
    }

    #[test]
    fn a_connected_vpn_service_is_neither_read_nor_written() {
        let (fs, p) = setup();
        let vpn = p.add_vpn_service("Alpha VPN", true);
        p.seed_pac(&vpn, leftover());
        let mut j = open(&fs);
        let r = enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(r.configured, vec!["Wi-Fi".to_string()]);
        assert_eq!(r.skipped_vpn, vec!["Alpha VPN".to_string()]);
        assert!(!touched(&p, &vpn), "calls: {:?}", p.calls());
        assert_eq!(p.pac_of(&vpn), leftover());
        assert!(j.entry(&Resource::Pac { service: vpn }).is_none());
        assert_eq!(
            vpn_untouched_line(&r.skipped_vpn),
            "VPN-службы не изменялись: Alpha VPN"
        );
    }

    #[test]
    fn a_disconnected_vpn_service_gets_no_pac_either() {
        let (fs, p) = setup();
        let vpn = p.add_vpn_service("Alpha VPN", false);
        let mut j = open(&fs);
        let r = enable_pac(&mut j, &p, PAC).unwrap();
        assert!(r.skipped_vpn.is_empty(), "only connected ones are announced");
        assert!(!touched(&p, &vpn));
        assert_eq!(p.pac_of(&vpn), PacState::default());
    }

    #[test]
    fn a_vpn_service_never_gets_the_chain_or_bypass_either() {
        let (fs, p) = setup();
        let vpn = p.add_vpn_service("Alpha VPN", true);
        let both = ChainState {
            http: ep(true, "127.0.0.1", 2080),
            https: ep(true, "127.0.0.1", 2080),
        };
        p.seed_chain(&vpn, both.clone());
        p.seed_bypass(&vpn, &["vpn.local"]);
        p.seed_chain(&wifi(), both);
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        assert!(!touched(&p, &vpn));
        assert_eq!(p.chain_of(&vpn).http.enabled, Some(true));
        assert_eq!(p.bypass_of(&vpn), vec!["vpn.local"]);
        assert_eq!(p.chain_of(&wifi()).http.enabled, Some(false));
    }

    #[test]
    fn with_only_vpn_services_nothing_is_written_and_the_user_is_told() {
        let p = FakePlatform::new();
        let vpn = p.add_vpn_service("Alpha VPN", true);
        let mut j = open(&FakeFs::new());
        let err = enable_pac(&mut j, &p, PAC).unwrap_err();
        assert_eq!(err, MSG_ONLY_VPN);
        assert_eq!(p.os_writes(), 0);
        assert!(!touched(&p, &vpn));
        assert!(!err.contains("://"));
    }

    #[test]
    fn when_the_connection_list_is_unreadable_nothing_is_written() {
        let (fs, p) = setup();
        p.fail_next(PlatOp::VpnList);
        let mut j = open(&fs);
        // Wi-Fi has a device but cannot be vouched for: fail closed, say so.
        assert_eq!(enable_pac(&mut j, &p, PAC).unwrap_err(), MSG_KIND_UNKNOWN);
        assert_eq!(p.os_writes(), 0);
        assert!(j.is_empty());
    }

    #[test]
    fn a_service_without_a_device_is_a_vpn_even_if_scutil_does_not_list_it() {
        let (fs, p) = setup();
        let odd = ServiceId::new("", "com.example.tunnel", "Odd Tunnel");
        p.add_service(odd.clone());
        let mut j = open(&fs);
        let r = enable_pac(&mut j, &p, PAC).unwrap();
        assert_eq!(r.configured, vec!["Wi-Fi".to_string()]);
        assert!(!touched(&p, &odd));
    }

    #[test]
    fn repeated_self_heal_on_a_physical_service_writes_nothing() {
        let (fs, p) = setup();
        let vpn = p.add_vpn_service("Alpha VPN", true);
        let mut j = open(&fs);
        let guard = HealGuard::new();
        let t0 = Instant::now();
        refresh_pac(&mut j, &p, PAC, &guard, t0).unwrap();
        let writes = p.os_writes();
        for i in 1..5 {
            let r = refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(5 * i)).unwrap();
            assert!(!r.changed);
        }
        assert_eq!(p.os_writes(), writes);
        assert!(!touched(&p, &vpn));
    }

    #[test]
    fn a_vpn_client_that_keeps_rewriting_the_pac_does_not_start_a_ping_pong() {
        let (fs, p) = setup();
        let mut j = open(&fs);
        let guard = HealGuard::new();
        let t0 = Instant::now();
        refresh_pac(&mut j, &p, PAC, &guard, t0).unwrap();
        let mut healed = 0;
        for i in 1..=8u64 {
            // The VPN client puts its own PAC back, every pass.
            p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
            let before = p.os_writes();
            refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(5 * i)).unwrap();
            if p.os_writes() > before {
                healed += 1;
            }
        }
        assert_eq!(healed, HEAL_MAX_REWRITES, "healed three times, then stopped");
        assert_eq!(
            p.pac_of(&wifi()),
            pac(Some("http://vpn.example/p.pac"), Some(true)),
            "the foreign value is left as it is"
        );
        // An explicit enable starts a fresh account.
        guard.reset();
        refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(60)).unwrap();
        assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
    }

    #[test]
    fn rewrites_far_apart_are_not_a_ping_pong_and_a_new_network_resumes_the_heal() {
        let (fs, p) = setup();
        let mut j = open(&fs);
        let guard = HealGuard::new();
        let t0 = Instant::now();
        refresh_pac(&mut j, &p, PAC, &guard, t0).unwrap();
        // Rewrites a window apart: each one is healed, none ever suspends the service.
        for i in 1..=5u64 {
            p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
            refresh_pac(&mut j, &p, PAC, &guard, t0 + (HEAL_WINDOW + Duration::from_secs(1)) * i as u32)
                .unwrap();
            assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)), "pass {i}");
        }
        // Now a burst suspends it ...
        let base = t0 + HEAL_WINDOW * 10;
        for i in 0..HEAL_MAX_REWRITES as u64 {
            p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
            refresh_pac(&mut j, &p, PAC, &guard, base + Duration::from_secs(i)).unwrap();
        }
        p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
        refresh_pac(&mut j, &p, PAC, &guard, base + Duration::from_secs(10)).unwrap();
        assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some("http://vpn.example/p.pac"));
        // ... until the set of services changes (another network).
        p.add_service(usb());
        refresh_pac(&mut j, &p, PAC, &guard, base + Duration::from_secs(20)).unwrap();
        assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
    }

    #[test]
    fn a_suspended_service_does_not_stop_the_healing_of_the_others() {
        let (fs, p) = setup();
        p.add_service(usb());
        let mut j = open(&fs);
        let guard = HealGuard::new();
        let t0 = Instant::now();
        refresh_pac(&mut j, &p, PAC, &guard, t0).unwrap();
        for i in 1..=4u64 {
            p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
            refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(i)).unwrap();
        }
        // USB loses its PAC for once: it is healed although Wi-Fi is given up on.
        p.seed_pac(&usb(), pac(None, Some(false)));
        refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(10)).unwrap();
        assert_eq!(p.pac_of(&usb()), pac(Some(PAC), Some(true)));
        assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some("http://vpn.example/p.pac"));
    }

    // --- first start after 2.0.0: no "off, then on" pair on one service ------------------------

    fn start_like_the_app(fs: &FakeFs, p: &FakePlatform) -> Journal {
        let mut j = open(fs);
        crate::sysproxy::cleanup::restore_and_migrate_with(&mut j, p, true);
        enable_pac(&mut j, p, PAC).unwrap();
        j
    }

    #[test]
    fn first_start_after_2_0_0_leaves_a_physical_service_with_our_pac_untouched() {
        let (fs, p) = setup();
        p.seed_pac(&wifi(), leftover()); // what 2.0.0 left
        let j = start_like_the_app(&fs, &p);
        assert_eq!(p.os_writes(), 0, "calls: {:?}", p.calls());
        assert_eq!(p.pac_of(&wifi()), leftover());
        // The state "before Zastava" is off: that is what the restore brings back.
        let mut j = j;
        j.restore_all(&p);
        assert_eq!(p.pac_of(&wifi()), pac(None, Some(false)));
    }

    #[test]
    fn first_start_with_an_old_port_leftover_is_one_write_not_two() {
        let (fs, p) = setup();
        p.seed_pac(&wifi(), pac(Some("http://127.0.0.1:8900/proxy.pac"), Some(true)));
        start_like_the_app(&fs, &p);
        assert_eq!(p.os_writes(), 1, "calls: {:?}", p.calls());
        assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
    }

    #[test]
    fn the_cleanup_pass_without_the_start_flag_still_clears_a_physical_leftover() {
        let (fs, p) = setup();
        p.seed_pac(&wifi(), leftover());
        let mut j = open(&fs);
        crate::sysproxy::cleanup::restore_and_migrate_with(&mut j, &p, false);
        assert_eq!(p.pac_of(&wifi()), pac(None, Some(false)));
    }

    #[test]
    fn a_physical_leftover_is_not_given_a_mark_until_the_enable_pass_has_taken_it() {
        let (fs, p) = setup();
        p.seed_pac(&wifi(), leftover());
        let mut j = open(&fs);
        crate::sysproxy::cleanup::restore_and_migrate_with(&mut j, &p, true);
        assert!(!j.has_mark(crate::sysproxy::cleanup::LEGACY_MIGRATION_MARK));
        enable_pac(&mut j, &p, PAC).unwrap();
        drop(j); // the journal is locked while it is open
        // Next start: the service is in the journal, nothing is deferred, the mark is set.
        let mut next = open(&fs);
        crate::sysproxy::cleanup::restore_and_migrate_with(&mut next, &p, true);
        assert!(next.has_mark(crate::sysproxy::cleanup::LEGACY_MIGRATION_MARK));
    }

    #[test]
    fn the_owners_first_start_with_one_connected_vpn_among_six() {
        let (fs, p) = setup();
        let bridge = ServiceId::new("bridge0", "Thunderbolt Bridge", "Thunderbolt Bridge");
        let phone = ServiceId::new("en5", "iPhone USB", "iPhone USB");
        p.add_service(bridge.clone());
        p.add_service(phone.clone());
        let mut vpns = Vec::new();
        for (name, up) in [
            ("Alpha", false),
            ("Beta Proxy", false),
            ("Gamma", false),
            ("Delta Pro", true),
            ("Epsilon", false),
            ("Zeta", false),
        ] {
            vpns.push((p.add_vpn_service(name, up), up));
        }
        // 2.0.0 wrote its PAC into all nine services.
        for svc in [wifi(), bridge.clone(), phone.clone()] {
            p.seed_pac(&svc, leftover());
        }
        for (svc, _) in &vpns {
            p.seed_pac(svc, leftover());
        }
        start_like_the_app(&fs, &p);
        // Physical services: our PAC stays, no write. Connected VPN: not touched at all.
        for svc in [wifi(), bridge, phone] {
            assert_eq!(p.pac_of(&svc), leftover());
        }
        for (svc, up) in &vpns {
            if *up {
                assert!(!touched(&p, svc), "a connected VPN was touched");
                assert_eq!(p.pac_of(svc), leftover());
            } else {
                // The one-time cleanup of 2.0.0's leftover: one write, only while disconnected.
                assert_eq!(p.pac_of(svc), pac(None, Some(false)));
            }
        }
        assert_eq!(p.os_writes(), 5, "five idle VPN services, one clear each");
    }
}
