use super::super::journal::{Journal, Resource};
use super::super::parsing::{format_proxy_url, is_local_proxy_reachable};
use super::super::platform::{
    ChainState, Platform, PlatformError, ProxyEndpoint, ServiceId, ServiceKind, classify_services,
};
use super::super::{
    is_gateway_target, os_effects_enabled, parse_gateway_port_from_pac_url, set_chained_proxy,
};
use super::{
    HealGuard, MSG_ADMIN_AUTH_REQUIRED, MSG_KIND_UNKNOWN, MSG_ONLY_VPN, vpn_untouched_line,
};
use std::sync::Mutex;
use std::time::Instant;

fn msg_incompatible_service(service: &str) -> String {
    format!(
        "Защита не включена: прокси на сетевой службе «{service}» нельзя безопасно объединить с \
Заставой (разные HTTP- и HTTPS-серверы либо прокси с авторизацией). Системные настройки не \
менялись. Отключите этот прокси или используйте один адрес для HTTP и HTTPS."
    )
}

pub(super) const MSG_INCOMPATIBLE_ACROSS: &str = "Защита не включена: на разных сетевых службах настроены \
разные прокси-серверы, и Застава не может объединить их в одну цепочку. Системные настройки не \
менялись. Оставьте прокси только на одной службе или используйте один адрес.";

pub(super) const MSG_ALL_HEAL_SUSPENDED_PREFIX: &str =
    "Защита системного прокси на macOS приостановлена:";

/// An enabled, non-Zastava explicit proxy on a service.
pub(super) struct Upstream {
    /// `host:port` for the chained PAC.
    target: String,
    /// What the service holds after the explicit proxy is switched off (everything else kept).
    pub(super) chain_off: ChainState,
}

enum Detect {
    None,
    Found(Upstream),
    Incompatible,
}

fn endpoint_target_any_state(
    ep: &ProxyEndpoint,
    gateway_port: Option<u16>,
) -> Option<(String, u16)> {
    let server = ep.server.as_deref().filter(|s| !s.is_empty())?;
    let port = ep.port.filter(|p| *p > 0)?;
    if is_gateway_target(server, port, gateway_port) {
        return None;
    }
    Some((server.to_string(), port))
}

fn endpoint_target(ep: &ProxyEndpoint, gateway_port: Option<u16>) -> Option<(String, u16)> {
    if ep.enabled != Some(true) {
        return None;
    }
    endpoint_target_any_state(ep, gateway_port)
}

/// Looks at the explicit HTTP / HTTPS / SOCKS proxy of one service. Different HTTP and HTTPS
/// upstreams are never flattened into one: they are refused. So is an upstream that needs
/// credentials. When only SOCKS is enabled (`-getsocksfirewallproxy`), preserves `socks5://`.
fn detect_upstream(chain: &ChainState, gateway_port: Option<u16>) -> Detect {
    let http = endpoint_target(&chain.http, gateway_port);
    let https = endpoint_target(&chain.https, gateway_port);
    let socks = endpoint_target(&chain.socks, gateway_port);

    let (scheme, target) = match (&http, &https, &socks) {
        (None, None, None) => return Detect::None,
        (Some(a), Some(b), _) if a != b => return Detect::Incompatible,
        (Some(a), _, _) | (_, Some(a), _) => ("http", a.clone()),
        (None, None, Some(s)) => ("socks5", s.clone()),
    };
    let needs_login = (http.is_some() && chain.http.authenticated == Some(true))
        || (https.is_some() && chain.https.authenticated == Some(true))
        || (socks.is_some() && chain.socks.authenticated == Some(true));
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
    if socks.is_some() {
        off.socks.enabled = Some(false);
    }
    Detect::Found(Upstream {
        target: format_proxy_url(scheme, &target.0, target.1),
        chain_off: off,
    })
}

/// Reconstructs the chained proxy target when Zastava already turned off the service's explicit
/// proxy in an earlier pass (`Resource::Chain` is in the journal) and checks whether a local
/// loopback proxy is still listening.
fn detect_journaled_upstream(chain: &ChainState, gateway_port: Option<u16>) -> Option<String> {
    let target = endpoint_target_any_state(&chain.http, gateway_port)
        .or_else(|| endpoint_target_any_state(&chain.https, gateway_port))
        .map(|(h, p)| format_proxy_url("http", &h, p))
        .or_else(|| {
            endpoint_target_any_state(&chain.socks, gateway_port)
                .map(|(h, p)| format_proxy_url("socks5", &h, p))
        })?;
    if os_effects_enabled() && !is_local_proxy_reachable(&target) {
        return None;
    }
    Some(target)
}

/// Read-only inspection of physical services when OS PAC writes are deferred (`os_pac_deferred`),
/// keeping `chained_proxy` accurate as external proxies appear or disappear.
fn inspect_chained_readonly(
    p: &dyn Platform,
    physical: &[ServiceId],
    gateway_port: Option<u16>,
    journal: Option<&Journal>,
) -> Option<String> {
    let mut chosen: Option<String> = None;
    let mut journaled: Option<String> = None;
    for svc in physical {
        let Ok(chain) = p.get_chain(svc) else {
            continue;
        };
        match detect_upstream(&chain, gateway_port) {
            Detect::Found(u) => {
                if chosen.is_none() {
                    chosen = Some(u.target);
                }
            }
            Detect::None => {
                if journaled.is_none()
                    && journal.is_some_and(|j| {
                        j.entry(&Resource::Chain {
                            service: svc.clone(),
                        })
                        .is_some()
                    })
                {
                    journaled = detect_journaled_upstream(&chain, gateway_port);
                }
            }
            Detect::Incompatible => return None,
        }
    }
    let resolved = chosen.or(journaled);
    set_chained_proxy(resolved.clone());
    resolved
}

pub(super) struct Plan {
    pub(super) svc: ServiceId,
    pub(super) upstream: Option<Upstream>,
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

pub(super) struct PlannedPac {
    pub(super) plans: Vec<Plan>,
    pub(super) vpn_untouched: Vec<String>,
    pub(super) suspended_services: Vec<String>,
    pub(super) unreadable: usize,
    pub(super) chain_admin_auth: bool,
    pub(super) os_pac_deferred: bool,
    pub(super) os_pac_defer_reason: Option<String>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) upstream_proxy: Option<String>,
}

fn split_services_by_kind(
    p: &dyn Platform,
    enabled: &[ServiceId],
) -> (Vec<ServiceId>, Vec<String>, bool) {
    // Only physical services are written (or even read for a write). A VPN service, connected or
    // not, is left alone: the system reconfigures it on any write and a connected tunnel can drop.
    let mut physical = Vec::new();
    let mut vpn_untouched = Vec::new();
    let mut unclassified = false;
    for (svc, kind) in classify_services(p, enabled) {
        match kind {
            ServiceKind::Physical => physical.push(svc),
            ServiceKind::Vpn { connected: false } => {}
            ServiceKind::Vpn { connected: true } => vpn_untouched.push(svc.name),
            ServiceKind::Unknown => {
                unclassified = true;
                vpn_untouched.push(svc.name);
            }
        }
    }
    (physical, vpn_untouched, unclassified)
}

pub(super) fn plan_physical_pac(
    p: &dyn Platform,
    pac_url: &str,
    heal: Option<(&HealGuard, Instant)>,
    journal: Option<&Journal>,
) -> Result<PlannedPac, String> {
    let gateway_port = parse_gateway_port_from_pac_url(pac_url);
    let defer_reason = match p.temp_dns_overrides() {
        Ok(false) => None,
        Ok(true) => Some("temp_dns_overrides=true".to_string()),
        Err(e) => Some(format!("temp_dns_overrides error: {e}")),
    };
    if let Some(reason) = defer_reason {
        let (physical, vpn_untouched) = p
            .list_services()
            .ok()
            .map(|all| {
                let enabled: Vec<ServiceId> = all.into_iter().filter(|s| s.enabled).collect();
                let (phys, vpn, _) = split_services_by_kind(p, &enabled);
                (phys, vpn)
            })
            .unwrap_or_default();
        let upstream_proxy = inspect_chained_readonly(p, &physical, gateway_port, journal);
        note_untouched_vpn(&vpn_untouched);
        return Ok(PlannedPac {
            plans: Vec::new(),
            vpn_untouched,
            suspended_services: Vec::new(),
            unreadable: 0,
            chain_admin_auth: false,
            os_pac_deferred: true,
            os_pac_defer_reason: Some(reason),
            upstream_proxy,
        });
    }
    let enabled: Vec<ServiceId> = p
        .list_services()
        .map_err(|e| {
            crate::diagnostics::record("sysproxy:macos", &format!("list_services failed: {e}"));
            "Не удалось получить список сетевых служб.".to_string()
        })?
        .into_iter()
        .filter(|s| s.enabled)
        .collect();
    let (mut services, vpn_untouched, unclassified) = split_services_by_kind(p, &enabled);
    note_untouched_vpn(&vpn_untouched);
    let had_physical = !services.is_empty();
    let mut suspended_services: Vec<String> = Vec::new();
    if let Some((guard, now)) = heal {
        let mut fingerprint: Vec<String> = services
            .iter()
            .map(|s| format!("svc:{}", s.key()))
            .collect();
        for name in &vpn_untouched {
            fingerprint.push(format!("vpn:{name}"));
        }
        guard.network(fingerprint);
        services.retain(|s| {
            if guard.is_suspended_at(&s.key(), now) {
                suspended_services.push(s.name.clone());
                false
            } else {
                true
            }
        });
    }
    if services.is_empty() && !enabled.is_empty() {
        if had_physical && !suspended_services.is_empty() {
            return Err(format!(
                "{MSG_ALL_HEAL_SUSPENDED_PREFIX} внешнее приложение постоянно переписывает настройки ({}).",
                suspended_services.join(", ")
            ));
        }
        crate::diagnostics::record(
            "sysproxy:macos",
            &format!(
                "no physical services (enabled={}, unclassified={unclassified}, untouched={})",
                enabled.len(),
                vpn_untouched.join(",")
            ),
        );
        return Err(if unclassified {
            MSG_KIND_UNKNOWN
        } else {
            MSG_ONLY_VPN
        }
        .to_string());
    }

    // Phase 1: read and validate everything. Nothing is written yet.
    let mut plans: Vec<Plan> = Vec::new();
    let mut unreadable = 0usize;
    let mut chain_admin_auth = false;
    let mut journaled_fallback: Option<String> = None;
    for svc in services {
        let chain = match p.get_chain(&svc) {
            Ok(c) => c,
            Err(e) => {
                unreadable += 1;
                if matches!(e, PlatformError::AdminAuthRequired(_)) {
                    chain_admin_auth = true;
                }
                crate::diagnostics::record(
                    "sysproxy:macos",
                    &format!("get_chain failed for {} ({}): {e}", svc.name, svc.key()),
                );
                continue;
            }
        };
        let upstream = match detect_upstream(&chain, gateway_port) {
            Detect::None => {
                if journaled_fallback.is_none()
                    && journal.is_some_and(|j| {
                        j.entry(&Resource::Chain {
                            service: svc.clone(),
                        })
                        .is_some()
                    })
                {
                    journaled_fallback = detect_journaled_upstream(&chain, gateway_port);
                }
                None
            }
            Detect::Found(u) => Some(u),
            Detect::Incompatible => {
                crate::diagnostics::record(
                    "sysproxy:macos",
                    &format!("incompatible explicit proxy on service={}", svc.name),
                );
                return Err(msg_incompatible_service(&svc.name));
            }
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
        if chain_admin_auth {
            return Err(MSG_ADMIN_AUTH_REQUIRED.to_string());
        }
        return Err("Не удалось прочитать настройки сетевых служб.".to_string());
    }
    // Always sync `chained_proxy`: set the newly discovered upstream, keep a still-alive
    // journaled upstream, or explicitly clear to `None` when no upstream proxy exists.
    let resolved_chained = chosen.map(str::to_string).or(journaled_fallback);
    set_chained_proxy(resolved_chained.clone());
    Ok(PlannedPac {
        plans,
        vpn_untouched,
        suspended_services,
        unreadable,
        chain_admin_auth,
        os_pac_deferred: false,
        os_pac_defer_reason: None,
        upstream_proxy: resolved_chained,
    })
}
