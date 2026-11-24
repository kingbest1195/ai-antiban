//! Isolated per-check async helpers used by [`super::evaluate`].

use std::sync::Arc;
use std::time::Duration;

use super::cache::{
    CheckCache, EXTERNAL_LIST_UNKNOWN_TTL, GEO_TTL, OS_TTL, RDNS_TTL, RESOLVER_UNKNOWN_TTL,
    UDP_TTL, WHOAMI_TTL, cached_check,
};
use super::probes::stun;
use super::probes::whoami::{self, ResolverView};
use super::rules::{DangerousAsns, ProviderMatrix};
use super::run_check::{blocking_check, run_check};
use super::{
    AuditEnv, AuditProgress, AuditProtectionContext, CheckResult, CheckStatus, NetworkResolver,
    NetworkTelemetry, ProgressSink, ProviderId, UnknownReason, check_dns_leak_with,
    evaluate_dns_resolver_for_route_with_protection, evaluate_locale_env_hygiene_with,
    evaluate_provider_geo, evaluate_reverse_dns_ptr_with_dns, evaluate_system_timezone_with_sync,
};

/// Time limit of a check that only computes (no I/O of its own).
pub(super) const CHECK_LIMIT_LOCAL: Duration = Duration::from_secs(2);
/// Time limit of a check that talks to the network or runs a child process.
pub(super) const CHECK_LIMIT_IO: Duration = Duration::from_secs(4);
/// Extended time limit for network checks routed through a Zastava key (double tunnel).
pub(super) const CHECK_LIMIT_IO_ROUTED: Duration = Duration::from_secs(10);

/// Runs a check future and reports its result to the sink (if any) when it completes.
pub(super) async fn tracked<F>(sink: &Option<ProgressSink>, index: usize, check: F) -> CheckResult
where
    F: std::future::Future<Output = CheckResult>,
{
    let result = check.await;
    if let Some(sink) = sink {
        sink(AuditProgress::Check {
            index,
            result: result.clone(),
        });
    }
    result
}

/// The DNS resolver that sees the requests of this machine (both whoami sources + its country),
/// measured once for the DNS-resolver and the DNS-country checks.
pub(super) async fn resolver_view(env: &AuditEnv, cache: &CheckCache) -> ResolverView {
    cache
        .resolver
        .get_or_compute_with_unknown_ttl(
            "whoami",
            WHOAMI_TTL,
            RESOLVER_UNKNOWN_TTL,
            |v| v.is_located(),
            whoami::measure_resolver(&*env.dns, &*env.probe, &cache.geo),
        )
        .await
}

pub(super) async fn resolve_udp_stun_country(
    answers: &[(&'static stun::StunServer, stun::ServerAnswer)],
    resolver: &NetworkResolver,
    cache: &CheckCache,
    env: &AuditEnv,
) -> Option<String> {
    let udp_v4 = answers.iter().find_map(|(_, a)| match a {
        stun::ServerAnswer::Addr(v4) => Some(*v4),
        _ => None,
    })?;
    let udp_str = udp_v4.to_string();
    if let Some(cc) = resolver.cached_direct_country(&udp_str).await {
        return Some(cc);
    }
    cache
        .geo
        .get_or_compute(
            &udp_str,
            GEO_TTL,
            |r| r.is_ok(),
            whoami::geo_of_ip(&*env.probe, std::net::IpAddr::V4(udp_v4)),
        )
        .await
        .ok()
        .map(|g| g.country)
}

pub(super) async fn run_dns_resolver_check(
    cache: Arc<CheckCache>,
    asns: Arc<DangerousAsns>,
    country: String,
    env: AuditEnv,
    via_zastava_key: bool,
    protection: AuditProtectionContext,
) -> CheckResult {
    run_check("DNS Resolver", CHECK_LIMIT_IO, async move {
        // The OS configuration is reference; the verdict is by the resolver that really
        // sees the requests.
        let os_key = format!("dns:{country}");
        let os_config = cached_check(&cache.os, &os_key, OS_TTL, async {
            let keywords = asns.russian_isp_keywords.clone();
            let cc = country.clone();
            let system = env.system.clone();
            blocking_check(move || check_dns_leak_with(&*system, &cc, &keywords)).await
        });
        let (config, view) = tokio::join!(os_config, resolver_view(&env, &cache));
        evaluate_dns_resolver_for_route_with_protection(
            config,
            &view,
            &country,
            via_zastava_key,
            protection,
        )
    })
    .await
}

pub(super) async fn run_timezone_check(
    cache: Arc<CheckCache>,
    ip_tz: Option<String>,
    synced: Option<String>,
    env: AuditEnv,
    sync_ai_tz_enabled: bool,
) -> CheckResult {
    run_check("Timezone", CHECK_LIMIT_IO, async move {
        let sys = env.system.clone();
        let (sys_tz_snap, sync_active) = tokio::task::spawn_blocking(move || {
            (
                sys.system_timezone().ok().unwrap_or_default(),
                sys.sync_ai_tz_active(),
            )
        })
        .await
        .unwrap_or_default();
        let key = format!(
            "tz:{}|{}|sys={}|en={}|act={}",
            ip_tz.as_deref().unwrap_or_default(),
            synced.as_deref().unwrap_or_default(),
            sys_tz_snap,
            sync_ai_tz_enabled,
            sync_active
        );
        cached_check(&cache.os, &key, OS_TTL, async {
            let system = env.system.clone();
            blocking_check(move || {
                evaluate_system_timezone_with_sync(
                    &*system,
                    ip_tz.as_deref(),
                    synced.as_deref(),
                    sync_ai_tz_enabled,
                )
            })
            .await
        })
        .await
    })
    .await
}

pub(super) async fn run_locale_check(
    cache: Arc<CheckCache>,
    env: AuditEnv,
    synced_tz: Option<String>,
    synced_key: String,
    sync_ai_tz_enabled: bool,
) -> CheckResult {
    run_check("Locale", CHECK_LIMIT_IO, async move {
        let sys = env.system.clone();
        let sync_active = tokio::task::spawn_blocking(move || sys.sync_ai_tz_active())
            .await
            .unwrap_or(false);
        let key = format!("locale:{synced_key}|en={sync_ai_tz_enabled}|act={sync_active}");
        cached_check(&cache.os, &key, OS_TTL, async {
            let system = env.system.clone();
            blocking_check(move || evaluate_locale_env_hygiene_with(&*system, synced_tz.as_deref()))
                .await
        })
        .await
    })
    .await
}

pub(super) async fn run_udp_stun_check(
    cache: Arc<CheckCache>,
    env: AuditEnv,
    ip: String,
    resolver: NetworkResolver,
    via_zastava_key: bool,
) -> CheckResult {
    run_check("UDP STUN", CHECK_LIMIT_IO, async move {
        let udp_key = format!("{ip}|routed={via_zastava_key}");
        cached_check(&cache.udp, &udp_key, UDP_TTL, async {
            let answers = stun::probe_servers(&*env.udp, stun::STUN_TIMEOUT).await;
            let udp_country = if via_zastava_key {
                resolve_udp_stun_country(&answers, &resolver, &cache, &env).await
            } else {
                None
            };
            stun::evaluate_udp_stun_for_route(
                &answers,
                &ip,
                via_zastava_key,
                udp_country.as_deref(),
            )
        })
        .await
    })
    .await
}

pub(super) async fn run_reverse_dns_check(
    cache: Arc<CheckCache>,
    tel: NetworkTelemetry,
    dns: Arc<dyn super::seams::DnsLookup>,
) -> CheckResult {
    run_check("Reverse DNS", CHECK_LIMIT_IO, async move {
        let key = format!(
            "rdns:{}|{}|{}|{}",
            tel.ip.trim(),
            tel.hostname.as_deref().unwrap_or_default(),
            tel.isp.as_deref().unwrap_or_default(),
            tel.org.as_deref().unwrap_or_default()
        );
        cache
            .rdns
            .get_or_compute_with_unknown_ttl(
                &key,
                RDNS_TTL,
                EXTERNAL_LIST_UNKNOWN_TTL,
                |r| !r.is_unknown(),
                async move { evaluate_reverse_dns_ptr_with_dns(&tel, &*dns).await },
            )
            .await
    })
    .await
}

pub(super) fn evaluate_gemini_exit_from_telemetry(
    telemetry: &NetworkTelemetry,
    matrix: &ProviderMatrix,
) -> CheckResult {
    let via_label = "gemini (маршрут ключа)".to_string();
    let cc = telemetry.country_code.trim();
    if cc.is_empty() {
        return CheckResult::unknown(
            "PROVIDER_EXIT_NO_DATA",
            "Реальный выход Gemini не содержит код страны в телеметрии маршрута.",
            UnknownReason::NoData,
        )
        .with_measured_via(via_label);
    }
    let geo = evaluate_provider_geo(matrix, ProviderId::Gemini, cc);
    if geo.status == CheckStatus::Critical {
        return CheckResult::critical(
            "PROVIDER_EXIT_BLOCKED_COUNTRY",
            format!(
                "Реальный выход Gemini определён как {cc} ({}): {}",
                telemetry.ip, geo.message
            ),
            geo.guide_ref,
        )
        .with_measured_via(via_label);
    }
    if geo.status == CheckStatus::Warning {
        return CheckResult::warning(
            "PROVIDER_EXIT_GEO_WARNING",
            format!(
                "Реальный выход Gemini ({}, {cc}): {}",
                telemetry.ip, geo.message
            ),
            geo.guide_ref,
        )
        .with_measured_via(via_label);
    }
    CheckResult::ok(
        "PROVIDER_EXIT_VERIFIED",
        format!(
            "Реальный выход Gemini подтвержден: {} ({cc}).",
            telemetry.ip
        ),
    )
    .with_measured_via(via_label)
}

/// When `via_zastava_key` is active and the key exit itself (`geo`, `travel`, `ipv6`, `claude_exit`)
/// is verified healthy, external-list reachability failures on `dnsbl` or `tor` (e.g. RU ISP blocks
/// on `dns.google` / `check.torproject.org`) are marked `NotApplicable` so they do not downgrade
/// a verified Zastava Key setup to `incomplete` / 94. Listed/Tor/sanctioned verdicts are untouched.
#[allow(clippy::too_many_arguments)]
pub fn reconcile_key_exit_external_lists(
    via_zastava_key: bool,
    route_usable: bool,
    geo: &CheckResult,
    travel: &CheckResult,
    ipv6: &CheckResult,
    claude_exit: &CheckResult,
    dnsbl: &mut CheckResult,
    asn: &mut CheckResult,
) {
    if !via_zastava_key || !route_usable {
        return;
    }
    let key_exit_clean = !geo.status.is_critical()
        && !geo.is_unknown()
        && !travel.status.is_critical()
        && (!travel.is_unknown() || travel.is_not_applicable())
        && !ipv6.status.is_critical()
        && !ipv6.status.is_warning()
        && !ipv6.is_unknown()
        && !claude_exit.status.is_critical()
        && !claude_exit.status.is_warning()
        && (!claude_exit.is_unknown() || claude_exit.is_not_applicable());
    if !key_exit_clean {
        return;
    }
    if dnsbl.is_unknown() && !dnsbl.is_not_applicable() {
        *dnsbl = CheckResult::unknown(
            "DNSBL_UNREACHABLE_KEY_OK",
            "Списки DNSBL недоступны напрямую из-за ограничений сети; выходной узел ключа Заставы проверен и исправен.",
            crate::auditor::UnknownReason::NotApplicable,
        );
    }
    if asn.is_unknown() && asn.code == "TOR_LIST_UNAVAILABLE" {
        *asn = CheckResult::unknown(
            "TOR_LIST_UNAVAILABLE",
            "Список выходных узлов Tor временно недоступен; провайдер выходного узла ключа Заставы проверен.",
            crate::auditor::UnknownReason::NotApplicable,
        );
    }
}
