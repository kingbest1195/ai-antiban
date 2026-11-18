//! Verdict evaluation comparing measured DNS resolver country against exit country.

use super::{MEASURED_VIA, ResolverView, all_sources_tun_fake_ip};
use crate::auditor::geo_matrix::{
    CheckResult, GUIDE_OS_PRIVACY, SourceState, SourceView, UnknownReason,
};

/// The country as it is compared: upper case, `None` when it is not a country code.
pub fn normalized_country(raw: &str) -> Option<String> {
    let c = raw.trim().to_uppercase();
    (c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())).then_some(c)
}

/// " Источники показали разные адреса (A и B), но оба принадлежат {service}..." when the two
/// sources answered with different addresses of one public DNS service; empty otherwise.
pub fn same_operator_note(sources: &[SourceView], service: &str) -> String {
    let addrs: Vec<&str> = sources
        .iter()
        .filter(|s| s.state == SourceState::Answered)
        .filter_map(|s| s.addr.as_deref())
        .collect();
    match addrs.as_slice() {
        [a, b] if a != b => format!(
            " Источники показали разные адреса ({a} и {b}), но оба принадлежат {service}: это один и тот же публичный DNS."
        ),
        _ => String::new(),
    }
}

/// "DNS country = exit country" on a measured resolver.
pub fn evaluate_dns_country(view: &ResolverView, exit_country: &str) -> CheckResult {
    evaluate_dns_country_for_route(view, exit_country, false)
}

/// Evaluates whether the measured DNS resolver country aligns with `exit_country`.
///
/// When `via_zastava_key` is true, traffic to the AI provider passes over TCP CONNECT through the
/// remote Zastava key, so a non-sanctioned foreign VPN resolver country does not trigger a mismatch.
/// Pure `198.18.0.0/15` TUN Fake-IP responses return `NotApplicable` so `report.incomplete` is not inflated.
pub fn evaluate_dns_country_for_route(
    view: &ResolverView,
    exit_country: &str,
    via_zastava_key: bool,
) -> CheckResult {
    let (ip, country, public_service, sources) = match view {
        ResolverView::Located {
            ip,
            country,
            public_service,
            sources,
        } => (ip, country, public_service, sources),
        ResolverView::Unmeasured(u) => {
            if u.code == "DNS_WHOAMI_FAKE_IP" && all_sources_tun_fake_ip(&u.sources) {
                return CheckResult::unknown(
                    "DNS_COUNTRY_FAKE_IP",
                    "Сравнение страны DNS и выходного узла неприменимо: используется режим Fake-IP VPN-туннеля (198.18.0.0/15).",
                    UnknownReason::NotApplicable,
                )
                .with_sources(&u.sources);
            }
            return CheckResult::unknown(
                u.code,
                format!(
                    "Согласованность страны DNS и выходного узла не проверена: {}.",
                    u.detail
                ),
                u.reason,
            )
            .with_sources(&u.sources);
        }
    };
    if let Some(service) = public_service {
        // Not penalised and not counted: there is nothing to compare for an anycast service.
        return CheckResult::unknown(
            "DNS_COUNTRY_PUBLIC_RESOLVER",
            format!(
                "Запросы DNS идут на публичный резолвер {service} ({ip}); страна резолвера не сравнивается: это anycast-сервис. ECS и DNS-over-HTTPS в браузере или приложении могут менять картину.{}",
                same_operator_note(sources, service)
            ),
            UnknownReason::NotApplicable,
        )
        .with_measured_via(MEASURED_VIA)
        .with_sources(sources);
    }
    let Some(exit) = normalized_country(exit_country) else {
        return CheckResult::unknown(
            "DNS_COUNTRY_NO_EXIT",
            format!("Согласованность страны DNS и выходного узла не проверена: страна выхода не определена (резолвер {ip} находится в {country})."),
            UnknownReason::NoData,
        )
        .with_measured_via(MEASURED_VIA)
        .with_sources(sources);
    };
    if *country != exit {
        if via_zastava_key && !crate::sanctions::is_sanctioned_or_blocked_country(country) {
            return CheckResult::ok(
                "DNS_KEY_COUNTRY_ISOLATED",
                format!(
                    "DNS-резолвер {ip} ({country}) работает через системный VPN, а трафик AI изолирован через ВПН Заставы ({exit}) по TCP CONNECT."
                ),
            )
            .with_measured_via(MEASURED_VIA)
            .with_sources(sources);
        }
        return CheckResult::warning(
            "DNS_COUNTRY_SPLIT",
            format!(
                "DNS-запросы видит резолвер {ip} в {country}, а выходной IP находится в {exit}: возможна утечка DNS мимо туннеля. Страна резолвера определена по его адресу, у публичных anycast-резолверов (1.1.1.1, 8.8.8.8) она бывает неточной; ECS и DNS-over-HTTPS в браузере могут менять картину."
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        )
        .with_measured_via(MEASURED_VIA)
        .with_sources(sources);
    }
    CheckResult::ok(
        "DNS_COUNTRY_CONSISTENT",
        format!(
            "DNS-запросы видит резолвер {ip} в {country}, страна совпадает со страной выхода ({exit}). Определено по двум публичным whoami-источникам (Akamai, Google); резолвер с ECS и DNS-over-HTTPS в браузере или приложении эту картину могут менять."
        ),
    )
    .with_measured_via(MEASURED_VIA)
    .with_sources(sources)
}
