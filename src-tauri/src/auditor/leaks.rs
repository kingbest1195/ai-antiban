use std::time::Duration;

use crate::auditor::geo_matrix::{CheckResult, CheckStatus, GUIDE_OS_PRIVACY, UnknownReason};
use crate::auditor::probes::whoami::{
    MEASURED_VIA, ResolverView, normalized_country, same_operator_note,
};
use crate::auditor::seams::{
    HttpProbeOutcome, IpProbe, RealSystem, ReqwestProbe, SystemInfo, SystemReadError,
};

pub const IPV6_CHECK_URL: &str = "https://[2606:4700:4700::1111]/cdn-cgi/trace";
pub const IPV6_CHECK_TIMEOUT_MS: u64 = 800;

pub use crate::auditor::os_env::{
    RUSSIAN_TIMEZONES, check_os_location_services, evaluate_locale_env_hygiene,
    is_russian_or_belarusian_timezone,
};

/// Evaluates whether system timezone exposes user's actual location (backward compatible wrapper).
pub fn evaluate_system_timezone(ip_timezone: Option<&str>) -> CheckResult {
    crate::auditor::os_env::evaluate_system_timezone(ip_timezone, None)
}

/// Evaluates whether system timezone exposes user's actual location with AI agent synced timezone check.
pub fn evaluate_system_timezone_with_synced(
    ip_timezone: Option<&str>,
    synced_ai_tz: Option<&str>,
) -> CheckResult {
    crate::auditor::os_env::evaluate_system_timezone(ip_timezone, synced_ai_tz)
}

/// Checks for dual-stack IPv6 leaks by pinging Cloudflare IPv6-only CDN trace endpoint.
pub async fn check_ipv6_leak(ipv4_country: &str, global_blocked: &[String]) -> CheckResult {
    check_ipv6_leak_split(ipv4_country, global_blocked, false).await
}

/// Checks for dual-stack IPv6 leaks; in `split_tunnel_mode` an active host IPv6 stack is reported
/// as informational `Ok` instead of blocking/warning on direct-OS IPv6 mismatch.
pub async fn check_ipv6_leak_split(
    ipv4_country: &str,
    global_blocked: &[String],
    split_tunnel_mode: bool,
) -> CheckResult {
    check_ipv6_leak_with_split(
        &ReqwestProbe,
        &RealSystem,
        IPV6_CHECK_URL,
        Duration::from_millis(IPV6_CHECK_TIMEOUT_MS),
        ipv4_country,
        global_blocked,
        split_tunnel_mode,
    )
    .await
}

/// [`check_ipv6_leak`] through `probe` / `system` (injectable for tests).
/// A host without a global IPv6 address cannot leak over IPv6; a probe that did not produce a
/// usable answer is `Unknown`, never "no leak".
pub async fn check_ipv6_leak_with(
    probe: &dyn IpProbe,
    system: &dyn SystemInfo,
    url: &str,
    limit: Duration,
    ipv4_country: &str,
    global_blocked: &[String],
) -> CheckResult {
    check_ipv6_leak_with_split(
        probe,
        system,
        url,
        limit,
        ipv4_country,
        global_blocked,
        false,
    )
    .await
}

/// Testable [`check_ipv6_leak_split`] implementation.
pub async fn check_ipv6_leak_with_split(
    probe: &dyn IpProbe,
    system: &dyn SystemInfo,
    url: &str,
    limit: Duration,
    ipv4_country: &str,
    global_blocked: &[String],
    split_tunnel_mode: bool,
) -> CheckResult {
    check_ipv6_leak_with_route(
        probe,
        system,
        url,
        limit,
        ipv4_country,
        global_blocked,
        split_tunnel_mode,
        false,
    )
    .await
}

/// Route-aware IPv6 leak check: when `via_zastava_key` is true, AI traffic goes over TCP CONNECT
/// through the key, so a non-sanctioned foreign VPN IPv6 country differing from the key country
/// is reported as `Ok("IPV6_KEY_TCP_ISOLATED")` instead of `IPV6_LEAK_MISMATCH`.
#[allow(clippy::too_many_arguments)]
pub async fn check_ipv6_leak_with_route(
    probe: &dyn IpProbe,
    system: &dyn SystemInfo,
    url: &str,
    limit: Duration,
    ipv4_country: &str,
    global_blocked: &[String],
    split_tunnel_mode: bool,
    via_zastava_key: bool,
) -> CheckResult {
    if system.has_global_ipv6() == Some(false) {
        return CheckResult::ok(
            "IPV6_NOT_CONFIGURED",
            "IPv6 не настроен: у этого компьютера нет глобального IPv6-адреса, утечка по IPv6 невозможна.",
        );
    }
    if split_tunnel_mode {
        return CheckResult::ok(
            "IPV6_SPLIT_TUNNEL_INFO",
            "Режим раздельного туннеля: системный IPv6 носит информационный характер и не блокирует трафик ИИ через PAC/маршрут.",
        );
    }

    let unknown = |code: &str, text: String, reason: UnknownReason| {
        CheckResult::unknown(code, format!("Проверка IPv6 не выполнена: {text}"), reason)
    };

    let (status, text) = match probe.get(url, limit).await {
        HttpProbeOutcome::Response { status, body } => (status, body),
        HttpProbeOutcome::Timeout => {
            return CheckResult::ok(
                "IPV6_BLOCKED_OR_TIMEOUT",
                format!(
                    "IPv6-проба не ответила за {} мс: IPv6-трафик заблокирован VPN-туннелем или недоступен, утечка по IPv6 не обнаружена.",
                    limit.as_millis()
                ),
            );
        }
        HttpProbeOutcome::ConnectFailed => {
            return CheckResult::ok(
                "IPV6_UNREACHABLE_SAFE",
                "Соединение по IPv6 недоступно: IPv6-трафик заблокирован туннелем или не маршрутизируется, утечка по IPv6 исключена.",
            );
        }
        HttpProbeOutcome::ReadFailed => {
            return unknown(
                "IPV6_PROBE_READ_ERROR",
                "ответ сервиса проверки не удалось прочитать.".to_string(),
                UnknownReason::NetworkError,
            );
        }
        HttpProbeOutcome::ClientError => {
            return unknown(
                "IPV6_PROBE_INTERNAL_ERROR",
                "не удалось создать HTTP-клиент.".to_string(),
                UnknownReason::InternalError,
            );
        }
    };

    if !(200..300).contains(&status) {
        return unknown(
            "IPV6_PROBE_BAD_STATUS",
            format!("сервис проверки ответил статусом {status}."),
            UnknownReason::EmptyResponse,
        );
    }
    let loc = text
        .lines()
        .find_map(|line| line.strip_prefix("loc="))
        .map(|val| val.trim().to_uppercase());
    let Some(ipv6_loc) = loc else {
        return unknown(
            "IPV6_PROBE_NO_LOC",
            "в ответе сервиса нет страны (loc).".to_string(),
            UnknownReason::EmptyResponse,
        );
    };

    if global_blocked.contains(&ipv6_loc) {
        return CheckResult::critical(
            "IPV6_LEAK_SANCTIONED_CRITICAL",
            format!(
                "КРИТИЧНО: Обнаружена утечка IPv6! Трафик идет мимо VPN напрямую из {ipv6_loc} по IPv6. Немедленно отключите IPv6 в настройках сети ОС.",
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        );
    }

    let is_country = ipv6_loc.len() == 2
        && ipv6_loc.bytes().all(|b| b.is_ascii_uppercase())
        && !matches!(ipv6_loc.as_str(), "XX" | "ZZ");
    if !is_country || ipv4_country.trim().is_empty() {
        return unknown(
            "IPV6_PROBE_NO_COUNTRY",
            format!(
                "страну IPv6 ({ipv6_loc}) не с чем сравнить с IPv4 ({}).",
                if ipv4_country.trim().is_empty() {
                    "страна не определена"
                } else {
                    ipv4_country
                },
            ),
            UnknownReason::NoData,
        );
    }

    if ipv6_loc != ipv4_country.trim().to_uppercase() {
        if via_zastava_key {
            return CheckResult::ok(
                "IPV6_KEY_TCP_ISOLATED",
                format!(
                    "Трафик AI изолирован через ВПН Заставы ({ipv4_country}) по TCP CONNECT; системный IPv6 выходит через VPN ({ipv6_loc}) — утечки реального IP нет."
                ),
            );
        }
        return CheckResult::warning(
            "IPV6_LEAK_MISMATCH",
            format!(
                "Рассинхрон маршрутов: IPv4 идет через {ipv4_country}, а IPv6 — через {ipv6_loc}. Рекомендуется отключить IPv6 для 100% защиты туннеля.",
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        );
    }

    CheckResult::ok(
        "IPV6_ENCAPSULATED",
        format!(
            "IPv6-проба вышла из {ipv6_loc}, как и IPv4: IPv6-трафик идет тем же маршрутом, что и IPv4."
        ),
    )
}

/// Checks OS DNS resolvers for Russian domestic ISP leaks (`scutil --dns` on macOS, `ipconfig /all` on Windows).
pub fn check_dns_leak(ipv4_country: &str, russian_keywords: &[String]) -> CheckResult {
    check_dns_leak_with(&RealSystem, ipv4_country, russian_keywords)
}

/// [`check_dns_leak`] through `system` (injectable for tests).
pub fn check_dns_leak_with(
    system: &dyn SystemInfo,
    ipv4_country: &str,
    russian_keywords: &[String],
) -> CheckResult {
    match system.dns_listing() {
        Ok(text) => evaluate_dns_listing(&text, ipv4_country, russian_keywords),
        Err(SystemReadError::Unsupported) => CheckResult::unknown(
            "DNS_UNSUPPORTED_OS",
            "Проверка DNS-резолверов не выполнена: на этой системе список DNS-серверов ОС не читается.",
            UnknownReason::UnsupportedOs,
        ),
        Err(SystemReadError::Failed) => CheckResult::unknown(
            "DNS_RESOLVERS_UNREADABLE",
            "Проверка DNS-резолверов не выполнена: список DNS-серверов ОС не удалось прочитать.",
            UnknownReason::InternalError,
        ),
    }
}

/// Verdict of the DNS-resolver check: by the resolver that really sees the requests (`view`, from
/// the whoami sources); the OS DNS configuration (`config`, [`check_dns_leak_with`]) is reference.
///
/// * a resolver in Russia (unless the exit is Russian) or in another country than the exit is a
///   `Warning`;
/// * a finding of the configuration check (a domestic provider, Yandex DNS) stays a `Warning`
///   whatever the real resolver is: measuring never loosens an existing finding;
/// * without a measured resolver nothing is verified: `Unknown`, except for such a finding.
pub fn evaluate_dns_resolver(
    config: CheckResult,
    view: &ResolverView,
    exit_country: &str,
) -> CheckResult {
    evaluate_dns_resolver_for_route(config, view, exit_country, false)
}

/// Route-aware DNS resolver check.
///
/// * When both whoami sources return TUN Fake-IP (`198.18.0.0/15`) and the OS DNS config check
///   found no domestic Russian ISP / Yandex resolvers (`config.status == CheckStatus::Ok`), returns
///   `Ok("DNS_TUN_FAKE_IP_SAFE")`.
/// * When `via_zastava_key` is true and the OS resolver belongs to a non-sanctioned foreign VPN
///   country different from the key's `exit_country`, returns `Ok("DNS_KEY_REMOTE_RESOLVE")`.
pub fn evaluate_dns_resolver_for_route(
    config: CheckResult,
    view: &ResolverView,
    exit_country: &str,
    via_zastava_key: bool,
) -> CheckResult {
    let sources = match view {
        ResolverView::Located { sources, .. } => sources,
        ResolverView::Unmeasured(u) => &u.sources,
    };
    resolve_dns_verdict(config, view, exit_country, via_zastava_key).with_sources(sources)
}

fn resolve_dns_verdict(
    config: CheckResult,
    view: &ResolverView,
    exit_country: &str,
    via_zastava_key: bool,
) -> CheckResult {
    let config_note = match config.status {
        CheckStatus::Ok => "в списке DNS ОС нет резолверов провайдеров РФ и Яндекс.DNS",
        CheckStatus::Unknown => "список DNS ОС прочитать не удалось",
        _ => "в списке DNS ОС есть замечание",
    };
    let config_finding = matches!(config.status, CheckStatus::Warning | CheckStatus::Critical);
    let caveat = "Страна определена по адресу резолвера; ECS и DNS-over-HTTPS в браузере или приложении могут менять картину.";

    let (ip, country, public_service) = match view {
        ResolverView::Located {
            ip,
            country,
            public_service,
            ..
        } => (ip, country, public_service),
        ResolverView::Unmeasured(u) => {
            if config_finding {
                let mut kept = config;
                kept.message = format!(
                    "{} Реальный резолвер определить не удалось: {}.",
                    kept.message, u.detail
                );
                return kept;
            }
            if config.status == CheckStatus::Ok
                && u.code == "DNS_WHOAMI_FAKE_IP"
                && crate::auditor::probes::whoami::all_sources_tun_fake_ip(&u.sources)
            {
                return CheckResult::ok(
                    "DNS_TUN_FAKE_IP_SAFE",
                    "DNS защищён режимом Fake-IP вашего VPN-туннеля, резолверов провайдеров РФ в системе нет.",
                );
            }
            return CheckResult::unknown(
                u.code,
                format!(
                    "Проверка DNS-резолвера не выполнена: {}. Справочно, настройки ОС: {config_note}.",
                    u.detail
                ),
                u.reason,
            );
        }
    };

    let exit = normalized_country(exit_country);
    if country == "RU" && exit.as_deref() != Some("RU") {
        return CheckResult::warning(
            "DNS_DOMESTIC_WARNING",
            format!(
                "Ваши DNS-запросы видит резолвер {ip}, расположенный в РФ, при выходе через {}. Пропишите публичный DNS (1.1.1.1 / 8.8.8.8) и убедитесь, что DNS идёт через туннель. {caveat}",
                exit.as_deref().unwrap_or("страну, которая не определена"),
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        )
        .with_measured_via(MEASURED_VIA);
    }
    if let Some(service) = public_service {
        // An anycast service is placed in the country of its nearest point of presence: the
        // country is not compared. A finding of the OS list still stands.
        if config_finding {
            let mut kept = config;
            kept.message = format!(
                "{} Реальный резолвер — публичный {service} ({ip}); замечание касается настроек ОС.",
                kept.message
            );
            return kept.with_measured_via(MEASURED_VIA);
        }
        let same_operator = match view {
            ResolverView::Located { sources, .. } => same_operator_note(sources, service),
            ResolverView::Unmeasured(_) => String::new(),
        };
        return CheckResult::ok(
            "DNS_PUBLIC_RESOLVER",
            format!(
                "Резолвер: {service} (публичный DNS). Запросы DNS идут на {ip}; страна резолвера не сравнивается: это anycast-сервис.{same_operator} Настройки DNS ОС (справочно): {config_note}. ECS и DNS-over-HTTPS в браузере или приложении могут менять картину."
            ),
        )
        .with_measured_via(MEASURED_VIA);
    }
    if let Some(exit) = exit.as_deref().filter(|e| *e != country.as_str()) {
        if via_zastava_key && !crate::sanctions::is_sanctioned_or_blocked_country(country) {
            if config_finding {
                let mut kept = config;
                kept.message = format!(
                    "{} Трафик AI изолирован через ВПН Заставы ({exit}), но в настройках ОС есть замечание.",
                    kept.message
                );
                return kept.with_measured_via(MEASURED_VIA);
            }
            return CheckResult::ok(
                "DNS_KEY_REMOTE_RESOLVE",
                format!(
                    "DNS-резолвер ОС ({ip}, {country}) относится к системному VPN, а запросы к AI-провайдеру резолвятся удалённо на ВПН Заставы ({exit}) через TCP CONNECT. Настройки DNS ОС (справочно): {config_note}."
                ),
            )
            .with_measured_via(MEASURED_VIA);
        }
        return CheckResult::warning(
            "DNS_RESOLVER_MISMATCH",
            format!(
                "Ваши DNS-запросы видит резолвер {ip} в {country}, а выход находится в {exit}: DNS и трафик идут разными путями. У публичных anycast-резолверов (1.1.1.1, 8.8.8.8) страна по адресу бывает неточной. {caveat}"
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        )
        .with_measured_via(MEASURED_VIA);
    }
    if config_finding {
        let mut kept = config;
        kept.message = format!(
            "{} Реальный резолвер ({ip}, {country}) вопросов не вызывает; замечание касается настроек ОС.",
            kept.message
        );
        return kept.with_measured_via(MEASURED_VIA);
    }

    let compared = match &exit {
        Some(exit) => format!("страна совпадает со страной выхода ({exit})"),
        None => "страну выхода сравнить не с чем".to_string(),
    };
    CheckResult::ok(
        "DNS_CLEAN",
        format!(
            "Ваши DNS-запросы видит резолвер {ip} в {country}: не РФ, {compared}. Настройки DNS ОС (справочно): {config_note}. {caveat}"
        ),
    )
    .with_measured_via(MEASURED_VIA)
}

/// Decision of the DNS check on the text of the OS resolver configuration.
pub fn evaluate_dns_listing(
    text: &str,
    ipv4_country: &str,
    russian_keywords: &[String],
) -> CheckResult {
    // Only the lines about DNS carry names of resolvers and search domains; the rest of
    // `ipconfig /all` / `scutil --dns` (adapter names, flags) would give false matches.
    let dns_lines: Vec<String> = text
        .lines()
        .map(str::to_lowercase)
        .filter(|l| l.contains("dns") || l.contains("domain") || l.contains("nameserver"))
        .collect();
    let has_addresses = text
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .any(|t| t.parse::<std::net::IpAddr>().is_ok());
    if !has_addresses {
        return CheckResult::unknown(
            "DNS_RESOLVERS_EMPTY",
            "Проверка DNS-резолверов не выполнена: в настройках ОС не найдено ни одного DNS-адреса.",
            UnknownReason::EmptyResponse,
        );
    }

    for kw in russian_keywords {
        let kw_lower = kw.to_lowercase();
        if !kw_lower.is_empty() && dns_lines.iter().any(|l| l.contains(&kw_lower)) {
            return CheckResult::warning(
                "DNS_DOMESTIC_WARNING",
                format!(
                    "В системном DNS обнаружен провайдер «{kw}». Пропишите публичный DNS (1.1.1.1 / 8.8.8.8) в настройках сети."
                ),
                Some(GUIDE_OS_PRIVACY.to_string()),
            );
        }
    }

    // A known domestic public DNS (Yandex DNS, 77.88.8.x) as a whole address, not as a substring.
    let yandex_dns = text
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|t| t.starts_with("77.88.8.") && t.parse::<std::net::Ipv4Addr>().is_ok());
    if yandex_dns && ipv4_country != "RU" {
        return CheckResult::warning(
            "DNS_YANDEX_LEAK",
            "Обнаружен Яндекс.DNS (77.88.8.8) при зарубежном VPN. Смените DNS на Cloudflare (1.1.1.1).",
            Some(GUIDE_OS_PRIVACY.to_string()),
        );
    }

    CheckResult::ok(
        "DNS_CLEAN",
        format!(
            "В настройках DNS ОС нет имён {} провайдеров РФ и Яндекс.DNS; проверен только список настроенных резолверов, не фактический путь запросов.",
            russian_keywords.len()
        ),
    )
}

#[cfg(test)]
#[path = "leaks_tests.rs"]
mod tests;
