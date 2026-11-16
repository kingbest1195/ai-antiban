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
mod tests {
    use super::*;
    use crate::auditor::geo_matrix::CheckStatus;
    use crate::auditor::seams::fakes::{FakeProbe, FakeSystem};

    const URL: &str = "https://probe.invalid/cdn-cgi/trace";
    const LIMIT: Duration = Duration::from_millis(50);

    fn v6_host() -> FakeSystem {
        FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        }
    }

    async fn ipv6(
        probe: &FakeProbe,
        sys: &FakeSystem,
        country: &str,
        blocked: &[&str],
    ) -> CheckResult {
        let blocked: Vec<String> = blocked.iter().map(|s| s.to_string()).collect();
        check_ipv6_leak_with(probe, sys, URL, LIMIT, country, &blocked).await
    }

    #[test]
    fn test_russian_timezone_detection() {
        use crate::auditor::os_env::is_russian_or_belarusian_timezone;
        assert!(is_russian_or_belarusian_timezone("Europe/Moscow"));
        assert!(is_russian_or_belarusian_timezone("Asia/Vladivostok"));
        assert!(is_russian_or_belarusian_timezone("Europe/Minsk"));
        assert!(!is_russian_or_belarusian_timezone("Europe/Amsterdam"));
        assert!(!is_russian_or_belarusian_timezone("America/New_York"));
    }

    // (1) a host with IPv6 whose IPv6 probe times out (e.g. blocked by VPN kill-switch)
    #[tokio::test]
    async fn ipv6_timeout_on_a_host_with_ipv6_is_ok_when_blocked_by_vpn() {
        let probe = FakeProbe::new(HttpProbeOutcome::Timeout);
        let r = ipv6(&probe, &v6_host(), "NL", &[]).await;
        assert_eq!(r.status, CheckStatus::Ok);
        assert_eq!(r.code, "IPV6_BLOCKED_OR_TIMEOUT");
        assert_eq!(probe.calls(), 1);
    }

    // (2) a host without global IPv6: nothing to leak, the probe is not even needed
    #[tokio::test]
    async fn ipv6_not_configured_is_ok_even_if_the_probe_would_time_out() {
        let probe = FakeProbe::new(HttpProbeOutcome::Timeout);
        let sys = FakeSystem {
            global_ipv6: Some(false),
            ..FakeSystem::healthy()
        };
        let r = ipv6(&probe, &sys, "NL", &[]).await;
        assert_eq!(r.status, CheckStatus::Ok);
        assert_eq!(r.code, "IPV6_NOT_CONFIGURED");
        assert!(r.message.contains("IPv6 не настроен"));
        assert_eq!(probe.calls(), 0);
    }

    // (3) HTTP 500 / 403 / HTML without loc=
    #[tokio::test]
    async fn ipv6_bad_status_or_no_loc_is_unknown_empty_response() {
        for (status, body) in [
            (500, "oops"),
            (403, "<html>blocked</html>"),
            (200, "<html>portal</html>"),
            (200, "ip=1.2.3.4"),
        ] {
            let r = ipv6(&FakeProbe::body(status, body), &v6_host(), "NL", &[]).await;
            assert_eq!(r.status, CheckStatus::Unknown, "{status} {body}");
            assert_eq!(
                r.reason,
                Some(UnknownReason::EmptyResponse),
                "{status} {body}"
            );
        }
    }

    // (4) the answer is the blocked country
    #[tokio::test]
    async fn ipv6_from_a_blocked_country_is_critical() {
        let r = ipv6(
            &FakeProbe::body(200, "ip=2a00::1\nloc=RU\n"),
            &v6_host(),
            "NL",
            &["RU"],
        )
        .await;
        assert_eq!(r.status, CheckStatus::Critical);
        assert_eq!(r.code, "IPV6_LEAK_SANCTIONED_CRITICAL");
    }

    // (5) a different country than IPv4 is a warning, the same one is ok
    #[tokio::test]
    async fn ipv6_country_is_compared_with_ipv4() {
        let probe = FakeProbe::body(200, "loc=DE\n");
        let r = ipv6(&probe, &v6_host(), "NL", &[]).await;
        assert_eq!(r.status, CheckStatus::Warning);
        let r = ipv6(&probe, &v6_host(), "de", &[]).await;
        assert_eq!(r.status, CheckStatus::Ok);
        assert!(r.message.contains("DE"));
        // Nothing to compare with: not a match.
        let r = ipv6(&probe, &v6_host(), "", &[]).await;
        assert_eq!(r.status, CheckStatus::Unknown);
        let r = ipv6(&FakeProbe::body(200, "loc=XX\n"), &v6_host(), "NL", &[]).await;
        assert_eq!(r.status, CheckStatus::Unknown);
    }

    // (6) client/read errors remain unknown; ConnectFailed means IPv6 cannot connect (safe)
    #[tokio::test]
    async fn ipv6_probe_errors_are_unknown() {
        let r = ipv6(
            &FakeProbe::new(HttpProbeOutcome::ClientError),
            &v6_host(),
            "NL",
            &[],
        )
        .await;
        assert_eq!(
            (r.status, r.reason),
            (CheckStatus::Unknown, Some(UnknownReason::InternalError))
        );
        let r = ipv6(
            &FakeProbe::new(HttpProbeOutcome::ReadFailed),
            &v6_host(),
            "NL",
            &[],
        )
        .await;
        assert_eq!(
            (r.status, r.reason),
            (CheckStatus::Unknown, Some(UnknownReason::NetworkError))
        );
        let r = ipv6(
            &FakeProbe::new(HttpProbeOutcome::ConnectFailed),
            &v6_host(),
            "NL",
            &[],
        )
        .await;
        assert_eq!(r.status, CheckStatus::Ok);
        assert_eq!(r.code, "IPV6_UNREACHABLE_SAFE");
    }

    // The host could not tell whether it has IPv6: the probe decides (leak warns, timeout/blocked is Ok).
    #[tokio::test]
    async fn ipv6_undetermined_host_falls_back_to_the_probe() {
        let sys = FakeSystem {
            global_ipv6: None,
            ..FakeSystem::healthy()
        };
        let timeout_probe = FakeProbe::new(HttpProbeOutcome::Timeout);
        assert_eq!(
            ipv6(&timeout_probe, &sys, "NL", &[]).await.status,
            CheckStatus::Ok
        );
        assert_eq!(timeout_probe.calls(), 1);

        let leak_probe = FakeProbe::body(200, "loc=DE\n");
        assert_eq!(
            ipv6(&leak_probe, &sys, "NL", &[]).await.status,
            CheckStatus::Warning
        );
        assert_eq!(leak_probe.calls(), 1);
    }

    #[tokio::test]
    async fn ipv6_split_tunnel_mode_returns_informational_ok() {
        let probe = FakeProbe::body(200, "ip=2a00::1\nloc=RU\n");
        let r = check_ipv6_leak_with_split(
            &probe,
            &v6_host(),
            "http://v6.test",
            Duration::from_millis(10),
            "NL",
            &["RU".to_string()],
            true,
        )
        .await;
        assert_eq!(r.status, CheckStatus::Ok);
        assert_eq!(r.code, "IPV6_SPLIT_TUNNEL_INFO");
        assert_eq!(probe.calls(), 0);
    }

    fn kws() -> Vec<String> {
        ["Rostelecom", "MTS", "VK", "Yandex"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn dns_unreadable_or_empty_is_unknown() {
        let offline = FakeSystem::offline();
        let r = check_dns_leak_with(&offline, "NL", &kws());
        assert_eq!(
            (r.status, r.reason),
            (CheckStatus::Unknown, Some(UnknownReason::InternalError))
        );
        let unsupported = FakeSystem {
            dns_listing: Err(SystemReadError::Unsupported),
            ..FakeSystem::healthy()
        };
        let r = check_dns_leak_with(&unsupported, "NL", &kws());
        assert_eq!(r.reason, Some(UnknownReason::UnsupportedOs));
        // A command that ran but printed no resolver address (also what a dry-run stub gives).
        let empty = FakeSystem {
            dns_listing: Ok("DNS configuration\n".into()),
            ..FakeSystem::healthy()
        };
        let r = check_dns_leak_with(&empty, "NL", &kws());
        assert_eq!(r.reason, Some(UnknownReason::EmptyResponse));
    }

    #[test]
    fn dns_listing_is_matched_on_dns_lines_only() {
        // Windows `ipconfig /all`: the provider shows in the DNS suffix line.
        let win = "Ethernet adapter Ethernet:\n   Description . . . : Realtek PCIe\n   Connection-specific DNS Suffix  . : mts.ru\n   DNS Servers . . . . . . . . . . . : 192.168.1.1\n";
        let r = evaluate_dns_listing(win, "NL", &kws());
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
        );
        // The same keyword outside of DNS lines (an adapter description) is not a finding.
        let desc = "Description . . . : Gigabit MTS Adapter\n   DNS Servers . . . : 1.1.1.1\n";
        assert_eq!(
            evaluate_dns_listing(desc, "NL", &kws()).status,
            CheckStatus::Ok
        );
        // macOS `scutil --dns`.
        let mac = "resolver #1\n  search domain[0] : beeline.local\n  nameserver[0] : 8.8.8.8\n";
        assert_eq!(
            evaluate_dns_listing(mac, "NL", &["Beeline".to_string()]).status,
            CheckStatus::Warning
        );
    }

    #[test]
    fn yandex_dns_is_an_address_match_not_a_substring() {
        let yandex = "resolver #1\n  nameserver[0] : 77.88.8.8\n";
        assert_eq!(
            evaluate_dns_listing(yandex, "NL", &[]).code,
            "DNS_YANDEX_LEAK"
        );
        // Exit in Russia: not a leak of this kind.
        assert_eq!(
            evaluate_dns_listing(yandex, "RU", &[]).status,
            CheckStatus::Ok
        );
        // 177.88.8.8 only contains the digits.
        let other = "resolver #1\n  nameserver[0] : 177.88.8.8\n";
        assert_eq!(
            evaluate_dns_listing(other, "NL", &[]).status,
            CheckStatus::Ok
        );
    }

    #[test]
    fn dns_ok_text_states_what_was_checked() {
        let r = evaluate_dns_listing("resolver #1\n  nameserver[0] : 1.1.1.1\n", "NL", &kws());
        assert_eq!(r.status, CheckStatus::Ok);
        assert!(
            r.message.contains("список настроенных резолверов"),
            "{}",
            r.message
        );
    }

    // ---- the resolver that really sees the requests ----

    use crate::auditor::probes::whoami::Unmeasured;

    fn located(ip: &str, cc: &str) -> ResolverView {
        ResolverView::Located {
            ip: ip.parse().unwrap(),
            country: cc.into(),
            public_service: None,
            sources: vec![],
        }
    }

    fn unmeasured(reason: UnknownReason) -> ResolverView {
        ResolverView::Unmeasured(Unmeasured {
            code: "DNS_WHOAMI_TIMEOUT",
            reason,
            detail: "источники молчат".into(),
            sources: vec![],
        })
    }

    fn config_ok() -> CheckResult {
        evaluate_dns_listing("resolver #1\n  nameserver[0] : 1.1.1.1\n", "NL", &kws())
    }

    fn config_domestic() -> CheckResult {
        evaluate_dns_listing(
            "resolver #1\n  search domain[0] : mts.ru\n  nameserver[0] : 192.168.1.1\n",
            "NL",
            &kws(),
        )
    }

    #[test]
    fn resolver_in_the_exit_country_is_ok_with_source_and_caveat() {
        let r = evaluate_dns_resolver(config_ok(), &located("9.9.9.9", "NL"), "NL");
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "DNS_CLEAN"));
        assert_eq!(r.measured_via.as_deref(), Some("whoami:akamai+google"));
        assert!(
            r.message.contains("9.9.9.9") && r.message.contains("ECS"),
            "{}",
            r.message
        );
        assert!(
            r.message.contains("справочно"),
            "the OS list is reference: {}",
            r.message
        );
    }

    #[test]
    fn resolver_in_russia_is_a_warning_like_the_other_domestic_findings() {
        let r = evaluate_dns_resolver(config_ok(), &located("77.88.8.8", "RU"), "NL");
        // The same severity and code as the configuration finding (never harsher).
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
        );
        assert!(
            r.message.contains("РФ") && r.message.contains("NL"),
            "{}",
            r.message
        );
        // The real resolver speaks even when the OS list looks clean; an unknown exit does too.
        assert_eq!(
            evaluate_dns_resolver(config_ok(), &located("77.88.8.8", "RU"), "").status,
            CheckStatus::Warning
        );
        // A Russian exit with a Russian resolver is consistent.
        assert_eq!(
            evaluate_dns_resolver(config_ok(), &located("77.88.8.8", "RU"), "RU").status,
            CheckStatus::Ok
        );
    }

    #[test]
    fn resolver_in_another_country_than_the_exit_is_a_warning() {
        let r = evaluate_dns_resolver(config_ok(), &located("8.8.8.8", "US"), "NL");
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Warning, "DNS_RESOLVER_MISMATCH")
        );
        assert!(r.message.contains("US") && r.message.contains("NL"));
    }

    #[test]
    fn a_finding_of_the_os_list_is_not_loosened_by_a_good_real_resolver() {
        let r = evaluate_dns_resolver(config_domestic(), &located("9.9.9.9", "NL"), "NL");
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
        );
        assert!(r.message.contains("9.9.9.9"));
        // ... and stays when the resolver could not be measured at all.
        let r = evaluate_dns_resolver(config_domestic(), &unmeasured(UnknownReason::Timeout), "NL");
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
        );
        assert!(r.message.contains("не удалось"));
    }

    #[test]
    fn unmeasured_resolver_is_unknown_not_ok_even_with_a_clean_os_list() {
        for reason in [
            UnknownReason::Timeout,
            UnknownReason::SourceRefused,
            UnknownReason::NoData,
        ] {
            let r = evaluate_dns_resolver(config_ok(), &unmeasured(reason), "NL");
            assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(reason)));
            assert_eq!(r.code, "DNS_WHOAMI_TIMEOUT");
            assert!(
                r.message.contains("Справочно")
                    && r.message.contains("нет резолверов провайдеров РФ")
            );
        }
        // An unreadable OS list does not matter when the real resolver is known.
        let unreadable = check_dns_leak_with(&FakeSystem::offline(), "NL", &kws());
        assert_eq!(
            evaluate_dns_resolver(unreadable, &located("9.9.9.9", "NL"), "NL").status,
            CheckStatus::Ok
        );
    }

    fn public(ip: &str, cc: &str, service: &'static str) -> ResolverView {
        ResolverView::Located {
            ip: ip.parse().unwrap(),
            country: cc.into(),
            public_service: Some(service),
            sources: vec![],
        }
    }

    #[test]
    fn public_resolver_is_ok_without_comparing_its_country() {
        for (ip, cc, svc) in [
            ("74.125.40.10", "US", "Google Public DNS"),
            ("162.158.1.1", "AU", "Cloudflare"),
        ] {
            let r = evaluate_dns_resolver(config_ok(), &public(ip, cc, svc), "NL");
            assert_eq!(
                (r.status, r.code.as_str()),
                (CheckStatus::Ok, "DNS_PUBLIC_RESOLVER"),
                "{svc}"
            );
            assert!(
                r.message.contains(svc) && r.message.contains("anycast"),
                "{}",
                r.message
            );
            assert!(r.message.contains("ECS") && r.message.contains("DNS-over-HTTPS"));
            assert_eq!(r.measured_via.as_deref(), Some("whoami:akamai+google"));
        }
        // An ordinary provider resolver in another country still warns, a Russian one too.
        assert_eq!(
            evaluate_dns_resolver(config_ok(), &located("203.0.113.53", "DE"), "NL").code,
            "DNS_RESOLVER_MISMATCH"
        );
        assert_eq!(
            evaluate_dns_resolver(config_ok(), &located("77.88.8.8", "RU"), "NL").code,
            "DNS_DOMESTIC_WARNING"
        );
    }

    #[test]
    fn findings_stay_with_a_public_resolver() {
        // A domestic provider in the OS list is still a Warning.
        let r = evaluate_dns_resolver(
            config_domestic(),
            &public("74.125.40.10", "US", "Google Public DNS"),
            "NL",
        );
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
        );
        // A public service seen in Russia is still reported as a resolver in Russia.
        let r = evaluate_dns_resolver(config_ok(), &public("1.1.1.1", "RU", "Cloudflare"), "NL");
        assert_eq!(
            (r.status, r.code.as_str()),
            (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
        );
    }

    #[tokio::test]
    async fn fake_ip_tun_dns_and_zastava_key_route_isolation_are_ok() {
        use crate::auditor::probes::whoami::{SourceReading, combine_sources};
        use crate::auditor::seams::fakes::FakeProbe;

        let fake_ip_view = ResolverView::Unmeasured(
            combine_sources(
                &SourceReading::Special("198.18.0.10".parse().unwrap()),
                &SourceReading::Special("198.18.0.11".parse().unwrap()),
            )
            .unwrap_err(),
        );

        let fake_ok = evaluate_dns_resolver_for_route(config_ok(), &fake_ip_view, "FR", false);
        assert_eq!(
            (fake_ok.status, fake_ok.code.as_str()),
            (CheckStatus::Ok, "DNS_TUN_FAKE_IP_SAFE")
        );

        // Domestic ISP resolver finding overrides Fake-IP Ok.
        let fake_ru =
            evaluate_dns_resolver_for_route(config_domestic(), &fake_ip_view, "FR", false);
        assert_eq!(
            (fake_ru.status, fake_ru.code.as_str()),
            (CheckStatus::Warning, "DNS_DOMESTIC_WARNING")
        );

        // Unknown OS DNS list keeps Fake-IP Unknown rather than assuming safe.
        let unknown_cfg = check_dns_leak_with(&FakeSystem::offline(), "FR", &kws());
        let fake_unknown = evaluate_dns_resolver_for_route(unknown_cfg, &fake_ip_view, "FR", false);
        assert_eq!(fake_unknown.status, CheckStatus::Unknown);

        // Routed Zastava key in FR with foreign VPN resolver in GB -> Ok("DNS_KEY_REMOTE_RESOLVE").
        let r_routed =
            evaluate_dns_resolver_for_route(config_ok(), &located("81.2.69.142", "GB"), "FR", true);
        assert_eq!(
            (r_routed.status, r_routed.code.as_str()),
            (CheckStatus::Ok, "DNS_KEY_REMOTE_RESOLVE")
        );

        // IPv6 exit in GB while Zastava key is in FR -> Ok("IPV6_KEY_TCP_ISOLATED"),
        // whereas RU IPv6 remains Critical even with Zastava key.
        let gb_probe = FakeProbe::body(200, "fl=1\nloc=GB\n");
        let sys_v6 = FakeSystem {
            global_ipv6: Some(true),
            ..FakeSystem::healthy()
        };
        let v6_routed = check_ipv6_leak_with_route(
            &gb_probe,
            &sys_v6,
            "https://example.invalid/cdn-cgi/trace",
            Duration::from_secs(1),
            "FR",
            &["RU".into(), "BY".into()],
            false,
            true,
        )
        .await;
        assert_eq!(
            (v6_routed.status, v6_routed.code.as_str()),
            (CheckStatus::Ok, "IPV6_KEY_TCP_ISOLATED")
        );

        let ru_probe = FakeProbe::body(200, "fl=1\nloc=RU\n");
        let v6_ru = check_ipv6_leak_with_route(
            &ru_probe,
            &sys_v6,
            "https://example.invalid/cdn-cgi/trace",
            Duration::from_secs(1),
            "FR",
            &["RU".into(), "BY".into()],
            false,
            true,
        )
        .await;
        assert_eq!(
            (v6_ru.status, v6_ru.code.as_str()),
            (CheckStatus::Critical, "IPV6_LEAK_SANCTIONED_CRITICAL")
        );
    }
}
