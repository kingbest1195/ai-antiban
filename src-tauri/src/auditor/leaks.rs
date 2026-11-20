#[path = "leaks_dns.rs"]
mod dns;

use std::time::Duration;

use crate::auditor::geo_matrix::{CheckResult, GUIDE_OS_NETWORK, UnknownReason};
use crate::auditor::seams::{HttpProbeOutcome, IpProbe, RealSystem, ReqwestProbe, SystemInfo};

pub use dns::{
    AuditProtectionContext, AuditProtectionFlags, check_dns_leak, check_dns_leak_with,
    evaluate_dns_listing, evaluate_dns_resolver, evaluate_dns_resolver_for_route,
    evaluate_dns_resolver_for_route_with_protection,
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
            Some(GUIDE_OS_NETWORK.to_string()),
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
            Some(GUIDE_OS_NETWORK.to_string()),
        );
    }

    CheckResult::ok(
        "IPV6_ENCAPSULATED",
        format!(
            "IPv6-проба вышла из {ipv6_loc}, как и IPv4: IPv6-трафик идет тем же маршрутом, что и IPv4."
        ),
    )
}

#[cfg(test)]
#[path = "leaks_tests.rs"]
mod tests;
