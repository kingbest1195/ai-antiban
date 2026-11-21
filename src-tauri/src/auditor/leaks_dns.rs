use crate::auditor::geo_matrix::{CheckResult, CheckStatus, GUIDE_OS_NETWORK, UnknownReason};
use crate::auditor::probes::whoami::{
    MEASURED_VIA, ResolverView, normalized_country, same_operator_note,
};
use crate::auditor::seams::{RealSystem, SystemInfo, SystemReadError};

/// Layer-3 protection booleans injected into Layer-2 [`crate::auditor::Auditor`] so DNS checks
/// can verify Precondition 2 without Layer-2 -> Layer-3 imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditProtectionFlags {
    pub sysproxy_active: bool,
    pub cli_or_sandbox_protection_active: bool,
    pub os_pac_deferred: bool,
}

/// Complete DNS isolation preconditions for `via_zastava_key` evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditProtectionContext {
    /// Precondition 1: bound Zastava route passes `check_usable`.
    pub route_usable: bool,
    /// Precondition 2a: system PAC proxy is active (`sysproxy::is_sysproxy_active()`).
    pub sysproxy_active: bool,
    /// Precondition 2b: CLI/IDE protection or isolated browser sandbox is active.
    pub cli_or_sandbox_protection_active: bool,
    /// Precondition 2c: OS PAC writes were deferred due to temporary VPN DNS (`os_pac_deferred`).
    pub os_pac_deferred: bool,
}

impl AuditProtectionContext {
    pub fn from_flags(route_usable: bool, flags: AuditProtectionFlags) -> Self {
        Self {
            route_usable,
            sysproxy_active: flags.sysproxy_active,
            cli_or_sandbox_protection_active: flags.cli_or_sandbox_protection_active,
            os_pac_deferred: flags.os_pac_deferred,
        }
    }

    pub fn assumed_active_for_route() -> Self {
        Self {
            route_usable: true,
            sysproxy_active: true,
            cli_or_sandbox_protection_active: false,
            os_pac_deferred: false,
        }
    }

    /// Returns `true` when Precondition 1 holds AND either CLI/sandbox/browser-PAC protection
    /// is active (which applies regardless of `os_pac_deferred`) OR OS PAC is active and not deferred:
    /// `route_usable && (cli_or_sandbox_protection_active || (sysproxy_active && !os_pac_deferred))`.
    pub fn zastava_dns_isolated(self) -> bool {
        self.route_usable
            && (self.cli_or_sandbox_protection_active
                || (self.sysproxy_active && !self.os_pac_deferred))
    }
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
pub fn evaluate_dns_resolver(
    config: CheckResult,
    view: &ResolverView,
    exit_country: &str,
) -> CheckResult {
    evaluate_dns_resolver_for_route(config, view, exit_country, false)
}

/// Route-aware DNS resolver check assuming healthy active route protection when `via_zastava_key`
/// is `true`. Production audit execution uses [`evaluate_dns_resolver_for_route_with_protection`].
pub fn evaluate_dns_resolver_for_route(
    config: CheckResult,
    view: &ResolverView,
    exit_country: &str,
    via_zastava_key: bool,
) -> CheckResult {
    let protection = if via_zastava_key {
        AuditProtectionContext::assumed_active_for_route()
    } else {
        AuditProtectionContext::default()
    };
    evaluate_dns_resolver_for_route_with_protection(
        config,
        view,
        exit_country,
        via_zastava_key,
        protection,
    )
}

/// Route-aware DNS resolver check enforcing all 3 `via_zastava_key` isolation preconditions.
pub fn evaluate_dns_resolver_for_route_with_protection(
    config: CheckResult,
    view: &ResolverView,
    exit_country: &str,
    via_zastava_key: bool,
    protection: AuditProtectionContext,
) -> CheckResult {
    let sources = match view {
        ResolverView::Located { sources, .. } => sources,
        ResolverView::Unmeasured(u) => &u.sources,
    };
    resolve_dns_verdict(config, view, exit_country, via_zastava_key, protection)
        .with_sources(sources)
}

fn remote_resolve_ok(exit_label: &str, os_dns_detail: &str) -> CheckResult {
    CheckResult::ok(
        "DNS_KEY_REMOTE_RESOLVE",
        format!(
            "Запросы к AI-провайдерам резолвятся удалённо на узле ВПН Заставы ({exit_label}) через TCP CONNECT ({os_dns_detail}). Обычные non-AI сайты в стандартном браузере по-прежнему используют DNS ОС."
        ),
    )
}

pub(super) fn resolve_dns_verdict(
    config: CheckResult,
    view: &ResolverView,
    exit_country: &str,
    via_zastava_key: bool,
    protection: AuditProtectionContext,
) -> CheckResult {
    let config_note = match config.status {
        CheckStatus::Ok => "в списке DNS ОС нет резолверов провайдеров РФ и Яндекс.DNS",
        CheckStatus::Unknown => "список DNS ОС прочитать не удалось",
        _ => "в списке DNS ОС есть замечание",
    };
    let config_finding = matches!(config.status, CheckStatus::Warning | CheckStatus::Critical);
    let caveat = "Страна определена по адресу резолвера; ECS и DNS-over-HTTPS в браузере или приложении могут менять картину.";
    let exit = normalized_country(exit_country);
    let zastava_isolated = via_zastava_key && protection.zastava_dns_isolated();
    let exit_label = exit.as_deref().unwrap_or("выходной узел");

    let (ip, country, public_service) = match view {
        ResolverView::Located {
            ip,
            country,
            public_service,
            ..
        } => (ip, country, public_service),
        ResolverView::Unmeasured(u) => {
            if config_finding {
                if zastava_isolated && exit.as_deref() != Some("RU") {
                    return remote_resolve_ok(
                        exit_label,
                        &format!(
                            "в настройках DNS ОС есть провайдер РФ/Яндекс, реальный резолвер не измерен: {}",
                            u.detail
                        ),
                    );
                }
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

    if country == "RU" && exit.as_deref() != Some("RU") {
        if zastava_isolated {
            return remote_resolve_ok(
                exit_label,
                &format!("резолвер ОС {ip} в RU, настройки DNS ОС: {config_note}"),
            )
            .with_measured_via(MEASURED_VIA);
        }
        return CheckResult::warning(
            "DNS_DOMESTIC_WARNING",
            format!(
                "Ваши DNS-запросы видит резолвер {ip}, расположенный в РФ, при выходе через {}. Пропишите публичный DNS (1.1.1.1 / 8.8.8.8) и убедитесь, что DNS идёт через туннель. {caveat}",
                exit.as_deref().unwrap_or("страну, которая не определена"),
            ),
            Some(GUIDE_OS_NETWORK.to_string()),
        )
        .with_measured_via(MEASURED_VIA);
    }
    if let Some(service) = public_service {
        // An anycast service is placed in the country of its nearest point of presence: the
        // country is not compared. A finding of the OS list still stands unless isolated via key.
        if config_finding {
            if zastava_isolated && exit.as_deref() != Some("RU") {
                return remote_resolve_ok(
                    exit_label,
                    &format!("реальный резолвер — публичный {service} ({ip}), в настройках ОС есть замечание"),
                )
                .with_measured_via(MEASURED_VIA);
            }
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
    if let Some(exit_cc) = exit.as_deref().filter(|e| *e != country.as_str()) {
        if via_zastava_key
            && protection.route_usable
            && !crate::sanctions::is_sanctioned_or_blocked_country(country)
            && !config_finding
        {
            return remote_resolve_ok(
                exit_cc,
                &format!("резолвер ОС {ip} в {country} относится к системному VPN; {config_note}"),
            )
            .with_measured_via(MEASURED_VIA);
        }
        if zastava_isolated && !crate::sanctions::is_sanctioned_or_blocked_country(country) {
            return remote_resolve_ok(
                exit_cc,
                &format!("резолвер ОС {ip} в {country} относится к системному VPN; {config_note}"),
            )
            .with_measured_via(MEASURED_VIA);
        }
        return CheckResult::warning(
            "DNS_RESOLVER_MISMATCH",
            format!(
                "Ваши DNS-запросы видит резолвер {ip} в {country}, а выход находится в {exit_cc}: DNS и трафик идут разными путями. У публичных anycast-резолверов (1.1.1.1, 8.8.8.8) страна по адресу бывает неточной. {caveat}"
            ),
            Some(GUIDE_OS_NETWORK.to_string()),
        )
        .with_measured_via(MEASURED_VIA);
    }
    if config_finding {
        if zastava_isolated && exit.as_deref() != Some("RU") {
            return remote_resolve_ok(
                exit_label,
                &format!("реальный резолвер {ip} ({country}), в настройках ОС есть замечание"),
            )
            .with_measured_via(MEASURED_VIA);
        }
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
                Some(GUIDE_OS_NETWORK.to_string()),
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
            Some(GUIDE_OS_NETWORK.to_string()),
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
#[path = "leaks_dns_tests.rs"]
mod tests;
