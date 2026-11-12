use std::time::Duration;
use crate::auditor::geo_matrix::{CheckResult, UnknownReason, GUIDE_OS_PRIVACY};

pub const IPV6_CHECK_URL: &str = "https://[2606:4700:4700::1111]/cdn-cgi/trace";
pub const IPV6_CHECK_TIMEOUT_MS: u64 = 800;

pub use crate::auditor::os_env::{
    check_os_location_services, evaluate_locale_env_hygiene, is_russian_or_belarusian_timezone,
    RUSSIAN_TIMEZONES,
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
    check_ipv6_leak_with(
        IPV6_CHECK_URL,
        Duration::from_millis(IPV6_CHECK_TIMEOUT_MS),
        ipv4_country,
        global_blocked,
    )
    .await
}

/// [`check_ipv6_leak`] against `url` with `limit` (injectable for tests).
/// A probe that did not produce a usable answer is `Unknown`, never "no leak".
pub async fn check_ipv6_leak_with(
    url: &str,
    limit: Duration,
    ipv4_country: &str,
    global_blocked: &[String],
) -> CheckResult {
    let client = match reqwest::Client::builder().timeout(limit).build() {
        Ok(c) => c,
        Err(_) => {
            return CheckResult::unknown(
                "IPV6_PROBE_INTERNAL_ERROR",
                "Проверка IPv6 не выполнена: не удалось создать HTTP-клиент.",
                UnknownReason::InternalError,
            );
        }
    };

    let resp = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(e) if e.is_timeout() => {
            return CheckResult::unknown(
                "IPV6_PROBE_TIMEOUT",
                format!(
                    "Проверка IPv6 не выполнена: проба к Cloudflare не ответила за {} мс.",
                    limit.as_millis()
                ),
                UnknownReason::Timeout,
            );
        }
        // No route / connection refused outside the tunnel: IPv6 does not leave this host.
        Err(_) => {
            return CheckResult::ok(
                "IPV6_DISABLED_SAFE",
                "IPv6 отключен или заблокирован вне туннеля (утечек нет).",
            );
        }
    };

    if !resp.status().is_success() {
        return CheckResult::unknown(
            "IPV6_PROBE_BAD_STATUS",
            format!(
                "Проверка IPv6 не выполнена: сервис проверки ответил статусом {}.",
                resp.status().as_u16()
            ),
            UnknownReason::EmptyResponse,
        );
    }
    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => {
            return CheckResult::unknown(
                "IPV6_PROBE_READ_ERROR",
                "Проверка IPv6 не выполнена: ответ сервиса проверки не удалось прочитать.",
                UnknownReason::NetworkError,
            );
        }
    };
    let loc = text
        .lines()
        .find_map(|line| line.strip_prefix("loc="))
        .map(|val| val.trim().to_uppercase());
    let Some(ipv6_loc) = loc else {
        return CheckResult::unknown(
            "IPV6_PROBE_NO_LOC",
            "Проверка IPv6 не выполнена: в ответе сервиса нет страны (loc).",
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

    if !ipv4_country.is_empty() && ipv6_loc != ipv4_country.to_uppercase() {
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
        format!("Трафик IPv6 надежно упакован в туннель ({ipv6_loc})."),
    )
}

/// Checks OS DNS resolvers for Russian domestic ISP leaks (`scutil --dns` on macOS, `ipconfig /all` on Windows).
pub fn check_dns_leak(ipv4_country: &str, russian_keywords: &[String]) -> CheckResult {
    // Whether the OS resolver list could be read at all (a failed read is not "clean").
    #[allow(unused_mut)]
    let mut probed = false;

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = crate::sysproxy::silent_command("scutil").arg("--dns").output() {
            probed = true;
            let text = String::from_utf8_lossy(&output.stdout);
            for kw in russian_keywords {
                if text.to_lowercase().contains(&kw.to_lowercase()) {
                    return CheckResult::warning(
                        "DNS_DOMESTIC_WARNING",
                        format!("В системном DNS обнаружен провайдер «{kw}». Пропишите публичный DNS (1.1.1.1 / 8.8.8.8) в настройках сети."),
                        Some(GUIDE_OS_PRIVACY.to_string()),
                    );
                }
            }
            // Check if nameserver[0] is a known domestic ISP public DNS (e.g. 77.88.8.8 Yandex DNS)
            if text.contains("77.88.8.") && ipv4_country != "RU" {
                return CheckResult::warning(
                    "DNS_YANDEX_LEAK",
                    "Обнаружен Яндекс.DNS (77.88.8.8) при зарубежном VPN. Смените DNS на Cloudflare (1.1.1.1).",
                    Some(GUIDE_OS_PRIVACY.to_string()),
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = crate::sysproxy::silent_command("ipconfig").arg("/all").output() {
            probed = true;
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("77.88.8.") && ipv4_country != "RU" {
                return CheckResult::warning(
                    "DNS_YANDEX_LEAK",
                    "Обнаружен Яндекс.DNS (77.88.8.8) при зарубежном VPN. Смените DNS на Cloudflare (1.1.1.1).",
                    Some(GUIDE_OS_PRIVACY.to_string()),
                );
            }
        }
    }

    let _ = (ipv4_country, russian_keywords);
    if !probed {
        return CheckResult::unknown(
            "DNS_RESOLVERS_UNREADABLE",
            "Проверка DNS-резолверов не выполнена: список DNS-серверов ОС не удалось прочитать.",
            UnknownReason::InternalError,
        );
    }
    CheckResult::ok(
        "DNS_CLEAN",
        "Утечек через локальные DNS-резолверы РФ не обнаружено.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_russian_timezone_detection() {
        assert!(is_russian_or_belarusian_timezone("Europe/Moscow"));
        assert!(is_russian_or_belarusian_timezone("Asia/Vladivostok"));
        assert!(is_russian_or_belarusian_timezone("Europe/Minsk"));
        assert!(!is_russian_or_belarusian_timezone("Europe/Amsterdam"));
        assert!(!is_russian_or_belarusian_timezone("America/New_York"));
    }

    #[test]
    fn test_timezone_evaluation_mismatch() {
        // If system is e.g. UTC and target is Amsterdam
        let res = evaluate_system_timezone(Some("Europe/Amsterdam"));
        // Either Ok or Warning depending on the machine's actual timezone, but must not panic
        assert!(!res.code.is_empty());
    }

    use crate::auditor::geo_matrix::CheckStatus;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One-shot local HTTP server; `None` = accept and stay silent.
    async fn serve(response: Option<&'static str>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    match response {
                        Some(r) => {
                            let _ = sock.write_all(r.as_bytes()).await;
                            let _ = sock.shutdown().await;
                        }
                        None => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        format!("http://{addr}/cdn-cgi/trace")
    }

    #[tokio::test]
    async fn ipv6_silent_probe_is_unknown_timeout_not_ok() {
        let url = serve(None).await;
        let r = check_ipv6_leak_with(&url, Duration::from_millis(50), "NL", &[]).await;
        assert_eq!(r.status, CheckStatus::Unknown);
        assert_eq!(r.reason, Some(UnknownReason::Timeout));
    }

    #[tokio::test]
    async fn ipv6_bad_status_or_no_loc_is_unknown_empty_response() {
        let url = serve(Some(
            "HTTP/1.1 403 Forbidden\r\ncontent-length: 4\r\n\r\nnope",
        ))
        .await;
        let r = check_ipv6_leak_with(&url, Duration::from_secs(2), "NL", &[]).await;
        assert_eq!(r.reason, Some(UnknownReason::EmptyResponse));

        let url = serve(Some("HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\r\nip=1.2.3")).await;
        let r = check_ipv6_leak_with(&url, Duration::from_secs(2), "NL", &[]).await;
        assert_eq!(r.status, CheckStatus::Unknown);
        assert_eq!(r.code, "IPV6_PROBE_NO_LOC");
    }

    #[tokio::test]
    async fn ipv6_loc_is_classified() {
        let url = serve(Some("HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nloc=RU")).await;
        let blocked = vec!["RU".to_string()];
        let r = check_ipv6_leak_with(&url, Duration::from_secs(2), "NL", &blocked).await;
        assert_eq!(r.status, CheckStatus::Critical);
        let r = check_ipv6_leak_with(&url, Duration::from_secs(2), "NL", &[]).await;
        assert_eq!(r.status, CheckStatus::Warning);
        let r = check_ipv6_leak_with(&url, Duration::from_secs(2), "RU", &[]).await;
        assert_eq!(r.status, CheckStatus::Ok);
    }
}
