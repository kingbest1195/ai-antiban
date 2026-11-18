//! Real AI provider exit verification probes and trace parsing.

use std::net::IpAddr;
use std::time::Duration;

use super::cascade::{IpInfoResponse, build_entry_client};
use super::resolver::NetworkResolver;
use super::{NEUTRAL_USER_AGENT, NetworkTelemetry, REQUEST_TIMEOUT_MS};
use crate::auditor::geo_matrix::{
    CheckResult, CheckStatus, ProviderId, UnknownReason, evaluate_provider_geo,
};
use crate::auditor::rules::ProviderMatrix;
use crate::auditor::seams::{HttpProbeOutcome, IpProbe};
use crate::routing::Route;

impl NetworkResolver {
    /// Probes the actual exit observed by the active AI provider (via its bound route if any,
    /// or the system direct client otherwise) to catch split-tunnel / QUIC / PAC leaks.
    pub async fn probe_provider_exit(
        &self,
        provider: ProviderId,
        route: Option<&Route>,
        telemetry: &NetworkTelemetry,
        matrix: &ProviderMatrix,
    ) -> CheckResult {
        self.probe_provider_exit_with_probe(provider, route, telemetry, matrix, None)
            .await
    }

    /// Variant of [`Self::probe_provider_exit`] that routes direct (unbound) probes through an
    /// injected [`IpProbe`] when provided by `Auditor::with_env` tests.
    pub async fn probe_provider_exit_with_probe(
        &self,
        provider: ProviderId,
        route: Option<&Route>,
        telemetry: &NetworkTelemetry,
        matrix: &ProviderMatrix,
        direct_probe: Option<&dyn IpProbe>,
    ) -> CheckResult {
        let url_override = default_exit_probe_url(provider, route.is_some());
        self.probe_provider_exit_inner(
            provider,
            route,
            telemetry,
            matrix,
            url_override,
            None,
            direct_probe,
            Duration::from_millis(REQUEST_TIMEOUT_MS),
        )
        .await
    }

    /// Testable core of [`Self::probe_provider_exit`]: probes `probe_url` directly or through
    /// `route`'s entry nodes (falling back to `client_override` / custom `timeout` in tests).
    #[allow(clippy::too_many_arguments)]
    pub async fn probe_provider_exit_with_url(
        &self,
        provider: ProviderId,
        route: Option<&Route>,
        telemetry: &NetworkTelemetry,
        matrix: &ProviderMatrix,
        probe_url: &str,
        client_override: Option<&reqwest::Client>,
        timeout: Duration,
    ) -> CheckResult {
        self.probe_provider_exit_inner(
            provider,
            route,
            telemetry,
            matrix,
            probe_url,
            client_override,
            None,
            timeout,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn probe_provider_exit_inner(
        &self,
        provider: ProviderId,
        route: Option<&Route>,
        telemetry: &NetworkTelemetry,
        matrix: &ProviderMatrix,
        probe_url: &str,
        client_override: Option<&reqwest::Client>,
        direct_probe: Option<&dyn IpProbe>,
        timeout: Duration,
    ) -> CheckResult {
        if provider == ProviderId::Gemini && route.is_none() {
            return CheckResult::unknown(
                "PROVIDER_EXIT_NOT_APPLICABLE",
                "Выход не проверен напрямую: Google Gemini не отдает /cdn-cgi/trace на прямом маршруте.",
                UnknownReason::NotApplicable,
            )
            .with_measured_via("gemini (без отдельного маршрута)");
        }

        // Never send unbound (route: None) probes to provider domains (claude.ai / chatgpt.com)
        // from the user's real IP; use neutral IP/geo endpoints (or chained proxy if configured).
        let effective_url = if route.is_none() && is_provider_domain_url(probe_url) {
            NEUTRAL_EXIT_PROBE_URL
        } else {
            probe_url
        };

        let gateway_port = self.gateway_port();
        let chained_client = if route.is_none() && client_override.is_none() && direct_probe.is_none()
        {
            crate::sysproxy::get_chained_proxy()
                .filter(|cp| {
                    !crate::sysproxy::is_gateway_host_port(
                        cp,
                        (gateway_port > 0).then_some(gateway_port),
                    )
                })
                .and_then(|cp| build_chained_probe_client(&cp, timeout))
        } else {
            None
        };

        let via_host = if route.is_some() {
            match provider {
                ProviderId::Anthropic => "claude.ai",
                ProviderId::Openai => "chatgpt.com",
                ProviderId::Gemini => "gemini (ipinfo.io)",
            }
        } else {
            "1.1.1.1"
        };
        let via_label = if route.is_some() {
            format!("{via_host} (маршрут ключа)")
        } else if chained_client.is_some() {
            format!("{via_host} (chained proxy)")
        } else {
            via_host.to_string()
        };

        let response = if let Some(c) = client_override {
            probe_url_with_client(c, effective_url, timeout).await
        } else if let Some(r) = route {
            if r.entries.is_empty() {
                return CheckResult::unknown(
                    "PROVIDER_EXIT_NO_ROUTE_ENTRY",
                    format!(
                        "Не удалось проверить реальный выход {}: у маршрута нет входных узлов.",
                        provider.display_name()
                    ),
                    UnknownReason::NoData,
                )
                .with_measured_via(via_label);
            }
            let allow_local = r.allows_local_entries();
            let mut last_err = ProbeFetchError::Unreachable("no route entry attempted".into());
            let mut fetched = None;
            for entry in &r.entries {
                match build_entry_client(entry, allow_local, gateway_port).await {
                    Ok(c) => match probe_url_with_client(&c, effective_url, timeout).await {
                        Ok(payload) => {
                            fetched = Some(payload);
                            break;
                        }
                        Err(e) => last_err = e,
                    },
                    Err(e) => last_err = ProbeFetchError::Unreachable(e),
                }
            }
            match fetched {
                Some(ok) => Ok(ok),
                None => Err(last_err),
            }
        } else if let Some(probe) = direct_probe {
            match probe.get(effective_url, timeout).await {
                HttpProbeOutcome::Response { status, body } => Ok((status, body)),
                HttpProbeOutcome::Timeout => Err(ProbeFetchError::Timeout),
                HttpProbeOutcome::ConnectFailed
                | HttpProbeOutcome::ReadFailed
                | HttpProbeOutcome::ClientError => {
                    Err(ProbeFetchError::Unreachable("probe transport error".into()))
                }
            }
        } else if let Some(c) = chained_client.as_ref() {
            probe_url_with_client(c, effective_url, timeout).await
        } else {
            probe_url_with_client(&self.client, effective_url, timeout).await
        };

        let (status, body) = match response {
            Ok(pair) => pair,
            Err(ProbeFetchError::Timeout) => {
                return CheckResult::unknown(
                    "PROVIDER_EXIT_TIMEOUT",
                    format!(
                        "Таймаут проверки реального выхода {} через {}: источник не ответил вовремя.",
                        provider.display_name(),
                        via_host
                    ),
                    UnknownReason::Timeout,
                )
                .with_measured_via(via_label);
            }
            Err(ProbeFetchError::Unreachable(e)) => {
                return CheckResult::unknown(
                    "PROVIDER_EXIT_UNREACHABLE",
                    format!(
                        "Не удалось проверить реальный выход {} через {}: {e}",
                        provider.display_name(),
                        via_host
                    ),
                    UnknownReason::NetworkError,
                )
                .with_measured_via(via_label);
            }
        };

        if status == 403 || !(200..300).contains(&status) || looks_like_html(&body) {
            return CheckResult::unknown(
                "PROVIDER_EXIT_REFUSED",
                format!(
                    "Источник {} отклонил проверку реального выхода (HTTP {status} или anti-bot страница).",
                    via_host
                ),
                UnknownReason::SourceRefused,
            )
            .with_measured_via(via_label);
        }

        let (exit_ip, trace_loc, colo) = if provider == ProviderId::Gemini {
            match parse_gemini_exit_probe(&body) {
                Some((ip, loc)) => (ip, loc, None),
                None => {
                    return CheckResult::unknown(
                        "PROVIDER_EXIT_REFUSED",
                        format!(
                            "Не удалось разобрать ответ проверки реального выхода {}.",
                            via_host
                        ),
                        UnknownReason::SourceRefused,
                    )
                    .with_measured_via(via_label);
                }
            }
        } else {
            match parse_cloudflare_trace(&body) {
                Some(trace) => (trace.ip, trace.loc, trace.colo),
                None => {
                    return CheckResult::unknown(
                        "PROVIDER_EXIT_REFUSED",
                        format!(
                            "Ответ {} не содержит корректного поля ip= для проверки выхода.",
                            via_host
                        ),
                        UnknownReason::SourceRefused,
                    )
                    .with_measured_via(via_label);
                }
            }
        };

        let effective_cc = trace_loc
            .as_deref()
            .filter(|cc| !cc.is_empty() && !matches!(*cc, "XX" | "ZZ"))
            .unwrap_or(&telemetry.country_code);
        let geo = evaluate_provider_geo(matrix, provider, effective_cc);
        if geo.status == CheckStatus::Critical {
            return CheckResult::critical(
                "PROVIDER_EXIT_BLOCKED_COUNTRY",
                format!(
                    "Реальный выход {} ({}) определен как {} ({exit_ip}): {}",
                    provider.display_name(),
                    via_host,
                    effective_cc,
                    geo.message
                ),
                geo.guide_ref,
            )
            .with_measured_via(via_label);
        }

        if route.is_none() && exit_ip != telemetry.ip {
            return CheckResult::warning(
                "PROVIDER_EXIT_SPLIT_MISMATCH",
                format!(
                    "Маршрут ИИ ({exit_ip}, {effective_cc}) и общий выход ({}) различаются (split tunnel/PAC) — проверьте настройки прокси и QUIC/DoH.",
                    telemetry.ip
                ),
                geo.guide_ref,
            )
            .with_measured_via(via_label);
        }

        if geo.status == CheckStatus::Warning {
            return CheckResult::warning(
                "PROVIDER_EXIT_GEO_WARNING",
                format!(
                    "Реальный выход {} ({exit_ip}, {effective_cc}): {}",
                    via_host, geo.message
                ),
                geo.guide_ref,
            )
            .with_measured_via(via_label);
        }

        let colo_note = colo
            .as_deref()
            .map(|c| format!(", POP {c}"))
            .unwrap_or_default();
        let route_note = if route.is_some() && exit_ip != telemetry.ip {
            format!("; отличается от общей телеметрии маршрута {}", telemetry.ip)
        } else {
            String::new()
        };
        CheckResult::ok(
            "PROVIDER_EXIT_VERIFIED",
            format!(
                "Реальный выход {} подтвержден: {exit_ip} ({effective_cc}{colo_note}){route_note}.",
                provider.display_name()
            ),
        )
        .with_measured_via(via_label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareTrace {
    pub ip: String,
    pub loc: Option<String>,
    pub colo: Option<String>,
}

/// Parses a Cloudflare `/cdn-cgi/trace` key=value response, validating that `ip=` is a real IP address.
pub fn parse_cloudflare_trace(text: &str) -> Option<CloudflareTrace> {
    let mut ip: Option<String> = None;
    let mut loc: Option<String> = None;
    let mut colo: Option<String> = None;

    for line in text.lines() {
        if let Some(val) = line.strip_prefix("ip=") {
            let trimmed = val.trim();
            if trimmed.parse::<IpAddr>().is_ok() {
                ip = Some(trimmed.to_string());
            }
        } else if let Some(val) = line.strip_prefix("loc=") {
            let trimmed = val.trim().to_uppercase();
            if !trimmed.is_empty() {
                loc = Some(trimmed);
            }
        } else if let Some(val) = line.strip_prefix("colo=") {
            let trimmed = val.trim().to_uppercase();
            if !trimmed.is_empty() {
                colo = Some(trimmed);
            }
        }
    }

    ip.map(|ip| CloudflareTrace { ip, loc, colo })
}

fn looks_like_html(body: &str) -> bool {
    let trimmed = body.trim_start();
    trimmed.starts_with('<')
        || trimmed.get(..64).is_some_and(|head| {
            let lower = head.to_ascii_lowercase();
            lower.contains("<!doctype") || lower.contains("<html")
        })
}

fn parse_gemini_exit_probe(body: &str) -> Option<(String, Option<String>)> {
    if let Ok(parsed) = serde_json::from_str::<IpInfoResponse>(body)
        && let Some(ip) = parsed.ip.filter(|s| s.trim().parse::<IpAddr>().is_ok())
    {
        let loc = parsed.country.map(|c| c.trim().to_uppercase());
        return Some((ip.trim().to_string(), loc));
    }
    let trimmed = body.trim();
    if trimmed.parse::<IpAddr>().is_ok() {
        return Some((trimmed.to_string(), None));
    }
    None
}

const NEUTRAL_EXIT_PROBE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";

fn is_provider_domain_url(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .is_some_and(|h| {
            h == "claude.ai"
                || h.ends_with(".claude.ai")
                || h == "chatgpt.com"
                || h.ends_with(".chatgpt.com")
        })
}

fn build_chained_probe_client(chained: &str, timeout: Duration) -> Option<reqwest::Client> {
    let proxy_url = if chained.contains("://") {
        chained.to_string()
    } else {
        format!("http://{chained}")
    };
    let proxy = reqwest::Proxy::all(&proxy_url).ok()?;
    reqwest::Client::builder()
        .timeout(timeout)
        .pool_max_idle_per_host(0)
        .user_agent(NEUTRAL_USER_AGENT)
        .proxy(proxy)
        .build()
        .ok()
}

pub(super) fn default_exit_probe_url(provider: ProviderId, has_route: bool) -> &'static str {
    if !has_route {
        return NEUTRAL_EXIT_PROBE_URL;
    }
    match provider {
        ProviderId::Anthropic => "https://claude.ai/cdn-cgi/trace",
        ProviderId::Openai => "https://chatgpt.com/cdn-cgi/trace",
        ProviderId::Gemini => "https://ipinfo.io/json",
    }
}

enum ProbeFetchError {
    Timeout,
    Unreachable(String),
}

async fn probe_url_with_client(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
) -> Result<(u16, String), ProbeFetchError> {
    let resp = client.get(url).timeout(timeout).send().await.map_err(|e| {
        if e.is_timeout() {
            ProbeFetchError::Timeout
        } else {
            ProbeFetchError::Unreachable(e.to_string())
        }
    })?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|e| {
        if e.is_timeout() {
            ProbeFetchError::Timeout
        } else {
            ProbeFetchError::Unreachable(e.to_string())
        }
    })?;
    Ok((status, body))
}
