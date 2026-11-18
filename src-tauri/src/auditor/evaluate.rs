//! Full 14-point audit execution (`evaluate_all_inner`) with per-check isolation and streaming progress.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::cache::{DNSBL_TTL, IPV6_TTL, OS_TTL, cached_check};
use super::evaluate_checks::{
    CHECK_LIMIT_IO, CHECK_LIMIT_LOCAL, resolver_view, run_dns_resolver_check, run_locale_check,
    run_timezone_check, run_udp_stun_check, tracked,
};
use super::probes::whoami;
use super::run_check::{blocking_check, run_check};
use super::{
    AuditProgress, Auditor, ProgressSink, ProviderId, RiskReport, check_all_dnsbl_with_doh,
    check_ipv6_leak_with_route, check_os_location_services_with, dnsbl, evaluate_dnsbl_report,
    evaluate_impossible_travel_with_pin_and_exit, evaluate_ip_pinning_for_route,
    evaluate_ip_reputation, evaluate_provider_geo, evaluate_reverse_dns_ptr_with_dns, leaks,
    lookup_tor, score_checks, seams,
};
use crate::auditor::ip_type::ExitIdentity;
use crate::routing::RouteSelection;
use crate::state::AppState;

impl Auditor {
    pub(super) async fn evaluate_all_inner(
        &self,
        provider: ProviderId,
        state: &AppState,
        selection: &RouteSelection,
        force_refresh_telemetry: bool,
        sink: Option<ProgressSink>,
    ) -> Result<RiskReport, String> {
        if force_refresh_telemetry {
            self.resolver.check_cache().os.clear().await;
        }
        let telemetry = self
            .resolve_for_selection(provider, state, selection, force_refresh_telemetry)
            .await?;
        if let Some(sink) = &sink {
            sink(AuditProgress::Telemetry {
                telemetry: telemetry.clone(),
            });
        }

        let matrix = Arc::new(self.rules.provider_matrix.read().await.clone());
        let dangerous_asns = Arc::new(self.rules.dangerous_asns.read().await.clone());
        let state_data = state.get_data().await;
        let cache = self.resolver.check_cache().clone();
        let env = self.env.clone();

        let bound_route = match selection {
            RouteSelection::Route(r) => Some(r),
            _ => None,
        };
        let via_zastava_key = bound_route.is_some();
        let route_label = bound_route.map(|r| r.label.clone());

        let provider_pinned = state_data.pinned_ips.get(provider.as_str()).cloned();
        let global_pinned = state_data
            .pinned_ips
            .get("default")
            .cloned()
            .or_else(|| state_data.pinned_ip.clone());
        let (pinning_verdict, is_pinned) = evaluate_ip_pinning_for_route(
            provider_pinned.as_deref(),
            global_pinned.as_deref(),
            state_data.strict_pinning_enabled,
            &telemetry.ip,
            route_label.as_deref(),
        );

        // The effective zone (None while the switch is off): flipping the switch changes the cache
        // keys below, so the checks never show a stale verdict until the TTL runs out.
        let sync_ai_tz_enabled = state_data.sync_ai_tz_enabled;
        let synced_tz = state_data.effective_sync_tz();
        let synced_key = synced_tz.clone().unwrap_or_default();
        let country = telemetry.country_code.clone();
        let dnsbl_label = Arc::new(Mutex::new("Не проверено".to_string()));
        let ipv6_exit = telemetry
            .ip
            .trim()
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_ipv6());

        // Every check runs isolated (own task, own time limit): a slow or panicking check ends
        // as `Unknown` and the others still finish.
        let geo = tracked(
            &sink,
            0,
            run_check("Geo Matrix", CHECK_LIMIT_LOCAL, {
                let (matrix, country) = (matrix.clone(), country.clone());
                async move { evaluate_provider_geo(&matrix, provider, &country) }
            }),
        );
        let pinning = tracked(
            &sink,
            1,
            run_check("IP Pinning", CHECK_LIMIT_LOCAL, async move {
                pinning_verdict
            }),
        );
        let geo_allows_travel_grace = {
            let geo = evaluate_provider_geo(&matrix, provider, &country);
            !country.trim().is_empty() && !geo.status.is_critical() && !geo.status.is_unknown()
        };
        let travel = tracked(
            &sink,
            2,
            run_check("Impossible Travel", CHECK_LIMIT_LOCAL, {
                let history = state_data.ip_history_for_selection(provider.as_str(), selection);
                let (country, resolved_at) = (country.clone(), telemetry.resolved_at);
                let current_ip = telemetry.ip.clone();
                let current_asn = telemetry.asn;
                let pinned_for_travel = is_pinned && geo_allows_travel_grace;
                async move {
                    evaluate_impossible_travel_with_pin_and_exit(
                        &history,
                        &country,
                        Some(&current_ip),
                        current_asn,
                        resolved_at,
                        provider,
                        pinned_for_travel,
                    )
                }
            }),
        );
        let dnsbl = tracked(
            &sink,
            3,
            run_check("DNSBL", Duration::from_secs(5), {
                let (cache, asns, ip, label, dns) = (
                    cache.clone(),
                    dangerous_asns.clone(),
                    telemetry.ip.clone(),
                    dnsbl_label.clone(),
                    env.dns.clone(),
                );
                let doh_dns = if self.use_env_probe_for_direct {
                    Some(Arc::new(dnsbl::DohDns::with_probe(env.probe.clone()))
                        as Arc<dyn seams::DnsLookup>)
                } else {
                    dnsbl::DohDns::real()
                        .ok()
                        .map(|d| Arc::new(d) as Arc<dyn seams::DnsLookup>)
                };
                async move {
                    let (result, summary) = cache
                        .dnsbl
                        .get_or_compute(&ip, DNSBL_TTL, |(r, _)| !r.is_unknown(), async {
                            let report = check_all_dnsbl_with_doh(dns, doh_dns, &ip, &asns).await;
                            (evaluate_dnsbl_report(&report), report.summary_label)
                        })
                        .await;
                    *label.lock().unwrap_or_else(|e| e.into_inner()) = summary;
                    result
                }
            }),
        );
        let asn = tracked(
            &sink,
            4,
            run_check("Address Reputation", CHECK_LIMIT_IO, {
                let (cache, asns, tel, env) = (
                    cache.clone(),
                    dangerous_asns.clone(),
                    telemetry.clone(),
                    env.clone(),
                );
                async move {
                    let tor = lookup_tor(&cache.tor, &*env.probe, &tel.ip).await;
                    evaluate_ip_reputation(
                        &ExitIdentity {
                            ip: &tel.ip,
                            country_code: &tel.country_code,
                            asn: tel.asn,
                            isp: tel.isp.as_deref(),
                            org: tel.org.as_deref(),
                        },
                        &asns,
                        tor,
                        is_pinned,
                    )
                }
            }),
        );
        let ipv6 = tracked(
            &sink,
            5,
            run_check("IPv6 Leak", CHECK_LIMIT_IO, {
                let (cache, matrix, country, env, split_tunnel_mode) = (
                    cache.clone(),
                    matrix.clone(),
                    country.clone(),
                    env.clone(),
                    state_data.split_tunnel_mode,
                );
                async move {
                    let key =
                        format!("{country}|split={split_tunnel_mode}|routed={via_zastava_key}");
                    cached_check(&cache.ipv6, &key, IPV6_TTL, async {
                        check_ipv6_leak_with_route(
                            &*env.probe,
                            &*env.system,
                            leaks::IPV6_CHECK_URL,
                            Duration::from_millis(leaks::IPV6_CHECK_TIMEOUT_MS),
                            &country,
                            &matrix.global_blocked_countries,
                            split_tunnel_mode,
                            via_zastava_key,
                        )
                        .await
                    })
                    .await
                }
            }),
        );
        let dns = tracked(
            &sink,
            6,
            run_dns_resolver_check(
                cache.clone(),
                dangerous_asns.clone(),
                country.clone(),
                env.clone(),
                via_zastava_key,
            ),
        );
        let timezone = tracked(
            &sink,
            7,
            run_timezone_check(
                cache.clone(),
                telemetry.timezone.clone(),
                synced_tz.clone(),
                env.clone(),
                sync_ai_tz_enabled,
            ),
        );
        let location = tracked(
            &sink,
            8,
            run_check("OS Location", CHECK_LIMIT_IO, {
                let (cache, env) = (cache.clone(), env.clone());
                async move {
                    cached_check(&cache.os, "location", OS_TTL, async {
                        let system = env.system.clone();
                        blocking_check(move || check_os_location_services_with(&*system)).await
                    })
                    .await
                }
            }),
        );
        let reverse_dns = tracked(
            &sink,
            9,
            run_check("Reverse DNS", CHECK_LIMIT_IO, {
                let tel = telemetry.clone();
                let dns = env.dns.clone();
                async move { evaluate_reverse_dns_ptr_with_dns(&tel, &*dns).await }
            }),
        );
        // Country of the resolver that sees the requests (whoami) against the exit country.
        let dns_country = tracked(
            &sink,
            10,
            run_check("DNS Country", CHECK_LIMIT_IO, {
                let (cache, country, env) = (cache.clone(), country.clone(), env.clone());
                async move {
                    let view = resolver_view(&env, &cache).await;
                    whoami::evaluate_dns_country_for_route(&view, &country, via_zastava_key)
                }
            }),
        );
        let locale = tracked(
            &sink,
            11,
            run_locale_check(
                cache.clone(),
                env.clone(),
                synced_tz.clone(),
                synced_key,
                sync_ai_tz_enabled,
            ),
        );

        // UDP leaves through the same address as HTTP? (STUN, per exit address, rare requests)
        let udp_stun = tracked(
            &sink,
            12,
            run_udp_stun_check(
                cache.clone(),
                env.clone(),
                telemetry.ip.trim().to_string(),
                self.resolver.clone(),
                via_zastava_key,
            ),
        );

        // Real AI provider exit verification (index 13, 14th check).
        let claude_exit = tracked(
            &sink,
            13,
            run_check("Provider Exit", CHECK_LIMIT_IO, {
                let resolver = self.resolver.clone();
                let bound_route = match selection {
                    RouteSelection::Route(r) => Some(r.clone()),
                    _ => None,
                };
                let tel = telemetry.clone();
                let matrix = matrix.clone();
                let probe = self.use_env_probe_for_direct.then(|| env.probe.clone());
                async move {
                    resolver
                        .probe_provider_exit_with_probe(
                            provider,
                            bound_route.as_ref(),
                            &tel,
                            &matrix,
                            probe.as_deref(),
                        )
                        .await
                }
            }),
        );

        let (
            geo_result,
            pinning_result,
            travel_result,
            dnsbl_result,
            asn_result,
            ipv6_result,
            dns_result,
            timezone_result,
            location_result,
            reverse_dns_result,
            dns_country_result,
            locale_result,
            udp_stun_result,
            claude_exit_result,
        ) = tokio::join!(
            geo,
            pinning,
            travel,
            dnsbl,
            asn,
            ipv6,
            dns,
            timezone,
            location,
            reverse_dns,
            dns_country,
            locale,
            udp_stun,
            claude_exit
        );
        let dnsbl_clean_count = dnsbl_label
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let checks = vec![
            geo_result.clone(),
            pinning_result.clone(),
            travel_result.clone(),
            dnsbl_result.clone(),
            asn_result.clone(),
            ipv6_result.clone(),
            dns_result,
            timezone_result.clone(),
            location_result,
            reverse_dns_result,
            dns_country_result,
            locale_result,
            // Index 12: not a core check.
            udp_stun_result,
            // Index 13 (`claude_exit`): provider-specific exit verification.
            claude_exit_result,
        ];
        let verdict = score_checks(&checks, is_pinned);
        self.journal_incomplete(provider, &checks);

        Ok(RiskReport {
            provider,
            overall_status: verdict.overall_status,
            trust_score: verdict.trust_score,
            telemetry,
            geo_result,
            pinning_result,
            travel_result,
            dnsbl_result,
            dnsbl_clean_count,
            asn_result,
            ipv6_result,
            timezone_result,
            ipv6_exit,
            checks,
            unknown_count: verdict.unknown_count,
            applicable_count: verdict.applicable_count,
            incomplete: verdict.incomplete,
        })
    }
}
