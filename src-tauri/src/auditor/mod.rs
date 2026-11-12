pub mod cache;
pub mod cache_cleaner;
pub mod claude_exporter;
pub mod dnsbl;
pub mod geo_matrix;
pub mod history;
pub mod leaks;
pub mod network;
pub mod os_env;
pub mod probes;
pub mod profile_switcher;
pub mod rules;
pub mod run_check;
pub mod seams;
pub mod telemetry;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cache::{CheckCache, DNSBL_TTL, IPV6_TTL, OS_TTL, UDP_TTL, WHOAMI_TTL, cached_check};
use probes::whoami::{self, ResolverView, evaluate_dns_country};
use probes::stun;
use run_check::{blocking_check, run_check};

pub use cache_cleaner::clean_ai_app_cache;
pub use dnsbl::{check_all_dnsbl, check_all_dnsbl_with, evaluate_asn_reputation, evaluate_dnsbl_report};
pub use geo_matrix::{CheckResult, CheckStatus, ProviderId, UnknownReason, evaluate_provider_geo};
pub use history::{evaluate_impossible_travel, evaluate_ip_pinning};
pub use leaks::{
    check_dns_leak, check_dns_leak_with, check_ipv6_leak, check_ipv6_leak_with, evaluate_dns_resolver,
};
pub use network::{
    build_upstream_client, evaluate_dns_country_consistency, evaluate_reverse_dns_ptr,
    NetworkResolver, NetworkTelemetry,
};
pub use os_env::{
    check_os_location_services, check_os_location_services_with, evaluate_locale_env_hygiene,
    evaluate_locale_env_hygiene_with, evaluate_system_timezone, evaluate_system_timezone_with,
};
pub use seams::AuditEnv;
pub use rules::RuleSet;
use crate::routing::{Route, RouteSelection};
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverallStatus {
    Green,
    Yellow,
    Red,
}

impl OverallStatus {
    pub fn is_allowed_by_default(&self) -> bool {
        matches!(self, OverallStatus::Green)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReport {
    pub provider: ProviderId,
    pub overall_status: OverallStatus,
    pub trust_score: u8,
    pub telemetry: NetworkTelemetry,
    pub geo_result: CheckResult,
    pub pinning_result: CheckResult,
    pub travel_result: CheckResult,
    pub dnsbl_result: CheckResult,
    pub dnsbl_clean_count: String,
    pub asn_result: CheckResult,
    pub ipv6_result: CheckResult,
    pub timezone_result: CheckResult,
    pub checks: Vec<CheckResult>,
    /// Checks that could not be performed (`Unknown`), not counting the not-applicable ones.
    #[serde(default)]
    pub unknown_count: u8,
    /// Checks that apply to this setup (all, minus the not-applicable ones).
    #[serde(default)]
    pub applicable_count: u8,
    /// `unknown_count > 0`: part of the protection was not verified, the report is not a clean bill.
    #[serde(default)]
    pub incomplete: bool,
}

/// A piece of an audit as soon as it is ready: the interface shows each check when it finishes
/// instead of waiting for the slowest one.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditProgress {
    /// The exit address is known (IP, country, provider).
    Telemetry { telemetry: NetworkTelemetry },
    /// Check number `index` of `RiskReport::checks` is done.
    Check { index: usize, result: CheckResult },
}

/// Receiver of [`AuditProgress`]; must not block.
pub type ProgressSink = Arc<dyn Fn(AuditProgress) + Send + Sync>;

/// Runs a check future and reports its result to the sink (if any) when it completes.
async fn tracked<F>(sink: &Option<ProgressSink>, index: usize, check: F) -> CheckResult
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

/// Time limit of a check that only computes (no I/O of its own).
const CHECK_LIMIT_LOCAL: Duration = Duration::from_secs(2);
/// Time limit of a check that talks to the network or runs a child process.
const CHECK_LIMIT_IO: Duration = Duration::from_secs(4);

/// Positions in `RiskReport::checks` of the core checks (geo matrix, impossible travel): when one
/// of them could not be performed the gateway must not let traffic through on its own (fail-closed).
/// An `Unknown` in any other check is shown, but does not change the admit decision.
const CORE_CHECKS: [usize; 2] = [0, 2];

/// The DNS resolver that sees the requests of this machine (both whoami sources + its country),
/// measured once for the DNS-resolver and the DNS-country checks.
async fn resolver_view(env: &AuditEnv, cache: &CheckCache) -> ResolverView {
    cache
        .resolver
        .get_or_compute(
            "whoami",
            WHOAMI_TTL,
            |v| v.is_located(),
            whoami::measure_resolver(&*env.dns, &*env.probe, &cache.geo),
        )
        .await
}

/// Outcome of scoring the checks of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub overall_status: OverallStatus,
    pub trust_score: u8,
    pub unknown_count: u8,
    pub applicable_count: u8,
    pub incomplete: bool,
}

/// `(unknown_count, applicable_count)`: not-applicable checks are in neither.
pub fn count_checks(checks: &[CheckResult]) -> (u8, u8) {
    let not_applicable = checks.iter().filter(|c| c.is_not_applicable()).count();
    let unknown = checks.iter().filter(|c| c.is_unknown()).count() - not_applicable;
    let applicable = checks.len() - not_applicable;
    (unknown.min(255) as u8, applicable.min(255) as u8)
}

/// Critical -40, Warning -15, Unknown -5 (the sum of the Unknown penalties is capped at -15);
/// not-applicable checks cost nothing. With any Unknown the score never exceeds 94.
pub fn score_checks(checks: &[CheckResult], is_pinned: bool) -> Verdict {
    const UNKNOWN_PENALTY: i32 = 5;
    const UNKNOWN_PENALTY_CAP: i32 = 15;
    const MAX_SCORE_WITH_UNKNOWN: i32 = 94;

    let (unknown_count, applicable_count) = count_checks(checks);
    let mut score: i32 = 100;
    let mut has_critical = false;
    let mut has_warning = false;

    for check in checks {
        match check.status {
            CheckStatus::Critical => {
                has_critical = true;
                score -= 40;
            }
            CheckStatus::Warning => {
                has_warning = true;
                score -= 15;
            }
            CheckStatus::Ok | CheckStatus::Unknown => {}
        }
    }
    score -= (i32::from(unknown_count) * UNKNOWN_PENALTY).min(UNKNOWN_PENALTY_CAP);

    // A core check that could not be performed can never end in an automatic "green".
    let core_unknown = CORE_CHECKS
        .iter()
        .filter_map(|&i| checks.get(i))
        .any(|c| c.is_unknown() && !c.is_not_applicable());

    if is_pinned && !has_critical {
        score = (score + 10).min(100);
    }
    if unknown_count > 0 {
        score = score.min(MAX_SCORE_WITH_UNKNOWN);
    }

    let overall_status = if has_critical {
        score = score.clamp(0, 35);
        OverallStatus::Red
    } else if has_warning || core_unknown {
        score = score.clamp(36, 85);
        OverallStatus::Yellow
    } else {
        score = score.clamp(
            86,
            if unknown_count > 0 {
                MAX_SCORE_WITH_UNKNOWN
            } else {
                100
            },
        );
        OverallStatus::Green
    };

    Verdict {
        overall_status,
        trust_score: score as u8,
        unknown_count,
        applicable_count,
        incomplete: unknown_count > 0,
    }
}

#[derive(Clone)]
pub struct Auditor {
    pub rules: RuleSet,
    pub resolver: NetworkResolver,
    /// DNS, HTTP probe and host reads of the checks (replaceable in tests).
    env: AuditEnv,
    /// Last logged set of unfinished checks per provider (the journal gets a line on change only).
    incomplete_logged: Arc<Mutex<HashMap<String, String>>>,
}

impl Default for Auditor {
    fn default() -> Self {
        Self::new().expect("Failed to initialize default Auditor")
    }
}

impl Auditor {
    pub fn new() -> Result<Self, String> {
        let rules = RuleSet::load_bundled().map_err(|e| e.to_string())?;
        let resolver = NetworkResolver::new();
        Ok(Self {
            rules,
            resolver,
            env: AuditEnv::real(),
            incomplete_logged: Arc::default(),
        })
    }

    /// An auditor whose DNS, probe and host reads come from `env` (tests: no network, no processes).
    pub fn with_env(env: AuditEnv) -> Result<Self, String> {
        Ok(Self {
            env,
            ..Self::new()?
        })
    }

    /// Telemetry of the egress `provider` traffic actually uses: its route, or direct.
    /// A selected but unusable route is an error (never silently replaced by the direct egress).
    pub async fn resolve_for_provider(
        &self,
        provider: ProviderId,
        state: &AppState,
        force_refresh: bool,
    ) -> Result<NetworkTelemetry, String> {
        let selection = state.route_selection(provider.as_str()).await;
        self.resolve_for_selection(provider, state, &selection, force_refresh)
            .await
    }

    /// Same as [`Self::resolve_for_provider`] for an already taken route snapshot, so that an
    /// audit and the tunnel it admits work with the very same route.
    pub async fn resolve_for_selection(
        &self,
        provider: ProviderId,
        state: &AppState,
        selection: &RouteSelection,
        force_refresh: bool,
    ) -> Result<NetworkTelemetry, String> {
        match selection {
            RouteSelection::Direct => self.resolver.resolve(force_refresh).await,
            RouteSelection::Missing(id) => Err(format!(
                "Маршрут {id} для {} не найден: ключ удалён, трафик заблокирован",
                provider.display_name()
            )),
            RouteSelection::Invalid(why) => Err(format!(
                "Ключ профиля Claude недействителен ({why}): трафик {} заблокирован",
                provider.display_name()
            )),
            RouteSelection::Route(route) => {
                if let Err(reason) = route.check_usable(network::current_timestamp()) {
                    return Err(format!(
                        "Маршрут «{}» недоступен ({}): трафик {} заблокирован",
                        route.label,
                        reason.message_ru(),
                        provider.display_name()
                    ));
                }
                self.resolve_route(route, state, force_refresh).await
            }
        }
    }

    /// Resolves the exit of a route and records it (incl. the declared `exit_ip` check).
    pub async fn resolve_route(
        &self,
        route: &Route,
        state: &AppState,
        force_refresh: bool,
    ) -> Result<NetworkTelemetry, String> {
        let tel = self
            .resolver
            .resolve_with_route(force_refresh, Some(route))
            .await?;
        state.route_health().record_exit(
            &route.id,
            &tel.ip,
            &tel.country_code,
            route.exit_ip.as_deref(),
        );
        Ok(tel)
    }

    /// Evaluates the complete 13-point risk assessment for the target AI provider,
    /// on the egress of that provider's route (or the direct egress).
    pub async fn evaluate_all(
        &self,
        provider: ProviderId,
        state: &AppState,
        force_refresh_telemetry: bool,
    ) -> Result<RiskReport, String> {
        let selection = state.route_selection(provider.as_str()).await;
        self.evaluate_all_with(provider, state, &selection, force_refresh_telemetry)
            .await
    }

    /// [`Self::evaluate_all`] that also reports the exit address and every check to `sink` as
    /// soon as it is ready (the final report is the return value, as always).
    pub async fn evaluate_all_progress(
        &self,
        provider: ProviderId,
        state: &AppState,
        force_refresh_telemetry: bool,
        sink: Option<ProgressSink>,
    ) -> Result<RiskReport, String> {
        let selection = state.route_selection(provider.as_str()).await;
        self.evaluate_all_inner(provider, state, &selection, force_refresh_telemetry, sink)
            .await
    }

    /// [`Self::evaluate_all`] on an already taken route snapshot (see [`Self::resolve_for_selection`]).
    pub async fn evaluate_all_with(
        &self,
        provider: ProviderId,
        state: &AppState,
        selection: &RouteSelection,
        force_refresh_telemetry: bool,
    ) -> Result<RiskReport, String> {
        self.evaluate_all_inner(provider, state, selection, force_refresh_telemetry, None)
            .await
    }

    async fn evaluate_all_inner(
        &self,
        provider: ProviderId,
        state: &AppState,
        selection: &RouteSelection,
        force_refresh_telemetry: bool,
        sink: Option<ProgressSink>,
    ) -> Result<RiskReport, String> {
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

        let is_pinned = match &state_data.pinned_ip {
            Some(pinned) => pinned.trim() == telemetry.ip.trim(),
            None => false,
        };
        // The effective zone (None while the switch is off): flipping the switch changes the cache
        // keys below, so the checks never show a stale verdict until the TTL runs out.
        let synced_tz = state_data.effective_sync_tz();
        let synced_key = synced_tz.clone().unwrap_or_default();
        let country = telemetry.country_code.clone();
        let dnsbl_label = Arc::new(Mutex::new("Не проверено".to_string()));

        // Every check runs isolated (own task, own time limit): a slow or panicking check ends
        // as `Unknown` and the others still finish.
        let geo = tracked(&sink, 0, run_check("Geo Matrix", CHECK_LIMIT_LOCAL, {
            let (matrix, country) = (matrix.clone(), country.clone());
            async move { evaluate_provider_geo(&matrix, provider, &country) }
        }));
        let pinning = tracked(&sink, 1, run_check("IP Pinning", CHECK_LIMIT_LOCAL, {
            let (pinned, strict, ip) = (
                state_data.pinned_ip.clone(),
                state_data.strict_pinning_enabled,
                telemetry.ip.clone(),
            );
            async move { evaluate_ip_pinning(pinned.as_deref(), strict, &ip) }
        }));
        let travel = tracked(&sink, 2, run_check("Impossible Travel", CHECK_LIMIT_LOCAL, {
            let history = state_data
                .ip_history
                .get(provider.as_str())
                .cloned()
                .unwrap_or_default();
            let (country, resolved_at) = (country.clone(), telemetry.resolved_at);
            async move { evaluate_impossible_travel(&history, &country, resolved_at, provider) }
        }));
        let dnsbl = tracked(&sink, 3, run_check("DNSBL", CHECK_LIMIT_IO, {
            let (cache, asns, ip, label, dns) = (
                cache.clone(),
                dangerous_asns.clone(),
                telemetry.ip.clone(),
                dnsbl_label.clone(),
                env.dns.clone(),
            );
            async move {
                let (result, summary) = cache
                    .dnsbl
                    .get_or_compute(&ip, DNSBL_TTL, |(r, _)| !r.is_unknown(), async {
                        let report = check_all_dnsbl_with(dns, &ip, &asns).await;
                        (evaluate_dnsbl_report(&report), report.summary_label)
                    })
                    .await;
                *label.lock().unwrap_or_else(|e| e.into_inner()) = summary;
                result
            }
        }));
        let asn = tracked(&sink, 4, run_check("ASN Reputation", CHECK_LIMIT_LOCAL, {
            let (asns, tel) = (dangerous_asns.clone(), telemetry.clone());
            async move {
                evaluate_asn_reputation(
                    tel.asn,
                    tel.isp.as_deref(),
                    tel.org.as_deref(),
                    &asns,
                    is_pinned,
                )
            }
        }));
        let ipv6 = tracked(&sink, 5, run_check("IPv6 Leak", CHECK_LIMIT_IO, {
            let (cache, matrix, country, env) =
                (cache.clone(), matrix.clone(), country.clone(), env.clone());
            async move {
                cached_check(&cache.ipv6, &country, IPV6_TTL, async {
                    check_ipv6_leak_with(
                        &*env.probe,
                        &*env.system,
                        leaks::IPV6_CHECK_URL,
                        Duration::from_millis(leaks::IPV6_CHECK_TIMEOUT_MS),
                        &country,
                        &matrix.global_blocked_countries,
                    )
                    .await
                })
                .await
            }
        }));
        let dns = tracked(&sink, 6, run_check("DNS Resolver", CHECK_LIMIT_IO, {
            let (cache, asns, country, env) =
                (cache.clone(), dangerous_asns.clone(), country.clone(), env.clone());
            async move {
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
                evaluate_dns_resolver(config, &view, &country)
            }
        }));
        let timezone = tracked(&sink, 7, run_check("Timezone", CHECK_LIMIT_IO, {
            let (cache, ip_tz, synced, env) = (
                cache.clone(),
                telemetry.timezone.clone(),
                synced_tz.clone(),
                env.clone(),
            );
            async move {
                let key = format!(
                    "tz:{}|{}",
                    ip_tz.as_deref().unwrap_or_default(),
                    synced.as_deref().unwrap_or_default()
                );
                cached_check(&cache.os, &key, OS_TTL, async {
                    let system = env.system.clone();
                    blocking_check(move || {
                        evaluate_system_timezone_with(&*system, ip_tz.as_deref(), synced.as_deref())
                    })
                    .await
                })
                .await
            }
        }));
        let location = tracked(&sink, 8, run_check("OS Location", CHECK_LIMIT_IO, {
            let (cache, env) = (cache.clone(), env.clone());
            async move {
                cached_check(&cache.os, "location", OS_TTL, async {
                    let system = env.system.clone();
                    blocking_check(move || check_os_location_services_with(&*system)).await
                })
                .await
            }
        }));
        let reverse_dns = tracked(&sink, 9, run_check("Reverse DNS", CHECK_LIMIT_LOCAL, {
            let tel = telemetry.clone();
            async move { evaluate_reverse_dns_ptr(&tel) }
        }));
        // Country of the resolver that sees the requests (whoami) against the exit country.
        let dns_country = tracked(&sink, 10, run_check("DNS Country", CHECK_LIMIT_IO, {
            let (cache, country, env) = (cache.clone(), country.clone(), env.clone());
            async move {
                let view = resolver_view(&env, &cache).await;
                evaluate_dns_country(&view, &country)
            }
        }));
        let locale = tracked(&sink, 11, run_check("Locale", CHECK_LIMIT_IO, {
            let (cache, env) = (cache.clone(), env.clone());
            async move {
                cached_check(&cache.os, &format!("locale:{synced_key}"), OS_TTL, async {
                    let system = env.system.clone();
                    blocking_check(move || {
                        evaluate_locale_env_hygiene_with(&*system, synced_tz.as_deref())
                    })
                    .await
                })
                .await
            }
        }));

        // UDP leaves through the same address as HTTP? (STUN, per exit address, rare requests)
        let udp_stun = tracked(&sink, 12, run_check("UDP STUN", CHECK_LIMIT_IO, {
            let (cache, env, ip) = (cache.clone(), env.clone(), telemetry.ip.trim().to_string());
            async move {
                cached_check(&cache.udp, &ip, UDP_TTL, async {
                    let answers = stun::probe_servers(&*env.udp, stun::STUN_TIMEOUT).await;
                    stun::evaluate_udp_stun(&answers, &ip)
                })
                .await
            }
        }));

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
            udp_stun
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
            checks,
            unknown_count: verdict.unknown_count,
            applicable_count: verdict.applicable_count,
            incomplete: verdict.incomplete,
        })
    }

    /// Writes a journal line when the set of checks that could not be performed changes
    /// (audits run every few seconds, so an unchanged state is not repeated).
    fn journal_incomplete(&self, provider: ProviderId, checks: &[CheckResult]) {
        let unfinished: Vec<&str> = checks
            .iter()
            .filter(|c| c.is_unknown() && !c.is_not_applicable())
            .map(|c| c.code.as_str())
            .collect();
        let signature = unfinished.join(",");
        let mut logged = self
            .incomplete_logged
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous = logged.get(provider.as_str()).cloned().unwrap_or_default();
        if previous == signature {
            return;
        }
        if unfinished.is_empty() {
            eprintln!(
                "Застава: проверка {} снова полная (все применимые проверки выполнены)",
                provider.as_str()
            );
        } else {
            eprintln!(
                "Застава: проверка {} неполная: не удалось выполнить {} ({})",
                provider.as_str(),
                unfinished.len(),
                signature
            );
        }
        logged.insert(provider.as_str().to_string(), signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overall_status_allowed() {
        assert!(OverallStatus::Green.is_allowed_by_default());
        assert!(!OverallStatus::Yellow.is_allowed_by_default());
        assert!(!OverallStatus::Red.is_allowed_by_default());
    }

    #[tokio::test]
    async fn test_auditor_initialization() {
        let auditor = Auditor::new().expect("Auditor initialization should succeed");
        let matrix = auditor.rules.provider_matrix.read().await;
        assert_eq!(matrix.version, "1.0.0");
    }

    fn ok() -> CheckResult {
        CheckResult::ok("OK", "ok")
    }
    fn unk() -> CheckResult {
        CheckResult::unknown("U", "u", UnknownReason::Timeout)
    }
    fn na() -> CheckResult {
        CheckResult::unknown("NA", "na", UnknownReason::NotApplicable)
    }
    /// The 13 results of a report in order, `ok()` everywhere except the given positions.
    fn all_checks(over: &[(usize, CheckResult)]) -> Vec<CheckResult> {
        let mut v: Vec<CheckResult> = (0..CHECK_COUNT).map(|_| ok()).collect();
        for (i, r) in over {
            v[*i] = r.clone();
        }
        v
    }

    /// Number of checks in a report (`udp_stun` is the 13th, index 12).
    const CHECK_COUNT: usize = 13;

    #[test]
    fn score_twelve_ok_and_one_unknown_is_below_100_and_green() {
        let v = score_checks(&all_checks(&[(3, unk())]), false);
        assert_eq!(v.overall_status, OverallStatus::Green);
        assert!(v.trust_score < 100);
        assert_eq!(v.trust_score, 94);
        assert!(v.incomplete);
    }

    #[test]
    fn score_thirteen_ok_is_100() {
        let v = score_checks(&all_checks(&[]), false);
        assert_eq!(
            (v.trust_score, v.overall_status),
            (100, OverallStatus::Green)
        );
        assert!(!v.incomplete && v.unknown_count == 0 && v.applicable_count == 13);
    }

    #[test]
    fn score_never_exceeds_94_with_unknown_even_when_pinned() {
        for pinned in [false, true] {
            let v = score_checks(&all_checks(&[(5, unk())]), pinned);
            assert!(v.trust_score <= 94, "pinned={pinned}");
        }
        // Unknown penalty is capped at -15: many Unknown still leave a Green 86+ (aux checks).
        let many = all_checks(&[
            (1, unk()),
            (3, unk()),
            (4, unk()),
            (5, unk()),
            (7, unk()),
            (9, unk()),
        ]);
        let v = score_checks(&many, false);
        assert_eq!(v.overall_status, OverallStatus::Green);
        assert_eq!(v.trust_score, 86);
        assert_eq!(v.unknown_count, 6);
    }

    #[test]
    fn score_not_applicable_is_not_penalised_nor_counted() {
        let v = score_checks(&all_checks(&[(8, na())]), false);
        assert_eq!(v.trust_score, 100);
        assert!(!v.incomplete);
        assert_eq!((v.unknown_count, v.applicable_count), (0, 12));
    }

    #[test]
    fn score_critical_plus_unknown_is_red_and_at_most_35() {
        let v = score_checks(
            &all_checks(&[(0, CheckResult::critical("C", "c", None)), (3, unk())]),
            false,
        );
        assert_eq!(v.overall_status, OverallStatus::Red);
        assert!(v.trust_score <= 35);
        assert!(v.incomplete);
    }

    #[test]
    fn score_counters() {
        let v = score_checks(
            &all_checks(&[(1, unk()), (3, unk()), (8, na()), (10, na())]),
            false,
        );
        assert_eq!(v.unknown_count, 2);
        assert_eq!(v.applicable_count, 11);
        assert_eq!(count_checks(&all_checks(&[(2, unk())])), (1, 13));
    }

    #[test]
    fn unknown_core_check_is_never_green() {
        // Geo (0) and Impossible Travel (2) are the core: fail-closed.
        for core in CORE_CHECKS {
            let v = score_checks(&all_checks(&[(core, unk())]), false);
            assert_eq!(v.overall_status, OverallStatus::Yellow, "core check {core}");
            assert!(!v.overall_status.is_allowed_by_default());
        }
        // The auxiliary ones keep the automatic admit (fail-open), but are reported.
        for aux in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
            let v = score_checks(&all_checks(&[(aux, unk())]), false);
            assert_eq!(v.overall_status, OverallStatus::Green, "aux check {aux}");
            assert!(v.incomplete);
        }
    }

    #[test]
    fn risk_report_without_new_fields_reads() {
        let mut report = report_fixture();
        let mut json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object_mut().unwrap();
        obj.remove("unknown_count");
        obj.remove("applicable_count");
        obj.remove("incomplete");
        let old: RiskReport = serde_json::from_value(json).unwrap();
        assert_eq!(
            (old.unknown_count, old.applicable_count, old.incomplete),
            (0, 0, false)
        );
        report.unknown_count = 2;
        report.incomplete = true;
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["unknown_count"], 2);
        assert_eq!(v["incomplete"], true);
    }

    fn report_fixture() -> RiskReport {
        RiskReport {
            provider: ProviderId::Anthropic,
            overall_status: OverallStatus::Green,
            trust_score: 100,
            telemetry: NetworkTelemetry {
                ip: "9.9.9.9".into(),
                country_code: "NL".into(),
                hostname: None,
                asn: None,
                org: None,
                isp: None,
                timezone: None,
                resolved_at: 0,
            },
            geo_result: ok(),
            pinning_result: ok(),
            travel_result: ok(),
            dnsbl_result: ok(),
            dnsbl_clean_count: String::new(),
            asn_result: ok(),
            ipv6_result: ok(),
            timezone_result: ok(),
            checks: vec![ok()],
            unknown_count: 0,
            applicable_count: 13,
            incomplete: false,
        }
    }

    // ---- the whole audit on substituted sources (no network, no processes) ----

    use probes::stun::testing::echoing;
    use seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp, addr};
    use seams::{HttpProbeOutcome, LookupOutcome, TxtOutcome};

    fn rich_telemetry() -> NetworkTelemetry {
        NetworkTelemetry {
            ip: "203.0.113.9".into(),
            country_code: "NL".into(),
            hostname: Some("host.example".into()),
            asn: Some(64500),
            org: Some("Example Net".into()),
            isp: Some("Example Net".into()),
            timezone: Some("Europe/Amsterdam".into()),
            resolved_at: network::current_timestamp(),
        }
    }

    /// What `1.1.1.1/cdn-cgi/trace` gives: an IP and a country, nothing else.
    fn trace_only_telemetry() -> NetworkTelemetry {
        NetworkTelemetry {
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            ..rich_telemetry()
        }
    }

    fn zones_answering(dns: FakeDns) -> FakeDns {
        let asns = rules::DangerousAsns::load_bundled().unwrap();
        asns.dnsbl_zones.iter().fold(dns, |d, z| {
            d.with(&format!("2.0.0.127.{}", z.zone), addr("127.0.0.2"))
                .with(&format!("9.113.0.203.{}", z.zone), LookupOutcome::NotFound)
        })
    }

    async fn audit(
        env: AuditEnv,
        tel: NetworkTelemetry,
    ) -> RiskReport {
        let auditor = Auditor::with_env(env).unwrap();
        auditor.resolver.set_cached(tel).await;
        auditor
            .evaluate_all(ProviderId::Anthropic, &AppState::new_in_memory(), false)
            .await
            .unwrap()
    }

    /// UDP stays silent (every STUN server times out).
    fn env_of(dns: FakeDns, probe: FakeProbe, system: FakeSystem) -> AuditEnv {
        env_with_udp(dns, probe, system, FakeUdp::new())
    }

    fn env_with_udp(dns: FakeDns, probe: FakeProbe, system: FakeSystem, udp: FakeUdp) -> AuditEnv {
        AuditEnv {
            dns: Arc::new(dns),
            probe: Arc::new(probe),
            udp: Arc::new(udp),
            system: Arc::new(system),
        }
    }

    /// Both whoami sources name `resolver` as the resolver that asks them.
    fn with_whoami(dns: FakeDns, resolver: &str) -> FakeDns {
        dns.with(whoami::AKAMAI_HOST, addr(resolver)).with_txt(
            whoami::GOOGLE_TXT_HOST,
            TxtOutcome::Records(vec![format!("\"{resolver}\"")]),
        )
    }

    /// The geo services place every address in `country`; the IPv6 probe reports NL.
    fn probe_locating(country: &str) -> FakeProbe {
        FakeProbe::body(200, "loc=NL\n").with_route(
            "ipwho.is",
            HttpProbeOutcome::Response {
                status: 200,
                body: format!("{{\"success\":true,\"country_code\":\"{country}\"}}"),
            },
        )
    }

    /// Both STUN servers report `ip` as the public UDP address.
    fn udp_exiting_as(ip: &str) -> FakeUdp {
        let ip: std::net::Ipv4Addr = ip.parse().unwrap();
        FakeUdp::new()
            .with_server(stun::SERVERS[0].addr, echoing(ip))
            .with_server(stun::SERVERS[1].addr, echoing(ip))
    }

    /// Every real source answers and everything is consistent (resolver and UDP exit in NL).
    fn healthy_env() -> AuditEnv {
        env_with_udp(
            with_whoami(zones_answering(FakeDns::new(LookupOutcome::Timeout)), "203.0.113.9"),
            probe_locating("NL"),
            FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::healthy()
            },
            udp_exiting_as("203.0.113.9"),
        )
    }

    /// DNSBL zones and the IPv6 probe all time out: not Green-100, the report says it is incomplete.
    #[tokio::test]
    async fn evaluate_all_with_substituted_probes_all_timing_out_is_incomplete() {
        let report = audit(
            env_of(
                FakeDns::new(LookupOutcome::Timeout),
                FakeProbe::new(HttpProbeOutcome::Timeout),
                FakeSystem {
                    global_ipv6: Some(true),
                    ..FakeSystem::healthy()
                },
            ),
            rich_telemetry(),
        )
        .await;
        assert_eq!(report.checks.len(), 13);
        assert!(report.dnsbl_result.is_unknown());
        assert_eq!(report.dnsbl_result.reason, Some(UnknownReason::Timeout));
        assert!(report.ipv6_result.is_unknown());
        assert_eq!(report.ipv6_result.reason, Some(UnknownReason::Timeout));
        // The real DNS resolver, its country and the UDP probe could not be measured either.
        for i in [6, 10, 12] {
            assert!(report.checks[i].is_unknown(), "check {i}: {:?}", report.checks[i]);
            assert_eq!(report.checks[i].reason, Some(UnknownReason::Timeout), "check {i}");
        }
        assert!(report.checks.iter().all(|c| c.checked_at.is_some()));
        assert!(report.incomplete);
        assert!(report.unknown_count >= 5, "{}", report.unknown_count);
        assert!(report.trust_score <= 94);
        assert!(!(report.overall_status == OverallStatus::Green && report.trust_score == 100));
    }

    /// Nothing reachable: every check that depends on the network or on a read of the host is Unknown.
    #[tokio::test]
    async fn evaluate_all_internet_off_every_network_check_is_unknown() {
        let report = audit(
            env_of(
                FakeDns::new(LookupOutcome::Failed),
                FakeProbe::new(HttpProbeOutcome::ConnectFailed),
                FakeSystem {
                    global_ipv6: Some(true),
                    ..FakeSystem::offline()
                },
            ),
            // Only the cached egress is left; its metadata is missing as in the 1.1.1.1 fallback.
            trace_only_telemetry(),
        )
        .await;
        let names = [
            (12, "udp stun"),
            (3, "dnsbl"),
            (4, "asn"),
            (5, "ipv6"),
            (6, "dns"),
            (7, "timezone"),
            (9, "reverse dns"),
            (10, "dns country"),
            (11, "locale"),
        ];
        for (i, name) in names {
            assert!(report.checks[i].is_unknown(), "{name}: {:?}", report.checks[i]);
            assert!(!report.checks[i].is_not_applicable(), "{name} must be a real Unknown");
        }
        // Not applicable here: pinning off, first session, no location setting on this host.
        for i in [1, 2, 8] {
            assert!(report.checks[i].is_not_applicable(), "check {i}: {:?}", report.checks[i]);
        }
        assert_eq!(report.checks.len(), 13);
        assert_eq!(report.unknown_count, 9);
        assert_eq!(report.applicable_count, 10);
        assert!(report.incomplete && report.trust_score <= 94);
    }

    /// A fallback geolocation answer without metadata must not leave a cascade of green checks.
    #[tokio::test]
    async fn evaluate_all_trace_fallback_has_no_cascade_of_false_greens() {
        let report = audit(
            env_of(
                zones_answering(FakeDns::new(LookupOutcome::Timeout)),
                FakeProbe::body(200, "loc=NL\n"),
                FakeSystem {
                    global_ipv6: Some(true),
                    ..FakeSystem::healthy()
                },
            ),
            trace_only_telemetry(),
        )
        .await;
        // The checks that need ASN / ISP / time zone of the exit IP.
        for i in [4, 7, 9] {
            assert!(report.checks[i].is_unknown(), "check {i}: {:?}", report.checks[i]);
            assert_eq!(report.checks[i].reason, Some(UnknownReason::NoData), "check {i}");
        }
        // The checks with their own sources still give an answer.
        assert!(report.dnsbl_result.status.is_ok(), "{:?}", report.dnsbl_result);
        assert!(report.ipv6_result.status.is_ok(), "{:?}", report.ipv6_result);
        assert!(report.incomplete);
    }

    /// The progress sink gets the exit address first and every one of the 13 checks exactly once,
    /// with the very result that ends up in the final report.
    #[tokio::test]
    async fn evaluate_all_progress_reports_telemetry_and_each_check_once() {
        let auditor = Auditor::with_env(healthy_env()).unwrap();
        auditor.resolver.set_cached(rich_telemetry()).await;
        let seen: Arc<Mutex<Vec<AuditProgress>>> = Arc::default();
        let sink: ProgressSink = {
            let seen = seen.clone();
            Arc::new(move |p| seen.lock().unwrap().push(p))
        };
        let report = auditor
            .evaluate_all_progress(
                ProviderId::Anthropic,
                &AppState::new_in_memory(),
                false,
                Some(sink),
            )
            .await
            .unwrap();
        let seen = seen.lock().unwrap();
        assert!(matches!(seen.first(), Some(AuditProgress::Telemetry { .. })));
        let mut indexes: Vec<usize> = Vec::new();
        for p in seen.iter() {
            if let AuditProgress::Check { index, result } = p {
                assert_eq!(result, &report.checks[*index], "check {index}");
                indexes.push(*index);
            }
        }
        indexes.sort_unstable();
        assert_eq!(indexes, (0..CHECK_COUNT).collect::<Vec<_>>());
        // The wire shape the interface reads.
        let json = serde_json::to_value(&seen[1]).unwrap();
        assert_eq!(json["kind"], "check");
    }

    /// With every source answering, the Ok texts claim only what was verified.
    #[tokio::test]
    async fn evaluate_all_healthy_sources_state_verified_facts() {
        let report = audit(healthy_env(), rich_telemetry()).await;
        assert_eq!(report.checks.len(), 13);
        assert!(report.dnsbl_result.status.is_ok());
        assert!(report.dnsbl_result.message.contains("Ответили 5 из 5"), "{}", report.dnsbl_result.message);
        assert_eq!(report.dnsbl_clean_count, "Ответили 5 из 5 баз");
        assert_eq!(report.ipv6_result.code, "IPV6_ENCAPSULATED");
        assert_eq!(report.timezone_result.code, "TIMEZONE_MATCH");
        // The three checks of the real DNS resolver and of UDP rest on measurements now.
        let (dns, dns_country, udp) = (&report.checks[6], &report.checks[10], &report.checks[12]);
        assert_eq!(dns.code, "DNS_CLEAN");
        assert_eq!(dns_country.code, "DNS_COUNTRY_CONSISTENT");
        assert_eq!(udp.code, "UDP_STUN_MATCH");
        assert_eq!(dns.measured_via.as_deref(), Some("whoami:akamai+google"));
        assert_eq!(dns_country.measured_via.as_deref(), Some("whoami:akamai+google"));
        assert_eq!(udp.measured_via.as_deref(), Some("stun:cloudflare+google"));
        // Only pinning, first session and location do not apply: everything else was verified.
        assert_eq!(report.unknown_count, 0);
        assert_eq!(report.applicable_count, 10);
        assert!(!report.incomplete);
        assert_eq!(
            (report.trust_score, report.overall_status),
            (100, OverallStatus::Green)
        );
    }

    /// TUN with fake-IP DNS: the whoami names resolve to the local pool, the real resolver is
    /// invisible, so neither the resolver check nor the country check may be Ok.
    #[tokio::test]
    async fn evaluate_all_fake_ip_dns_makes_the_resolver_checks_unknown() {
        let env = env_with_udp(
            with_whoami(zones_answering(FakeDns::new(LookupOutcome::Timeout)), "198.18.0.12"),
            probe_locating("NL"),
            FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::healthy()
            },
            udp_exiting_as("203.0.113.9"),
        );
        let report = audit(env, rich_telemetry()).await;
        for i in [6, 10] {
            let c = &report.checks[i];
            assert_eq!(
                (c.status, c.reason),
                (CheckStatus::Unknown, Some(UnknownReason::SourceRefused)),
                "check {i}: {c:?}"
            );
        }
        assert_eq!(report.unknown_count, 2);
        assert!(report.incomplete && report.trust_score <= 94);
    }

    /// The resolver is in Russia while the exit is in NL: both DNS checks warn.
    #[tokio::test]
    async fn evaluate_all_resolver_in_russia_warns_in_both_dns_checks() {
        let env = env_with_udp(
            with_whoami(zones_answering(FakeDns::new(LookupOutcome::Timeout)), "77.88.8.8"),
            probe_locating("RU"),
            FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::healthy()
            },
            udp_exiting_as("203.0.113.9"),
        );
        let report = audit(env, rich_telemetry()).await;
        assert_eq!(report.checks[6].status, CheckStatus::Warning);
        assert_eq!(report.checks[6].code, "DNS_DOMESTIC_WARNING");
        assert_eq!(report.checks[10].status, CheckStatus::Warning);
        assert_eq!(report.checks[10].code, "DNS_COUNTRY_SPLIT");
        assert_eq!(report.overall_status, OverallStatus::Yellow);
    }

    /// UDP exits through another address than HTTP: a Warning in the 13th check.
    #[tokio::test]
    async fn evaluate_all_udp_through_another_address_is_a_warning() {
        let env = env_with_udp(
            with_whoami(zones_answering(FakeDns::new(LookupOutcome::Timeout)), "203.0.113.9"),
            probe_locating("NL"),
            FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::healthy()
            },
            udp_exiting_as("198.51.100.77"),
        );
        let report = audit(env, rich_telemetry()).await;
        let udp = &report.checks[12];
        assert_eq!((udp.status, udp.code.as_str()), (CheckStatus::Warning, "UDP_STUN_MISMATCH"));
        assert_eq!(report.overall_status, OverallStatus::Yellow);
        assert!(report.trust_score <= 85);
    }

    /// A closed UDP is not a leak and, as an auxiliary check, does not stop the automatic admit.
    #[tokio::test]
    async fn evaluate_all_silent_udp_is_unknown_and_keeps_the_admit() {
        let env = env_with_udp(
            with_whoami(zones_answering(FakeDns::new(LookupOutcome::Timeout)), "203.0.113.9"),
            probe_locating("NL"),
            FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::healthy()
            },
            FakeUdp::new(),
        );
        let report = audit(env, rich_telemetry()).await;
        let udp = &report.checks[12];
        assert_eq!((udp.status, udp.reason), (CheckStatus::Unknown, Some(UnknownReason::Timeout)));
        assert_eq!((report.unknown_count, report.incomplete), (1, true));
        assert_eq!(report.overall_status, OverallStatus::Green);
        assert_eq!(report.trust_score, 94);
    }

    /// The same exit address is probed over UDP once per minute (and the DNS resolver once per
    /// audit round): repeated audits do not repeat the network work.
    #[tokio::test]
    async fn evaluate_all_repeated_audits_reuse_the_probes() {
        let udp = Arc::new(udp_exiting_as("203.0.113.9"));
        let dns = Arc::new(with_whoami(zones_answering(FakeDns::new(LookupOutcome::Timeout)), "203.0.113.9"));
        let env = AuditEnv {
            dns: dns.clone(),
            probe: Arc::new(probe_locating("NL")),
            udp: udp.clone(),
            system: Arc::new(FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::healthy()
            }),
        };
        let auditor = Auditor::with_env(env).unwrap();
        auditor.resolver.set_cached(rich_telemetry()).await;
        let state = AppState::new_in_memory();
        for provider in [ProviderId::Anthropic, ProviderId::Anthropic] {
            auditor.evaluate_all(provider, &state, false).await.unwrap();
        }
        assert_eq!(udp.calls(), 2, "two STUN servers, asked once");
    }

    /// Google Public DNS: the resolver check is Ok, the country check is not applicable (not
    /// counted, not penalised), so the report is complete and Green-100.
    #[tokio::test]
    async fn evaluate_all_public_resolver_is_ok_and_its_country_not_applicable() {
        let probe = FakeProbe::body(200, "loc=NL\n").with_route(
            "ipwho.is",
            HttpProbeOutcome::Response {
                status: 200,
                body: "{\"success\":true,\"country_code\":\"US\",\"connection\":{\"asn\":15169,\"org\":\"Google LLC\"}}".into(),
            },
        );
        let env = env_with_udp(
            with_whoami(zones_answering(FakeDns::new(LookupOutcome::Timeout)), "74.125.40.10"),
            probe,
            FakeSystem {
                global_ipv6: Some(true),
                ..FakeSystem::healthy()
            },
            udp_exiting_as("203.0.113.9"),
        );
        let report = audit(env, rich_telemetry()).await;
        assert_eq!(report.checks[6].code, "DNS_PUBLIC_RESOLVER");
        assert!(report.checks[6].status.is_ok());
        assert!(report.checks[10].is_not_applicable(), "{:?}", report.checks[10]);
        assert_eq!((report.unknown_count, report.applicable_count), (0, 9));
        assert!(!report.incomplete);
        assert_eq!((report.trust_score, report.overall_status), (100, OverallStatus::Green));
    }
}
