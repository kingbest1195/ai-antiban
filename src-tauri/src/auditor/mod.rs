pub mod cache;
pub mod cache_cleaner;
pub mod claude_exporter;
pub mod dnsbl;
pub mod geo_matrix;
pub mod history;
pub mod leaks;
pub mod network;
pub mod os_env;
pub mod profile_switcher;
pub mod rules;
pub mod run_check;
pub mod telemetry;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cache::{DNSBL_TTL, IPV6_TTL, OS_TTL, cached_check};
use run_check::{blocking_check, run_check};

pub use cache_cleaner::clean_ai_app_cache;
pub use dnsbl::{check_all_dnsbl, evaluate_asn_reputation, evaluate_dnsbl_report};
pub use geo_matrix::{CheckResult, CheckStatus, ProviderId, UnknownReason, evaluate_provider_geo};
pub use history::{evaluate_impossible_travel, evaluate_ip_pinning};
pub use leaks::{check_dns_leak, check_ipv6_leak};
pub use network::{
    build_upstream_client, evaluate_dns_country_consistency, evaluate_reverse_dns_ptr,
    NetworkResolver, NetworkTelemetry,
};
pub use os_env::{
    check_os_location_services, evaluate_locale_env_hygiene, evaluate_system_timezone,
};
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

/// Time limit of a check that only computes (no I/O of its own).
const CHECK_LIMIT_LOCAL: Duration = Duration::from_secs(2);
/// Time limit of a check that talks to the network or runs a child process.
const CHECK_LIMIT_IO: Duration = Duration::from_secs(4);

/// Positions in `RiskReport::checks` of the core checks (geo matrix, impossible travel): when one
/// of them could not be performed the gateway must not let traffic through on its own (fail-closed).
/// An `Unknown` in any other check is shown, but does not change the admit decision.
const CORE_CHECKS: [usize; 2] = [0, 2];

/// Outcome of scoring the 12 checks.
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
            incomplete_logged: Arc::default(),
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

    /// Evaluates complete 12-point risk assessment for the target AI provider,
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

    /// [`Self::evaluate_all`] on an already taken route snapshot (see [`Self::resolve_for_selection`]).
    pub async fn evaluate_all_with(
        &self,
        provider: ProviderId,
        state: &AppState,
        selection: &RouteSelection,
        force_refresh_telemetry: bool,
    ) -> Result<RiskReport, String> {
        let telemetry = self
            .resolve_for_selection(provider, state, selection, force_refresh_telemetry)
            .await?;

        let matrix = Arc::new(self.rules.provider_matrix.read().await.clone());
        let dangerous_asns = Arc::new(self.rules.dangerous_asns.read().await.clone());
        let state_data = state.get_data().await;
        let cache = self.resolver.check_cache().clone();

        let is_pinned = match &state_data.pinned_ip {
            Some(pinned) => pinned.trim() == telemetry.ip.trim(),
            None => false,
        };
        let synced_tz = state_data.synced_ai_timezone.clone();
        let synced_key = synced_tz.clone().unwrap_or_default();
        let country = telemetry.country_code.clone();
        let dnsbl_label = Arc::new(Mutex::new("Не проверено".to_string()));

        // Every check runs isolated (own task, own time limit): a slow or panicking check ends
        // as `Unknown` and the others still finish.
        let geo = run_check("Geo Matrix", CHECK_LIMIT_LOCAL, {
            let (matrix, country) = (matrix.clone(), country.clone());
            async move { evaluate_provider_geo(&matrix, provider, &country) }
        });
        let pinning = run_check("IP Pinning", CHECK_LIMIT_LOCAL, {
            let (pinned, strict, ip) = (
                state_data.pinned_ip.clone(),
                state_data.strict_pinning_enabled,
                telemetry.ip.clone(),
            );
            async move { evaluate_ip_pinning(pinned.as_deref(), strict, &ip) }
        });
        let travel = run_check("Impossible Travel", CHECK_LIMIT_LOCAL, {
            let history = state_data
                .ip_history
                .get(provider.as_str())
                .cloned()
                .unwrap_or_default();
            let (country, resolved_at) = (country.clone(), telemetry.resolved_at);
            async move { evaluate_impossible_travel(&history, &country, resolved_at, provider) }
        });
        let dnsbl = run_check("DNSBL", CHECK_LIMIT_IO, {
            let (cache, asns, ip, label) = (
                cache.clone(),
                dangerous_asns.clone(),
                telemetry.ip.clone(),
                dnsbl_label.clone(),
            );
            async move {
                let (result, summary) = cache
                    .dnsbl
                    .get_or_compute(&ip, DNSBL_TTL, |(r, _)| !r.is_unknown(), async {
                        let report = check_all_dnsbl(&ip, &asns).await;
                        (evaluate_dnsbl_report(&report), report.summary_label)
                    })
                    .await;
                *label.lock().unwrap_or_else(|e| e.into_inner()) = summary;
                result
            }
        });
        let asn = run_check("ASN Reputation", CHECK_LIMIT_LOCAL, {
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
        });
        let ipv6 = run_check("IPv6 Leak", CHECK_LIMIT_IO, {
            let (cache, matrix, country) = (cache.clone(), matrix.clone(), country.clone());
            async move {
                cached_check(&cache.ipv6, &country, IPV6_TTL, async {
                    check_ipv6_leak(&country, &matrix.global_blocked_countries).await
                })
                .await
            }
        });
        let dns = run_check("DNS Resolver", CHECK_LIMIT_IO, {
            let (cache, asns, country) = (cache.clone(), dangerous_asns.clone(), country.clone());
            async move {
                cached_check(&cache.os, &format!("dns:{country}"), OS_TTL, async {
                    let keywords = asns.russian_isp_keywords.clone();
                    let cc = country.clone();
                    blocking_check(move || check_dns_leak(&cc, &keywords)).await
                })
                .await
            }
        });
        let timezone = run_check("Timezone", CHECK_LIMIT_LOCAL, {
            let (cache, ip_tz, synced) =
                (cache.clone(), telemetry.timezone.clone(), synced_tz.clone());
            async move {
                let key = format!(
                    "tz:{}|{}",
                    ip_tz.as_deref().unwrap_or_default(),
                    synced.as_deref().unwrap_or_default()
                );
                cached_check(&cache.os, &key, OS_TTL, async {
                    evaluate_system_timezone(ip_tz.as_deref(), synced.as_deref())
                })
                .await
            }
        });
        let location = run_check("OS Location", CHECK_LIMIT_IO, {
            let cache = cache.clone();
            async move {
                cached_check(&cache.os, "location", OS_TTL, async {
                    blocking_check(check_os_location_services).await
                })
                .await
            }
        });
        let reverse_dns = run_check("Reverse DNS", CHECK_LIMIT_LOCAL, {
            let tel = telemetry.clone();
            async move { evaluate_reverse_dns_ptr(&tel) }
        });
        // No independent source of the DNS country exists yet: honestly `Unknown`, not "consistent".
        let dns_country = run_check("DNS Country", CHECK_LIMIT_LOCAL, {
            let tel = telemetry.clone();
            async move { evaluate_dns_country_consistency(&tel, None) }
        });
        let locale = run_check("Locale", CHECK_LIMIT_LOCAL, {
            let cache = cache.clone();
            async move {
                cached_check(&cache.os, &format!("locale:{synced_key}"), OS_TTL, async {
                    evaluate_locale_env_hygiene(synced_tz.as_deref())
                })
                .await
            }
        });

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
            locale
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
    /// 12 results in report order, `ok()` everywhere except the given positions.
    fn twelve(over: &[(usize, CheckResult)]) -> Vec<CheckResult> {
        let mut v: Vec<CheckResult> = (0..12).map(|_| ok()).collect();
        for (i, r) in over {
            v[*i] = r.clone();
        }
        v
    }

    #[test]
    fn score_eleven_ok_and_one_unknown_is_below_100_and_green() {
        let v = score_checks(&twelve(&[(3, unk())]), false);
        assert_eq!(v.overall_status, OverallStatus::Green);
        assert!(v.trust_score < 100);
        assert_eq!(v.trust_score, 94);
        assert!(v.incomplete);
    }

    #[test]
    fn score_twelve_ok_is_100() {
        let v = score_checks(&twelve(&[]), false);
        assert_eq!(
            (v.trust_score, v.overall_status),
            (100, OverallStatus::Green)
        );
        assert!(!v.incomplete && v.unknown_count == 0 && v.applicable_count == 12);
    }

    #[test]
    fn score_never_exceeds_94_with_unknown_even_when_pinned() {
        for pinned in [false, true] {
            let v = score_checks(&twelve(&[(5, unk())]), pinned);
            assert!(v.trust_score <= 94, "pinned={pinned}");
        }
        // Unknown penalty is capped at -15: many Unknown still leave a Green 86+ (aux checks).
        let many = twelve(&[
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
        let v = score_checks(&twelve(&[(8, na())]), false);
        assert_eq!(v.trust_score, 100);
        assert!(!v.incomplete);
        assert_eq!((v.unknown_count, v.applicable_count), (0, 11));
    }

    #[test]
    fn score_critical_plus_unknown_is_red_and_at_most_35() {
        let v = score_checks(
            &twelve(&[(0, CheckResult::critical("C", "c", None)), (3, unk())]),
            false,
        );
        assert_eq!(v.overall_status, OverallStatus::Red);
        assert!(v.trust_score <= 35);
        assert!(v.incomplete);
    }

    #[test]
    fn score_counters() {
        let v = score_checks(
            &twelve(&[(1, unk()), (3, unk()), (8, na()), (10, na())]),
            false,
        );
        assert_eq!(v.unknown_count, 2);
        assert_eq!(v.applicable_count, 10);
        assert_eq!(count_checks(&twelve(&[(2, unk())])), (1, 12));
    }

    #[test]
    fn unknown_core_check_is_never_green() {
        // Geo (0) and Impossible Travel (2) are the core: fail-closed.
        for core in CORE_CHECKS {
            let v = score_checks(&twelve(&[(core, unk())]), false);
            assert_eq!(v.overall_status, OverallStatus::Yellow, "core check {core}");
            assert!(!v.overall_status.is_allowed_by_default());
        }
        // The auxiliary ones keep the automatic admit (fail-open), but are reported.
        for aux in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11] {
            let v = score_checks(&twelve(&[(aux, unk())]), false);
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
            applicable_count: 12,
            incomplete: false,
        }
    }

    /// Whole audit with DNSBL and IPv6 failing (cache seeded with a timeout): not 100, incomplete.
    #[tokio::test]
    async fn evaluate_all_with_failed_probes_is_incomplete() {
        let auditor = Auditor::new().unwrap();
        let state = AppState::new_in_memory();
        let tel = NetworkTelemetry {
            ip: "9.9.9.9".into(),
            country_code: "NL".into(),
            hostname: Some("host.example".into()),
            asn: Some(64500),
            org: Some("Example Net".into()),
            isp: Some("Example Net".into()),
            timezone: Some("Europe/Amsterdam".into()),
            resolved_at: network::current_timestamp(),
        };
        auditor.resolver.set_cached(tel.clone()).await;
        let cache = auditor.resolver.check_cache();
        let timeout = || CheckResult::unknown("T", "t", UnknownReason::Timeout);
        cache
            .dnsbl
            .get_or_compute("9.9.9.9", cache::DNSBL_TTL, |_| false, async {
                (timeout(), "x".to_string())
            })
            .await;
        cache
            .ipv6
            .get_or_compute("NL", cache::IPV6_TTL, |_| false, async { timeout() })
            .await;

        let report = auditor
            .evaluate_all(ProviderId::Anthropic, &state, false)
            .await
            .unwrap();
        assert_eq!(report.checks.len(), 12);
        assert!(report.dnsbl_result.is_unknown() && report.ipv6_result.is_unknown());
        assert!(
            report.checks[10].is_unknown(),
            "dns country has no source yet"
        );
        assert!(report.incomplete && report.unknown_count >= 3);
        assert!(report.trust_score <= 94);
        assert!(report.checks.iter().all(|c| c.checked_at.is_some()));
    }
}
