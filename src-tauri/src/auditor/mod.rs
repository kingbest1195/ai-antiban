pub mod cache;
pub mod cache_cleaner;
pub mod claude_exporter;
pub mod dnsbl;
mod evaluate;
mod evaluate_checks;
pub mod geo_matrix;
pub mod history;
pub mod ip_type;
pub mod leaks;
pub mod network;
pub mod os_env;
pub mod probes;
pub mod profile_switcher;
pub mod rules;
pub mod run_check;
mod scoring;
pub mod seams;
pub mod telemetry;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::routing::{Route, RouteSelection};
use crate::state::AppState;
pub use cache_cleaner::clean_ai_app_cache;
pub use dnsbl::{
    check_all_dnsbl, check_all_dnsbl_with, check_all_dnsbl_with_doh, evaluate_dnsbl_report,
};
pub use geo_matrix::{CheckResult, CheckStatus, ProviderId, UnknownReason, evaluate_provider_geo};
pub use history::{
    apply_pinned_travel_grace, evaluate_impossible_travel, evaluate_impossible_travel_with_exit,
    evaluate_impossible_travel_with_pin, evaluate_impossible_travel_with_pin_and_exit,
    evaluate_ip_pinning, evaluate_ip_pinning_for_route,
};
pub use ip_type::{ExitIdentity, IpType, TorLookup, evaluate_ip_reputation, lookup_tor};
pub use leaks::{
    check_dns_leak, check_dns_leak_with, check_ipv6_leak, check_ipv6_leak_with,
    check_ipv6_leak_with_route, check_ipv6_leak_with_split, evaluate_dns_resolver,
    evaluate_dns_resolver_for_route,
};
pub use network::{
    NetworkResolver, NetworkTelemetry, build_upstream_client, evaluate_dns_country_consistency,
    evaluate_reverse_dns_ptr, evaluate_reverse_dns_ptr_with_dns, evaluate_reverse_dns_ptr_with_ptr,
};
pub use os_env::{
    check_os_location_services, check_os_location_services_with, evaluate_locale_env_hygiene,
    evaluate_locale_env_hygiene_with, evaluate_system_timezone, evaluate_system_timezone_with,
    evaluate_system_timezone_with_sync,
};
#[cfg(test)]
use cache::OS_TTL;
#[cfg(test)]
use probes::{stun, whoami};
pub use rules::RuleSet;
#[cfg(test)]
use scoring::CORE_CHECKS;
pub use scoring::{Verdict, count_checks, score_checks};
pub use seams::AuditEnv;

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
    /// The exit address is IPv6: the spam-list and Tor checks do not apply to it (shown as
    /// "not applicable", the interface explains why).
    #[serde(default)]
    pub ipv6_exit: bool,
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

#[derive(Clone)]
pub struct Auditor {
    pub rules: RuleSet,
    pub resolver: NetworkResolver,
    /// DNS, HTTP probe and host reads of the checks (replaceable in tests).
    env: AuditEnv,
    /// In `Auditor::with_env` tests, route direct `claude_exit` probes through `env.probe`
    /// so offline fake tests never touch the network; production uses `NetworkResolver`.
    use_env_probe_for_direct: bool,
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
            use_env_probe_for_direct: false,
            incomplete_logged: Arc::default(),
        })
    }

    /// An auditor whose DNS, probe and host reads come from `env` (tests: no network, no processes).
    pub fn with_env(env: AuditEnv) -> Result<Self, String> {
        Ok(Self {
            env,
            use_env_probe_for_direct: true,
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

    /// Telemetry of the direct egress path (uses `env.probe` when constructed with `Auditor::with_env`).
    pub async fn resolve_direct(&self, force_refresh: bool) -> Result<NetworkTelemetry, String> {
        if self.use_env_probe_for_direct {
            self.resolver
                .resolve_direct_via_probe(&*self.env.probe, force_refresh)
                .await
        } else {
            self.resolver.resolve(force_refresh).await
        }
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
            RouteSelection::Direct => self.resolve_direct(force_refresh).await,
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

    /// Evaluates the complete 14-point risk assessment for the target AI provider,
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
#[path = "mod_tests/mod.rs"]
mod tests;
