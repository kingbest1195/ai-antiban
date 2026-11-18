//! Application network coverage and incoming socket process auditing.
//!
//! A status is never guessed from an in-memory flag:
//! * `confirmed`  - the app made an AI request through the gateway within [`CONFIRM_TTL_MS`];
//! * `configured` - a fact read from the system says so (the PAC the OS hands out equals ours,
//!   `http.proxy` in the editor's `settings.json` points at the gateway port);
//! * `off`        - the fact was read and it says "not configured";
//! * `unknown`    - the app is there but there is nothing reliable to read (or reading failed);
//! * `not_installed`.
//!
//! Everything that touches the OS (`lsof` / `netstat` / `tasklist` / `ss`, `Platform`, files)
//! goes through a seam, so the tests feed canned output and fakes instead of starting processes.


mod catalog;
mod cli_scanners;
mod ide_scanners;
mod pac_verify;
mod process_lookup;
mod tracker;
mod types;

pub use catalog::{KnownAppInfo, classify_process_name, get_known_app_info, resolve_app_identity};
pub use cli_scanners::check_app_installed;
#[cfg(test)]
use cli_scanners::check_app_installed_in;
pub(crate) use ide_scanners::antigravity_app_path;
#[cfg(test)]
use ide_scanners::{AntigravityKind, antigravity_kind, jetbrains_fact, listing_has_antigravity};
#[cfg(test)]
use tracker::Step;
pub use ide_scanners::proxy_value_targets_gateway;
pub use process_lookup::{
    lookup_process_name_by_port, lookup_process_name_by_port_sync, lookup_process_with,
    parse_lsof_owner, parse_netstat_pid, parse_ss_owner, parse_tasklist_name,
};
pub use tracker::CoverageTracker;
pub(crate) use types::CoverageEnv;
pub use types::{
    ANTIGRAVITY_BYPASS_DETAIL, AppCoverageItem, CONFIRM_TTL_MS, CoverageSnapshot, CoverageStatus,
    JETBRAINS_XML_CONFIRMED, Os, PacSource, RealProbe, SystemProbe, TrafficKind, pac_url_for,
    steps,
};

#[cfg(test)]
use crate::sysproxy::FileCtx;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Arc, Mutex};
#[cfg(test)]
use types::{
    Clock, FACTS_TTL_MS, LOOKUP_CACHE_TTL_MS, LOOKUP_NEGATIVE_TTL_MS, LOOKUP_RATE_MAX,
    LOOKUP_RATE_WINDOW_MS, PROCESS_CHECK_TTL_MS,
};

use crate::state::CliMode;
use ide_scanners::is_antigravity_agent_id;
use pac_verify::compute_config_facts;
use types::{AppTrafficStats, FACTS_TTL_MS as PROD_FACTS_TTL_MS, KNOWN_IDS};

impl CoverageTracker {
    /// Builds the snapshot. `force` ignores the cache of configuration facts (re-reads the OS
    /// and the files right now).
    pub(crate) fn snapshot(&self, env: &CoverageEnv<'_>, force: bool) -> CoverageSnapshot {
        let now = self.now_ms();
        let gateway = self.gateway_addr();
        let cli_mode = self.cli_mode();

        let facts = {
            let mut guard = self.facts.lock().unwrap_or_else(|e| e.into_inner());
            let fresh = match &*guard {
                Some((at, f)) => {
                    !force && now.saturating_sub(*at) < PROD_FACTS_TTL_MS && f.gateway == gateway
                }
                None => false,
            };
            if !fresh {
                *guard = Some((
                    now,
                    compute_config_facts(env, gateway, cli_mode, self.os, &*self.probe),
                ));
            }
            guard.as_ref().map(|(_, f)| f.clone()).unwrap_or_default()
        };

        let stats_map = self.stats.lock().map(|l| l.clone()).unwrap_or_default();
        let mut apps = Vec::new();

        // The agent of Antigravity 2.x talks to the gateway under its own process name. It is
        // counted for Antigravity unless Windsurf (same `language_server*` binary) is installed.
        let windsurf_installed = facts.apps.get("windsurf").is_some_and(|f| f.installed);
        let antigravity_app = facts
            .apps
            .get("antigravity")
            .is_some_and(|f| f.watch_bypass);
        let merge_agent = antigravity_app && !windsurf_installed;
        let antigravity_traffic = merge_agent.then(|| {
            let mut sum = AppTrafficStats {
                ai_requests: 0,
                pac_fetches: 0,
                last_seen_ms: 0,
                detected_name: String::new(),
                category: String::new(),
            };
            for (id, t) in &stats_map {
                if id == "antigravity" || is_antigravity_agent_id(id) {
                    sum.ai_requests = sum.ai_requests.saturating_add(t.ai_requests);
                    sum.pac_fetches = sum.pac_fetches.saturating_add(t.pac_fetches);
                    if t.ai_requests > 0 {
                        sum.last_seen_ms = sum.last_seen_ms.max(t.last_seen_ms);
                    }
                }
            }
            sum
        });

        for app_id in KNOWN_IDS {
            let info = get_known_app_info(app_id).unwrap_or(KnownAppInfo {
                id: app_id,
                name: app_id,
                category: "desktop",
            });
            let traffic = match (&antigravity_traffic, app_id) {
                (Some(sum), "antigravity") => Some(sum),
                _ => stats_map.get(app_id),
            };
            let ai_requests = traffic.map(|t| t.ai_requests).unwrap_or(0);
            let pac_fetches = traffic.map(|t| t.pac_fetches).unwrap_or(0);
            let last_seen_ms = traffic
                .filter(|t| t.ai_requests > 0)
                .map(|t| t.last_seen_ms);
            let fact = facts.apps.get(app_id);
            let installed = fact.map(|f| f.installed).unwrap_or(false) || ai_requests > 0;
            let fresh = last_seen_ms.is_some_and(|t| now.saturating_sub(t) < CONFIRM_TTL_MS);

            let mut bypass_suspected = false;
            let (status, manual_steps, detail) = if fresh {
                (
                    CoverageStatus::Confirmed,
                    Vec::new(),
                    format!("Подтверждено трафиком ({} запр.)", ai_requests),
                )
            } else if !installed {
                (
                    CoverageStatus::NotInstalled,
                    Vec::new(),
                    "Не установлено".to_string(),
                )
            } else if let Some(f) = fact.filter(|f| f.installed) {
                let (mut status, mut detail) = (f.status, f.detail.clone());
                if f.watch_bypass && self.app_is_running(now) {
                    // A running app whose requests never reach the gateway is not covered, even
                    // when the system PAC is ours: do not show "configured, waiting".
                    bypass_suspected = true;
                    status = CoverageStatus::Off;
                    detail = ANTIGRAVITY_BYPASS_DETAIL.to_string();
                } else if app_id == "opencode"
                    && cli_mode == CliMode::AiOnly
                    && status == CoverageStatus::Off
                {
                    bypass_suspected = true;
                }
                (status, f.manual_steps.clone(), detail)
            } else {
                // Seen on traffic earlier, but nothing to read now.
                (
                    CoverageStatus::Unknown,
                    Vec::new(),
                    "Подтверждение устарело".to_string(),
                )
            };

            apps.push(AppCoverageItem {
                id: info.id.to_string(),
                name: info.name.to_string(),
                category: info.category.to_string(),
                installed,
                status,
                requests_seen: ai_requests,
                ai_requests,
                pac_fetches,
                last_seen_ms,
                manual_steps,
                detail,
                bypass_suspected,
            });
        }

        // Processes seen on AI traffic that are not in the catalog (the merged agent is not one).
        let mut dynamic: Vec<_> = stats_map
            .iter()
            .filter(|(id, t)| {
                !KNOWN_IDS.contains(&id.as_str())
                    && t.ai_requests > 0
                    && !(merge_agent && is_antigravity_agent_id(id))
            })
            .collect();
        dynamic.sort_by(|a, b| a.0.cmp(b.0));
        for (id, t) in dynamic {
            let fresh = now.saturating_sub(t.last_seen_ms) < CONFIRM_TTL_MS;
            apps.push(AppCoverageItem {
                id: id.clone(),
                name: t.detected_name.clone(),
                category: t.category.clone(),
                installed: true,
                status: if fresh {
                    CoverageStatus::Confirmed
                } else {
                    CoverageStatus::Unknown
                },
                requests_seen: t.ai_requests,
                ai_requests: t.ai_requests,
                pac_fetches: t.pac_fetches,
                last_seen_ms: Some(t.last_seen_ms),
                manual_steps: Vec::new(),
                detail: format!("Подтверждено трафиком ({} запр.)", t.ai_requests),
                bypass_suspected: false,
            });
        }

        CoverageSnapshot {
            sysproxy_enabled: env.sysproxy_enabled,
            cli_protection_enabled: env.cli_protection_enabled,
            cli_mode,
            chained_proxy: env.chained_proxy.clone(),
            gateway_addr: facts.gateway.map(|g| g.to_string()),
            pac_url: facts.gateway.map(pac_url_for),
            generated_at_ms: now,
            apps,
            system_proxy_effective: if env.sysproxy_enabled {
                facts.system_proxy_effective
            } else {
                None
            },
            vpn_connected: facts.vpn_connected.clone(),
            browser_pac_policy_active: facts.browser_pac_policy_active,
            browsers_needing_restart: facts.browsers_needing_restart.clone(),
            browsers_pac_active: facts.browsers_pac_active.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
