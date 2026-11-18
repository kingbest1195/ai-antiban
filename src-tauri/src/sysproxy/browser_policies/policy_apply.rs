//! Journaled application, revert, and active-policy checks for browser policy specs.

use super::{
    KEY_PROXY_MODE, KEY_PROXY_PAC_URL, PROXY_MODE_PAC_SCRIPT, PolicyApplyReport, PolicySpec,
    PolicyStore, PolicyValue,
    chromium::{clean_pac_url, policy_specs_with_pac, same_pac_url},
    reconcile::{apply_browser_prefs_with_pac, detect_browser_pac_status_with},
};
#[cfg(test)]
use super::chromium::MACOS_CHROMIUM_DOMAIN_NAMES;
#[cfg(all(test, target_os = "windows"))]
use super::chromium::WINDOWS_CHROMIUM_DOMAIN_NAMES;
#[cfg(test)]
use super::process::inspect_running_browsers;
use crate::sysproxy::{Os, RealProbe, SystemProbe};
use crate::sysproxy::FileCtx;
use crate::sysproxy::journal::{ApplyOutcome, Journal, JournalError, Resource, Value};
#[cfg(test)]
use crate::sysproxy::journal::{Outcome, RecoveryReport, ReportItem};
#[cfg(test)]
use crate::sysproxy::os_effects_enabled;
use crate::sysproxy::platform::{Platform, PlatformError};
#[cfg(test)]
use std::collections::BTreeMap;

/// Applies browser QUIC/DoH policies and, when `pac_url` is `Some`, also sets
/// `ProxyMode = "pac_script"` and `ProxyPacUrl = <pac_url>` across Chromium-family browsers,
/// plus injects `"proxy"` into non-running Chromium profile `Preferences` files.
pub fn apply_browser_policies_with_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: Option<&str>,
) -> PolicyApplyReport {
    let ctx = if crate::sysproxy::os_effects_enabled() {
        FileCtx::real_with_fs(j.fs())
    } else {
        None
    };
    apply_browser_policies_with_pac_in(j, p, pac_url, ctx.as_ref(), Os::current(), &RealProbe)
}

/// Applies browser QUIC/DoH/PAC policies and (when `ctx` is `Some` and `pac_url` is `Some`)
/// injects `"proxy"` into `Preferences` files of non-running Chromium-family browsers.
pub fn apply_browser_policies_with_pac_in(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: Option<&str>,
    ctx: Option<&FileCtx>,
    os: Os,
    probe: &dyn SystemProbe,
) -> PolicyApplyReport {
    let specs = policy_specs_with_pac(pac_url);
    let mut report = apply_policy_specs(j, p, &specs);
    if let Some(url) = clean_pac_url(pac_url)
        && let Some(file_ctx) = ctx
    {
        apply_browser_prefs_with_pac(j, p, url, file_ctx, os, probe, &mut report);
        let store = j.policy_store_arc();
        let status =
            detect_browser_pac_status_with(Some(file_ctx), os, probe, Some(url), &*store, p);
        report.pac_policy_active = !status.browsers_pac_active.is_empty();
    }
    report
}

/// Restores every journaled [`Resource::BrowserPolicy`] and non-running
/// [`Resource::BrowserPacPref`] entry to its pre-Zastava baseline.
#[cfg(test)]
pub fn revert_browser_policies(j: &mut Journal, p: &dyn Platform) -> RecoveryReport {
    if os_effects_enabled() {
        revert_browser_policies_with(j, p, Os::current(), &RealProbe)
    } else {
        j.restore_where(p, |r| {
            matches!(
                r,
                Resource::BrowserPolicy { .. } | Resource::BrowserPacPref { .. }
            )
        })
    }
}

/// Restores every journaled [`Resource::BrowserPolicy`] and every [`Resource::BrowserPacPref`]
/// whose browser is not currently running; running browsers are skipped with
/// [`Outcome::Skipped`] (`"browser_running"`) so they don't overwrite `Preferences` on exit.
#[cfg(test)]
pub fn revert_browser_policies_with(
    j: &mut Journal,
    p: &dyn Platform,
    os: Os,
    probe: &dyn SystemProbe,
) -> RecoveryReport {
    let has_prefs = j
        .entries()
        .iter()
        .any(|e| matches!(e.resource, Resource::BrowserPacPref { .. }));
    let running_map = if has_prefs {
        inspect_running_browsers(probe, os, None)
    } else {
        Some(BTreeMap::new())
    };
    let skipped_prefs: Vec<String> = j
        .entries()
        .iter()
        .filter_map(|e| match &e.resource {
            Resource::BrowserPacPref { domain, .. } => {
                let is_running = match &running_map {
                    Some(map) => map.get(domain.as_str()).is_some_and(|i| i.running),
                    None => true,
                };
                is_running.then(|| e.resource.id())
            }
            _ => None,
        })
        .collect();

    let mut report = j.restore_where(p, |r| match r {
        Resource::BrowserPolicy { .. } => true,
        Resource::BrowserPacPref { domain, .. } => match &running_map {
            Some(map) => !map.get(domain.as_str()).is_some_and(|i| i.running),
            None => false,
        },
        _ => false,
    });
    for id in skipped_prefs {
        report.items.push(ReportItem {
            resource: id,
            outcome: Outcome::Skipped("browser_running"),
        });
    }
    report
}

/// Returns `true` when at least one installed/applicable browser domain in `domains` currently has
/// `ProxyMode = "pac_script"` and `ProxyPacUrl` pointing at `pac_url`.
pub fn is_pac_policy_active_in(store: &dyn PolicyStore, domains: &[&str], pac_url: &str) -> bool {
    let Some(expected) = clean_pac_url(Some(pac_url)) else {
        return false;
    };
    for domain in domains {
        if !store.is_domain_applicable(domain) {
            continue;
        }
        let Ok(Some(PolicyValue::Sz(actual_url))) = store.read(domain, KEY_PROXY_PAC_URL) else {
            continue;
        };
        if !same_pac_url(&actual_url, expected) {
            continue;
        }
        let Ok(Some(PolicyValue::Sz(mode))) = store.read(domain, KEY_PROXY_MODE) else {
            continue;
        };
        if mode.trim().eq_ignore_ascii_case(PROXY_MODE_PAC_SCRIPT) {
            return true;
        }
    }
    false
}

/// Checks [`is_pac_policy_active_in`] for the current platform's Chromium-family policy domains.
#[cfg(test)]
pub fn is_pac_policy_active(store: &dyn PolicyStore, pac_url: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        is_pac_policy_active_in(store, &WINDOWS_CHROMIUM_DOMAIN_NAMES, pac_url)
    }
    #[cfg(target_os = "macos")]
    {
        is_pac_policy_active_in(store, &MACOS_CHROMIUM_DOMAIN_NAMES, pac_url)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (store, pac_url);
        false
    }
}

/// Applies explicit `specs` through `j` using `j.policy_store()`, recording baselines first.
pub fn apply_policy_specs(
    j: &mut Journal,
    p: &dyn Platform,
    specs: &[PolicySpec],
) -> PolicyApplyReport {
    let mut report = PolicyApplyReport::default();
    let store = j.policy_store_arc();
    for spec in specs {
        if !store.is_domain_applicable(&spec.domain) {
            report.skipped += 1;
            continue;
        }
        let res = Resource::BrowserPolicy {
            domain: spec.domain.clone(),
            key: spec.key.clone(),
        };
        let val = Value::Policy(Some(spec.value.clone()));
        match j.apply(p, &res, val) {
            Ok(ApplyOutcome::Applied | ApplyOutcome::Rebased) => report.applied += 1,
            Ok(ApplyOutcome::Unchanged) => report.unchanged += 1,
            Err(JournalError::Platform(PlatformError::DryRun | PlatformError::Unsupported(_))) => {
                report.skipped += 1;
            }
            Err(err) => {
                report.failed += 1;
                eprintln!("Застава: не удалось применить политику {}: {err}", res.id());
            }
        }
    }
    report
}
