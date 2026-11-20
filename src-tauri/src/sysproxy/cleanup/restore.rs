use super::super::browser_policies;
use super::super::journal::{Journal, Outcome, RecoveryReport, ReportItem, Resource};
use super::super::platform::{Platform, classify_services};
use super::super::{FileCtx, Run, os_effects_enabled, state, with_journal};
use super::migration::migrate_legacy_with;
use crate::sysproxy::{Os, RealProbe, SystemProbe};

/// Which journal resources a restore pass covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Scope {
    /// Everything Zastava owns.
    All,
    /// Only the user environment (launchd / `HKCU\Environment`).
    UserEnv,
}

impl Scope {
    fn covers(self, r: &Resource) -> bool {
        match self {
            Scope::All => true,
            Scope::UserEnv => matches!(r, Resource::UserEnv { .. }),
        }
    }
}

fn is_network_setting(r: &Resource) -> bool {
    matches!(
        r,
        Resource::Pac { .. } | Resource::Chain { .. } | Resource::Bypass { .. }
    )
}

/// The recorded network settings of services that are VPN connections up right now. Writing
/// into such a service can drop the tunnel, so a restore leaves it alone. A service that is not in
/// the service list any more is not held (the restore only finds it gone); neither is a service
/// that could not be classified because the connection list is unreadable.
fn held_by_connected_vpn(j: &Journal, p: &dyn Platform, scope: Scope) -> Vec<Resource> {
    let Ok(services) = p.list_services() else {
        return Vec::new();
    };
    let kinds = classify_services(p, &services);
    j.entries()
        .iter()
        .filter(|e| scope.covers(&e.resource) && is_network_setting(&e.resource))
        .filter_map(|e| {
            let svc = match &e.resource {
                Resource::Pac { service }
                | Resource::Chain { service }
                | Resource::Bypass { service } => service,
                _ => return None,
            };
            let kind = kinds.iter().find(|(s, _)| s.key() == svc.key())?.1;
            matches!(
                kind,
                super::super::platform::ServiceKind::Vpn { connected: true }
            )
            .then(|| e.resource.clone())
        })
        .collect()
}

/// Restores the journal resources in `scope`. PAC and chain are written through `networksetup`;
/// while an active VPN keeps temporary DNS settings (or that cannot be checked) they are NOT
/// written: their records stay and the pass reports a failure, so a later pass finishes the job.
pub(crate) fn restore_with(j: &mut Journal, p: &dyn Platform, scope: Scope) -> RecoveryReport {
    let probe = os_effects_enabled().then_some((Os::current(), &RealProbe as &dyn SystemProbe));
    restore_with_probe(j, p, scope, probe)
}

pub(crate) fn restore_with_probe(
    j: &mut Journal,
    p: &dyn Platform,
    scope: Scope,
    probe: Option<(Os, &dyn SystemProbe)>,
) -> RecoveryReport {
    let net_ids: Vec<String> = j
        .entries()
        .iter()
        .filter(|e| scope.covers(&e.resource) && is_network_setting(&e.resource))
        .map(|e| e.resource.id())
        .collect();
    let dns_blocked = !net_ids.is_empty() && !matches!(p.temp_dns_overrides(), Ok(false));
    let vpn_held = if net_ids.is_empty() {
        Vec::new()
    } else {
        held_by_connected_vpn(j, p, scope)
    };
    let browser_held: Vec<Resource> = if let Some((os, pr)) = probe
        && j.entries().iter().any(|e| {
            scope.covers(&e.resource) && matches!(e.resource, Resource::BrowserPacPref { .. })
        }) {
        let running = browser_policies::inspect_running_browsers(pr, os, None);
        j.entries()
            .iter()
            .filter_map(|e| match &e.resource {
                Resource::BrowserPacPref { domain, .. } if scope.covers(&e.resource) => {
                    let is_running = match &running {
                        Some(map) => map.get(domain.as_str()).is_some_and(|i| i.running),
                        None => true,
                    };
                    is_running.then(|| e.resource.clone())
                }
                _ => None,
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut report = j.restore_where(p, |r| {
        scope.covers(r)
            && (!dns_blocked || !is_network_setting(r))
            && !vpn_held.contains(r)
            && !browser_held.contains(r)
    });
    for r in &vpn_held {
        // Not an error: the record stays and is put back once the VPN is disconnected.
        report.items.push(ReportItem {
            resource: r.id(),
            outcome: Outcome::Skipped("vpn"),
        });
    }
    for r in &browser_held {
        report.items.push(ReportItem {
            resource: r.id(),
            outcome: Outcome::Skipped("browser_running"),
        });
    }
    if dns_blocked {
        for id in net_ids {
            report.items.push(ReportItem {
                resource: id,
                outcome: Outcome::Failed("temp_dns"),
            });
        }
    }
    report
}

/// Restore of everything in the journal plus the one-time legacy migration, and the cut of an old
/// Zastava block out of `~/.zshenv` by its exact markers (a half marker or an edited block is
/// left as it is and named in the log).
pub(crate) fn restore_and_migrate(j: &mut Journal, p: &dyn Platform) -> RecoveryReport {
    restore_and_migrate_with(j, p, false)
}

/// [`restore_and_migrate`] for the start of the app (`at_app_start`): the protection is enabled
/// right after, so a leftover PAC on a physical service is left for that pass.
pub(crate) fn restore_and_migrate_with(
    j: &mut Journal,
    p: &dyn Platform,
    at_app_start: bool,
) -> RecoveryReport {
    let mut report = restore_with(j, p, Scope::All);
    report.items.extend(migrate_legacy_with(
        j,
        p,
        state().gateway_port(),
        at_app_start,
    ));
    if let Some(ctx) = FileCtx::real_with_fs(j.fs()) {
        let (strip, items) = super::super::cli_protection::clean_zshenv(j, p, &ctx);
        report.items.extend(items);
        if let Some(note) = strip.note("~/.zshenv") {
            eprintln!("Застава: {note}");
        }
        if !at_app_start && os_effects_enabled() {
            browser_policies::clear_stale_browser_pac_prefs_in(&ctx, Os::current(), &RealProbe);
        }
    }
    report
}

/// Restores the user environment recorded in the journal (what `disable_cli_protection` needs).
pub(crate) fn restore_user_env() -> RecoveryReport {
    match with_journal("ownership_restore_env", |j, p| {
        restore_with(j, p, Scope::UserEnv)
    }) {
        Run::Done(r) => r,
        Run::Blocked => RecoveryReport {
            skipped_dry_run: true,
            ..Default::default()
        },
        Run::Failed(_) => RecoveryReport {
            journal_write_failed: true,
            ..Default::default()
        },
    }
}

/// IDE / CLI settings files and shell profiles: the keys and blocks Zastava wrote are put back
/// through the journal (see `cli_protection::disable_files`).
pub(crate) fn cleanup_cli_files() -> RecoveryReport {
    super::super::cli_protection::disable_cli_files()
}
