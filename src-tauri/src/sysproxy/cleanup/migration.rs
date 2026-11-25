use super::super::journal::{Journal, Outcome, ReportItem, Resource};
use super::super::platform::{
    PacState, Platform, PlatformError, RegKind, RegValue, classify_services,
};
use super::signatures::{is_zastava_pac_signature, legacy_env_plan_with_gateway};
use std::collections::BTreeMap;

/// Names a 1.3.x build may have written into the user environment (launchd / `HKCU\Environment`).
const LEGACY_ENV_NAMES: [&str; 18] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "TZ",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_ADDRESS",
];

/// Marker of the finished one-time migration of PAC / WinINet leftovers (stored in the journal,
/// same lock, atomic).
pub(crate) const LEGACY_MIGRATION_MARK: &str = "legacy-1.3-signature-cleanup";

/// Marker of the finished one-time cleanup of the user environment (launchd / `HKCU\Environment`)
/// that 2.0.0 and 1.3.x left behind. Separate from [`LEGACY_MIGRATION_MARK`], which may already be
/// set by an earlier 2.1 build that did not know the 2.1 rules for the GUI session.
pub(crate) const LAUNCHD_MIGRATION_MARK: &str = "legacy-2.0-launchctl-cleanup";

/// Marker of the one-time cleanup of the PAC that 2.0.0 wrote into VPN services. Set only after
/// every VPN service was examined, which needs it to be disconnected: a connected one is never
/// touched, not even read, so the pass is repeated at a later start.
pub(crate) const VPN_PAC_MIGRATION_MARK: &str = "legacy-2.0-vpn-services-pac-cleanup";

/// One-time cleanups of what builds without a journal (1.3.x, 2.0) left behind: the user
/// environment ([`migrate_launchd_leftovers`]) and PAC / WinINet ([`migrate_legacy_pac`]). Each
/// has its own marker and runs until it has examined everything once.
#[cfg(test)]
pub(crate) fn migrate_legacy(
    j: &mut Journal,
    p: &dyn Platform,
    gateway_port: Option<u16>,
) -> Vec<ReportItem> {
    migrate_legacy_with(j, p, gateway_port, false)
}

/// [`migrate_legacy`]; with `defer_physical_pac` a leftover PAC on a physical service is not
/// cleared here. That is the start of the app: the protection is enabled right after and writes
/// the PAC into the same service, so clearing it first would be a pointless "off, then on" pair.
/// The enable pass adopts the leftover (see `Journal::apply`) with one write or none.
pub(crate) fn migrate_legacy_with(
    j: &mut Journal,
    p: &dyn Platform,
    gateway_port: Option<u16>,
    defer_physical_pac: bool,
) -> Vec<ReportItem> {
    let mut items = migrate_launchd_leftovers(j, p, gateway_port);
    items.extend(migrate_legacy_pac(j, p, gateway_port, defer_physical_pac));
    items.extend(migrate_vpn_pac_leftovers(j, p, gateway_port));
    items
}

/// User environment (launchd on macOS, `HKCU\Environment` on Windows). Since 2.1 Zastava puts
/// nothing there, so what 2.0.0 left is removed, by its signature only: the set selected by
/// [`legacy_env_plan_with_gateway`] (proxy variables whose value is our loopback address, our
/// `NO_PROXY`, `TZ` when a signed proxy variable is there too, `LANG` / `LC_*` with the value
/// `en_US.UTF-8`). A user's own `HTTPS_PROXY=http://corp:3128` or `TZ=Europe/Berlin` stays, and
/// so does everything the journal manages (the journal restores it by the general rule
/// "current value equals what we wrote"). The marker is set only when every name could be
/// examined, so a transient failure is retried at the next start; the second run changes
/// nothing and calls nothing.
pub(crate) fn migrate_launchd_leftovers(
    j: &mut Journal,
    p: &dyn Platform,
    gateway_port: Option<u16>,
) -> Vec<ReportItem> {
    let mut items = Vec::new();
    if j.has_mark(LAUNCHD_MIGRATION_MARK) {
        return items;
    }
    let mut complete = true;
    let mut names: Vec<String> = LEGACY_ENV_NAMES.iter().map(|s| s.to_string()).collect();
    if let Ok(listed) = p.list_user_env_names() {
        for n in listed {
            if n.to_ascii_uppercase().starts_with("LC_")
                && !names.iter().any(|k| k.eq_ignore_ascii_case(&n))
            {
                names.push(n);
            }
        }
    }
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    for name in &names {
        let managed = j.entry(&Resource::UserEnv { name: name.clone() }).is_some();
        if managed {
            continue;
        }
        match p.get_user_env(name) {
            Ok(Some(v)) => {
                env.insert(name.clone(), v);
            }
            Ok(None) | Err(PlatformError::Unsupported(_)) => {}
            Err(_) => complete = false,
        }
    }
    let mut env_removed = false;
    for name in legacy_env_plan_with_gateway(&env, gateway_port) {
        let ok = p.unset_user_env(&name).is_ok();
        env_removed |= ok;
        complete &= ok;
        items.push(ReportItem {
            resource: format!("legacy:env:{name}"),
            outcome: if ok {
                Outcome::Restored
            } else {
                Outcome::Failed("unset")
            },
        });
    }
    if env_removed {
        let _ = p.broadcast_env_change(); // only after a real change
    }

    if complete && j.set_mark(p, LAUNCHD_MIGRATION_MARK).is_err() {
        // The marker is not durable: the (idempotent) migration simply runs again next time.
    }
    items
}

/// Checks whether `url` matches Zastava's PAC signature (`gateway_port` or any loopback port).
fn is_orphaned_zastava_auto_config_url(url: &str, gateway_port: Option<u16>) -> bool {
    is_zastava_pac_signature(url, gateway_port)
        || crate::sysproxy::parse_gateway_port_from_pac_url(url)
            .is_some_and(|port| is_zastava_pac_signature(url, Some(port)))
}

/// Continuously sweeps orphaned Windows WinINet `AutoConfigURL` entries matching Zastava's PAC
/// signature (any loopback port) when not owned by an active journal entry, and refreshes WinINet.
pub(crate) fn sweep_orphaned_windows_auto_config_url(
    j: &Journal,
    p: &dyn Platform,
    gateway_port: Option<u16>,
) -> (Option<ReportItem>, bool) {
    if j.entry(&Resource::Inet {
        name: "AutoConfigURL".into(),
    })
    .is_some()
    {
        return (None, true);
    }
    match p.get_inet("AutoConfigURL") {
        Ok(Some(RegValue {
            kind: RegKind::Sz | RegKind::ExpandSz,
            data,
        })) if is_orphaned_zastava_auto_config_url(&data, gateway_port) => {
            let ok = p.delete_inet("AutoConfigURL").is_ok();
            if ok {
                let _ = p.notify_inet_refresh();
            }
            let item = ReportItem {
                resource: "legacy:inet:AutoConfigURL".to_string(),
                outcome: if ok {
                    Outcome::Restored
                } else {
                    Outcome::Failed("delete")
                },
            };
            (Some(item), ok)
        }
        Ok(_) | Err(PlatformError::Unsupported(_)) => (None, true),
        Err(_) => (None, false),
    }
}

/// Cleanup of PAC / WinINet values with the Zastava signature:
/// * macOS (one-time via [`LEGACY_MIGRATION_MARK`]): a PAC that is switched on and points at
///   `http://127.0.0.1|localhost:<our port>/proxy.pac` is switched off and its URL is cleared;
/// * Windows (continuous on every cleanup/recovery pass, regardless of [`LEGACY_MIGRATION_MARK`]):
///   an orphaned `AutoConfigURL` with Zastava's PAC signature on any loopback port is deleted and
///   WinINet is refreshed (`ProxyEnable` is never touched here).
///
/// Resources already in the journal belong to the journal and are skipped.
pub(crate) fn migrate_legacy_pac(
    j: &mut Journal,
    p: &dyn Platform,
    gateway_port: Option<u16>,
    defer_physical_pac: bool,
) -> Vec<ReportItem> {
    let mut items = Vec::new();
    let mut complete = true;

    // 2. macOS PAC with the signature, left switched on by a build that was killed (one-time).
    if !j.has_mark(LEGACY_MIGRATION_MARK) {
        match p.list_services() {
            Ok(services) => {
                let mut candidates = Vec::new();
                let enabled: Vec<_> = services.into_iter().filter(|s| s.enabled).collect();
                // Only physical services here; VPN services have their own, gentler pass.
                for (svc, kind) in classify_services(p, &enabled) {
                    if !kind.is_physical() {
                        continue;
                    }
                    let svc = &svc;
                    if j.entry(&Resource::Pac {
                        service: svc.clone(),
                    })
                    .is_some()
                    {
                        continue;
                    }
                    match p.get_pac(svc) {
                        Ok(st) => {
                            let signed = st
                                .url
                                .as_deref()
                                .is_some_and(|u| is_zastava_pac_signature(u, gateway_port));
                            if signed && st.enabled == Some(true) {
                                if defer_physical_pac {
                                    // Left for the enable pass; the marker waits until it has run.
                                    complete = false;
                                } else {
                                    candidates.push(svc.clone());
                                }
                            }
                        }
                        Err(PlatformError::Unsupported(_)) => {}
                        Err(_) => complete = false,
                    }
                }
                if !candidates.is_empty() {
                    // Same guard as for every other write through networksetup.
                    if matches!(p.temp_dns_overrides(), Ok(false)) {
                        for svc in candidates {
                            let ok = p
                                .set_pac(
                                    &svc,
                                    &PacState {
                                        url: Some(String::new()),
                                        enabled: Some(false),
                                    },
                                )
                                .is_ok();
                            complete &= ok;
                            items.push(ReportItem {
                                resource: format!("legacy:pac:{}", svc.key()),
                                outcome: if ok {
                                    Outcome::Restored
                                } else {
                                    Outcome::Failed("set_pac")
                                },
                            });
                        }
                    } else {
                        complete = false;
                    }
                }
            }
            Err(PlatformError::Unsupported(_)) => {}
            Err(_) => complete = false,
        }
    }

    // 3. Windows AutoConfigURL with the signature (always swept regardless of LEGACY_MIGRATION_MARK).
    let (win_item, win_ok) = sweep_orphaned_windows_auto_config_url(j, p, gateway_port);
    if let Some(item) = win_item {
        items.push(item);
    }
    complete &= win_ok;

    if !j.has_mark(LEGACY_MIGRATION_MARK)
        && complete
        && j.set_mark(p, LEGACY_MIGRATION_MARK).is_err()
    {
        // The marker is not durable: the (idempotent) migration simply runs again next time.
    }
    items
}

/// One-time cleanup of the PAC that 2.0.0 left in VPN services (it wrote into every enabled
/// service). Only a service that is surely Disconnected is examined, and only a PAC that is
/// switched on and has our loopback address is cleared; a connected (or unknown) VPN is not
/// touched at all, because a write into its service can drop the tunnel. The leftover there is
/// harmless: the address does not answer without Zastava, so the system goes direct.
fn migrate_vpn_pac_leftovers(
    j: &mut Journal,
    p: &dyn Platform,
    gateway_port: Option<u16>,
) -> Vec<ReportItem> {
    let mut items = Vec::new();
    if j.has_mark(VPN_PAC_MIGRATION_MARK) {
        return items;
    }
    let Ok(services) = p.list_services() else {
        return items; // not macOS, or unreadable: nothing to clear, retried later
    };
    let enabled: Vec<_> = services.into_iter().filter(|s| s.enabled).collect();
    let mut complete = true;
    let mut candidates = Vec::new();
    for (svc, kind) in classify_services(p, &enabled) {
        if kind.is_physical() {
            continue;
        }
        if j.entry(&Resource::Pac {
            service: svc.clone(),
        })
        .is_some()
        {
            continue; // the journal restores it by the general rule
        }
        if !kind.is_idle_vpn() {
            complete = false; // connected or unknown: not touched, not even read
            continue;
        }
        match p.get_pac(&svc) {
            Ok(st) => {
                let signed = st
                    .url
                    .as_deref()
                    .is_some_and(|u| is_zastava_pac_signature(u, gateway_port));
                if signed && st.enabled == Some(true) {
                    candidates.push(svc);
                }
            }
            Err(PlatformError::Unsupported(_)) => {}
            Err(_) => complete = false,
        }
    }
    if !candidates.is_empty() {
        if matches!(p.temp_dns_overrides(), Ok(false)) {
            for svc in candidates {
                let ok = p
                    .set_pac(
                        &svc,
                        &PacState {
                            url: Some(String::new()),
                            enabled: Some(false),
                        },
                    )
                    .is_ok();
                complete &= ok;
                items.push(ReportItem {
                    resource: format!("legacy:vpn-pac:{}", svc.key()),
                    outcome: if ok {
                        Outcome::Restored
                    } else {
                        Outcome::Failed("set_pac")
                    },
                });
            }
        } else {
            complete = false;
        }
    }
    if complete && j.set_mark(p, VPN_PAC_MIGRATION_MARK).is_err() {
        // Not durable: the pass simply runs again next time.
    }
    items
}
