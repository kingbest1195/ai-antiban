//! Process-exit safety net and cleanup entry points: panic flag, OS signal watcher, restore of
//! the ownership journal and the one-time, signature-based cleanup of 1.3.x leftovers.

use super::journal::{self, Journal, Outcome, RecoveryReport, ReportItem, Resource};
use super::platform::{Platform, PlatformError, RegKind, RegValue};
use super::{
    CLI_PROTECTION_ACTIVE, LAST_PAC_URL, NO_PROXY_VALUE, Run, SYS_PROXY_ACTIVE,
    parse_gateway_port_from_pac_url, set_chained_proxy, with_journal,
};
use std::collections::BTreeMap;
use std::sync::Once;
use std::sync::atomic::Ordering;

static CLEAN_HOOK_INIT: Once = Once::new();

/// Registers the panic hook once per process. The hook only raises a flag: no I/O and no system
/// call from inside a panic. Everything Zastava changed is in the journal, so the restore
/// happens at the next start (the release build aborts on panic; SIGKILL is the same case).
pub fn register_clean_exit_guard() {
    CLEAN_HOOK_INIT.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            journal::note_panic();
            default_hook(panic_info);
        }));
    });
}

/// Spawns an asynchronous OS signal watcher (`SIGINT` / `SIGTERM` / `SIGHUP`) that restores the
/// system settings Zastava changed before the process terminates.
pub fn spawn_signal_cleanup_watcher() {
    tauri::async_runtime::spawn(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate()).ok();
            let mut sighup = signal(SignalKind::hangup()).ok();

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = async {
                    match &mut sigterm {
                        Some(s) => { let _ = s.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {},
                _ = async {
                    match &mut sighup {
                        Some(s) => { let _ = s.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {},
            }
        }

        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }

        eprintln!("Termination signal received! Restoring system settings...");
        let _ = cleanup_all_persistent_settings();
        std::process::exit(0);
    });
}

/// Proxy variables that older Zastava versions wrote into `HKCU\Environment`.
const LEGACY_PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

/// Whether `value` is a Zastava gateway address (`127.0.0.1`/`localhost` on 8899, 8900 or the
/// current gateway port), with or without a scheme, trailing slash or `/proxy.pac`.
fn is_zastava_env_signature(value: &str, gateway_port: Option<u16>) -> bool {
    let v = value.trim();
    let v = v
        .strip_prefix("http://")
        .or_else(|| v.strip_prefix("https://"))
        .unwrap_or(v);
    let host_port = v.split('/').next().unwrap_or("");
    let Some((host, port)) = host_port.rsplit_once(':') else {
        return false;
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    let host = host.trim().to_ascii_lowercase();
    if host != "127.0.0.1" && host != "localhost" {
        return false;
    }
    port == 8899 || port == 8900 || gateway_port.is_some_and(|gp| gp > 0 && port == gp)
}

/// Decides which `HKCU\Environment` values were written by Zastava and may be deleted.
///
/// The set counts as written by Zastava only when at least one of `HTTP(S)_PROXY` / `ALL_PROXY`
/// carries the Zastava gateway signature (`127.0.0.1:8899`, `:8900`). Then the proxy variables that
/// carry the signature, `NO_PROXY` with Zastava's own value, `TZ`, `LANG` and `LC_*` are returned;
/// otherwise nothing is: a user's own `HTTPS_PROXY=http://corp:3128` or `TZ=Europe/Berlin` stays.
pub fn legacy_env_plan(env: &BTreeMap<String, String>) -> Vec<String> {
    let gateway_port = LAST_PAC_URL
        .lock()
        .ok()
        .and_then(|g| g.as_deref().and_then(parse_gateway_port_from_pac_url));
    legacy_env_plan_with_gateway(env, gateway_port)
}

/// Same as [`legacy_env_plan`] with an explicit current gateway port.
pub fn legacy_env_plan_with_gateway(
    env: &BTreeMap<String, String>,
    gateway_port: Option<u16>,
) -> Vec<String> {
    let is_proxy_var = |name: &str| {
        LEGACY_PROXY_VARS
            .iter()
            .any(|v| v.eq_ignore_ascii_case(name))
    };
    let signed = env
        .iter()
        .any(|(k, v)| is_proxy_var(k) && is_zastava_env_signature(v, gateway_port));
    if !signed {
        return Vec::new();
    }
    env.iter()
        .filter(|(k, v)| {
            let k = k.as_str();
            if is_proxy_var(k) {
                is_zastava_env_signature(v, gateway_port)
            } else if k.eq_ignore_ascii_case("NO_PROXY") {
                v.trim() == NO_PROXY_VALUE
            } else {
                k.eq_ignore_ascii_case("TZ")
                    || k.eq_ignore_ascii_case("LANG")
                    || k.to_ascii_uppercase().starts_with("LC_")
            }
        })
        .map(|(k, _)| k.clone())
        .collect()
}

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

/// Marker of the finished one-time migration (stored in the journal, same lock, atomic).
pub(super) const LEGACY_MIGRATION_MARK: &str = "legacy-1.3-signature-cleanup";

fn gateway_port_now() -> Option<u16> {
    LAST_PAC_URL
        .lock()
        .ok()
        .and_then(|g| g.as_deref().and_then(parse_gateway_port_from_pac_url))
}

/// One-time cleanup of what builds without a journal (1.3.x, 2.0) left behind. Without a journal
/// the previous state cannot be known, so only values carrying Zastava's own signature
/// (`127.0.0.1` / `localhost` on 8899, 8900 or the current gateway port) are touched:
/// * user environment: the set selected by [`legacy_env_plan_with_gateway`] (proxy variables with
///   the signature, our `NO_PROXY`, `TZ`, `LANG`, `LC_*` - only when at least one proxy variable
///   is signed), so a user's own `HTTPS_PROXY=http://corp:3128` or `TZ=Europe/Berlin` stays;
/// * macOS: a PAC that is switched on and points at the signature is switched off (the URL stays);
/// * Windows: an `AutoConfigURL` with the signature is deleted (`ProxyEnable` is never touched).
///
/// Resources already in the journal belong to the journal and are skipped. The marker is set only
/// when every step could be examined, so a transient failure is retried at the next start.
pub(super) fn migrate_legacy(
    j: &mut Journal,
    p: &dyn Platform,
    gateway_port: Option<u16>,
) -> Vec<ReportItem> {
    let mut items = Vec::new();
    if j.has_mark(LEGACY_MIGRATION_MARK) {
        return items;
    }
    let mut complete = true;

    // 1. User environment.
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

    // 2. macOS PAC with the signature, left switched on by a build that was killed.
    match p.list_services() {
        Ok(services) => {
            let mut candidates = Vec::new();
            for svc in services.iter().filter(|s| s.enabled) {
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
                            .is_some_and(|u| is_zastava_env_signature(u, gateway_port));
                        if signed && st.enabled == Some(true) {
                            candidates.push(svc.clone());
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
                                &super::platform::PacState {
                                    url: None,
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

    // 3. Windows AutoConfigURL with the signature.
    if j.entry(&Resource::Inet {
        name: "AutoConfigURL".into(),
    })
    .is_none()
    {
        match p.get_inet("AutoConfigURL") {
            Ok(Some(RegValue {
                kind: RegKind::Sz,
                data,
            })) if is_zastava_env_signature(&data, gateway_port) => {
                let ok = p.delete_inet("AutoConfigURL").is_ok();
                if ok {
                    let _ = p.notify_inet_refresh();
                }
                complete &= ok;
                items.push(ReportItem {
                    resource: "legacy:inet:AutoConfigURL".to_string(),
                    outcome: if ok {
                        Outcome::Restored
                    } else {
                        Outcome::Failed("delete")
                    },
                });
            }
            Ok(_) | Err(PlatformError::Unsupported(_)) => {}
            Err(_) => complete = false,
        }
    }

    if complete && j.set_mark(p, LEGACY_MIGRATION_MARK).is_err() {
        // The marker is not durable: the (idempotent) migration simply runs again next time.
    }
    items
}

/// Which journal resources a restore pass covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Scope {
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
    matches!(r, Resource::Pac { .. } | Resource::Chain { .. })
}

/// Restores the journal resources in `scope`. PAC and chain are written through `networksetup`;
/// while an active VPN keeps temporary DNS settings (or that cannot be checked) they are NOT
/// written: their records stay and the pass reports a failure, so a later pass finishes the job.
pub(super) fn restore_with(j: &mut Journal, p: &dyn Platform, scope: Scope) -> RecoveryReport {
    let net_ids: Vec<String> = j
        .entries()
        .iter()
        .filter(|e| scope.covers(&e.resource) && is_network_setting(&e.resource))
        .map(|e| e.resource.id())
        .collect();
    let dns_blocked = !net_ids.is_empty() && !matches!(p.temp_dns_overrides(), Ok(false));
    let mut report = j.restore_where(p, |r| {
        scope.covers(r) && !(dns_blocked && is_network_setting(r))
    });
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

/// Restore of everything in the journal plus the one-time legacy migration.
pub(super) fn restore_and_migrate(j: &mut Journal, p: &dyn Platform) -> RecoveryReport {
    let mut report = restore_with(j, p, Scope::All);
    report
        .items
        .extend(migrate_legacy(j, p, gateway_port_now()));
    report
}

/// Restores the user environment recorded in the journal (what `disable_cli_protection` needs).
pub(super) fn restore_user_env() -> RecoveryReport {
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

/// IDE / CLI settings files and shell profiles (the file side is handled separately, and is
/// still as in 2.0 until it gets the same journal treatment).
pub(super) fn cleanup_cli_files() {
    super::cli_protection::disable_cli_files();
}

/// Restores everything Zastava changed in the system from the ownership journal (PAC, chained
/// proxy, WinINet, user environment), runs the one-time legacy migration and cleans the CLI/IDE
/// files. Anything that cannot be restored right now (temporary VPN DNS, busy journal) stays
/// recorded and is finished at the next start; the report says what was not done.
pub fn cleanup_all_persistent_settings() -> RecoveryReport {
    let report = match with_journal("ownership_cleanup", restore_and_migrate) {
        Run::Done(r) => r,
        Run::Blocked => RecoveryReport {
            skipped_dry_run: true,
            ..Default::default()
        },
        Run::Failed(_) => RecoveryReport {
            journal_write_failed: true,
            ..Default::default()
        },
    };
    cleanup_cli_files();
    SYS_PROXY_ACTIVE.store(false, Ordering::SeqCst);
    CLI_PROTECTION_ACTIVE.store(false, Ordering::SeqCst);
    if let Ok(mut g) = LAST_PAC_URL.lock() {
        *g = None;
    }
    set_chained_proxy(None);
    report
}

/// Forcefully restores all system settings Zastava owns and cleans CLI/IDE files, returning a
/// human-readable list of the cleaned components. Foreign settings are never touched.
pub fn force_clean_all_os_proxy_traces() -> Vec<String> {
    let _ = cleanup_all_persistent_settings();
    cleaned_components()
}

/// Names of the components a full cleanup covers (for the user-facing result list).
pub fn cleaned_components() -> Vec<String> {
    vec![
        "Системный PAC-прокси".to_string(),
        "Конфигурации VS Code / Cursor / Claude".to_string(),
        "Профили терминала и переменные среды ОС".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysproxy::fs::FakeFs;
    use crate::sysproxy::journal::{Journal, Value, recover_with};
    use crate::sysproxy::platform::{
        ChainState, FakePlatform, PacState, PlatOp, ProxyEndpoint, ServiceId,
    };
    use crate::sysproxy::{
        SysProxy, dry_run_blocked_calls, is_sysproxy_active, os_effects_enabled,
    };
    use std::path::Path;
    use std::sync::Arc;

    const DIR: &str = "/data";

    fn open(fs: &FakeFs) -> Journal {
        Journal::open(Arc::new(fs.clone()), Path::new(DIR)).unwrap()
    }
    fn wifi() -> ServiceId {
        ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
    }
    fn env_res(name: &str) -> Resource {
        Resource::UserEnv { name: name.into() }
    }

    // --- entry points never touch the OS in unit tests -------------------------------------

    #[test]
    fn cleanup_entry_points_run_in_dry_run_without_touching_the_os() {
        assert!(
            !os_effects_enabled(),
            "unit tests must run in OS dry-run mode"
        );
        let before = dry_run_blocked_calls();
        register_clean_exit_guard();
        SysProxy::disable();
        assert!(!SysProxy::is_active());
        let report = cleanup_all_persistent_settings();
        assert!(report.skipped_dry_run);
        assert!(!is_sysproxy_active());
        assert_eq!(force_clean_all_os_proxy_traces().len(), 3);
        assert!(cleaned_components().iter().any(|c| c.contains("PAC")));
        assert!(
            dry_run_blocked_calls() > before,
            "the journal gate must have counted the calls"
        );
    }

    #[test]
    fn panic_hook_only_raises_the_flag() {
        register_clean_exit_guard();
        let before = dry_run_blocked_calls();
        let _ = std::panic::catch_unwind(|| panic!("probe"));
        assert!(journal::panic_flagged());
        assert_eq!(
            dry_run_blocked_calls(),
            before,
            "no system call from the hook"
        );
    }

    // --- restore / DNS guard ---------------------------------------------------------------

    fn own_pac(j: &mut Journal, p: &FakePlatform) {
        j.apply(
            p,
            &Resource::Pac { service: wifi() },
            Value::Pac(PacState {
                url: Some("http://127.0.0.1:8899/proxy.pac".into()),
                enabled: Some(true),
            }),
        )
        .unwrap();
    }

    #[test]
    fn cleanup_of_our_pac_under_temporary_dns_keeps_the_record_and_reports_an_error() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.add_service(wifi());
        p.seed_pac(
            &wifi(),
            PacState {
                url: None,
                enabled: Some(false),
            },
        );
        let mut j = open(&fs);
        own_pac(&mut j, &p);
        j.apply(&p, &env_res("HTTPS_PROXY"), Value::Env(Some("x".into())))
            .unwrap();
        p.set_temp_dns(true);
        let writes = p.os_writes();
        let rep = restore_with(&mut j, &p, Scope::All);
        assert!(rep.has_failures());
        assert_eq!(rep.failed(), 1);
        assert!(
            j.entry(&Resource::Pac { service: wifi() }).is_some(),
            "record kept"
        );
        assert_eq!(p.pac_of(&wifi()).enabled, Some(true), "PAC not written");
        assert_eq!(
            p.os_writes(),
            writes + 1,
            "only the environment variable was restored"
        );
        assert_eq!(p.env_of("HTTPS_PROXY"), None);
        // The VPN goes away: the next pass finishes the job.
        p.set_temp_dns(false);
        let rep = restore_with(&mut j, &p, Scope::All);
        assert_eq!(rep.restored(), 1);
        assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
        assert!(j.is_empty());
    }

    #[test]
    fn unknown_dns_state_also_defers_network_restores() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.add_service(wifi());
        let mut j = open(&fs);
        own_pac(&mut j, &p);
        p.fail_next(PlatOp::TempDns);
        let rep = restore_with(&mut j, &p, Scope::All);
        assert_eq!(rep.failed(), 1);
        assert!(!j.is_empty());
    }

    #[test]
    fn env_only_restore_does_not_touch_pac_nor_ask_about_dns() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.add_service(wifi());
        let mut j = open(&fs);
        own_pac(&mut j, &p);
        j.apply(&p, &env_res("HTTP_PROXY"), Value::Env(Some("x".into())))
            .unwrap();
        p.clear_calls();
        let rep = restore_with(&mut j, &p, Scope::UserEnv);
        assert_eq!(rep.restored(), 1);
        assert!(!p.calls().iter().any(|c| c.starts_with("temp_dns")));
        assert!(j.entry(&Resource::Pac { service: wifi() }).is_some());
        assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
    }

    #[test]
    fn restore_after_a_hard_kill_returns_everything_in_one_pass() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.add_service(wifi());
        p.seed_env("TZ", "Europe/Berlin");
        {
            let mut j = open(&fs);
            own_pac(&mut j, &p);
            j.apply(
                &p,
                &env_res("HTTPS_PROXY"),
                Value::Env(Some("http://127.0.0.1:8899".into())),
            )
            .unwrap();
            // kill -9: no cleanup runs, only the file remains.
        }
        let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert_eq!(r.restored(), 2);
        assert_eq!(p.env_of("HTTPS_PROXY"), None);
        assert_eq!(
            p.env_of("TZ"),
            Some("Europe/Berlin".into()),
            "a foreign TZ is never touched"
        );
        // Running it twice changes nothing.
        let writes = p.os_writes();
        let mut j = open(&fs);
        assert_eq!(restore_with(&mut j, &p, Scope::All).items.len(), 0);
        assert_eq!(p.os_writes(), writes);
    }

    // --- legacy_env_plan (pure) -------------------------------------------------------------

    fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn legacy_env_plan_keeps_foreign_proxy_and_timezone() {
        let env = env_of(&[("HTTPS_PROXY", "http://corp:3128"), ("TZ", "Europe/Berlin")]);
        assert!(legacy_env_plan_with_gateway(&env, None).is_empty());
    }

    #[test]
    fn legacy_env_plan_removes_whole_signed_set() {
        let env = env_of(&[
            ("HTTP_PROXY", "http://127.0.0.1:8899"),
            ("HTTPS_PROXY", "http://127.0.0.1:8899"),
            ("ALL_PROXY", "http://127.0.0.1:8899"),
            ("NO_PROXY", NO_PROXY_VALUE),
            ("TZ", "Europe/Amsterdam"),
            ("LANG", "en_US.UTF-8"),
            ("LC_TIME", "en_US.UTF-8"),
            ("LC_ALL", "en_US.UTF-8"),
        ]);
        let mut plan = legacy_env_plan_with_gateway(&env, None);
        plan.sort();
        let mut expected: Vec<String> = env.keys().cloned().collect();
        expected.sort();
        assert_eq!(plan, expected);
    }

    #[test]
    fn legacy_env_plan_empty_environment() {
        assert!(legacy_env_plan_with_gateway(&BTreeMap::new(), Some(8899)).is_empty());
    }

    #[test]
    fn legacy_env_plan_timezone_only_is_not_ours() {
        let env = env_of(&[("TZ", "Europe/Moscow"), ("LANG", "ru_RU.UTF-8")]);
        assert!(legacy_env_plan_with_gateway(&env, None).is_empty());
    }

    #[test]
    fn legacy_env_plan_mixed_set_removes_only_signed_proxy_vars() {
        let env = env_of(&[
            ("HTTP_PROXY", "http://127.0.0.1:8899"),
            ("HTTPS_PROXY", "http://corp:3128"),
            ("NO_PROXY", "internal.example"),
            ("TZ", "Europe/Helsinki"),
            ("Path", r"C:\Windows"),
        ]);
        let mut plan = legacy_env_plan_with_gateway(&env, None);
        plan.sort();
        assert_eq!(plan, vec!["HTTP_PROXY".to_string(), "TZ".to_string()]);
    }

    #[test]
    fn legacy_env_plan_recognises_8900_and_custom_gateway_port() {
        let env_8900 = env_of(&[
            ("ALL_PROXY", "http://127.0.0.1:8900/"),
            ("LC_ALL", "en_US.UTF-8"),
        ]);
        assert_eq!(legacy_env_plan_with_gateway(&env_8900, None).len(), 2);

        let env_custom = env_of(&[
            ("https_proxy", "http://localhost:9123"),
            ("TZ", "Asia/Tokyo"),
        ]);
        assert!(legacy_env_plan_with_gateway(&env_custom, None).is_empty());
        assert_eq!(
            legacy_env_plan_with_gateway(&env_custom, Some(9123)).len(),
            2
        );

        // Look-alikes are not signatures.
        let lookalike = env_of(&[("HTTP_PROXY", "http://127.0.0.1:88990"), ("TZ", "UTC")]);
        assert!(legacy_env_plan_with_gateway(&lookalike, Some(9123)).is_empty());
        let foreign_host = env_of(&[("HTTP_PROXY", "http://10.0.0.1:8899"), ("TZ", "UTC")]);
        assert!(legacy_env_plan_with_gateway(&foreign_host, None).is_empty());
    }

    // --- one-time migration of 1.3.x leftovers -----------------------------------------------

    #[test]
    fn migration_removes_the_signed_set_through_the_platform_and_sets_the_mark() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_env("HTTPS_PROXY", "http://127.0.0.1:8899");
        p.seed_env("HTTP_PROXY", "http://127.0.0.1:8900");
        p.seed_env("NO_PROXY", NO_PROXY_VALUE);
        p.seed_env("TZ", "Europe/Amsterdam");
        let mut j = open(&fs);
        let items = migrate_legacy(&mut j, &p, None);
        assert_eq!(items.len(), 4);
        for n in ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "TZ"] {
            assert_eq!(p.env_of(n), None, "{n}");
        }
        assert!(j.has_mark(LEGACY_MIGRATION_MARK));
        assert!(
            p.calls()
                .iter()
                .any(|c| c.starts_with("broadcast_env_change"))
        );
    }

    #[test]
    fn migration_without_the_signature_touches_nothing() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_env("HTTPS_PROXY", "http://corp:3128");
        p.seed_env("TZ", "Europe/Berlin");
        p.seed_env("LANG", "de_DE.UTF-8");
        p.seed_env("HTTP_PROXY", "http://localhost:3128");
        let mut j = open(&fs);
        assert!(migrate_legacy(&mut j, &p, None).is_empty());
        assert_eq!(p.os_writes(), 0);
        assert_eq!(p.env_of("HTTPS_PROXY"), Some("http://corp:3128".into()));
        assert_eq!(p.env_of("TZ"), Some("Europe/Berlin".into()));
        assert!(
            !p.calls()
                .iter()
                .any(|c| c.starts_with("broadcast_env_change")),
            "no change, no broadcast"
        );
        assert!(
            j.has_mark(LEGACY_MIGRATION_MARK),
            "examined completely, so done"
        );
    }

    #[test]
    fn migration_runs_once_and_the_mark_survives_a_restart() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        {
            let mut j = open(&fs);
            migrate_legacy(&mut j, &p, None);
        }
        // Leftovers that appear later are no longer "legacy": the migration does not run again.
        p.seed_env("HTTPS_PROXY", "http://127.0.0.1:8899");
        let mut j = open(&fs);
        assert!(j.has_mark(LEGACY_MIGRATION_MARK));
        assert!(migrate_legacy(&mut j, &p, None).is_empty());
        assert_eq!(
            p.env_of("HTTPS_PROXY"),
            Some("http://127.0.0.1:8899".into())
        );
    }

    #[test]
    fn migration_failure_keeps_the_values_and_is_retried() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_env("HTTPS_PROXY", "http://127.0.0.1:8899");
        let mut j = open(&fs);
        p.fail_next(PlatOp::UnsetEnv);
        let items = migrate_legacy(&mut j, &p, None);
        assert!(
            items
                .iter()
                .any(|i| matches!(i.outcome, Outcome::Failed(_)))
        );
        assert!(!j.has_mark(LEGACY_MIGRATION_MARK));
        migrate_legacy(&mut j, &p, None);
        assert_eq!(p.env_of("HTTPS_PROXY"), None);
        assert!(j.has_mark(LEGACY_MIGRATION_MARK));
    }

    #[test]
    fn migration_skips_variables_the_journal_manages() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        let mut j = open(&fs);
        j.apply(
            &p,
            &env_res("HTTPS_PROXY"),
            Value::Env(Some("http://127.0.0.1:8899".into())),
        )
        .unwrap();
        migrate_legacy(&mut j, &p, None);
        assert_eq!(
            p.env_of("HTTPS_PROXY"),
            Some("http://127.0.0.1:8899".into()),
            "the journal restores it, the migration does not guess"
        );
    }

    #[test]
    fn migration_switches_off_a_dead_signed_pac_but_never_a_foreign_one() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        let usb = ServiceId::new("en5", "USB LAN", "USB LAN");
        p.add_service(wifi());
        p.add_service(usb.clone());
        p.seed_pac(
            &wifi(),
            PacState {
                url: Some("http://127.0.0.1:8899/proxy.pac".into()),
                enabled: Some(true),
            },
        );
        p.seed_pac(
            &usb,
            PacState {
                url: Some("http://corp/p.pac".into()),
                enabled: Some(true),
            },
        );
        let mut j = open(&fs);
        migrate_legacy(&mut j, &p, None);
        assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
        assert_eq!(p.pac_of(&usb).enabled, Some(true));
        assert_eq!(p.pac_of(&usb).url.as_deref(), Some("http://corp/p.pac"));
    }

    #[test]
    fn migration_of_pac_waits_for_temporary_dns_and_keeps_the_mark_unset() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.add_service(wifi());
        p.seed_pac(
            &wifi(),
            PacState {
                url: Some("http://127.0.0.1:8899/proxy.pac".into()),
                enabled: Some(true),
            },
        );
        p.set_temp_dns(true);
        let mut j = open(&fs);
        migrate_legacy(&mut j, &p, None);
        assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
        assert!(!j.has_mark(LEGACY_MIGRATION_MARK));
        p.set_temp_dns(false);
        migrate_legacy(&mut j, &p, None);
        assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
        assert!(j.has_mark(LEGACY_MIGRATION_MARK));
    }

    #[test]
    fn migration_deletes_a_signed_wininet_pac_only() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_inet(
            "AutoConfigURL",
            RegValue::sz("http://127.0.0.1:8899/proxy.pac"),
        );
        p.seed_inet("ProxyEnable", RegValue::dword(1));
        let mut j = open(&fs);
        migrate_legacy(&mut j, &p, None);
        assert_eq!(p.inet_of("AutoConfigURL"), None);
        assert_eq!(p.inet_of("ProxyEnable"), Some(RegValue::dword(1)));

        let (fs2, p2) = (FakeFs::new(), FakePlatform::new());
        p2.seed_inet("AutoConfigURL", RegValue::sz("http://corp/p.pac"));
        let mut j2 = open(&fs2);
        migrate_legacy(&mut j2, &p2, None);
        assert_eq!(
            p2.inet_of("AutoConfigURL"),
            Some(RegValue::sz("http://corp/p.pac"))
        );
        assert_eq!(p2.os_writes(), 0);
    }

    #[test]
    fn migration_also_finds_locale_variables_the_registry_lists() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.seed_env("HTTPS_PROXY", "http://127.0.0.1:8899");
        p.seed_env("LC_IDENTIFICATION", "en_US.UTF-8");
        let mut j = open(&fs);
        migrate_legacy(&mut j, &p, None);
        assert_eq!(p.env_of("LC_IDENTIFICATION"), None);
    }

    #[test]
    fn chain_endpoints_are_untouched_by_the_migration() {
        let (fs, p) = (FakeFs::new(), FakePlatform::new());
        p.add_service(wifi());
        let chain = ChainState {
            http: ProxyEndpoint {
                enabled: Some(true),
                server: Some("127.0.0.1".into()),
                port: Some(8899),
                authenticated: None,
            },
            https: ProxyEndpoint::default(),
        };
        p.seed_chain(&wifi(), chain.clone());
        let mut j = open(&fs);
        migrate_legacy(&mut j, &p, None);
        assert_eq!(
            p.chain_of(&wifi()),
            chain,
            "no signature-based guessing for explicit proxies"
        );
    }
}
