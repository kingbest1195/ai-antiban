//! Process-exit safety net and cleanup entry points: panic hook, OS signal watcher,
//! forced removal of every proxy trace, and signature-based legacy Windows `HKCU\Environment` cleanup.

#[cfg(target_os = "windows")]
use super::windows::{broadcast_windows_env_change, delete_windows_user_env_var};
use super::{
    LAST_PAC_URL, NO_PROXY_VALUE, disable_all_sysproxy, disable_cli_protection,
    parse_gateway_port_from_pac_url,
};
use std::collections::BTreeMap;
use std::sync::Once;

static CLEAN_HOOK_INIT: Once = Once::new();

/// Registers panic hook and cleanup guard once per process.
pub fn register_clean_exit_guard() {
    CLEAN_HOOK_INIT.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            eprintln!("Panic detected! Executing emergency system PAC proxy cleanup...");
            disable_all_sysproxy();
            default_hook(panic_info);
        }));
    });
}

/// Spawns an asynchronous OS signal watcher (`SIGINT` / `SIGTERM` / `SIGHUP`) that guarantees
/// systemic PAC proxy settings are disabled before the process terminates.
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

        eprintln!("Termination signal received! Cleaning up system PAC proxy...");
        disable_all_sysproxy();
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

/// Access to the Windows user environment (`HKCU\Environment`). A trait so the cleanup decision
/// can be tested on any platform with a fake registry.
pub trait WinEnv {
    /// All string values currently stored under `HKCU\Environment`.
    fn read_user_env(&self) -> BTreeMap<String, String>;
    /// Deletes one value (no error if it does not exist).
    fn delete_user_env(&mut self, name: &str);
    /// Broadcasts `WM_SETTINGCHANGE` ("Environment") so running apps reload the environment.
    fn broadcast_change(&mut self);
}

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

/// Reads the environment through `env`, deletes what [`legacy_env_plan_with_gateway`] selects and
/// broadcasts the change only when something was removed. Returns the removed names.
pub fn cleanup_legacy_user_env_with(
    env: &mut dyn WinEnv,
    gateway_port: Option<u16>,
) -> Vec<String> {
    let plan = legacy_env_plan_with_gateway(&env.read_user_env(), gateway_port);
    for name in &plan {
        env.delete_user_env(name);
    }
    if !plan.is_empty() {
        env.broadcast_change();
    }
    plan
}

/// Parses `reg query HKCU\Environment` output (`    NAME    REG_SZ    value`) into a map.
/// Only `REG_SZ` / `REG_EXPAND_SZ` values are returned.
pub fn parse_reg_query_environment(output: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in output.lines() {
        let line = line.trim();
        let Some(name_end) = line.find(char::is_whitespace) else {
            continue;
        };
        let (name, rest) = line.split_at(name_end);
        let rest = rest.trim_start();
        let value = ["REG_EXPAND_SZ", "REG_SZ"]
            .iter()
            .find_map(|t| rest.strip_prefix(t))
            .filter(|v| v.is_empty() || v.starts_with(char::is_whitespace));
        if let Some(v) = value {
            map.insert(name.to_string(), v.trim().to_string());
        }
    }
    map
}

/// The real registry-backed implementation (Windows only; verified in Windows CI).
#[cfg(target_os = "windows")]
struct RegistryWinEnv;

#[cfg(target_os = "windows")]
impl WinEnv for RegistryWinEnv {
    fn read_user_env(&self) -> BTreeMap<String, String> {
        super::silent_command("reg")
            .args(["query", r"HKCU\Environment"])
            .output()
            .map(|o| parse_reg_query_environment(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }

    fn delete_user_env(&mut self, name: &str) {
        let _ = delete_windows_user_env_var(name);
    }

    fn broadcast_change(&mut self) {
        broadcast_windows_env_change();
    }
}

/// Removes proxy / timezone (`TZ`) / locale (`LANG`, `LC_*`) values that Zastava itself once wrote
/// into `HKCU\Environment` on Windows, recognised by the gateway signature (see
/// [`legacy_env_plan`]); a user's own variables are never touched. Broadcasts `WM_SETTINGCHANGE`
/// ("Environment") only when something was removed. No-op on other platforms and in dry-run mode.
pub fn cleanup_legacy_windows_user_env() {
    #[cfg(target_os = "windows")]
    {
        if !super::os_effects_enabled() {
            super::note_dry_run_blocked("cleanup_legacy_windows_user_env");
            return;
        }
        let gateway_port = LAST_PAC_URL
            .lock()
            .ok()
            .and_then(|g| g.as_deref().and_then(parse_gateway_port_from_pac_url));
        let _ = cleanup_legacy_user_env_with(&mut RegistryWinEnv, gateway_port);
    }
}

/// Forcefully and completely cleans all OS, terminal, IDE, and registry proxy traces,
/// returning a human-readable list of cleaned components.
pub fn force_clean_all_os_proxy_traces() -> Vec<String> {
    disable_all_sysproxy();
    disable_cli_protection();
    cleanup_legacy_windows_user_env();
    vec![
        "Системный PAC-прокси".to_string(),
        "Конфигурации VS Code / Cursor / Claude".to_string(),
        "Профили терминала и переменные среды ОС".to_string(),
    ]
}

/// Forcefully cleans all OS proxy settings, CLI profile blocks, IDE configs, and uninstaller persistent traces.
pub fn cleanup_all_persistent_settings() {
    let _ = force_clean_all_os_proxy_traces();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysproxy::{
        SysProxy, dry_run_blocked_calls, dry_run_blocked_programs, is_sysproxy_active,
        os_effects_enabled,
    };

    /// On macOS/Windows the cleanup talks to `networksetup`/`launchctl`/`reg`; in dry-run every such
    /// call must have been swapped for a no-op and counted. Elsewhere there are no OS calls.
    fn assert_os_calls_were_blocked(before: usize) {
        assert!(
            !os_effects_enabled(),
            "unit tests must run in OS dry-run mode"
        );
        if cfg!(any(target_os = "macos", target_os = "windows")) {
            assert!(
                dry_run_blocked_calls() > before,
                "expected OS commands to be blocked, blocked programs: {:?}",
                dry_run_blocked_programs()
            );
        }
    }

    #[test]
    fn test_graceful_proxy_cleanup() {
        let before = dry_run_blocked_calls();
        register_clean_exit_guard();
        SysProxy::disable();
        assert!(!SysProxy::is_active());
        assert_os_calls_were_blocked(before);
    }

    #[test]
    fn test_graceful_proxy_cleanup_hook() {
        let before = dry_run_blocked_calls();
        register_clean_exit_guard();
        // Disabling proxy should execute safely without crashing
        disable_all_sysproxy();
        assert!(!is_sysproxy_active());
        assert_os_calls_were_blocked(before);
    }

    #[test]
    fn test_force_clean_all_os_proxy_traces() {
        let before = dry_run_blocked_calls();
        let cleaned = force_clean_all_os_proxy_traces();
        assert_eq!(cleaned.len(), 3);
        assert!(cleaned.iter().any(|c| c.contains("PAC")));
        assert_os_calls_were_blocked(before);
    }

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

    struct FakeWinEnv {
        vars: BTreeMap<String, String>,
        deleted: Vec<String>,
        broadcasts: usize,
    }

    impl WinEnv for FakeWinEnv {
        fn read_user_env(&self) -> BTreeMap<String, String> {
            self.vars.clone()
        }
        fn delete_user_env(&mut self, name: &str) {
            self.vars.remove(name);
            self.deleted.push(name.to_string());
        }
        fn broadcast_change(&mut self) {
            self.broadcasts += 1;
        }
    }

    #[test]
    fn cleanup_with_fake_registry_touches_only_signed_sets() {
        let mut foreign = FakeWinEnv {
            vars: env_of(&[("HTTPS_PROXY", "http://corp:3128"), ("TZ", "Europe/Berlin")]),
            deleted: vec![],
            broadcasts: 0,
        };
        assert!(cleanup_legacy_user_env_with(&mut foreign, None).is_empty());
        assert!(foreign.deleted.is_empty());
        assert_eq!(foreign.broadcasts, 0);
        assert_eq!(foreign.vars.len(), 2);

        let mut ours = FakeWinEnv {
            vars: env_of(&[
                ("HTTPS_PROXY", "http://127.0.0.1:8899"),
                ("TZ", "Europe/Berlin"),
                ("Path", "C:\\bin"),
            ]),
            deleted: vec![],
            broadcasts: 0,
        };
        let removed = cleanup_legacy_user_env_with(&mut ours, None);
        assert_eq!(removed.len(), 2);
        assert_eq!(ours.broadcasts, 1);
        assert_eq!(ours.vars.keys().collect::<Vec<_>>(), vec!["Path"]);
    }

    #[test]
    fn parse_reg_query_environment_reads_sz_and_expand_sz() {
        let out = "\r\nHKEY_CURRENT_USER\\Environment\r\n    HTTPS_PROXY    REG_SZ    http://127.0.0.1:8899\r\n    TEMP    REG_EXPAND_SZ    %USERPROFILE%\\AppData\\Local\\Temp\r\n    Flags    REG_DWORD    0x1\r\n    Empty    REG_SZ    \r\n";
        let map = parse_reg_query_environment(out);
        assert_eq!(
            map.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:8899")
        );
        assert_eq!(
            map.get("TEMP").map(String::as_str),
            Some("%USERPROFILE%\\AppData\\Local\\Temp")
        );
        assert_eq!(map.get("Empty").map(String::as_str), Some(""));
        assert!(!map.contains_key("Flags"));
    }
}
