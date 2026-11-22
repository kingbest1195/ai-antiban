use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::journal::{Outcome, Resource, Value};
use crate::sysproxy::platform::{ChainState, FakePlatform, PacState, ProxyEndpoint, ServiceId};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

static CLEANUP_GLOBAL_LOCK: Mutex<()> = Mutex::new(());

struct ShutdownHooksGuard;
impl Drop for ShutdownHooksGuard {
    fn drop(&mut self) {
        crate::core::shutdown::register_shutdown_hook(|| {});
        crate::core::shutdown::register_startup_drain_hook(|_| true);
        crate::core::shutdown::register_tunnel_abort_hook(|| {});
        crate::core::shutdown::register_sandbox_exit_hook(|| {});
        reset_shutdown_cleanup_guard();
    }
}

#[test]
fn signal_shutdown_without_app_handle_aborts_tunnels_drains_startup_and_stops_sandboxes() {
    let _lock = CLEANUP_GLOBAL_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _reset = ShutdownHooksGuard;
    reset_shutdown_cleanup_guard();

    let shutdown_notified = Arc::new(AtomicBool::new(false));
    let drain_waited = Arc::new(AtomicBool::new(false));
    let tunnels_aborted = Arc::new(AtomicBool::new(false));
    let sandboxes_stopped = Arc::new(AtomicUsize::new(0));

    let s_flag = shutdown_notified.clone();
    crate::core::shutdown::register_shutdown_hook(move || {
        s_flag.store(true, Ordering::SeqCst);
    });
    let d_flag = drain_waited.clone();
    crate::core::shutdown::register_startup_drain_hook(move |timeout| {
        assert_eq!(timeout, Duration::from_secs(2));
        d_flag.store(true, Ordering::SeqCst);
        true
    });
    let t_flag = tunnels_aborted.clone();
    crate::core::shutdown::register_tunnel_abort_hook(move || {
        t_flag.store(true, Ordering::SeqCst);
    });
    let sb_count = sandboxes_stopped.clone();
    crate::core::shutdown::register_sandbox_exit_hook(move || {
        sb_count.fetch_add(1, Ordering::SeqCst);
    });

    // Signal-style shutdown (`app = None`) must still trigger all 4 shutdown hooks.
    let rep = cleanup_on_shutdown_once(None, "quit");
    assert!(rep.is_some());
    assert!(shutdown_notified.load(Ordering::SeqCst));
    assert!(drain_waited.load(Ordering::SeqCst));
    assert!(tunnels_aborted.load(Ordering::SeqCst));
    assert_eq!(sandboxes_stopped.load(Ordering::SeqCst), 1);

    // Subsequent call in same process is deduplicated.
    assert!(cleanup_on_shutdown_once(None, "quit").is_none());
}

#[test]
fn restore_clears_physical_zastava_pac_and_chain_when_utun_vpn_causes_temp_dns() {
    let fs = FakeFs::new();
    let p = FakePlatform::new();
    let tb = ServiceId::new("bridge0", "Thunderbolt Bridge", "Thunderbolt Bridge");
    p.add_service(wifi());
    p.add_service(tb.clone());
    // Active third-party utun / PacketTunnel VPN (`V2BOX`) + temporary DNS override on Wi-Fi.
    let utun_vpn = ServiceId::new("utun4", "dev.hexasoftware.V2Box", "V2BOX Pro");
    p.add_service(utun_vpn.clone());
    p.set_vpn_connection("V2BOX Pro", true);
    p.set_temp_dns(true);

    let upstream = ChainState {
        http: ProxyEndpoint {
            enabled: Some(true),
            server: Some("127.0.0.1".into()),
            port: Some(10808),
            authenticated: Some(false),
        },
        https: ProxyEndpoint::default(),
        socks: ProxyEndpoint::default(),
    };
    p.seed_chain(&wifi(), upstream.clone());
    p.seed_pac(
        &wifi(),
        PacState {
            url: None,
            enabled: Some(false),
        },
    );
    p.seed_pac(
        &tb,
        PacState {
            url: None,
            enabled: Some(false),
        },
    );
    p.seed_pac(
        &utun_vpn,
        PacState {
            url: Some("http://127.0.0.1:8899/proxy.pac".into()),
            enabled: Some(true),
        },
    );

    let mut j = open(&fs);
    let our_pac = Value::Pac(PacState {
        url: Some("http://127.0.0.1:8899/proxy.pac".into()),
        enabled: Some(true),
    });
    j.apply(&p, &Resource::Pac { service: wifi() }, our_pac.clone())
        .unwrap();
    j.apply(
        &p,
        &Resource::Pac {
            service: tb.clone(),
        },
        our_pac.clone(),
    )
    .unwrap();
    j.apply(
        &p,
        &Resource::Chain { service: wifi() },
        Value::Chain(ChainState {
            http: ProxyEndpoint {
                enabled: Some(false),
                server: Some("127.0.0.1".into()),
                port: Some(10808),
                authenticated: Some(false),
            },
            ..Default::default()
        }),
    )
    .unwrap();
    // Simulate a legacy VPN PAC entry too: connected VPN must stay untouched.
    j.apply(
        &p,
        &Resource::Pac {
            service: utun_vpn.clone(),
        },
        our_pac,
    )
    .unwrap();

    p.clear_calls();
    let rep = restore_with_probe(&mut j, &p, Scope::All, None);
    assert!(
        !rep.has_failures(),
        "physical Zastava PAC must not fail with temp_dns under active utun VPN: {:?}",
        rep.items
    );
    assert!(!rep.restore_deferred_by_vpn_dns());
    assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
    assert_eq!(p.pac_of(&wifi()).url, None);
    assert_eq!(p.pac_of(&tb).enabled, Some(false));
    assert_eq!(p.chain_of(&wifi()), upstream);
    assert!(
        rep.items
            .iter()
            .any(|i| i.outcome == Outcome::Skipped("vpn"))
    );
    assert_eq!(p.pac_of(&utun_vpn).enabled, Some(true));
    assert!(
        !p.calls()
            .iter()
            .any(|c| c.starts_with("set_") && c.contains(&utun_vpn.key()))
    );
}

#[cfg(target_os = "macos")]
#[test]
fn admin_auth_required_during_interactive_quit_triggers_privileged_fallback_only_after_refusal() {
    use crate::sysproxy::journal::EntryState;
    use crate::sysproxy::platform::PlatOp;

    let fs = FakeFs::new();
    let p = FakePlatform::new();
    p.add_service(wifi());
    p.seed_pac(
        &wifi(),
        PacState {
            url: None,
            enabled: Some(false),
        },
    );

    let mut j = open(&fs);
    j.apply(
        &p,
        &Resource::Pac { service: wifi() },
        Value::Pac(PacState {
            url: Some("http://127.0.0.1:8899/proxy.pac".into()),
            enabled: Some(true),
        }),
    )
    .unwrap();

    // Non-quit / non-interactive pass keeps entry and surfaces AdminAuthRequired failure.
    p.fail_next_auth(PlatOp::SetPac);
    let rep_no_fallback = restore_with_probe_options(
        &mut j,
        &p,
        Scope::All,
        None,
        RestoreOptions {
            allow_privileged_quit_fallback: false,
        },
    );
    assert!(rep_no_fallback.has_failures());
    assert!(
        rep_no_fallback
            .items
            .iter()
            .any(|i| i.outcome == Outcome::Failed("admin_auth"))
    );
    assert_eq!(
        j.entry(&Resource::Pac { service: wifi() }).unwrap().state,
        EntryState::Applied
    );

    // Interactive quit retries via privileged fallback only after networksetup returned AdminAuthRequired.
    p.fail_next_auth(PlatOp::SetPac);
    let rep_quit = restore_with_probe_options(
        &mut j,
        &p,
        Scope::All,
        None,
        RestoreOptions {
            allow_privileged_quit_fallback: true,
        },
    );
    assert!(!rep_quit.has_failures(), "{:?}", rep_quit.items);
    assert_eq!(rep_quit.restored(), 1);
    assert!(j.is_empty());
}

#[test]
fn shutdown_progress_payload_gateway_bound_apps_serde_and_process_collection() {
    // Backward compatibility: older JSON without `gateway_bound_apps` deserializes cleanly.
    let legacy_json = r#"{"mode":"quit","step":4,"total":4,"label":"Готово, закрываем приложение...","done":true}"#;
    let parsed: ShutdownProgressPayload = serde_json::from_str(legacy_json).unwrap();
    assert!(parsed.gateway_bound_apps.is_empty());
    assert!(parsed.done);

    // New payload serializes `gateway_bound_apps` cleanly.
    let payload = ShutdownProgressPayload::done_with_apps(
        "quit",
        vec!["Antigravity".to_string(), "Cursor".to_string()],
    );
    let val = serde_json::to_value(&payload).unwrap();
    assert_eq!(
        val["gateway_bound_apps"],
        serde_json::json!(["Antigravity", "Cursor"])
    );

    // Collect running supported editors when CLI protection is active + explicitly restarted Antigravity.
    struct EditorProbe;
    impl SystemProbe for EditorProbe {
        fn run(&self, program: &str, _args: &[&str]) -> Option<String> {
            assert_eq!(program, "ps");
            Some(
                "/Applications/Antigravity.app/Contents/MacOS/Electron\n\
                 /Applications/Cursor.app/Contents/MacOS/Cursor\n\
                 /Applications/Visual Studio Code.app/Contents/MacOS/Electron\n\
                 /Applications/Safari.app/Contents/MacOS/Safari\n"
                    .to_string(),
            )
        }
    }
    let collected = collect_gateway_bound_apps_with(
        &["Antigravity".to_string()],
        true,
        Os::Macos,
        &EditorProbe,
    );
    assert_eq!(
        collected,
        vec![
            "Antigravity".to_string(),
            "Cursor".to_string(),
            "Visual Studio Code".to_string(),
        ]
    );

    // When CLI protection is OFF and launched Antigravity was already closed, nothing is reported.
    struct ClosedProbe;
    impl SystemProbe for ClosedProbe {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<String> {
            Some("/Applications/Cursor.app/Contents/MacOS/Cursor\n".to_string())
        }
    }
    assert!(
        collect_gateway_bound_apps_with(
            &["Antigravity".to_string()],
            false,
            Os::Macos,
            &ClosedProbe
        )
        .is_empty()
    );

    // ShutdownCleanupGuard::run_once_full emits gateway_bound_apps on the final `done` step.
    let guard = ShutdownCleanupGuard::new();
    let mut events = Vec::new();
    guard.run_once_full(
        "quit",
        false,
        true,
        |p| events.push(p),
        || {},
        RecoveryReport::default,
        RecoveryReport::default,
        || {},
        || vec!["Antigravity".to_string(), "Windsurf".to_string()],
    );
    let last = events.last().unwrap();
    assert!(last.done);
    assert_eq!(
        last.gateway_bound_apps,
        vec!["Antigravity".to_string(), "Windsurf".to_string()]
    );

    let win_entries = vec![
        crate::win_native::process::ProcessEntry {
            pid: 10,
            parent_pid: 1,
            exe_name: "Antigravity.exe".into(),
        },
        crate::win_native::process::ProcessEntry {
            pid: 11,
            parent_pid: 1,
            exe_name: "Code.exe".into(),
        },
        crate::win_native::process::ProcessEntry {
            pid: 12,
            parent_pid: 1,
            exe_name: "notepad.exe".into(),
        },
    ];
    let win_apps = super::super::shutdown::collect_gateway_bound_apps_from_win_entries(
        &["Antigravity".to_string()],
        true,
        &win_entries,
    );
    assert_eq!(
        win_apps,
        vec!["Antigravity".to_string(), "Visual Studio Code".to_string()]
    );
}
