use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::Value;
use tempfile::tempdir;
use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::seams::fakes::FakeUdp;
use zastava_lib::clean_room::browser_sandbox::{
    SandboxMeta, SandboxProcessRegistry, build_hardened_chromium_args_for_engine,
    cleanup_stale_singleton_files, read_sandbox_meta, write_fail_closed_preferences_with_country,
    write_sandbox_meta,
};
use zastava_lib::clean_room::detector::DetectorEnv;
use zastava_lib::clean_room::{CreateCleanProfileInput, TraceSeverity};
use zastava_lib::commands::clean_room::{
    create_clean_profile_in, delete_clean_profile_in, run_clean_room_audit_with_route_env,
    untaint_clean_room_ip_in, update_clean_profile_route_in,
};
use zastava_lib::cowork_guard::{
    SchtasksQueryError, build_windows_summary, classify_schtasks_query_error,
    decode_windows_cmd_text, is_task_list_healthy, is_task_xml_healthy,
};
use zastava_lib::proxy::ProxyManager;
use zastava_lib::state::AppState;

use crate::harness::{
    EntryMode, MockEchoTarget, MockZastavaEntry, OfflineDns, RuIspKeyProbe, acquire_global_state,
    build_offline_auditor, clean_de_telemetry, send_connect_and_echo, start_proxy_server,
};

struct FakeCleanEnv {
    is_win: bool,
    browsers: Vec<(&'static str, PathBuf)>,
}

impl DetectorEnv for FakeCleanEnv {
    fn path_exists(&self, p: &Path) -> bool {
        p.exists()
    }
    fn running_ai_processes(&self) -> Vec<String> {
        vec![]
    }
    fn browser_profile_dirs(&self) -> Vec<(&'static str, PathBuf)> {
        self.browsers.clone()
    }
    fn claude_data_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
    fn chatgpt_data_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
    fn cursor_data_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
    fn is_windows(&self) -> bool {
        self.is_win
    }
}

#[tokio::test]
async fn e2e_clean_room_insert_key_pre_profile_and_rebind_route() {
    let _g = acquire_global_state().await;
    let tmp = tempdir().unwrap();
    let target_a = MockEchoTarget::spawn().await;
    let target_b = MockEchoTarget::spawn().await;
    let entry_a = MockZastavaEntry::spawn(EntryMode::HttpHealthy, Some(target_a.addr)).await;
    let entry_b = MockZastavaEntry::spawn(EntryMode::HttpHealthy, Some(target_b.addr)).await;
    let route_a = entry_a.as_route("cr-key-a", "Key A");
    let route_b = entry_b.as_route("cr-key-b", "Key B");

    let state = AppState::new_in_memory();
    state.upsert_route(route_a.clone()).await.unwrap();
    state.upsert_route(route_b.clone()).await.unwrap();
    state
        .set_profile_route(Some(route_a.id.clone()))
        .await
        .unwrap();

    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "RU",
        block_doh_and_tor: false,
        stun_ip: "5.18.10.2",
        stun_cc: "RU",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    auditor
        .resolver
        .set_cached_for_route(Some(route_a.id.clone()), clean_de_telemetry())
        .await;
    auditor
        .resolver
        .set_cached_for_route(Some(route_b.id.clone()), clean_de_telemetry())
        .await;
    auditor
        .resolver
        .set_cached(NetworkTelemetry {
            ip: "5.18.10.2".into(),
            country_code: "RU".into(),
            hostname: None,
            asn: Some(8359),
            org: Some("MTS".into()),
            isp: Some("MTS".into()),
            timezone: Some("Europe/Moscow".into()),
            resolved_at: current_timestamp(),
        })
        .await;

    let env = FakeCleanEnv {
        is_win: false,
        browsers: vec![],
    };

    // 1. Fresh Clean Room (profile_id = None, route_id = None) must audit active Key A (NOT Direct!)
    let pre_audit =
        run_clean_room_audit_with_route_env(&env, tmp.path(), &state, &auditor, None, None)
            .await
            .unwrap();
    assert!(
        pre_audit.ready_to_launch,
        "fresh Clean Room with active Zastava Key must be ready: {:?}",
        pre_audit.findings
    );
    assert_eq!(pre_audit.exit_ip.as_deref(), Some("185.100.10.2"));

    // 2. Explicit "direct" audits Direct (RU IP -> blocked!)
    let direct_audit = run_clean_room_audit_with_route_env(
        &env,
        tmp.path(),
        &state,
        &auditor,
        None,
        Some("direct"),
    )
    .await
    .unwrap();
    assert!(!direct_audit.ready_to_launch);
    assert_eq!(direct_audit.exit_ip.as_deref(), Some("5.18.10.2"));

    // 3. Create profile on Key A, start alias, then update_clean_profile_route to Key B
    let profile = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "Claude Work".into(),
            provider: "anthropic".into(),
            browser_engine: "chrome".into(),
            bound_route_id: Some(route_a.id.clone()),
        },
        &state,
    )
    .await
    .unwrap();

    let (srv, srv_task) = start_proxy_server(auditor.clone(), state.clone(), None, None).await;
    let pm = ProxyManager::from_server(Arc::clone(&srv));
    let port1 = pm
        .ensure_profile_alias(profile.id.as_str(), profile.bound_route_id.clone())
        .await
        .unwrap();
    let addr1 = format!("127.0.0.1:{port1}").parse().unwrap();
    assert_eq!(
        send_connect_and_echo(addr1, "claude.ai:443", b"via-a")
            .await
            .unwrap(),
        b"via-a"
    );
    let a_after = target_a.connections.load(Ordering::SeqCst);
    assert!(a_after >= 1);
    let b_before = target_b.connections.load(Ordering::SeqCst);

    // Rebind profile to Key B + restart alias on same preferred port
    let updated =
        update_clean_profile_route_in(profile.id.as_str(), Some(route_b.id.as_str()), &state, &pm)
            .await
            .unwrap();
    assert_eq!(updated.bound_route_id.as_deref(), Some(route_b.id.as_str()));

    let port2 = pm
        .ensure_profile_alias_preferred(
            profile.id.as_str(),
            updated.bound_route_id.clone(),
            Some(port1),
        )
        .await
        .unwrap();
    let addr2 = format!("127.0.0.1:{port2}").parse().unwrap();
    assert_eq!(
        send_connect_and_echo(addr2, "claude.ai:443", b"via-b")
            .await
            .unwrap(),
        b"via-b"
    );
    assert_eq!(target_a.connections.load(Ordering::SeqCst), a_after);
    assert!(target_b.connections.load(Ordering::SeqCst) > b_before);
    pm.stop_profile_alias(profile.id.as_str()).await;
    srv_task.abort();
}

#[tokio::test]
async fn e2e_clean_room_delete_no_silent_taint_and_untaint_ip() {
    let _g = acquire_global_state().await;
    let tmp = tempdir().unwrap();
    let entry = MockZastavaEntry::spawn(EntryMode::HttpHealthy, None).await;
    let route = entry.as_route("cr-key", "Clean Key");
    let state = AppState::new_in_memory();
    state.upsert_route(route.clone()).await.unwrap();

    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "DE",
        block_doh_and_tor: false,
        stun_ip: "185.100.10.2",
        stun_cc: "DE",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    auditor
        .resolver
        .set_cached_for_route(Some(route.id.clone()), clean_de_telemetry())
        .await;
    let env = FakeCleanEnv {
        is_win: false,
        browsers: vec![],
    };
    let (srv, srv_task) = start_proxy_server(auditor.clone(), state.clone(), None, None).await;
    let pm = ProxyManager::from_server(Arc::clone(&srv));
    let reg = SandboxProcessRegistry::new();

    // Profile 1 deleted with taint_exit_ip = None -> does NOT taint exit IP
    let p1 = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "P1".into(),
            provider: "anthropic".into(),
            browser_engine: "chrome".into(),
            bound_route_id: Some(route.id.clone()),
        },
        &state,
    )
    .await
    .unwrap();
    {
        let mut w = state.write().await;
        if let Some(prof) = w.clean_room.profiles.iter_mut().find(|x| x.id == p1.id) {
            prof.last_exit_ip = Some("185.100.10.2".into());
        }
    }
    let st_after_none = delete_clean_profile_in(p1.id.as_str(), None, None, &state, &pm, &reg)
        .await
        .unwrap();
    assert!(st_after_none.tainted_ips.is_empty());

    // Profile 2 deleted with taint_exit_ip = Some(false) -> does NOT taint exit IP
    let p2 = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "P2".into(),
            provider: "anthropic".into(),
            browser_engine: "chrome".into(),
            bound_route_id: Some(route.id.clone()),
        },
        &state,
    )
    .await
    .unwrap();
    {
        let mut w = state.write().await;
        if let Some(prof) = w.clean_room.profiles.iter_mut().find(|x| x.id == p2.id) {
            prof.last_exit_ip = Some("185.100.10.2".into());
        }
    }
    let st_after_false =
        delete_clean_profile_in(p2.id.as_str(), Some(false), None, &state, &pm, &reg)
            .await
            .unwrap();
    assert!(st_after_false.tainted_ips.is_empty());

    // Profile 3 deleted with taint_exit_ip = Some(true) -> taints IP -> blocks Clean Room
    let p3 = create_clean_profile_in(
        CreateCleanProfileInput {
            label: "P3".into(),
            provider: "anthropic".into(),
            browser_engine: "chrome".into(),
            bound_route_id: Some(route.id.clone()),
        },
        &state,
    )
    .await
    .unwrap();
    {
        let mut w = state.write().await;
        if let Some(prof) = w.clean_room.profiles.iter_mut().find(|x| x.id == p3.id) {
            prof.last_exit_ip = Some("185.100.10.2".into());
        }
    }
    let st_after_true =
        delete_clean_profile_in(p3.id.as_str(), Some(true), None, &state, &pm, &reg)
            .await
            .unwrap();
    assert!(st_after_true.tainted_ips.contains_key("185.100.10.2"));

    let blocked = run_clean_room_audit_with_route_env(
        &env,
        tmp.path(),
        &state,
        &auditor,
        None,
        Some(route.id.as_str()),
    )
    .await
    .unwrap();
    assert!(blocked.ip_is_tainted);
    assert!(!blocked.ready_to_launch);

    // untaint_clean_room_ip removes taint and unblocks Clean Room
    let st_untainted = untaint_clean_room_ip_in("185.100.10.2", &state)
        .await
        .unwrap();
    assert!(st_untainted.tainted_ips.is_empty());

    // Canonical IPv6 untaint matching (uppercase/uncompressed vs compressed)
    {
        let mut w = state.write().await;
        w.clean_room
            .tainted_ips
            .insert("2001:0DB8::1".to_string(), 1_700_000_000);
    }
    let st_ipv6_untainted = untaint_clean_room_ip_in("2001:db8::1", &state)
        .await
        .unwrap();
    assert!(!st_ipv6_untainted.tainted_ips.contains_key("2001:0DB8::1"));
    let unblocked = run_clean_room_audit_with_route_env(
        &env,
        tmp.path(),
        &state,
        &auditor,
        None,
        Some(route.id.as_str()),
    )
    .await
    .unwrap();
    assert!(!unblocked.ip_is_tainted);
    assert!(unblocked.ready_to_launch);
    srv_task.abort();
}

#[tokio::test]
async fn e2e_clean_room_sandbox_prefs_first_run_and_windows_tz_warning() {
    let _g = acquire_global_state().await;
    let tmp = tempdir().unwrap();
    let profile_dir = tmp.path().join("sandbox-de");

    // 1. Preferences + First Run + Chromium flags (NO --lang=en-US)
    write_fail_closed_preferences_with_country(&profile_dir, 41234, Some("DE")).unwrap();
    assert!(
        profile_dir.join("First Run").exists(),
        "First Run sentinel must be created"
    );
    let prefs_raw = std::fs::read_to_string(profile_dir.join("Default/Preferences")).unwrap();
    let prefs: Value = serde_json::from_str(&prefs_raw).unwrap();
    assert_eq!(prefs["intl"]["accept_languages"], "de-DE,de,en");
    assert_eq!(
        prefs["webrtc"]["ip_handling_policy"],
        "disable_non_proxied_udp"
    );
    assert_eq!(prefs["webrtc"]["multiple_routes_enabled"], false);
    assert_eq!(prefs["signin"]["allowed"], false);
    assert_eq!(prefs["sync"]["requested"], false);
    assert_eq!(prefs["browser"]["has_seen_welcome_page"], true);
    assert_eq!(prefs["browser"]["edge_first_run_complete"], true);

    let args = build_hardened_chromium_args_for_engine(&profile_dir, 41234, None, "edge");
    assert!(
        !args.iter().any(|a| a.starts_with("--lang=")),
        "must not force --lang=en-US on browser UI"
    );
    assert!(args.iter().any(|a| a.contains("msEdgeFRE")));

    // Stale Singleton cleanup & .zastava-sandbox.json persistence
    write_sandbox_meta(
        &profile_dir,
        SandboxMeta {
            pid: 999999,
            alias_port: 41234,
        },
    )
    .unwrap();
    let meta = read_sandbox_meta(&profile_dir).unwrap();
    assert_eq!(meta.alias_port, 41234);
    for lock in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
        std::fs::write(profile_dir.join(lock), b"stale").unwrap();
    }
    cleanup_stale_singleton_files(&profile_dir);
    for lock in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
        assert!(!profile_dir.join(lock).exists());
    }

    // 2. Windows TZ mismatch is Warning (ready_to_launch == true) + Russian detector findings
    let personal_chrome = tmp.path().join("PersonalChrome");
    std::fs::create_dir_all(personal_chrome.join("Default")).unwrap();
    let win_env = FakeCleanEnv {
        is_win: true,
        browsers: vec![("Chrome", personal_chrome)],
    };
    let entry = MockZastavaEntry::spawn(EntryMode::HttpHealthy, None).await;
    let route = entry.as_route("win-key", "Win Key");
    let state = AppState::new_in_memory();
    state.upsert_route(route.clone()).await.unwrap();

    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "DE",
        block_doh_and_tor: false,
        stun_ip: "185.100.10.2",
        stun_cc: "DE",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor_win = zastava_lib::auditor::Auditor::with_env(zastava_lib::auditor::AuditEnv {
        dns,
        probe,
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(zastava_lib::auditor::seams::fakes::FakeSystem {
            global_ipv6: Some(false),
            timezone: Ok("Europe/Moscow".into()),
            ..zastava_lib::auditor::seams::fakes::FakeSystem::healthy()
        }),
    })
    .unwrap();
    auditor_win
        .resolver
        .set_cached_for_route(Some(route.id.clone()), clean_de_telemetry())
        .await;

    let win_report = run_clean_room_audit_with_route_env(
        &win_env,
        tmp.path(),
        &state,
        &auditor_win,
        None,
        Some(route.id.as_str()),
    )
    .await
    .unwrap();
    assert!(
        win_report.ready_to_launch,
        "Windows OS TZ mismatch must be a Warning, not block Clean Room launch: {:?}",
        win_report.findings
    );
    let tz_finding = win_report
        .findings
        .iter()
        .find(|f| f.id == "windows_os_tz_mismatch")
        .expect("windows_os_tz_mismatch finding expected");
    assert_eq!(tz_finding.severity, TraceSeverity::Warning);
    assert!(
        !tz_finding.title.is_ascii(),
        "finding title must be localized in Russian: {}",
        tz_finding.title
    );
    let browser_finding = win_report
        .findings
        .iter()
        .find(|f| f.id == "personal_browsers_present")
        .expect("personal_browsers_present finding expected");
    assert!(!browser_finding.title.is_ascii());
}

#[test]
fn e2e_cowork_guard_xml_localized_system_utf16_no_bom_and_acl_fallback() {
    let xml_system_tag = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>SYSTEM</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command></Exec></Actions>
</Task>"#;
    assert!(is_task_xml_healthy(xml_system_tag));

    let xml_ru_system = xml_system_tag.replace(
        "<UserId>SYSTEM</UserId>",
        "<UserId>NT AUTHORITY\\СИСТЕМА</UserId>",
    );
    assert!(is_task_xml_healthy(&xml_ru_system));

    let text_ru = "Имя задачи: \\Zastava\\CoworkVMServiceManualGuard\r\nСостояние: Готово";
    let mut no_bom_bytes = Vec::with_capacity(text_ru.len() * 2);
    for u in text_ru.encode_utf16() {
        no_bom_bytes.extend_from_slice(&u.to_le_bytes());
    }
    let decoded = decode_windows_cmd_text(&no_bom_bytes);
    assert_eq!(decoded, text_ru);
    assert!(is_task_list_healthy(&decoded));

    assert_eq!(
        classify_schtasks_query_error("ERROR: Access is denied.", ""),
        SchtasksQueryError::AccessDenied
    );
    assert_eq!(
        classify_schtasks_query_error("ОШИБКА: Отказано в доступе.", ""),
        SchtasksQueryError::AccessDenied
    );

    for (present, start, running, installed, healthy) in [
        (true, Some(3), false, true, true),
        (true, Some(2), false, true, true),
        (true, Some(4), false, true, true),
        (true, Some(3), false, false, false),
    ] {
        let (_needs, summary) = build_windows_summary(present, start, running, installed, healthy);
        assert!(
            !summary.contains("Start="),
            "summary must not contain raw Start= jargon: {summary}"
        );
    }
}

#[tokio::test]
async fn e2e_clean_room_restart_recovery_on_preferred_port() {
    let _g = acquire_global_state().await;
    let target = MockEchoTarget::spawn().await;
    let entry = MockZastavaEntry::spawn(EntryMode::HttpHealthy, Some(target.addr)).await;
    let route = entry.as_route("cr-restart", "Restart Key");

    let state = AppState::new_in_memory();
    state.upsert_route(route.clone()).await.unwrap();
    let probe = Arc::new(RuIspKeyProbe {
        ipv6_loc: "DE",
        block_doh_and_tor: false,
        stun_ip: "185.100.10.2",
        stun_cc: "DE",
    });
    let dns = Arc::new(OfflineDns {
        block_dnsbl: false,
        resolver_ip: "185.100.10.2",
    });
    let auditor = build_offline_auditor(probe, dns, FakeUdp::new());
    auditor
        .resolver
        .set_cached_for_route(Some(route.id.clone()), clean_de_telemetry())
        .await;

    let (srv1, task1) = start_proxy_server(auditor.clone(), state.clone(), None, None).await;
    let pm1 = ProxyManager::from_server(Arc::clone(&srv1));
    let port1 = pm1
        .ensure_profile_alias_preferred("prof-restart", Some(route.id.clone()), None)
        .await
        .unwrap();
    assert_eq!(
        send_connect_and_echo(
            format!("127.0.0.1:{port1}").parse().unwrap(),
            "claude.ai:443",
            b"run1"
        )
        .await
        .unwrap(),
        b"run1"
    );
    pm1.stop_profile_alias("prof-restart").await;
    task1.abort();

    // Simulated restart: new ProxyManager rebinds on the exact same preferred port1
    let (srv2, task2) = start_proxy_server(auditor, state, None, None).await;
    let pm2 = ProxyManager::from_server(Arc::clone(&srv2));
    let port2 = pm2
        .ensure_profile_alias_preferred("prof-restart", Some(route.id), Some(port1))
        .await
        .unwrap();
    assert_eq!(
        port2, port1,
        "preferred port must be reclaimed across restart"
    );
    assert_eq!(
        send_connect_and_echo(
            format!("127.0.0.1:{port2}").parse().unwrap(),
            "claude.ai:443",
            b"run2"
        )
        .await
        .unwrap(),
        b"run2"
    );
    pm2.stop_profile_alias("prof-restart").await;
    task2.abort();
}
