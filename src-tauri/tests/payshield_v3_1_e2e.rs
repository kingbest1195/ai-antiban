//! Cross-module End-to-End integration tests for Zastava v3.1.0 (spec-v3.1.0.md §9.4).
//! Covers Scenarios 1, 2, 3, 4, 6, 7, 8 through the public `zastava_lib` API without touching OS state.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zastava_lib::auditor::geo_matrix::CheckStatus;
use zastava_lib::auditor::payment_readiness::{
    PaymentChannel, PaymentReadinessInput, ReadinessTier, SubscriptionPlan,
    evaluate_payment_readiness,
};
use zastava_lib::auditor::rules::ProviderMatrix;
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{HttpProbeOutcome, LookupOutcome};
use zastava_lib::auditor::{AuditEnv, Auditor};
use zastava_lib::bin_checker::http_adapter::HttpBinLookupAdapter;
use zastava_lib::bin_checker::{BinChecker, BinSource, validate_strict_bin_prefix};
use zastava_lib::bunker::payment_passport::{
    PassportChannel, PaymentPassport, load_payment_passport_in, save_payment_passport_in,
};
use zastava_lib::clean_room::quarantine::{
    QuarantineActivationInput, activate_quarantine_at, get_quarantine_status_at,
    override_quarantine_at,
};
use zastava_lib::cowork_guard::{
    COWORK_TASK_SDDL, CoworkGuardStatus, SchtasksQueryError, classify_schtasks_query_error,
    decode_windows_cmd_text, is_task_xml_healthy, verify_post_install_status,
};
use zastava_lib::os_tz::{
    OsTzPlatform, get_os_timezone_sync_status_with_keep, keep_system_tz_on_exit, read_baseline,
    recover_baseline_on_start_with_keep, restore_if_synced_on_disable_with_keep,
    restore_on_exit_once_with_keep, restore_os_timezone_with, set_keep_system_tz_on_exit,
    sync_os_timezone_with_keep,
};
use zastava_lib::proxy::pac::get_all_ai_domains_filtered;
use zastava_lib::proxy::{HoldQueue, HoldResolution, ProxyServer, generate_pac_script};
use zastava_lib::state::{AppState, AppStateData, CleanProfileStatus, CleanRoomProfile};
use zastava_lib::sysproxy;

fn offline_auditor() -> Auditor {
    Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(FakeProbe::new(HttpProbeOutcome::Timeout)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .expect("offline auditor")
}

#[test]
fn e2e_1_checkout_split_ip_parity_in_direct_and_chained_pac() {
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let domains = get_all_ai_domains_filtered(&matrix, &[], &HashSet::new());

    for chained in [None, Some("socks5://127.0.0.1:10808")] {
        let pac = generate_pac_script(&domains, "127.0.0.1:8899", chained);
        let start = pac.find("var aiDomains = ").unwrap() + "var aiDomains = ".len();
        let end = start + pac[start..].find(";\n").unwrap();
        let pac_domains: Vec<String> = serde_json::from_str(&pac[start..end]).unwrap();

        let route_for = |host: &str| {
            let h = host.to_ascii_lowercase();
            if pac_domains
                .iter()
                .any(|d| h == *d || h.ends_with(&format!(".{d}")))
            {
                "PROXY 127.0.0.1:8899"
            } else {
                "FALLBACK"
            }
        };

        let claude_route = route_for("claude.ai");
        assert_eq!(claude_route, "PROXY 127.0.0.1:8899");
        for host in [
            "checkout.stripe.com",
            "m.stripe.network",
            "withpersona.com",
            "inquiry.withpersona.com",
            "challenges.cloudflare.com",
            "pay.google.com",
        ] {
            assert_eq!(
                route_for(host),
                claude_route,
                "{host} must match claude.ai route"
            );
        }
        assert_eq!(route_for("example.com"), "FALLBACK");
    }
}

#[tokio::test]
async fn e2e_2_andrew_incident_pauses_in_hold_queue_and_blocks_on_cancel() {
    sysproxy::force_os_dry_run();
    let checker = BinChecker::new();
    let bin = checker
        .check_bin_report_with_cache_dir("493724", Some("DE"), None)
        .await
        .unwrap();
    assert_eq!(bin.country_code.as_deref(), Some("SG"));

    let report = evaluate_payment_readiness(&PaymentReadinessInput {
        exit_ip: Some("185.10.20.30".to_string()),
        exit_country: Some("DE".to_string()),
        exit_asn: Some(24940),
        is_pinned: true,
        bin_report: Some(bin),
        billing_country: Some("DE".to_string()),
        google_profile_country: Some("RU".to_string()),
        channel: PaymentChannel::GooglePayWeb,
        in_clean_room: true,
        warmup_hours: Some(120),
        plan: SubscriptionPlan::Pro,
        ..Default::default()
    });
    assert_eq!(report.tier, ReadinessTier::Red);
    assert!(report.score < 50);

    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_auditor(),
            AppState::new_in_memory(),
            Arc::clone(&hold_queue),
            None,
        )
        .await
        .unwrap()
        .with_hold_ttl(Duration::from_secs(5)),
    );
    server.checkout_guard.set_cached_report(report).await;
    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let client_task = tokio::spawn(async move {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            b"CONNECT checkout.stripe.com:443 HTTP/1.1\r\nHost: checkout.stripe.com:443\r\n\r\n",
        )
        .await
        .unwrap();
        let mut buf = [0u8; 512];
        let n = s.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });

    let mut alert = None;
    for _ in 0..50 {
        if let Some(a) = hold_queue.current_alert() {
            alert = Some(a);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let alert = alert.expect("checkout HoldQueue alert must appear");
    assert_eq!(alert.scope, "checkout");
    assert_eq!(alert.host, "checkout.stripe.com");
    let risk = alert.checkout_risk.unwrap();
    assert_eq!(risk.tier, ReadinessTier::Red);
    assert_no_banned_jargon(&risk.reason);
    for msg in risk
        .blockers
        .iter()
        .chain(risk.warnings.iter())
        .chain(risk.recommended_action.iter())
    {
        assert_no_banned_jargon(msg);
    }

    assert!(hold_queue.resolve(&alert.id, HoldResolution::Block).await);
    let resp = client_task.await.unwrap();
    assert!(resp.contains("403 Forbidden"), "{resp}");
}

#[tokio::test]
async fn e2e_3_fail_closed_bin_429_forbids_green_readiness() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        }
    });

    let adapter = Arc::new(HttpBinLookupAdapter::with_endpoints(
        None,
        format!("http://{addr}"),
        1000,
    ));
    let checker = BinChecker::with_port(adapter);
    let bin = checker
        .check_bin_report_with_cache_dir("411111", Some("US"), None)
        .await
        .unwrap();
    assert_eq!(bin.status, CheckStatus::Unknown);
    assert_eq!(bin.source, BinSource::FallbackUnknown);
    for w in &bin.warnings {
        assert_no_banned_jargon(w);
    }

    let readiness = evaluate_payment_readiness(&PaymentReadinessInput {
        exit_ip: Some("23.45.67.89".to_string()),
        exit_country: Some("US".to_string()),
        is_pinned: true,
        bin_report: Some(bin),
        billing_country: Some("US".to_string()),
        channel: PaymentChannel::DirectCard,
        in_clean_room: true,
        warmup_hours: Some(120),
        plan: SubscriptionPlan::Pro,
        ..Default::default()
    });
    assert!(readiness.fail_closed_bin);
    assert_ne!(readiness.tier, ReadinessTier::Green);
    for msg in readiness
        .warnings
        .iter()
        .chain(readiness.blockers.iter())
        .chain(readiness.recommended_action.iter())
    {
        assert_no_banned_jargon(msg);
    }
}

#[tokio::test]
async fn e2e_4_and_6_quarantine_persistence_and_zero_pci_dss_passport() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");
    let mut data = AppStateData::default();
    data.clean_room.profiles.push(CleanRoomProfile {
        id: "cr-e2e".to_string(),
        label: "E2E".to_string(),
        provider: "anthropic".to_string(),
        browser_engine: "chrome".to_string(),
        bound_route_id: Some("route-us".to_string()),
        last_exit_ip: Some("23.45.67.89".to_string()),
        last_exit_country: Some("US".to_string()),
        status: CleanProfileStatus::Ready,
        created_at: 1_700_000_000,
        last_opened_at: None,
        warmup_started_at: Some(1_700_000_000),
        launchpad_step: 4,
        completed_checklist: vec![],
        post_payment_quarantine: None,
    });
    AppState::save_data_to_file(&data, &state_path).unwrap();

    let state = AppState::load_or_default(state_path.clone());
    let t0 = 1_760_000_000u64;
    let active = activate_quarantine_at(
        &state,
        QuarantineActivationInput {
            profile_id: Some("cr-e2e".to_string()),
            route_id: None,
            exit_ip: None,
            exit_asn: Some(20473),
            exit_country: None,
        },
        t0,
    )
    .await
    .unwrap();
    assert!(active.active);
    assert_eq!(active.remaining_hours, 72);

    let reloaded = AppState::load_or_default(state_path);
    assert!(
        get_quarantine_status_at(&reloaded, Some("cr-e2e"), t0 + 36 * 3600)
            .await
            .unwrap()
            .active
    );
    assert!(
        !override_quarantine_at(&reloaded, Some("cr-e2e"), Some("user_confirmed"), t0 + 100)
            .await
            .unwrap()
            .active
    );

    // Zero PCI-DSS: >8 digits rejected without echo, passport strips/forbids PAN/CVV/last4
    let err = validate_strict_bin_prefix("4111222233334444").unwrap_err();
    assert!(!err.contains("4444"));
    let saved = save_payment_passport_in(
        dir.path(),
        PaymentPassport {
            profile_id: "cr-e2e".to_string(),
            bin_prefix: "44661412".to_string(),
            card_country: "US".to_string(),
            channel: PassportChannel::DirectCard,
            billing_country: "US".to_string(),
            exit_ip: "23.45.67.89".to_string(),
            exit_asn: Some(20473),
            paid_at: t0,
        },
    )
    .unwrap();
    let json = serde_json::to_string(&saved).unwrap().to_ascii_lowercase();
    for key in ["pan", "cvv", "last4", "expiry"] {
        assert!(!json.contains(key), "must not contain {key}");
    }
    assert_eq!(
        load_payment_passport_in(dir.path(), "cr-e2e")
            .unwrap()
            .unwrap(),
        saved
    );
}

#[test]
fn e2e_7_windows_cowork_guard_cp866_acl_and_post_install_err() {
    sysproxy::force_os_dry_run();
    // CP866 "ОШИБКА: Отказано в доступе." -> AccessDenied
    let cp866_denied: Vec<u8> = vec![
        0x8E, 0x98, 0x88, 0x81, 0x8A, 0x80, 0x3A, 0x20, 0x8E, 0xE2, 0xAA, 0xA0, 0xA7, 0xA0, 0xAD,
        0xAE, 0x20, 0xA2, 0x20, 0xA4, 0xAE, 0xE1, 0xE2, 0xE3, 0xAF, 0xA5, 0x2E,
    ];
    let decoded = decode_windows_cmd_text(&cp866_denied);
    assert_eq!(decoded, "ОШИБКА: Отказано в доступе.");
    assert_eq!(
        classify_schtasks_query_error(&decoded, ""),
        SchtasksQueryError::AccessDenied
    );

    // Localized Russian SYSTEM principal XML -> healthy (Zero-LOLBin native binary action)
    let ru_xml = "<Task><Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers><Principals><Principal><UserId>NT AUTHORITY\\СИСТЕМА</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>C:\\Program Files\\Zastava\\zastava.exe</Command><Arguments>--apply-cowork-guard-once</Arguments></Exec></Actions></Task>";
    assert!(is_task_xml_healthy(ru_xml));

    // Explicit COM SDDL grants SYSTEM/Admins FA and Authenticated Users (A;;GRGX;;;AU) without PowerShell
    assert!(COWORK_TASK_SDDL.contains("(A;;FA;;;SY)"));
    assert!(COWORK_TASK_SDDL.contains("(A;;GRGX;;;AU)"));
    assert!(!COWORK_TASK_SDDL.to_ascii_lowercase().contains("powershell"));

    // Post-install check fails with Err when needs_repair == true
    let broken = CoworkGuardStatus {
        platform: "windows".to_string(),
        supported: true,
        service_present: true,
        start_type: Some(2),
        service_running: true,
        task_installed: false,
        task_healthy: false,
        needs_repair: true,
        summary: "still broken".to_string(),
        detected_ai_apps: vec![],
    };
    assert!(verify_post_install_status(broken, Some("acl error")).is_err());
}

struct FakeTzPlat {
    iana: Mutex<String>,
    restore_calls: Mutex<usize>,
}

impl OsTzPlatform for FakeTzPlat {
    fn current_iana_timezone(&self) -> Result<String, String> {
        Ok(self.iana.lock().unwrap().clone())
    }
    fn current_windows_tz_id(&self) -> Result<Option<String>, String> {
        Ok(Some("Russian Standard Time".to_string()))
    }
    fn is_auto_tz_enabled(&self) -> Result<Option<bool>, String> {
        Ok(Some(true))
    }
    fn apply_timezone(&self, target: &str, _: bool) -> Result<(), String> {
        *self.iana.lock().unwrap() = target.to_string();
        Ok(())
    }
    fn restore_timezone(&self, orig: &str, _: Option<&str>, _: Option<bool>) -> Result<(), String> {
        *self.restore_calls.lock().unwrap() += 1;
        *self.iana.lock().unwrap() = orig.to_string();
        Ok(())
    }
}

#[tokio::test]
async fn e2e_8_keep_system_tz_on_exit_lifecycle_preserves_baseline() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");
    let state = AppState::load_or_default(state_path.clone());
    state.set_keep_system_tz_on_exit(true).await.unwrap();
    assert!(keep_system_tz_on_exit());

    let plat = FakeTzPlat {
        iana: Mutex::new("Europe/Moscow".to_string()),
        restore_calls: Mutex::new(0),
    };
    let synced = sync_os_timezone_with_keep(&plat, dir.path(), "Europe/Amsterdam", true).unwrap();
    assert!(synced.synced);
    assert!(!synced.auto_restore_pending);

    // Exit, disable, and startup recovery all skip restore_timezone and keep os_tz_baseline.json
    assert!(!restore_on_exit_once_with_keep(&plat, dir.path(), true).unwrap());
    assert!(!restore_if_synced_on_disable_with_keep(&plat, dir.path(), true).unwrap());
    recover_baseline_on_start_with_keep(&plat, dir.path(), true);
    assert_eq!(*plat.restore_calls.lock().unwrap(), 0);
    assert!(read_baseline(dir.path()).unwrap().is_some());

    let reloaded = AppState::load_or_default(state_path);
    assert!(reloaded.get_keep_system_tz_on_exit().await);
    let status = get_os_timezone_sync_status_with_keep(&plat, dir.path(), true).unwrap();
    assert!(status.synced && !status.auto_restore_pending);

    // Manual restore restores original TZ and removes baseline
    let restored = restore_os_timezone_with(&plat, dir.path()).unwrap();
    assert!(!restored.synced);
    assert_eq!(*plat.restore_calls.lock().unwrap(), 1);
    assert!(read_baseline(dir.path()).unwrap().is_none());
    set_keep_system_tz_on_exit(false);
}

fn assert_no_banned_jargon(text: &str) {
    let lower = text.to_lowercase();
    for term in [
        "payshield",
        "stripe",
        "bin-рентген",
        "финтех-bin",
        "fail-closed",
        "fallbackunknown",
        "persona",
        "kyc",
        "apple iap",
        "directcard",
        "биллинг",
        "чекаут",
        "split-ip",
        "is_pinned",
        "tainted",
        "webrtc",
        "stun",
        "пост-платёжный карантин",
        "vc.ru",
        "prepaid",
        "commercial",
        "business",
        "coworkvmservice",
    ] {
        assert!(!lower.contains(term), "banned term '{term}' in: {text}");
    }
    for word in text.split(|c: char| !c.is_alphanumeric() && c != '_') {
        assert!(
            !word.eq_ignore_ascii_case("bin") && !word.eq_ignore_ascii_case("asn"),
            "banned standalone acronym '{word}' in: {text}"
        );
    }
}
