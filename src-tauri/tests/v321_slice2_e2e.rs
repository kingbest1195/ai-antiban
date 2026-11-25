//! End-to-End Slice 2 verification suite for Zastava v3.2.1 (`spec-v3.2.1.md` §8.2 Scenario 9; §10–§12).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zastava_lib::auditor::geo_matrix::is_payment_or_kyc_host;
use zastava_lib::auditor::matrix_sync::{
    MATRIX_CACHE_FILE_NAME, MATRIX_FILE_NAME, apply_signed_matrix_update_with_key,
    load_provider_matrix_with_key, rules_data_dir,
};
use zastava_lib::auditor::network::{
    NetworkTelemetry, current_timestamp, evaluate_reverse_dns_ptr_with_ptr_for_mode,
};
use zastava_lib::auditor::probes::stun;
use zastava_lib::auditor::rules::{
    DangerousAsns, ProviderMatrix, RUNTIME_MATRIX_TEST_LOCK, RuleSet,
    clear_runtime_provider_matrix_for_test, publish_runtime_provider_matrix,
};
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp, addr};
use zastava_lib::auditor::seams::{HttpProbeOutcome, LookupOutcome, TxtOutcome};
use zastava_lib::auditor::{AuditEnv, AuditProtectionFlags, Auditor, CheckStatus, ProviderId};
use zastava_lib::core::redact::sanitize_diagnostic_text;
use zastava_lib::diagnostics::build_sanitized_diagnostic_bundle;
use zastava_lib::proxy::coverage::{
    classify_process_name, get_known_app_info, resolve_app_identity,
};
use zastava_lib::proxy::domain_drift;
use zastava_lib::proxy::{HoldQueue, ProxyServer};
use zastava_lib::routing::{Entry, EntryProto, Route};
use zastava_lib::state::{AppState, CliMode};
use zastava_lib::sysproxy::fs::{FakeFs, Fs};
use zastava_lib::sysproxy::platform::{FakePlatform, PacState, ServiceId};
use zastava_lib::sysproxy::test_support::{
    HEAL_WINDOW_SECS, TestHealGuard, apply_cli_protection_in_fs, disable_cli_protection_in_fs,
    open_journal_with_fake_policies, refresh_macos_pac,
};

struct MatrixSnapshotRestoreGuard;
impl Drop for MatrixSnapshotRestoreGuard {
    fn drop(&mut self) {
        if let Ok(bundled) = ProviderMatrix::load_bundled() {
            publish_runtime_provider_matrix(Arc::new(bundled));
        } else {
            clear_runtime_provider_matrix_for_test();
        }
    }
}

struct DriftResetGuard;
impl Drop for DriftResetGuard {
    fn drop(&mut self) {
        domain_drift::clear_for_test();
    }
}

fn test_ed25519_keypair() -> (Ed25519KeyPair, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_key = pair.public_key().as_ref().to_vec();
    (pair, pub_key)
}

fn sign_matrix(mut matrix: ProviderMatrix, pair: &Ed25519KeyPair) -> (ProviderMatrix, String) {
    matrix.signature_ed25519_b64.clear();
    let payload = matrix.canonical_payload_bytes().unwrap();
    let sig = pair.sign(&payload);
    matrix.signature_ed25519_b64 = B64.encode(sig.as_ref());
    let json = serde_json::to_string_pretty(&matrix).unwrap();
    (matrix, json)
}

async fn spawn_echo_upstream() -> Option<SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("bind echo upstream: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Some(addr)
}

async fn fetch_pac_http(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    String::from_utf8_lossy(&raw).into_owned()
}

#[test]
fn sec10_heal_guard_all_suspended_surfaces_explicit_error_and_macos_diagnostics() {
    zastava_lib::sysproxy::force_os_dry_run();
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let wifi = ServiceId::new("en9", "Slice2-WiFi", "Slice2-WiFi");
    plat.add_service(wifi.clone());

    let mut journal = open_journal_with_fake_policies(fs, Path::new("/slice2-heal")).unwrap();
    let guard = TestHealGuard::new();
    let pac_url = "http://127.0.0.1:8899/proxy.pac";
    let t0 = Instant::now();

    let initial = refresh_macos_pac(&mut journal, &plat, pac_url, &guard, t0).unwrap();
    assert_eq!(initial.configured, vec!["Slice2-WiFi".to_string()]);
    assert_eq!(plat.pac_of(&wifi).url.as_deref(), Some(pac_url));

    let foreign = PacState {
        url: Some("http://vpn.example/foreign.pac".into()),
        enabled: Some(true),
    };
    for i in 1..=3u64 {
        plat.seed_pac(&wifi, foreign.clone());
        refresh_macos_pac(
            &mut journal,
            &plat,
            pac_url,
            &guard,
            t0 + Duration::from_secs(i * 5),
        )
        .expect("re-heal within threshold must succeed");
    }
    assert!(guard.is_suspended_at(&wifi.key(), t0 + Duration::from_secs(20)));

    // Pass 4 with sole physical service suspended: MUST return explicit Err + [sysproxy:macos] diag.
    plat.seed_pac(&wifi, foreign);
    let err = refresh_macos_pac(
        &mut journal,
        &plat,
        pac_url,
        &guard,
        t0 + Duration::from_secs(25),
    )
    .expect_err("all physical services suspended must surface explicit Err");
    assert!(
        err.contains("приостановлена") && err.contains("Slice2-WiFi"),
        "{err}"
    );

    let diag = zastava_lib::diagnostics::dump();
    assert!(
        diag.iter().any(|l| {
            l.contains("[sysproxy:macos]")
                && l.contains("all physical services suspended by HealGuard")
        }),
        "missing [sysproxy:macos] HealGuard diagnostic: {diag:?}"
    );

    let usb = ServiceId::new("en10", "Slice2-USB", "Slice2-USB");
    plat.add_service(usb);
    let resumed = refresh_macos_pac(
        &mut journal,
        &plat,
        pac_url,
        &guard,
        t0 + Duration::from_secs(HEAL_WINDOW_SECS + 30),
    )
    .expect("topology change should resume macOS PAC self-heal");
    assert_eq!(resumed.configured.len(), 2);
    let diag_after = zastava_lib::diagnostics::dump();
    assert!(
        diag_after
            .iter()
            .any(|l| l.contains("[sysproxy:macos]") && l.contains("pac active:")),
        "missing [sysproxy:macos] pac active state transition: {diag_after:?}"
    );
}

#[tokio::test]
async fn sec10_ptr_masking_bundle_sanitization_and_distinct_key_dns_codes() {
    zastava_lib::sysproxy::force_os_dry_run();
    let exit_ip = "64.176.194.110";
    let tel = NetworkTelemetry {
        ip: exit_ip.into(),
        country_code: "NL".into(),
        hostname: None,
        asn: Some(20473),
        org: Some("Choopa".into()),
        isp: Some("Choopa".into()),
        timezone: Some("Europe/Amsterdam".into()),
        resolved_at: current_timestamp(),
    };

    let dot_ptr = evaluate_reverse_dns_ptr_with_ptr_for_mode(
        &tel,
        Some("64.176.194.110.vultrusercontent.com"),
        true,
    );
    assert_eq!(dot_ptr.code, "REVERSE_DNS_CLEAN");
    assert!(!dot_ptr.message.contains("64.176.194.110"));
    assert!(
        dot_ptr
            .message
            .contains("xxx.xxx.xxx.xxx.vultrusercontent.com")
    );

    let dash_ptr =
        evaluate_reverse_dns_ptr_with_ptr_for_mode(&tel, Some("185-220-101-5.isp.net"), true);
    assert_eq!(dash_ptr.code, "REVERSE_DNS_CLEAN");
    assert!(!dash_ptr.message.contains("185-220-101-5"));
    assert!(dash_ptr.message.contains("xxx-xxx-xxx-xxx.isp.net"));

    let raw_diag = "PTR 64.176.194.110.vultrusercontent.com & ec2-54-12-34-56.compute-1.amazonaws.com | Zastava v3.2.1 Chrome/131.0.0.0 date 2026-11-25";
    let sanitized = sanitize_diagnostic_text(raw_diag);
    assert!(
        !sanitized.contains("64.176.194.110") && !sanitized.contains("54-12-34-56"),
        "{sanitized}"
    );
    assert!(sanitized.contains("xxx.xxx.xxx.xxx.vultrusercontent.com"));
    assert!(sanitized.contains("ec2-xxx-xxx-xxx-xxx.compute-1.amazonaws.com"));
    assert!(
        sanitized.contains("v3.2.1")
            && sanitized.contains("Chrome/131.0.0.0")
            && sanitized.contains("2026-11-25")
    );

    let Some(upstream_addr) = spawn_echo_upstream().await else {
        return;
    };
    let state = AppState::new_in_memory();
    state.set_hide_ip_mode(true).await.unwrap();
    let route = Route {
        id: "key-nl-slice2".into(),
        label: "Zastava Key NL".into(),
        country: Some("NL".into()),
        exit_ip: Some(exit_ip.into()),
        expires_at: None,
        sub_url: None,
        grace_extended: false,
        entries: vec![Entry {
            proto: EntryProto::Http,
            host: "127.0.0.1".into(),
            port: upstream_addr.port(),
            username: None,
            password: None,
            sni: None,
        }],
        raw_key: format!("http://127.0.0.1:{}", upstream_addr.port()),
        enabled: true,
        added_at: 0,
    };
    state.upsert_route(route.clone()).await.unwrap();
    state
        .bind_provider_route("anthropic", Some(&route.id))
        .await
        .unwrap();

    let ru_resolver = "77.88.8.8";
    let mut dns = FakeDns::new(LookupOutcome::NotFound)
        .with("whoami.akamai.net", addr(ru_resolver))
        .with_txt(
            "o-o.myaddr.l.google.com",
            TxtOutcome::Records(vec![format!("\"{ru_resolver}\"")]),
        )
        .with_ptr(
            exit_ip.parse::<IpAddr>().unwrap(),
            "64.176.194.110.vultrusercontent.com",
        );
    for z in DangerousAsns::load_bundled().unwrap().dnsbl_zones {
        dns = dns
            .with(&format!("2.0.0.127.{}", z.zone), addr("127.0.0.2"))
            .with(
                &format!("110.194.176.64.{}", z.zone),
                LookupOutcome::NotFound,
            );
    }

    let probe = FakeProbe::body(
        200,
        r#"{"success":true,"ip":"64.176.194.110","country_code":"NL","connection":{"asn":20473,"org":"Choopa","isp":"Choopa"},"timezone":{"id":"Europe/Amsterdam"}}"#,
    )
    .with_route(ru_resolver, HttpProbeOutcome::Response {
        status: 200,
        body: r#"{"success":true,"ip":"77.88.8.8","country_code":"RU","connection":{"asn":13238,"org":"Yandex","isp":"Yandex"}}"#.into(),
    })
    .with_route("torbulkexitlist", HttpProbeOutcome::Response { status: 200, body: "198.51.100.1\n".into() })
    .with_route("cdn-cgi/trace", HttpProbeOutcome::Response {
        status: 200,
        body: format!("fl=1\nip={exit_ip}\nloc=NL\ncolo=AMS\n"),
    });

    let exit_v4: Ipv4Addr = exit_ip.parse().unwrap();
    let udp = FakeUdp::new()
        .with_server(stun::SERVERS[0].addr, stun::testing::echoing(exit_v4))
        .with_server(stun::SERVERS[1].addr, stun::testing::echoing(exit_v4));

    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(dns),
        probe: Arc::new(probe),
        udp: Arc::new(udp),
        system: Arc::new(FakeSystem {
            dns_listing: Ok("resolver #1\n  nameserver[0] : 77.88.8.8\n".into()),
            ..FakeSystem::healthy()
        }),
    })
    .unwrap();
    auditor
        .resolver
        .set_cached_for_route(Some(route.id.clone()), tel)
        .await;

    let report = auditor
        .evaluate_all_with_protection(
            ProviderId::Anthropic,
            &state,
            false,
            AuditProtectionFlags {
                sysproxy_active: true,
                cli_or_sandbox_protection_active: true,
                os_pac_deferred: false,
            },
        )
        .await
        .unwrap();

    assert_eq!(report.checks.len(), 14);
    assert_eq!(
        (report.checks[6].status, report.checks[6].code.as_str()),
        (CheckStatus::Ok, "DNS_KEY_REMOTE_RESOLVE")
    );
    assert_eq!(report.checks[9].code, "REVERSE_DNS_CLEAN");
    assert_eq!(
        (report.checks[10].status, report.checks[10].code.as_str()),
        (CheckStatus::Ok, "DNS_COUNTRY_KEY_ISOLATED")
    );

    let mut seen_codes = HashSet::new();
    for chk in &report.checks {
        assert!(
            seen_codes.insert(chk.code.clone()),
            "duplicate check code: {}",
            chk.code
        );
    }

    let state_data = state.get_data().await;
    assert!(state_data.hide_ip_mode);
    let mut reports_map = HashMap::new();
    reports_map.insert("anthropic".into(), Ok(report));
    let bundle = build_sanitized_diagnostic_bundle(
        &state_data,
        &state.stats().snapshot_sync(),
        &reports_map,
        true,
        true,
        8899,
        Some("macOS 15.6.1".into()),
        &[raw_diag.into()],
    );
    let rdns_in_bundle = &bundle.audit_reports["anthropic"].checks[9].message;
    assert!(
        !rdns_in_bundle.contains("64.176.194.110"),
        "{rdns_in_bundle}"
    );
    assert!(rdns_in_bundle.contains("xxx.xxx.xxx.xxx.vultrusercontent.com"));
    assert!(!bundle.recent_diagnostics[0].contains("64.176.194.110"));
    assert!(!bundle.recent_diagnostics[0].contains("54-12-34-56"));
    assert!(
        bundle.recent_diagnostics[0].contains("v3.2.1")
            && bundle.recent_diagnostics[0].contains("2026-11-25")
    );
}

#[tokio::test]
async fn sec11_expanded_domain_matrix_pac_and_cli_node_codex_lifecycle() {
    zastava_lib::sysproxy::force_os_dry_run();
    let _lock = RUNTIME_MATRIX_TEST_LOCK.lock().await;
    let _restore = MatrixSnapshotRestoreGuard;

    let server = ProxyServer::bind_ephemeral(
        Auditor::new().unwrap(),
        AppState::new_in_memory(),
        Arc::new(HoldQueue::new()),
        None,
    )
    .await
    .unwrap();
    let pac = server.build_pac_script().await;

    for (host, expected) in [
        ("jnn-pa.googleapis.com", ProviderId::Gemini),
        ("signaler-pa.googleapis.com", ProviderId::Gemini),
        ("apis.google.com", ProviderId::Gemini),
        ("autopush-cloudcode-pa.googleapis.com", ProviderId::Gemini),
        ("geller-pa.googleapis.com", ProviderId::Gemini),
        ("clau.de", ProviderId::Anthropic),
        ("ingest.sentry.io", ProviderId::Anthropic),
        ("statsigapi.net", ProviderId::Anthropic),
        ("sora.com", ProviderId::Openai),
        ("livekit.cloud", ProviderId::Openai),
    ] {
        assert_eq!(ProviderId::from_host(host), Some(expected), "{host}");
        assert!(pac.contains(&format!("\"{host}\"")), "PAC missing {host}");
    }

    for pay_host in [
        "paddle.com",
        "checkout.paddle.com",
        "veriff.com",
        "id.veriff.com",
    ] {
        assert!(is_payment_or_kyc_host(pay_host), "{pay_host}");
        assert_eq!(ProviderId::from_host(pay_host), None, "{pay_host}");
    }
    assert!(pac.contains("\"paddle.com\"") && pac.contains("\"veriff.com\""));

    assert_eq!(classify_process_name("codex"), "codex-cli");
    assert_eq!(
        get_known_app_info("codex-cli").map(|i| i.name),
        Some("Codex CLI")
    );
    assert_eq!(
        resolve_app_identity("unknown", Some("codex/1.2.3")).0,
        "codex-cli"
    );

    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let home = PathBuf::from("/fake-home");
    let codex_dir = home.join(".codex");
    let codex_settings = codex_dir.join("settings.json");
    let claude_settings = home.join(".claude").join("settings.json");
    fs.create_private_dir_all(&codex_dir).unwrap();
    fs.put(
        &codex_settings,
        br#"{"model":"o4-mini","env":{"USER_VAR":"keep"}}"#,
        0o644,
    );

    let mut journal =
        open_journal_with_fake_policies(fs.clone(), Path::new("/slice2-cli")).unwrap();
    let (targets, enable_rep) = apply_cli_protection_in_fs(
        &mut journal,
        &plat,
        fs.clone(),
        &home,
        Vec::new(),
        Some("http://127.0.0.1:8899"),
        None,
        CliMode::AiOnly,
    );
    assert!(!enable_rep.has_failures());
    assert!(targets.contains(&"Codex CLI".into()) && targets.contains(&"Claude Code".into()));

    let codex_on: serde_json::Value =
        serde_json::from_slice(&fs.get(&codex_settings).unwrap()).unwrap();
    assert_eq!(codex_on["model"], "o4-mini");
    assert_eq!(codex_on["env"]["USER_VAR"], "keep");
    assert_eq!(codex_on["env"]["NODE_USE_ENV_PROXY"], "1");
    assert_eq!(codex_on["env"]["HTTPS_PROXY"], "http://127.0.0.1:8899");
    let claude_on: serde_json::Value =
        serde_json::from_slice(&fs.get(&claude_settings).unwrap()).unwrap();
    assert_eq!(claude_on["env"]["NODE_USE_ENV_PROXY"], "1");

    let disable_rep = disable_cli_protection_in_fs(
        &mut journal,
        &plat,
        fs.clone(),
        &home,
        Vec::new(),
        CliMode::AiOnly,
    );
    assert!(!disable_rep.has_failures());

    let codex_off: serde_json::Value =
        serde_json::from_slice(&fs.get(&codex_settings).unwrap()).unwrap();
    assert_eq!(codex_off["model"], "o4-mini");
    assert_eq!(codex_off["env"]["USER_VAR"], "keep");
    assert!(codex_off["env"].get("NODE_USE_ENV_PROXY").is_none());
    assert!(codex_off["env"].get("HTTPS_PROXY").is_none());
    assert!(codex_off["env"].get("HTTP_PROXY").is_none());
    assert!(fs.get(&claude_settings).is_none());
}

#[tokio::test]
async fn sec12_signed_matrix_hot_update_anti_downgrade_and_fallback() {
    let _lock = RUNTIME_MATRIX_TEST_LOCK.lock().await;
    let _restore = MatrixSnapshotRestoreGuard;

    let (pair, pub_key) = test_ed25519_keypair();
    let dir = tempfile::tempdir().unwrap();
    let rules = RuleSet::load_bundled().unwrap();
    let mut auditor = Auditor::new().unwrap();
    auditor.rules = rules.clone();

    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor,
            AppState::new_in_memory(),
            Arc::new(HoldQueue::new()),
            None,
        )
        .await
        .unwrap(),
    );
    let pac_addr = server.bound_addr;
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    assert_eq!(ProviderId::from_host("hot-slice2-ai.example"), None);
    assert!(!is_payment_or_kyc_host("hot-slice2-pay.example"));
    assert!(
        !server
            .build_pac_script()
            .await
            .contains("\"hot-slice2-ai.example\"")
    );

    let mut next = ProviderMatrix::load_bundled().unwrap();
    next.schema_version = 1;
    next.version = "1.2.0".into();
    next.updated_at = "2026-11-25".into();
    next.generated_at_utc = "2026-11-25T19:00:00Z".into();
    next.providers
        .get_mut("gemini")
        .unwrap()
        .domains
        .push("hot-slice2-ai.example".into());
    next.payment_kyc_domains
        .push("hot-slice2-pay.example".into());
    let (_signed, signed_json) = sign_matrix(next.clone(), &pair);

    let applied =
        apply_signed_matrix_update_with_key(Some(dir.path()), &rules, &signed_json, &pub_key)
            .await
            .expect("valid signed matrix update must succeed");
    assert_eq!(applied.version, "1.2.0");
    assert_eq!(
        ProviderId::from_host("api.hot-slice2-ai.example"),
        Some(ProviderId::Gemini)
    );
    assert!(is_payment_or_kyc_host("checkout.hot-slice2-pay.example"));

    let pac_after = server.build_pac_script().await;
    assert!(
        pac_after.contains("\"hot-slice2-ai.example\"")
            && pac_after.contains("\"hot-slice2-pay.example\"")
    );
    let pac_http = fetch_pac_http(pac_addr).await;
    assert!(
        pac_http.contains("\"hot-slice2-ai.example\"")
            && pac_http.contains("\"hot-slice2-pay.example\"")
    );

    let tampered = signed_json.replacen("hot-slice2-ai.example", "evil-tampered.example", 1);
    assert!(
        apply_signed_matrix_update_with_key(Some(dir.path()), &rules, &tampered, &pub_key)
            .await
            .is_err()
    );
    assert_eq!(ProviderId::from_host("evil-tampered.example"), None);
    assert_eq!(
        ProviderId::from_host("hot-slice2-ai.example"),
        Some(ProviderId::Gemini)
    );

    let mut downgrade = next;
    downgrade.version = "1.0.5".into();
    let (_d_mat, downgrade_json) = sign_matrix(downgrade, &pair);
    assert!(
        apply_signed_matrix_update_with_key(Some(dir.path()), &rules, &downgrade_json, &pub_key)
            .await
            .is_err()
    );
    assert_eq!(rules.provider_matrix.read().await.version, "1.2.0");

    let rdir = rules_data_dir(dir.path());
    std::fs::write(rdir.join(MATRIX_FILE_NAME), &tampered).unwrap();
    std::fs::write(rdir.join(MATRIX_CACHE_FILE_NAME), "{not-json").unwrap();
    let fallback = load_provider_matrix_with_key(Some(dir.path()), &pub_key);
    assert_eq!(
        fallback.version,
        ProviderMatrix::load_bundled().unwrap().version
    );
}

#[tokio::test]
async fn sec12_live_proxy_direct_passthrough_logs_domain_drift_into_bundle() {
    zastava_lib::sysproxy::force_os_dry_run();
    domain_drift::clear_for_test();
    let _drift_guard = DriftResetGuard;

    let Some(echo_addr) = spawn_echo_upstream().await else {
        return;
    };
    let auditor = Auditor::with_env(AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::NotFound)),
        probe: Arc::new(FakeProbe::new(HttpProbeOutcome::Timeout)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    })
    .unwrap();
    let state = AppState::new_in_memory();
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            auditor,
            state.clone(),
            Arc::new(HoldQueue::new()),
            Some(echo_addr),
        )
        .await
        .unwrap(),
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    for host in [
        "new-telemetry.claude.example",
        "edge.statsig-new.anthropic.example",
        "people-pa.googleapis.com",
    ] {
        let mut client = TcpStream::connect(server.bound_addr).await.unwrap();
        let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();
        let mut head = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut head))
            .await
            .expect("direct pass-through must not block on drift detection")
            .unwrap();
        assert!(
            String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"),
            "{host}"
        );

        client.write_all(b"PING").await.unwrap();
        let mut echo = [0u8; 4];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"PING");
    }

    let diag = zastava_lib::diagnostics::dump();
    assert!(
        diag.iter()
            .any(|l| l.contains("[domain:drift]") && l.contains("new-telemetry.claude.example"))
    );
    assert!(
        diag.iter()
            .any(|l| l.contains("[domain:drift]")
                && l.contains("edge.statsig-new.anthropic.example"))
    );
    assert!(
        !diag
            .iter()
            .any(|l| l.contains("[domain:drift]") && l.contains("people-pa.googleapis.com"))
    );

    let bundle = build_sanitized_diagnostic_bundle(
        &state.get_data().await,
        &state.stats().snapshot_sync(),
        &HashMap::new(),
        true,
        false,
        server.bound_addr.port(),
        None,
        &diag,
    );
    assert!(
        bundle
            .unmapped_companion_domains
            .contains(&"new-telemetry.claude.example".into())
    );
    assert!(
        bundle
            .unmapped_companion_domains
            .contains(&"edge.statsig-new.anthropic.example".into())
    );
    assert!(
        !bundle
            .unmapped_companion_domains
            .contains(&"people-pa.googleapis.com".into())
    );
}
