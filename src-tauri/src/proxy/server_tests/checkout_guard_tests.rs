use super::super::*;
use super::coverage_and_holds_tests::offline_test_auditor;
use crate::auditor::payment_readiness::{
    PaymentChannel, PaymentReadinessInput, ReadinessTier, SubscriptionPlan,
    evaluate_payment_readiness,
};
use crate::bin_checker::BinChecker;
use crate::proxy::hold_queue::{HoldQueue, HoldResolution};
use crate::proxy::server::checkout_guard::checkout_provider_key;
use crate::state::{AppState, AppStateData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn andrew_red_report() -> crate::auditor::payment_readiness::PaymentReadinessReport {
    let checker = BinChecker::new();
    let bin = checker
        .check_bin_report_with_cache_dir("493724", Some("DE"), None)
        .await
        .unwrap();
    evaluate_payment_readiness(&PaymentReadinessInput {
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
    })
}

async fn send_connect(addr: SocketAddr, host: &str) -> String {
    let mut client = TcpStream::connect(addr).await.unwrap();
    let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test]
async fn checkout_guard_pauses_andrew_scenario_and_cancels_on_block() {
    crate::sysproxy::force_os_dry_run();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_test_auditor(),
            AppState::new_in_memory(),
            Arc::clone(&hold_queue),
            None,
        )
        .await
        .unwrap()
        .with_hold_ttl(Duration::from_secs(5)),
    );
    let report = andrew_red_report().await;
    assert_eq!(report.tier, ReadinessTier::Red);
    assert!(report.score < 50);
    server.checkout_guard.set_cached_report(report).await;

    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // CONNECT to checkout.stripe.com pauses in HoldQueue and sets checkout_risk alert.
    let client_task = tokio::spawn(send_connect(addr, "checkout.stripe.com"));

    let mut alert = None;
    for _ in 0..50 {
        if let Some(a) = hold_queue.current_alert() {
            alert = Some(a);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let alert = alert.expect("checkout alert must be raised in HoldQueue");
    assert_eq!(alert.scope, "checkout");
    assert_eq!(alert.host, "checkout.stripe.com");
    let risk = alert.checkout_risk.expect("checkout_risk payload present");
    assert_eq!(risk.tier, ReadinessTier::Red);
    assert!(risk.score < 50);
    assert_no_banned_jargon(&risk.reason);
    for msg in risk
        .blockers
        .iter()
        .chain(risk.warnings.iter())
        .chain(risk.recommended_action.iter())
    {
        assert_no_banned_jargon(msg);
    }

    // Cancel and inspect resolves hold as Block -> 403 Forbidden.
    assert!(hold_queue.resolve(&alert.id, HoldResolution::Block).await);
    let resp = client_task.await.unwrap();
    assert!(resp.contains("403 Forbidden"), "{resp}");
}

#[tokio::test]
async fn checkout_guard_intercepts_pay_google_and_allows_15m_override() {
    crate::sysproxy::force_os_dry_run();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move { while let Ok((_s, _)) = upstream.accept().await {} });

    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_test_auditor(),
            AppState::new_in_memory(),
            Arc::clone(&hold_queue),
            Some(upstream_addr),
        )
        .await
        .unwrap()
        .with_hold_ttl(Duration::from_secs(5)),
    );
    server
        .checkout_guard
        .set_cached_report(andrew_red_report().await)
        .await;

    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    // 1. CONNECT pay.google.com pauses until user clicks "Allow 15m".
    let client_task = tokio::spawn(send_connect(addr, "pay.google.com"));

    let mut alert = None;
    for _ in 0..50 {
        if let Some(a) = hold_queue.current_alert() {
            alert = Some(a);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let alert = alert.expect("pay.google.com alert must be raised");
    assert_eq!(alert.host, "pay.google.com");

    server
        .checkout_guard
        .allow_domain_15m("pay.google.com")
        .await;
    hold_queue
        .resolve_all_for_provider(
            &checkout_provider_key("pay.google.com"),
            HoldResolution::Allow,
        )
        .await;
    let resp1 = client_task.await.unwrap();
    assert!(resp1.contains("200 Connection Established"), "{resp1}");

    // 2. Subsequent CONNECT to pay.google.com passes immediately without pausing.
    let resp2 = send_connect(addr, "pay.google.com").await;
    assert!(resp2.contains("200 Connection Established"), "{resp2}");
    assert!(hold_queue.current_alert().is_none());
}

#[tokio::test]
async fn checkout_guard_fails_closed_on_superseded_and_unassessed_state() {
    crate::sysproxy::force_os_dry_run();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_test_auditor(),
            AppState::new_in_memory(),
            Arc::clone(&hold_queue),
            None,
        )
        .await
        .unwrap()
        .with_hold_ttl(Duration::from_secs(5)),
    );
    // Intentionally leave cached_report == None to verify unassessed main-gateway checkout
    // does NOT silently pass and HoldResolution::Superseded still fails closed (403).
    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    let srv_task = tokio::spawn(async move { srv.run().await });

    let client_task = tokio::spawn(send_connect(addr, "checkout.stripe.com"));

    let mut alert = None;
    for _ in 0..50 {
        if let Some(a) = hold_queue.current_alert() {
            alert = Some(a);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let alert = alert.expect("unassessed main-gateway checkout must raise HoldQueue alert");
    assert_eq!(alert.scope, "checkout");
    assert!(
        hold_queue
            .resolve(&alert.id, HoldResolution::Superseded)
            .await
    );

    let resp = client_task.await.unwrap();
    assert!(resp.contains("403 Forbidden"), "{resp}");
    srv_task.abort();
}

#[tokio::test]
async fn manual_killswitch_blocks_payment_hosts_in_direct_mode() {
    crate::sysproxy::force_os_dry_run();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move { while let Ok((_s, _)) = upstream.accept().await {} });

    let state = AppState::new_in_memory();
    let hold_queue = Arc::new(HoldQueue::new());
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_test_auditor(),
            state.clone(),
            Arc::clone(&hold_queue),
            Some(upstream_addr),
        )
        .await
        .unwrap()
        .with_hold_ttl(Duration::from_secs(5)),
    );
    server.guard.set_manual_killswitch(true, &state).await;

    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    let srv_task = tokio::spawn(async move { srv.run().await });

    for host in ["api.stripe.com", "checkout.stripe.com"] {
        let resp = send_connect(addr, host).await;
        assert!(
            resp.contains("403 Forbidden"),
            "{host} must be blocked by manual_killswitch in Direct mode, got: {resp}"
        );
    }
    assert!(hold_queue.current_alert().is_none());
    srv_task.abort();
}

#[tokio::test]
async fn active_payment_route_selection_follows_anthropic_direct_without_openai_split_ip() {
    crate::sysproxy::force_os_dry_run();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move { while let Ok((_s, _)) = upstream.accept().await {} });

    // Bind OpenAI to a dead/closed SOCKS5 route, while Anthropic remains Direct.
    let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed_listener.local_addr().unwrap().port();
    drop(closed_listener);

    let state = AppState::new_in_memory();
    state
        .upsert_route(crate::routing::Route {
            id: "openai-only".to_string(),
            label: "OpenAI Route".to_string(),
            country: Some("US".to_string()),
            exit_ip: None,
            expires_at: None,
            entries: vec![crate::routing::Entry {
                proto: crate::routing::EntryProto::Socks5,
                host: "127.0.0.1".to_string(),
                port: closed_port,
                username: None,
                password: None,
                sni: None,
            }],
            raw_key: format!("socks5://127.0.0.1:{closed_port}"),
            enabled: true,
            added_at: 0,
        })
        .await
        .unwrap();
    state
        .bind_provider_route("openai", Some("openai-only"))
        .await
        .unwrap();

    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_test_auditor(),
            state,
            Arc::new(HoldQueue::new()),
            Some(upstream_addr),
        )
        .await
        .unwrap(),
    );

    let addr = server.bound_addr;
    let srv = Arc::clone(&server);
    let srv_task = tokio::spawn(async move { srv.run().await });

    // api.stripe.com must follow Anthropic (Direct -> 200 via upstream_addr), NOT OpenAI's closed route (502).
    let resp = send_connect(addr, "api.stripe.com").await;
    assert!(
        resp.contains("200 Connection Established"),
        "payment host must stay on Anthropic Direct instead of OpenAI route, got: {resp}"
    );
    srv_task.abort();
}

fn assert_no_banned_jargon(text: &str) {
    let lower = text.to_lowercase();
    for term in [
        "payshield",
        "stripe",
        "bin-рентген",
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

#[tokio::test]
async fn checkout_guard_alerts_contain_no_banned_jargon_across_all_branches() {
    use crate::proxy::server::checkout_guard::CheckoutGuardState;
    use crate::state::{CleanProfileStatus, CleanRoomProfile, PostPaymentQuarantine};

    let guard = CheckoutGuardState::new();
    let now = crate::auditor::network::current_timestamp();

    // 1. 4h cooldown branch
    let cooldown_state = AppStateData {
        ip_change_cooldown_until: Some((now + 600) as i64),
        ..Default::default()
    };
    let cooldown_alert = guard
        .evaluate_risk_for_host("checkout.stripe.com", &cooldown_state)
        .await
        .expect("cooldown alert");
    assert_no_banned_jargon(&cooldown_alert.reason);
    for msg in cooldown_alert
        .blockers
        .iter()
        .chain(cooldown_alert.warnings.iter())
        .chain(cooldown_alert.recommended_action.iter())
    {
        assert_no_banned_jargon(msg);
    }

    // 2. 72h post-payment protection branch
    let mut quarantine_state = AppStateData::default();
    quarantine_state.clean_room.global_post_payment_quarantine = Some(PostPaymentQuarantine {
        started_at: now,
        expires_at: now + 3600 * 72,
        pinned_route_id: None,
        pinned_exit_ip: None,
        pinned_asn: None,
        pinned_country: Some("DE".to_string()),
        overridden_at: None,
    });
    let quarantine_alert = guard
        .evaluate_risk_for_host("checkout.stripe.com", &quarantine_state)
        .await
        .expect("quarantine alert");
    assert_no_banned_jargon(&quarantine_alert.reason);
    for msg in quarantine_alert
        .blockers
        .iter()
        .chain(quarantine_alert.warnings.iter())
        .chain(quarantine_alert.recommended_action.iter())
    {
        assert_no_banned_jargon(msg);
    }

    // 3. Tainted profile branch
    let mut tainted_state = AppStateData::default();
    tainted_state.clean_room.active_profile_id = Some("cr-tainted".to_string());
    tainted_state.clean_room.profiles.push(CleanRoomProfile {
        id: "cr-tainted".to_string(),
        label: "Профиль 1".to_string(),
        provider: "anthropic".to_string(),
        browser_engine: "chrome".to_string(),
        bound_route_id: None,
        last_exit_ip: Some("1.2.3.4".to_string()),
        last_exit_country: Some("DE".to_string()),
        status: CleanProfileStatus::Tainted,
        created_at: now,
        last_opened_at: None,
        warmup_started_at: None,
        launchpad_step: 1,
        completed_checklist: vec![],
        post_payment_quarantine: None,
    });
    let tainted_alert = guard
        .evaluate_risk_for_host("withpersona.com", &tainted_state)
        .await
        .expect("tainted alert");
    assert_no_banned_jargon(&tainted_alert.reason);
    for msg in tainted_alert
        .blockers
        .iter()
        .chain(tainted_alert.warnings.iter())
        .chain(tainted_alert.recommended_action.iter())
    {
        assert_no_banned_jargon(msg);
    }
}
