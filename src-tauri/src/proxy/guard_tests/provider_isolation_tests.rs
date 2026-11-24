use super::*;
use crate::auditor::CheckResult;
use crate::state::InterceptionBehavior;
use std::sync::atomic::Ordering;

#[tokio::test(start_paused = true)]
async fn test_red_claude_never_blocks_healthy_chatgpt_ask_popup() {
    let audit: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            match provider {
                ProviderId::Anthropic => {
                    let mut r = test_report(provider, OverallStatus::Red, "203.0.113.10", "GB");
                    r.checks = vec![CheckResult::critical(
                        "IMPOSSIBLE_TRAVEL_CRITICAL",
                        "Country changed FR -> GB in 2 min",
                        None,
                    )];
                    Ok(r)
                }
                ProviderId::Openai => Ok(test_report(
                    provider,
                    OverallStatus::Green,
                    "203.0.113.10",
                    "GB",
                )),
                ProviderId::Gemini => Ok(test_report(
                    provider,
                    OverallStatus::Green,
                    "136.244.114.42",
                    "FR",
                )),
            }
        })
    });

    let h = harness(audit, "203.0.113.10").await;
    h.state
        .add_trusted_exception("openai", "203.0.113.10")
        .await
        .unwrap();
    // Bind Gemini to a Zastava key so only Anthropic & OpenAI are unrouted.
    let fr_route = crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
    let fr_id = h.state.upsert_route(fr_route).await.unwrap();
    h.state
        .bind_provider_route("gemini", Some(&fr_id))
        .await
        .unwrap();

    h.change("203.0.113.10").await;
    let ready =
        h.io.wait_for("interceptor://enriched", 3000)
            .await
            .expect("enriched ready");
    assert_eq!(ready.0["phase"], "ready");
    let id = ready.0["id"].as_str().expect("alert id");

    // Healthy ChatGPT is immediately open once audit confirms OpenAI is Green;
    // Claude stays Pending waiting for decision.
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);

    // User blocks the alert (or hold TTL expires) -> ONLY Claude is blocked.
    h.env.hold_queue.resolve(id, HoldResolution::Block).await;
    tokio::task::yield_now().await;
    for _ in 0..10 {
        if h.guard.gate_for(ProviderId::Anthropic) == Gate::Blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    assert!(h.state.is_provider_blocked("anthropic").await);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert!(!h.state.is_provider_blocked("openai").await);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
    assert!(!h.state.is_provider_blocked("gemini").await);
}

#[tokio::test(start_paused = true)]
async fn test_red_claude_never_blocks_healthy_chatgpt_silent_and_auto_allow() {
    for behavior in [
        InterceptionBehavior::AutoLockSilent,
        InterceptionBehavior::AutoAllowTrusted,
    ] {
        let audit: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                match provider {
                    ProviderId::Anthropic => {
                        let mut r = test_report(provider, OverallStatus::Red, "203.0.113.10", "GB");
                        r.checks = vec![CheckResult::critical(
                            "IMPOSSIBLE_TRAVEL_CRITICAL",
                            "Country changed FR -> GB in 2 min",
                            None,
                        )];
                        Ok(r)
                    }
                    ProviderId::Openai => Ok(test_report(
                        provider,
                        OverallStatus::Green,
                        "203.0.113.10",
                        "GB",
                    )),
                    ProviderId::Gemini => Ok(test_report(
                        provider,
                        OverallStatus::Green,
                        "136.244.114.42",
                        "FR",
                    )),
                }
            })
        });

        let h = harness(audit, "203.0.113.10").await;
        let fr_route =
            crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
        let fr_id = h.state.upsert_route(fr_route).await.unwrap();
        h.state
            .bind_provider_route("gemini", Some(&fr_id))
            .await
            .unwrap();
        h.state.set_interception_behavior(behavior).await.unwrap();
        if behavior == InterceptionBehavior::AutoLockSilent {
            h.state
                .add_trusted_exception("openai", "203.0.113.10")
                .await
                .unwrap();
        }

        {
            let mut inner = h.guard.inner.lock().await;
            inner.route_dirty = true;
        }
        h.guard.check_route_and_tick(&h.env).await;
        h.io.wait_for("network://changed", 2000)
            .await
            .expect("silent audit settled");

        assert_eq!(
            h.guard.gate_for(ProviderId::Anthropic),
            Gate::Blocked,
            "anthropic must be blocked under {behavior:?}"
        );
        assert!(
            h.state.is_provider_blocked("anthropic").await,
            "anthropic must be in blocked_providers under {behavior:?}"
        );
        assert_eq!(
            h.guard.gate_for(ProviderId::Openai),
            Gate::Open,
            "healthy openai must remain Open under {behavior:?}"
        );
        assert!(
            !h.state.is_provider_blocked("openai").await,
            "healthy openai must not be collaterally blocked under {behavior:?}"
        );
        assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
    }
}

#[tokio::test(start_paused = true)]
async fn test_finish_audit_opens_all_healthy_providers_when_affected_is_empty() {
    let audit: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            Ok(test_report(
                provider,
                OverallStatus::Green,
                "145.241.193.245",
                "GB",
            ))
        })
    });
    let h = harness(audit, "145.241.193.245").await;
    h.state
        .set_interception_behavior(InterceptionBehavior::AutoAllowTrusted)
        .await
        .unwrap();
    let fr_route = crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
    let fr_id = h.state.upsert_route(fr_route).await.unwrap();
    h.state
        .bind_provider_route("gemini", Some(&fr_id))
        .await
        .unwrap();

    h.change("145.241.193.245").await;
    h.io.wait_for("network://changed", 3000)
        .await
        .expect("network://changed");
    assert_eq!(h.io.count("interceptor://enriched"), 0);
    assert!(h.env.hold_queue.current_alert().is_none());

    // Both unrouted providers audited Green -> must immediately transition to Gate::Open,
    // never stuck in Pending or written to blocked_providers.
    assert_eq!(h.guard.gate(), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
    assert!(h.state.get_data().await.blocked_providers.is_empty());
    assert_eq!(h.guard.pause_mode(), PauseMode::None);
    assert!(h.guard.gate_reason().is_none());
    assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
}

#[tokio::test(start_paused = true)]
async fn test_spawn_decision_waiter_with_empty_affected_never_blocks_unrouted_providers() {
    for resolution in [None, Some(HoldResolution::Block)] {
        let h = harness(
            slow_audit(
                Duration::from_millis(10),
                "145.241.193.245",
                OverallStatus::Green,
            ),
            "145.241.193.245",
        )
        .await;
        let fr_route =
            crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
        let fr_id = h.state.upsert_route(fr_route).await.unwrap();
        h.state
            .bind_provider_route("gemini", Some(&fr_id))
            .await
            .unwrap();

        let id = "waiter-empty-affected".to_string();
        let rx = h.env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
        let tel = test_report(
            ProviderId::Anthropic,
            OverallStatus::Green,
            "145.241.193.245",
            "GB",
        )
        .telemetry;
        let epoch = {
            let mut inner = h.guard.inner.lock().await;
            inner.observed_ip = Some("145.241.193.245".to_string());
            inner.pending = Some(Pending {
                id: id.clone(),
                epoch: inner.epoch,
                target_ip: "145.241.193.245".to_string(),
                tel: Some(tel),
                clear_old_state: None,
                affected_providers: Vec::new(),
                already_blocked_providers: Vec::new(),
                healthy_providers: vec!["anthropic", "openai"],
                alert_emitted: true,
            });
            inner.epoch
        };
        h.guard.set_gate(Gate::Pending);
        h.guard.spawn_decision_waiter(&h.env, id.clone(), epoch, rx);

        if let Some(res) = resolution {
            assert!(h.env.hold_queue.resolve(&id, res).await);
            tokio::time::sleep(Duration::from_millis(20)).await;
        } else {
            tokio::time::sleep(Duration::from_secs(DEFAULT_HOLD_TTL_SECS + 1)).await;
        }

        assert_eq!(h.guard.gate(), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert!(!h.state.is_provider_blocked("anthropic").await);
        assert!(!h.state.is_provider_blocked("openai").await);
        assert_eq!(h.guard.pause_mode(), PauseMode::None);
    }
}

#[tokio::test(start_paused = true)]
async fn test_routing_gemini_does_not_freeze_or_reset_anthropic_and_openai() {
    let audit: AuditFn = Arc::new(|provider, _force| {
        Box::pin(async move {
            Ok(test_report(
                provider,
                OverallStatus::Green,
                "145.241.193.245",
                "GB",
            ))
        })
    });
    let h = harness(audit, "145.241.193.245").await;
    h.state
        .set_pinned_ip(Some("145.241.193.245".to_string()))
        .await
        .unwrap();
    h.state.set_strict_pinning_enabled(true).await.unwrap();
    {
        let mut inner = h.guard.inner.lock().await;
        inner.baseline = None;
        inner.last_route_fp = Some(compute_local_route_fingerprint(None));
    }

    // Initial startup tick on pinned VPN IP sets baseline cleanly and keeps gates Open.
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.gate(), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);

    // Bind Gemini to a Zastava key -> unrouted shrinks from 3 to 2.
    let fr_route = crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
    let fr_id = h.state.upsert_route(fr_route).await.unwrap();
    h.state
        .bind_provider_route("gemini", Some(&fr_id))
        .await
        .unwrap();
    h.guard.open_routed_providers(&["gemini"]);

    h.guard.inner.lock().await.last_probe = None;
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.gate(), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    assert!(h.state.get_data().await.blocked_providers.is_empty());

    // Even if Gemini is unbound later, healthy Anthropic & OpenAI remain Open.
    h.state.bind_provider_route("gemini", None).await.unwrap();
    h.guard.inner.lock().await.last_probe = None;
    h.guard.check_route_and_tick(&h.env).await;
    assert_eq!(h.guard.gate(), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
    assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
    assert_eq!(h.io.count("interceptor://risk-detected"), 0);
}

#[tokio::test]
async fn network_guard_client_uses_neutral_user_agent() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nip=1.2.3.4\n",
                )
                .await;
        }
    });

    let guard = NetworkGuard::new();
    let _ = guard
        .client
        .get(format!("http://127.0.0.1:{port}/cdn-cgi/trace"))
        .send()
        .await
        .unwrap();
    let raw_req = rx.await.unwrap();
    assert!(
        !raw_req.to_ascii_lowercase().contains("zastava"),
        "Guard client User-Agent must never reveal Zastava: {raw_req}"
    );
    assert!(raw_req.contains(crate::auditor::network::NEUTRAL_USER_AGENT));
}

#[tokio::test]
async fn guard_audit_all_with_unbound_routes_never_probes_provider_domains() {
    use crate::auditor::seams::fakes::{FakeDns, FakeSystem, FakeUdp};
    use crate::auditor::seams::{AuditEnv, HttpProbeOutcome, IpProbe, LookupOutcome};

    struct RecordingProbe {
        urls: std::sync::Mutex<Vec<String>>,
    }
    impl IpProbe for RecordingProbe {
        fn get<'a>(
            &'a self,
            url: &'a str,
            _limit: Duration,
        ) -> crate::auditor::seams::BoxFuture<'a, HttpProbeOutcome> {
            self.urls.lock().unwrap().push(url.to_string());
            let body = if url.contains("ipwho.is") {
                r#"{"success":true,"country_code":"NL","connection":{"asn":20473,"org":"Choopa"}}"#
            } else {
                "fl=1\nip=203.0.113.9\nloc=NL\ncolo=AMS\n"
            };
            Box::pin(async move {
                HttpProbeOutcome::Response {
                    status: 200,
                    body: body.to_string(),
                }
            })
        }
    }

    let probe = Arc::new(RecordingProbe {
        urls: std::sync::Mutex::new(Vec::new()),
    });
    let env = AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::Timeout)),
        probe: probe.clone(),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    };
    let auditor = Auditor::with_env(env).unwrap();
    let tel = test_report(
        ProviderId::Anthropic,
        OverallStatus::Green,
        "203.0.113.9",
        "NL",
    )
    .telemetry;
    auditor.resolver.set_cached(tel).await;

    let state = AppState::new_in_memory();
    let audit: AuditFn = Arc::new(move |provider, force| {
        let (auditor, state) = (auditor.clone(), state.clone());
        Box::pin(async move { auditor.evaluate_all(provider, &state, force).await })
    });

    let results = audit_all(&audit).await;
    assert_eq!(results.len(), 3);
    let seen = probe.urls.lock().unwrap();
    assert!(!seen.is_empty());
    for url in seen.iter() {
        assert!(
            !url.contains("claude.ai") && !url.contains("chatgpt.com"),
            "audit_all with route: None must never probe provider domains: {url}"
        );
    }
}
