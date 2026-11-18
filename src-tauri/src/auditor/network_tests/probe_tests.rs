use super::*;

#[tokio::test]
async fn probe_provider_exit_matches_telemetry_ip_and_sets_measured_via() {
    let url = spawn_http_mock(
        "200 OK",
        "text/plain",
        "fl=1\nip=185.10.20.30\nloc=NL\ncolo=AMS\n",
        Duration::ZERO,
    )
    .await;
    let resolver = NetworkResolver::new();
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let telemetry = NetworkTelemetry {
        ip: "185.10.20.30".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: Some(20473),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let res = resolver
        .probe_provider_exit_with_url(
            ProviderId::Anthropic,
            None,
            &telemetry,
            &matrix,
            &url,
            Some(&client),
            Duration::from_secs(2),
        )
        .await;
    assert_eq!(res.status, CheckStatus::Ok);
    assert_eq!(res.code, "PROVIDER_EXIT_VERIFIED");
    assert_eq!(res.measured_via.as_deref(), Some("1.1.1.1"));
    assert!(res.message.contains("185.10.20.30"));
    assert!(res.message.contains("AMS"));
}

#[tokio::test]
async fn probe_provider_exit_warns_on_split_tunnel_ip_mismatch() {
    let url = spawn_http_mock(
        "200 OK",
        "text/plain",
        "fl=1\nip=95.10.20.30\nloc=DE\ncolo=FRA\n",
        Duration::ZERO,
    )
    .await;
    let resolver = NetworkResolver::new();
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let telemetry = NetworkTelemetry {
        ip: "185.10.20.30".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: Some(20473),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let res = resolver
        .probe_provider_exit_with_url(
            ProviderId::Anthropic,
            None,
            &telemetry,
            &matrix,
            &url,
            Some(&client),
            Duration::from_secs(2),
        )
        .await;
    assert_eq!(res.status, CheckStatus::Warning);
    assert_eq!(res.code, "PROVIDER_EXIT_SPLIT_MISMATCH");
    assert!(res.message.contains("split tunnel/PAC"));
}

#[tokio::test]
async fn probe_provider_exit_returns_source_refused_on_403_and_html_challenge() {
    let url_403 = spawn_http_mock(
        "403 Forbidden",
        "text/plain",
        "Just a moment...",
        Duration::ZERO,
    )
    .await;
    let url_html = spawn_http_mock(
        "200 OK",
        "text/html",
        "<!doctype html><html><body>Challenge</body></html>",
        Duration::ZERO,
    )
    .await;
    let resolver = NetworkResolver::new();
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let telemetry = NetworkTelemetry {
        ip: "185.10.20.30".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: None,
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    for url in [url_403, url_html] {
        let res = resolver
            .probe_provider_exit_with_url(
                ProviderId::Openai,
                None,
                &telemetry,
                &matrix,
                &url,
                Some(&client),
                Duration::from_secs(2),
            )
            .await;
        assert_eq!(res.status, CheckStatus::Unknown);
        assert_eq!(res.reason, Some(UnknownReason::SourceRefused));
        assert_eq!(res.measured_via.as_deref(), Some("1.1.1.1"));
    }
}

#[tokio::test]
async fn probe_provider_exit_returns_timeout_when_server_stalls() {
    let url = spawn_http_mock(
        "200 OK",
        "text/plain",
        "ip=185.10.20.30\nloc=NL\n",
        Duration::from_millis(300),
    )
    .await;
    let resolver = NetworkResolver::new();
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let telemetry = NetworkTelemetry {
        ip: "185.10.20.30".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: None,
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let res = resolver
        .probe_provider_exit_with_url(
            ProviderId::Anthropic,
            None,
            &telemetry,
            &matrix,
            &url,
            Some(&client),
            Duration::from_millis(50),
        )
        .await;
    assert_eq!(res.status, CheckStatus::Unknown);
    assert_eq!(res.reason, Some(UnknownReason::Timeout));
}

#[tokio::test]
async fn probe_provider_exit_gemini_direct_is_not_applicable_and_bound_route_uses_route_label()
{
    let url = spawn_http_mock(
        "200 OK",
        "application/json",
        r#"{"ip":"185.55.66.77","country":"DE"}"#,
        Duration::ZERO,
    )
    .await;
    let resolver = NetworkResolver::new();
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let telemetry = NetworkTelemetry {
        ip: "185.55.66.77".to_string(),
        country_code: "DE".to_string(),
        hostname: None,
        asn: Some(24940),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let direct = resolver
        .probe_provider_exit(ProviderId::Gemini, None, &telemetry, &matrix)
        .await;
    assert_eq!(direct.status, CheckStatus::Unknown);
    assert_eq!(direct.reason, Some(UnknownReason::NotApplicable));

    let route = Route {
        id: "r1".to_string(),
        label: "DE VPS".to_string(),
        country: Some("DE".to_string()),
        exit_ip: None,
        expires_at: None,
        entries: vec![],
        raw_key: String::new(),
        enabled: true,
        added_at: 0,
    };
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let bound = resolver
        .probe_provider_exit_with_url(
            ProviderId::Gemini,
            Some(&route),
            &telemetry,
            &matrix,
            &url,
            Some(&client),
            Duration::from_secs(2),
        )
        .await;
    assert_eq!(bound.status, CheckStatus::Ok);
    assert_eq!(
        bound.measured_via.as_deref(),
        Some("gemini (ipinfo.io) (маршрут ключа)")
    );
}

#[tokio::test]
async fn resolver_and_entry_clients_use_neutral_user_agent_without_zastava() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    assert!(!NEUTRAL_USER_AGENT.to_ascii_lowercase().contains("zastava"));

    // 1. Direct client in NetworkResolver::new
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        }
    });

    let resolver = NetworkResolver::new();
    let _ = resolver
        .client
        .get(format!("http://127.0.0.1:{port}/test"))
        .send()
        .await
        .unwrap();
    let raw_req = rx.await.unwrap();
    let lower = raw_req.to_ascii_lowercase();
    assert!(
        !lower.contains("zastava"),
        "User-Agent must never reveal Zastava: {raw_req}"
    );
    assert!(
        raw_req.contains(NEUTRAL_USER_AGENT),
        "Expected neutral UA in request: {raw_req}"
    );

    // 2. Entry proxy client in entry_client_builder
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let (ptx, prx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = proxy_listener.accept().await {
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let _ = ptx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        }
    });
    let entry = Entry {
        proto: EntryProto::Http,
        host: "127.0.0.1".to_string(),
        port: proxy_port,
        username: None,
        password: None,
        sni: None,
    };
    let entry_client = build_entry_client(&entry, true, 0).await.unwrap();
    let _ = entry_client.get("http://probe.invalid/").send().await;
    let proxy_req = prx.await.unwrap();
    assert!(!proxy_req.to_ascii_lowercase().contains("zastava"));
    assert!(proxy_req.contains(NEUTRAL_USER_AGENT));
}

#[tokio::test]
async fn probe_provider_exit_with_no_route_never_contacts_claude_or_chatgpt() {
    use std::sync::Mutex;

    struct RecordingProbe {
        urls: Mutex<Vec<String>>,
    }
    impl IpProbe for RecordingProbe {
        fn get<'a>(
            &'a self,
            url: &'a str,
            _limit: Duration,
        ) -> crate::auditor::seams::BoxFuture<'a, HttpProbeOutcome> {
            self.urls.lock().unwrap().push(url.to_string());
            Box::pin(async move {
                HttpProbeOutcome::Response {
                    status: 200,
                    body: "fl=1\nip=185.10.20.30\nloc=NL\ncolo=AMS\n".to_string(),
                }
            })
        }
    }

    assert_eq!(
        default_exit_probe_url(ProviderId::Anthropic, false),
        "https://1.1.1.1/cdn-cgi/trace"
    );
    assert_eq!(
        default_exit_probe_url(ProviderId::Openai, false),
        "https://1.1.1.1/cdn-cgi/trace"
    );
    assert_eq!(
        default_exit_probe_url(ProviderId::Anthropic, true),
        "https://claude.ai/cdn-cgi/trace"
    );
    assert_eq!(
        default_exit_probe_url(ProviderId::Openai, true),
        "https://chatgpt.com/cdn-cgi/trace"
    );

    let resolver = NetworkResolver::new();
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let telemetry = NetworkTelemetry {
        ip: "185.10.20.30".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: Some(20473),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let probe = RecordingProbe {
        urls: Mutex::new(Vec::new()),
    };

    for pid in [
        ProviderId::Anthropic,
        ProviderId::Openai,
        ProviderId::Gemini,
    ] {
        let _ = resolver
            .probe_provider_exit_with_probe(pid, None, &telemetry, &matrix, Some(&probe))
            .await;
    }

    let urls = probe.urls.lock().unwrap();
    assert!(!urls.is_empty());
    for u in urls.iter() {
        assert!(
            !u.contains("claude.ai") && !u.contains("chatgpt.com"),
            "Unbound probe must NEVER contact provider domains directly: {u}"
        );
        assert_eq!(u, "https://1.1.1.1/cdn-cgi/trace");
    }
}

#[test]
fn checked_entry_error_separates_dns_failure_from_policy_rejection() {
    let dns_err = std::io::Error::from_raw_os_error(11001);
    let dns_msg = format_checked_entry_error("node.example:443", &dns_err);
    assert!(dns_msg.contains("DNS lookup failed:"), "{dns_msg}");
    assert!(!dns_msg.contains("rejected:"), "{dns_msg}");

    let policy_err = std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "entry node points to the Zastava gateway itself",
    );
    let policy_msg = format_checked_entry_error("127.0.0.1:8899", &policy_err);
    assert!(policy_msg.contains("rejected:"), "{policy_msg}");
    assert!(!policy_msg.contains("DNS lookup failed:"), "{policy_msg}");
}

#[tokio::test]
async fn invalidate_cache_mid_flight_discards_stale_telemetry_and_clears_check_cache() {
    use std::sync::atomic::AtomicUsize;

    let resolver = NetworkResolver::new();
    let _ = resolver
        .check_cache()
        .os
        .get_or_compute("tz:stale", Duration::from_secs(60), |_| true, async {
            CheckResult::ok("T", "stale")
        })
        .await;
    assert!(resolver.check_cache().os.contains_key("tz:stale").await);

    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let started_bg = Arc::clone(&started);
    let release_bg = Arc::clone(&release);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_bg = Arc::clone(&calls);

    let resolver_bg = resolver.clone();
    let inflight = tokio::spawn(async move {
        resolver_bg
            .resolve_cached_or_fetch(None, None, false, || async move {
                calls_bg.fetch_add(1, Ordering::SeqCst);
                started_bg.notify_one();
                release_bg.notified().await;
                Ok(NetworkTelemetry {
                    ip: "5.5.5.5".to_string(),
                    country_code: "RU".to_string(),
                    hostname: None,
                    asn: Some(9009),
                    org: None,
                    isp: Some("OldVPN".to_string()),
                    timezone: None,
                    resolved_at: current_timestamp(),
                })
            })
            .await
    });

    // Wait until the slow resolve is mid-flight inside `resolve_lock`, then invalidate.
    started.notified().await;
    resolver.invalidate_cache().await;
    assert!(
        resolver.check_cache().os.is_empty().await,
        "invalidate_cache must clear CheckCache immediately"
    );

    release.notify_one();
    let stale_ret = inflight.await.unwrap().unwrap();
    assert_eq!(stale_ret.ip, "5.5.5.5");

    // Stale result MUST NOT poison `self.cache` for subsequent lookups.
    assert!(
        resolver.cached_direct_country("5.5.5.5").await.is_none(),
        "stale IP must be discarded instead of poisoning cache"
    );

    let calls_next = Arc::clone(&calls);
    let fresh = resolver
        .resolve_cached_or_fetch(None, None, false, || async move {
            calls_next.fetch_add(1, Ordering::SeqCst);
            Ok(NetworkTelemetry {
                ip: "145.241.193.245".to_string(),
                country_code: "GB".to_string(),
                hostname: None,
                asn: Some(31898),
                org: None,
                isp: Some("PinnedVPS".to_string()),
                timezone: None,
                resolved_at: current_timestamp(),
            })
        })
        .await
        .unwrap();
    assert_eq!(fresh.ip, "145.241.193.245");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        resolver
            .cached_direct_country("145.241.193.245")
            .await
            .as_deref(),
        Some("GB")
    );

    // Next lookup uses the newly populated clean cache without re-fetching.
    let calls_cached = Arc::clone(&calls);
    let hit = resolver
        .resolve_cached_or_fetch(None, None, false, || async move {
            calls_cached.fetch_add(1, Ordering::SeqCst);
            Err("should hit cache".to_string())
        })
        .await
        .unwrap();
    assert_eq!(hit.ip, "145.241.193.245");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
