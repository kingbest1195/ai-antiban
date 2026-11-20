use super::*;

#[test]
fn test_telemetry_freshness() {
    let mut tel = NetworkTelemetry {
        ip: "185.1.1.1".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: Some(20473),
        org: Some("Choopa".to_string()),
        isp: Some("Choopa".to_string()),
        timezone: Some("Europe/Amsterdam".to_string()),
        resolved_at: current_timestamp(),
    };

    assert!(tel.is_fresh(30));

    // Expired telemetry
    tel.resolved_at = current_timestamp().saturating_sub(35);
    assert!(!tel.is_fresh(30));
}

#[test]
fn test_ipinfo_org_parsing() {
    let org_str = "AS20473 The Constant Company, LLC";
    let rest = org_str.strip_prefix("AS").unwrap();
    let mut parts = rest.splitn(2, ' ');
    let asn: u32 = parts.next().unwrap().parse().unwrap();
    let org = parts.next().unwrap();
    assert_eq!(asn, 20473);
    assert_eq!(org, "The Constant Company, LLC");
}

#[test]
fn test_build_upstream_client() {
    let socks_cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: "socks5://u:p@127.0.0.1:1080".to_string(),
        protocol: "socks5".to_string(),
        host: "127.0.0.1".to_string(),
        port: 1080,
        username: Some("u".to_string()),
        password: Some("p".to_string()),
        label: None,
    };
    assert!(build_upstream_client(&socks_cfg).is_ok());

    let http_cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: "http://127.0.0.1:8080".to_string(),
        protocol: "http".to_string(),
        host: "127.0.0.1".to_string(),
        port: 8080,
        username: None,
        password: None,
        label: None,
    };
    assert!(build_upstream_client(&http_cfg).is_ok());
}

#[tokio::test]
async fn test_resolver_cache_with_upstream_key() {
    let resolver = NetworkResolver::new();

    let tel_direct = NetworkTelemetry {
        ip: "109.1.1.1".to_string(),
        country_code: "RU".to_string(),
        hostname: None,
        asn: Some(1234),
        org: Some("Rostelecom".to_string()),
        isp: Some("Rostelecom".to_string()),
        timezone: Some("Europe/Moscow".to_string()),
        resolved_at: current_timestamp(),
    };

    let tel_nl = NetworkTelemetry {
        ip: "185.10.10.1".to_string(),
        country_code: "NL".to_string(),
        hostname: Some("nl-exit-01.cleanhost.net".to_string()),
        asn: Some(20473),
        org: Some("Choopa".to_string()),
        isp: Some("Choopa".to_string()),
        timezone: Some("Europe/Amsterdam".to_string()),
        resolved_at: current_timestamp(),
    };

    // Cache direct IP
    resolver.set_cached(tel_direct.clone()).await;
    let res1 = resolver.resolve(false).await.unwrap();
    assert_eq!(res1.ip, "109.1.1.1");

    // Cache NL upstream proxy IP under specific proxy key
    let key = Some("socks5://185.10.10.1:1080".to_string());
    resolver
        .set_cached_for_key(key.clone(), tel_nl.clone())
        .await;

    let cfg = UpstreamProxyConfig {
        enabled: true,
        raw_key: "socks5://185.10.10.1:1080".to_string(),
        protocol: "socks5".to_string(),
        host: "185.10.10.1".to_string(),
        port: 1080,
        username: None,
        password: None,
        label: None,
    };

    let res2 = resolver
        .resolve_with_upstream(false, Some(&cfg))
        .await
        .unwrap();
    assert_eq!(res2.ip, "185.10.10.1");
    assert_eq!(res2.country_code, "NL");
}

#[test]
fn test_reverse_dns_ptr_detection() {
    let bad_tel = NetworkTelemetry {
        ip: "185.220.101.5".to_string(),
        country_code: "DE".to_string(),
        hostname: Some("tor-exit-node-03.anonymizer.org".to_string()),
        asn: Some(1234),
        org: Some("Privacy Inc".to_string()),
        isp: Some("Tor Exit Relay".to_string()),
        timezone: Some("Europe/Berlin".to_string()),
        resolved_at: current_timestamp(),
    };
    let bad_res = evaluate_reverse_dns_ptr(&bad_tel);
    assert_eq!(
        bad_res.status,
        crate::auditor::geo_matrix::CheckStatus::Warning
    );
    assert_eq!(bad_res.code, "REVERSE_DNS_ANONYMIZER_MARKER");

    let clean_tel = NetworkTelemetry {
        ip: "95.217.1.1".to_string(),
        country_code: "FI".to_string(),
        hostname: Some("static.95-217-1-1.clients.your-server.de".to_string()),
        asn: Some(24940),
        org: Some("Hetzner Online GmbH".to_string()),
        isp: Some("Hetzner Online GmbH".to_string()),
        timezone: Some("Europe/Helsinki".to_string()),
        resolved_at: current_timestamp(),
    };
    let clean_res = evaluate_reverse_dns_ptr(&clean_tel);
    assert_eq!(
        clean_res.status,
        crate::auditor::geo_matrix::CheckStatus::Ok
    );
    assert_eq!(clean_res.code, "REVERSE_DNS_CLEAN");
}

#[test]
fn test_dns_country_consistency() {
    let tel = NetworkTelemetry {
        ip: "185.10.10.1".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: Some(20473),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };

    // Split country
    let split_res = evaluate_dns_country_consistency(&tel, Some("RU"));
    assert_eq!(
        split_res.status,
        crate::auditor::geo_matrix::CheckStatus::Warning
    );
    assert_eq!(split_res.code, "DNS_COUNTRY_SPLIT");

    // Matching country
    let clean_res = evaluate_dns_country_consistency(&tel, Some("NL"));
    assert_eq!(
        clean_res.status,
        crate::auditor::geo_matrix::CheckStatus::Ok
    );
    assert_eq!(clean_res.code, "DNS_COUNTRY_CONSISTENT");

    // No independent source: unknown, never "consistent"
    let none_res = evaluate_dns_country_consistency(&tel, None);
    assert_eq!(
        none_res.status,
        crate::auditor::geo_matrix::CheckStatus::Unknown
    );
    assert_eq!(none_res.reason, Some(UnknownReason::NoData));
}

#[test]
fn test_reverse_dns_without_any_data_is_unknown() {
    let bare = NetworkTelemetry {
        ip: "185.10.10.1".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: Some(1),
        org: None,
        isp: Some("  ".to_string()),
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let res = evaluate_reverse_dns_ptr(&bare);
    assert_eq!(res.status, crate::auditor::geo_matrix::CheckStatus::Unknown);
    assert_eq!(res.reason, Some(UnknownReason::NoData));
}

#[test]
fn test_has_provider_metadata() {
    let bare = NetworkTelemetry {
        ip: "185.10.10.1".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: None,
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    assert!(!bare.has_provider_metadata());

    let rich = NetworkTelemetry {
        asn: Some(20473),
        ..bare
    };
    assert!(rich.has_provider_metadata());
}

/// reqwest 0.12 + rustls can use an `https://` proxy: TLS to the entry (verified against the
/// trusted root, SNI from the key), `CONNECT` with Basic auth, then TLS to the target inside.
#[tokio::test]
async fn test_entry_client_through_https_proxy_stub() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "audit.test".to_string()])
            .unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let server_cfg = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut outer = acceptor.accept(tcp).await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if outer.read(&mut b).await.unwrap() == 0 {
                return;
            }
            head.push(b[0]);
        }
        let _ = seen_tx.send(String::from_utf8_lossy(&head).to_string());
        outer
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        // Inner TLS: we are now the target audit.test.
        let mut inner = acceptor.accept(outer).await.unwrap();
        let mut req = [0u8; 1024];
        let _ = inner.read(&mut req).await.unwrap();
        inner
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        let _ = inner.shutdown().await;
    });

    let entry = Entry {
        proto: EntryProto::Https,
        host: "127.0.0.1".to_string(),
        port,
        username: Some("alice".to_string()),
        password: Some("wonderland".to_string()),
        sni: Some("localhost".to_string()),
    };
    let root = reqwest::Certificate::from_der(ca.der()).unwrap();
    let client = build_entry_client_with_root(&entry, root).await.unwrap();
    let body = match client.get("https://audit.test/").send().await {
        Ok(r) => r.text().await.unwrap(),
        Err(e) if format!("{e:?}").contains("PermissionDenied") => return,
        Err(e) => panic!("request through https proxy failed: {e:?}"),
    };
    assert_eq!(body, "ok");
    let seen = seen_rx.await.unwrap();
    assert!(
        seen.starts_with("CONNECT audit.test:443 HTTP/1.1"),
        "{seen}"
    );
    // base64("alice:wonderland")
    assert!(seen.contains("YWxpY2U6d29uZGVybGFuZA=="), "{seen}");

    // Without the test root (production path) the private CA is rejected.
    let prod = build_entry_client(&entry, true, 0).await.unwrap();
    assert!(prod.get("https://audit.test/").send().await.is_err());
}

#[tokio::test]
async fn test_resolver_cache_keyed_by_route_id() {
    let resolver = NetworkResolver::new();
    let tel = |ip: &str| NetworkTelemetry {
        ip: ip.to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: Some(1),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    resolver.set_cached(tel("109.1.1.1")).await;
    resolver
        .set_cached_for_route(Some("route-a".into()), tel("185.1.1.1"))
        .await;
    resolver
        .set_cached_for_route(Some("route-b".into()), tel("185.2.2.2"))
        .await;
    let mk = |id: &str| Route {
        id: id.to_string(),
        label: id.to_string(),
        country: None,
        exit_ip: None,
        expires_at: None,
        entries: vec![],
        raw_key: String::new(),
        enabled: true,
        added_at: 0,
    };
    assert_eq!(resolver.resolve(false).await.unwrap().ip, "109.1.1.1");
    assert_eq!(
        resolver
            .resolve_with_route(false, Some(&mk("route-a")))
            .await
            .unwrap()
            .ip,
        "185.1.1.1"
    );
    assert_eq!(
        resolver
            .resolve_with_route(false, Some(&mk("route-b")))
            .await
            .unwrap()
            .ip,
        "185.2.2.2"
    );
    resolver.invalidate_route("route-a").await;
    // No entries -> cannot resolve, and never falls back to the direct cache.
    assert!(
        resolver
            .resolve_with_route(false, Some(&mk("route-a")))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_reverse_ptr_via_fake_dns() {
    use crate::auditor::geo_matrix::CheckStatus;
    use crate::auditor::seams::LookupOutcome;
    use crate::auditor::seams::fakes::FakeDns;

    let clean_ip: std::net::IpAddr = "95.217.1.1".parse().unwrap();
    let tor_ip: std::net::IpAddr = "185.220.101.5".parse().unwrap();
    let dns = FakeDns::new(LookupOutcome::Timeout)
        .with_ptr(clean_ip, "static.95-217-1-1.clients.your-server.de")
        .with_ptr(tor_ip, "tor-exit-01.anonymizer.example");

    let bare_clean = NetworkTelemetry {
        ip: clean_ip.to_string(),
        country_code: "FI".to_string(),
        hostname: None,
        asn: Some(24940),
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let clean_res = evaluate_reverse_dns_ptr_with_dns(&bare_clean, &dns).await;
    assert_eq!(clean_res.status, CheckStatus::Ok);
    assert_eq!(clean_res.code, "REVERSE_DNS_CLEAN");
    assert_eq!(clean_res.measured_via.as_deref(), Some("rdns:ptr"));
    assert!(
        clean_res
            .message
            .contains("static.95-217-1-1.clients.your-server.de")
    );
    assert!(!clean_res.message.contains("не запрашивалась"));

    let bare_tor = NetworkTelemetry {
        ip: tor_ip.to_string(),
        country_code: "DE".to_string(),
        hostname: None,
        asn: None,
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let tor_res = evaluate_reverse_dns_ptr_with_dns(&bare_tor, &dns).await;
    assert_eq!(tor_res.status, CheckStatus::Warning);
    assert_eq!(tor_res.code, "REVERSE_DNS_ANONYMIZER_MARKER");
    assert_eq!(tor_res.measured_via.as_deref(), Some("rdns:ptr"));

    let unmapped = NetworkTelemetry {
        ip: "203.0.113.55".to_string(),
        country_code: "NL".to_string(),
        hostname: None,
        asn: None,
        org: None,
        isp: None,
        timezone: None,
        resolved_at: current_timestamp(),
    };
    let unk_res = evaluate_reverse_dns_ptr_with_dns(&unmapped, &dns).await;
    assert_eq!(unk_res.status, CheckStatus::Unknown);
    assert_eq!(unk_res.code, "REVERSE_DNS_NO_DATA");
}
