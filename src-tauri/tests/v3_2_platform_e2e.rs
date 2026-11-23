//! E2E regression & scenario tests for Zastava v3.2.0 §7.4, §7.5, and §7.6.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zastava_lib::auditor::{
    Auditor, CheckStatus, ExitIdentity, TorLookup, evaluate_ip_reputation,
};
use zastava_lib::proxy::upstream::connect_via_route_with_chained;
use zastava_lib::proxy::{HoldQueue, ProxyServer};
use zastava_lib::routing::{Entry, EntryProto, Route};
use zastava_lib::state::AppState;

fn route_with_entries(id: &str, entries: Vec<Entry>) -> Route {
    let raw_key = format!(
        "socks5://127.0.0.1:{}",
        entries.first().map(|e| e.port).unwrap_or(1080)
    );
    Route {
        id: id.to_string(),
        label: format!("test {id}"),
        country: Some("NL".to_string()),
        exit_ip: None,
        expires_at: None,
        entries,
        raw_key,
        enabled: true,
        added_at: 0,
    }
}

fn socks_entry(host: &str, port: u16) -> Entry {
    Entry {
        proto: EntryProto::Socks5,
        host: host.to_string(),
        port,
        username: None,
        password: None,
        sni: None,
    }
}

async fn spawn_socks_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut g = [0u8; 3];
                if s.read_exact(&mut g).await.is_err() {
                    return;
                }
                let _ = s.write_all(&[0x05, 0x00]).await;
                let mut head = [0u8; 4];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut len = [0u8; 1];
                if s.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut rest = vec![0u8; len[0] as usize + 2];
                if s.read_exact(&mut rest).await.is_err() {
                    return;
                }
                let _ = s
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn sec7_4_embedded_rules_block_mass_vpn_even_when_pinned_and_classify_ipv6() {
    let auditor = Auditor::new().expect("auditor loads embedded dangerous_asns.json");
    let asns = auditor.rules.dangerous_asns.read().await.clone();

    // 1. Mass VPN ASNs (including Cloudflare WARP AS13335, M247 AS9009, NordVPN AS136787) and VPN ISP keywords
    // must ALWAYS return Warning HIGH_RISK_MASS_VPN_ASN even if is_pinned=true.
    for (ip, asn, isp, org) in [
        ("104.28.1.10", Some(13335), Some("Cloudflare, Inc."), Some("Cloudflare WARP")),
        ("185.220.101.4", Some(9009), Some("M247 Europe SRL"), Some("M247 Ltd")),
        ("194.36.25.8", Some(136787), Some("TEFINCOM S.A."), Some("NordVPN")),
        ("91.90.44.12", Some(999999), Some("ProtonVPN AG"), Some("ProtonVPN")),
    ] {
        let res = evaluate_ip_reputation(
            &ExitIdentity {
                ip,
                country_code: "NL",
                asn,
                isp,
                org,
            },
            &asns,
            TorLookup::NotListed,
            true,
        );
        assert_eq!(
            res.status,
            CheckStatus::Warning,
            "pinned VPN exit ({ip}, {asn:?}, {isp:?}) must never be masked as ASN_VERIFIED_PINNED"
        );
        assert_eq!(res.code, "HIGH_RISK_MASS_VPN_ASN");
    }

    // 2. Clean pinned exit still gets ASN_VERIFIED_PINNED.
    let clean_pinned = evaluate_ip_reputation(
        &ExitIdentity {
            ip: "198.51.100.10",
            country_code: "NL",
            asn: Some(65001),
            isp: Some("Clean Private Fiber"),
            org: Some("Clean Private Fiber"),
        },
        &asns,
        TorLookup::NotListed,
        true,
    );
    assert_eq!(clean_pinned.status, CheckStatus::Ok);
    assert_eq!(clean_pinned.code, "ASN_VERIFIED_PINNED");

    // 3. IPv6 with TorLookup::NotApplicable continues into hosting/residential classification.
    let ipv6_hosting = evaluate_ip_reputation(
        &ExitIdentity {
            ip: "2a01:4f8:c0c::1",
            country_code: "DE",
            asn: Some(24940),
            isp: Some("Hetzner Online GmbH"),
            org: Some("Hetzner Online GmbH"),
        },
        &asns,
        TorLookup::NotApplicable,
        false,
    );
    assert_eq!(ipv6_hosting.code, "IP_TYPE_HOSTING");

    let ipv6_clean = evaluate_ip_reputation(
        &ExitIdentity {
            ip: "2001:db8:85a3::1",
            country_code: "NL",
            asn: Some(65001),
            isp: Some("KPN B.V."),
            org: Some("KPN B.V."),
        },
        &asns,
        TorLookup::NotApplicable,
        false,
    );
    assert_eq!(ipv6_clean.code, "ASN_CLEAN");
}

#[tokio::test]
async fn sec7_5_staggered_multi_entry_recovers_fast_when_first_entry_hangs() {
    // Entry #1 accepts TCP connections and silently stalls without SOCKS5 greeting reply.
    let stall_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stall_port = stall_listener.local_addr().unwrap().port();
    let _stall_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = stall_listener.accept().await {
            held.push(s);
        }
    });

    // Entry #2 is a healthy SOCKS5 server.
    let good_port = spawn_socks_echo().await;
    let route = route_with_entries(
        "multi",
        vec![
            socks_entry("127.0.0.1", stall_port),
            socks_entry("127.0.0.1", good_port),
        ],
    );

    let start = Instant::now();
    let mut stream = connect_via_route_with_chained(
        &route,
        "api.anthropic.com",
        443,
        Duration::from_secs(5),
        0,
        None,
    )
    .await
    .expect("staggered start must win via entry #2 before entry #1 5s timeout");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "staggered failover took {:?}, expected <3s",
        start.elapsed()
    );

    stream.write_all(b"STAGGER_OK").await.unwrap();
    let mut buf = [0u8; 10];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"STAGGER_OK");
}

#[tokio::test]
async fn sec7_5_http_connect_bufreader_preserves_pipelined_payload() {
    // Mock HTTP entry proxy returning 200 Connection Established + early server bytes in one packet.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut req = [0u8; 512];
            let _ = s.read(&mut req).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\nEARLY_BYTES")
                .await;
            let mut buf = [0u8; 64];
            if let Ok(n) = s.read(&mut buf).await {
                let _ = s.write_all(&buf[..n]).await;
            }
        }
    });

    let route = route_with_entries(
        "http-pipelined",
        vec![Entry {
            proto: EntryProto::Http,
            host: "127.0.0.1".to_string(),
            port,
            username: None,
            password: None,
            sni: None,
        }],
    );

    let mut stream = connect_via_route_with_chained(
        &route,
        "api.openai.com",
        443,
        Duration::from_secs(5),
        0,
        None,
    )
    .await
    .expect("HTTP CONNECT should succeed");

    let mut prefix = [0u8; 11];
    stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"EARLY_BYTES");
    stream.write_all(b"REST").await.unwrap();
    let mut tail = [0u8; 4];
    stream.read_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"REST");
}

#[tokio::test]
async fn sec7_5_live_route_soft_bypasses_geo_timeout_without_marking_unreachable() {
    let socks_port = spawn_socks_echo().await;
    let state = AppState::new_in_memory();
    let route = route_with_entries("live-vpn", vec![socks_entry("127.0.0.1", socks_port)]);
    state.upsert_route(route).await.unwrap();
    state
        .bind_provider_route("anthropic", Some("live-vpn"))
        .await
        .unwrap();
    // Simulate a route that passed its tunnel check and is live while GeoIP lookup hits a blip.
    state.route_health().mark_reachable("live-vpn");

    let auditor = Auditor::new().unwrap();
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor, state.clone(), Arc::new(HoldQueue::new()), None)
            .await
            .unwrap(),
    );
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.run().await });

    let mut client = match tokio::net::TcpStream::connect(server.bound_addr).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("connect to gateway: {e}"),
    };
    client
        .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        .await
        .unwrap();

    let mut resp = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(15), client.read(&mut resp))
        .await
        .expect("gateway response")
        .unwrap();
    let head = String::from_utf8_lossy(&resp[..n]);
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "expected soft-bypass 200 Connection Established on live route, got: {head}"
    );
    assert!(
        state
            .route_health()
            .get("live-vpn")
            .is_some_and(|h| h.reachable == Some(true)),
        "live route must NOT be marked unreachable on transient GeoIP audit failure"
    );

    client.write_all(b"LIVE_TUNNEL").await.unwrap();
    let mut echo = [0u8; 11];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"LIVE_TUNNEL");
}

#[tokio::test]
async fn sec7_6_session_allowance_never_auto_persists_trusted_exceptions() {
    let state = AppState::new_in_memory();
    state.allow_provider_for_session("openai").await.unwrap();
    let data = state.get_data().await;
    assert!(data.session_allowed_providers.iter().any(|p| p == "openai"));
    assert!(
        data.trusted_exceptions.is_empty(),
        "ephemeral session allowance must never mutate trusted_exceptions"
    );
}
