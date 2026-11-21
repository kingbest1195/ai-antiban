use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use zastava_lib::auditor::AuditProtectionContext;
use zastava_lib::auditor::cache::TtlCache;
use zastava_lib::auditor::probes::whoami::{
    AKAMAI_HOST, GOOGLE_TXT_HOST, evaluate_dns_country_for_route_with_protection, measure_resolver,
};
use zastava_lib::auditor::seams::fakes::{FakeDns, FakeProbe, addr};
use zastava_lib::auditor::seams::{HttpProbeOutcome, LookupOutcome, TxtOutcome};
use zastava_lib::proxy::Transit;
use zastava_lib::routing::net::test_support::resolve_entry_checked_with_closures;
use zastava_lib::routing::{Entry, EntryProto};
use zastava_lib::sysproxy::fs::{FakeFs, Fs, WriteMode};
use zastava_lib::sysproxy::platform::{ChainState, FakePlatform, ProxyEndpoint, ServiceId};
use zastava_lib::sysproxy::test_support::{
    TestHealGuard, apply_browser_policies_for_os, enable_macos_pac,
    open_journal_with_fake_policies, refresh_macos_pac,
};
use zastava_lib::sysproxy::{get_chained_proxy, is_os_pac_deferred};

use crate::harness::{MockEchoTarget, acquire_global_state};

fn wifi() -> ServiceId {
    ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
}

#[tokio::test]
async fn e2e_tun_temp_dns_macos_os_pac_deferred_still_detects_upstream_and_dns_isolated() {
    let _g = acquire_global_state().await;
    let pac_url = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let chrome_default = Path::new("/fake-home/Library/Application Support/Google/Chrome/Default");
    fs.create_private_dir_all(chrome_default).unwrap();
    fs.write_atomic(
        &chrome_default.join("Preferences"),
        b"{}",
        WriteMode::Private,
    )
    .unwrap();
    let plat = FakePlatform::new();
    plat.add_service(wifi());
    plat.set_temp_dns(true);
    plat.seed_chain(
        &wifi(),
        ChainState {
            http: ProxyEndpoint {
                enabled: Some(true),
                server: Some("127.0.0.1".into()),
                port: Some(10809),
                authenticated: Some(false),
            },
            https: ProxyEndpoint {
                enabled: Some(true),
                server: Some("127.0.0.1".into()),
                port: Some(10809),
                authenticated: Some(false),
            },
            socks: ProxyEndpoint::default(),
        },
    );

    let mut j = open_journal_with_fake_policies(fs, Path::new("/tun-deferred")).unwrap();
    let rep = enable_macos_pac(&mut j, &plat, pac_url).unwrap();
    assert!(rep.os_pac_deferred, "temp_dns ON must defer OS PAC writes");
    assert!(is_os_pac_deferred());
    assert_eq!(
        plat.os_writes(),
        0,
        "networksetup must remain untouched when temp_dns is active"
    );
    assert_eq!(
        get_chained_proxy().as_deref(),
        Some("http://127.0.0.1:10809"),
        "read-only upstream detection must still work while os_pac_deferred is true"
    );

    // Browser managed PAC / Clean Room alias keeps zastava_dns_isolated() == true
    let policy_rep = apply_browser_policies_for_os(&mut j, &plat, Some(pac_url), true);
    assert!(policy_rep.pac_policy_active);
    let protection = AuditProtectionContext {
        route_usable: true,
        sysproxy_active: true,
        cli_or_sandbox_protection_active: policy_rep.pac_policy_active,
        os_pac_deferred: true,
    };
    assert!(
        protection.zastava_dns_isolated(),
        "Chromium managed PAC / Clean Room keeps AI DNS isolated despite os_pac_deferred"
    );

    // Turning temp_dns OFF dynamically clears os_pac_deferred and configures Wi-Fi PAC
    plat.set_temp_dns(false);
    let heal = TestHealGuard::new();
    let rep2 = refresh_macos_pac(&mut j, &plat, pac_url, &heal, Instant::now()).unwrap();
    assert!(!rep2.os_pac_deferred);
    assert!(!is_os_pac_deferred());
    assert!(rep2.changed);
    assert_eq!(plat.pac_of(&wifi()).url.as_deref(), Some(pac_url));
}

#[tokio::test]
async fn e2e_tun_fake_ip_v4_and_v6_resolution_and_verdict() {
    let _g = acquire_global_state().await;
    let entry = Entry {
        proto: EntryProto::Https,
        host: "node.zastava.test".into(),
        port: 443,
        username: None,
        password: None,
        sni: None,
    };

    // 1. Fake-IPv4 (198.18.0.5) overridden by real public IP (8.8.4.4) from DoH/fallback
    let resolved_real = resolve_entry_checked_with_closures(
        &entry,
        false,
        8899,
        |_, p, _| {
            Ok(vec![
                format!("198.18.0.5:{p}").parse::<SocketAddr>().unwrap(),
            ])
        },
        |_, p| Ok(vec![format!("8.8.4.4:{p}").parse::<SocketAddr>().unwrap()]),
    )
    .await
    .unwrap();
    assert_eq!(
        resolved_real,
        vec!["8.8.4.4:443".parse::<SocketAddr>().unwrap()],
        "real public IP from DoH must beat TUN Fake-IPv4"
    );

    // 2. Fake-IPv6 (fc00::5) overridden by real public IP when DoH works
    let resolved_real_v6 = resolve_entry_checked_with_closures(
        &entry,
        false,
        8899,
        |_, p, _| {
            Ok(vec![
                format!("[fc00::5]:{p}").parse::<SocketAddr>().unwrap(),
            ])
        },
        |_, p| Ok(vec![format!("8.8.4.4:{p}").parse::<SocketAddr>().unwrap()]),
    )
    .await
    .unwrap();
    assert_eq!(
        resolved_real_v6,
        vec!["8.8.4.4:443".parse::<SocketAddr>().unwrap()]
    );

    // 3. When DoH/fallback is blocked, Fake-IPv4 and Fake-IPv6 are accepted as last resort
    let fallback_v4 = resolve_entry_checked_with_closures(
        &entry,
        false,
        8899,
        |_, p, _| {
            Ok(vec![
                format!("198.18.0.5:{p}").parse::<SocketAddr>().unwrap(),
            ])
        },
        |_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "doh blocked",
            ))
        },
    )
    .await
    .unwrap();
    assert_eq!(
        fallback_v4,
        vec!["198.18.0.5:443".parse::<SocketAddr>().unwrap()]
    );

    let fallback_v6 = resolve_entry_checked_with_closures(
        &entry,
        false,
        8899,
        |_, p, _| {
            Ok(vec![
                format!("[fc00::5]:{p}").parse::<SocketAddr>().unwrap(),
            ])
        },
        |_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "doh blocked",
            ))
        },
    )
    .await
    .unwrap();
    assert_eq!(
        fallback_v6,
        vec!["[fc00::5]:443".parse::<SocketAddr>().unwrap()]
    );

    // 4. LAN / loopback answers are strictly rejected (even if fallback fails)
    for bad in ["127.0.0.1", "192.168.1.10", "169.254.169.254"] {
        let err = resolve_entry_checked_with_closures(
            &entry,
            false,
            8899,
            move |_, p, _| Ok(vec![format!("{bad}:{p}").parse::<SocketAddr>().unwrap()]),
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "doh blocked",
                ))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    // 5. Whoami -> verdict.rs accurately prints fc00::/18 for IPv6 Fake-IP and 198.18.0.0/15 for IPv4
    let probe = FakeProbe::new(HttpProbeOutcome::Timeout);
    let geo_cache = TtlCache::default();

    let dns_v6 = FakeDns::new(LookupOutcome::NotFound)
        .with(AKAMAI_HOST, addr("fc00::1"))
        .with_txt(
            GOOGLE_TXT_HOST,
            TxtOutcome::Records(vec!["\"fc00::2\"".into()]),
        );
    let view_v6 = measure_resolver(&dns_v6, &probe, &geo_cache).await;
    let res_v6 = evaluate_dns_country_for_route_with_protection(
        &view_v6,
        "DE",
        true,
        AuditProtectionContext::assumed_active_for_route(),
    );
    assert_eq!(res_v6.code, "DNS_COUNTRY_FAKE_IP");
    assert!(
        res_v6.message.contains("fc00::/18"),
        "expected fc00::/18 in IPv6 Fake-IP verdict, got: {}",
        res_v6.message
    );

    let dns_v4 = FakeDns::new(LookupOutcome::NotFound)
        .with(AKAMAI_HOST, addr("198.18.0.1"))
        .with_txt(
            GOOGLE_TXT_HOST,
            TxtOutcome::Records(vec!["\"198.18.0.2\"".into()]),
        );
    let view_v4 = measure_resolver(&dns_v4, &probe, &geo_cache).await;
    let res_v4 = evaluate_dns_country_for_route_with_protection(
        &view_v4,
        "DE",
        true,
        AuditProtectionContext::assumed_active_for_route(),
    );
    assert_eq!(res_v4.code, "DNS_COUNTRY_FAKE_IP");
    assert!(
        res_v4.message.contains("198.18.0.0/15"),
        "expected 198.18.0.0/15 in IPv4 Fake-IP verdict, got: {}",
        res_v4.message
    );
}

#[tokio::test]
async fn e2e_tun_transit_fake_ip_allowed_while_ssrf_blocked() {
    let _g = acquire_global_state().await;
    let target = MockEchoTarget::spawn().await;
    let target_addr = target.addr;

    let transit_fake = Transit::with_backends(
        Arc::new(|_host| {
            Box::pin(async move { Ok(vec!["198.18.0.9".parse::<IpAddr>().unwrap()]) })
        }),
        Arc::new(move |_addr| {
            Box::pin(async move { tokio::net::TcpStream::connect(target_addr).await })
        }),
        Arc::new(Instant::now),
    );
    let mut stream = transit_fake
        .connect_direct("example.org", 443)
        .await
        .expect("Transit must allow TUN Fake-IP for hostname lookups");
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"fakeip")
        .await
        .unwrap();
    let mut echoed = [0u8; 6];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut echoed)
        .await
        .unwrap();
    assert_eq!(&echoed, b"fakeip");
    assert_eq!(target.connections.load(Ordering::SeqCst), 1);

    let transit_ssrf = Transit::with_backends(
        Arc::new(|_host| Box::pin(async move { Ok(vec!["127.0.0.1".parse::<IpAddr>().unwrap()]) })),
        Arc::new(move |_addr| {
            Box::pin(async move { tokio::net::TcpStream::connect(target_addr).await })
        }),
        Arc::new(Instant::now),
    );
    let err = transit_ssrf
        .connect_direct("evil.test", 443)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(target.connections.load(Ordering::SeqCst), 1);
}
