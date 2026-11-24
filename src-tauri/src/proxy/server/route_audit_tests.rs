use super::*;
use crate::auditor::seams::fakes::{FakeDns, FakeProbe, FakeSystem, FakeUdp};
use crate::auditor::seams::{AuditEnv, HttpProbeOutcome, LookupOutcome};
use crate::auditor::{AuditProtectionFlags, NetworkTelemetry};
use crate::routing::{Entry, EntryProto};

fn test_route(id: &str) -> Route {
    Route {
        id: id.to_string(),
        label: format!("test-{id}"),
        country: Some("NL".to_string()),
        exit_ip: None,
        expires_at: None,
        sub_url: None,
        grace_extended: false,
        entries: vec![Entry {
            proto: EntryProto::Socks5,
            host: "127.0.0.1".to_string(),
            port: 1080,
            username: None,
            password: None,
            sni: None,
        }],
        raw_key: "socks5://127.0.0.1:1080".to_string(),
        enabled: true,
        added_at: 0,
    }
}

#[tokio::test(start_paused = true)]
async fn bg_geoip_failure_preserves_grace_report_without_marking_unreachable() {
    let state = AppState::new_in_memory();
    let route = test_route("nl-grace");
    state.upsert_route(route.clone()).await.unwrap();
    state
        .bind_provider_route("anthropic", Some(&route.id))
        .await
        .unwrap();

    let env = AuditEnv {
        dns: Arc::new(FakeDns::new(LookupOutcome::Timeout)),
        probe: Arc::new(FakeProbe::new(HttpProbeOutcome::Timeout)),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem::healthy()),
    };
    let auditor = Auditor::with_env(env).unwrap();
    auditor.set_protection_flags(AuditProtectionFlags {
        sysproxy_active: true,
        cli_or_sandbox_protection_active: true,
        os_pac_deferred: false,
    });
    auditor
        .resolver
        .set_cached_for_route(
            Some(route.id.clone()),
            NetworkTelemetry {
                ip: "185.220.10.50".to_string(),
                country_code: "NL".to_string(),
                hostname: Some("nl-vps.example.net".to_string()),
                asn: Some(20473),
                org: Some("Choopa".to_string()),
                isp: Some("Choopa".to_string()),
                timezone: Some("Europe/Amsterdam".to_string()),
                resolved_at: crate::auditor::network::current_timestamp(),
            },
        )
        .await;

    let cache = Arc::new(RouteReportCache::default());
    let selection = RouteSelection::Route(route.clone());
    let first = cache
        .get_or_evaluate(&auditor, &state, ProviderId::Anthropic, &route, &selection)
        .await
        .expect("initial evaluation with cached telemetry must succeed");
    assert!(!first.from_cache);

    // Force cached telemetry to expire so the background refresh actually hits GeoIP and fails.
    auditor
        .resolver
        .set_cached_for_route(
            Some(route.id.clone()),
            NetworkTelemetry {
                ip: "185.220.10.50".to_string(),
                country_code: "NL".to_string(),
                hostname: Some("nl-vps.example.net".to_string()),
                asn: Some(20473),
                org: Some("Choopa".to_string()),
                isp: Some("Choopa".to_string()),
                timezone: Some("Europe/Amsterdam".to_string()),
                resolved_at: 1,
            },
        )
        .await;
    // Advance past bg-refresh threshold (30s) and fresh TTL (60s), still inside grace TTL (600s).
    tokio::time::advance(Duration::from_secs(65)).await;

    let second = cache
        .get_or_evaluate(&auditor, &state, ProviderId::Anthropic, &route, &selection)
        .await
        .expect("grace TTL must serve last valid RiskReport while bg refresh runs");
    assert!(second.from_cache);

    // Let the spawned background refresh finish failing.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // Route health must NOT be poisoned with reachable = Some(false).
    assert_ne!(
        state
            .route_health()
            .get(&route.id)
            .and_then(|h| h.reachable),
        Some(false)
    );
    // Subsequent auxiliary CONNECTs within grace TTL must still succeed from cache.
    let third = cache
        .get_or_evaluate(&auditor, &state, ProviderId::Anthropic, &route, &selection)
        .await
        .expect("cached report must survive failed bg GeoIP refresh");
    assert!(third.from_cache);
}
