use super::super::*;
use super::coverage_and_holds_tests::offline_test_auditor;
use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::hold_queue::HoldQueue;
use crate::proxy::upstream::connect_via_route_with_chained;
use crate::routing::{Entry, EntryProto, Route, RouteDownReason};
use crate::state::AppState;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn proxy_route_diagnostic_logs_are_rate_limited_for_repeated_errors() {
    crate::sysproxy::force_os_dry_run();

    // 1. Empty-entries route repeated 15x logs at most once within 5s.
    let empty_route = Route {
        id: "throttle-empty-unique-1".to_string(),
        label: "Empty".to_string(),
        country: None,
        exit_ip: None,
        expires_at: None,
        sub_url: None,
        grace_extended: false,
        entries: vec![],
        raw_key: String::new(),
        enabled: true,
        added_at: 0,
    };
    for _ in 0..15 {
        let _ = connect_via_route_with_chained(
            &empty_route,
            "api.anthropic.com",
            443,
            Duration::from_millis(200),
            0,
            None,
        )
        .await;
    }

    // 2. Unreachable entry route repeated 15x logs phase & summary at most once per key within 5s.
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);
    let dead_route = Route {
        id: "throttle-dead-unique-1".to_string(),
        label: "Dead".to_string(),
        country: None,
        exit_ip: None,
        expires_at: None,
        sub_url: None,
        grace_extended: false,
        entries: vec![Entry {
            proto: EntryProto::Socks5,
            host: "127.0.0.1".to_string(),
            port: dead_port,
            username: None,
            password: None,
            sni: None,
        }],
        raw_key: format!("socks5://127.0.0.1:{dead_port}"),
        enabled: true,
        added_at: 0,
    };
    for _ in 0..15 {
        let _ = connect_via_route_with_chained(
            &dead_route,
            "api.anthropic.com",
            443,
            Duration::from_millis(300),
            0,
            None,
        )
        .await;
    }

    // 3. refuse_route_down repeated 15x logs at most once per (route_id, provider, reason) within 5s.
    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            offline_test_auditor(),
            AppState::new_in_memory(),
            Arc::new(HoldQueue::new()),
            None,
        )
        .await
        .unwrap(),
    );
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = sink.accept().await {
            let _ = s.shutdown().await;
        }
    });
    for _ in 0..15 {
        let mut client = TcpStream::connect(sink_addr).await.unwrap();
        let _ = server
            .refuse_route_down(
                &mut client,
                "api.anthropic.com",
                ProviderId::Gemini,
                "throttle-refuse-unique-1",
                RouteDownReason::Disabled,
                None,
                false,
            )
            .await;
    }

    let dump = crate::diagnostics::dump();
    let empty_hits = dump
        .iter()
        .filter(|l| l.contains("[proxy:route]") && l.contains("route=throttle-empty-unique-1"))
        .count();
    let dead_phase_hits = dump
        .iter()
        .filter(|l| {
            l.contains("[proxy:route]")
                && l.contains("route=throttle-dead-unique-1")
                && l.contains("phase=")
        })
        .count();
    let dead_summary_hits = dump
        .iter()
        .filter(|l| {
            l.contains("[proxy:route]")
                && l.contains("route=throttle-dead-unique-1")
                && l.contains("all entry nodes failed")
        })
        .count();
    let refuse_hits = dump
        .iter()
        .filter(|l| {
            l.contains("[proxy:route]")
                && l.contains("refuse_route_down route=throttle-refuse-unique-1")
        })
        .count();

    assert_eq!(empty_hits, 1, "empty route log must be throttled: {dump:?}");
    assert!(
        dead_phase_hits <= 1,
        "entry phase log must be throttled to <=1, got {dead_phase_hits}: {dump:?}"
    );
    assert_eq!(
        dead_summary_hits, 1,
        "route summary log must be throttled: {dump:?}"
    );
    assert_eq!(
        refuse_hits, 1,
        "refuse_route_down log must be throttled: {dump:?}"
    );
}
