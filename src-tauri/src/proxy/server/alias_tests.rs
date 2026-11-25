use super::*;
use crate::auditor::network::current_timestamp;
use crate::routing::{Entry, EntryProto};
use crate::state::AppState;

fn sample_route(id: &str) -> Route {
    let now = current_timestamp();
    Route {
        id: id.to_string(),
        label: "NL Primary".to_string(),
        country: Some("NL".to_string()),
        exit_ip: Some("185.220.10.50".to_string()),
        expires_at: Some(now + 3_600),
        sub_url: Some("https://sub.example.net/k1".to_string()),
        grace_extended: false,
        entries: vec![Entry {
            proto: EntryProto::Socks5,
            host: "198.51.100.10".to_string(),
            port: 1080,
            username: Some("u".to_string()),
            password: Some("p".to_string()),
            sni: None,
        }],
        raw_key: "socks5://u:p@198.51.100.10:1080".to_string(),
        enabled: true,
        added_at: now - 60,
    }
}

#[tokio::test]
async fn alias_route_is_stale_survives_metadata_refresh_and_aborts_on_transport_or_usability_change()
 {
    let state = AppState::new_in_memory();
    let baseline = sample_route("alias-r1");
    state.upsert_route(baseline.clone()).await.unwrap();

    assert!(
        !alias_route_is_stale(&state, &baseline).await,
        "identical usable route should not be stale"
    );

    // Metadata-only refresh (label / expires_at / grace_extended / exit_ip / country)
    // must keep active alias tunnels alive.
    let mut metadata_refreshed = baseline.clone();
    metadata_refreshed.label = "NL Primary (Renewed)".to_string();
    metadata_refreshed.expires_at = Some(current_timestamp() + 86_400);
    metadata_refreshed.grace_extended = true;
    metadata_refreshed.country = Some("DE".to_string());
    metadata_refreshed.exit_ip = Some("185.220.10.51".to_string());
    state.upsert_route(metadata_refreshed).await.unwrap();
    assert!(
        !alias_route_is_stale(&state, &baseline).await,
        "metadata-only refresh must not abort live alias tunnel"
    );

    // Transport entry change (port/host/credentials) must mark stale immediately.
    let mut entry_changed = baseline.clone();
    entry_changed.entries[0].port = 1081;
    state.upsert_route(entry_changed).await.unwrap();
    assert!(
        alias_route_is_stale(&state, &baseline).await,
        "entry change must mark alias route stale"
    );

    // Local-entry policy change (`allows_local_entries()` via raw_key) must mark stale.
    let mut local_policy_changed = baseline.clone();
    local_policy_changed.raw_key = "zastava://token-198-51-100-10".to_string();
    state.upsert_route(local_policy_changed).await.unwrap();
    assert!(
        alias_route_is_stale(&state, &baseline).await,
        "allows_local_entries policy change must mark alias route stale"
    );

    // Disabling the route must mark stale.
    state.set_route_enabled(&baseline.id, false).await.unwrap();
    assert!(
        alias_route_is_stale(&state, &baseline).await,
        "disabled route must mark alias route stale"
    );

    // Expiring the route must mark stale.
    state.set_route_enabled(&baseline.id, true).await.unwrap();
    let mut expired = baseline.clone();
    expired.expires_at = Some(current_timestamp() - 10);
    state.upsert_route(expired).await.unwrap();
    assert!(
        alias_route_is_stale(&state, &baseline).await,
        "expired route must mark alias route stale"
    );

    // Removing the route must mark stale.
    state.remove_route(&baseline.id).await.unwrap();
    assert!(
        alias_route_is_stale(&state, &baseline).await,
        "missing route must mark alias route stale"
    );
}

#[tokio::test]
async fn gemini_clean_room_alias_attributes_non_ai_route_failure_to_gemini() {
    use crate::auditor::Auditor;
    use crate::proxy::hold_queue::HoldQueue;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    crate::sysproxy::force_os_dry_run();
    let state = AppState::new_in_memory();
    let mut route = sample_route("gemini-alias-down-1");
    route.enabled = false;
    state.upsert_route(route).await.unwrap();

    let server = Arc::new(
        ProxyServer::bind_ephemeral(
            Auditor::new().unwrap(),
            state.clone(),
            Arc::new(HoldQueue::new()),
            None,
        )
        .await
        .unwrap(),
    );
    let alias = Arc::new(
        server
            .bind_alias_on(
                Some("gemini-alias-down-1".to_string()),
                Some(ProviderId::Gemini),
                None,
                None,
            )
            .await
            .unwrap(),
    );
    let alias_addr = alias.bound_addr;
    let alias_task = tokio::spawn(async move { alias.run().await });

    let mut client = TcpStream::connect(alias_addr).await.unwrap();
    client
        .write_all(b"CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(
        resp.contains("gemini"),
        "non-AI Chrome subresource failure inside Gemini Clean Room must blame gemini, got: {resp}"
    );
    assert!(
        !resp.contains("anthropic"),
        "must NEVER blame anthropic: {resp}"
    );

    let snap = state.stats().snapshot().await;
    let ev = snap
        .recent_events
        .iter()
        .find(|e| {
            e.host == "www.google.com" && e.action == crate::proxy::server::VERDICT_ROUTE_DOWN
        })
        .expect("expected ROUTE_DOWN stats event for www.google.com");
    assert_eq!(ev.provider, "gemini");

    let diag = crate::diagnostics::dump();
    assert!(
        diag.iter()
            .any(|l| l.contains("route=gemini-alias-down-1") && l.contains("provider=gemini")),
        "expected provider=gemini in diagnostics: {diag:?}"
    );
    assert!(
        !diag
            .iter()
            .any(|l| l.contains("route=gemini-alias-down-1") && l.contains("provider=anthropic")),
        "must not blame anthropic in diagnostics: {diag:?}"
    );

    alias_task.abort();
}
