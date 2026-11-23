//! End-to-end tests for §7.2 (subscription refresh, grace extension, deduplication, v3.1.1 compat).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zastava_lib::commands::routes_sub::{
    parse_subscription_response, parse_subscription_userinfo_expire,
    refresh_route_subscription_inner,
};
use zastava_lib::routing::{
    RouteDownReason, RouteSelection, RouteStatus, compute_status, parse_route_key,
};
use zastava_lib::state::AppState;

fn zkey(json: &str) -> String {
    format!("zastava://{}", URL_SAFE_NO_PAD.encode(json.as_bytes()))
}

async fn spawn_mock_sub_server(
    headers: String,
    body: String,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (format!("http://{addr}/sub"), handle)
}

#[tokio::test]
async fn subscription_refresh_updates_expiry_via_userinfo_header_and_key_json() {
    let dir = TempDir::new().unwrap();
    let state = AppState::load_or_default(dir.path().join("state.json"));
    let now = 1_700_000_000u64;
    let expired_ts = now - 3600;
    let renewed_ts = now + 30 * 86_400;

    let initial_key = zkey(&format!(
        r#"{{"v":2,"id":"sub-key-1","label":"NL Sub","expires_at":{expired_ts},"sub_url":"https://sub.example.net/1","entry":[{{"proto":"https","host":"entry1.example.net","port":443}}]}}"#
    ));
    let route = parse_route_key(&initial_key, now).unwrap();
    let id = state.upsert_route(route).await.unwrap();
    assert_eq!(
        compute_status(&state.get_route(&id).await.unwrap(), None, now),
        RouteStatus::Expired
    );

    // 1) Mock endpoint returning `subscription-userinfo: expire=<future>` header.
    let (url1, h1) = spawn_mock_sub_server(
        format!("subscription-userinfo: upload=0; download=0; total=100; expire={renewed_ts}\r\n"),
        String::new(),
    )
    .await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let changed = refresh_route_subscription_inner(&state, &id, Some(&client), Some(&url1))
        .await
        .unwrap();
    assert!(changed);
    let _ = h1.await;

    let updated = state.get_route(&id).await.unwrap();
    assert_eq!(updated.expires_at, Some(renewed_ts));
    assert_eq!(compute_status(&updated, None, now), RouteStatus::Active);

    // 2) Mock endpoint returning updated KeyV2 JSON payload with a newer expiry & entry port.
    let newer_ts = renewed_ts + 86_400;
    let key_json = format!(
        r#"{{"v":2,"id":"sub-key-1","label":"NL Sub Renewed","expires_at":{newer_ts},"sub_url":"https://sub.example.net/1","entry":[{{"proto":"https","host":"entry2.example.net","port":8443}}]}}"#
    );
    let (url2, h2) =
        spawn_mock_sub_server("Content-Type: application/json\r\n".into(), key_json).await;
    let changed2 = refresh_route_subscription_inner(&state, &id, Some(&client), Some(&url2))
        .await
        .unwrap();
    assert!(changed2);
    let _ = h2.await;

    let updated2 = state.get_route(&id).await.unwrap();
    assert_eq!(updated2.expires_at, Some(newer_ts));
    assert_eq!(updated2.entries[0].host, "entry2.example.net");
    assert_eq!(updated2.entries[0].port, 8443);
    assert_eq!(
        parse_subscription_userinfo_expire("upload=1; expire=1800000123"),
        Some(1800000123)
    );
    assert!(parse_subscription_response(Some(1800000123), "", now).is_ok());
}

#[tokio::test]
async fn legacy_expired_key_without_sub_url_unlocks_via_grace_extension_and_persists() {
    let dir = TempDir::new().unwrap();
    let state_path = dir.path().join("state.json");
    let state = AppState::load_or_default(state_path.clone());
    let now = 1_700_000_000u64;

    let old_key = zkey(&format!(
        r#"{{"v":2,"id":"legacy-grace","label":"Legacy NL","expires_at":{},"entry":[{{"proto":"socks5","host":"185.20.20.2","port":1080}}]}}"#,
        now - 100
    ));
    let route = parse_route_key(&old_key, now).unwrap();
    let id = state.upsert_route(route).await.unwrap();

    let r0 = state.get_route(&id).await.unwrap();
    assert_eq!(r0.check_usable(now), Err(RouteDownReason::Expired));
    assert_eq!(compute_status(&r0, None, now), RouteStatus::Expired);

    // Live handshake succeeds -> test_route sets grace_extended = true.
    assert!(state.mark_route_grace_extended(&id, true).await.unwrap());
    let r1 = state.get_route(&id).await.unwrap();
    assert!(r1.grace_extended);
    assert!(r1.check_usable(now).is_ok());
    assert_eq!(compute_status(&r1, None, now), RouteStatus::Active);

    // Persists across state.json reload.
    let reloaded = AppState::load_or_default(state_path);
    let r2 = reloaded.get_route(&id).await.unwrap();
    assert!(r2.grace_extended);
    assert_eq!(compute_status(&r2, None, now), RouteStatus::Active);
}

#[tokio::test]
async fn reimporting_renewed_key_without_id_updates_in_place_preserving_bindings() {
    let dir = TempDir::new().unwrap();
    let state = AppState::load_or_default(dir.path().join("state.json"));
    let now = 1_700_000_000u64;

    let key_old = zkey(&format!(
        r#"{{"v":2,"label":"Worker NL","expires_at":{},"entry":[{{"proto":"https","host":"n1.example.net","port":443,"username":"u1","password":"p1"}},{{"proto":"socks5","host":"n2.example.net","port":1080}}]}}"#,
        now - 60
    ));
    let id1 = state
        .upsert_route(parse_route_key(&key_old, now).unwrap())
        .await
        .unwrap();
    state.set_default_route(Some(&id1)).await.unwrap();
    state
        .bind_provider_route("openai", Some(&id1))
        .await
        .unwrap();
    state.set_profile_route(Some(id1.clone())).await.unwrap();

    // Renewed key omits `id`, reorders entries, adds `sub_url`, and extends `expires_at`.
    let future = now + 86_400 * 30;
    let key_renewed = zkey(&format!(
        r#"{{"v":2,"label":"Worker NL Renewed","expires_at":{future},"sub_url":"https://sub.example.net/renew","entry":[{{"proto":"socks5","host":"n2.example.net","port":1080}},{{"proto":"https","host":"N1.EXAMPLE.NET","port":443,"username":"u1","password":"p1"}}]}}"#
    ));
    let id2 = state
        .upsert_route(parse_route_key(&key_renewed, now + 10).unwrap())
        .await
        .unwrap();

    assert_eq!(
        id2, id1,
        "must reuse existing route id without creating a duplicate"
    );
    let routes = state.get_routes().await;
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].expires_at, Some(future));
    assert_eq!(
        routes[0].sub_url.as_deref(),
        Some("https://sub.example.net/renew")
    );
    assert_eq!(routes[0].raw_key, key_renewed);
    assert_eq!(compute_status(&routes[0], None, now), RouteStatus::Active);

    // Bindings remain intact.
    let data = state.get_data().await;
    assert_eq!(data.default_route_id.as_deref(), Some(id1.as_str()));
    assert_eq!(data.profile_route_id.as_deref(), Some(id1.as_str()));
    assert_eq!(
        data.provider_routes.get("openai").map(String::as_str),
        Some(id1.as_str())
    );
    assert!(matches!(
        state.route_selection("openai").await,
        RouteSelection::Route(_)
    ));
}

#[test]
fn v311_state_json_without_new_route_fields_loads_cleanly() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let raw = r#"{
      "schema_version": 3,
      "routes": [{
        "id": "r-legacy",
        "label": "NL",
        "entries": [{"proto":"socks5","host":"185.10.10.2","port":1080}],
        "raw_key": "socks5://185.10.10.2:1080",
        "enabled": true,
        "added_at": 1
      }]
    }"#;
    std::fs::write(&path, raw).unwrap();
    let state = AppState::load_or_default(path);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let routes = rt.block_on(state.get_routes());
    assert_eq!(routes.len(), 1);
    assert!(routes[0].sub_url.is_none());
    assert!(!routes[0].grace_extended);
}
