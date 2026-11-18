use super::*;

#[tokio::test]
async fn reconcile_active_profile_clears_stale_anthropic_pin_even_when_route_matches() {
    let app_state = state::AppState::new_in_memory();
    let route = crate::routing::parse_route_key("socks5://1.2.3.4:1080#nl", 1).unwrap();
    let route_id = route.id.clone();
    let raw_key = route.raw_key.clone();
    app_state.apply_profile_route(route).await.unwrap();
    app_state
        .set_pinned_ip_for(state::PROVIDER_ANTHROPIC, Some("9.9.9.9".to_string()))
        .await
        .unwrap();
    app_state
        .set_pinned_ip_for("default", Some("2.2.2.2".to_string()))
        .await
        .unwrap();

    // Active profile has matching bound_route_id and bound_ip = None -> stale anthropic pin
    // must still be cleared while preserving "default".
    reconcile_active_profile_binding_async(
        &app_state,
        auditor::profile_switcher::ActiveProfileBindingState {
            profile_id: "p1".to_string(),
            bound_ip: None,
            bound_upstream_key: Some(raw_key.clone()),
            bound_route_id: Some(route_id.clone()),
        },
    )
    .await;
    let st1 = app_state.get_data().await;
    assert!(!st1.pinned_ips.contains_key(state::PROVIDER_ANTHROPIC));
    assert_eq!(st1.pinned_ips.get("default").map(String::as_str), Some("2.2.2.2"));

    // Active profile sets bound_ip while route still matches -> anthropic pin updated cleanly.
    reconcile_active_profile_binding_async(
        &app_state,
        auditor::profile_switcher::ActiveProfileBindingState {
            profile_id: "p1".to_string(),
            bound_ip: Some("1.2.3.4".to_string()),
            bound_upstream_key: Some(raw_key),
            bound_route_id: Some(route_id),
        },
    )
    .await;
    let st2 = app_state.get_data().await;
    assert_eq!(
        st2.pinned_ips
            .get(state::PROVIDER_ANTHROPIC)
            .map(String::as_str),
        Some("1.2.3.4")
    );
    assert_eq!(st2.pinned_ips.get("default").map(String::as_str), Some("2.2.2.2"));
}
