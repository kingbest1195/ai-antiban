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
    assert_eq!(
        st1.pinned_ips.get("default").map(String::as_str),
        Some("2.2.2.2")
    );

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
    assert_eq!(
        st2.pinned_ips.get("default").map(String::as_str),
        Some("2.2.2.2")
    );
}

#[test]
fn enable_default_protection_skips_sysproxy_and_cli_when_shutdown_started() {
    let _lock = startup::GLOBAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    startup::reset_global_for_test();

    // Case 1: shutdown started before enable_sysproxy -> neither step runs.
    startup::note_shutdown_global();
    let calls = std::cell::RefCell::new(Vec::new());
    run_default_protection_with(
        startup::is_shutting_down_global,
        || calls.borrow_mut().push("sys"),
        || calls.borrow_mut().push("cli"),
    );
    assert!(calls.borrow().is_empty());

    // Case 2: shutdown begins during enable_sysproxy -> cli step is cancelled.
    startup::reset_global_for_test();
    let calls2 = std::cell::RefCell::new(Vec::new());
    run_default_protection_with(
        startup::is_shutting_down_global,
        || {
            calls2.borrow_mut().push("sys");
            startup::note_shutdown_global();
        },
        || calls2.borrow_mut().push("cli"),
    );
    assert_eq!(*calls2.borrow(), vec!["sys"]);
    startup::reset_global_for_test();
}
