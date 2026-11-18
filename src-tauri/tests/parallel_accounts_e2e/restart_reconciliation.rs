use std::fs;

use tempfile::TempDir;

use zastava_lib::auditor::profile_switcher::{
    active_profile_binding_state_in, create_claude_profile_in, list_claude_profiles_in,
    mark_profiles_route_removed_in, switch_claude_profile_in_with_home, update_profile_bound_ip_in,
    update_profile_bound_upstream_in,
};
use zastava_lib::reconcile_active_profile_binding_async;
use zastava_lib::routing::{RouteSelection, parse_route_key, select_route};
use zastava_lib::state::{AppState, PROVIDER_ANTHROPIC};

#[tokio::test]
async fn e2e_scenario_5_restart_reconciliation_and_concurrency_resilience() {
    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state.json");
    let storage = tmp.path().join("profiles");
    let claude = tmp.path().join("Claude");

    let k1_raw = "socks5://127.0.0.1:19999#RestartKey";
    let k1_route = parse_route_key(k1_raw, 1).unwrap();
    let k1_id = k1_route.id.clone();

    // Pre-restart session: active Profile A bound to K1, trusted exception + stale blocked_providers
    let c = create_claude_profile_in(&storage, &claude, "Account A", Some("185.212.102.40".into()), Some("NL".into()), Some(k1_raw.into())).unwrap();
    let prof_a_id = c.profiles.iter().find(|p| p.name == "Account A").unwrap().id.clone();
    let _ = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a_id).unwrap();

    let state1 = AppState::load_or_default(state_path.clone());
    state1.apply_profile_route(k1_route).await.unwrap();
    state1.add_trusted_exception("openai", "203.0.113.77").await.unwrap();
    state1.block_provider(PROVIDER_ANTHROPIC).await.unwrap();
    state1.block_provider("openai").await.unwrap();
    drop(state1);

    // Simulate app restart
    let state2 = AppState::load_or_default(state_path.clone());
    let binding = active_profile_binding_state_in(&storage).unwrap().unwrap();
    reconcile_active_profile_binding_async(&state2, binding).await;

    let st = state2.get_data().await;
    assert_eq!(st.profile_route_id.as_deref(), Some(k1_id.as_str()));
    assert_eq!(st.pinned_ips.get("anthropic").map(String::as_str), Some("185.212.102.40"));
    assert!(st.is_ip_trusted_for_provider("openai", "203.0.113.77"));
    assert!(!st.blocked_providers.iter().any(|b| b == PROVIDER_ANTHROPIC), "stale anthropic block clears on restart with active key");
    assert!(st.blocked_providers.iter().any(|b| b == "openai"), "non-profile provider block stays until audited");

    // Simulate deleted-route dangling survival across restart
    assert!(mark_profiles_route_removed_in(&storage, &claude, &k1_id).unwrap());
    state2.remove_route(&k1_id).await.unwrap();
    state2.set_profile_route_dangling(k1_id.clone()).await.unwrap();
    drop(state2);

    let state3 = AppState::load_or_default(state_path);
    let binding3 = active_profile_binding_state_in(&storage).unwrap().unwrap();
    reconcile_active_profile_binding_async(&state3, binding3).await;
    let st3 = state3.get_data().await;
    assert!(matches!(select_route(&st3, PROVIDER_ANTHROPIC), RouteSelection::Missing(ref id) if id == &k1_id));

    // Concurrent profile reads/updates leave valid profiles.json with zero .tmp residue
    std::thread::scope(|s| {
        for i in 0..8 {
            let (st_dir, cl_dir, pid) = (&storage, &claude, &prof_a_id);
            s.spawn(move || {
                let _ = list_claude_profiles_in(st_dir, cl_dir, None);
                if i % 2 == 0 {
                    let _ = update_profile_bound_ip_in(st_dir, cl_dir, pid, Some("185.212.102.40".into()), Some("NL".into()));
                } else {
                    let _ = update_profile_bound_upstream_in(st_dir, cl_dir, pid, Some(k1_raw.into()));
                }
            });
        }
    });
    let profiles_raw = fs::read_to_string(storage.join("profiles.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&profiles_raw).expect("profiles.json must remain valid JSON");
    assert!(parsed.get("profiles").is_some());
    assert!(!storage.join("profiles.json.tmp").exists());
}
