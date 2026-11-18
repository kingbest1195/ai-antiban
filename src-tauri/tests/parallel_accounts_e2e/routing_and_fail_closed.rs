use std::sync::atomic::Ordering;

use tempfile::TempDir;

use zastava_lib::auditor::network::current_timestamp;
use zastava_lib::auditor::profile_switcher::{
    create_claude_profile_in, mark_profiles_route_removed_in, resolve_route_id_for_key,
    switch_claude_profile_in_with_home,
};
use zastava_lib::auditor::{OverallStatus, ProviderId};
use zastava_lib::commands::claude::sync_active_profile_binding_to_runtime;
use zastava_lib::proxy::Gate;
use zastava_lib::proxy::guard::PauseMode;
use zastava_lib::routing::{RouteSelection, select_route, snapshot as build_routes_snapshot};
use zastava_lib::state::PROVIDER_ANTHROPIC;

use crate::helpers::{
    ExitState, connect_and_echo, route_telemetry, spawn_socks_echo, start_gateway, wait_for_gate,
};

#[tokio::test]
async fn e2e_scenario_2_parallel_accounts_pinned_key_and_unrouted_ai_isolation() {
    let (state, _server, guard, _exit, _hits, auditor) = start_gateway(ExitState::clean_de()).await;
    let (k1_port, _) = spawn_socks_echo().await;
    let k1_raw = format!("socks5://127.0.0.1:{k1_port}#AccountA-NL");
    let k1_id = resolve_route_id_for_key(Some(&k1_raw)).unwrap();
    let ip_a = "185.212.102.40";
    auditor
        .resolver
        .set_cached_for_route(Some(k1_id.clone()), route_telemetry(ip_a, "NL"))
        .await;

    // Global OS VPN pinned for OpenAI & Gemini
    state.set_pinned_ip_for("default", Some("185.100.10.2".into())).await.unwrap();

    let tmp = TempDir::new().unwrap();
    let storage = tmp.path().join("profiles");
    let claude = tmp.path().join("Claude");
    let c = create_claude_profile_in(&storage, &claude, "Account A", Some(ip_a.into()), Some("NL".into()), Some(k1_raw.clone())).unwrap();
    let prof_a = c.profiles.iter().find(|p| p.name == "Account A").unwrap().clone();

    // Activate Profile A -> anthropic gets K1 + IP_A, default pin remains untouched
    let sw_a = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a.id).unwrap();
    sync_active_profile_binding_to_runtime(
        &state,
        &guard,
        sw_a.pinned_ip_updated.clone(),
        sw_a.bound_upstream_key_updated.as_deref(),
        sw_a.active_profile.bound_route_id.as_deref(),
    )
    .await
    .unwrap();

    let st_a = state.get_data().await;
    assert_eq!(st_a.pinned_ips.get("anthropic").map(String::as_str), Some(ip_a));
    assert_eq!(st_a.pinned_ips.get("default").map(String::as_str), Some("185.100.10.2"));
    assert_eq!(st_a.profile_route_id.as_deref(), Some(k1_id.as_str()));

    for p in [ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
        let rep = auditor.evaluate_all(p, &state, false).await.unwrap();
        assert_eq!(rep.overall_status, OverallStatus::Green, "{p:?} should be Green");
    }

    // Switch to Profile B ("default", unrouted / Direct) -> clears anthropic pin only
    let sw_b = switch_claude_profile_in_with_home(&storage, &claude, None, "default").unwrap();
    sync_active_profile_binding_to_runtime(
        &state,
        &guard,
        sw_b.pinned_ip_updated.clone(),
        sw_b.bound_upstream_key_updated.as_deref(),
        sw_b.active_profile.bound_route_id.as_deref(),
    )
    .await
    .unwrap();
    let st_b = state.get_data().await;
    assert!(!st_b.pinned_ips.contains_key("anthropic"));
    assert_eq!(st_b.pinned_ips.get("default").map(String::as_str), Some("185.100.10.2"));
    assert_eq!(st_b.profile_route_id, None);
}

#[tokio::test]
async fn e2e_scenario_3_ru_drop_on_bound_key_a_then_switch_to_direct_b() {
    let (state, server, guard, exit, direct_hits, auditor) = start_gateway(ExitState::clean_de()).await;
    let (k1_port, k1_tunnels) = spawn_socks_echo().await;
    let k1_raw = format!("socks5://127.0.0.1:{k1_port}#KeyA");
    let k1_id = resolve_route_id_for_key(Some(&k1_raw)).unwrap();
    auditor
        .resolver
        .set_cached_for_route(Some(k1_id.clone()), route_telemetry("185.212.102.40", "NL"))
        .await;
    state.set_pinned_ip_for("default", Some("185.100.10.2".into())).await.unwrap();

    // Baseline healthy tick on DE
    guard.tick_test().await;

    let tmp = TempDir::new().unwrap();
    let storage = tmp.path().join("profiles");
    let claude = tmp.path().join("Claude");
    let c = create_claude_profile_in(&storage, &claude, "Account A", Some("185.212.102.40".into()), Some("NL".into()), Some(k1_raw.clone())).unwrap();
    let prof_a_id = c.profiles.iter().find(|p| p.name == "Account A").unwrap().id.clone();

    let sw_a = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a_id).unwrap();
    sync_active_profile_binding_to_runtime(&state, &guard, sw_a.pinned_ip_updated, sw_a.bound_upstream_key_updated.as_deref(), Some(&k1_id))
        .await
        .unwrap();
    guard.tick_test().await;

    let (resp_a1, echo_a1) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"PING_A1").await;
    assert!(resp_a1.starts_with("HTTP/1.1 200"), "{resp_a1}");
    assert_eq!(echo_a1, b"PING_A1");
    let hits_before_ru = direct_hits.load(Ordering::SeqCst);

    // Drop OS VPN to RU while Profile A uses K1
    *exit.write().await = ExitState::blocked_ru();
    guard.tick_test().await;
    wait_for_gate(&guard, ProviderId::Openai, Gate::Blocked).await;
    assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);
    assert_eq!(guard.gate_for(ProviderId::Openai), Gate::Blocked);
    assert_eq!(guard.gate_for(ProviderId::Gemini), Gate::Blocked);

    let (resp_oai, _) = connect_and_echo(server.bound_addr, "chatgpt.com", b"NO").await;
    assert!(resp_oai.starts_with("HTTP/1.1 403"), "OpenAI must block on RU: {resp_oai}");
    let (resp_gem, _) = connect_and_echo(server.bound_addr, "gemini.google.com", b"NO").await;
    assert!(resp_gem.starts_with("HTTP/1.1 403"), "Gemini must block on RU: {resp_gem}");

    // Profile A's Claude through K1 STILL works while OS VPN is on RU!
    let k1_before = k1_tunnels.load(Ordering::SeqCst);
    let (resp_a_ru, echo_a_ru) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"PING_A_ON_RU").await;
    assert!(resp_a_ru.starts_with("HTTP/1.1 200"), "Profile A on K1 must stay open on RU: {resp_a_ru}");
    assert_eq!(echo_a_ru, b"PING_A_ON_RU");
    assert_eq!(k1_tunnels.load(Ordering::SeqCst), k1_before + 1);
    assert_eq!(direct_hits.load(Ordering::SeqCst), hits_before_ru, "no direct leak allowed while on RU");

    // Switch to Profile B (Direct) while STILL on RU -> anthropic MUST fail-closed immediately!
    let sw_b = switch_claude_profile_in_with_home(&storage, &claude, None, "default").unwrap();
    sync_active_profile_binding_to_runtime(&state, &guard, sw_b.pinned_ip_updated, sw_b.bound_upstream_key_updated.as_deref(), None)
        .await
        .unwrap();
    guard.tick_test().await;
    wait_for_gate(&guard, ProviderId::Anthropic, Gate::Blocked).await;
    assert_eq!(guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
    let (resp_b_ru, _) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"NO").await;
    assert!(resp_b_ru.starts_with("HTTP/1.1 403"), "Direct Profile B on RU must 403: {resp_b_ru}");
    assert_eq!(direct_hits.load(Ordering::SeqCst), hits_before_ru);

    // Switch back to Profile A -> K1 immediately restores Claude access
    let sw_a2 = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a_id).unwrap();
    sync_active_profile_binding_to_runtime(&state, &guard, sw_a2.pinned_ip_updated, sw_a2.bound_upstream_key_updated.as_deref(), Some(&k1_id))
        .await
        .unwrap();
    guard.tick_test().await;
    let (resp_a2, echo_a2) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"PING_A2").await;
    assert!(resp_a2.starts_with("HTTP/1.1 200"), "{resp_a2}");
    assert_eq!(echo_a2, b"PING_A2");
}

#[tokio::test]
async fn e2e_scenario_4_fail_closed_on_key_disable_or_delete_and_vpn_recovery() {
    let (state, server, guard, exit, direct_hits, auditor) = start_gateway(ExitState::clean_de()).await;
    let (k1_port, _) = spawn_socks_echo().await;
    let k1_raw = format!("socks5://127.0.0.1:{k1_port}#KeyA");
    let k1_id = resolve_route_id_for_key(Some(&k1_raw)).unwrap();
    auditor
        .resolver
        .set_cached_for_route(Some(k1_id.clone()), route_telemetry("185.212.102.40", "NL"))
        .await;
    state.set_pinned_ip_for("default", Some("185.100.10.2".into())).await.unwrap();
    guard.tick_test().await;

    let tmp = TempDir::new().unwrap();
    let storage = tmp.path().join("profiles");
    let claude = tmp.path().join("Claude");
    let c = create_claude_profile_in(&storage, &claude, "Account A", Some("185.212.102.40".into()), Some("NL".into()), Some(k1_raw.clone())).unwrap();
    let prof_a_id = c.profiles.iter().find(|p| p.name == "Account A").unwrap().id.clone();
    let sw_a = switch_claude_profile_in_with_home(&storage, &claude, None, &prof_a_id).unwrap();
    sync_active_profile_binding_to_runtime(&state, &guard, sw_a.pinned_ip_updated, sw_a.bound_upstream_key_updated.as_deref(), Some(&k1_id))
        .await
        .unwrap();

    // Drop VPN to RU so direct exit would be blocked anyway
    *exit.write().await = ExitState::blocked_ru();
    guard.tick_test().await;
    wait_for_gate(&guard, ProviderId::Openai, Gate::Blocked).await;
    let hits_before = direct_hits.load(Ordering::SeqCst);

    // Disable route K1 -> must fail closed (403 fail-closed, never Direct!)
    state.set_route_enabled(&k1_id, false).await.unwrap();
    let (resp_dis, _) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"NO").await;
    assert!(resp_dis.starts_with("HTTP/1.1 403") && resp_dis.contains("fail-closed"), "{resp_dis}");
    assert_eq!(direct_hits.load(Ordering::SeqCst), hits_before);

    // Re-enable then delete K1 (mirroring commands::routes::remove_route)
    state.set_route_enabled(&k1_id, true).await.unwrap();
    let active_hit = mark_profiles_route_removed_in(&storage, &claude, &k1_id).unwrap();
    assert!(active_hit);
    assert!(state.remove_route(&k1_id).await.unwrap());
    state.set_profile_route_dangling(k1_id.clone()).await.unwrap();

    let st_del = state.get_data().await;
    assert!(matches!(select_route(&st_del, PROVIDER_ANTHROPIC), RouteSelection::Missing(ref id) if id == &k1_id));
    let snap = build_routes_snapshot(&st_del, state.route_health(), current_timestamp());
    assert!(snap.dangling.iter().any(|d| d.kind == "profile" && d.route_id == k1_id));

    let (resp_del, _) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"NO").await;
    assert!(resp_del.starts_with("HTTP/1.1 403") && resp_del.contains("fail-closed"), "{resp_del}");
    assert_eq!(direct_hits.load(Ordering::SeqCst), hits_before);

    // Return OS VPN back to clean Pinned IP (DE) -> OpenAI/Gemini recover automatically,
    // while Profile A STILL holds DanglingBinding (fail-closed) until explicitly fixed!
    *exit.write().await = ExitState::clean_de();
    guard.tick_test().await;
    wait_for_gate(&guard, ProviderId::Openai, Gate::Open).await;
    assert_eq!(guard.gate_for(ProviderId::Openai), Gate::Open);
    let (resp_oai_rec, echo_oai) = connect_and_echo(server.bound_addr, "chatgpt.com", b"OK_OAI").await;
    assert!(resp_oai_rec.starts_with("HTTP/1.1 200"), "{resp_oai_rec}");
    assert_eq!(echo_oai, b"OK_OAI");

    let (resp_still_dangling, _) = connect_and_echo(server.bound_addr, "api.anthropic.com", b"STILL_BLOCKED").await;
    assert!(resp_still_dangling.starts_with("HTTP/1.1 403") && resp_still_dangling.contains("fail-closed"), "{resp_still_dangling}");
}
