use super::super::*;

#[tokio::test]
async fn test_gate_default_open_and_wait() {
    let guard = NetworkGuard::new();
    assert_eq!(guard.gate(), Gate::Open);

    let mut rx = guard.subscribe();
    assert!(wait_open(&mut rx).await);
}

#[tokio::test]
async fn test_gate_pending_blocks_until_open() {
    let guard = Arc::new(NetworkGuard::new());
    guard.set_gate(Gate::Pending);

    let g2 = Arc::clone(&guard);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        g2.set_gate(Gate::Open);
    });

    let decision = guard.await_decision().await;
    assert_eq!(decision, Gate::Open);
}

#[tokio::test]
async fn test_await_decision_returns_blocked() {
    let guard = Arc::new(NetworkGuard::new());
    guard.set_gate(Gate::Pending);

    let g2 = Arc::clone(&guard);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        g2.set_gate(Gate::Blocked);
    });

    assert_eq!(guard.await_decision().await, Gate::Blocked);
}

#[tokio::test]
async fn test_wait_open_returns_false_immediately_on_blocked() {
    let guard = NetworkGuard::new();
    guard.set_gate(Gate::Blocked);
    let mut rx = guard.subscribe();
    assert!(!wait_open(&mut rx).await);
}

#[test]
fn test_compute_local_route_fingerprint() {
    let fp1 = compute_local_route_fingerprint(None);
    assert!(!fp1.is_empty());
    assert!(fp1.contains("|upstream:"));

    let fp2 = compute_local_route_fingerprint(Some("socks5://user:pass@127.0.0.1:1080"));
    assert!(fp2.contains("|upstream:socks5://user:pass@127.0.0.1:1080"));
    assert_ne!(fp1, fp2);
}

#[tokio::test]
async fn test_tunnel_abort_notification() {
    let guard = NetworkGuard::new();
    let mut abort_rx = guard.subscribe_tunnel_abort();
    assert_eq!(*abort_rx.borrow_and_update(), 0);

    guard.abort_active_tunnels();
    assert!(abort_rx.changed().await.is_ok());
    assert_eq!(*abort_rx.borrow_and_update(), 1);
}

#[tokio::test]
async fn test_abort_all_tunnels_on_shutdown_notifies_all_policies() {
    let guard = NetworkGuard::new();
    let mut abort_rx = guard.subscribe_tunnel_abort();
    let mut shutdown_rx = guard.subscribe_shutdown_abort();
    assert!(!*shutdown_rx.borrow_and_update());

    guard.abort_all_tunnels_on_shutdown();
    assert!(abort_rx.changed().await.is_ok());
    assert_eq!(*abort_rx.borrow_and_update(), 1);
    assert!(shutdown_rx.changed().await.is_ok());
    assert!(*shutdown_rx.borrow_and_update());
}

#[tokio::test]
async fn test_route_fingerprint_sync_detects_change() {
    let guard = NetworkGuard::new();
    {
        let mut inner = guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "1.2.3.4".to_string(),
            country: Some("NL".to_string()),
            trusted: true,
        });
        inner.last_route_fp = Some("192.168.1.100|upstream:old".to_string());
    }

    // Calling with different upstream key detects route change immediately
    let changed = guard.check_route_fingerprint_sync(Some("socks5://new"));
    assert!(changed);
    assert_eq!(guard.gate(), Gate::Pending);
    // The change is flagged for the next tick (it must not wait for PROBE_MIN_GAP_MS).
    assert!(guard.inner.lock().await.route_dirty);
}

#[tokio::test]
async fn test_manual_killswitch_toggle() {
    let guard = NetworkGuard::new();
    assert!(!guard.is_gate_blocked());

    let state = AppState::new_in_memory();

    // Freeze
    let frozen = guard.set_manual_killswitch(true, &state).await;
    assert!(frozen);
    assert!(guard.is_gate_blocked());
    assert_eq!(guard.gate(), Gate::Blocked);
    for p in KNOWN_PROVIDERS {
        assert!(state.is_provider_blocked(p).await);
    }

    // Unfreeze
    let unfrozen = guard.set_manual_killswitch(false, &state).await;
    assert!(!unfrozen);
    assert!(!guard.is_gate_blocked());
    assert_eq!(guard.gate(), Gate::Open);
    for p in KNOWN_PROVIDERS {
        assert!(!state.is_provider_blocked(p).await);
    }
}

#[tokio::test]
async fn test_manual_killswitch_flag_is_distinct_from_automatic_freeze() {
    let guard = Arc::new(NetworkGuard::new());
    let state = AppState::new_in_memory();
    let mut kill_rx = guard.subscribe_killswitch();

    // Automatic freeze (VPN drop simulation): gate closes, kill flag stays off.
    guard.freeze_for_test().await;
    assert_eq!(guard.gate(), Gate::Blocked);
    assert!(!guard.is_manual_killswitch());
    guard.set_gate(Gate::Pending);
    assert!(!guard.is_manual_killswitch());

    // Manual kill-switch: explicit flag, observable by routed tunnels.
    guard.set_manual_killswitch(true, &state).await;
    assert!(guard.is_manual_killswitch());
    assert!(kill_rx.changed().await.is_ok());
    assert!(*kill_rx.borrow_and_update());

    // accept_current (popup "allow") must not lift the manual kill-switch.
    guard.accept_current().await;
    assert!(guard.is_manual_killswitch());
    assert_eq!(guard.gate(), Gate::Blocked);

    guard.set_manual_killswitch(false, &state).await;
    assert!(!guard.is_manual_killswitch());
    assert_eq!(guard.gate(), Gate::Open);
}

// ---- window-first alert flow (event seam + AuditFn / ProbeFn seams) ----

#[tokio::test]
async fn test_guard_status_transitions_update_tray_immediately_without_audit() {
    let h = super::harness(
        super::slow_audit(Duration::from_millis(500), "1.2.3.4", OverallStatus::Green),
        "1.2.3.4",
    )
    .await;

    h.guard.set_gate(Gate::Pending);
    h.guard
        .pause_until_network_change(&h.state, Some("Пауза".to_string()))
        .await;
    h.guard.set_manual_killswitch(true, &h.state).await;
    h.guard.set_manual_killswitch(false, &h.state).await;

    let trays = h.io.guard_trays.lock().unwrap().clone();
    assert!(
        trays.iter().any(|s| s.gate == "pending" && !s.paused),
        "expected immediate Pending tray update: {trays:?}"
    );
    assert!(
        trays.iter().any(|s| s.paused
            && s.mode == PauseMode::UntilNetworkChange
            && s.gate == "blocked"
            && !s.manual_killswitch),
        "expected immediate UntilNetworkChange tray update: {trays:?}"
    );
    assert!(
        trays
            .iter()
            .any(|s| s.manual_killswitch && s.mode == PauseMode::Manual && s.gate == "blocked"),
        "expected immediate manual kill-switch tray update: {trays:?}"
    );
    let last = trays.last().expect("final tray status");
    assert_eq!(last.gate, "open");
    assert!(!last.paused);
    assert!(!last.manual_killswitch);
}

#[test]
fn utun_drop_surfaces_at_zero_ms_while_additive_ipv6_churn_debounces() {
    use super::super::fingerprint_os::{UtunDebounceState, stabilize_non_default_utun_entries_in};

    let mut st = UtunDebounceState::default();
    let t0 = Instant::now();
    let udp = "192.168.1.10|192.168.1.10|none";

    // Initial utun4 IPv4 established with udp_sig.
    let s0 = stabilize_non_default_utun_entries_in(
        &mut st,
        udp,
        vec!["en0=192.168.1.10".into()],
        vec!["utun4=10.8.0.2".into()],
        t0,
    );
    assert_eq!(s0, "en0=192.168.1.10,utun4=10.8.0.2");

    // Additive IPv6 churn while utun4 IPv4 remains up is debounced for 2000ms.
    let s1 = stabilize_non_default_utun_entries_in(
        &mut st,
        udp,
        vec!["en0=192.168.1.10".into()],
        vec!["utun4=10.8.0.2".into(), "utun4=fd7a:115c::/64".into()],
        t0 + Duration::from_millis(100),
    );
    assert_eq!(s1, "en0=192.168.1.10,utun4=10.8.0.2");

    // Disappearance of utun4 surfaces IMMEDIATELY at 0ms debounce (1ms later).
    let s2 = stabilize_non_default_utun_entries_in(
        &mut st,
        udp,
        vec!["en0=192.168.1.10".into()],
        vec![],
        t0 + Duration::from_millis(101),
    );
    assert_eq!(s2, "en0=192.168.1.10");

    // Re-establish utun4=10.8.0.2 and utun4=fd7a::/64 after 2000ms, then drop ONLY IPv4 -> 0ms!
    let t1 = t0 + Duration::from_secs(3);
    let _ = stabilize_non_default_utun_entries_in(
        &mut st,
        "192.168.1.11|192.168.1.11|none",
        vec!["en0=192.168.1.11".into()],
        vec!["utun4=10.8.0.2".into(), "utun4=fd7a::/64".into()],
        t1,
    );
    let s3 = stabilize_non_default_utun_entries_in(
        &mut st,
        "192.168.1.11|192.168.1.11|none",
        vec!["en0=192.168.1.11".into()],
        vec!["utun4=fd7a::/64".into()],
        t1 + Duration::from_millis(5),
    );
    assert_eq!(s3, "en0=192.168.1.11,utun4=fd7a::/64");
}
