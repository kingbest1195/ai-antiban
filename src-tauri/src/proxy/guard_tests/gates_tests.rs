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
