use super::audit_summary::summarize;
use super::*;
use crate::auditor::CheckResult;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::Instant as TInstant;

#[derive(Default)]
struct TestIo {
    events: std::sync::Mutex<Vec<(String, serde_json::Value, TInstant)>>,
    trays: std::sync::Mutex<Vec<String>>,
    guard_trays: std::sync::Mutex<Vec<GuardPauseStatus>>,
    shows: AtomicUsize,
    hides: AtomicUsize,
}

impl TestIo {
    fn names(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.0.clone())
            .collect()
    }

    fn count(&self, name: &str) -> usize {
        self.names().iter().filter(|n| *n == name).count()
    }

    fn first(&self, name: &str) -> Option<(serde_json::Value, TInstant)> {
        self.nth(name, 0)
    }

    fn nth(&self, name: &str, idx: usize) -> Option<(serde_json::Value, TInstant)> {
        let ev = self.events.lock().unwrap();
        ev.iter()
            .filter(|e| e.0 == name)
            .nth(idx)
            .map(|e| (e.1.clone(), e.2))
    }

    async fn wait_for(&self, name: &str, ms: u64) -> Option<(serde_json::Value, TInstant)> {
        self.wait_for_count(name, 1, ms).await
    }

    async fn wait_for_count(
        &self,
        name: &str,
        min_count: usize,
        ms: u64,
    ) -> Option<(serde_json::Value, TInstant)> {
        let idx = min_count.saturating_sub(1);
        let deadline = TInstant::now() + Duration::from_millis(ms);
        while TInstant::now() < deadline {
            if let Some(e) = self.nth(name, idx) {
                return Some(e);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }
}

impl GuardIo for TestIo {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        self.events
            .lock()
            .unwrap()
            .push((event.to_string(), payload, TInstant::now()));
    }

    fn show_alert_popup(&self, _timing: Option<(String, Instant)>) {
        self.shows.fetch_add(1, Ordering::SeqCst);
    }

    fn hide_alert_popup(&self) {
        self.hides.fetch_add(1, Ordering::SeqCst);
    }

    fn tray_report(&self, _report: &RiskReport, _pinned: bool, _blocked: bool) {}

    fn tray_status(&self, color: &str, _title: Option<&str>) {
        self.trays.lock().unwrap().push(color.to_string());
    }

    fn tray_guard_status(&self, status: &GuardPauseStatus) {
        self.guard_trays.lock().unwrap().push(status.clone());
    }
}

fn test_report(provider: ProviderId, status: OverallStatus, ip: &str, cc: &str) -> RiskReport {
    let ok = CheckResult::ok("T", "t");
    RiskReport {
        provider,
        overall_status: status,
        trust_score: 90,
        telemetry: NetworkTelemetry {
            ip: ip.to_string(),
            country_code: cc.to_string(),
            hostname: None,
            asn: Some(1),
            org: None,
            isp: None,
            timezone: None,
            resolved_at: 0,
        },
        geo_result: ok.clone(),
        pinning_result: ok.clone(),
        travel_result: ok.clone(),
        dnsbl_result: ok.clone(),
        dnsbl_clean_count: "0/0".to_string(),
        asn_result: ok.clone(),
        ipv6_result: ok.clone(),
        timezone_result: ok.clone(),
        ipv6_exit: false,
        checks: vec![ok],
        unknown_count: 0,
        applicable_count: 14,
        incomplete: false,
        gateway_latency_ms: None,
    }
}

/// Audit that answers after `delay` with a report for `ip` (status Yellow unless told otherwise).
fn slow_audit(delay: Duration, ip: &'static str, status: OverallStatus) -> AuditFn {
    Arc::new(move |provider, _force| {
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(test_report(provider, status, ip, "NL"))
        })
    })
}

struct Harness {
    guard: Arc<NetworkGuard>,
    io: Arc<TestIo>,
    env: Env,
    state: AppState,
    probes: Arc<AtomicUsize>,
}

async fn harness(audit: AuditFn, probe_ip: &'static str) -> Harness {
    harness_env(audit, probe_ip, |_| {}).await
}

async fn harness_env(
    audit: AuditFn,
    probe_ip: &'static str,
    tweak: impl FnOnce(&mut Env),
) -> Harness {
    let io = Arc::new(TestIo::default());
    let state = AppState::new_in_memory();
    let probes = Arc::new(AtomicUsize::new(0));
    let probes2 = Arc::clone(&probes);
    let probe: ProbeFn = Arc::new(move || {
        probes2.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Some(probe_ip.to_string()) })
    });
    let mut env = Env {
        auditor: Auditor::new().expect("auditor"),
        state: state.clone(),
        hold_queue: Arc::new(HoldQueue::new()),
        io: io.clone(),
        audit,
        probe: Some(probe),
        resolve: None,
        audit_timeout: Duration::from_secs(5),
    };
    tweak(&mut env);
    let guard = Arc::new(NetworkGuard::new());
    assert!(guard.install_env(env.clone()));
    guard.register_self_weak();
    {
        let mut inner = guard.inner.lock().await;
        inner.baseline = Some(Baseline {
            ip: "1.1.1.1".to_string(),
            country: Some("DE".to_string()),
            trusted: true,
        });
    }
    Harness {
        guard,
        io,
        env,
        state,
        probes,
    }
}

impl Harness {
    async fn change(&self, new_ip: &str) {
        let mut inner = self.guard.inner.lock().await;
        self.guard
            .handle_change_locked(&self.env, &mut inner, new_ip.to_string(), Instant::now())
            .await;
    }
}

fn alert_id(ev: &(serde_json::Value, TInstant)) -> String {
    ev.0["id"].as_str().expect("id").to_string()
}

struct DropCounter(Arc<AtomicUsize>);

impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn all_providers() -> Vec<String> {
    KNOWN_PROVIDERS.iter().map(|p| p.to_string()).collect()
}

#[test]
fn periodic_sysproxy_sync_skips_unchanged_steady_state_ticks() {
    use super::fingerprint::PeriodicSysproxySync;

    let mut sync = PeriodicSysproxySync::default();
    let t0 = Instant::now();

    // Inactive sysproxy never triggers periodic refresh.
    assert!(!sync.should_refresh_at("192.168.1.10|upstream:", false, false, t0));

    // Activation triggers once for the current route fingerprint.
    assert!(sync.should_refresh_at("192.168.1.10|upstream:", true, false, t0));
    // Repeated steady-state ticks inside 120s with unchanged route are skipped.
    assert!(!sync.should_refresh_at(
        "192.168.1.10|upstream:",
        true,
        false,
        t0 + Duration::from_millis(250),
    ));
    assert!(!sync.should_refresh_at(
        "192.168.1.10|upstream:",
        true,
        false,
        t0 + Duration::from_secs(30),
    ));
    assert!(!sync.should_refresh_at(
        "192.168.1.10|upstream:",
        true,
        false,
        t0 + Duration::from_secs(119),
    ));

    // Reaching the 120s self-heal / new-browser interval triggers one refresh, then pauses again.
    let t_heal = t0 + PeriodicSysproxySync::SELF_HEAL_INTERVAL;
    assert!(sync.should_refresh_at("192.168.1.10|upstream:", true, false, t_heal));
    assert!(!sync.should_refresh_at(
        "192.168.1.10|upstream:",
        true,
        false,
        t_heal + Duration::from_secs(5),
    ));

    // Route change or chained upstream change triggers a refresh immediately, even inside 120s.
    let t_route = t_heal + Duration::from_secs(10);
    assert!(sync.should_refresh_at("10.8.0.2|upstream:", true, false, t_route));
    assert!(!sync.should_refresh_at(
        "10.8.0.2|upstream:",
        true,
        false,
        t_route + Duration::from_secs(1),
    ));

    // Deferred macOS OS PAC does NOT fire every 250ms; it throttles retries to once per 5s.
    assert!(!sync.should_refresh_at(
        "10.8.0.2|upstream:",
        true,
        true,
        t_route + Duration::from_millis(250),
    ));
    assert!(!sync.should_refresh_at(
        "10.8.0.2|upstream:",
        true,
        true,
        t_route + Duration::from_millis(4750),
    ));
    let t_def1 = t_route + PeriodicSysproxySync::DEFERRED_RETRY_INTERVAL;
    assert!(sync.should_refresh_at("10.8.0.2|upstream:", true, true, t_def1));
    assert!(!sync.should_refresh_at(
        "10.8.0.2|upstream:",
        true,
        true,
        t_def1 + Duration::from_millis(250),
    ));
    assert!(sync.should_refresh_at(
        "10.8.0.2|upstream:",
        true,
        true,
        t_def1 + PeriodicSysproxySync::DEFERRED_RETRY_INTERVAL,
    ));
    // Clearing deferral drops back to steady-state (120s) without immediate extra write.
    let t_cleared = t_def1 + PeriodicSysproxySync::DEFERRED_RETRY_INTERVAL + Duration::from_secs(1);
    assert!(!sync.should_refresh_at("10.8.0.2|upstream:", true, false, t_cleared));

    // Turning sysproxy off resets state so next activation refreshes immediately.
    assert!(!sync.should_refresh_at(
        "10.8.0.2|upstream:",
        false,
        false,
        t_cleared + Duration::from_secs(1),
    ));
    assert!(sync.should_refresh_at(
        "10.8.0.2|upstream:",
        true,
        false,
        t_cleared + Duration::from_secs(2),
    ));

    // Production wrapper `should_refresh` delegates to `Instant::now()` cleanly.
    let mut wall_sync = PeriodicSysproxySync::default();
    assert!(wall_sync.should_refresh("192.168.1.10|upstream:", true, false));
    assert!(!wall_sync.should_refresh("192.168.1.10|upstream:", true, false));
}

mod allow_and_ttl_tests;
mod asn_cooldown_tests;
mod audit_lifecycle_tests;
mod gates_tests;
mod offline_fail_closed_tests;
mod pinning_and_pause_tests;
mod provider_isolation_tests;
mod real_ticker_changed_tests;
mod real_ticker_tests;
mod recovery_and_exceptions_tests;
