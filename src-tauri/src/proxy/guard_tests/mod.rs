use super::*;
use crate::auditor::CheckResult;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::Instant as TInstant;

#[derive(Default)]
struct TestIo {
    events: std::sync::Mutex<Vec<(String, serde_json::Value, TInstant)>>,
    trays: std::sync::Mutex<Vec<String>>,
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

mod gates_tests;
mod audit_lifecycle_tests;
mod allow_and_ttl_tests;
mod pinning_and_pause_tests;
mod provider_isolation_tests;
mod recovery_and_exceptions_tests;
mod real_ticker_tests;
mod asn_cooldown_tests;
