//! Network guard: detects sudden egress-IP changes (VPN switch, reconnect, roaming),
//! freezes ALL AI traffic (new and already established tunnels) and asks the user
//! to confirm the new network before anything is forwarded again.
//!
//! Providers whose traffic goes through a route (see `crate::routing`) have a fixed exit IP, so
//! local network / VPN changes do not apply to them: the automatic `Pending` / `Blocked` gate
//! states, popups and provider blocks only concern unrouted providers. The manual kill-switch
//! ("СТОП СЕТИ") is an explicit, separate flag that stops everything, routed traffic included.
//!
//! Alert window: for the `AskPopup` behavior the gate is `Pending` from the moment of detection and
//! the window is shown at once with a minimal payload (`phase: "detecting"`); the audit runs in the
//! background and is delivered with `interceptor://enriched` (followed by `network://changed`).
//! Nothing in that background work can open the gate: an audit error, a timeout or a stale audit
//! (another change, accept or restore happened meanwhile, see `Inner::epoch`) leaves the traffic
//! blocked until the user decides or the hold expires.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::Emitter;
use tokio::sync::{Mutex, oneshot, watch};
use tokio::task::{AbortHandle, JoinHandle};
use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::{Auditor, NetworkTelemetry, OverallStatus, RiskReport};
use crate::popup::log_timing;
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, EnrichedPayload, HoldQueue, HoldResolution, NetworkChange,
    PHASE_DETECTING, PHASE_FAILED, PHASE_READY, RiskInterceptPayload,
};
use crate::state::{AppState, IpHistoryEntry, KNOWN_PROVIDERS};

/// Fast kernel routing table check interval (sub-250ms reaction time on VPN disconnect).
pub const ROUTE_CHECK_INTERVAL_MS: u64 = 250;
/// Remote IP probe interval when route fingerprint has not changed.
pub const PROBE_INTERVAL_MS: u64 = 1000;
/// Minimum gap between two remote HTTP probes.
pub const PROBE_MIN_GAP_MS: u64 = 1000;
/// How long an established tunnel may stall before it is dropped (looks like a dead network).
pub const MAX_STALL_SECS: u64 = 90;
/// Upper bound for the audit of a new network; a longer audit counts as failed (traffic stays blocked).
pub const AUDIT_TIMEOUT_SECS: u64 = 25;
/// Pseudo provider id used for network-wide holds.
pub const ALL_PROVIDERS: &str = "all";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Traffic flows normally.
    Open,
    /// Network changed, waiting for the user's decision.
    Pending,
    /// User refused the new network: traffic stays frozen until the IP is restored or confirmed.
    Blocked,
}

#[derive(Clone)]
pub struct GuardCtx {
    pub auditor: Auditor,
    pub state: AppState,
    pub hold_queue: Arc<HoldQueue>,
    pub app: tauri::AppHandle,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Audit of one provider (`force_refresh` = fresh geo lookup). Production: `Auditor::evaluate_all`;
/// tests substitute it to control timing and failures.
pub type AuditFn =
    Arc<dyn Fn(ProviderId, bool) -> BoxFuture<Result<RiskReport, String>> + Send + Sync>;
/// Fetches the current egress IP; `None` when offline. Production: [`NetworkGuard::probe_ip`].
pub type ProbeFn = Arc<dyn Fn() -> BoxFuture<Option<String>> + Send + Sync>;
/// Egress telemetry for a manual override (`accept_current`). Production: the resolver.
pub type ResolveFn = Arc<dyn Fn() -> BoxFuture<Result<NetworkTelemetry, String>> + Send + Sync>;
/// Outcome of [`audit_all`]: one entry per provider in the fixed order anthropic, openai, gemini.
pub type AuditResults = Vec<(ProviderId, Result<RiskReport, String>)>;

/// Everything the guard does to the outside world besides the gate itself (events, windows, tray).
/// Window and tray work must happen on the main thread: implementations dispatch there.
pub(crate) trait GuardIo: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value);
    /// Shows the alert popup; `timing` = `(alert id, detection instant)` for `ZASTAVA_TIMING`.
    fn show_alert_popup(&self, timing: Option<(String, Instant)>);
    fn hide_alert_popup(&self);
    fn tray_report(&self, report: &RiskReport, is_pinned: bool, has_blocked: bool);
    fn tray_status(&self, color: &str, title: Option<&str>);
}

struct TauriIo {
    app: tauri::AppHandle,
}

impl GuardIo for TauriIo {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        let _ = self.app.emit(event, payload);
    }

    fn show_alert_popup(&self, timing: Option<(String, Instant)>) {
        crate::popup::show_and_position_alert_popup_timed(&self.app, timing);
    }

    fn hide_alert_popup(&self) {
        crate::popup::hide_alert_popup(&self.app);
    }

    fn tray_report(&self, report: &RiskReport, is_pinned: bool, has_blocked: bool) {
        crate::update_tray_from_report(&self.app, report, is_pinned, has_blocked);
    }

    fn tray_status(&self, color: &str, title: Option<&str>) {
        crate::update_tray_status(&self.app, color, title);
    }
}

/// Dependencies of the guard once it runs (built from [`GuardCtx`]; tests build their own).
#[derive(Clone)]
pub(crate) struct Env {
    auditor: Auditor,
    state: AppState,
    hold_queue: Arc<HoldQueue>,
    io: Arc<dyn GuardIo>,
    audit: AuditFn,
    probe: Option<ProbeFn>,
    resolve: Option<ResolveFn>,
    audit_timeout: Duration,
}

impl Env {
    fn from_ctx(ctx: GuardCtx) -> Self {
        let (auditor, state) = (ctx.auditor.clone(), ctx.state.clone());
        let audit: AuditFn = Arc::new(move |provider, force| {
            let (auditor, state) = (auditor.clone(), state.clone());
            Box::pin(async move { auditor.evaluate_all(provider, &state, force).await })
        });
        Self {
            auditor: ctx.auditor,
            state: ctx.state,
            hold_queue: ctx.hold_queue,
            io: Arc::new(TauriIo { app: ctx.app }),
            audit,
            probe: None,
            resolve: None,
            audit_timeout: Duration::from_secs(AUDIT_TIMEOUT_SECS),
        }
    }

    async fn resolve_telemetry(&self) -> Result<NetworkTelemetry, String> {
        match &self.resolve {
            Some(resolve) => resolve().await,
            None => self.auditor.resolver.resolve(false).await,
        }
    }

    fn emit<T: Serialize>(&self, event: &str, payload: &T) {
        self.io.emit(
            event,
            serde_json::to_value(payload).unwrap_or(serde_json::Value::Null),
        );
    }
}

#[derive(Clone)]
struct Baseline {
    ip: String,
    country: Option<String>,
    /// True only if the baseline was either user-confirmed or verified non-sanctioned.
    /// Prevents a VPN drop back to an initial sanctioned IP (e.g. RU at boot) from auto-opening the gate.
    trusted: bool,
}

struct Pending {
    id: String,
    /// `Inner::epoch` at the moment this alert was registered.
    epoch: u64,
    /// Telemetry of the new network; `None` until the audit has finished (or when it failed).
    tel: Option<NetworkTelemetry>,
    /// Background clean-up of the old network's allowances / blocks. Whoever decides for this
    /// alert awaits it first, so the clean-up can never land after the decision's own writes.
    clear_old_state: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct Inner {
    baseline: Option<Baseline>,
    observed_ip: Option<String>,
    /// IP of the network the user has already been asked about (avoids popup loops).
    handled_ip: Option<String>,
    pending: Option<Pending>,
    last_probe: Option<Instant>,
    last_route_fp: Option<String>,
    /// Unrouted providers seen on the previous tick (a provider becoming unrouted re-arms checks).
    last_unrouted: Option<Vec<&'static str>>,
    /// Grows on every change / accept / restore / withdrawn alert. A background audit or a
    /// decision is applied only while its alert id AND epoch are still the current ones.
    epoch: u64,
    /// `check_route_fingerprint_sync` saw the route change and already closed the gate: the next
    /// tick must handle it at once (no `PROBE_MIN_GAP_MS` wait).
    route_dirty: bool,
    /// When `route_dirty` was raised (only for the `ZASTAVA_TIMING` log).
    dirty_since: Option<Instant>,
    /// Background audit of the current alert (cancelled when the alert is superseded).
    audit_abort: Option<AbortHandle>,
}

impl Inner {
    /// Withdraws the current alert: its id and epoch stop being valid, its audit is cancelled.
    /// The caller removes the returned alert from the hold queue.
    fn invalidate_alert(&mut self) -> Option<Pending> {
        self.epoch = self.epoch.wrapping_add(1);
        if let Some(abort) = self.audit_abort.take() {
            abort.abort();
        }
        self.pending.take()
    }

    fn is_current(&self, id: &str, epoch: u64) -> bool {
        self.epoch == epoch
            && self
                .pending
                .as_ref()
                .is_some_and(|p| p.id == id && p.epoch == epoch)
    }
}

pub struct NetworkGuard {
    gate_tx: watch::Sender<Gate>,
    tunnel_abort_tx: watch::Sender<u64>,
    /// Manual kill-switch. Unlike the automatic gate it also stops routed providers.
    kill_tx: watch::Sender<bool>,
    /// Serialises every gate write with the kill flag: while the manual kill-switch is engaged the
    /// gate can never be anything but `Blocked`, no matter which task (tick, accept, restore,
    /// popup resolution) races with it.
    gate_lock: std::sync::Mutex<()>,
    inner: Mutex<Inner>,
    /// One route check at a time (as when `inner` was held across the probe): a CONNECT waits for
    /// the check in flight and then sees its verdict. `inner` itself is only held in short sections.
    tick_lock: Mutex<()>,
    env: OnceLock<Env>,
    client: reqwest::Client,
}

/// Computes the local default-route network interface fingerprint in < 0.05ms
/// using a local UDP routing table lookup without transmitting any network packet.
pub fn compute_local_route_fingerprint(upstream_key: Option<&str>) -> String {
    let local_ip = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => match socket.connect("1.1.1.1:80") {
            Ok(_) => match socket.local_addr() {
                Ok(addr) => addr.ip().to_string(),
                Err(_) => "0.0.0.0".to_string(),
            },
            Err(_) => "0.0.0.0".to_string(),
        },
        Err(_) => "0.0.0.0".to_string(),
    };
    format!("{local_ip}|upstream:{}", upstream_key.unwrap_or(""))
}

impl Default for NetworkGuard {
    fn default() -> Self {
        Self::new()
    }
}

fn severity(report: &RiskReport) -> u8 {
    match report.overall_status {
        OverallStatus::Red => 2,
        OverallStatus::Yellow => 1,
        OverallStatus::Green => 0,
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn network_change(
    old: Option<&Baseline>,
    new_ip: Option<String>,
    new_country: Option<String>,
) -> NetworkChange {
    NetworkChange {
        old_ip: old.map(|b| b.ip.clone()),
        old_country: old.and_then(|b| b.country.clone()),
        new_ip,
        new_country,
    }
}

/// Audits anthropic, openai and gemini (each on its own egress) concurrently. Only the first call
/// forces a fresh geo lookup (with 1 automatic retry for transient VPN interface handshakes);
/// the others share the resolver's cache. One provider failing does not affect the others.
async fn audit_all(audit: &AuditFn) -> AuditResults {
    let anthropic = async {
        match audit(ProviderId::Anthropic, true).await {
            Ok(r) => Ok(r),
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(400)).await;
                audit(ProviderId::Anthropic, true).await
            }
        }
    };
    let (anthropic, openai, gemini) = tokio::join!(
        anthropic,
        audit(ProviderId::Openai, false),
        audit(ProviderId::Gemini, false)
    );
    vec![
        (ProviderId::Anthropic, anthropic),
        (ProviderId::Openai, openai),
        (ProviderId::Gemini, gemini),
    ]
}

/// What the decision logic needs from an audit of the new network.
struct AuditSummary {
    /// Report for the tray (the first report that succeeded, i.e. anthropic's when it did).
    tray: RiskReport,
    /// The worst report among the providers that use the changed network.
    worst: RiskReport,
    tel: NetworkTelemetry,
    /// Every unrouted provider was audited successfully and is green.
    all_green: bool,
}

/// `None` = the audit failed: the first (active) unrouted provider could not be audited.
/// Failures of other providers are skipped, but they make `all_green` false (fail-closed).
fn summarize(results: &AuditResults, unrouted: &[&'static str]) -> Option<AuditSummary> {
    let relevant_id = |p: &ProviderId| unrouted.contains(&p.as_str());
    let active = results
        .iter()
        .map(|(p, _)| p)
        .find(|p| relevant_id(p))
        .or_else(|| results.first().map(|(p, _)| p))?;
    let active_report = results
        .iter()
        .find(|(p, _)| p == active)
        .and_then(|(_, r)| r.as_ref().ok())?;

    let relevant: Vec<&RiskReport> = results
        .iter()
        .filter(|(p, _)| relevant_id(p))
        .filter_map(|(_, r)| r.as_ref().ok())
        .collect();
    let mut worst = relevant.first().copied().unwrap_or(active_report);
    for r in relevant.iter().skip(1) {
        if severity(r) > severity(worst) {
            worst = r;
        }
    }
    let any_unrouted_failed = results.iter().any(|(p, r)| relevant_id(p) && r.is_err());
    let all_green = !any_unrouted_failed
        && relevant
            .iter()
            .all(|r| r.overall_status == OverallStatus::Green);
    let tray = results
        .iter()
        .find_map(|(_, r)| r.as_ref().ok())
        .unwrap_or(active_report)
        .clone();
    let worst = worst.clone();
    let tel = worst.telemetry.clone();
    Some(AuditSummary {
        tray,
        worst,
        tel,
        all_green,
    })
}

/// Waits until the gate is open. Returns `false` immediately when blocked or stall limit is exceeded.
pub async fn wait_open(rx: &mut watch::Receiver<Gate>) -> bool {
    let fut = async {
        loop {
            match *rx.borrow_and_update() {
                Gate::Open => return true,
                Gate::Blocked => return false,
                Gate::Pending => {}
            }
            if rx.changed().await.is_err() {
                return false;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(MAX_STALL_SECS), fut)
        .await
        .unwrap_or(false)
}

/// Completes as soon as the gate leaves the `Open` state.
pub async fn gate_closed(rx: &mut watch::Receiver<Gate>) {
    loop {
        if *rx.borrow_and_update() != Gate::Open {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// What the first (short, locked) part of a tick decided.
enum TickPlan {
    Done,
    /// The route changed (or was reported changed by a CONNECT): probe at once, ignore the min gap.
    ProbeChanged(Instant, String),
    /// Regular periodic probe. Both carry the route fingerprint the plan was made for.
    ProbeRegular(String),
}

impl NetworkGuard {
    pub fn new() -> Self {
        let (gate_tx, _rx) = watch::channel(Gate::Open);
        let (tunnel_abort_tx, _abort_rx) = watch::channel(0u64);
        let (kill_tx, _kill_rx) = watch::channel(false);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(2000))
            // Never reuse keep-alive sockets: they may still point to the previous route.
            .pool_max_idle_per_host(0)
            .user_agent("Zastava/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            gate_tx,
            tunnel_abort_tx,
            kill_tx,
            gate_lock: std::sync::Mutex::new(()),
            inner: Mutex::new(Inner::default()),
            tick_lock: Mutex::new(()),
            env: OnceLock::new(),
            client,
        }
    }

    pub fn gate(&self) -> Gate {
        *self.gate_tx.borrow()
    }

    pub fn subscribe(&self) -> watch::Receiver<Gate> {
        self.gate_tx.subscribe()
    }

    pub fn subscribe_tunnel_abort(&self) -> watch::Receiver<u64> {
        self.tunnel_abort_tx.subscribe()
    }

    /// True while the manual kill-switch is engaged (automatic freezes do not set it).
    pub fn is_manual_killswitch(&self) -> bool {
        *self.kill_tx.borrow()
    }

    pub fn subscribe_killswitch(&self) -> watch::Receiver<bool> {
        self.kill_tx.subscribe()
    }

    /// Aborts unrouted tunnels (routed tunnels only obey the manual kill-switch).
    pub fn abort_active_tunnels(&self) {
        let _ = self.tunnel_abort_tx.send_modify(|val| *val = val.wrapping_add(1));
    }

    /// Cheap local check used by every CONNECT. On a route change it closes the gate and aborts
    /// the tunnels at once and marks the change `route_dirty`, so the next tick handles it without
    /// waiting for `PROBE_MIN_GAP_MS`.
    pub fn check_route_fingerprint_sync(&self, upstream_key: Option<&str>) -> bool {
        let fp = compute_local_route_fingerprint(upstream_key);
        let mut g = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        if g.baseline.is_none() {
            g.last_route_fp = Some(fp);
            return false;
        }
        if let Some(ref old_fp) = g.last_route_fp {
            if fp != *old_fp {
                g.last_route_fp = Some(fp);
                if !g.route_dirty {
                    g.dirty_since = Some(Instant::now());
                }
                g.route_dirty = true;
                self.set_gate(Gate::Pending);
                self.abort_active_tunnels();
                return true;
            }
        } else {
            g.last_route_fp = Some(fp);
        }
        false
    }

    /// Sets the gate. While the manual kill-switch is engaged every request is coerced to
    /// `Blocked`: `Open` (or `Pending`) cannot be set behind the kill-switch's back.
    fn set_gate(&self, gate: Gate) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        let effective = if *self.kill_tx.borrow() { Gate::Blocked } else { gate };
        self.gate_tx.send_replace(effective);
    }

    /// Engages the kill flag and blocks the gate as one step with respect to `set_gate`.
    fn engage_kill(&self) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.kill_tx.send_replace(true);
        self.gate_tx.send_replace(Gate::Blocked);
    }

    /// Lifts the kill flag and opens the gate as one step with respect to `set_gate`.
    fn release_kill(&self) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.kill_tx.send_replace(false);
        self.gate_tx.send_replace(Gate::Open);
    }

    /// Re-engages a manual kill-switch saved by a previous run (a restart must not lift it).
    /// Returns whether it is engaged.
    pub async fn restore_manual_killswitch(&self, state: &AppState) -> bool {
        if state.is_manual_killswitch_saved().await {
            self.engage_kill();
            true
        } else {
            false
        }
    }

    pub fn is_gate_blocked(&self) -> bool {
        self.gate() == Gate::Blocked
    }

    pub async fn set_manual_killswitch(&self, freeze: bool, state: &AppState) -> bool {
        if freeze {
            self.engage_kill();
            self.abort_active_tunnels();
            if let Err(e) = state.set_manual_killswitch_saved(true).await {
                eprintln!("Warning: could not persist the kill-switch: {e}");
            }
            let mut inner = self.inner.lock().await;
            if let (Some(p), Some(env)) = (inner.invalidate_alert(), self.env.get()) {
                env.hold_queue.remove(&p.id).await;
            }
            drop(inner);
            for p in KNOWN_PROVIDERS {
                let _ = state.block_provider(p).await;
            }
            if let Some(env) = self.env.get() {
                self.hide_popup(env);
                env.io
                    .tray_status("red", Some("⛔ СТОП СЕТИ (Ручная блокировка ИИ)"));
            }
            true
        } else {
            self.release_kill();
            if let Err(e) = state.set_manual_killswitch_saved(false).await {
                eprintln!("Warning: could not persist the kill-switch: {e}");
            }
            let mut inner = self.inner.lock().await;
            if let (Some(p), Some(env)) = (inner.invalidate_alert(), self.env.get()) {
                env.hold_queue.remove(&p.id).await;
            }
            drop(inner);
            let _ = state.clear_blocked_providers().await;
            if let Some(env) = self.env.get() {
                self.hide_popup(env);
                env.io.tray_status("green", None);
            }
            false
        }
    }

    pub async fn freeze_for_test(&self) {
        self.set_gate(Gate::Blocked);
        self.abort_active_tunnels();
        if let Some(env) = self.env.get() {
            env.io.show_alert_popup(None);
        }
    }

    pub async fn verify_before_connect(self: &Arc<Self>) -> bool {
        self.ensure_fresh().await;
        self.gate() == Gate::Open
    }

    /// Used by new CONNECT requests: waits for the user's decision while the gate is pending.
    pub async fn await_decision(&self) -> Gate {
        let mut rx = self.gate_tx.subscribe();
        let fut = async {
            loop {
                let g = *rx.borrow_and_update();
                if g != Gate::Pending {
                    return g;
                }
                if rx.changed().await.is_err() {
                    return Gate::Blocked;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(DEFAULT_HOLD_TTL_SECS + 15), fut)
            .await
            .unwrap_or(Gate::Blocked)
    }

    /// Starts the background monitor (call once from the Tauri setup hook).
    pub fn start(self: &Arc<Self>, ctx: GuardCtx) {
        if !self.install_env(Env::from_ctx(ctx)) {
            return;
        }
        let guard = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let mut n: u64 = 0;
            loop {
                if let Some(env) = guard.env.get() {
                    guard.check_route_and_tick(env).await;
                    if n % 20 == 0 {
                        let _ = tokio::task::spawn_blocking(
                            crate::sysproxy::refresh_if_services_changed,
                        )
                        .await;
                    }
                }
                n += 1;
                tokio::time::sleep(Duration::from_millis(ROUTE_CHECK_INTERVAL_MS)).await;
            }
        });
    }

    /// Stores the dependencies; `false` when they were already set.
    fn install_env(&self, env: Env) -> bool {
        self.env.set(env).is_ok()
    }

    /// Cheap pre-flight check used by every new CONNECT (no-op when the monitor is not running).
    pub async fn ensure_fresh(self: &Arc<Self>) {
        if let Some(env) = self.env.get() {
            self.check_route_and_tick(env).await;
        }
    }

    /// Fetches the current egress IP (Cloudflare trace, falls back to ipify).
    async fn probe_ip(&self) -> Option<String> {
        if let Ok(resp) = self.client.get("https://1.1.1.1/cdn-cgi/trace").send().await {
            if let Ok(text) = resp.text().await {
                for line in text.lines() {
                    if let Some(val) = line.strip_prefix("ip=") {
                        let val = val.trim();
                        if val.parse::<IpAddr>().is_ok() {
                            return Some(val.to_string());
                        }
                    }
                }
            }
        }
        if let Ok(resp) = self.client.get("https://api.ipify.org").send().await {
            if let Ok(text) = resp.text().await {
                let val = text.trim();
                if val.parse::<IpAddr>().is_ok() {
                    return Some(val.to_string());
                }
            }
        }
        None
    }

    async fn probe(&self, env: &Env) -> Option<String> {
        match &env.probe {
            Some(probe) => probe().await,
            None => self.probe_ip().await,
        }
    }

    /// First part of a tick, under the `inner` lock (no network I/O).
    async fn plan_tick(&self, current_fp: String, unrouted: &[&'static str]) -> TickPlan {
        let mut inner = self.inner.lock().await;
        let dirty = std::mem::take(&mut inner.route_dirty);
        let dirty_since = inner.dirty_since.take();

        // A provider that just lost its route must be re-checked against the current network.
        let gained_unrouted = inner
            .last_unrouted
            .as_ref()
            .map(|prev| unrouted.iter().any(|p| !prev.contains(p)))
            .unwrap_or(false);
        if gained_unrouted {
            inner.handled_ip = None;
        }
        inner.last_unrouted = Some(unrouted.to_vec());

        // Manual kill-switch: nothing to decide until the user lifts it.
        if self.is_manual_killswitch() {
            inner.last_route_fp = Some(current_fp);
            return TickPlan::Done;
        }

        // Every provider has a fixed exit: local network changes are irrelevant.
        if unrouted.is_empty() {
            inner.last_route_fp = Some(current_fp);
            if self.gate() != Gate::Open {
                self.set_gate(Gate::Open);
            }
            return TickPlan::Done;
        }

        let route_changed = if inner.baseline.is_some() {
            // `dirty`: a CONNECT already saw the change (and overwrote the fingerprint).
            dirty
                || inner
                    .last_route_fp
                    .as_ref()
                    .is_some_and(|old_fp| *old_fp != current_fp)
        } else {
            false
        };

        if route_changed {
            inner.last_route_fp = Some(current_fp.clone());
            // 1. Immediately freeze gate (so zero packets leak during the probe!)
            self.set_gate(Gate::Pending);
            return TickPlan::ProbeChanged(dirty_since.unwrap_or_else(Instant::now), current_fp);
        }

        inner.last_route_fp = Some(current_fp.clone());

        if let Some(t) = inner.last_probe {
            if t.elapsed() < Duration::from_millis(PROBE_MIN_GAP_MS) {
                return TickPlan::Done;
            }
        }
        TickPlan::ProbeRegular(current_fp)
    }

    /// True when the route moved (or a CONNECT flagged it) while a probe was in flight. Such a
    /// probe may have travelled over the old route, so it must never open the gate: the gate is
    /// kept closed and the next tick (fingerprint differs / `route_dirty`) handles the change.
    fn probe_is_stale(&self, inner: &Inner, planned_fp: &str) -> bool {
        let stale = inner.route_dirty || compute_local_route_fingerprint(None) != planned_fp;
        if stale && self.gate() == Gate::Open {
            self.set_gate(Gate::Pending);
        }
        stale
    }

    async fn check_route_and_tick(self: &Arc<Self>, env: &Env) {
        let _tick = self.tick_lock.lock().await;
        // Routes do not take part in the fingerprint: routed traffic has a fixed exit and is not
        // governed by the gate, and the probe below measures the direct egress only.
        let current_fp = compute_local_route_fingerprint(None);
        let unrouted = env.state.unrouted_providers().await;

        match self.plan_tick(current_fp, &unrouted).await {
            TickPlan::Done => {}
            TickPlan::ProbeChanged(t0, planned_fp) => {
                // 2. Probe external IP (no lock held: other tasks keep working meanwhile)
                let probed = self.probe(env).await;
                let mut inner = self.inner.lock().await;
                self.apply_changed_probe(env, &mut inner, probed, t0, &planned_fp)
                    .await;
            }
            TickPlan::ProbeRegular(planned_fp) => {
                let probed = self.probe(env).await;
                let mut inner = self.inner.lock().await;
                self.apply_regular_probe(env, &mut inner, probed, &planned_fp)
                    .await;
            }
        }
    }

    /// The route fingerprint changed: decide what the probed IP means.
    async fn apply_changed_probe(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        probed: Option<String>,
        t0: Instant,
        planned_fp: &str,
    ) {
        inner.last_probe = Some(Instant::now());

        // 3. Check if probed IP equals baseline IP
        let (baseline_ip, baseline_trusted) = inner
            .baseline
            .as_ref()
            .map(|b| (b.ip.clone(), b.trusted))
            .unzip();
        let baseline_trusted = baseline_trusted.unwrap_or(false);

        if let Some(ref new_ip) = probed {
            inner.observed_ip = Some(new_ip.clone());

            if baseline_ip.as_deref() == Some(new_ip.as_str()) {
                // The external IP did NOT change at all — local utun refresh on macOS (e.g. Amnezia)!
                if baseline_trusted {
                    if self.probe_is_stale(inner, planned_fp) {
                        return; // the route moved again meanwhile: the next tick decides
                    }
                    if inner.pending.is_some() {
                        // An alert for another network is still open: the old network is back.
                        self.restore_locked(env, inner).await;
                    } else {
                        self.set_gate(Gate::Open);
                    }
                    return;
                }
                if inner.handled_ip.as_deref() == Some(new_ip.as_str()) {
                    return;
                }
            }
        }

        // 4. Only if new_ip actually changed (or if probed is None / different from baseline):
        self.abort_active_tunnels();
        env.auditor.resolver.invalidate_cache().await;
        let old_country = inner
            .baseline
            .as_ref()
            .and_then(|b| b.country.clone())
            .unwrap_or_else(|| "??".to_string());
        env.state
            .stats()
            .record_intercepted("all", "NetworkGuard", "HELD", &old_country);

        if let Some(new_ip) = probed {
            self.handle_change_locked(env, inner, new_ip, t0).await;
        }
    }

    /// Periodic probe without a route change.
    async fn apply_regular_probe(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        probed: Option<String>,
        planned_fp: &str,
    ) {
        inner.last_probe = Some(Instant::now());
        let t0 = Instant::now();
        let Some(ip) = probed else {
            return; // offline: nothing to compare
        };
        inner.observed_ip = Some(ip.clone());

        let Some((baseline_ip, baseline_trusted)) = inner
            .baseline
            .as_ref()
            .map(|b| (b.ip.clone(), b.trusted))
        else {
            let country = env
                .auditor
                .resolver
                .resolve(false)
                .await
                .ok()
                .map(|t| t.country_code);
            let is_sanctioned = if let Some(ref cc) = country {
                let matrix = env.auditor.rules.provider_matrix.read().await;
                matrix
                    .global_blocked_countries
                    .iter()
                    .any(|b| b.eq_ignore_ascii_case(cc))
            } else {
                false
            };
            inner.baseline = Some(Baseline {
                ip,
                country,
                trusted: !is_sanctioned,
            });
            return;
        };

        if ip == baseline_ip {
            if baseline_trusted {
                if self.gate() != Gate::Open {
                    if self.probe_is_stale(inner, planned_fp) {
                        return; // the route moved again meanwhile: the next tick decides
                    }
                    self.restore_locked(env, inner).await;
                } else {
                    inner.handled_ip = None;
                }
                return;
            }
            // If the initial baseline was untrusted (e.g. app started on a sanctioned IP before VPN)
            // and the user switched away and dropped back to it, treat it as an unsafe change!
        }

        if inner.handled_ip.as_deref() == Some(ip.as_str()) {
            return; // user already decided about this network
        }

        self.handle_change_locked(env, inner, ip, t0).await;
    }

    pub async fn tick(self: &Arc<Self>, ctx: &GuardCtx) {
        match self.env.get() {
            Some(env) => self.check_route_and_tick(env).await,
            None => self.check_route_and_tick(&Env::from_ctx(ctx.clone())).await,
        }
    }

    /// Persists "the previous allowances / blocks belonged to the old network" in the background
    /// (two JSON writes with fsync). Whoever decides later awaits the handle first, so a write can
    /// never land after the decision's own `block_provider` / allowance. The manual kill-switch's
    /// blocks are kept.
    fn spawn_clear_old_network_state(self: &Arc<Self>, env: &Env) -> JoinHandle<()> {
        let guard = Arc::clone(self);
        let state = env.state.clone();
        tokio::spawn(async move {
            let _ = state.clear_session_allowed_providers().await;
            if !guard.is_manual_killswitch() {
                let _ = state.clear_blocked_providers().await;
            }
        })
    }

    async fn handle_change_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        t0: Instant,
    ) {
        let unrouted = env.state.unrouted_providers().await;
        if unrouted.is_empty() {
            // All providers are routed: nothing flows over the changed network, no popup.
            inner.handled_ip = Some(new_ip);
            self.set_gate(Gate::Open);
            return;
        }

        // 1. Freeze everything immediately (unrouted traffic only; routed tunnels ignore the gate).
        //    A previous alert and its audit are withdrawn (new epoch).
        self.set_gate(Gate::Pending);
        self.abort_active_tunnels();
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }

        // Window first: everything it needs (old IP / country, new IP) is already known. A network
        // that is the pinned one may need no window at all (decided from the audit), so it keeps
        // the audit-first order below, as do the silent behaviors (they decide from the country).
        let behavior = env.state.get_interception_behavior().await;
        let pinned_new_ip = env
            .state
            .get_pinned_ip()
            .await
            .is_some_and(|p| p.trim() == new_ip.trim());
        if behavior == crate::state::InterceptionBehavior::AskPopup && !pinned_new_ip {
            self.alert_first(env, inner, new_ip, unrouted, t0).await;
            return;
        }

        // 2. Previous allowances / blocks belonged to the old network (the manual kill-switch's
        //    blocks do not).
        let _ = env.state.clear_session_allowed_providers().await;
        if !self.is_manual_killswitch() {
            let _ = env.state.clear_blocked_providers().await;
        }
        env.auditor.resolver.invalidate_cache().await;

        // 3. Full re-audit of the new network.
        let audited = tokio::time::timeout(env.audit_timeout, audit_all(&env.audit)).await;
        let Some(summary) = audited
            .ok()
            .and_then(|results| summarize(&results, &unrouted))
        else {
            eprintln!("Network guard: audit of the new network failed or timed out");
            return; // gate stays closed, next tick retries
        };

        let old = inner.baseline.clone();
        if old.as_ref().map(|b| b.ip.as_str()) == Some(new_ip.as_str())
            && inner.handled_ip.as_deref() == Some(new_ip.as_str())
        {
            return;
        }
        inner.handled_ip = Some(new_ip.clone());

        let AuditSummary {
            tray,
            worst,
            tel,
            all_green,
        } = summary;

        let pinned_ip = env.state.get_pinned_ip().await;
        let is_pinned = pinned_ip
            .as_deref()
            .map(|p| p.trim() == new_ip.trim() || p.trim() == tel.ip.trim())
            .unwrap_or(false);

        self.update_tray(env, &tray).await;

        // Returning to the trusted pinned VPS with a clean audit needs no confirmation.
        if is_pinned && all_green {
            self.accept_locked(env, inner, &new_ip, &tel).await;
            return;
        }

        // Respect preset InterceptionBehavior
        match behavior {
            crate::state::InterceptionBehavior::AutoLockSilent => {
                for p in &unrouted {
                    let _ = env.state.block_provider(p).await;
                }
                self.set_gate(Gate::Blocked);
                self.hide_popup(env);
                self.update_tray(env, &worst).await;
                env.emit("network://changed", &worst);
                return;
            }
            crate::state::InterceptionBehavior::AutoAllowTrusted => {
                let is_blocked = crate::is_sanctioned_or_blocked_country(&tel.country_code)
                    || tel.country_code.eq_ignore_ascii_case("HK")
                    || tel.country_code.eq_ignore_ascii_case("CN");
                if !is_blocked {
                    self.accept_locked(env, inner, &new_ip, &tel).await;
                    env.emit("network://changed", &worst);
                    return;
                } else {
                    for p in &unrouted {
                        let _ = env.state.block_provider(p).await;
                    }
                    self.set_gate(Gate::Blocked);
                    self.hide_popup(env);
                    self.update_tray(env, &worst).await;
                    env.emit("network://changed", &worst);
                    return;
                }
            }
            crate::state::InterceptionBehavior::AskPopup => {
                // proceed with hold_queue and the alert popup
            }
        }

        // 4. Ask the user (popup in configured corner without stealing focus), traffic stays frozen.
        //    The audit is complete already: the payload is `ready`.
        let id = Uuid::new_v4().to_string();
        let rx = env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
        let epoch = inner.epoch;
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            tel: Some(tel.clone()),
            clear_old_state: None,
        });

        let payload = RiskInterceptPayload {
            id: id.clone(),
            provider: worst.provider,
            host: "Смена сети · все ИИ-сервисы".to_string(),
            report: Some(worst.clone()),
            ttl_seconds: DEFAULT_HOLD_TTL_SECS,
            scope: "network".to_string(),
            network_change: Some(network_change(
                old.as_ref(),
                Some(tel.ip.clone()),
                Some(tel.country_code.clone()),
            )),
            is_simulation: false,
            detected_at_ms: now_unix_ms(),
            phase: PHASE_READY.to_string(),
        };

        env.hold_queue.set_alert(payload.clone());
        env.emit("interceptor://risk-detected", &payload);
        env.io.show_alert_popup(None);
        env.emit("network://changed", &worst);

        // 5. Wait for the decision in the background.
        self.spawn_decision_waiter(env, id, epoch, rx);
    }

    /// `AskPopup` and the new IP is not the pinned one: the gate is already `Pending`; emit the
    /// minimal payload and show the window NOW, then audit in the background.
    async fn alert_first(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        unrouted: Vec<&'static str>,
        t0: Instant,
    ) {
        let old = inner.baseline.clone();
        if old.as_ref().map(|b| b.ip.as_str()) == Some(new_ip.as_str())
            && inner.handled_ip.as_deref() == Some(new_ip.as_str())
        {
            return; // the user was already asked about exactly this network
        }
        inner.handled_ip = Some(new_ip.clone());

        // The audit must not see telemetry cached for the previous network. This is the last
        // await before the alert, its audit and its waiter all exist: a cancelled tick cannot
        // leave a window without an audit and without the TTL block.
        env.auditor.resolver.invalidate_cache().await;

        let id = Uuid::new_v4().to_string();
        let rx = env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
        let epoch = inner.epoch;
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            tel: None,
            clear_old_state: Some(self.spawn_clear_old_network_state(env)),
        });

        let provider = unrouted
            .iter()
            .find_map(|p| ProviderId::from_id(p))
            .unwrap_or(ProviderId::Anthropic);
        let payload = RiskInterceptPayload {
            id: id.clone(),
            provider,
            host: "Смена сети · все ИИ-сервисы".to_string(),
            report: None,
            ttl_seconds: DEFAULT_HOLD_TTL_SECS,
            scope: "network".to_string(),
            network_change: Some(network_change(old.as_ref(), Some(new_ip.clone()), None)),
            is_simulation: false,
            detected_at_ms: now_unix_ms(),
            phase: PHASE_DETECTING.to_string(),
        };

        log_timing(&id, "detected", t0);
        env.hold_queue.set_alert(payload.clone());
        env.emit("interceptor://risk-detected", &payload);
        log_timing(&id, "risk_detected_emitted", t0);
        env.io.show_alert_popup(Some((id.clone(), t0)));
        log_timing(&id, "popup_show_queued", t0);
        // Gate is Pending: the tray must not stay green while the window asks.
        env.io.tray_status("yellow", None);

        let audit_env = env.clone();
        let audit = tokio::spawn(async move { audit_all(&audit_env.audit).await });
        let audit_abort = audit.abort_handle();
        inner.audit_abort = Some(audit_abort.clone());

        let guard = Arc::clone(self);
        let env2 = env.clone();
        let id2 = id.clone();
        tokio::spawn(async move {
            let results = match tokio::time::timeout(env2.audit_timeout, audit).await {
                Ok(Ok(results)) => Some(results),
                Ok(Err(e)) => {
                    if !e.is_cancelled() {
                        eprintln!("Network guard: audit task ended abnormally: {e}");
                    }
                    None
                }
                Err(_) => {
                    audit_abort.abort();
                    eprintln!("Network guard: audit of the new network timed out");
                    None
                }
            };
            guard
                .finish_audit(&env2, &id2, epoch, new_ip, &unrouted, results, t0)
                .await;
        });

        self.spawn_decision_waiter(env, id, epoch, rx);
    }

    /// Delivers the result of the background audit. Applied only to the alert it was started for
    /// (same id and epoch); anything older is dropped. It never changes the gate.
    #[allow(clippy::too_many_arguments)]
    async fn finish_audit(
        &self,
        env: &Env,
        id: &str,
        epoch: u64,
        new_ip: String,
        unrouted: &[&'static str],
        results: Option<AuditResults>,
        t0: Instant,
    ) {
        let summary = results.and_then(|r| summarize(&r, unrouted));
        let mut inner = self.inner.lock().await;
        if !inner.is_current(id, epoch) {
            log_timing(id, "enriched_dropped_stale", t0);
            return;
        }
        let old = inner.baseline.clone();
        match summary {
            None => {
                // Fail-closed: the gate stays `Pending`, the window stays (and is not reopened);
                // the user can block, or the hold expires and blocks.
                let enriched = EnrichedPayload {
                    id: id.to_string(),
                    epoch,
                    phase: PHASE_FAILED.to_string(),
                    report: None,
                    network_change: network_change(old.as_ref(), Some(new_ip), None),
                };
                env.hold_queue.update_alert(&enriched);
                env.emit("interceptor://enriched", &enriched);
                env.io.tray_status("red", None);
                log_timing(id, "enriched_failed", t0);
            }
            Some(summary) => {
                let tel = summary.tel.clone();
                if let Some(p) = inner.pending.as_mut() {
                    p.tel = Some(tel.clone());
                }
                self.update_tray(env, &summary.tray).await;
                let enriched = EnrichedPayload {
                    id: id.to_string(),
                    epoch,
                    phase: PHASE_READY.to_string(),
                    report: Some(summary.worst.clone()),
                    network_change: network_change(
                        old.as_ref(),
                        Some(tel.ip.clone()),
                        Some(tel.country_code.clone()),
                    ),
                };
                env.hold_queue.update_alert(&enriched);
                env.emit("interceptor://enriched", &enriched);
                log_timing(id, "enriched_ready", t0);
                // After `enriched`: the main window starts its own audit on this event.
                env.emit("network://changed", &summary.worst);
            }
        }
    }

    /// Waits for the user's decision (or the hold TTL) and applies it, unless the alert was
    /// superseded meanwhile. Anything but an explicit `Allow` blocks.
    fn spawn_decision_waiter(
        self: &Arc<Self>,
        env: &Env,
        id: String,
        epoch: u64,
        rx: oneshot::Receiver<HoldResolution>,
    ) {
        let guard = Arc::clone(self);
        let env = env.clone();
        tokio::spawn(async move {
            let res = tokio::time::timeout(Duration::from_secs(DEFAULT_HOLD_TTL_SECS), rx).await;
            let allow = matches!(res, Ok(Ok(HoldResolution::Allow)));

            let mut inner = guard.inner.lock().await;
            if !inner.is_current(&id, epoch) {
                return; // superseded by a newer change or already accepted/restored
            }
            let pending = inner.invalidate_alert();
            env.hold_queue.remove(&id).await;
            let (tel, clear_old_state) = match pending {
                Some(p) => (p.tel, p.clear_old_state),
                None => (None, None),
            };
            if let Some(clear) = clear_old_state {
                // The old network's clean-up lands before anything this decision writes.
                let _ = clear.await;
            }

            // An allow is honoured only for a network that was audited (telemetry known). An
            // allow before / without the audit is NOT a decision about anything the user saw.
            if allow {
                if let Some(tel) = tel {
                    let ip = inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone());
                    guard.accept_locked(&env, &mut inner, &ip, &tel).await;
                    return;
                }
                eprintln!("Network guard: allow without a finished audit, traffic stays blocked");
            }
            for p in env.state.unrouted_providers().await {
                let _ = env.state.block_provider(p).await;
            }
            guard.set_gate(Gate::Blocked);
            guard.hide_popup(&env);
            guard.spawn_refresh_tray(&env);
        });
    }

    /// Confirms the current network as the new trusted baseline and resumes traffic.
    async fn accept_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        ip: &str,
        tel: &NetworkTelemetry,
    ) {
        inner.baseline = Some(Baseline {
            ip: ip.to_string(),
            country: Some(tel.country_code.clone()),
            trusted: true,
        });
        inner.handled_ip = None;
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }

        // Routed providers keep their own (route) history.
        let now = crate::auditor::network::current_timestamp();
        for p in env.state.unrouted_providers().await {
            let entry = IpHistoryEntry::new(tel.ip.clone(), tel.country_code.clone(), tel.asn, now);
            let _ = env.state.record_ip_history(p, entry).await;
        }

        self.set_gate(Gate::Open);
        self.hide_popup(env);
        env.emit("network://changed", &());
        self.spawn_refresh_tray(env);
    }

    /// The previous (trusted) IP is back: resume traffic.
    async fn restore_locked(self: &Arc<Self>, env: &Env, inner: &mut Inner) {
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        inner.handled_ip = None;
        env.auditor.resolver.invalidate_cache().await;
        if !self.is_manual_killswitch() {
            let _ = env.state.clear_blocked_providers().await;
        }
        self.set_gate(Gate::Open);
        self.hide_popup(env);
        env.emit("network://changed", &());
        self.spawn_refresh_tray(env);
    }

    /// Manual override from the main window ("Разблокировать и разрешить доступ").
    /// If the current network cannot be resolved, nothing is opened: the gate stays as it is
    /// (an unverifiable network is never confirmed by a side effect).
    pub async fn accept_current(self: &Arc<Self>) {
        let Some(env) = self.env.get() else {
            return;
        };
        // Only the explicit toggle lifts the manual kill-switch.
        if self.is_manual_killswitch() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if self.gate() == Gate::Open {
            return;
        }
        match env.resolve_telemetry().await {
            Ok(tel) => {
                let ip = inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone());
                self.accept_locked(env, &mut inner, &ip, &tel).await;
            }
            Err(e) => {
                eprintln!("Network guard: cannot confirm the network, gate stays closed: {e}")
            }
        }
    }

    /// The user's "allow" for the network alert `id` (command layer). Accepted only while that
    /// alert is still the current one (same id and epoch) AND its audit finished (`phase ==
    /// "ready"`); otherwise nothing is opened or written and an error goes back to the window.
    /// The session allowances for `providers` are written under the same lock, so a newer
    /// change cannot interleave between the check and the decision.
    pub async fn allow_network_alert(
        self: &Arc<Self>,
        id: &str,
        providers: &[String],
    ) -> Result<(), String> {
        let env = self.env.get().ok_or("network guard is not running")?;
        if self.is_manual_killswitch() {
            return Err("manual kill-switch is engaged".to_string());
        }
        let mut inner = self.inner.lock().await;
        let epoch = inner.epoch;
        if !inner.is_current(id, epoch) {
            return Err("this alert is no longer current".to_string());
        }
        let Some(tel) = inner.pending.as_ref().and_then(|p| p.tel.clone()) else {
            return Err("the network audit is not finished".to_string());
        };
        if let Some(clear) = inner
            .pending
            .as_mut()
            .and_then(|p| p.clear_old_state.take())
        {
            let _ = clear.await;
        }
        for p in providers {
            env.state
                .allow_provider_for_session(p)
                .await
                .map_err(|e| e.to_string())?;
        }
        let ip = inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone());
        self.accept_locked(env, &mut inner, &ip, &tel).await;
        Ok(())
    }

    fn hide_popup(&self, env: &Env) {
        env.io.hide_alert_popup();
        env.io.emit(
            "interceptor://resolved",
            serde_json::Value::String(String::new()),
        );
    }

    async fn update_tray(&self, env: &Env, report: &RiskReport) {
        let st = env.state.get_data().await;
        let is_pinned = st
            .pinned_ip
            .as_deref()
            .map(|p| p.trim() == report.telemetry.ip.trim())
            .unwrap_or(false);
        let held = self.gate() != Gate::Open || !st.blocked_providers.is_empty();
        env.io.tray_report(report, is_pinned, held);
    }

    /// Re-reads the status for the tray in the background (a full audit: 0.3-2 s must never be
    /// spent under `tick_lock` / `inner`).
    fn spawn_refresh_tray(self: &Arc<Self>, env: &Env) {
        let guard = Arc::clone(self);
        let env = env.clone();
        tokio::spawn(async move {
            if let Ok(report) = (env.audit)(ProviderId::Anthropic, false).await {
                guard.update_tray(&env, &report).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    use crate::auditor::CheckResult;
    use crate::state::InterceptionBehavior;
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
            let ev = self.events.lock().unwrap();
            ev.iter().find(|e| e.0 == name).map(|e| (e.1.clone(), e.2))
        }

        async fn wait_for(&self, name: &str, ms: u64) -> Option<(serde_json::Value, TInstant)> {
            let deadline = TInstant::now() + Duration::from_millis(ms);
            while TInstant::now() < deadline {
                if let Some(e) = self.first(name) {
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
            checks: vec![ok],
            unknown_count: 0,
            applicable_count: 12,
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

    #[tokio::test(start_paused = true)]
    async fn test_window_shown_before_slow_audit_and_events_are_ordered() {
        let h = harness(
            slow_audit(Duration::from_secs(2), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        let started = TInstant::now();
        h.change("9.9.9.9").await;

        // risk-detected comes out at once, long before the 2 s audit is done.
        let (detected, detected_at) =
            h.io.first("interceptor://risk-detected")
                .expect("risk-detected");
        assert!(detected_at.duration_since(started) <= Duration::from_millis(300));
        assert_eq!(detected["phase"], "detecting");
        assert!(detected["report"].is_null());
        assert_eq!(detected["scope"], "network");
        assert_eq!(detected["is_simulation"], false);
        assert!(detected["detected_at_ms"].as_u64().unwrap() > 0);
        assert_eq!(detected["network_change"]["old_ip"], "1.1.1.1");
        assert_eq!(detected["network_change"]["old_country"], "DE");
        assert_eq!(detected["network_change"]["new_ip"], "9.9.9.9");
        assert!(detected["network_change"]["new_country"].is_null());
        assert_eq!(h.io.shows.load(Ordering::SeqCst), 1);
        // The tray does not stay green while the gate is Pending.
        assert_eq!(
            h.io.trays.lock().unwrap().first().map(String::as_str),
            Some("yellow")
        );
        // The gate has been closed since detection; nothing is enriched yet.
        assert_eq!(h.guard.gate(), Gate::Pending);
        assert_eq!(h.io.count("interceptor://enriched"), 0);
        assert_eq!(h.io.count("network://changed"), 0);
        let snapshot = h
            .env
            .hold_queue
            .current_alert()
            .expect("take_pending_alert snapshot");
        assert_eq!(snapshot.phase, "detecting");
        assert!(snapshot.report.is_none());

        // Then the audit lands: risk-detected < enriched < network://changed.
        let enriched =
            h.io.wait_for("interceptor://enriched", 4000)
                .await
                .expect("enriched");
        assert_eq!(enriched.0["phase"], "ready");
        assert_eq!(enriched.0["id"], detected["id"]);
        assert!(enriched.0["epoch"].is_u64());
        assert_eq!(enriched.0["network_change"]["new_country"], "NL");
        assert!(enriched.0["report"].is_object());
        let changed =
            h.io.wait_for("network://changed", 1000)
                .await
                .expect("network://changed");
        assert!(detected_at <= enriched.1 && enriched.1 <= changed.1);
        let names = h.io.names();
        let pos = |n: &str| names.iter().position(|x| x == n).unwrap();
        assert!(pos("interceptor://risk-detected") < pos("interceptor://enriched"));
        assert!(pos("interceptor://enriched") < pos("network://changed"));
        // Still frozen: the audit does not decide anything.
        assert_eq!(h.guard.gate(), Gate::Pending);
        assert_eq!(h.io.shows.load(Ordering::SeqCst), 1);
        let snapshot = h.env.hold_queue.current_alert().expect("snapshot");
        assert_eq!(snapshot.phase, "ready");
        assert!(snapshot.report.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn test_stale_enriched_is_ignored() {
        let h = harness(
            slow_audit(Duration::from_millis(100), "9.9.9.9", OverallStatus::Yellow),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let first =
            h.io.first("interceptor://risk-detected")
                .expect("first alert");
        let first_id = alert_id(&first);
        let first_epoch = h.guard.inner.lock().await.epoch;

        // A newer change supersedes it (new id, new epoch).
        h.change("8.8.8.8").await;
        let second_epoch = h.guard.inner.lock().await.epoch;
        assert!(second_epoch > first_epoch);

        // Late result of the first alert: id no longer pending.
        h.guard
            .finish_audit(
                &h.env,
                &first_id,
                first_epoch,
                "9.9.9.9".into(),
                &["anthropic"],
                None,
                Instant::now(),
            )
            .await;
        // Current id but an old epoch: also dropped.
        let second_id = {
            let inner = h.guard.inner.lock().await;
            inner.pending.as_ref().expect("pending").id.clone()
        };
        h.guard
            .finish_audit(
                &h.env,
                &second_id,
                first_epoch,
                "8.8.8.8".into(),
                &["anthropic"],
                None,
                Instant::now(),
            )
            .await;
        assert_eq!(h.io.count("interceptor://enriched"), 0);

        // Only the current alert gets its enriched event.
        let enriched =
            h.io.wait_for("interceptor://enriched", 3000)
                .await
                .expect("enriched");
        assert_eq!(enriched.0["id"], second_id.as_str());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(h.io.count("interceptor://enriched"), 1);
        assert_eq!(h.guard.gate(), Gate::Pending);
    }

    #[tokio::test(start_paused = true)]
    async fn test_accept_cancels_inflight_audit() {
        let h = harness(
            slow_audit(Duration::from_millis(300), "9.9.9.9", OverallStatus::Yellow),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        {
            let mut inner = h.guard.inner.lock().await;
            let tel =
                test_report(ProviderId::Anthropic, OverallStatus::Green, "9.9.9.9", "NL").telemetry;
            h.guard
                .accept_locked(&h.env, &mut inner, "9.9.9.9", &tel)
                .await;
            assert!(inner.pending.is_none());
            assert!(inner.audit_abort.is_none());
        }
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(h.io.count("interceptor://enriched"), 0);
        assert_eq!(h.guard.gate(), Gate::Open);
        assert!(h.env.hold_queue.current_alert().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_pinned_ip_with_green_audit_shows_no_window() {
        let h = harness(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Green),
            "9.9.9.9",
        )
        .await;
        h.state
            .set_pinned_ip(Some("9.9.9.9".to_string()))
            .await
            .unwrap();
        h.change("9.9.9.9").await;
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
        assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
        assert_eq!(h.guard.gate(), Gate::Open);
        let inner = h.guard.inner.lock().await;
        assert_eq!(
            inner.baseline.as_ref().map(|b| b.ip.as_str()),
            Some("9.9.9.9")
        );
        assert!(inner.pending.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_silent_behavior_keeps_audit_first_order() {
        let h = harness(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Yellow),
            "9.9.9.9",
        )
        .await;
        h.state
            .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
            .await
            .unwrap();
        h.change("9.9.9.9").await;
        // No window; the decision came from the finished audit; traffic is blocked.
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
        assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
        assert_eq!(h.guard.gate(), Gate::Blocked);
        assert_eq!(h.io.count("network://changed"), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_audit_failure_keeps_gate_closed_and_does_not_reopen_window() {
        let failing: AuditFn = Arc::new(|_, _| Box::pin(async { Err("geo down".to_string()) }));
        let h = harness(failing, "9.9.9.9").await;
        h.change("9.9.9.9").await;

        let enriched =
            h.io.wait_for("interceptor://enriched", 3000)
                .await
                .expect("enriched");
        assert_eq!(enriched.0["phase"], "failed");
        assert_eq!(
            h.io.trays.lock().unwrap().last().map(String::as_str),
            Some("red")
        );
        assert!(enriched.0["report"].is_null());
        assert_eq!(enriched.0["network_change"]["new_ip"], "9.9.9.9");
        assert!(enriched.0["network_change"]["new_country"].is_null());
        // Fail-closed: still pending, not allowed to pass, no network://changed.
        assert_eq!(h.guard.gate(), Gate::Pending);
        let mut rx = h.guard.subscribe();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), wait_open(&mut rx))
                .await
                .is_err(),
            "traffic must keep waiting"
        );
        assert_eq!(h.io.count("network://changed"), 0);

        // The next tick sees the same network: no second window.
        let env = h.env.clone();
        h.guard.check_route_and_tick(&env).await;
        assert_eq!(h.io.count("interceptor://risk-detected"), 1);
        assert_eq!(h.io.shows.load(Ordering::SeqCst), 1);
        assert_eq!(h.guard.gate(), Gate::Pending);
        let snapshot = h.env.hold_queue.current_alert().expect("alert stays");
        assert_eq!(snapshot.phase, "failed");
    }

    #[tokio::test(start_paused = true)]
    async fn test_audit_timeout_is_a_failure() {
        let mut h = harness(
            slow_audit(Duration::from_secs(10), "9.9.9.9", OverallStatus::Green),
            "9.9.9.9",
        )
        .await;
        h.env.audit_timeout = Duration::from_millis(100);
        // Rebuild the guard around the shortened timeout.
        let guard = Arc::new(NetworkGuard::new());
        guard.install_env(h.env.clone());
        guard.inner.lock().await.baseline = h.guard.inner.lock().await.baseline.clone();
        h.guard = guard;
        h.change("9.9.9.9").await;
        let enriched =
            h.io.wait_for("interceptor://enriched", 2000)
                .await
                .expect("enriched");
        assert_eq!(enriched.0["phase"], "failed");
        assert_eq!(h.guard.gate(), Gate::Pending);
    }

    #[tokio::test(start_paused = true)]
    async fn test_decision_block_and_allow_after_enriched() {
        // Deny right away (audit still running): providers blocked, gate Blocked, popup hidden.
        let h = harness(
            slow_audit(Duration::from_millis(200), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let id = alert_id(&h.io.first("interceptor://risk-detected").unwrap());
        assert!(h.env.hold_queue.resolve(&id, HoldResolution::Block).await);
        for _ in 0..200 {
            if h.guard.gate() == Gate::Blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(h.guard.gate(), Gate::Blocked);
        for p in KNOWN_PROVIDERS {
            assert!(h.state.is_provider_blocked(p).await);
        }
        assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            h.io.count("interceptor://enriched"),
            0,
            "withdrawn alert gets no data"
        );

        // Allow after the audit is ready: baseline becomes the new network, gate opens.
        let h = harness(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Yellow),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let ev =
            h.io.wait_for("interceptor://enriched", 2000)
                .await
                .expect("enriched");
        let id = ev.0["id"].as_str().unwrap().to_string();
        assert!(h.env.hold_queue.resolve(&id, HoldResolution::Allow).await);
        for _ in 0..200 {
            if h.guard.gate() == Gate::Open {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(h.guard.gate(), Gate::Open);
        let inner = h.guard.inner.lock().await;
        assert_eq!(
            inner.baseline.as_ref().map(|b| b.ip.as_str()),
            Some("9.9.9.9")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_route_dirty_bypasses_probe_min_gap() {
        let h = harness(
            slow_audit(Duration::from_millis(10), "1.1.1.1", OverallStatus::Green),
            "1.1.1.1",
        )
        .await;
        let fp = compute_local_route_fingerprint(None);
        {
            let mut inner = h.guard.inner.lock().await;
            inner.last_route_fp = Some(fp);
            inner.last_probe = Some(Instant::now()); // a probe just ran: the min gap applies
        }
        let env = h.env.clone();

        // Nothing dirty: the min gap suppresses the probe.
        h.guard.check_route_and_tick(&env).await;
        assert_eq!(h.probes.load(Ordering::SeqCst), 0);

        // A CONNECT flagged the change (gate already closed): probed at once, gap ignored.
        h.guard.inner.lock().await.route_dirty = true;
        h.guard.set_gate(Gate::Pending);
        h.guard.check_route_and_tick(&env).await;
        assert_eq!(h.probes.load(Ordering::SeqCst), 1);
        assert!(!h.guard.inner.lock().await.route_dirty, "flag is consumed");
        // Probed IP == trusted baseline: the network did not really change.
        assert_eq!(h.guard.gate(), Gate::Open);
    }

    #[tokio::test(start_paused = true)]
    async fn test_route_dirty_with_new_ip_opens_window_immediately() {
        let h = harness(
            slow_audit(Duration::from_secs(1), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        {
            let mut inner = h.guard.inner.lock().await;
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
            inner.last_probe = Some(Instant::now());
            inner.route_dirty = true;
        }
        h.guard.set_gate(Gate::Pending);
        let started = TInstant::now();
        let env = h.env.clone();
        h.guard.check_route_and_tick(&env).await;
        assert!(started.elapsed() < Duration::from_millis(300));
        assert_eq!(h.io.count("interceptor://risk-detected"), 1);
        assert_eq!(h.guard.gate(), Gate::Pending);
    }

    #[tokio::test(start_paused = true)]
    async fn test_audit_all_forces_only_first_and_isolates_failures() {
        let calls: Arc<std::sync::Mutex<Vec<(ProviderId, bool)>>> = Arc::default();
        let calls2 = Arc::clone(&calls);
        let audit: AuditFn = Arc::new(move |provider, force| {
            calls2.lock().unwrap().push((provider, force));
            Box::pin(async move {
                if provider == ProviderId::Openai {
                    Err("openai down".to_string())
                } else {
                    Ok(test_report(provider, OverallStatus::Green, "9.9.9.9", "NL"))
                }
            })
        });
        let results = audit_all(&audit).await;
        let providers: Vec<ProviderId> = results.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            providers,
            vec![
                ProviderId::Anthropic,
                ProviderId::Openai,
                ProviderId::Gemini
            ]
        );
        assert!(results[0].1.is_ok() && results[1].1.is_err() && results[2].1.is_ok());
        let calls = calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .all(|(p, force)| *force == (*p == ProviderId::Anthropic))
        );
        assert_eq!(calls.len(), 3);
    }

    #[test]
    fn test_summarize_failure_rules() {
        let ok = |p| (p, Ok(test_report(p, OverallStatus::Green, "9.9.9.9", "NL")));
        let err = |p| (p, Err::<RiskReport, String>("x".to_string()));
        let all = ["anthropic", "openai", "gemini"];

        // The active (first unrouted) provider failed: the audit failed.
        let r = vec![
            err(ProviderId::Anthropic),
            ok(ProviderId::Openai),
            ok(ProviderId::Gemini),
        ];
        assert!(summarize(&r, &all).is_none());
        // ...but not when that provider is routed (not part of the changed network).
        let s = summarize(&r, &["openai", "gemini"]).expect("openai is the active one");
        assert!(s.all_green);

        // Another provider failed: the rest survives, but "all green" is no longer provable.
        let r = vec![
            ok(ProviderId::Anthropic),
            err(ProviderId::Openai),
            ok(ProviderId::Gemini),
        ];
        let s = summarize(&r, &all).expect("anthropic is the active one");
        assert!(!s.all_green);
        let s = summarize(&r, &["anthropic", "gemini"]).unwrap();
        assert!(s.all_green);
    }

    // ---- review fixes: stale probe, stale / premature allow, TTL, cancellation ----

    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn all_providers() -> Vec<String> {
        KNOWN_PROVIDERS.iter().map(|p| p.to_string()).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn test_stale_probe_never_opens_gate() {
        // The route moves (a CONNECT sees it) while the tick's probe is in flight, and the probe
        // still answers with the old, trusted baseline IP.
        let slot: Arc<std::sync::OnceLock<Arc<NetworkGuard>>> = Arc::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let (slot2, calls2) = (Arc::clone(&slot), Arc::clone(&calls));
        let h = harness_env(
            slow_audit(Duration::from_millis(50), "9.9.9.9", OverallStatus::Yellow),
            "1.1.1.1",
            move |env| {
                env.probe = Some(Arc::new(move || {
                    let first = calls2.fetch_add(1, Ordering::SeqCst) == 0;
                    let guard = slot2.get().cloned();
                    Box::pin(async move {
                        if first {
                            let g = guard.expect("guard");
                            assert!(g.check_route_fingerprint_sync(Some("moved")));
                            Some("1.1.1.1".to_string())
                        } else {
                            Some("9.9.9.9".to_string())
                        }
                    })
                }));
            },
        )
        .await;
        slot.set(Arc::clone(&h.guard)).ok();
        {
            let mut inner = h.guard.inner.lock().await;
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        }
        h.guard.set_gate(Gate::Pending);
        let env = h.env.clone();

        h.guard.check_route_and_tick(&env).await;
        assert_eq!(
            h.guard.gate(),
            Gate::Pending,
            "stale probe must not open the gate"
        );
        assert!(
            h.guard.inner.lock().await.route_dirty,
            "change stays flagged"
        );
        assert_eq!(h.io.count("network://changed"), 0);
        assert_eq!(h.io.hides.load(Ordering::SeqCst), 0);

        // The next tick handles the change at once and opens the window for the new network.
        h.guard.check_route_and_tick(&env).await;
        assert_eq!(h.io.count("interceptor://risk-detected"), 1);
        assert_eq!(h.guard.gate(), Gate::Pending);
    }

    #[tokio::test(start_paused = true)]
    async fn test_allow_for_superseded_alert_changes_nothing() {
        let h = harness(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Yellow),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let ev =
            h.io.wait_for("interceptor://enriched", 2000)
                .await
                .expect("enriched");
        let id1 = ev.0["id"].as_str().unwrap().to_string();

        // A new change C arrives; the user's allow for alert 1 reaches the guard afterwards.
        h.change("8.8.8.8").await;
        let err = h.guard.allow_network_alert(&id1, &all_providers()).await;
        assert!(err.is_err());
        assert_eq!(h.guard.gate(), Gate::Pending);
        let inner = h.guard.inner.lock().await;
        assert_eq!(
            inner.baseline.as_ref().map(|b| b.ip.as_str()),
            Some("1.1.1.1")
        );
        let id2 = inner.pending.as_ref().expect("alert 2 alive").id.clone();
        drop(inner);
        assert_ne!(id1, id2);
        assert_eq!(h.env.hold_queue.current_alert().map(|a| a.id), Some(id2));
        for p in KNOWN_PROVIDERS {
            assert!(!h.state.is_provider_blocked(p).await);
            assert!(!h.state.is_provider_session_allowed(p).await);
        }
        let mut rx = h.guard.subscribe();
        assert!(
            tokio::time::timeout(Duration::from_millis(80), wait_open(&mut rx))
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_network_allow_only_when_ready() {
        // detecting: refused, nothing changes.
        let h = harness(
            slow_audit(Duration::from_millis(300), "9.9.9.9", OverallStatus::Yellow),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let id = alert_id(&h.io.first("interceptor://risk-detected").unwrap());
        assert!(
            h.guard
                .allow_network_alert(&id, &all_providers())
                .await
                .is_err()
        );
        assert_eq!(h.guard.gate(), Gate::Pending);
        assert!(h.env.hold_queue.current_alert().is_some());
        assert!(!h.state.is_provider_session_allowed("anthropic").await);

        // ready: accepted, gate opens, session allowances written, alert gone.
        h.io.wait_for("interceptor://enriched", 2000)
            .await
            .expect("enriched");
        h.guard
            .allow_network_alert(&id, &all_providers())
            .await
            .expect("allowed");
        assert_eq!(h.guard.gate(), Gate::Open);
        assert!(h.state.is_provider_session_allowed("anthropic").await);
        assert!(h.env.hold_queue.current_alert().is_none());
        assert_eq!(
            h.guard
                .inner
                .lock()
                .await
                .baseline
                .as_ref()
                .map(|b| b.ip.as_str()),
            Some("9.9.9.9")
        );
        // The same allow again (stale id) is refused.
        assert!(
            h.guard
                .allow_network_alert(&id, &all_providers())
                .await
                .is_err()
        );

        // failed: refused as well, window and gate stay.
        let failing: AuditFn = Arc::new(|_, _| Box::pin(async { Err("geo down".to_string()) }));
        let h = harness(failing, "9.9.9.9").await;
        h.change("9.9.9.9").await;
        let ev =
            h.io.wait_for("interceptor://enriched", 3000)
                .await
                .expect("failed");
        assert_eq!(ev.0["phase"], "failed");
        let id = ev.0["id"].as_str().unwrap().to_string();
        assert!(
            h.guard
                .allow_network_alert(&id, &all_providers())
                .await
                .is_err()
        );
        assert_eq!(h.guard.gate(), Gate::Pending);
        assert!(h.env.hold_queue.current_alert().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn test_allow_without_audit_never_opens_gate() {
        // An allow that reaches the waiter before the audit finished is not honoured.
        let h = harness(
            slow_audit(Duration::from_secs(5), "9.9.9.9", OverallStatus::Yellow),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let id = alert_id(&h.io.first("interceptor://risk-detected").unwrap());
        assert!(h.env.hold_queue.resolve(&id, HoldResolution::Allow).await);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(h.guard.gate(), Gate::Blocked);
        assert_ne!(h.guard.gate(), Gate::Open);
        assert!(h.state.is_provider_blocked("anthropic").await);
        assert_eq!(
            h.guard
                .inner
                .lock()
                .await
                .baseline
                .as_ref()
                .map(|b| b.ip.as_str()),
            Some("1.1.1.1")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_accept_current_error_does_not_open_gate() {
        let tel =
            test_report(ProviderId::Anthropic, OverallStatus::Green, "9.9.9.9", "NL").telemetry;
        let ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ok2 = Arc::clone(&ok);
        let h = harness_env(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Yellow),
            "9.9.9.9",
            move |env| {
                env.resolve = Some(Arc::new(move || {
                    let tel = tel.clone();
                    let ok = ok2.load(Ordering::SeqCst);
                    Box::pin(async move {
                        if ok {
                            Ok(tel)
                        } else {
                            Err("offline".to_string())
                        }
                    })
                }));
            },
        )
        .await;
        h.change("9.9.9.9").await;
        let hides = h.io.hides.load(Ordering::SeqCst);

        h.guard.accept_current().await;
        assert_eq!(
            h.guard.gate(),
            Gate::Pending,
            "unverifiable network stays closed"
        );
        assert!(
            h.env.hold_queue.current_alert().is_some(),
            "alert is untouched"
        );
        assert_eq!(h.io.hides.load(Ordering::SeqCst), hides);

        ok.store(true, Ordering::SeqCst);
        h.guard.accept_current().await;
        assert_eq!(h.guard.gate(), Gate::Open);
    }

    #[tokio::test(start_paused = true)]
    async fn test_hold_ttl_blocks_a_ready_alert() {
        let h = harness(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Yellow),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        h.io.wait_for("interceptor://enriched", 2000)
            .await
            .expect("enriched");
        assert_eq!(h.guard.gate(), Gate::Pending);

        tokio::time::sleep(Duration::from_secs(DEFAULT_HOLD_TTL_SECS - 1)).await;
        assert_eq!(h.guard.gate(), Gate::Pending);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(h.guard.gate(), Gate::Blocked);
        assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
        for p in KNOWN_PROVIDERS {
            assert!(h.state.is_provider_blocked(p).await);
        }
        assert!(h.env.hold_queue.current_alert().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_default_audit_timeout_then_ttl_blocks() {
        // A hanging audit: failed after AUDIT_TIMEOUT_SECS, the hold TTL then blocks.
        let hanging: AuditFn = Arc::new(|_, _| Box::pin(std::future::pending()));
        let h = harness_env(hanging, "9.9.9.9", |env| {
            env.audit_timeout = Duration::from_secs(AUDIT_TIMEOUT_SECS);
        })
        .await;
        h.change("9.9.9.9").await;

        tokio::time::sleep(Duration::from_secs(AUDIT_TIMEOUT_SECS - 1)).await;
        assert_eq!(h.io.count("interceptor://enriched"), 0);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let failed =
            h.io.first("interceptor://enriched")
                .expect("failed after the timeout");
        assert_eq!(failed.0["phase"], "failed");
        assert_eq!(h.guard.gate(), Gate::Pending);

        tokio::time::sleep(Duration::from_secs(DEFAULT_HOLD_TTL_SECS)).await;
        assert_eq!(h.guard.gate(), Gate::Blocked);
        assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
        assert!(h.state.is_provider_blocked("anthropic").await);
    }

    #[tokio::test(start_paused = true)]
    async fn test_killswitch_mid_alert_really_cancels_the_audit() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let dropped2 = Arc::clone(&dropped);
        let audit: AuditFn = Arc::new(move |_, _| {
            let guard = DropCounter(Arc::clone(&dropped2));
            Box::pin(async move {
                let _guard = guard;
                std::future::pending().await
            })
        });
        let h = harness(audit, "9.9.9.9").await;
        h.change("9.9.9.9").await;
        tokio::time::sleep(Duration::from_millis(50)).await; // the three audits are running
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert!(h.env.hold_queue.current_alert().is_some());

        assert!(h.guard.set_manual_killswitch(true, &h.state).await);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            3,
            "the audit futures were dropped"
        );
        assert_eq!(h.guard.gate(), Gate::Blocked);
        assert!(h.env.hold_queue.current_alert().is_none());
        assert!(h.io.hides.load(Ordering::SeqCst) >= 1);

        tokio::time::sleep(Duration::from_secs(40)).await;
        assert_eq!(h.io.count("interceptor://enriched"), 0);
        assert_eq!(h.guard.gate(), Gate::Blocked);
    }
}
