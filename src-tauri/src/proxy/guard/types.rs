use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::Emitter;
use tokio::sync::{Mutex, watch};
use tokio::task::{AbortHandle, JoinHandle};

use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::{Auditor, NetworkTelemetry, RiskReport};
use crate::proxy::hold_queue::HoldQueue;
use crate::state::AppState;

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

/// Protection pause mode tracked by [`NetworkGuard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseMode {
    /// Active protection / normal operation (no global pause engaged).
    None,
    /// Traffic stays paused/blocked until the next network interface or exit IP change (or cache invalidation).
    UntilNetworkChange,
    /// Manual kill-switch: stays blocked across network changes until explicitly released.
    Manual,
}

/// Snapshot of [`NetworkGuard`]'s current gate, pause mode, and `gate_reason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardPauseStatus {
    pub paused: bool,
    pub mode: PauseMode,
    pub gate: String,
    pub gate_reason: Option<String>,
    pub manual_killswitch: bool,
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

pub(super) struct TauriIo {
    app: tauri::AppHandle,
}

impl GuardIo for TauriIo {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        let _ = self.app.emit(event, payload);
    }

    fn show_alert_popup(&self, timing: Option<(String, Instant)>) {
        crate::proxy::popup_port::show_alert_popup(&self.app, timing);
    }

    fn hide_alert_popup(&self) {
        crate::proxy::popup_port::hide_alert_popup(&self.app);
    }

    fn tray_report(&self, report: &RiskReport, is_pinned: bool, has_blocked: bool) {
        crate::proxy::popup_port::update_tray_from_report(
            &self.app,
            report,
            is_pinned,
            has_blocked,
        );
    }

    fn tray_status(&self, color: &str, title: Option<&str>) {
        crate::proxy::popup_port::update_tray_status(&self.app, color, title);
    }
}

/// Dependencies of the guard once it runs (built from [`GuardCtx`]; tests build their own).
#[derive(Clone)]
pub(crate) struct Env {
    pub(super) auditor: Auditor,
    pub(super) state: AppState,
    pub(super) hold_queue: Arc<HoldQueue>,
    pub(super) io: Arc<dyn GuardIo>,
    pub(super) audit: AuditFn,
    pub(super) probe: Option<ProbeFn>,
    pub(super) resolve: Option<ResolveFn>,
    pub(super) audit_timeout: Duration,
}

impl Env {
    pub(super) fn from_ctx(ctx: GuardCtx) -> Self {
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

    pub(super) async fn resolve_telemetry(&self) -> Result<NetworkTelemetry, String> {
        match &self.resolve {
            Some(resolve) => resolve().await,
            None => self.auditor.resolve_direct(false).await,
        }
    }

    pub(super) fn emit<T: Serialize>(&self, event: &str, payload: &T) {
        self.io.emit(
            event,
            serde_json::to_value(payload).unwrap_or(serde_json::Value::Null),
        );
    }
}

#[derive(Clone)]
pub(super) struct Baseline {
    pub(super) ip: String,
    pub(super) country: Option<String>,
    /// True only if the baseline was either user-confirmed or verified non-sanctioned.
    /// Prevents a VPN drop back to an initial sanctioned IP (e.g. RU at boot) from auto-opening the gate.
    pub(super) trusted: bool,
}

pub(super) struct Pending {
    pub(super) id: String,
    /// `Inner::epoch` at the moment this alert was registered.
    pub(super) epoch: u64,
    /// Target egress IP this pending audit / alert was started for (prevents 1s probe loops
    /// from aborting and restarting an in-flight audit for the same IP).
    pub(super) target_ip: String,
    /// Telemetry of the new network; `None` until the audit has finished (or when it failed).
    pub(super) tel: Option<NetworkTelemetry>,
    /// Background clean-up of the old network's session allowances. Whoever decides for this
    /// alert awaits it first, so the clean-up can never land after the decision's own writes.
    pub(super) clear_old_state: Option<JoinHandle<()>>,
    /// Newly affected enabled unrouted providers whose verdict requires blocking/holding.
    pub(super) affected_providers: Vec<&'static str>,
    /// Providers that were already blocked before this check (preserved if user allows newly affected ones).
    pub(super) already_blocked_providers: Vec<&'static str>,
    /// Enabled unrouted providers whose audit passed (`no_critical_and_geo_ok` or trusted exception).
    pub(super) healthy_providers: Vec<&'static str>,
    /// True once an alert popup has been emitted/queued to `HoldQueue` and UI.
    pub(super) alert_emitted: bool,
}

#[derive(Default)]
pub(super) struct Inner {
    pub(super) baseline: Option<Baseline>,
    pub(super) observed_ip: Option<String>,
    /// IP of the network the user has already been asked about (avoids popup loops).
    pub(super) handled_ip: Option<String>,
    pub(super) pending: Option<Pending>,
    pub(super) last_probe: Option<Instant>,
    pub(super) last_route_fp: Option<String>,
    /// Unrouted enabled providers seen on the previous tick (a provider becoming unrouted/enabled re-arms checks).
    pub(super) last_unrouted: Option<Vec<&'static str>>,
    /// Set when a provider unbinds its route or re-enables monitoring so same-IP ticks do not skip re-audit.
    pub(super) needs_reaudit: bool,
    /// Grows on every change / accept / restore / withdrawn alert. A background audit or a
    /// decision is applied only while its alert id AND epoch are still the current ones.
    pub(super) epoch: u64,
    /// `check_route_fingerprint_sync` saw the route change and already closed the gate: the next
    /// tick must handle it at once (no `PROBE_MIN_GAP_MS` wait).
    pub(super) route_dirty: bool,
    /// When `route_dirty` was raised (only for the `ZASTAVA_TIMING` log).
    pub(super) dirty_since: Option<Instant>,
    /// Background audit of the current alert (cancelled when the alert is superseded).
    pub(super) audit_abort: Option<AbortHandle>,
    /// Exit IP on which `PauseMode::UntilNetworkChange` was engaged (unchanged ticks stay paused).
    pub(super) paused_ip: Option<String>,
}

impl Inner {
    /// Withdraws the current alert: its id and epoch stop being valid, its audit is cancelled.
    /// The caller removes the returned alert from the hold queue.
    pub(super) fn invalidate_alert(&mut self) -> Option<Pending> {
        self.epoch = self.epoch.wrapping_add(1);
        if let Some(abort) = self.audit_abort.take() {
            abort.abort();
        }
        self.pending.take()
    }

    pub(super) fn is_current(&self, id: &str, epoch: u64) -> bool {
        self.epoch == epoch
            && self
                .pending
                .as_ref()
                .is_some_and(|p| p.id == id && p.epoch == epoch)
    }
}

pub struct NetworkGuard {
    pub(super) gate_tx: watch::Sender<Gate>,
    /// Per-provider automatic gates so a critical verdict on one unrouted provider does not
    /// freeze or block unrelated healthy providers.
    pub(super) provider_gates: HashMap<ProviderId, watch::Sender<Gate>>,
    pub(super) tunnel_abort_tx: watch::Sender<u64>,
    /// Manual kill-switch. Unlike the automatic gate it also stops routed providers.
    pub(super) kill_tx: watch::Sender<bool>,
    /// Process-exit tunnel abort flag: stops ALL tunnels (`FollowGate`, `KillSwitchOnly`, `transit_tunnel`).
    pub(super) shutdown_abort_tx: watch::Sender<bool>,
    /// Serialises every gate write with the kill flag: while the manual kill-switch is engaged the
    /// gate can never be anything but `Blocked`, no matter which task (tick, accept, restore,
    /// popup resolution) races with it.
    pub(super) gate_lock: std::sync::Mutex<()>,
    pub(super) pause_mode: std::sync::Mutex<PauseMode>,
    pub(super) gate_reason: std::sync::Mutex<Option<String>>,
    pub(super) inner: Mutex<Inner>,
    /// One route check at a time (as when `inner` was held across the probe): a CONNECT waits for
    /// the check in flight and then sees its verdict. `inner` itself is only held in short sections.
    pub(super) tick_lock: Mutex<()>,
    pub(super) env: OnceLock<Env>,
    pub(super) self_weak: OnceLock<Weak<NetworkGuard>>,
    pub(super) wake_notify: Arc<tokio::sync::Notify>,
    pub(super) loop_running: AtomicBool,
    /// Lock-free re-audit flag set by `kick_reaudit` / `sync_provider_route_change` /
    /// `sync_provider_monitoring_enabled` so signals are never dropped when `inner` is locked.
    pub(super) force_reaudit: AtomicBool,
    /// Lock-free queue of `(provider, routed)` route-change syncs applied as soon as `inner` is
    /// acquired (`plan_tick`, `finish_audit`, `sync_gates_with_state`, etc.).
    pub(super) pending_route_sync: std::sync::Mutex<HashMap<String, bool>>,
    /// Monotonic epoch bumped whenever the guard cleanly restores or accepts a network.
    /// Per-provider `HoldQueue` entries record this epoch on registration so expired 60s holds
    /// from an earlier network cannot re-block after recovery.
    pub(super) restore_epoch: AtomicU64,
    pub(super) client: reqwest::Client,
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

/// What the first (short, locked) part of a tick decided.
pub(super) enum TickPlan {
    Done,
    /// The route changed (or was reported changed by a CONNECT): probe at once, ignore the min gap.
    ProbeChanged(Instant, String),
    /// Regular periodic probe. Both carry the route fingerprint the plan was made for.
    ProbeRegular(String),
}
