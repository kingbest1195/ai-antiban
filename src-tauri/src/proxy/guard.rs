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

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::Emitter;
use tokio::sync::{Mutex, oneshot, watch};
use tokio::task::{AbortHandle, JoinHandle};
use uuid::Uuid;

use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::{Auditor, NetworkTelemetry, OverallStatus, RiskReport};
use crate::popup::log_timing;
use crate::proxy::allow_error::{AllowError, AllowErrorCode};
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, EnrichedPayload, HoldQueue, HoldResolution, NetworkChange,
    PHASE_DETECTING, PHASE_FAILED, PHASE_READY, RiskInterceptPayload, build_gate_reason,
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
            None => self.auditor.resolve_direct(false).await,
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
    /// Target egress IP this pending audit / alert was started for (prevents 1s probe loops
    /// from aborting and restarting an in-flight audit for the same IP).
    target_ip: String,
    /// Telemetry of the new network; `None` until the audit has finished (or when it failed).
    tel: Option<NetworkTelemetry>,
    /// Background clean-up of the old network's session allowances. Whoever decides for this
    /// alert awaits it first, so the clean-up can never land after the decision's own writes.
    clear_old_state: Option<JoinHandle<()>>,
    /// Newly affected enabled unrouted providers whose verdict requires blocking/holding.
    affected_providers: Vec<&'static str>,
    /// Providers that were already blocked before this check (preserved if user allows newly affected ones).
    already_blocked_providers: Vec<&'static str>,
    /// Enabled unrouted providers whose audit passed (`no_critical_and_geo_ok` or trusted exception).
    healthy_providers: Vec<&'static str>,
    /// True once an alert popup has been emitted/queued to `HoldQueue` and UI.
    alert_emitted: bool,
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
    /// Unrouted enabled providers seen on the previous tick (a provider becoming unrouted/enabled re-arms checks).
    last_unrouted: Option<Vec<&'static str>>,
    /// Set when a provider unbinds its route or re-enables monitoring so same-IP ticks do not skip re-audit.
    needs_reaudit: bool,
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
    /// Exit IP on which `PauseMode::UntilNetworkChange` was engaged (unchanged ticks stay paused).
    paused_ip: Option<String>,
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
    /// Per-provider automatic gates so a critical verdict on one unrouted provider does not
    /// freeze or block unrelated healthy providers.
    provider_gates: HashMap<ProviderId, watch::Sender<Gate>>,
    tunnel_abort_tx: watch::Sender<u64>,
    /// Manual kill-switch. Unlike the automatic gate it also stops routed providers.
    kill_tx: watch::Sender<bool>,
    /// Serialises every gate write with the kill flag: while the manual kill-switch is engaged the
    /// gate can never be anything but `Blocked`, no matter which task (tick, accept, restore,
    /// popup resolution) races with it.
    gate_lock: std::sync::Mutex<()>,
    pause_mode: std::sync::Mutex<PauseMode>,
    gate_reason: std::sync::Mutex<Option<String>>,
    inner: Mutex<Inner>,
    /// One route check at a time (as when `inner` was held across the probe): a CONNECT waits for
    /// the check in flight and then sees its verdict. `inner` itself is only held in short sections.
    tick_lock: Mutex<()>,
    env: OnceLock<Env>,
    self_weak: OnceLock<Weak<NetworkGuard>>,
    wake_notify: Arc<tokio::sync::Notify>,
    loop_running: AtomicBool,
    /// Lock-free re-audit flag set by `kick_reaudit` / `sync_provider_route_change` /
    /// `sync_provider_monitoring_enabled` so signals are never dropped when `inner` is locked.
    force_reaudit: AtomicBool,
    /// Lock-free queue of `(provider, routed)` route-change syncs applied as soon as `inner` is
    /// acquired (`plan_tick`, `finish_audit`, `sync_gates_with_state`, etc.).
    pending_route_sync: std::sync::Mutex<HashMap<String, bool>>,
    /// Monotonic epoch bumped whenever the guard cleanly restores or accepts a network.
    /// Per-provider `HoldQueue` entries record this epoch on registration so expired 60s holds
    /// from an earlier network cannot re-block after recovery.
    restore_epoch: AtomicU64,
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

pub(crate) fn is_blocked_geo_code(country_code: &str) -> bool {
    let cc = country_code.trim();
    crate::is_sanctioned_or_blocked_country(cc)
        || cc.eq_ignore_ascii_case("HK")
        || cc.eq_ignore_ascii_case("CN")
        || cc.eq_ignore_ascii_case("MO")
}

/// Returns `true` when `report` has an allowed, resolved exit country and zero critical
/// failures (non-critical Yellow warnings such as KZ, RS, Timezone, AI Studio warning remain acceptable).
pub(crate) fn report_no_critical_and_geo_ok(report: &RiskReport) -> bool {
    report.overall_status != OverallStatus::Red
        && !report.checks.iter().any(|c| c.status.is_critical())
        && !report.geo_result.status.is_critical()
        && !report.geo_result.status.is_unknown()
        && !is_blocked_geo_code(&report.telemetry.country_code)
}

/// True when `report` matches the provider's saved/routed pin on a non-sanctioned/non-blocked
/// country and has NO non-travel critical checks (so `IMPOSSIBLE_TRAVEL_CRITICAL` / `WARNING`
/// alone must not brand the pinned IP as Red/`"СТОП СЕТИ"`).
pub(crate) fn is_report_pinned_travel_only(
    report: &RiskReport,
    st: &crate::state::AppStateData,
) -> bool {
    let pid = report.provider.as_str();
    let routed = crate::routing::select_route_id(st, pid).is_some();
    let is_pinned = if routed {
        st.pinned_ip_for_provider(pid, true)
            .is_none_or(|pin| pin.trim() == report.telemetry.ip.trim())
    } else {
        st.pinned_ip_for_provider(pid, false)
            .is_some_and(|pin| pin.trim() == report.telemetry.ip.trim())
    };
    if !is_pinned {
        return false;
    }
    if is_blocked_geo_code(&report.telemetry.country_code)
        || report.geo_result.status.is_critical()
        || report.geo_result.status.is_unknown()
    {
        return false;
    }
    let is_travel_anomaly = |code: &str| {
        matches!(
            code,
            "IMPOSSIBLE_TRAVEL_CRITICAL" | "IMPOSSIBLE_TRAVEL_WARNING"
        )
    };
    let has_non_travel_critical = report
        .checks
        .iter()
        .any(|c| c.status.is_critical() && !is_travel_anomaly(&c.code))
        || (report.pinning_result.status.is_critical()
            && !is_travel_anomaly(&report.pinning_result.code))
        || report.dnsbl_result.status.is_critical()
        || report.asn_result.status.is_critical()
        || report.ipv6_result.status.is_critical();
    !has_non_travel_critical
}

/// True when `report` matches the provider's pinned IP and the ONLY failure preventing admission
/// is a transient `Unknown` geo check during `utun` stabilization (no critical checks and not
/// a globally sanctioned/blocked country).
fn is_pinned_transient_unknown_geo(
    report: &RiskReport,
    st: &crate::state::AppStateData,
    routed: bool,
) -> bool {
    let pid = report.provider.as_str();
    let matches_pin = st
        .pinned_ip_for_provider(pid, routed)
        .is_some_and(|pin| pin.trim() == report.telemetry.ip.trim());
    let has_non_travel_critical = report
        .checks
        .iter()
        .any(|c| c.status.is_critical() && c.code != "IMPOSSIBLE_TRAVEL_CRITICAL")
        || (report.pinning_result.status.is_critical()
            && report.pinning_result.code != "IMPOSSIBLE_TRAVEL_CRITICAL")
        || report.dnsbl_result.status.is_critical()
        || report.asn_result.status.is_critical()
        || report.ipv6_result.status.is_critical();
    matches_pin
        && report.geo_result.status.is_unknown()
        && !report.geo_result.status.is_critical()
        && !is_blocked_geo_code(&report.telemetry.country_code)
        && !has_non_travel_critical
}

/// Downgrades a `Red` report for tray display when traffic is actually flowing (`!has_blocked`):
/// - Returns `Green` (or `Yellow` if unrelated warnings exist) when returning to an explicitly
///   pinned non-sanctioned IP where `IMPOSSIBLE_TRAVEL_CRITICAL` / `WARNING` was the only issue.
/// - Downgrades `Red` -> `Yellow` when the user explicitly allowed the audited provider for the
///   session or via a persistent trusted exception.
pub(crate) fn effective_tray_report<'a>(
    report: &'a RiskReport,
    has_blocked: bool,
    st: &crate::state::AppStateData,
) -> std::borrow::Cow<'a, RiskReport> {
    if !has_blocked
        && matches!(report.overall_status, OverallStatus::Red | OverallStatus::Yellow)
        && is_report_pinned_travel_only(report, st)
    {
        let mut adjusted = report.clone();
        if crate::auditor::history::apply_pinned_travel_grace(&mut adjusted, true) {
            return std::borrow::Cow::Owned(adjusted);
        }
    }
    let allowed = st
        .session_allowed_providers
        .contains(report.provider.as_str())
        || st.is_ip_trusted_for_provider(report.provider.as_str(), &report.telemetry.ip);
    if !has_blocked && report.overall_status == OverallStatus::Red && allowed {
        let mut adjusted = report.clone();
        adjusted.overall_status = OverallStatus::Yellow;
        std::borrow::Cow::Owned(adjusted)
    } else {
        std::borrow::Cow::Borrowed(report)
    }
}

fn all_excepted(st: &crate::state::AppStateData, unrouted: &[&'static str], ip: &str) -> bool {
    !unrouted.is_empty()
        && unrouted
            .iter()
            .all(|p| st.is_ip_trusted_for_provider(p, ip))
}

fn all_pinned_or_excepted_for(
    st: &crate::state::AppStateData,
    unrouted: &[&'static str],
    ip: &str,
) -> bool {
    !unrouted.is_empty()
        && unrouted.iter().all(|p| {
            st.pinned_ip_for_provider(p, false)
                .is_some_and(|pin| pin.trim() == ip.trim())
                || st.is_ip_trusted_for_provider(p, ip)
        })
}

fn all_unrouted_session_or_excepted(
    unrouted: &[&'static str],
    st: &crate::state::AppStateData,
    ip: &str,
) -> bool {
    !unrouted.is_empty()
        && unrouted.iter().all(|p| {
            st.session_allowed_providers.contains(*p) || st.is_ip_trusted_for_provider(p, ip)
        })
}

async fn audit_one_with_retry(
    audit: &AuditFn,
    provider: ProviderId,
    force: bool,
) -> Result<RiskReport, String> {
    match audit(provider, force).await {
        Ok(r) => Ok(r),
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(400)).await;
            audit(provider, force).await
        }
    }
}

/// Audits enabled providers (each on its own egress) concurrently, each with 1 short retry for
/// transient VPN interface handshakes. Only the first enabled call forces a fresh geo lookup;
/// disabled providers are skipped completely.
async fn audit_enabled(audit: &AuditFn, disabled: &HashSet<String>) -> AuditResults {
    let enabled: Vec<ProviderId> = [
        ProviderId::Anthropic,
        ProviderId::Openai,
        ProviderId::Gemini,
    ]
    .into_iter()
    .filter(|p| {
        let pid = p.as_str();
        !disabled.iter().any(|d| {
            ProviderId::from_id(d.trim())
                .map(|dp| dp.as_str() == pid)
                .unwrap_or_else(|| d.trim().eq_ignore_ascii_case(pid))
        })
    })
    .collect();

    match enabled.as_slice() {
        [] => Vec::new(),
        [a] => vec![(*a, audit_one_with_retry(audit, *a, true).await)],
        [a, b] => {
            let (ra, rb) = tokio::join!(
                audit_one_with_retry(audit, *a, true),
                audit_one_with_retry(audit, *b, false),
            );
            vec![(*a, ra), (*b, rb)]
        }
        [a, b, c, ..] => {
            let (ra, rb, rc) = tokio::join!(
                audit_one_with_retry(audit, *a, true),
                audit_one_with_retry(audit, *b, false),
                audit_one_with_retry(audit, *c, false),
            );
            vec![(*a, ra), (*b, rb), (*c, rc)]
        }
    }
}

/// Audits anthropic, openai and gemini concurrently (all enabled).
#[allow(dead_code)]
async fn audit_all(audit: &AuditFn) -> AuditResults {
    audit_enabled(audit, &HashSet::new()).await
}

/// True when an individual provider's audit confirmed `Green` on an allowed egress country.
#[allow(dead_code)]
fn is_provider_healthy(res: &Result<RiskReport, String>) -> bool {
    match res {
        Ok(r) => {
            r.overall_status == OverallStatus::Green
                && !is_blocked_geo_code(&r.telemetry.country_code)
        }
        Err(_) => false,
    }
}

/// True when an individual provider has a critical risk, blocked country, or failed audit.
fn is_provider_critical_or_blocked(res: &Result<RiskReport, String>) -> bool {
    match res {
        Ok(r) => !report_no_critical_and_geo_ok(r),
        Err(_) => true,
    }
}

/// True when `report` permits traffic without blocking or alerting for `st`:
/// either `(provider, exit_ip)` is in `trusted_exceptions`, OR `no_critical_and_geo_ok`
/// (Green or non-critical Yellow without strict-pinning mismatch), OR the IP matches
/// `pinned_ip`/`pinned_ips[provider]` on an allowed geo with no non-travel critical checks.
pub(crate) fn report_allowed_for_state(
    report: &RiskReport,
    st: &crate::state::AppStateData,
    routed: bool,
) -> bool {
    let pid = report.provider.as_str();
    if st.is_ip_trusted_for_provider(pid, &report.telemetry.ip) {
        return true;
    }
    if report_no_critical_and_geo_ok(report) {
        if st.strict_pinning_enabled
            && let Some(pin) = st.pinned_ip_for_provider(pid, routed)
            && pin.trim() != report.telemetry.ip.trim()
        {
            return false;
        }
        return true;
    }
    let matches_pin = st
        .pinned_ip_for_provider(pid, routed)
        .is_some_and(|pin| pin.trim() == report.telemetry.ip.trim());
    let has_non_travel_critical = report
        .checks
        .iter()
        .any(|c| c.status.is_critical() && c.code != "IMPOSSIBLE_TRAVEL_CRITICAL");
    matches_pin
        && !is_blocked_geo_code(&report.telemetry.country_code)
        && !report.geo_result.status.is_critical()
        && !report.geo_result.status.is_unknown()
        && !has_non_travel_critical
}

/// True when an enabled unrouted provider's audit permits traffic without blocking or alerting.
fn provider_allowed_by_audit(
    _pid: &str,
    res: &Result<RiskReport, String>,
    st: &crate::state::AppStateData,
) -> bool {
    match res {
        Ok(r) => report_allowed_for_state(r, st, false),
        Err(_) => false,
    }
}

/// What the decision logic needs from an audit of the new network.
struct AuditSummary {
    /// Report for the tray (the first enabled report that succeeded).
    tray: RiskReport,
    /// The worst report among the providers that use the changed network.
    worst: RiskReport,
    tel: NetworkTelemetry,
    /// Every enabled unrouted provider was audited successfully and is green.
    #[allow(dead_code)]
    all_green: bool,
    /// Every enabled unrouted provider was audited successfully, geo is allowed, and zero critical issues.
    #[allow(dead_code)]
    no_critical_and_geo_ok: bool,
    /// Enabled unrouted providers permitted without blocking (`no_critical_and_geo_ok` / excepted / pinned-geo-ok).
    healthy_providers: Vec<&'static str>,
    /// Enabled unrouted providers with a non-excepted critical risk, blocked geo, or failed audit.
    affected_providers: Vec<&'static str>,
    /// Enabled unrouted providers with a critical issue (`Red`), blocked geo, or failed audit (excl. trusted exceptions).
    #[allow(dead_code)]
    critical_providers: Vec<&'static str>,
    /// Enabled unrouted providers whose audit call failed (`Err(...)`).
    #[allow(dead_code)]
    failed_providers: Vec<&'static str>,
    /// Successful reports keyed by provider id for selecting worst report of a subset.
    reports: HashMap<&'static str, RiskReport>,
}

impl AuditSummary {
    fn worst_for(&self, providers: &[&'static str]) -> RiskReport {
        providers
            .iter()
            .filter_map(|p| self.reports.get(p))
            .max_by_key(|r| severity(r))
            .cloned()
            .unwrap_or_else(|| self.worst.clone())
    }
}

#[allow(dead_code)]
fn summarize(results: &AuditResults, unrouted: &[&'static str]) -> Option<AuditSummary> {
    summarize_for_state(results, unrouted, &crate::state::AppStateData::default())
}

/// Returns `None` only when NO enabled unrouted provider produced a report (all failed or none
/// unrouted). Partial failures where the first provider fails while sibling providers succeed
/// preserve sibling results in `healthy_providers`/`affected_providers` and record the failure
/// in `failed_providers` / `affected_providers` / `critical_providers`.
fn summarize_for_state(
    results: &AuditResults,
    unrouted: &[&'static str],
    st: &crate::state::AppStateData,
) -> Option<AuditSummary> {
    let relevant_id = |p: &ProviderId| unrouted.contains(&p.as_str());
    let relevant: Vec<&RiskReport> = results
        .iter()
        .filter(|(p, _)| relevant_id(p))
        .filter_map(|(_, r)| r.as_ref().ok())
        .collect();
    let active_report = *relevant.first()?;

    let mut worst = active_report;
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
    let no_critical_and_geo_ok = !any_unrouted_failed
        && !relevant.is_empty()
        && relevant.iter().all(|r| report_no_critical_and_geo_ok(r));

    let mut healthy_providers = Vec::new();
    let mut affected_providers = Vec::new();
    let mut critical_providers = Vec::new();
    let mut failed_providers = Vec::new();
    let mut reports = HashMap::new();
    for (p, res) in results {
        let pid = p.as_str();
        if let Ok(r) = res {
            reports.insert(pid, r.clone());
        }
        if !unrouted.contains(&pid) {
            continue;
        }
        if res.is_err() {
            failed_providers.push(pid);
        }
        if provider_allowed_by_audit(pid, res, st) {
            healthy_providers.push(pid);
        } else {
            affected_providers.push(pid);
            if is_provider_critical_or_blocked(res) || st.strict_pinning_enabled {
                critical_providers.push(pid);
            }
        }
    }

    let tray = active_report.clone();
    let worst = worst.clone();
    let tel = worst.telemetry.clone();
    Some(AuditSummary {
        tray,
        worst,
        tel,
        all_green,
        no_critical_and_geo_ok,
        healthy_providers,
        affected_providers,
        critical_providers,
        failed_providers,
        reports,
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
        let mut provider_gates = HashMap::with_capacity(3);
        for p in [
            ProviderId::Anthropic,
            ProviderId::Openai,
            ProviderId::Gemini,
        ] {
            let (tx, _rx) = watch::channel(Gate::Open);
            provider_gates.insert(p, tx);
        }
        let (tunnel_abort_tx, _abort_rx) = watch::channel(0u64);
        let (kill_tx, _kill_rx) = watch::channel(false);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(2000))
            // Never reuse keep-alive sockets: they may still point to the previous route.
            .pool_max_idle_per_host(0)
            .user_agent(crate::auditor::network::NEUTRAL_USER_AGENT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            gate_tx,
            provider_gates,
            tunnel_abort_tx,
            kill_tx,
            gate_lock: std::sync::Mutex::new(()),
            pause_mode: std::sync::Mutex::new(PauseMode::None),
            gate_reason: std::sync::Mutex::new(None),
            inner: Mutex::new(Inner::default()),
            tick_lock: Mutex::new(()),
            env: OnceLock::new(),
            self_weak: OnceLock::new(),
            wake_notify: Arc::new(tokio::sync::Notify::new()),
            loop_running: AtomicBool::new(false),
            force_reaudit: AtomicBool::new(false),
            pending_route_sync: std::sync::Mutex::new(HashMap::new()),
            restore_epoch: AtomicU64::new(0),
            client,
        }
    }

    pub fn restore_epoch(&self) -> u64 {
        self.restore_epoch.load(Ordering::SeqCst)
    }

    fn register_self_weak(self: &Arc<Self>) {
        let _ = self.self_weak.set(Arc::downgrade(self));
    }

    pub fn gate(&self) -> Gate {
        *self.gate_tx.borrow()
    }

    /// Gate state for a specific provider (isolated from collateral blocks on sibling providers).
    pub fn gate_for(&self, provider: ProviderId) -> Gate {
        self.provider_gates
            .get(&provider)
            .map(|tx| *tx.borrow())
            .unwrap_or_else(|| self.gate())
    }

    pub fn any_provider_gate_closed(&self) -> bool {
        self.gate() != Gate::Open
            || self
                .provider_gates
                .values()
                .any(|tx| *tx.borrow() != Gate::Open)
    }

    pub fn any_provider_gate_blocked(&self) -> bool {
        self.gate() == Gate::Blocked
            || self
                .provider_gates
                .values()
                .any(|tx| *tx.borrow() == Gate::Blocked)
    }

    pub fn any_provider_gate_pending(&self) -> bool {
        self.gate() == Gate::Pending
            || self
                .provider_gates
                .values()
                .any(|tx| *tx.borrow() == Gate::Pending)
    }

    /// Wakes the background monitor loop without clearing `handled_ip`.
    pub fn wake(&self) {
        if self.loop_running.load(Ordering::SeqCst) {
            self.wake_notify.notify_one();
        }
    }

    pub fn pause_mode(&self) -> PauseMode {
        if self.is_manual_killswitch() {
            return PauseMode::Manual;
        }
        *self.pause_mode.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn gate_reason(&self) -> Option<String> {
        self.gate_reason
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn set_gate_reason(&self, reason: Option<String>) {
        let mut g = self.gate_reason.lock().unwrap_or_else(|p| p.into_inner());
        *g = reason;
    }

    fn set_pause_mode_raw(&self, mode: PauseMode) {
        let mut g = self.pause_mode.lock().unwrap_or_else(|p| p.into_inner());
        *g = mode;
    }

    pub fn pause_status(&self) -> GuardPauseStatus {
        let mode = self.pause_mode();
        let gate = match self.gate() {
            Gate::Open => "open",
            Gate::Pending => "pending",
            Gate::Blocked => "blocked",
        }
        .to_string();
        GuardPauseStatus {
            paused: mode != PauseMode::None,
            mode,
            gate,
            gate_reason: self.gate_reason(),
            manual_killswitch: self.is_manual_killswitch(),
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<Gate> {
        self.gate_tx.subscribe()
    }

    pub fn subscribe_for(&self, provider: ProviderId) -> watch::Receiver<Gate> {
        self.provider_gates
            .get(&provider)
            .map(|tx| tx.subscribe())
            .unwrap_or_else(|| self.gate_tx.subscribe())
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
        self.tunnel_abort_tx
            .send_modify(|val| *val = val.wrapping_add(1));
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
                g.paused_ip = None;
                if !self.is_manual_killswitch() {
                    let mut pm = self.pause_mode.lock().unwrap_or_else(|p| p.into_inner());
                    if *pm == PauseMode::UntilNetworkChange {
                        *pm = PauseMode::None;
                        drop(pm);
                        self.set_gate_reason(None);
                    }
                }
                self.set_gate(Gate::Pending);
                self.abort_active_tunnels();
                return true;
            }
        } else {
            g.last_route_fp = Some(fp);
        }
        false
    }

    /// Sets the gate for every provider and overall guard state. While the manual kill-switch is
    /// engaged every request is coerced to `Blocked`: `Open` (or `Pending`) cannot be set behind
    /// the kill-switch's back.
    fn set_gate(&self, gate: Gate) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        let effective = if *self.kill_tx.borrow() {
            Gate::Blocked
        } else {
            gate
        };
        self.gate_tx.send_replace(effective);
        for tx in self.provider_gates.values() {
            tx.send_replace(effective);
        }
    }

    /// Applies isolated per-provider gates after an audit:
    /// Synchronises per-provider and global gates against full `AppStateData` (respecting
    /// `disabled_providers`, routed providers, `blocked_providers`, and any `Pending` alert).
    fn sync_gates_with_state_and_pending(
        &self,
        st: &crate::state::AppStateData,
        pending: Option<&Pending>,
    ) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        if *self.kill_tx.borrow() {
            self.gate_tx.send_replace(Gate::Blocked);
            for tx in self.provider_gates.values() {
                tx.send_replace(Gate::Blocked);
            }
            return;
        }
        let mut any_open = false;
        let mut any_pending = false;
        for (pid, tx) in &self.provider_gates {
            let name = pid.as_str();
            let is_routed = crate::routing::select_route_id(st, name).is_some();
            if st.is_provider_disabled(name) || is_routed {
                tx.send_replace(Gate::Open);
                any_open = true;
            } else if st.blocked_providers.contains(name) {
                tx.send_replace(Gate::Blocked);
            } else if pending.is_some_and(|p| p.affected_providers.contains(&name)) {
                tx.send_replace(Gate::Pending);
                any_pending = true;
            } else {
                tx.send_replace(Gate::Open);
                any_open = true;
            }
        }
        let global = if any_open {
            Gate::Open
        } else if any_pending {
            Gate::Pending
        } else {
            Gate::Blocked
        };
        self.gate_tx.send_replace(global);
    }

    pub async fn sync_gates_with_state(&self, state: &AppState) {
        let mut inner = self.inner.lock().await;
        self.drain_pending_route_sync_locked(self.env.get(), &mut inner)
            .await;
        let st = state.get_data().await;
        self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
    }

    /// Returns enabled unrouted provider IDs currently blocked in either `state` or `provider_gates`.
    fn currently_blocked_set(&self, st: &crate::state::AppStateData) -> HashSet<String> {
        let mut blocked = HashSet::new();
        for p in st.enabled_unrouted_providers() {
            if st.blocked_providers.contains(p)
                || ProviderId::from_id(p).is_some_and(|pid| self.gate_for(pid) == Gate::Blocked)
            {
                blocked.insert(p.to_string());
            }
        }
        blocked
    }

    /// Freezes ONLY `freeze_providers` to `Gate::Pending` while preserving `already_blocked`
    /// at `Gate::Blocked` and keeping disabled/routed/healthy providers `Gate::Open`.
    fn freeze_providers_pending(
        &self,
        st: &crate::state::AppStateData,
        freeze_providers: &[&'static str],
        already_blocked: &HashSet<String>,
    ) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        if *self.kill_tx.borrow() {
            self.gate_tx.send_replace(Gate::Blocked);
            for tx in self.provider_gates.values() {
                tx.send_replace(Gate::Blocked);
            }
            return;
        }
        let mut any_open = false;
        let mut any_pending = false;
        for (pid, tx) in &self.provider_gates {
            let name = pid.as_str();
            let is_routed = crate::routing::select_route_id(st, name).is_some();
            if st.is_provider_disabled(name) || is_routed {
                tx.send_replace(Gate::Open);
                any_open = true;
            } else if already_blocked.contains(name) || st.blocked_providers.contains(name) {
                tx.send_replace(Gate::Blocked);
            } else if freeze_providers.contains(&name) {
                tx.send_replace(Gate::Pending);
                any_pending = true;
            } else {
                tx.send_replace(Gate::Open);
                any_open = true;
            }
        }
        let global = if any_open {
            Gate::Open
        } else if any_pending {
            Gate::Pending
        } else {
            Gate::Blocked
        };
        self.gate_tx.send_replace(global);
    }

    /// Returns the newly affected providers for an active network alert `id`, if present.
    pub async fn affected_providers_for_alert(&self, id: &str) -> Option<Vec<String>> {
        let mut inner = self.inner.lock().await;
        self.drain_pending_route_sync_locked(self.env.get(), &mut inner)
            .await;
        inner
            .pending
            .as_ref()
            .filter(|p| p.id == id)
            .map(|p| p.affected_providers.iter().map(|s| s.to_string()).collect())
    }

    /// Returns the most recently observed egress IP, if any.
    pub async fn current_observed_ip(&self) -> Option<String> {
        let inner = self.inner.lock().await;
        inner
            .observed_ip
            .clone()
            .or_else(|| inner.baseline.as_ref().map(|b| b.ip.clone()))
    }

    pub fn is_env_installed(&self) -> bool {
        self.env.get().is_some()
    }

    pub async fn has_baseline(&self) -> bool {
        self.inner.lock().await.baseline.is_some()
    }

    async fn drain_pending_route_sync_locked(&self, env: Option<&Env>, inner: &mut Inner) {
        let pending_sync: HashMap<String, bool> = {
            let mut map = self
                .pending_route_sync
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            std::mem::take(&mut *map)
        };
        if pending_sync.is_empty() {
            return;
        }
        for (provider, routed) in pending_sync {
            if routed {
                if !self.is_manual_killswitch()
                    && let Some(env) = env
                {
                    let _ = env.state.unblock_provider(&provider).await;
                    let resolved = env
                        .hold_queue
                        .resolve_all_for_provider(&provider, HoldResolution::Superseded)
                        .await;
                    if resolved > 0 && env.hold_queue.current_alert().is_none() {
                        self.hide_popup(env);
                    }
                }
                if let Some(p) = inner.pending.as_mut() {
                    p.affected_providers.retain(|x| *x != provider);
                    p.already_blocked_providers.retain(|x| *x != provider);
                    if p.affected_providers.is_empty()
                        && let Some(env) = env
                    {
                        let old_id = p.id.clone();
                        inner.invalidate_alert();
                        env.hold_queue.remove(&old_id).await;
                        self.hide_popup(env);
                        if !self.is_manual_killswitch() {
                            self.set_gate_reason(None);
                        }
                    }
                }
            } else {
                inner.handled_ip = None;
                inner.last_probe = None;
                inner.needs_reaudit = true;
            }
        }
    }

    /// Synchronises guard gates & audit state when `provider`'s route binding changes.
    /// When `routed == true`, opens `provider`'s gate (respecting manual kill-switch) and queues
    /// pending/blocked state cleanup lock-free so signals are never dropped when `inner` is held.
    /// When `routed == false`, resets gate/handled state and kicks an immediate re-audit so
    /// `provider` does not skip verification after unbinding.
    pub fn sync_provider_route_change(&self, provider: &str, routed: bool) {
        let canonical = ProviderId::from_id(provider).map(|p| p.as_str()).unwrap_or(provider);
        {
            let mut map = self
                .pending_route_sync
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            map.insert(canonical.to_string(), routed);
        }
        if routed {
            self.open_routed_providers(&[canonical]);
            if let Ok(mut inner) = self.inner.try_lock()
                && let Some(p) = inner.pending.as_mut()
            {
                p.affected_providers.retain(|x| *x != canonical);
                p.already_blocked_providers.retain(|x| *x != canonical);
            }
            if self.loop_running.load(Ordering::SeqCst) {
                self.wake_notify.notify_one();
            }
            return;
        }

        self.force_reaudit.store(true, Ordering::SeqCst);
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }
        if !self.is_manual_killswitch()
            && let Some(pid) = ProviderId::from_id(canonical)
            && let Some(tx) = self.provider_gates.get(&pid)
        {
            let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
            if !*self.kill_tx.borrow() {
                if self.env.get().is_some() {
                    tx.send_replace(Gate::Pending);
                } else {
                    tx.send_replace(Gate::Open);
                }
            }
        }
        self.kick_reaudit();
    }

    /// Kicks an immediate background guard check/re-audit (e.g. after route unbind, monitoring
    /// re-enable, or trusted exception removal). Uses an atomic `force_reaudit` flag so the
    /// signal is never dropped even when `self.inner` is actively locked by `check_route_and_tick`.
    pub fn kick_reaudit(&self) {
        self.force_reaudit.store(true, Ordering::SeqCst);
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }
        if self.loop_running.load(Ordering::SeqCst) {
            self.wake_notify.notify_one();
            return;
        }
        if let (Some(env), Some(guard_arc)) = (
            self.env.get().cloned(),
            self.self_weak.get().and_then(Weak::upgrade),
        ) && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                guard_arc.check_route_and_tick(&env).await;
            });
        }
    }

    /// Opens `provider`'s gate and removes it from any active pending alert when monitoring is
    /// disabled for that provider.
    pub async fn sync_provider_disabled(self: &Arc<Self>, provider: &str, state: &AppState) {
        let canonical = ProviderId::from_id(provider).map(|p| p.as_str()).unwrap_or(provider);
        self.open_routed_providers(&[canonical]);
        let mut inner = self.inner.lock().await;
        if let Some(p) = inner.pending.as_mut() {
            p.affected_providers.retain(|x| *x != canonical);
            p.already_blocked_providers.retain(|x| *x != canonical);
            if p.affected_providers.is_empty()
                && let Some(env) = self.env.get()
            {
                let old_id = p.id.clone();
                inner.invalidate_alert();
                env.hold_queue.remove(&old_id).await;
                self.hide_popup(env);
                self.set_gate_reason(None);
            }
        }
        let st = state.get_data().await;
        self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
        if let Some(env) = self.env.get() {
            let resolved = env
                .hold_queue
                .resolve_all_for_provider(canonical, HoldResolution::Superseded)
                .await;
            if resolved > 0 && env.hold_queue.current_alert().is_none() {
                self.hide_popup(env);
            }
            self.spawn_refresh_tray(env);
        }
    }

    /// Marks `needs_reaudit` and wakes the guard when a provider's monitoring is re-enabled.
    pub async fn sync_provider_monitoring_enabled(&self, _provider: &str) {
        self.force_reaudit.store(true, Ordering::SeqCst);
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }
        self.kick_reaudit();
    }

    /// Opens per-provider gates for providers that just moved onto a fixed route without
    /// disturbing unrouted providers' gates. Respects the manual kill-switch.
    pub fn open_routed_providers(&self, routed: &[&str]) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        if *self.kill_tx.borrow() {
            return;
        }
        for pid_str in routed {
            if let Some(pid) = ProviderId::from_id(pid_str)
                && let Some(tx) = self.provider_gates.get(&pid)
            {
                tx.send_replace(Gate::Open);
            }
        }
        if self
            .provider_gates
            .values()
            .all(|tx| *tx.borrow() == Gate::Open)
        {
            self.gate_tx.send_replace(Gate::Open);
        }
    }

    /// Test seam: sets the gate directly (e.g. `Pending`, which only a real network change sets).
    #[cfg(test)]
    pub(crate) fn set_gate_for_test(&self, gate: Gate) {
        self.set_gate(gate);
    }

    #[cfg(test)]
    pub(crate) fn install_noop_env_for_test(
        &self,
        auditor: Auditor,
        state: AppState,
        hold_queue: Arc<HoldQueue>,
    ) {
        struct NoopIo;
        impl GuardIo for NoopIo {
            fn emit(&self, _event: &str, _payload: serde_json::Value) {}
            fn show_alert_popup(&self, _timing: Option<(String, Instant)>) {}
            fn hide_alert_popup(&self) {}
            fn tray_report(&self, _report: &RiskReport, _is_pinned: bool, _has_blocked: bool) {}
            fn tray_status(&self, _color: &str, _title: Option<&str>) {}
        }
        let audit: AuditFn = Arc::new(|_provider, _force| {
            Box::pin(async move { Err("noop test audit".to_string()) })
        });
        let _ = self.install_env(Env {
            auditor,
            state,
            hold_queue,
            io: Arc::new(NoopIo),
            audit,
            probe: None,
            resolve: None,
            audit_timeout: Duration::from_secs(1),
        });
    }

    #[cfg(test)]
    pub(crate) async fn restore_for_test(self: &Arc<Self>) {
        if let Some(env) = self.env.get() {
            let mut inner = self.inner.lock().await;
            self.restore_locked(env, &mut inner).await;
        }
    }

    #[cfg(test)]
    pub(crate) fn bump_restore_epoch_for_test(&self) {
        self.restore_epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Engages the kill flag and blocks the gate as one step with respect to `set_gate`.
    fn engage_kill(&self) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.kill_tx.send_replace(true);
        self.set_pause_mode_raw(PauseMode::Manual);
        self.set_gate_reason(Some(
            "Включён ручной Kill-Switch — все ИИ-запросы остановлены".to_string(),
        ));
        self.gate_tx.send_replace(Gate::Blocked);
        for tx in self.provider_gates.values() {
            tx.send_replace(Gate::Blocked);
        }
    }

    /// Lifts the kill flag and opens the gate as one step with respect to `set_gate`.
    fn release_kill(&self) {
        let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.kill_tx.send_replace(false);
        self.set_pause_mode_raw(PauseMode::None);
        self.set_gate_reason(None);
        self.gate_tx.send_replace(Gate::Open);
        for tx in self.provider_gates.values() {
            tx.send_replace(Gate::Open);
        }
    }

    /// Puts the guard in `PauseMode::UntilNetworkChange`: unrouted AI traffic stays paused
    /// (`Gate::Blocked`) until the network interface/IP changes or `invalidate_cache` clears it.
    /// Does not override an active manual kill-switch.
    pub async fn pause_until_network_change(
        &self,
        state: &AppState,
        reason: Option<String>,
    ) -> GuardPauseStatus {
        if self.is_manual_killswitch() {
            return self.pause_status();
        }
        let cleaned_reason = reason
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "Защита поставлена на паузу до следующей смены сети".to_string());
        self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
        self.set_gate_reason(Some(cleaned_reason.clone()));
        self.abort_active_tunnels();

        let enabled_unrouted = state.enabled_unrouted_providers().await;
        for p in &enabled_unrouted {
            let _ = state.block_provider(p).await;
        }
        let st = state.get_data().await;
        {
            let mut inner = self.inner.lock().await;
            if let (Some(p), Some(env)) = (inner.invalidate_alert(), self.env.get()) {
                env.hold_queue.remove(&p.id).await;
            }
            let current_ip = inner
                .observed_ip
                .clone()
                .or_else(|| inner.baseline.as_ref().map(|b| b.ip.clone()));
            inner.paused_ip = current_ip.clone();
            if inner.handled_ip.is_none() {
                inner.handled_ip = current_ip;
            }
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
        }
        if let Some(env) = self.env.get() {
            self.hide_popup(env);
            env.io.tray_status("red", Some(&cleaned_reason));
        }
        self.pause_status()
    }

    /// Marks `PauseMode::UntilNetworkChange` when an alert is blocked until network change
    /// without clearing `blocked_providers` or overriding explicit target selections.
    pub async fn mark_paused_until_network_change(&self, reason: Option<String>) {
        if self.is_manual_killswitch() {
            return;
        }
        if let Some(r) = reason
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            self.set_gate_reason(Some(r));
        } else if self.gate_reason().is_none() {
            self.set_gate_reason(Some("Защита на паузе до следующей смены сети".to_string()));
        }
        self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
        let mut inner = self.inner.lock().await;
        let current_ip = inner
            .observed_ip
            .clone()
            .or_else(|| inner.pending.as_ref().map(|p| p.target_ip.clone()))
            .or_else(|| inner.handled_ip.clone())
            .or_else(|| inner.baseline.as_ref().map(|b| b.ip.clone()));
        inner.paused_ip = current_ip;
        if let Some(env) = self.env.get() {
            let st = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
        } else {
            self.set_gate(Gate::Blocked);
        }
    }

    fn clear_until_network_change_locked(&self, inner: &mut Inner) -> bool {
        if self.is_manual_killswitch() {
            return false;
        }
        let mut pm = self.pause_mode.lock().unwrap_or_else(|p| p.into_inner());
        let was_until_change = *pm == PauseMode::UntilNetworkChange;
        if was_until_change {
            *pm = PauseMode::None;
        }
        drop(pm);
        inner.paused_ip = None;
        if was_until_change {
            self.set_gate_reason(None);
        }
        was_until_change
    }

    /// Clears `PauseMode::UntilNetworkChange` on network change or cache invalidation.
    /// Never lifts a manual kill-switch. Returns `true` when an `UntilNetworkChange` pause was cleared.
    pub async fn clear_pause_on_network_change(
        &self,
        state: Option<&AppState>,
        open_gate_if_blocked: bool,
    ) -> bool {
        if self.is_manual_killswitch() {
            return false;
        }
        let cleared = {
            let mut inner = self.inner.lock().await;
            let cleared = self.clear_until_network_change_locked(&mut inner);
            if cleared {
                inner.handled_ip = None;
            }
            cleared
        };
        if cleared {
            if let Some(st) = state {
                let _ = st.clear_blocked_providers().await;
            }
            if open_gate_if_blocked && self.any_provider_gate_blocked() {
                self.set_gate(Gate::Open);
            }
        }
        cleared
    }

    /// Invalidates cached network telemetry and automatically clears any `UntilNetworkChange` pause.
    pub async fn invalidate_cache_and_clear_pause(
        &self,
        resolver: &crate::auditor::network::NetworkResolver,
        state: Option<&AppState>,
    ) -> bool {
        resolver.invalidate_cache().await;
        self.clear_pause_on_network_change(state, true).await
    }

    /// Clears automatic provider blocks, `PauseMode::UntilNetworkChange`, and pending alerts
    /// when `!is_manual_killswitch()`, opens gates, and triggers an immediate re-audit.
    /// Used when the user clicks "Снять СТОП СЕТИ" in the tray or UI while only automatic blocks
    /// (never the manual kill-switch) are active.
    pub async fn clear_stop_and_reaudit(&self, state: &AppState) {
        if self.is_manual_killswitch() {
            return;
        }
        {
            let mut inner = self.inner.lock().await;
            self.clear_until_network_change_locked(&mut inner);
            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
            if let (Some(p), Some(env)) = (inner.invalidate_alert(), self.env.get()) {
                env.hold_queue.remove(&p.id).await;
            }
            if let Some(env) = self.env.get() {
                env.hold_queue.cancel_all_superseded().await;
            }
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }
        self.set_gate_reason(None);
        let _ = state.clear_blocked_providers().await;
        let st = state.get_data().await;
        self.sync_gates_with_state_and_pending(&st, None);
        if let Some(env) = self.env.get() {
            self.hide_popup(env);
            env.io.tray_status("green", None);
        }
        self.kick_reaudit();
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
            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
            if let (Some(p), Some(env)) = (inner.invalidate_alert(), self.env.get()) {
                env.hold_queue.remove(&p.id).await;
            }
            if let Some(env) = self.env.get() {
                env.hold_queue.cancel_all_superseded().await;
            }
            inner.paused_ip = None;
            inner.handled_ip = None;
            inner.needs_reaudit = false;
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

    async fn await_gate_rx(mut rx: watch::Receiver<Gate>) -> Gate {
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

    /// Used by new CONNECT requests: waits for the user's decision while the gate is pending.
    pub async fn await_decision(&self) -> Gate {
        Self::await_gate_rx(self.gate_tx.subscribe()).await
    }

    /// Waits for a specific provider's gate decision while pending.
    pub async fn await_decision_for(&self, provider: ProviderId) -> Gate {
        Self::await_gate_rx(self.subscribe_for(provider)).await
    }

    /// Starts the background monitor (call once from the Tauri setup hook).
    pub fn start(self: &Arc<Self>, ctx: GuardCtx) {
        self.register_self_weak();
        if !self.install_env(Env::from_ctx(ctx)) {
            return;
        }
        self.start_loop();
    }

    #[cfg(test)]
    pub(crate) fn start_with_env(self: &Arc<Self>, env: Env) {
        self.register_self_weak();
        self.install_env(env);
        self.start_loop();
    }

    /// Integration-test seam: installs an offline [`Env`] wired to `auditor.evaluate_all`,
    /// optional `probe`, and optional `resolve` without starting a wall-clock background loop;
    /// drive ticks deterministically via [`Self::tick_test`] or `ensure_fresh`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn start_with_test_env(
        self: &Arc<Self>,
        auditor: Auditor,
        state: AppState,
        hold_queue: Arc<HoldQueue>,
        probe: Option<ProbeFn>,
        resolve: Option<ResolveFn>,
    ) {
        struct TestNoopIo;
        impl GuardIo for TestNoopIo {
            fn emit(&self, _event: &str, _payload: serde_json::Value) {}
            fn show_alert_popup(&self, _timing: Option<(String, Instant)>) {}
            fn hide_alert_popup(&self) {}
            fn tray_report(&self, _report: &RiskReport, _is_pinned: bool, _has_blocked: bool) {}
            fn tray_status(&self, _color: &str, _title: Option<&str>) {}
        }
        let audit_auditor = auditor.clone();
        let audit_state = state.clone();
        let audit: AuditFn = Arc::new(move |provider, force| {
            let (auditor, state) = (audit_auditor.clone(), audit_state.clone());
            Box::pin(async move { auditor.evaluate_all(provider, &state, force).await })
        });
        self.register_self_weak();
        let _ = self.install_env(Env {
            auditor,
            state,
            hold_queue,
            io: Arc::new(TestNoopIo),
            audit,
            probe,
            resolve,
            audit_timeout: Duration::from_secs(AUDIT_TIMEOUT_SECS),
        });
    }

    /// Deterministic integration-test driver for one full guard route/IP/audit tick.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn tick_test(self: &Arc<Self>) {
        self.register_self_weak();
        self.inner.lock().await.last_probe = None;
        if let Some(env) = self.env.get() {
            self.check_route_and_tick(env).await;
        }
    }

    fn start_loop(self: &Arc<Self>) {
        if self.loop_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let guard = Arc::clone(self);
        let task = async move {
            #[cfg(not(test))]
            let mut n: u64 = 0;
            loop {
                if let Some(env) = guard.env.get() {
                    guard.check_route_and_tick(env).await;
                    #[cfg(not(test))]
                    if n.is_multiple_of(20) {
                        let _ = tokio::task::spawn_blocking(|| {
                            crate::sysproxy::refresh_if_services_changed();
                            crate::sysproxy::reconcile_browser_pac_prefs(None);
                        })
                        .await;
                    }
                }
                #[cfg(not(test))]
                {
                    n = n.wrapping_add(1);
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(ROUTE_CHECK_INTERVAL_MS)) => {}
                    _ = guard.wake_notify.notified() => {}
                }
            }
        };
        #[cfg(not(test))]
        tauri::async_runtime::spawn(task);
        #[cfg(test)]
        tokio::spawn(task);
    }

    /// Stores the dependencies; `false` when they were already set.
    fn install_env(&self, env: Env) -> bool {
        self.env.set(env).is_ok()
    }

    /// Cheap pre-flight check used by every new CONNECT (no-op when the monitor is not running).
    pub async fn ensure_fresh(self: &Arc<Self>) {
        self.register_self_weak();
        if let Some(env) = self.env.get() {
            self.check_route_and_tick(env).await;
        }
    }

    /// Fetches the current egress IP (Cloudflare trace, falls back to ipify).
    async fn probe_ip(&self) -> Option<String> {
        if let Ok(resp) = self
            .client
            .get("https://1.1.1.1/cdn-cgi/trace")
            .send()
            .await
            && let Ok(text) = resp.text().await
        {
            for line in text.lines() {
                if let Some(val) = line.strip_prefix("ip=") {
                    let val = val.trim();
                    if val.parse::<IpAddr>().is_ok() {
                        return Some(val.to_string());
                    }
                }
            }
        }
        if let Ok(resp) = self.client.get("https://api.ipify.org").send().await
            && let Ok(text) = resp.text().await
        {
            let val = text.trim();
            if val.parse::<IpAddr>().is_ok() {
                return Some(val.to_string());
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
    async fn plan_tick(
        &self,
        env: &Env,
        current_fp: String,
        st_data: &crate::state::AppStateData,
        unrouted: &[&'static str],
    ) -> TickPlan {
        let mut inner = self.inner.lock().await;
        self.drain_pending_route_sync_locked(Some(env), &mut inner)
            .await;
        let dirty = std::mem::take(&mut inner.route_dirty);
        let dirty_since = inner.dirty_since.take();

        // A provider that just lost its route or re-enabled monitoring must be re-checked.
        let gained_unrouted = inner
            .last_unrouted
            .as_ref()
            .map(|prev| unrouted.iter().any(|p| !prev.contains(p)))
            .unwrap_or(false);
        if gained_unrouted {
            inner.handled_ip = None;
            inner.needs_reaudit = true;
        }
        inner.last_unrouted = Some(unrouted.to_vec());

        // Manual kill-switch: nothing to decide until the user lifts it.
        if self.is_manual_killswitch() {
            inner.last_route_fp = Some(current_fp);
            return TickPlan::Done;
        }

        // Every enabled provider has a fixed exit (or all disabled): local network changes are irrelevant.
        if unrouted.is_empty() {
            inner.last_route_fp = Some(current_fp);
            if self.gate() != Gate::Open
                || self.any_provider_gate_closed()
                || inner.pending.is_some()
                || env.hold_queue.has_active_non_sim_holds().await
            {
                self.restore_epoch.fetch_add(1, Ordering::SeqCst);
                inner.invalidate_alert();
                env.hold_queue.cancel_all_superseded().await;
                self.set_gate(Gate::Open);
                self.hide_popup(env);
            }
            return TickPlan::Done;
        }

        if self.force_reaudit.swap(false, Ordering::SeqCst) {
            inner.handled_ip = None;
            inner.last_probe = None;
            inner.needs_reaudit = true;
        }

        if st_data.split_tunnel_mode {
            // In split-tunnel / PAC mode, general interface / 1.1.1.1 jitter is expected:
            // never hold gates in `Gate::Pending` (keep any explicit `Blocked` providers synced),
            // and run telemetry probes on regular cadence.
            inner.last_route_fp = Some(current_fp.clone());
            if self.any_provider_gate_pending() {
                self.sync_gates_with_state_and_pending(st_data, None);
            }
            if let Some(t) = inner.last_probe
                && t.elapsed() < Duration::from_millis(PROBE_MIN_GAP_MS)
            {
                return TickPlan::Done;
            }
            return TickPlan::ProbeRegular(current_fp);
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
            // Immediately freeze ONLY non-already-blocked enabled unrouted providers (Pending).
            return TickPlan::ProbeChanged(dirty_since.unwrap_or_else(Instant::now), current_fp);
        }

        inner.last_route_fp = Some(current_fp.clone());

        if let Some(t) = inner.last_probe
            && t.elapsed() < Duration::from_millis(PROBE_MIN_GAP_MS)
        {
            return TickPlan::Done;
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
        self.register_self_weak();
        let _tick = self.tick_lock.lock().await;
        // Routes do not take part in the fingerprint: routed traffic has a fixed exit and is not
        // governed by the gate, and the probe below measures the direct egress only.
        let current_fp = compute_local_route_fingerprint(None);
        let st_data = env.state.get_data().await;
        let enabled_unrouted = st_data.enabled_unrouted_providers();
        if !self.is_manual_killswitch() {
            for p in KNOWN_PROVIDERS {
                if st_data.blocked_providers.contains(p) && !enabled_unrouted.contains(&p) {
                    let _ = env.state.unblock_provider(p).await;
                }
            }
        }
        // Capture before `plan_tick` transitions any gates.
        let was_blocked = self.any_provider_gate_blocked() || !st_data.blocked_providers.is_empty();

        match self
            .plan_tick(env, current_fp, &st_data, &enabled_unrouted)
            .await
        {
            TickPlan::Done => {}
            TickPlan::ProbeChanged(t0, planned_fp) => {
                let already_blocked = self.currently_blocked_set(&st_data);
                self.freeze_providers_pending(&st_data, &enabled_unrouted, &already_blocked);
                // 2. Probe external IP (no lock held: other tasks keep working meanwhile)
                let probed = self.probe(env).await;
                let mut inner = self.inner.lock().await;
                self.apply_changed_probe(env, &mut inner, probed, t0, &planned_fp, was_blocked)
                    .await;
            }
            TickPlan::ProbeRegular(planned_fp) => {
                let probed = self.probe(env).await;
                let mut inner = self.inner.lock().await;
                self.apply_regular_probe(env, &mut inner, probed, &planned_fp, was_blocked)
                    .await;
            }
        }
    }

    async fn unblock_disabled_and_routed(&self, env: &Env, st: &crate::state::AppStateData) {
        if self.is_manual_killswitch() {
            return;
        }
        let enabled_unrouted = st.enabled_unrouted_providers();
        for p in KNOWN_PROVIDERS {
            if st.blocked_providers.contains(p) && !enabled_unrouted.contains(&p) {
                let _ = env.state.unblock_provider(p).await;
            }
        }
    }

    /// Re-audits the baseline IP after a prior block, recovery, route unbind, or monitoring toggle.
    /// Silently clears `blocked_providers` and opens gates for any provider meeting
    /// `no_critical_and_geo_ok` (Green OR Yellow), matching `pinned_ip`/`pinned_ips[provider]`
    /// on allowed geo, or present in `trusted_exceptions[(provider, exit_ip)]`.
    /// Never pops up an alert when all violated enabled providers are already blocked, and never
    /// latches `handled_ip` or pops a failed-audit alert on transient audit errors.
    async fn verify_and_restore_baseline_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        baseline_ip: &str,
        was_blocked: bool,
    ) {
        if self.is_manual_killswitch() {
            self.set_gate(Gate::Blocked);
            return;
        }
        self.clear_until_network_change_locked(inner);
        inner.needs_reaudit = false;
        self.drain_pending_route_sync_locked(Some(env), inner).await;
        env.auditor.resolver.invalidate_direct_cache().await;
        let st_before = env.state.get_data().await;
        self.unblock_disabled_and_routed(env, &st_before).await;
        let enabled_unrouted = st_before.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            self.restore_locked(env, inner).await;
            return;
        }
        let was_blocked_set = self.currently_blocked_set(&st_before);

        let audited = tokio::time::timeout(
            env.audit_timeout,
            audit_enabled(&env.audit, &st_before.disabled_providers),
        )
        .await;
        let Some(summary) = audited
            .ok()
            .and_then(|results| summarize_for_state(&results, &enabled_unrouted, &st_before))
        else {
            self.drain_pending_route_sync_locked(Some(env), inner).await;
            let st_cur = env.state.get_data().await;
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            if was_blocked || self.any_provider_gate_closed() {
                self.sync_gates_with_state_and_pending(&st_cur, inner.pending.as_ref());
            }
            return;
        };

        for p in &summary.healthy_providers {
            if st_before.blocked_providers.contains(*p) {
                let _ = env.state.unblock_provider(p).await;
            }
        }

        if summary.affected_providers.is_empty() {
            if inner.baseline.is_none() {
                inner.baseline = Some(Baseline {
                    ip: baseline_ip.to_string(),
                    country: Some(summary.tel.country_code.clone()),
                    trusted: true,
                });
            } else if let Some(b) = inner.baseline.as_mut() {
                b.trusted = true;
                if b.country.is_none() {
                    b.country = Some(summary.tel.country_code.clone());
                }
            }
            let now = crate::auditor::network::current_timestamp();
            for p in &summary.healthy_providers {
                if let Some(r) = summary.reports.get(p)
                    && (report_no_critical_and_geo_ok(r)
                        || is_report_pinned_travel_only(r, &st_before))
                {
                    let entry = IpHistoryEntry::new(
                        r.telemetry.ip.clone(),
                        r.telemetry.country_code.clone(),
                        r.telemetry.asn,
                        now,
                    );
                    let _ = env
                        .state
                        .record_ip_history_for_selection(
                            p,
                            &crate::routing::RouteSelection::Direct,
                            entry,
                        )
                        .await;
                }
            }
            self.restore_locked(env, inner).await;
            self.update_tray(env, &summary.tray).await;
            return;
        }

        let already_blocked: Vec<&'static str> = summary
            .affected_providers
            .iter()
            .copied()
            .filter(|p| was_blocked_set.contains(*p))
            .collect();
        let newly_affected: Vec<&'static str> = summary
            .affected_providers
            .iter()
            .copied()
            .filter(|p| !already_blocked.contains(p))
            .collect();

        if newly_affected.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            if !summary.failed_providers.is_empty() {
                inner.handled_ip = None;
                inner.needs_reaudit = true;
            } else {
                inner.handled_ip = Some(baseline_ip.to_string());
            }
            for p in &already_blocked {
                if !st_before.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
            self.hide_popup(env);
            env.emit("network://changed", &summary.worst);
            self.update_tray(env, &summary.tray).await;
            return;
        }

        // Transient failures (`Err` / unknown geo during `utun` stabilization) on a saved pinned
        // IP must retry silently without blocking, alerting, or locking `PauseMode` onto `baseline_ip`.
        let is_transient_pinned_failure = |p: &str| -> bool {
            let is_pinned = st_before
                .pinned_ip_for_provider(p, false)
                .is_some_and(|pin| pin.trim() == baseline_ip.trim());
            if !is_pinned {
                return false;
            }
            summary.failed_providers.contains(&p)
                || summary
                    .reports
                    .get(p)
                    .is_some_and(|r| is_pinned_transient_unknown_geo(r, &st_before, false))
        };
        let has_transient_pinned = newly_affected.iter().any(|p| is_transient_pinned_failure(p));
        let newly_affected: Vec<&'static str> = newly_affected
            .into_iter()
            .filter(|p| !is_transient_pinned_failure(p))
            .collect();
        if newly_affected.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            for p in &already_blocked {
                if !st_before.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
            self.hide_popup(env);
            self.update_tray(env, &summary.tray).await;
            return;
        }

        // At least one currently allowed enabled non-excepted provider has a Critical violation or failed.
        let has_newly_report = newly_affected
            .iter()
            .any(|p| summary.reports.contains_key(p));
        let worst_newly = summary.worst_for(&newly_affected);
        match st_before.interception_behavior {
            crate::state::InterceptionBehavior::AutoLockSilent
            | crate::state::InterceptionBehavior::AutoAllowTrusted => {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                for p in &newly_affected {
                    let _ = env.state.block_provider(p).await;
                }
                for p in &already_blocked {
                    if !st_before.blocked_providers.contains(*p) {
                        let _ = env.state.block_provider(p).await;
                    }
                }
                let st_after = env.state.get_data().await;
                let all_blocked = enabled_unrouted
                    .iter()
                    .all(|p| st_after.blocked_providers.contains(*p));
                if all_blocked
                    && !self.is_manual_killswitch()
                    && summary.failed_providers.is_empty()
                    && !has_transient_pinned
                {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(baseline_ip.to_string());
                }
                if !summary.failed_providers.is_empty() || has_transient_pinned {
                    inner.handled_ip = None;
                    inner.needs_reaudit = true;
                } else {
                    inner.handled_ip = Some(baseline_ip.to_string());
                }
                self.sync_gates_with_state_and_pending(&st_after, None);
                self.hide_popup(env);
                if has_newly_report {
                    env.emit("network://changed", &worst_newly);
                }
                self.update_tray(env, &summary.tray).await;
            }
            crate::state::InterceptionBehavior::AskPopup => {
                if inner.handled_ip.as_deref() == Some(baseline_ip) || inner.pending.is_some() {
                    let st_after = env.state.get_data().await;
                    self.sync_gates_with_state_and_pending(&st_after, inner.pending.as_ref());
                    self.update_tray(env, &summary.tray).await;
                    return;
                }
                let old_baseline = inner.baseline.clone();
                let ip_owned = baseline_ip.to_string();
                if has_newly_report {
                    self.emit_ready_network_alert_locked(
                        env,
                        inner,
                        old_baseline.as_ref(),
                        ip_owned,
                        &summary,
                        &already_blocked,
                        &newly_affected,
                        None,
                        None,
                        Instant::now(),
                    )
                    .await;
                } else {
                    self.emit_failed_network_alert_locked(
                        env,
                        inner,
                        old_baseline.as_ref(),
                        ip_owned,
                        &already_blocked,
                        &newly_affected,
                        &summary.healthy_providers,
                        None,
                        Instant::now(),
                    )
                    .await;
                }
                if has_transient_pinned {
                    inner.needs_reaudit = true;
                }
                self.update_tray(env, &summary.tray).await;
            }
        }
    }

    /// Background verification spawned immediately after instant auto-recovery onto a verified
    /// baseline or pinned/excepted IP. Updates tray & Direct IP history; only re-blocks if a real
    /// non-travel critical violation (`Ok(Red)`) is reported for the restored network.
    fn spawn_verify_restored_baseline(self: &Arc<Self>, env: &Env, ip: String, epoch: u64) {
        let guard = Arc::clone(self);
        let env = env.clone();
        tokio::spawn(async move {
            let st_before = env.state.get_data().await;
            let enabled_unrouted = st_before.enabled_unrouted_providers();
            if enabled_unrouted.is_empty() {
                return;
            }
            let audited = tokio::time::timeout(
                env.audit_timeout,
                audit_enabled(&env.audit, &st_before.disabled_providers),
            )
            .await;
            let Ok(results) = audited else {
                let mut inner = guard.inner.lock().await;
                if inner.epoch == epoch
                    && !guard.is_manual_killswitch()
                    && inner.observed_ip.as_deref() == Some(ip.as_str())
                {
                    let st = env.state.get_data().await;
                    let cur_unrouted = st.enabled_unrouted_providers();
                    if all_pinned_or_excepted_for(&st, &cur_unrouted, &ip) {
                        inner.handled_ip = None;
                        inner.needs_reaudit = true;
                    }
                }
                return;
            };
            let mut inner = guard.inner.lock().await;
            if inner.epoch != epoch
                || guard.is_manual_killswitch()
                || inner.observed_ip.as_deref() != Some(ip.as_str())
            {
                return;
            }
            let st = env.state.get_data().await;
            let cur_unrouted = st.enabled_unrouted_providers();
            let Some(summary) = summarize_for_state(&results, &cur_unrouted, &st) else {
                if all_pinned_or_excepted_for(&st, &cur_unrouted, &ip) {
                    inner.handled_ip = None;
                    inner.needs_reaudit = true;
                }
                return;
            };
            guard.update_tray(&env, &summary.tray).await;
            let is_transient_pinned = |p: &str| -> bool {
                let is_pinned = st
                    .pinned_ip_for_provider(p, false)
                    .is_some_and(|pin| pin.trim() == ip.trim());
                if !is_pinned {
                    return false;
                }
                summary.failed_providers.contains(&p)
                    || summary
                        .reports
                        .get(p)
                        .is_some_and(|r| is_pinned_transient_unknown_geo(r, &st, false))
            };
            let any_transient_pinned = summary.affected_providers.iter().any(|p| is_transient_pinned(p));
            let real_violations: Vec<&'static str> = summary
                .affected_providers
                .iter()
                .copied()
                .filter(|p| !summary.failed_providers.contains(p) && !is_transient_pinned(p))
                .collect();
            if real_violations.is_empty() {
                if !summary.failed_providers.is_empty() || any_transient_pinned {
                    inner.handled_ip = None;
                    inner.needs_reaudit = true;
                } else if let Some(b) = inner.baseline.as_mut()
                    && b.ip == ip
                {
                    b.country = Some(summary.tel.country_code.clone());
                    b.trusted = true;
                }
                let now = crate::auditor::network::current_timestamp();
                for p in &summary.healthy_providers {
                    if let Some(r) = summary.reports.get(p)
                        && (report_no_critical_and_geo_ok(r)
                            || is_report_pinned_travel_only(r, &st))
                    {
                        let entry = IpHistoryEntry::new(
                            r.telemetry.ip.clone(),
                            r.telemetry.country_code.clone(),
                            r.telemetry.asn,
                            now,
                        );
                        let _ = env
                            .state
                            .record_ip_history_for_selection(
                                p,
                                &crate::routing::RouteSelection::Direct,
                                entry,
                            )
                            .await;
                    }
                }
                return;
            }

            let old = inner.baseline.clone();
            let empty_blocked = HashSet::new();
            guard
                .apply_audit_outcome_locked(
                    &env,
                    &mut inner,
                    ip,
                    old.as_ref(),
                    &results,
                    &empty_blocked,
                    None,
                    false,
                    None,
                    Instant::now(),
                )
                .await;
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_same_baseline_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        ip: &str,
        baseline_trusted: bool,
        baseline_country: Option<&str>,
        planned_fp: &str,
        was_blocked: bool,
        needs_reaudit: bool,
        returning_from_other_ip: bool,
    ) -> bool {
        if baseline_trusted {
            if needs_reaudit
                || self.any_provider_gate_closed()
                || inner.pending.is_some()
                || was_blocked
            {
                if self.probe_is_stale(inner, planned_fp) {
                    return true;
                }
                let country_ok = baseline_country.is_some_and(|c| !is_blocked_geo_code(c));
                if returning_from_other_ip
                    && !needs_reaudit
                    && country_ok
                    && !self.is_manual_killswitch()
                {
                    self.restore_locked(env, inner).await;
                    let epoch = inner.epoch;
                    self.spawn_verify_restored_baseline(env, ip.to_string(), epoch);
                } else {
                    self.verify_and_restore_baseline_locked(env, inner, ip, was_blocked)
                        .await;
                }
            } else {
                inner.handled_ip = None;
                let st = env.state.get_data().await;
                self.sync_gates_with_state_and_pending(&st, None);
            }
            return true;
        }

        let st = env.state.get_data().await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        if all_unrouted_session_or_excepted(&enabled_unrouted, &st, ip) {
            if let Some(b) = inner.baseline.as_mut() {
                b.trusted = true;
            }
            inner.handled_ip = None;
            if self.any_provider_gate_closed() || inner.pending.is_some() || was_blocked {
                if self.probe_is_stale(inner, planned_fp) {
                    return true;
                }
                self.restore_locked(env, inner).await;
            }
            return true;
        }

        if needs_reaudit || was_blocked {
            if self.probe_is_stale(inner, planned_fp) {
                return true;
            }
            self.verify_and_restore_baseline_locked(env, inner, ip, was_blocked)
                .await;
            return true;
        }

        // If the app booted on a sanctioned IP without prior blocks (`baseline.trusted == false`),
        // keep cold startup quiet (CONNECTs still enforce fail-closed in `server.rs`); only treat
        // returning to it from another IP as a network change!
        !returning_from_other_ip
    }

    /// The route fingerprint changed: decide what the probed IP means.
    async fn apply_changed_probe(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        probed: Option<String>,
        t0: Instant,
        planned_fp: &str,
        was_blocked: bool,
    ) {
        inner.last_probe = Some(Instant::now());
        let Some(new_ip) = probed else {
            self.abort_active_tunnels();
            env.auditor.resolver.invalidate_direct_cache().await;
            let old_country = inner
                .baseline
                .as_ref()
                .and_then(|b| b.country.clone())
                .unwrap_or_else(|| "??".to_string());
            env.state
                .stats()
                .record_intercepted("all", "NetworkGuard", "HELD", &old_country);
            return;
        };

        let needs_reaudit = std::mem::take(&mut inner.needs_reaudit);
        if inner.pending.as_ref().is_some_and(|p| p.target_ip == new_ip) && !needs_reaudit {
            let st = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
            return;
        }

        let prev_observed_ip = inner.observed_ip.replace(new_ip.clone());
        let prev_paused_ip = inner.paused_ip.clone();
        // Local network interface / route changed: clear temporary pause-until-network-change.
        let pause_cleared = self.clear_until_network_change_locked(inner);
        if pause_cleared {
            inner.handled_ip = None;
        }

        if let Some((baseline_ip, baseline_trusted, baseline_country)) = inner
            .baseline
            .as_ref()
            .map(|b| (b.ip.clone(), b.trusted, b.country.clone()))
            && baseline_ip == new_ip
        {
            let pending_other_ip = inner.pending.as_ref().is_some_and(|p| p.target_ip != new_ip);
            let observed_other_ip = prev_observed_ip
                .as_deref()
                .is_some_and(|prev| prev != new_ip.as_str());
            let paused_other_ip = prev_paused_ip
                .as_deref()
                .is_some_and(|prev| prev != new_ip.as_str());
            let returning_from_other_ip =
                pending_other_ip || observed_other_ip || paused_other_ip || pause_cleared;
            if self
                .handle_same_baseline_locked(
                    env,
                    inner,
                    &new_ip,
                    baseline_trusted,
                    baseline_country.as_deref(),
                    planned_fp,
                    was_blocked,
                    needs_reaudit,
                    returning_from_other_ip,
                )
                .await
            {
                return;
            }
        }

        if inner.handled_ip.as_deref() == Some(new_ip.as_str()) && !needs_reaudit {
            let st = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
            return;
        }

        self.handle_change_locked(env, inner, new_ip, t0).await;
    }

    /// Periodic probe without a route change.
    async fn apply_regular_probe(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        probed: Option<String>,
        planned_fp: &str,
        was_blocked: bool,
    ) {
        inner.last_probe = Some(Instant::now());
        let t0 = Instant::now();
        let Some(ip) = probed else {
            return; // offline: nothing to compare
        };

        let prev_paused_ip = inner.paused_ip.clone();
        let mut pinned_untrapped = false;
        // If user explicitly paused until the next network change on this exact IP, stay paused
        // until the external IP changes or route fingerprint invalidates — UNLESS this IP matches
        // saved `pinned_ip` / `pinned_ips` (and `!is_manual_killswitch()`), in which case we never
        // trap the pinned IP permanently and silently recover cleanly.
        if self.pause_mode() == PauseMode::UntilNetworkChange
            && prev_paused_ip.as_deref() == Some(ip.as_str())
            && !inner.needs_reaudit
            && !self.force_reaudit.load(Ordering::SeqCst)
        {
            let st_pause = env.state.get_data().await;
            let unrouted_pause = st_pause.enabled_unrouted_providers();
            let ip_matches_pin = !self.is_manual_killswitch()
                && !unrouted_pause.is_empty()
                && unrouted_pause.iter().all(|p| {
                    st_pause
                        .pinned_ip_for_provider(p, false)
                        .is_some_and(|pin| pin.trim() == ip.trim())
                });
            if !ip_matches_pin {
                inner.observed_ip = Some(ip);
                return;
            }
            pinned_untrapped = true;
            inner.needs_reaudit = true;
        }
        let prev_observed_ip = inner.observed_ip.replace(ip.clone());
        let pause_cleared = self.clear_until_network_change_locked(inner) || pinned_untrapped;
        if pause_cleared {
            inner.handled_ip = None;
        }

        if env.state.is_split_tunnel_mode().await {
            let prev_baseline_ip = inner.baseline.as_ref().map(|b| b.ip.clone());
            let ip_changed = prev_baseline_ip
                .as_deref()
                .is_some_and(|old| old != ip.as_str());
            if let Some(b) = inner.baseline.as_mut() {
                b.ip = ip;
                b.trusted = true;
            } else {
                inner.baseline = Some(Baseline {
                    ip,
                    country: None,
                    trusted: true,
                });
            }
            let needs_reaudit = std::mem::take(&mut inner.needs_reaudit);
            if !self.is_manual_killswitch()
                && (ip_changed || pause_cleared || needs_reaudit)
                && (was_blocked || self.any_provider_gate_closed() || inner.pending.is_some())
            {
                self.restore_locked(env, inner).await;
            } else {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                    self.hide_popup(env);
                }
                inner.handled_ip = None;
                let st = env.state.get_data().await;
                self.sync_gates_with_state_and_pending(&st, None);
            }
            return;
        }

        let Some((baseline_ip, baseline_trusted, baseline_country)) = inner
            .baseline
            .as_ref()
            .map(|b| (b.ip.clone(), b.trusted, b.country.clone()))
        else {
            // Startup baseline initialization: NEVER fire alert_first before auditing;
            // silently clear any stale persisted `blocked_providers` that now satisfy
            // `no_critical_and_geo_ok`, pinned IP, or `trusted_exceptions`.
            let st = env.state.get_data().await;
            self.unblock_disabled_and_routed(env, &st).await;
            let enabled_unrouted = st.enabled_unrouted_providers();
            let matches_pinned = !enabled_unrouted.is_empty()
                && enabled_unrouted.iter().all(|p| {
                    st.pinned_ip_for_provider(p, false)
                        .is_some_and(|pin| pin.trim() == ip.trim())
                });
            let matches_exception = all_excepted(&st, &enabled_unrouted, &ip);
            let country = env
                .auditor
                .resolve_direct(false)
                .await
                .ok()
                .map(|t| t.country_code);
            let country_ok = country
                .as_deref()
                .is_some_and(|c| !is_blocked_geo_code(c));
            let trusted = matches_pinned || matches_exception || country_ok;
            inner.baseline = Some(Baseline {
                ip: ip.clone(),
                country,
                trusted,
            });
            inner.needs_reaudit = false;
            let st_after = env.state.get_data().await;
            let still_blocked =
                !st_after.blocked_providers.is_empty() || self.any_provider_gate_blocked();
            if still_blocked && !self.is_manual_killswitch() {
                self.verify_and_restore_baseline_locked(env, inner, &ip, true)
                    .await;
            }
            return;
        };

        let needs_reaudit = std::mem::take(&mut inner.needs_reaudit);

        // Critical anti-starvation guard: if an audit or alert is already running/active for
        // this exact IP, regular 1s probes must NOT abort or restart it!
        if inner.pending.as_ref().is_some_and(|p| p.target_ip == ip) && !needs_reaudit {
            return;
        }

        if ip == baseline_ip {
            let pending_other_ip = inner.pending.as_ref().is_some_and(|p| p.target_ip != ip);
            let observed_other_ip = prev_observed_ip
                .as_deref()
                .is_some_and(|prev| prev != ip.as_str());
            let paused_other_ip = prev_paused_ip
                .as_deref()
                .is_some_and(|prev| prev != ip.as_str());
            let returning_from_other_ip =
                pending_other_ip || observed_other_ip || paused_other_ip || pause_cleared;
            if self
                .handle_same_baseline_locked(
                    env,
                    inner,
                    &ip,
                    baseline_trusted,
                    baseline_country.as_deref(),
                    planned_fp,
                    was_blocked,
                    needs_reaudit,
                    returning_from_other_ip,
                )
                .await
            {
                return;
            }
        }

        if inner.handled_ip.as_deref() == Some(ip.as_str()) && !needs_reaudit {
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

    /// Persists "the previous temporary session allowances belonged to the old network" in the
    /// background. Neither `trusted_exceptions` nor `blocked_providers` is cleared here:
    /// persistent exceptions always survive network switches, and `apply_audit_outcome_locked`
    /// keeps or silently unblocks `blocked_providers` based on the new network's audit.
    fn spawn_clear_old_network_state(self: &Arc<Self>, env: &Env) -> JoinHandle<()> {
        let state = env.state.clone();
        tokio::spawn(async move {
            let _ = state.clear_session_allowed_providers().await;
        })
    }

    fn collect_was_blocked_set(
        &self,
        inner: &Inner,
        st: &crate::state::AppStateData,
    ) -> HashSet<String> {
        let mut set = self.currently_blocked_set(st);
        if let Some(p) = inner.pending.as_ref() {
            for b in &p.already_blocked_providers {
                set.insert((*b).to_string());
            }
        }
        set
    }

    async fn handle_change_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        t0: Instant,
    ) {
        self.drain_pending_route_sync_locked(Some(env), inner).await;
        let st = env.state.get_data().await;
        self.unblock_disabled_and_routed(env, &st).await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            // Every enabled provider is routed (or all providers disabled): local network change
            // does not trigger alerts or block traffic.
            let had_alert = inner.invalidate_alert().is_some()
                || env.hold_queue.has_active_non_sim_holds().await;
            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
            let cancelled = env.hold_queue.cancel_all_superseded().await;
            inner.handled_ip = Some(new_ip);
            inner.needs_reaudit = false;
            self.sync_gates_with_state_and_pending(&st, None);
            if had_alert || cancelled > 0 {
                self.hide_popup(env);
            }
            return;
        }

        let old = inner.baseline.clone();
        // Never abort/restart an in-flight audit or already-handled check for the exact same IP
        // unless `needs_reaudit` was explicitly armed (e.g. route unbind / exception removed).
        if !inner.needs_reaudit
            && (inner.pending.as_ref().is_some_and(|p| p.target_ip == new_ip)
                || (old.as_ref().map(|b| b.ip.as_str()) == Some(new_ip.as_str())
                    && inner.handled_ip.as_deref() == Some(new_ip.as_str())))
        {
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
            return;
        }

        // Fast-path 1: every enabled unrouted provider has an explicit persistent trusted exception
        // for `new_ip` -> immediately open/restore without interrupting traffic or showing a popup.
        if all_excepted(&st, &enabled_unrouted, &new_ip) {
            inner.baseline = Some(Baseline {
                ip: new_ip.clone(),
                country: None,
                trusted: true,
            });
            self.restore_locked(env, inner).await;
            let epoch = inner.epoch;
            self.spawn_verify_restored_baseline(env, new_ip, epoch);
            return;
        }

        // Fast-path 2: return-to-pinned IP for all enabled unrouted providers whose geo is already
        // known non-sanctioned -> recover immediately without flashing Gate::Pending or popup.
        let all_pinned = all_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);
        if all_pinned {
            self.clear_until_network_change_locked(inner);
            let cached_cc = env.auditor.resolver.cached_direct_country(&new_ip).await;
            if cached_cc.as_deref().is_some_and(|c| !is_blocked_geo_code(c)) {
                inner.baseline = Some(Baseline {
                    ip: new_ip.clone(),
                    country: cached_cc,
                    trusted: true,
                });
                self.restore_locked(env, inner).await;
                let epoch = inner.epoch;
                self.spawn_verify_restored_baseline(env, new_ip, epoch);
                return;
            }
        }

        // Capture which enabled unrouted providers are ALREADY blocked before touching gates,
        // then freeze ONLY allowed enabled unrouted providers to Pending while auditing runs.
        let was_blocked_set = self.collect_was_blocked_set(inner, &st);
        let already_blocked_vec: Vec<&'static str> = enabled_unrouted
            .iter()
            .copied()
            .filter(|p| was_blocked_set.contains(*p))
            .collect();
        let non_blocked: Vec<&'static str> = enabled_unrouted
            .iter()
            .copied()
            .filter(|p| !was_blocked_set.contains(*p))
            .collect();

        self.freeze_providers_pending(&st, &non_blocked, &was_blocked_set);
        self.abort_active_tunnels();
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        env.auditor.resolver.invalidate_direct_cache().await;

        if !non_blocked.is_empty() {
            let old_country = old
                .as_ref()
                .and_then(|b| b.country.clone())
                .unwrap_or_else(|| "??".to_string());
            env.state
                .stats()
                .record_intercepted("all", "NetworkGuard", "HELD", &old_country);
        }

        // Instant alert-first for AskPopup when at least one enabled unrouted provider was open
        // and the new IP is not pinned/excepted; silent/pinned modes keep zero popup and load
        // the audit asynchronously under `Pending.target_ip` protection (no 1s probe starvation!).
        if st.interception_behavior == crate::state::InterceptionBehavior::AskPopup
            && !all_pinned
            && !non_blocked.is_empty()
        {
            self.alert_first_locked(
                env,
                inner,
                new_ip,
                &old,
                &enabled_unrouted,
                &non_blocked,
                &already_blocked_vec,
                t0,
            )
            .await;
            return;
        }

        if all_pinned {
            self.hide_popup(env);
        }
        self.spawn_silent_audit_locked(
            env,
            inner,
            new_ip,
            &st,
            &enabled_unrouted,
            &non_blocked,
            &already_blocked_vec,
            all_pinned,
            t0,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn alert_first_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        old_baseline: &Option<Baseline>,
        enabled_unrouted: &[&'static str],
        non_blocked: &[&'static str],
        already_blocked: &[&'static str],
        t0: Instant,
    ) {
        inner.handled_ip = Some(new_ip.clone());
        inner.needs_reaudit = false;

        let id = Uuid::new_v4().to_string();
        let rx = env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
        let epoch = inner.epoch;
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            target_ip: new_ip.clone(),
            tel: None,
            clear_old_state: Some(self.spawn_clear_old_network_state(env)),
            affected_providers: non_blocked.to_vec(),
            already_blocked_providers: already_blocked.to_vec(),
            healthy_providers: Vec::new(),
            alert_emitted: true,
        });

        let provider = non_blocked
            .iter()
            .find_map(|p| ProviderId::from_id(p))
            .unwrap_or(ProviderId::Anthropic);
        let net_change = network_change(old_baseline.as_ref(), Some(new_ip.clone()), None);
        let reason = build_gate_reason(None, Some(&net_change), false);
        self.set_gate_reason(Some(reason.clone()));
        let payload = RiskInterceptPayload {
            id: id.clone(),
            provider,
            host: "Смена сети · все ИИ-сервисы".to_string(),
            report: None,
            ttl_seconds: DEFAULT_HOLD_TTL_SECS,
            scope: "network".to_string(),
            network_change: Some(net_change),
            is_simulation: false,
            detected_at_ms: now_unix_ms(),
            phase: PHASE_DETECTING.to_string(),
            gate_reason: Some(reason),
        };

        log_timing(&id, "detected", t0);
        env.hold_queue.set_alert(payload.clone());
        env.emit("interceptor://risk-detected", &payload);
        log_timing(&id, "risk_detected_emitted", t0);
        env.io.show_alert_popup(Some((id.clone(), t0)));
        log_timing(&id, "popup_show_queued", t0);
        env.io.tray_status("yellow", None);

        let st = env.state.get_data().await;
        self.spawn_background_audit_task(
            env,
            inner,
            id.clone(),
            epoch,
            new_ip,
            enabled_unrouted.to_vec(),
            st.disabled_providers,
            t0,
        );
        self.spawn_decision_waiter(env, id, epoch, rx);
    }

    #[allow(clippy::too_many_arguments)]
    async fn spawn_silent_audit_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        st: &crate::state::AppStateData,
        enabled_unrouted: &[&'static str],
        non_blocked: &[&'static str],
        already_blocked: &[&'static str],
        all_pinned: bool,
        t0: Instant,
    ) {
        inner.needs_reaudit = false;
        let id = Uuid::new_v4().to_string();
        let epoch = inner.epoch;
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            target_ip: new_ip.clone(),
            tel: None,
            clear_old_state: Some(self.spawn_clear_old_network_state(env)),
            affected_providers: non_blocked.to_vec(),
            already_blocked_providers: already_blocked.to_vec(),
            healthy_providers: Vec::new(),
            alert_emitted: false,
        });

        if !non_blocked.is_empty() {
            if all_pinned {
                env.io.tray_status("yellow", None);
            } else {
                match st.interception_behavior {
                    crate::state::InterceptionBehavior::AutoLockSilent => {
                        self.set_gate_reason(Some(
                            "Смена сети — трафик приостановлен на время проверки".to_string(),
                        ));
                        env.io.tray_status("red", None);
                    }
                    crate::state::InterceptionBehavior::AutoAllowTrusted
                    | crate::state::InterceptionBehavior::AskPopup => {
                        self.set_gate_reason(Some(
                            "Смена сети — проверяем безопасность подключения".to_string(),
                        ));
                        env.io.tray_status("yellow", None);
                    }
                }
            }
        }

        self.spawn_background_audit_task(
            env,
            inner,
            id,
            epoch,
            new_ip,
            enabled_unrouted.to_vec(),
            st.disabled_providers.clone(),
            t0,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_background_audit_task(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        id: String,
        epoch: u64,
        new_ip: String,
        enabled_unrouted: Vec<&'static str>,
        disabled: HashSet<String>,
        t0: Instant,
    ) {
        let audit_env = env.clone();
        let audit = tokio::spawn(async move { audit_enabled(&audit_env.audit, &disabled).await });
        let audit_abort = audit.abort_handle();
        inner.audit_abort = Some(audit_abort.clone());

        let guard = Arc::clone(self);
        let env2 = env.clone();
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
                .finish_audit(&env2, &id, epoch, new_ip, &enabled_unrouted, results, t0)
                .await;
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_audit_outcome_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        new_ip: String,
        old_baseline: Option<&Baseline>,
        results: &AuditResults,
        was_blocked_set: &HashSet<String>,
        existing_id: Option<String>,
        existing_alert_emitted: bool,
        clear_old_state: Option<JoinHandle<()>>,
        t0: Instant,
    ) {
        if let Some(clear) = clear_old_state {
            let _ = clear.await;
        }
        self.drain_pending_route_sync_locked(Some(env), inner).await;
        let st = env.state.get_data().await;
        self.unblock_disabled_and_routed(env, &st).await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        if enabled_unrouted.is_empty() {
            self.restore_locked(env, inner).await;
            return;
        }
        let all_pinned = all_pinned_or_excepted_for(&st, &enabled_unrouted, &new_ip);

        let Some(summary) = summarize_for_state(results, &enabled_unrouted, &st) else {
            let newly_failed: Vec<&'static str> = enabled_unrouted
                .iter()
                .copied()
                .filter(|p| !was_blocked_set.contains(*p) && !st.blocked_providers.contains(*p))
                .collect();
            let already_blocked_vec: Vec<&'static str> = enabled_unrouted
                .iter()
                .copied()
                .filter(|p| was_blocked_set.contains(*p) || st.blocked_providers.contains(*p))
                .collect();
            if all_pinned {
                // Never latch handled_ip or pop a failed-audit alert on a pinned IP during
                // transient VPN handshake failures; retry on subsequent ticks!
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                inner.handled_ip = None;
                inner.needs_reaudit = true;
                self.sync_gates_with_state_and_pending(&st, None);
                if existing_alert_emitted {
                    self.hide_popup(env);
                }
                return;
            }
            for p in &already_blocked_vec {
                if !st.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            if newly_failed.is_empty() {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                inner.handled_ip = Some(new_ip.clone());
                inner.needs_reaudit = false;
                if !self.is_manual_killswitch() {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(new_ip);
                }
                let st_after = env.state.get_data().await;
                self.sync_gates_with_state_and_pending(&st_after, None);
                self.hide_popup(env);
                env.io.tray_status("red", None);
            } else if st.interception_behavior == crate::state::InterceptionBehavior::AskPopup {
                if existing_alert_emitted && let Some(ref alert_id) = existing_id {
                    self.enrich_failed_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        alert_id,
                        &already_blocked_vec,
                        &newly_failed,
                        &[],
                        t0,
                    )
                    .await;
                } else {
                    self.emit_failed_network_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        &already_blocked_vec,
                        &newly_failed,
                        &[],
                        existing_id,
                        t0,
                    )
                    .await;
                }
            } else {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                self.set_gate_reason(Some(
                    "Не удалось проверить новую сеть после смены IP — запросы временно остановлены"
                        .to_string(),
                ));
                for p in &newly_failed {
                    let _ = env.state.block_provider(p).await;
                }
                let st_after = env.state.get_data().await;
                let all_blocked = enabled_unrouted
                    .iter()
                    .all(|p| st_after.blocked_providers.contains(*p));
                if all_blocked && !self.is_manual_killswitch() {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(new_ip.clone());
                }
                inner.handled_ip = Some(new_ip);
                inner.needs_reaudit = false;
                self.sync_gates_with_state_and_pending(&st_after, None);
                self.hide_popup(env);
                env.io.tray_status("red", None);
                env.emit("network://changed", &());
            }
            return;
        };

        // Silent recovery for any enabled provider meeting `no_critical_and_geo_ok`, pinned IP,
        // or `(provider, exit_ip)` in `trusted_exceptions`.
        if !self.is_manual_killswitch() {
            for p in &summary.healthy_providers {
                if st.blocked_providers.contains(*p) {
                    let _ = env.state.unblock_provider(p).await;
                }
                env.hold_queue
                    .resolve_all_for_provider(p, HoldResolution::Superseded)
                    .await;
            }
        }

        let already_blocked: Vec<&'static str> = summary
            .affected_providers
            .iter()
            .copied()
            .filter(|p| was_blocked_set.contains(*p) || st.blocked_providers.contains(*p))
            .collect();
        let newly_affected: Vec<&'static str> = summary
            .affected_providers
            .iter()
            .copied()
            .filter(|p| !already_blocked.contains(p))
            .collect();

        if summary.affected_providers.is_empty() {
            let ip = inner
                .observed_ip
                .clone()
                .unwrap_or_else(|| summary.tel.ip.clone());
            self.accept_locked(env, inner, &ip, &summary.tel).await;
            return;
        }

        // Record history only for non-critical, geo-allowed healthy providers (or pinned returns).
        let now = crate::auditor::network::current_timestamp();
        for p in &summary.healthy_providers {
            if let Some(r) = summary.reports.get(p)
                && (report_no_critical_and_geo_ok(r) || is_report_pinned_travel_only(r, &st))
            {
                let entry = IpHistoryEntry::new(
                    r.telemetry.ip.clone(),
                    r.telemetry.country_code.clone(),
                    r.telemetry.asn,
                    now,
                );
                let _ = env
                    .state
                    .record_ip_history_for_selection(
                        p,
                        &crate::routing::RouteSelection::Direct,
                        entry,
                    )
                    .await;
            }
        }

        if newly_affected.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            for p in &already_blocked {
                if !st.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            let st_after = env.state.get_data().await;
            if all_pinned && !summary.failed_providers.is_empty() {
                inner.handled_ip = None;
                inner.needs_reaudit = true;
            } else {
                inner.handled_ip = Some(new_ip.clone());
                inner.needs_reaudit = false;
                if summary.healthy_providers.is_empty() && !self.is_manual_killswitch() {
                    self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                    inner.paused_ip = Some(new_ip);
                }
            }
            self.sync_gates_with_state_and_pending(&st_after, None);
            self.hide_popup(env);
            self.update_tray(env, &summary.tray).await;
            env.emit("network://changed", &summary.worst);
            return;
        }

        // Transient audit errors or unknown geo on a saved pinned IP must retry silently without
        // blocking, alerting, or locking `PauseMode` onto the pinned IP.
        let is_transient_pinned = |p: &str| -> bool {
            let is_pinned = st
                .pinned_ip_for_provider(p, false)
                .is_some_and(|pin| pin.trim() == new_ip.trim());
            if !is_pinned {
                return false;
            }
            summary.failed_providers.contains(&p)
                || summary
                    .reports
                    .get(p)
                    .is_some_and(|r| is_pinned_transient_unknown_geo(r, &st, false))
        };
        let has_transient_pinned = newly_affected.iter().any(|p| is_transient_pinned(p));
        let newly_affected: Vec<&'static str> = newly_affected
            .into_iter()
            .filter(|p| !is_transient_pinned(p))
            .collect();
        if newly_affected.is_empty() {
            if let Some(p) = inner.invalidate_alert() {
                env.hold_queue.remove(&p.id).await;
            }
            inner.handled_ip = None;
            inner.needs_reaudit = true;
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
            if existing_alert_emitted {
                self.hide_popup(env);
            }
            self.update_tray(env, &summary.tray).await;
            return;
        }

        let has_newly_report = newly_affected
            .iter()
            .any(|p| summary.reports.contains_key(p));
        let worst_newly = summary.worst_for(&newly_affected);
        match st.interception_behavior {
            crate::state::InterceptionBehavior::AutoLockSilent
            | crate::state::InterceptionBehavior::AutoAllowTrusted => {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                let reason = if has_newly_report {
                    let change = network_change(
                        old_baseline,
                        Some(worst_newly.telemetry.ip.clone()),
                        Some(worst_newly.telemetry.country_code.clone()),
                    );
                    build_gate_reason(Some(&worst_newly), Some(&change), false)
                } else {
                    "Не удалось проверить новую сеть после смены IP — запросы временно остановлены"
                        .to_string()
                };
                self.set_gate_reason(Some(reason));
                for p in &newly_affected {
                    let _ = env.state.block_provider(p).await;
                }
                for p in &already_blocked {
                    if !st.blocked_providers.contains(*p) {
                        let _ = env.state.block_provider(p).await;
                    }
                }
                let st_after = env.state.get_data().await;
                let all_blocked = enabled_unrouted
                    .iter()
                    .all(|p| st_after.blocked_providers.contains(*p));
                if (all_pinned && !summary.failed_providers.is_empty()) || has_transient_pinned {
                    inner.handled_ip = None;
                    inner.needs_reaudit = true;
                } else {
                    if all_blocked && !self.is_manual_killswitch() {
                        self.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                        inner.paused_ip = Some(new_ip.clone());
                    }
                    inner.handled_ip = Some(new_ip);
                    inner.needs_reaudit = false;
                }
                self.sync_gates_with_state_and_pending(&st_after, None);
                self.hide_popup(env);
                if has_newly_report {
                    self.update_tray(env, &worst_newly).await;
                    env.emit("network://changed", &worst_newly);
                } else {
                    self.update_tray(env, &summary.tray).await;
                    env.emit("network://changed", &summary.tray);
                }
            }
            crate::state::InterceptionBehavior::AskPopup => {
                if existing_alert_emitted && let Some(ref alert_id) = existing_id {
                    if has_newly_report {
                        self.enrich_ready_alert_locked(
                            env,
                            inner,
                            old_baseline,
                            new_ip,
                            alert_id,
                            &summary,
                            &already_blocked,
                            &newly_affected,
                            t0,
                        )
                        .await;
                    } else {
                        self.enrich_failed_alert_locked(
                            env,
                            inner,
                            old_baseline,
                            new_ip,
                            alert_id,
                            &already_blocked,
                            &newly_affected,
                            &summary.healthy_providers,
                            t0,
                        )
                        .await;
                    }
                } else if has_newly_report {
                    self.emit_ready_network_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        &summary,
                        &already_blocked,
                        &newly_affected,
                        existing_id,
                        None,
                        t0,
                    )
                    .await;
                } else {
                    self.emit_failed_network_alert_locked(
                        env,
                        inner,
                        old_baseline,
                        new_ip,
                        &already_blocked,
                        &newly_affected,
                        &summary.healthy_providers,
                        existing_id,
                        t0,
                    )
                    .await;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn enrich_ready_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        old_baseline: Option<&Baseline>,
        new_ip: String,
        id: &str,
        summary: &AuditSummary,
        already_blocked: &[&'static str],
        newly_affected: &[&'static str],
        t0: Instant,
    ) {
        let st = env.state.get_data().await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        let mut blocked_set: HashSet<String> =
            already_blocked.iter().map(|s| (*s).to_string()).collect();
        for p in &st.blocked_providers {
            if enabled_unrouted.contains(&p.as_str()) && !newly_affected.contains(&p.as_str()) {
                blocked_set.insert(p.clone());
            }
        }
        for p in already_blocked {
            if !st.blocked_providers.contains(*p) {
                let _ = env.state.block_provider(p).await;
            }
        }
        self.freeze_providers_pending(&st, newly_affected, &blocked_set);
        inner.handled_ip = Some(new_ip);
        inner.needs_reaudit = false;

        let epoch = inner.epoch;
        if let Some(p) = inner.pending.as_mut() {
            p.tel = Some(summary.tel.clone());
            p.affected_providers = newly_affected.to_vec();
            p.already_blocked_providers = already_blocked.to_vec();
            p.healthy_providers = summary.healthy_providers.clone();
        }

        let worst_newly = summary.worst_for(newly_affected);
        let net_change = network_change(
            old_baseline,
            Some(summary.tel.ip.clone()),
            Some(summary.tel.country_code.clone()),
        );
        let reason = build_gate_reason(Some(&worst_newly), Some(&net_change), false);
        self.set_gate_reason(Some(reason.clone()));
        self.update_tray(env, &worst_newly).await;

        let enriched = EnrichedPayload {
            id: id.to_string(),
            epoch,
            phase: PHASE_READY.to_string(),
            report: Some(worst_newly.clone()),
            network_change: net_change,
            gate_reason: Some(reason),
        };
        env.hold_queue.update_alert(&enriched);
        env.emit("interceptor://enriched", &enriched);
        log_timing(id, "enriched_ready", t0);
        env.emit("network://changed", &worst_newly);
    }

    #[allow(clippy::too_many_arguments)]
    async fn enrich_failed_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        old_baseline: Option<&Baseline>,
        new_ip: String,
        id: &str,
        already_blocked: &[&'static str],
        newly_affected: &[&'static str],
        healthy_providers: &[&'static str],
        t0: Instant,
    ) {
        let st = env.state.get_data().await;
        let blocked_set: HashSet<String> = already_blocked
            .iter()
            .map(|s| (*s).to_string())
            .chain(st.blocked_providers.iter().cloned())
            .filter(|p| {
                !newly_affected.contains(&p.as_str()) && !healthy_providers.contains(&p.as_str())
            })
            .collect();
        self.freeze_providers_pending(&st, newly_affected, &blocked_set);
        inner.handled_ip = Some(new_ip.clone());
        inner.needs_reaudit = false;

        let epoch = inner.epoch;
        if let Some(p) = inner.pending.as_mut() {
            p.tel = None;
            p.affected_providers = newly_affected.to_vec();
            p.already_blocked_providers = already_blocked.to_vec();
            p.healthy_providers = healthy_providers.to_vec();
        }

        let reason =
            "Не удалось проверить новую сеть после смены IP — запросы временно остановлены"
                .to_string();
        self.set_gate_reason(Some(reason.clone()));

        let enriched = EnrichedPayload {
            id: id.to_string(),
            epoch,
            phase: PHASE_FAILED.to_string(),
            report: None,
            network_change: network_change(old_baseline, Some(new_ip), None),
            gate_reason: Some(reason),
        };
        env.hold_queue.update_alert(&enriched);
        env.emit("interceptor://enriched", &enriched);
        env.io.tray_status("red", None);
        log_timing(id, "enriched_failed", t0);
    }

    #[allow(clippy::too_many_arguments)]
    async fn emit_ready_network_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        old_baseline: Option<&Baseline>,
        new_ip: String,
        summary: &AuditSummary,
        already_blocked: &[&'static str],
        newly_affected: &[&'static str],
        existing_id: Option<String>,
        clear_old_state: Option<JoinHandle<()>>,
        t0: Instant,
    ) {
        if let Some(clear) = clear_old_state {
            let _ = clear.await;
        }
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        let st = env.state.get_data().await;
        let enabled_unrouted = st.enabled_unrouted_providers();
        let mut blocked_set: HashSet<String> =
            already_blocked.iter().map(|s| (*s).to_string()).collect();
        for p in &st.blocked_providers {
            if enabled_unrouted.contains(&p.as_str()) && !newly_affected.contains(&p.as_str()) {
                blocked_set.insert(p.clone());
            }
        }
        for p in already_blocked {
            if !st.blocked_providers.contains(*p) {
                let _ = env.state.block_provider(p).await;
            }
        }
        self.freeze_providers_pending(&st, newly_affected, &blocked_set);
        inner.handled_ip = Some(new_ip.clone());
        inner.needs_reaudit = false;

        let id = existing_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let rx = env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
        let epoch = inner.epoch;
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            target_ip: new_ip,
            tel: Some(summary.tel.clone()),
            clear_old_state: None,
            affected_providers: newly_affected.to_vec(),
            already_blocked_providers: already_blocked.to_vec(),
            healthy_providers: summary.healthy_providers.clone(),
            alert_emitted: true,
        });

        let worst_newly = summary.worst_for(newly_affected);
        let net_change = network_change(
            old_baseline,
            Some(summary.tel.ip.clone()),
            Some(summary.tel.country_code.clone()),
        );
        let reason = build_gate_reason(Some(&worst_newly), Some(&net_change), false);
        self.set_gate_reason(Some(reason.clone()));

        let payload = RiskInterceptPayload {
            id: id.clone(),
            provider: worst_newly.provider,
            host: "Смена сети · все ИИ-сервисы".to_string(),
            report: Some(worst_newly.clone()),
            ttl_seconds: DEFAULT_HOLD_TTL_SECS,
            scope: "network".to_string(),
            network_change: Some(net_change),
            is_simulation: false,
            detected_at_ms: now_unix_ms(),
            phase: PHASE_READY.to_string(),
            gate_reason: Some(reason),
        };

        env.hold_queue.set_alert(payload.clone());
        log_timing(&id, "risk_detected_emitted", t0);
        env.emit("interceptor://risk-detected", &payload);
        env.io.show_alert_popup(Some((id.clone(), t0)));
        env.emit("network://changed", &worst_newly);

        self.spawn_decision_waiter(env, id, epoch, rx);
    }

    #[allow(clippy::too_many_arguments)]
    async fn emit_failed_network_alert_locked(
        self: &Arc<Self>,
        env: &Env,
        inner: &mut Inner,
        old_baseline: Option<&Baseline>,
        new_ip: String,
        already_blocked: &[&'static str],
        newly_affected: &[&'static str],
        healthy_providers: &[&'static str],
        existing_id: Option<String>,
        t0: Instant,
    ) {
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        let st = env.state.get_data().await;
        let blocked_set: HashSet<String> = already_blocked
            .iter()
            .map(|s| (*s).to_string())
            .chain(st.blocked_providers.iter().cloned())
            .filter(|p| {
                !newly_affected.contains(&p.as_str()) && !healthy_providers.contains(&p.as_str())
            })
            .collect();
        self.freeze_providers_pending(&st, newly_affected, &blocked_set);
        inner.handled_ip = Some(new_ip.clone());
        inner.needs_reaudit = false;

        let id = existing_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let rx = env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
        let epoch = inner.epoch;
        inner.pending = Some(Pending {
            id: id.clone(),
            epoch,
            target_ip: new_ip.clone(),
            tel: None,
            clear_old_state: None,
            affected_providers: newly_affected.to_vec(),
            already_blocked_providers: already_blocked.to_vec(),
            healthy_providers: healthy_providers.to_vec(),
            alert_emitted: true,
        });

        let provider = newly_affected
            .iter()
            .find_map(|p| ProviderId::from_id(p))
            .unwrap_or(ProviderId::Anthropic);
        let net_change = network_change(old_baseline, Some(new_ip), None);
        let reason =
            "Не удалось проверить новую сеть после смены IP — запросы временно остановлены"
                .to_string();
        self.set_gate_reason(Some(reason.clone()));

        let payload = RiskInterceptPayload {
            id: id.clone(),
            provider,
            host: "Смена сети · все ИИ-сервисы".to_string(),
            report: None,
            ttl_seconds: DEFAULT_HOLD_TTL_SECS,
            scope: "network".to_string(),
            network_change: Some(net_change),
            is_simulation: false,
            detected_at_ms: now_unix_ms(),
            phase: PHASE_FAILED.to_string(),
            gate_reason: Some(reason),
        };

        env.hold_queue.set_alert(payload.clone());
        log_timing(&id, "risk_detected_failed_emitted", t0);
        env.emit("interceptor://risk-detected", &payload);
        env.io.show_alert_popup(Some((id.clone(), t0)));
        env.io.tray_status("red", None);

        self.spawn_decision_waiter(env, id, epoch, rx);
    }

    /// Delivers the result of the background audit started by `handle_change_locked`.
    #[allow(clippy::too_many_arguments)]
    async fn finish_audit(
        self: &Arc<Self>,
        env: &Env,
        id: &str,
        epoch: u64,
        new_ip: String,
        _unrouted: &[&'static str],
        results: Option<AuditResults>,
        t0: Instant,
    ) {
        let mut inner = self.inner.lock().await;
        if !inner.is_current(id, epoch) {
            log_timing(id, "audit_dropped_stale", t0);
            return;
        }
        let old = inner.baseline.clone();
        let (clear_old_state, prev_already_blocked, alert_emitted) = match inner.pending.as_mut() {
            Some(p) => (
                p.clear_old_state.take(),
                p.already_blocked_providers
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect::<HashSet<String>>(),
                p.alert_emitted,
            ),
            None => (None, HashSet::new(), false),
        };

        let res_vec = results.unwrap_or_default();
        self.apply_audit_outcome_locked(
            env,
            &mut inner,
            new_ip,
            old.as_ref(),
            &res_vec,
            &prev_already_blocked,
            Some(id.to_string()),
            alert_emitted,
            clear_old_state,
            t0,
        )
        .await;
    }

    /// Waits for the user's decision (or the hold TTL) and applies it, unless the alert was
    /// superseded meanwhile. Anything but an explicit `Allow` blocks ONLY `affected` (critical /
    /// blocked-geo / failed) providers, never `healthy` (including `Yellow`) providers.
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
            if matches!(res, Ok(Ok(HoldResolution::Superseded))) {
                return;
            }
            let allow = matches!(res, Ok(Ok(HoldResolution::Allow)));

            let mut inner = guard.inner.lock().await;
            if !inner.is_current(&id, epoch) {
                return; // superseded by a newer change or already accepted/restored
            }
            let pending = inner.invalidate_alert();
            env.hold_queue.remove(&id).await;
            let (tel, target_ip, clear_old_state, affected, already_blocked, healthy) =
                match pending {
                    Some(p) => (
                        p.tel,
                        p.target_ip,
                        p.clear_old_state,
                        p.affected_providers,
                        p.already_blocked_providers,
                        p.healthy_providers,
                    ),
                    None => (
                        None,
                        String::new(),
                        None,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ),
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
                    if already_blocked.is_empty() {
                        guard.accept_locked(&env, &mut inner, &ip, &tel).await;
                        return;
                    }
                    let now = crate::auditor::network::current_timestamp();
                    for p in affected.iter().chain(healthy.iter()) {
                        let _ = env.state.allow_provider_for_session(p).await;
                        if !guard.is_manual_killswitch() {
                            let _ = env.state.unblock_provider(p).await;
                        }
                        let entry = IpHistoryEntry::new(
                            tel.ip.clone(),
                            tel.country_code.clone(),
                            tel.asn,
                            now,
                        );
                        let _ = env
                            .state
                            .record_ip_history_for_selection(
                                p,
                                &crate::routing::RouteSelection::Direct,
                                entry,
                            )
                            .await;
                    }
                    for p in &already_blocked {
                        let _ = env.state.block_provider(p).await;
                    }
                    inner.baseline = Some(Baseline {
                        ip,
                        country: Some(tel.country_code.clone()),
                        trusted: true,
                    });
                    inner.handled_ip = None;
                    inner.needs_reaudit = false;
                    guard.clear_until_network_change_locked(&mut inner);
                    guard.set_gate_reason(None);
                    let st_after = env.state.get_data().await;
                    guard.sync_gates_with_state_and_pending(&st_after, None);
                    guard.hide_popup(&env);
                    env.emit("network://changed", &());
                    guard.spawn_refresh_tray(&env);
                    return;
                }
                eprintln!("Network guard: allow without a finished audit, traffic stays blocked");
            }
            let st = env.state.get_data().await;
            let enabled_unrouted = st.enabled_unrouted_providers();
            let to_block: Vec<&'static str> = affected
                .iter()
                .copied()
                .filter(|p| enabled_unrouted.contains(p))
                .collect();
            for p in &to_block {
                let _ = env.state.block_provider(p).await;
            }
            for p in &already_blocked {
                if enabled_unrouted.contains(p) && !st.blocked_providers.contains(*p) {
                    let _ = env.state.block_provider(p).await;
                }
            }
            let st_after = env.state.get_data().await;
            let remaining_open: Vec<&'static str> = enabled_unrouted
                .iter()
                .copied()
                .filter(|p| !st_after.blocked_providers.contains(*p))
                .collect();

            if !to_block.is_empty() && remaining_open.is_empty() && !guard.is_manual_killswitch()
            {
                guard.set_pause_mode_raw(PauseMode::UntilNetworkChange);
                if guard.gate_reason().is_none() {
                    guard.set_gate_reason(Some(
                        "Запросы на паузе до следующей смены сети".to_string(),
                    ));
                }
                inner.paused_ip = inner
                    .observed_ip
                    .clone()
                    .or_else(|| (!target_ip.is_empty()).then_some(target_ip.clone()))
                    .or_else(|| inner.handled_ip.clone());
            } else if to_block.is_empty() && !guard.is_manual_killswitch() {
                guard.clear_until_network_change_locked(&mut inner);
                if remaining_open.len() == enabled_unrouted.len() {
                    guard.set_gate_reason(None);
                }
                if let Some(ref tel) = tel {
                    let ip = inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone());
                    inner.baseline = Some(Baseline {
                        ip,
                        country: Some(tel.country_code.clone()),
                        trusted: true,
                    });
                    inner.handled_ip = None;
                }
            }
            guard.sync_gates_with_state_and_pending(&st_after, None);
            guard.hide_popup(&env);
            if !to_block.is_empty() {
                env.emit("network://changed", &());
            }
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
        self.restore_epoch.fetch_add(1, Ordering::SeqCst);
        inner.baseline = Some(Baseline {
            ip: ip.to_string(),
            country: Some(tel.country_code.clone()),
            trusted: true,
        });
        inner.handled_ip = None;
        inner.needs_reaudit = false;
        self.clear_until_network_change_locked(inner);
        if !self.is_manual_killswitch() {
            self.set_gate_reason(None);
        }
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        env.hold_queue.cancel_all_superseded().await;

        // Only enabled unrouted providers record Direct IP history.
        let now = crate::auditor::network::current_timestamp();
        for p in env.state.enabled_unrouted_providers().await {
            let entry = IpHistoryEntry::new(tel.ip.clone(), tel.country_code.clone(), tel.asn, now);
            let _ = env
                .state
                .record_ip_history_for_selection(p, &crate::routing::RouteSelection::Direct, entry)
                .await;
        }

        if !self.is_manual_killswitch() {
            let _ = env.state.clear_blocked_providers().await;
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
        } else {
            self.set_gate(Gate::Blocked);
        }
        self.hide_popup(env);
        env.emit("network://changed", &());
        self.spawn_refresh_tray(env);
    }

    /// Opens the guard gate (when not under a manual kill-switch) after a single provider was
    /// verified and unblocked, without touching remaining entries in `blocked_providers`.
    pub async fn ensure_open_for_verified(self: &Arc<Self>, tel: &NetworkTelemetry) {
        let Some(env) = self.env.get() else {
            return;
        };
        if self.is_manual_killswitch() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        inner.handled_ip = None;
        inner.needs_reaudit = false;
        self.clear_until_network_change_locked(&mut inner);
        self.set_gate_reason(None);
        inner.baseline = Some(Baseline {
            ip: tel.ip.clone(),
            country: Some(tel.country_code.clone()),
            trusted: true,
        });
        let st = env.state.get_data().await;
        self.sync_gates_with_state_and_pending(&st, None);
        if !self.any_provider_gate_closed() && st.blocked_providers.is_empty() {
            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
            env.hold_queue.cancel_all_superseded().await;
        }
        self.hide_popup(env);
    }

    /// The previous (trusted) or fully healthy/excepted network is active: resume traffic.
    async fn restore_locked(self: &Arc<Self>, env: &Env, inner: &mut Inner) {
        self.restore_epoch.fetch_add(1, Ordering::SeqCst);
        if let Some(p) = inner.invalidate_alert() {
            env.hold_queue.remove(&p.id).await;
        }
        env.hold_queue.cancel_all_superseded().await;
        inner.handled_ip = None;
        inner.needs_reaudit = false;
        self.clear_until_network_change_locked(inner);
        if !self.is_manual_killswitch() {
            self.set_gate_reason(None);
        }
        env.auditor.resolver.invalidate_direct_cache().await;
        if !self.is_manual_killswitch() {
            let _ = env.state.clear_blocked_providers().await;
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, None);
        } else {
            self.set_gate(Gate::Blocked);
        }
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
        if !self.any_provider_gate_closed() {
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

    /// Scoped per-provider confirmation after explicit user override ("Разрешить принудительно" /
    /// `allow_provider_session` / single-provider `AllowSession`).
    /// Never leaks across other unrelated blocked/pending providers and cleanly sets
    /// `baseline.trusted = true` even when telemetry could not be resolved externally.
    pub async fn confirm_provider_session(
        self: &Arc<Self>,
        provider: &str,
        tel: Option<&NetworkTelemetry>,
    ) {
        if self.is_manual_killswitch() {
            return;
        }
        let canonical = ProviderId::from_id(provider)
            .map(|p| p.as_str())
            .unwrap_or(provider);
        let mut inner = self.inner.lock().await;
        if let Some(env) = self.env.get() {
            let st = env.state.get_data().await;
            let is_direct_enabled = !st.is_provider_disabled(canonical)
                && crate::routing::select_route_id(&st, canonical).is_none();
            let has_enabled_unrouted = !st.enabled_unrouted_providers().is_empty();
            // Never fall back to direct egress telemetry (or mark an untrusted direct baseline
            // as trusted) when the confirmed provider is routed/disabled or all providers are routed.
            if is_direct_enabled && has_enabled_unrouted {
                let resolved = match tel {
                    Some(t) => Some(t.clone()),
                    None => env.resolve_telemetry().await.ok(),
                };
                if let Some(t) = resolved {
                    let ip = inner.observed_ip.clone().unwrap_or_else(|| t.ip.clone());
                    inner.baseline = Some(Baseline {
                        ip,
                        country: Some(t.country_code.clone()),
                        trusted: true,
                    });
                } else if let Some(b) = inner.baseline.as_mut() {
                    b.trusted = true;
                }
            }
            if let Some(p) = inner.pending.as_mut() {
                p.affected_providers.retain(|x| *x != canonical);
                p.already_blocked_providers.retain(|x| *x != canonical);
                if p.affected_providers.is_empty() {
                    let old_id = p.id.clone();
                    inner.invalidate_alert();
                    env.hold_queue.remove(&old_id).await;
                }
            }
            self.sync_gates_with_state_and_pending(&st, inner.pending.as_ref());
            if !self.any_provider_gate_closed() {
                self.restore_epoch.fetch_add(1, Ordering::SeqCst);
                env.hold_queue.cancel_all_superseded().await;
                inner.handled_ip = None;
                inner.needs_reaudit = false;
                self.clear_until_network_change_locked(&mut inner);
                self.set_gate_reason(None);
                self.hide_popup(env);
            }
            self.spawn_refresh_tray(env);
            return;
        }

        if let Some(t) = tel {
            inner.baseline = Some(Baseline {
                ip: t.ip.clone(),
                country: Some(t.country_code.clone()),
                trusted: true,
            });
        } else if let Some(b) = inner.baseline.as_mut() {
            b.trusted = true;
        }
        if let Some(pid) = ProviderId::from_id(canonical)
            && let Some(tx) = self.provider_gates.get(&pid)
        {
            let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
            if !*self.kill_tx.borrow() {
                tx.send_replace(Gate::Open);
                if self.provider_gates.values().all(|g| *g.borrow() == Gate::Open) {
                    self.gate_tx.send_replace(Gate::Open);
                    inner.handled_ip = None;
                }
            }
        }
    }

    /// Confirms the current network as a trusted baseline after explicit user confirmation in the
    /// main window (`allow_provider_session` / `unblock_provider_cmd`). Unlike `accept_current`,
    /// this also updates `baseline.trusted = true` when the gate is already `Gate::Open` (e.g.
    /// startup on a warning/untrusted network) so subsequent regular probes on the same IP do not
    /// re-freeze or block traffic. Never lifts a manual kill-switch or opens a closed gate without
    /// resolved telemetry.
    pub async fn confirm_current_session(self: &Arc<Self>, tel: Option<&NetworkTelemetry>) {
        if self.is_manual_killswitch() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if let Some(env) = self.env.get() {
            let resolved = match tel {
                Some(t) => Ok(t.clone()),
                None => env.resolve_telemetry().await,
            };
            match resolved {
                Ok(t) => {
                    let ip = inner.observed_ip.clone().unwrap_or_else(|| t.ip.clone());
                    let st = env.state.get_data().await;
                    if self.any_provider_gate_closed() && st.blocked_providers.is_empty() {
                        self.accept_locked(env, &mut inner, &ip, &t).await;
                    } else {
                        if let Some(p) = inner.invalidate_alert() {
                            env.hold_queue.remove(&p.id).await;
                        }
                        if st.blocked_providers.is_empty() {
                            self.restore_epoch.fetch_add(1, Ordering::SeqCst);
                            env.hold_queue.cancel_all_superseded().await;
                        }
                        inner.baseline = Some(Baseline {
                            ip,
                            country: Some(t.country_code.clone()),
                            trusted: true,
                        });
                        inner.handled_ip = None;
                        inner.needs_reaudit = false;
                        self.clear_until_network_change_locked(&mut inner);
                        self.set_gate_reason(None);
                        self.sync_gates_with_state_and_pending(&st, None);
                        self.hide_popup(env);
                    }
                }
                Err(e) => {
                    if !self.any_provider_gate_closed() {
                        if let Some(b) = inner.baseline.as_mut() {
                            b.trusted = true;
                        }
                        inner.handled_ip = None;
                    } else {
                        eprintln!(
                            "Network guard: cannot confirm the network, gate stays closed: {e}"
                        );
                    }
                }
            }
            return;
        }

        if let Some(t) = tel {
            inner.invalidate_alert();
            inner.baseline = Some(Baseline {
                ip: t.ip.clone(),
                country: Some(t.country_code.clone()),
                trusted: true,
            });
            inner.handled_ip = None;
            self.set_gate(Gate::Open);
        } else if !self.any_provider_gate_closed() {
            if let Some(b) = inner.baseline.as_mut() {
                b.trusted = true;
            }
            inner.handled_ip = None;
        }
    }

    /// The user's "allow" for the network alert `id` (command layer). Accepted only while that
    /// alert is still the current one (same id and epoch) AND its audit finished (`phase ==
    /// "ready"` and `alert_emitted == true`); otherwise nothing is opened or written and an error
    /// goes back to the window. Persists `(provider, exit_ip)` in `trusted_exceptions`, preserves
    /// unrelated `already_blocked_providers`, and opens only the allowed providers.
    pub async fn allow_network_alert(
        self: &Arc<Self>,
        id: &str,
        providers: &[String],
    ) -> Result<(), AllowError> {
        let env = self.env.get().ok_or_else(|| {
            AllowError::new(
                AllowErrorCode::GuardNotRunning,
                "network guard is not running",
            )
        })?;
        if self.is_manual_killswitch() {
            return Err(AllowError::new(
                AllowErrorCode::BlockedByManualKillswitch,
                "manual kill-switch is engaged",
            ));
        }
        let mut inner = self.inner.lock().await;
        let epoch = inner.epoch;
        if !inner.is_current(id, epoch) {
            return Err(AllowError::new(
                AllowErrorCode::AlertStale,
                "this alert is no longer current",
            ));
        }
        let Some(tel) = inner
            .pending
            .as_ref()
            .filter(|p| p.alert_emitted)
            .and_then(|p| p.tel.clone())
        else {
            return Err(AllowError::new(
                AllowErrorCode::AuditPending,
                "the network audit is not finished",
            ));
        };
        if let Some(clear) = inner
            .pending
            .as_mut()
            .and_then(|p| p.clear_old_state.take())
        {
            let _ = clear.await;
        }
        let ip = inner.observed_ip.clone().unwrap_or_else(|| tel.ip.clone());
        let st_before = env.state.get_data().await;
        let targets: Vec<String> = {
            let pending_affected = inner
                .pending
                .as_ref()
                .map(|p| p.affected_providers.clone())
                .unwrap_or_default();
            if providers.is_empty() || providers.iter().any(|p| p == ALL_PROVIDERS) {
                pending_affected.into_iter().map(|p| p.to_string()).collect()
            } else {
                let mut seen = HashSet::new();
                let mut list = Vec::new();
                for raw in providers {
                    let canonical = ProviderId::from_id(raw)
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_else(|| raw.clone());
                    if !st_before.is_provider_disabled(&canonical) && seen.insert(canonical.clone())
                    {
                        list.push(canonical);
                    }
                }
                list
            }
        };

        let now = crate::auditor::network::current_timestamp();
        for p in &targets {
            env.state
                .allow_provider_for_session(p)
                .await
                .map_err(|e| AllowError::new(AllowErrorCode::Internal, e.to_string()))?;
            if !ip.trim().is_empty() {
                env.state
                    .add_trusted_exception(p, &ip)
                    .await
                    .map_err(|e| AllowError::new(AllowErrorCode::Internal, e.to_string()))?;
            }
            env.state
                .unblock_provider(p)
                .await
                .map_err(|e| AllowError::new(AllowErrorCode::Internal, e.to_string()))?;
            let entry = IpHistoryEntry::new(tel.ip.clone(), tel.country_code.clone(), tel.asn, now);
            let _ = env
                .state
                .record_ip_history_for_selection(p, &crate::routing::RouteSelection::Direct, entry)
                .await;
        }

        let target_set: HashSet<&str> = targets.iter().map(String::as_str).collect();
        let (remaining_affected, already_blocked) = if let Some(p) = inner.pending.as_mut() {
            p.affected_providers.retain(|x| !target_set.contains(*x));
            p.already_blocked_providers
                .retain(|x| !target_set.contains(*x));
            (
                p.affected_providers.clone(),
                p.already_blocked_providers.clone(),
            )
        } else {
            (Vec::new(), Vec::new())
        };

        if remaining_affected.is_empty() {
            let st_now = env.state.get_data().await;
            let has_remaining_blocks = !already_blocked.is_empty()
                || st_now
                    .enabled_unrouted_providers()
                    .iter()
                    .any(|p| st_now.blocked_providers.contains(*p));
            if !has_remaining_blocks {
                self.accept_locked(env, &mut inner, &ip, &tel).await;
            } else {
                if let Some(p) = inner.invalidate_alert() {
                    env.hold_queue.remove(&p.id).await;
                }
                for p in &already_blocked {
                    if !st_now.blocked_providers.contains(*p) {
                        let _ = env.state.block_provider(p).await;
                    }
                }
                inner.baseline = Some(Baseline {
                    ip,
                    country: Some(tel.country_code.clone()),
                    trusted: true,
                });
                inner.handled_ip = None;
                inner.needs_reaudit = false;
                self.clear_until_network_change_locked(&mut inner);
                self.set_gate_reason(None);
                let st_after = env.state.get_data().await;
                self.sync_gates_with_state_and_pending(&st_after, None);
                self.hide_popup(env);
                env.emit("network://changed", &());
                self.spawn_refresh_tray(env);
            }
        } else {
            let st_after = env.state.get_data().await;
            self.sync_gates_with_state_and_pending(&st_after, inner.pending.as_ref());
            self.spawn_refresh_tray(env);
        }
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
        let is_pinned = crate::commands::audit::is_ip_pinned_for_state(
            &st,
            report.provider,
            &report.telemetry.ip,
        );
        let held = self.any_provider_gate_closed() || !st.blocked_providers.is_empty();
        let tray_report = effective_tray_report(report, held, &st);
        env.io.tray_report(&tray_report, is_pinned, held);
    }

    /// Re-reads the status for the tray in the background (a full audit: 0.3-2 s must never be
    /// spent under `tick_lock` / `inner`). Audits the first enabled provider only.
    fn spawn_refresh_tray(self: &Arc<Self>, env: &Env) {
        let guard = Arc::clone(self);
        let env = env.clone();
        tokio::spawn(async move {
            let st = env.state.get_data().await;
            let Some(pid) = st.enabled_providers().into_iter().find_map(ProviderId::from_id) else {
                env.io.tray_status("green", Some("Мониторинг провайдеров отключён"));
                return;
            };
            if let Ok(report) = (env.audit)(pid, false).await {
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

    #[tokio::test(start_paused = true)]
    async fn test_window_shown_before_slow_audit_and_events_are_ordered() {
        let h = harness(
            slow_audit(Duration::from_secs(2), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        let started = TInstant::now();
        h.change("9.9.9.9").await;

        // Window-first: risk-detected (phase = detecting) fires immediately at t0 so user
        // gets instant feedback while traffic stays safely frozen (Pending) during slow audit.
        let (detected, detected_at) = h
            .io
            .wait_for("interceptor://risk-detected", 300)
            .await
            .expect("immediate risk-detected");
        assert!(detected_at.duration_since(started) < Duration::from_millis(300));
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
        assert_eq!(h.env.hold_queue.current_alert().expect("snapshot").phase, "detecting");
        assert_eq!(
            h.io.trays.lock().unwrap().first().map(String::as_str),
            Some("yellow")
        );
        assert_eq!(h.guard.gate(), Gate::Pending);
        assert_eq!(h.io.count("interceptor://enriched"), 0);
        assert_eq!(h.io.count("network://changed"), 0);

        // Once the 2 s audit lands with Critical risk, enriched (phase = ready) and
        // network://changed are emitted.
        let (enriched, enriched_at) = h
            .io
            .wait_for("interceptor://enriched", 4000)
            .await
            .expect("enriched");
        assert!(enriched_at.duration_since(started) >= Duration::from_secs(2));
        assert_eq!(enriched["phase"], "ready");
        assert_eq!(enriched["network_change"]["new_country"], "NL");
        assert!(enriched["report"].is_object());

        let changed = h
            .io
            .wait_for("network://changed", 1000)
            .await
            .expect("network://changed");
        assert!(detected_at <= enriched_at && enriched_at <= changed.1);
        assert_eq!(h.guard.gate(), Gate::Pending);
        let snapshot = h.env.hold_queue.current_alert().expect("snapshot");
        assert_eq!(snapshot.phase, "ready");
        assert!(snapshot.report.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn test_stale_audit_result_is_ignored() {
        let h = harness(
            slow_audit(Duration::from_millis(100), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let first = h
            .io
            .first("interceptor://risk-detected")
            .expect("first immediate risk-detected");
        assert_eq!(first.0["phase"], "detecting");
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

        // Only the current alert emits enriched (phase = ready).
        let enriched = h
            .io
            .wait_for("interceptor://enriched", 3000)
            .await
            .expect("enriched");
        assert_eq!(enriched.0["id"], second_id.as_str());
        assert_eq!(enriched.0["phase"], "ready");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(h.io.count("interceptor://enriched"), 1);
        assert_eq!(h.guard.gate(), Gate::Pending);
    }

    #[tokio::test(start_paused = true)]
    async fn test_accept_cancels_inflight_audit() {
        let h = harness(
            slow_audit(Duration::from_millis(300), "9.9.9.9", OverallStatus::Red),
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
        assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
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
        h.io.wait_for("network://changed", 2000)
            .await
            .expect("pinned audit completed");
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
    async fn test_silent_behavior_freezes_immediately_and_blocks_without_popup() {
        let h = harness(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        h.state
            .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
            .await
            .unwrap();
        h.change("9.9.9.9").await;
        // Freezes immediately at t=0ms with Pending gate and zero popup while async audit runs.
        assert_eq!(h.guard.gate(), Gate::Pending);
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
        assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);

        h.io.wait_for("network://changed", 2000)
            .await
            .expect("network://changed");
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
        assert_eq!(h.io.count("interceptor://risk-detected"), 1);

        let enriched = h
            .io
            .wait_for("interceptor://enriched", 3000)
            .await
            .expect("failed enriched");
        assert_eq!(enriched.0["phase"], "failed");
        assert_eq!(
            h.io.trays.lock().unwrap().last().map(String::as_str),
            Some("red")
        );
        assert!(enriched.0["report"].is_null());
        assert!(enriched.0["new_country"].is_null());
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
        guard.register_self_weak();
        guard.inner.lock().await.baseline = h.guard.inner.lock().await.baseline.clone();
        h.guard = guard;
        h.change("9.9.9.9").await;
        let enriched = h
            .io
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("failed enrichment");
        assert_eq!(enriched.0["phase"], "failed");
        assert_eq!(h.guard.gate(), Gate::Pending);
    }

    #[tokio::test(start_paused = true)]
    async fn test_decision_block_and_allow_after_ready_audit() {
        // Deny after audit is ready: providers blocked, gate Blocked, popup hidden.
        let h = harness(
            slow_audit(Duration::from_millis(50), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let ev = h
            .io
            .wait_for("interceptor://risk-detected", 2000)
            .await
            .expect("risk-detected");
        let id = alert_id(&ev);
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

        // Allow after the audit is ready: baseline becomes the new network, gate opens.
        let h = harness(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let enriched = h
            .io
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("ready enrichment");
        let id = enriched.0["id"].as_str().unwrap().to_string();
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
    async fn test_route_dirty_with_new_ip_freezes_gate_until_audit_completes() {
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
        // Alert-first emits detecting immediately while slow audit runs; gate stays Pending.
        let ev = h
            .io
            .first("interceptor://risk-detected")
            .expect("immediate risk-detected");
        assert_eq!(ev.0["phase"], "detecting");
        assert_eq!(h.guard.gate(), Gate::Pending);

        let enr = h
            .io
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("enriched after audit");
        assert_eq!(enr.0["phase"], "ready");
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
        // Anthropic (1) + OpenAI (1 + 1 retry) + Gemini (1) = 4
        assert_eq!(calls.len(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn test_audit_all_retries_transient_openai_and_gemini_failures() {
        let attempts: Arc<std::sync::Mutex<std::collections::HashMap<ProviderId, usize>>> =
            Arc::default();
        let attempts2 = Arc::clone(&attempts);
        let audit: AuditFn = Arc::new(move |provider, _force| {
            let mut map = attempts2.lock().unwrap();
            let count = map.entry(provider).or_insert(0);
            *count += 1;
            let n = *count;
            Box::pin(async move {
                if matches!(provider, ProviderId::Openai | ProviderId::Gemini) && n == 1 {
                    Err("transient interface shake".to_string())
                } else {
                    Ok(test_report(provider, OverallStatus::Green, "9.9.9.9", "NL"))
                }
            })
        });
        let results = audit_all(&audit).await;
        assert!(results.iter().all(|(_, r)| r.is_ok()));
        let map = attempts.lock().unwrap();
        assert_eq!(map.get(&ProviderId::Anthropic), Some(&1));
        assert_eq!(map.get(&ProviderId::Openai), Some(&2));
        assert_eq!(map.get(&ProviderId::Gemini), Some(&2));
    }

    #[test]
    fn test_summarize_failure_rules() {
        let ok = |p| (p, Ok(test_report(p, OverallStatus::Green, "9.9.9.9", "NL")));
        let err = |p| (p, Err::<RiskReport, String>("x".to_string()));
        let all = ["anthropic", "openai", "gemini"];

        // First provider failed while siblings succeeded: preserve sibling results and track the
        // failed provider instead of returning None.
        let r = vec![
            err(ProviderId::Anthropic),
            ok(ProviderId::Openai),
            ok(ProviderId::Gemini),
        ];
        let s = summarize(&r, &all).expect("sibling reports must be preserved");
        assert!(!s.all_green);
        assert!(!s.no_critical_and_geo_ok);
        assert_eq!(s.healthy_providers, vec!["openai", "gemini"]);
        assert_eq!(s.affected_providers, vec!["anthropic"]);
        assert_eq!(s.critical_providers, vec!["anthropic"]);
        assert_eq!(s.failed_providers, vec!["anthropic"]);
        // ...and when that failed provider is routed, unrouted siblings are all green.
        let s = summarize(&r, &["openai", "gemini"]).expect("openai & gemini are healthy");
        assert!(s.all_green);
        assert!(s.failed_providers.is_empty());

        // Only when ALL unrouted providers fail does summarize return None.
        assert!(summarize(&r, &["anthropic"]).is_none());
        let all_err = vec![
            err(ProviderId::Anthropic),
            err(ProviderId::Openai),
            err(ProviderId::Gemini),
        ];
        assert!(summarize(&all_err, &all).is_none());

        // Another provider failed: the rest survives, but "all green" is no longer provable.
        let r = vec![
            ok(ProviderId::Anthropic),
            err(ProviderId::Openai),
            ok(ProviderId::Gemini),
        ];
        let s = summarize(&r, &all).expect("anthropic & gemini are healthy");
        assert!(!s.all_green);
        assert_eq!(s.healthy_providers, vec!["anthropic", "gemini"]);
        assert_eq!(s.affected_providers, vec!["openai"]);
        assert_eq!(s.failed_providers, vec!["openai"]);
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
            slow_audit(Duration::from_millis(50), "9.9.9.9", OverallStatus::Red),
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

        // The next tick handles the change and emits the window once the audit completes.
        h.guard.check_route_and_tick(&env).await;
        h.io
            .wait_for("interceptor://risk-detected", 1000)
            .await
            .expect("risk-detected");
        assert_eq!(h.guard.gate(), Gate::Pending);
    }

    #[tokio::test(start_paused = true)]
    async fn test_allow_for_superseded_alert_changes_nothing() {
        let h = harness(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let ev = h
            .io
            .wait_for("interceptor://risk-detected", 2000)
            .await
            .expect("first risk-detected");
        let id1 = ev.0["id"].as_str().unwrap().to_string();

        // A new change C arrives; the user's allow for alert 1 reaches the guard afterwards.
        h.change("8.8.8.8").await;
        let err = h.guard.allow_network_alert(&id1, &all_providers()).await;
        assert_eq!(err.map_err(|e| e.code), Err(AllowErrorCode::AlertStale));
        assert_eq!(h.guard.gate(), Gate::Pending);
        let deadline = TInstant::now() + Duration::from_millis(2000);
        while TInstant::now() < deadline && h.io.count("interceptor://risk-detected") < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(h.io.count("interceptor://risk-detected"), 2);
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
        // Pending audit: immediate detecting alert emitted, allow refused with AuditPending.
        let h = harness(
            slow_audit(Duration::from_millis(300), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        let det = h
            .io
            .first("interceptor://risk-detected")
            .expect("immediate detecting");
        assert_eq!(det.0["phase"], "detecting");
        let internal_id = alert_id(&det);
        assert_eq!(
            h.guard
                .allow_network_alert(&internal_id, &all_providers())
                .await
                .map_err(|e| e.code),
            Err(AllowErrorCode::AuditPending)
        );
        assert_eq!(h.guard.gate(), Gate::Pending);
        assert!(!h.state.is_provider_session_allowed("anthropic").await);

        // Ready: enriched emitted, allow accepted, gate opens, trusted_exception written.
        let ev = h
            .io
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("ready enriched");
        assert_eq!(ev.0["phase"], "ready");
        let id = ev.0["id"].as_str().unwrap().to_string();
        h.guard
            .allow_network_alert(&id, &all_providers())
            .await
            .expect("allowed");
        assert_eq!(h.guard.gate(), Gate::Open);
        assert!(h.state.is_provider_session_allowed("anthropic").await);
        assert!(h.state.is_ip_trusted_for_provider("anthropic", "9.9.9.9").await);
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
        assert_eq!(
            h.guard
                .allow_network_alert(&id, &all_providers())
                .await
                .map_err(|e| e.code),
            Err(AllowErrorCode::AlertStale)
        );

        // Failed audit: refused as well, window and gate stay.
        let failing: AuditFn = Arc::new(|_, _| Box::pin(async { Err("geo down".to_string()) }));
        let h = harness(failing, "9.9.9.9").await;
        h.change("9.9.9.9").await;
        let ev = h
            .io
            .wait_for("interceptor://enriched", 3000)
            .await
            .expect("failed enrichment");
        assert_eq!(ev.0["phase"], "failed");
        let id = ev.0["id"].as_str().unwrap().to_string();
        assert_eq!(
            h.guard
                .allow_network_alert(&id, &all_providers())
                .await
                .map_err(|e| e.code),
            Err(AllowErrorCode::AuditPending)
        );
        assert_eq!(h.guard.gate(), Gate::Pending);
        assert!(h.env.hold_queue.current_alert().is_some());

        // The manual kill-switch outranks everything: refused with its own code.
        h.guard.set_manual_killswitch(true, &h.state).await;
        assert_eq!(
            h.guard
                .allow_network_alert(&id, &all_providers())
                .await
                .map_err(|e| e.code),
            Err(AllowErrorCode::BlockedByManualKillswitch)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_allow_without_audit_never_opens_gate() {
        // An allow sent to a failed (un-audited) alert is never honoured.
        let failing: AuditFn = Arc::new(|_, _| Box::pin(async { Err("geo down".to_string()) }));
        let h = harness(failing, "9.9.9.9").await;
        h.change("9.9.9.9").await;
        let ev = h
            .io
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("failed enriched");
        assert_eq!(ev.0["phase"], "failed");
        let id = ev.0["id"].as_str().unwrap().to_string();
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
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
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
        h.io
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("ready enrichment");
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
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        h.change("9.9.9.9").await;
        h.io
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("ready enrichment");
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
        let failed = h
            .io
            .first("interceptor://enriched")
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

    #[tokio::test(start_paused = true)]
    async fn test_returning_to_pinned_ip_after_blocked_audits_and_clears_blocked_providers() {
        let current_ip = Arc::new(std::sync::Mutex::new("9.9.9.9".to_string()));
        let probe_ip = Arc::clone(&current_ip);
        let audit_calls: Arc<std::sync::Mutex<Vec<ProviderId>>> = Arc::default();
        let audit_calls2 = Arc::clone(&audit_calls);
        let current_ip_audit = Arc::clone(&current_ip);
        let audit: AuditFn = Arc::new(move |provider, _force| {
            audit_calls2.lock().unwrap().push(provider);
            let ip = current_ip_audit.lock().unwrap().clone();
            Box::pin(async move {
                if ip == "9.9.9.9" {
                    Ok(test_report(provider, OverallStatus::Red, "9.9.9.9", "RU"))
                } else {
                    // Non-critical Yellow warning on pinned IP must still auto-restore.
                    let mut r = test_report(provider, OverallStatus::Yellow, "1.1.1.1", "DE");
                    r.checks = vec![
                        CheckResult::ok("Geo", "ok"),
                        CheckResult::warning("Timezone", "mismatch", None),
                    ];
                    Ok(r)
                }
            })
        });

        let io = Arc::new(TestIo::default());
        let state = AppState::new_in_memory();
        state
            .set_pinned_ip(Some("1.1.1.1".to_string()))
            .await
            .unwrap();
        state
            .set_interception_behavior(crate::state::InterceptionBehavior::AutoLockSilent)
            .await
            .unwrap();
        let probe: ProbeFn = Arc::new(move || {
            let ip = probe_ip.lock().unwrap().clone();
            Box::pin(async move { Some(ip) })
        });
        let env = Env {
            auditor: Auditor::new().expect("auditor"),
            state: state.clone(),
            hold_queue: Arc::new(HoldQueue::new()),
            io: io.clone(),
            audit,
            probe: Some(probe),
            resolve: None,
            audit_timeout: Duration::from_secs(5),
        };
        let guard = Arc::new(NetworkGuard::new());
        assert!(guard.install_env(env.clone()));
        {
            let mut inner = guard.inner.lock().await;
            inner.baseline = Some(Baseline {
                ip: "1.1.1.1".to_string(),
                country: Some("DE".to_string()),
                trusted: true,
            });
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        }

        // 1. Drop to RU -> immediately freezes Pending, then async silent audit blocks all 3.
        guard.inner.lock().await.route_dirty = true;
        guard.check_route_and_tick(&env).await;
        assert_eq!(guard.gate(), Gate::Pending);
        io.wait_for("network://changed", 2000)
            .await
            .expect("silent block event");
        assert_eq!(guard.gate(), Gate::Blocked);
        assert!(guard.inner.lock().await.pending.is_none());
        for p in KNOWN_PROVIDERS {
            assert!(state.is_provider_blocked(p).await);
        }
        let changed_before = io.count("network://changed");
        audit_calls.lock().unwrap().clear();

        // 2. Return to previously pinned IP ("1.1.1.1") -> clears blocked_providers, opens gate
        // immediately, emits network://changed, and verifies all 3 providers asynchronously.
        *current_ip.lock().unwrap() = "1.1.1.1".to_string();
        guard.inner.lock().await.route_dirty = true;
        guard.check_route_and_tick(&env).await;
        io.wait_for_count("network://changed", changed_before + 1, 2000)
            .await
            .expect("restored network://changed");
        for _ in 0..40 {
            if audit_calls.lock().unwrap().len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        assert_eq!(guard.gate(), Gate::Open);
        assert!(guard.inner.lock().await.handled_ip.is_none());
        assert!(state.get_data().await.blocked_providers.is_empty());
        assert_eq!(io.count("network://changed"), changed_before + 1);
        let audited = audit_calls.lock().unwrap();
        assert!(audited.contains(&ProviderId::Anthropic));
        assert!(audited.contains(&ProviderId::Openai));
        assert!(audited.contains(&ProviderId::Gemini));
    }

    #[tokio::test(start_paused = true)]
    async fn test_returning_to_baseline_with_critical_audit_stays_blocked() {
        let audit: AuditFn = Arc::new(move |provider, _force| {
            Box::pin(async move { Ok(test_report(provider, OverallStatus::Red, "1.1.1.1", "RU")) })
        });
        let io = Arc::new(TestIo::default());
        let state = AppState::new_in_memory();
        state.block_provider("anthropic").await.unwrap();
        let probe: ProbeFn = Arc::new(|| Box::pin(async { Some("1.1.1.1".to_string()) }));
        let env = Env {
            auditor: Auditor::new().expect("auditor"),
            state: state.clone(),
            hold_queue: Arc::new(HoldQueue::new()),
            io,
            audit,
            probe: Some(probe),
            resolve: None,
            audit_timeout: Duration::from_secs(5),
        };
        let guard = Arc::new(NetworkGuard::new());
        assert!(guard.install_env(env.clone()));
        {
            let mut inner = guard.inner.lock().await;
            inner.baseline = Some(Baseline {
                ip: "1.1.1.1".to_string(),
                country: Some("DE".to_string()),
                trusted: true,
            });
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        }
        guard.set_gate(Gate::Blocked);
        guard.inner.lock().await.route_dirty = true;
        guard.check_route_and_tick(&env).await;

        assert_eq!(guard.gate(), Gate::Blocked);
        assert!(state.is_provider_blocked("anthropic").await);
    }

    #[tokio::test(start_paused = true)]
    async fn test_transient_route_flicker_on_non_pinned_warning_network_recovers_and_keeps_allows()
    {
        let probe_calls = Arc::new(AtomicUsize::new(0));
        let probe_calls2 = Arc::clone(&probe_calls);
        let probe: ProbeFn = Arc::new(move || {
            let n = probe_calls2.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if n == 0 {
                    None // brief DNS/socket hiccup during local route flicker
                } else {
                    Some("8.8.8.8".to_string())
                }
            })
        });
        let audit: AuditFn = Arc::new(move |provider, _force| {
            Box::pin(async move {
                let mut r = test_report(provider, OverallStatus::Yellow, "8.8.8.8", "NL");
                r.unknown_count = 1;
                r.checks = vec![
                    CheckResult::ok("Geo", "ok"),
                    CheckResult::warning("Timezone", "mismatch", None),
                ];
                Ok(r)
            })
        });

        let io = Arc::new(TestIo::default());
        let state = AppState::new_in_memory();
        // Not pinned, user has a session allowance on this warning network.
        state.allow_provider_for_session("anthropic").await.unwrap();
        let env = Env {
            auditor: Auditor::new().expect("auditor"),
            state: state.clone(),
            hold_queue: Arc::new(HoldQueue::new()),
            io: io.clone(),
            audit,
            probe: Some(probe),
            resolve: None,
            audit_timeout: Duration::from_secs(5),
        };
        let guard = Arc::new(NetworkGuard::new());
        assert!(guard.install_env(env.clone()));
        {
            let mut inner = guard.inner.lock().await;
            inner.baseline = Some(Baseline {
                ip: "8.8.8.8".to_string(),
                country: Some("NL".to_string()),
                trusted: true,
            });
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        }

        // 1. Transient route flicker where probe returns None: stays recoverable (not Blocked)
        //    and preserves session_allowed_providers.
        guard.inner.lock().await.route_dirty = true;
        guard.check_route_and_tick(&env).await;
        assert_eq!(guard.gate(), Gate::Pending);
        assert!(state.is_provider_session_allowed("anthropic").await);
        assert!(state.get_data().await.blocked_providers.is_empty());

        // 2. Next regular probe gets unchanged IP "8.8.8.8" on non-pinned warning network:
        //    restores Gate::Open and keeps session allowance.
        guard.inner.lock().await.last_probe =
            Instant::now().checked_sub(Duration::from_millis(PROBE_MIN_GAP_MS + 10));
        guard.check_route_and_tick(&env).await;
        assert_eq!(probe_calls.load(Ordering::SeqCst), 2);
        assert_eq!(guard.gate(), Gate::Open);
        assert!(state.is_provider_session_allowed("anthropic").await);
        assert!(state.get_data().await.blocked_providers.is_empty());
        assert_eq!(io.count("interceptor://risk-detected"), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_confirm_current_session_marks_untrusted_baseline_trusted() {
        let h = harness(
            slow_audit(Duration::from_millis(10), "5.5.5.5", OverallStatus::Red),
            "5.5.5.5",
        )
        .await;
        {
            let mut inner = h.guard.inner.lock().await;
            inner.baseline = Some(Baseline {
                ip: "5.5.5.5".to_string(),
                country: Some("RU".to_string()),
                trusted: false,
            });
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        }
        assert_eq!(h.guard.gate(), Gate::Open);

        let tel = test_report(ProviderId::Anthropic, OverallStatus::Red, "5.5.5.5", "RU").telemetry;
        h.guard.confirm_current_session(Some(&tel)).await;
        {
            let inner = h.guard.inner.lock().await;
            assert!(inner.baseline.as_ref().is_some_and(|b| b.trusted));
            assert!(inner.handled_ip.is_none());
        }

        // Subsequent regular probe on the same IP must not freeze or open an alert.
        let probes_before = h.probes.load(Ordering::SeqCst);
        h.guard.inner.lock().await.last_probe =
            Instant::now().checked_sub(Duration::from_millis(PROBE_MIN_GAP_MS + 10));
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.probes.load(Ordering::SeqCst), probes_before + 1);
        assert_eq!(h.guard.gate(), Gate::Open);
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
        assert!(h.state.get_data().await.blocked_providers.is_empty());

        // Manual kill-switch must not be lifted by confirm_current_session.
        assert!(h.guard.set_manual_killswitch(true, &h.state).await);
        h.guard.confirm_current_session(Some(&tel)).await;
        assert_eq!(h.guard.gate(), Gate::Blocked);
        assert!(h.guard.is_manual_killswitch());
    }

    #[tokio::test(start_paused = true)]
    async fn test_regular_probe_on_untrusted_baseline_respects_all_session_allowed() {
        let h = harness(
            slow_audit(Duration::from_millis(10), "5.5.5.5", OverallStatus::Red),
            "5.5.5.5",
        )
        .await;
        for p in KNOWN_PROVIDERS {
            h.state.allow_provider_for_session(p).await.unwrap();
        }
        {
            let mut inner = h.guard.inner.lock().await;
            inner.baseline = Some(Baseline {
                ip: "5.5.5.5".to_string(),
                country: Some("RU".to_string()),
                trusted: false,
            });
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        }

        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.guard.gate(), Gate::Open);
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
        assert!(
            h.guard
                .inner
                .lock()
                .await
                .baseline
                .as_ref()
                .is_some_and(|b| b.trusted)
        );
        for p in KNOWN_PROVIDERS {
            assert!(h.state.is_provider_session_allowed(p).await);
        }
    }

    #[test]
    fn test_effective_tray_report_downgrades_red_when_session_allowed_and_open() {
        let report = test_report(ProviderId::Anthropic, OverallStatus::Red, "5.5.5.5", "RU");
        let mut st = crate::state::AppStateData::default();
        assert_eq!(
            effective_tray_report(&report, false, &st).overall_status,
            OverallStatus::Red
        );

        st.session_allowed_providers.insert("anthropic".to_string());
        assert_eq!(
            effective_tray_report(&report, false, &st).overall_status,
            OverallStatus::Yellow
        );
        // When actually blocked/pending, keep Red.
        assert_eq!(
            effective_tray_report(&report, true, &st).overall_status,
            OverallStatus::Red
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_split_tunnel_mode_ignores_1_1_1_1_exit_ip_jitter() {
        let h = harness(
            slow_audit(Duration::from_millis(10), "5.5.5.5", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;
        h.state.set_split_tunnel_mode(true).await.unwrap();
        {
            let mut inner = h.guard.inner.lock().await;
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
            inner.route_dirty = true;
        }

        // Baseline is "1.1.1.1", fake probe returns "9.9.9.9" + route_dirty:
        // split_tunnel_mode must NOT trip, show alert popup, block providers, or freeze the gate.
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.guard.gate(), Gate::Open);
        assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
        assert!(h.state.get_data().await.blocked_providers.is_empty());
        assert_eq!(
            h.guard.inner.lock().await.observed_ip.as_deref(),
            Some("9.9.9.9")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn gate_reason_populated_on_ready_risk_detected_event() {
        let h = harness(
            slow_audit(Duration::from_millis(20), "9.9.9.9", OverallStatus::Red),
            "9.9.9.9",
        )
        .await;

        let fp = compute_local_route_fingerprint(None);
        {
            let mut inner = h.guard.inner.lock().await;
            inner.last_route_fp = Some(format!("{fp}-old"));
            inner.route_dirty = true;
        }
        h.guard.check_route_and_tick(&h.env).await;

        // Window-first: detecting alert emitted immediately before slow audit completes.
        let det = h
            .env
            .hold_queue
            .current_alert()
            .expect("detecting alert emitted immediately");
        assert_eq!(det.phase, PHASE_DETECTING);
        assert!(
            det.gate_reason
                .as_deref()
                .is_some_and(|r| !r.trim().is_empty()),
            "expected detecting gate_reason, got {:?}",
            det.gate_reason
        );

        h.io.wait_for("interceptor://enriched", 1000)
            .await
            .expect("enriched ready event emitted");

        let ready = h
            .env
            .hold_queue
            .current_alert()
            .expect("alert still held after audit");
        assert_eq!(ready.phase, PHASE_READY);
        assert!(
            ready
                .gate_reason
                .as_deref()
                .is_some_and(|r| !r.trim().is_empty()),
            "expected ready gate_reason, got {:?}",
            ready.gate_reason
        );
        assert_eq!(h.guard.gate_reason(), ready.gate_reason);
    }

    #[tokio::test(start_paused = true)]
    async fn pause_until_network_change_stays_on_same_ip_and_clears_on_change_or_invalidate_cache()
    {
        let probe_ip = Arc::new(std::sync::Mutex::new("1.1.1.1".to_string()));
        let probe_ip_env = Arc::clone(&probe_ip);
        let h = harness_env(
            slow_audit(Duration::from_millis(10), "1.1.1.1", OverallStatus::Green),
            "1.1.1.1",
            move |env| {
                env.probe = Some(Arc::new(move || {
                    let ip = probe_ip_env.lock().unwrap().clone();
                    Box::pin(async move { Some(ip) })
                }));
            },
        )
        .await;

        // 1. Engage PauseMode::UntilNetworkChange on baseline 1.1.1.1.
        let status = h
            .guard
            .pause_until_network_change(&h.state, Some("Пауза на время теста".to_string()))
            .await;
        assert!(status.paused);
        assert_eq!(status.mode, PauseMode::UntilNetworkChange);
        assert_eq!(status.gate, "blocked");
        assert_eq!(status.gate_reason.as_deref(), Some("Пауза на время теста"));
        assert_eq!(h.guard.gate(), Gate::Blocked);
        assert!(!h.state.get_data().await.blocked_providers.is_empty());

        // Same IP tick (after probe interval) MUST keep PauseMode::UntilNetworkChange.
        tokio::time::advance(Duration::from_secs(2)).await;
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.guard.pause_mode(), PauseMode::UntilNetworkChange);
        assert_eq!(h.guard.gate(), Gate::Blocked);

        // 2. invalidate_cache_and_clear_pause automatically clears UntilNetworkChange pause.
        let dummy_tel = NetworkTelemetry {
            ip: "1.1.1.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            resolved_at: crate::auditor::network::current_timestamp(),
        };
        h.env.auditor.resolver.set_cached(dummy_tel).await;
        let cleared = h
            .guard
            .invalidate_cache_and_clear_pause(&h.env.auditor.resolver, Some(&h.state))
            .await;
        assert!(cleared);
        assert_eq!(h.guard.pause_mode(), PauseMode::None);
        assert_eq!(h.guard.gate(), Gate::Open);
        assert!(h.guard.gate_reason().is_none());
        assert!(h.state.get_data().await.blocked_providers.is_empty());

        // 3. Re-engage UntilNetworkChange and trigger a real IP/network change on next tick -> cleared.
        h.guard
            .pause_until_network_change(&h.state, Some("Ждём новую сеть".to_string()))
            .await;
        assert_eq!(h.guard.pause_mode(), PauseMode::UntilNetworkChange);
        {
            let mut w = probe_ip.lock().unwrap();
            *w = "9.9.9.9".to_string();
        }
        {
            // `last_probe` uses `std::time::Instant`; clear it so the next tick runs the probe.
            let mut inner = h.guard.inner.lock().await;
            inner.last_probe = None;
        }
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.guard.pause_mode(), PauseMode::None);

        // 4. Manual kill-switch must NEVER clear on invalidate_cache_and_clear_pause.
        h.guard.set_manual_killswitch(true, &h.state).await;
        assert_eq!(h.guard.pause_mode(), PauseMode::Manual);
        assert!(
            !h.guard
                .invalidate_cache_and_clear_pause(&h.env.auditor.resolver, Some(&h.state))
                .await
        );
        assert_eq!(h.guard.pause_mode(), PauseMode::Manual);
        assert_eq!(h.guard.gate(), Gate::Blocked);
    }

    #[tokio::test(start_paused = true)]
    async fn test_red_claude_never_blocks_healthy_chatgpt_ask_popup() {
        let audit: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                match provider {
                    ProviderId::Anthropic => {
                        let mut r = test_report(provider, OverallStatus::Red, "203.0.113.10", "GB");
                        r.checks = vec![CheckResult::critical(
                            "IMPOSSIBLE_TRAVEL_CRITICAL",
                            "Country changed FR -> GB in 2 min",
                            None,
                        )];
                        Ok(r)
                    }
                    ProviderId::Openai => Ok(test_report(
                        provider,
                        OverallStatus::Green,
                        "203.0.113.10",
                        "GB",
                    )),
                    ProviderId::Gemini => Ok(test_report(
                        provider,
                        OverallStatus::Green,
                        "136.244.114.42",
                        "FR",
                    )),
                }
            })
        });

        let h = harness(audit, "203.0.113.10").await;
        // Bind Gemini to a Zastava key so only Anthropic & OpenAI are unrouted.
        let fr_route =
            crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
        let fr_id = h.state.upsert_route(fr_route).await.unwrap();
        h.state
            .bind_provider_route("gemini", Some(&fr_id))
            .await
            .unwrap();

        h.change("203.0.113.10").await;
        let ready = h
            .io
            .wait_for("interceptor://enriched", 3000)
            .await
            .expect("enriched ready");
        assert_eq!(ready.0["phase"], "ready");
        let id = ready.0["id"].as_str().expect("alert id");

        // Healthy ChatGPT is immediately open once audit confirms OpenAI is Green;
        // Claude stays Pending waiting for decision.
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
        assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);

        // User blocks the alert (or hold TTL expires) -> ONLY Claude is blocked.
        h.env.hold_queue.resolve(id, HoldResolution::Block).await;
        tokio::task::yield_now().await;
        for _ in 0..10 {
            if h.guard.gate_for(ProviderId::Anthropic) == Gate::Blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
        assert!(h.state.is_provider_blocked("anthropic").await);
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert!(!h.state.is_provider_blocked("openai").await);
        assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
        assert!(!h.state.is_provider_blocked("gemini").await);
    }

    #[tokio::test(start_paused = true)]
    async fn test_red_claude_never_blocks_healthy_chatgpt_silent_and_auto_allow() {
        for behavior in [
            InterceptionBehavior::AutoLockSilent,
            InterceptionBehavior::AutoAllowTrusted,
        ] {
            let audit: AuditFn = Arc::new(|provider, _force| {
                Box::pin(async move {
                    match provider {
                        ProviderId::Anthropic => {
                            let mut r =
                                test_report(provider, OverallStatus::Red, "203.0.113.10", "GB");
                            r.checks = vec![CheckResult::critical(
                                "IMPOSSIBLE_TRAVEL_CRITICAL",
                                "Country changed FR -> GB in 2 min",
                                None,
                            )];
                            Ok(r)
                        }
                        ProviderId::Openai => Ok(test_report(
                            provider,
                            OverallStatus::Green,
                            "203.0.113.10",
                            "GB",
                        )),
                        ProviderId::Gemini => Ok(test_report(
                            provider,
                            OverallStatus::Green,
                            "136.244.114.42",
                            "FR",
                        )),
                    }
                })
            });

            let h = harness(audit, "203.0.113.10").await;
            let fr_route =
                crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
            let fr_id = h.state.upsert_route(fr_route).await.unwrap();
            h.state
                .bind_provider_route("gemini", Some(&fr_id))
                .await
                .unwrap();
            h.state.set_interception_behavior(behavior).await.unwrap();

            {
                let mut inner = h.guard.inner.lock().await;
                inner.route_dirty = true;
            }
            h.guard.check_route_and_tick(&h.env).await;
            h.io.wait_for("network://changed", 2000)
                .await
                .expect("silent audit settled");

            assert_eq!(
                h.guard.gate_for(ProviderId::Anthropic),
                Gate::Blocked,
                "anthropic must be blocked under {behavior:?}"
            );
            assert!(
                h.state.is_provider_blocked("anthropic").await,
                "anthropic must be in blocked_providers under {behavior:?}"
            );
            assert_eq!(
                h.guard.gate_for(ProviderId::Openai),
                Gate::Open,
                "healthy openai must remain Open under {behavior:?}"
            );
            assert!(
                !h.state.is_provider_blocked("openai").await,
                "healthy openai must not be collaterally blocked under {behavior:?}"
            );
            assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_finish_audit_opens_all_healthy_providers_when_affected_is_empty() {
        let audit: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                Ok(test_report(
                    provider,
                    OverallStatus::Green,
                    "145.241.193.245",
                    "GB",
                ))
            })
        });
        let h = harness(audit, "145.241.193.245").await;
        let fr_route =
            crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
        let fr_id = h.state.upsert_route(fr_route).await.unwrap();
        h.state
            .bind_provider_route("gemini", Some(&fr_id))
            .await
            .unwrap();

        h.change("145.241.193.245").await;
        h.io.wait_for("network://changed", 3000)
            .await
            .expect("network://changed");
        assert_eq!(h.io.count("interceptor://enriched"), 0);
        assert!(h.env.hold_queue.current_alert().is_none());

        // Both unrouted providers audited Green -> must immediately transition to Gate::Open,
        // never stuck in Pending or written to blocked_providers.
        assert_eq!(h.guard.gate(), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
        assert!(h.state.get_data().await.blocked_providers.is_empty());
        assert_eq!(h.guard.pause_mode(), PauseMode::None);
        assert!(h.guard.gate_reason().is_none());
        assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_spawn_decision_waiter_with_empty_affected_never_blocks_unrouted_providers() {
        for resolution in [None, Some(HoldResolution::Block)] {
            let h = harness(
                slow_audit(
                    Duration::from_millis(10),
                    "145.241.193.245",
                    OverallStatus::Green,
                ),
                "145.241.193.245",
            )
            .await;
            let fr_route =
                crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
            let fr_id = h.state.upsert_route(fr_route).await.unwrap();
            h.state
                .bind_provider_route("gemini", Some(&fr_id))
                .await
                .unwrap();

            let id = "waiter-empty-affected".to_string();
            let rx = h.env.hold_queue.register(id.clone(), ALL_PROVIDERS).await;
            let tel = test_report(
                ProviderId::Anthropic,
                OverallStatus::Green,
                "145.241.193.245",
                "GB",
            )
            .telemetry;
            let epoch = {
                let mut inner = h.guard.inner.lock().await;
                inner.observed_ip = Some("145.241.193.245".to_string());
                inner.pending = Some(Pending {
                    id: id.clone(),
                    epoch: inner.epoch,
                    target_ip: "145.241.193.245".to_string(),
                    tel: Some(tel),
                    clear_old_state: None,
                    affected_providers: Vec::new(),
                    already_blocked_providers: Vec::new(),
                    healthy_providers: vec!["anthropic", "openai"],
                    alert_emitted: true,
                });
                inner.epoch
            };
            h.guard.set_gate(Gate::Pending);
            h.guard.spawn_decision_waiter(&h.env, id.clone(), epoch, rx);

            if let Some(res) = resolution {
                assert!(h.env.hold_queue.resolve(&id, res).await);
                tokio::time::sleep(Duration::from_millis(20)).await;
            } else {
                tokio::time::sleep(Duration::from_secs(DEFAULT_HOLD_TTL_SECS + 1)).await;
            }

            assert_eq!(h.guard.gate(), Gate::Open);
            assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
            assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
            assert!(!h.state.is_provider_blocked("anthropic").await);
            assert!(!h.state.is_provider_blocked("openai").await);
            assert_eq!(h.guard.pause_mode(), PauseMode::None);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_routing_gemini_does_not_freeze_or_reset_anthropic_and_openai() {
        let audit: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                Ok(test_report(
                    provider,
                    OverallStatus::Green,
                    "145.241.193.245",
                    "GB",
                ))
            })
        });
        let h = harness(audit, "145.241.193.245").await;
        h.state
            .set_pinned_ip(Some("145.241.193.245".to_string()))
            .await
            .unwrap();
        h.state.set_strict_pinning_enabled(true).await.unwrap();
        {
            let mut inner = h.guard.inner.lock().await;
            inner.baseline = None;
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        }

        // Initial startup tick on pinned VPN IP sets baseline cleanly and keeps gates Open.
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.guard.gate(), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);

        // Bind Gemini to a Zastava key -> unrouted shrinks from 3 to 2.
        let fr_route =
            crate::routing::parse_route_key("socks5://136.244.114.42:1080#fr", 1).unwrap();
        let fr_id = h.state.upsert_route(fr_route).await.unwrap();
        h.state
            .bind_provider_route("gemini", Some(&fr_id))
            .await
            .unwrap();
        h.guard.open_routed_providers(&["gemini"]);

        h.guard.inner.lock().await.last_probe = None;
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.guard.gate(), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
        assert!(h.state.get_data().await.blocked_providers.is_empty());

        // Even if Gemini is unbound later, healthy Anthropic & OpenAI remain Open.
        h.state.bind_provider_route("gemini", None).await.unwrap();
        h.guard.inner.lock().await.last_probe = None;
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.guard.gate(), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
    }

    #[tokio::test]
    async fn network_guard_client_uses_neutral_user_agent() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nip=1.2.3.4\n",
                    )
                    .await;
            }
        });

        let guard = NetworkGuard::new();
        let _ = guard
            .client
            .get(format!("http://127.0.0.1:{port}/cdn-cgi/trace"))
            .send()
            .await
            .unwrap();
        let raw_req = rx.await.unwrap();
        assert!(
            !raw_req.to_ascii_lowercase().contains("zastava"),
            "Guard client User-Agent must never reveal Zastava: {raw_req}"
        );
        assert!(raw_req.contains(crate::auditor::network::NEUTRAL_USER_AGENT));
    }

    #[tokio::test]
    async fn guard_audit_all_with_unbound_routes_never_probes_provider_domains() {
        use crate::auditor::seams::fakes::{FakeDns, FakeSystem, FakeUdp};
        use crate::auditor::seams::{AuditEnv, HttpProbeOutcome, IpProbe, LookupOutcome};

        struct RecordingProbe {
            urls: std::sync::Mutex<Vec<String>>,
        }
        impl IpProbe for RecordingProbe {
            fn get<'a>(
                &'a self,
                url: &'a str,
                _limit: Duration,
            ) -> crate::auditor::seams::BoxFuture<'a, HttpProbeOutcome> {
                self.urls.lock().unwrap().push(url.to_string());
                let body = if url.contains("ipwho.is") {
                    r#"{"success":true,"country_code":"NL","connection":{"asn":20473,"org":"Choopa"}}"#
                } else {
                    "fl=1\nip=203.0.113.9\nloc=NL\ncolo=AMS\n"
                };
                Box::pin(async move {
                    HttpProbeOutcome::Response {
                        status: 200,
                        body: body.to_string(),
                    }
                })
            }
        }

        let probe = Arc::new(RecordingProbe {
            urls: std::sync::Mutex::new(Vec::new()),
        });
        let env = AuditEnv {
            dns: Arc::new(FakeDns::new(LookupOutcome::Timeout)),
            probe: probe.clone(),
            udp: Arc::new(FakeUdp::new()),
            system: Arc::new(FakeSystem::healthy()),
        };
        let auditor = Auditor::with_env(env).unwrap();
        let tel = test_report(ProviderId::Anthropic, OverallStatus::Green, "203.0.113.9", "NL")
            .telemetry;
        auditor.resolver.set_cached(tel).await;

        let state = AppState::new_in_memory();
        let audit: AuditFn = Arc::new(move |provider, force| {
            let (auditor, state) = (auditor.clone(), state.clone());
            Box::pin(async move { auditor.evaluate_all(provider, &state, force).await })
        });

        let results = audit_all(&audit).await;
        assert_eq!(results.len(), 3);
        let seen = probe.urls.lock().unwrap();
        assert!(!seen.is_empty());
        for url in seen.iter() {
            assert!(
                !url.contains("claude.ai") && !url.contains("chatgpt.com"),
                "audit_all with route: None must never probe provider domains: {url}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_yellow_never_blocks_or_alerts_in_all_behaviors() {
        for behavior in [
            InterceptionBehavior::AskPopup,
            InterceptionBehavior::AutoLockSilent,
            InterceptionBehavior::AutoAllowTrusted,
        ] {
            let audit: AuditFn = Arc::new(|provider, _force| {
                Box::pin(async move {
                    let mut r = test_report(provider, OverallStatus::Yellow, "9.9.9.9", "KZ");
                    r.checks = vec![
                        CheckResult::ok("GEO_LOCATION", "KZ"),
                        CheckResult::warning("TIMEZONE_MISMATCH", "TZ offset", None),
                    ];
                    Ok(r)
                })
            });
            let h = harness(audit, "9.9.9.9").await;
            h.state.set_interception_behavior(behavior).await.unwrap();
            h.change("9.9.9.9").await;
            h.io.wait_for("network://changed", 2000)
                .await
                .expect("yellow settled");
            if behavior == InterceptionBehavior::AskPopup {
                assert!(
                    h.io.hides.load(Ordering::SeqCst) >= 1,
                    "AskPopup quick detecting popup must auto-hide when audit settles Yellow"
                );
            } else {
                assert_eq!(
                    h.io.count("interceptor://risk-detected"),
                    0,
                    "Yellow must never emit risk-detected under {behavior:?}"
                );
                assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
            }
            assert_eq!(
                h.io.count("interceptor://enriched"),
                0,
                "Yellow must never enrich/keep an active risk alert under {behavior:?}"
            );
            assert!(h.env.hold_queue.current_alert().is_none());
            assert_eq!(h.guard.gate(), Gate::Open);
            assert!(h.state.get_data().await.blocked_providers.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_trusted_exception_survives_restart_and_network_change_no_alert() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let state1 = AppState::load_or_default(state_path.clone());
        let io1 = Arc::new(TestIo::default());
        let audit_red: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                r.checks = vec![r.geo_result.clone()];
                Ok(r)
            })
        });
        let env1 = Env {
            auditor: Auditor::new().expect("auditor"),
            state: state1.clone(),
            hold_queue: Arc::new(HoldQueue::new()),
            io: io1.clone(),
            audit: audit_red.clone(),
            probe: Some(Arc::new(|| Box::pin(async { Some("5.5.5.5".to_string()) }))),
            resolve: None,
            audit_timeout: Duration::from_secs(2),
        };
        let guard1 = Arc::new(NetworkGuard::new());
        guard1.install_env(env1.clone());
        guard1.register_self_weak();
        guard1.inner.lock().await.baseline = Some(Baseline {
            ip: "1.1.1.1".to_string(),
            country: Some("DE".to_string()),
            trusted: true,
        });
        {
            let mut inner = guard1.inner.lock().await;
            guard1
                .handle_change_locked(&env1, &mut inner, "5.5.5.5".to_string(), Instant::now())
                .await;
        }
        let ev = io1
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("initial ready alert on Critical non-excepted IP");
        let id = ev.0["id"].as_str().unwrap().to_string();
        guard1
            .allow_network_alert(&id, &["anthropic".to_string()])
            .await
            .unwrap();
        assert!(state1.is_ip_trusted_for_provider("anthropic", "5.5.5.5").await);

        // Simulate switching away and restarting app from disk (session_allowed cleared,
        // trusted_exceptions preserved). Force-allowing openai & gemini too for completeness.
        state1.add_trusted_exception("openai", "5.5.5.5").await.unwrap();
        state1.add_trusted_exception("gemini", "5.5.5.5").await.unwrap();
        drop(state1);

        let state2 = AppState::load_or_default(state_path);
        assert!(!state2.is_provider_session_allowed("anthropic").await);
        assert!(state2.is_ip_trusted_for_provider("anthropic", "5.5.5.5").await);

        let io2 = Arc::new(TestIo::default());
        let env2 = Env {
            auditor: Auditor::new().expect("auditor"),
            state: state2.clone(),
            hold_queue: Arc::new(HoldQueue::new()),
            io: io2.clone(),
            audit: audit_red,
            probe: Some(Arc::new(|| Box::pin(async { Some("5.5.5.5".to_string()) }))),
            resolve: None,
            audit_timeout: Duration::from_secs(2),
        };
        let guard2 = Arc::new(NetworkGuard::new());
        guard2.install_env(env2.clone());
        guard2.register_self_weak();
        guard2.inner.lock().await.baseline = Some(Baseline {
            ip: "8.8.8.8".to_string(),
            country: Some("NL".to_string()),
            trusted: true,
        });
        {
            let mut inner = guard2.inner.lock().await;
            guard2
                .handle_change_locked(&env2, &mut inner, "5.5.5.5".to_string(), Instant::now())
                .await;
        }
        assert_eq!(io2.count("interceptor://risk-detected"), 0);
        assert_eq!(io2.shows.load(Ordering::SeqCst), 0);
        assert_eq!(guard2.gate(), Gate::Open);
        assert!(state2.get_data().await.blocked_providers.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_disabled_provider_skipped_in_audit_gates_and_alerts() {
        let audited_providers: Arc<std::sync::Mutex<Vec<ProviderId>>> = Arc::default();
        let audited2 = Arc::clone(&audited_providers);
        let audit: AuditFn = Arc::new(move |provider, _force| {
            audited2.lock().unwrap().push(provider);
            Box::pin(async move {
                if provider == ProviderId::Gemini {
                    let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                    r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                    r.checks = vec![r.geo_result.clone()];
                    Ok(r)
                } else {
                    Ok(test_report(provider, OverallStatus::Green, "5.5.5.5", "NL"))
                }
            })
        });
        let h = harness(audit, "5.5.5.5").await;
        h.state.block_provider("gemini").await.unwrap();
        h.state
            .set_provider_monitoring("gemini", false)
            .await
            .unwrap();
        h.guard.sync_provider_disabled("gemini", &h.state).await;
        assert!(!h.state.is_provider_blocked("gemini").await);
        assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);

        h.change("5.5.5.5").await;
        h.io.wait_for("network://changed", 2000)
            .await
            .expect("audit settled");
        assert_eq!(h.io.count("interceptor://enriched"), 0);
        assert!(h.env.hold_queue.current_alert().is_none());
        assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
        assert_eq!(h.guard.gate(), Gate::Open);
        assert!(!audited_providers.lock().unwrap().contains(&ProviderId::Gemini));
    }

    #[tokio::test(start_paused = true)]
    async fn test_already_blocked_alert_suppression_and_partial_newly_affected_alert() {
        let audit: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                match provider {
                    ProviderId::Anthropic | ProviderId::Openai => {
                        let mut r = test_report(provider, OverallStatus::Red, "6.6.6.6", "RU");
                        r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                        r.checks = vec![r.geo_result.clone()];
                        Ok(r)
                    }
                    ProviderId::Gemini => {
                        Ok(test_report(provider, OverallStatus::Green, "6.6.6.6", "NL"))
                    }
                }
            })
        });
        let h = harness(audit, "6.6.6.6").await;
        // Disable gemini; block BOTH anthropic and openai before network change.
        h.state
            .set_provider_monitoring("gemini", false)
            .await
            .unwrap();
        h.state.block_provider("anthropic").await.unwrap();
        h.state.block_provider("openai").await.unwrap();
        h.guard.sync_gates_with_state(&h.state).await;

        // 1. All violated enabled providers are ALREADY blocked -> NO alert popup.
        h.change("6.6.6.6").await;
        h.io.wait_for("network://changed", 2000)
            .await
            .expect("network://changed after audit");
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
        assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Blocked);
        assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);

        // 2. Now only anthropic is blocked while openai was allowed -> alert ONLY for openai,
        //    and allowing it keeps anthropic blocked while persisting exception only for openai.
        h.state.unblock_provider("openai").await.unwrap();
        h.guard.sync_gates_with_state(&h.state).await;
        h.change("7.7.7.7").await;
        let det = h
            .io
            .wait_for("interceptor://risk-detected", 2000)
            .await
            .expect("detecting alert for newly affected openai");
        assert_eq!(det.0["phase"], "detecting");
        assert_eq!(det.0["provider"], "openai");
        let enr = h
            .io
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("ready enrichment for newly affected openai");
        assert_eq!(enr.0["phase"], "ready");
        let id = enr.0["id"].as_str().unwrap().to_string();
        let affected = h
            .guard
            .affected_providers_for_alert(&id)
            .await
            .expect("pending affected");
        assert_eq!(affected, vec!["openai".to_string()]);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Pending);

        h.guard
            .allow_network_alert(&id, &affected)
            .await
            .unwrap();
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
        assert!(h.state.is_provider_blocked("anthropic").await);
        assert!(!h.state.is_provider_blocked("openai").await);
    }

    #[tokio::test(start_paused = true)]
    async fn test_silent_auto_recovery_when_checks_become_yellow_pinned_or_excepted() {
        let mode = Arc::new(AtomicUsize::new(0));
        let mode2 = Arc::clone(&mode);
        let audit: AuditFn = Arc::new(move |provider, _force| {
            let cur = mode2.load(Ordering::SeqCst);
            Box::pin(async move {
                if cur == 0 {
                    let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                    r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                    r.checks = vec![r.geo_result.clone()];
                    Ok(r)
                } else {
                    let mut r = test_report(provider, OverallStatus::Yellow, "9.9.9.9", "RS");
                    r.checks = vec![
                        CheckResult::ok("GEO_LOCATION", "RS"),
                        CheckResult::warning("TIMEZONE_MISMATCH", "TZ", None),
                    ];
                    Ok(r)
                }
            })
        });
        let h = harness(audit, "9.9.9.9").await;
        h.state.block_provider("anthropic").await.unwrap();
        h.state.block_provider("openai").await.unwrap();
        h.guard.sync_gates_with_state(&h.state).await;
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);

        // Recovery via Yellow (`no_critical_and_geo_ok`) on new IP -> silent unblock & Open!
        mode.store(1, Ordering::SeqCst);
        h.change("9.9.9.9").await;
        h.io.wait_for("network://changed", 2000)
            .await
            .expect("silent recovery event");
        assert_eq!(h.io.count("interceptor://enriched"), 0);
        assert!(h.env.hold_queue.current_alert().is_none());
        assert!(h.io.hides.load(Ordering::SeqCst) >= 1);
        assert_eq!(h.guard.gate(), Gate::Open);
        assert!(h.state.get_data().await.blocked_providers.is_empty());

        // Recovery on same baseline IP when per-provider pinned_ips matches and geo is OK!
        mode.store(0, Ordering::SeqCst);
        h.state.block_provider("anthropic").await.unwrap();
        h.state
            .set_pinned_ip_for("anthropic", Some("5.5.5.5".to_string()))
            .await
            .unwrap();
        h.state
            .add_trusted_exception("openai", "5.5.5.5")
            .await
            .unwrap();
        h.state
            .set_provider_monitoring("gemini", false)
            .await
            .unwrap();
        h.guard.sync_gates_with_state(&h.state).await;
        {
            let mut inner = h.guard.inner.lock().await;
            inner.baseline = Some(Baseline {
                ip: "5.5.5.5".to_string(),
                country: Some("RU".to_string()),
                trusted: true,
            });
            // Keep trusted_exception for anthropic off to ensure trusted_exceptions OR Yellow recovers cleanly:
        }
        // Make geo DE with impossible-travel critical so pinned_ips["anthropic"] recovers anthropic & trusted_exception recovers openai.
        let travel_audit: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "DE");
                r.checks = vec![CheckResult::critical(
                    "IMPOSSIBLE_TRAVEL_CRITICAL",
                    "DE hop",
                    None,
                )];
                Ok(r)
            })
        });
        let h2 = harness(travel_audit, "5.5.5.5").await;
        h2.state.block_provider("anthropic").await.unwrap();
        h2.state.block_provider("openai").await.unwrap();
        h2.state
            .set_pinned_ip_for("anthropic", Some("5.5.5.5".to_string()))
            .await
            .unwrap();
        h2.state
            .add_trusted_exception("openai", "5.5.5.5")
            .await
            .unwrap();
        h2.state
            .set_provider_monitoring("gemini", false)
            .await
            .unwrap();
        h2.guard.sync_gates_with_state(&h2.state).await;
        {
            let mut inner = h2.guard.inner.lock().await;
            h2.guard
                .verify_and_restore_baseline_locked(&h2.env, &mut inner, "5.5.5.5", true)
                .await;
        }
        assert_eq!(h2.io.count("interceptor://risk-detected"), 0);
        assert_eq!(h2.guard.gate(), Gate::Open);
        assert!(h2.state.get_data().await.blocked_providers.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_startup_pinned_ip_and_stale_block_silent_clear_no_alert() {
        let audit: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                let mut r = test_report(provider, OverallStatus::Yellow, "1.1.1.1", "DE");
                r.checks = vec![
                    CheckResult::ok("GEO_LOCATION", "DE"),
                    CheckResult::warning("TIMEZONE_MISMATCH", "TZ", None),
                ];
                Ok(r)
            })
        });
        let h = harness(audit, "1.1.1.1").await;
        h.state.block_provider("anthropic").await.unwrap();
        h.state
            .set_pinned_ip_for("anthropic", Some("1.1.1.1".to_string()))
            .await
            .unwrap();
        {
            let mut inner = h.guard.inner.lock().await;
            inner.baseline = None;
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        }
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.io.count("interceptor://risk-detected"), 0);
        assert_eq!(h.io.shows.load(Ordering::SeqCst), 0);
        assert_eq!(h.guard.gate(), Gate::Open);
        assert!(h.state.get_data().await.blocked_providers.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_sync_provider_route_change_unbind_triggers_reaudit() {
        let audit_calls = Arc::new(AtomicUsize::new(0));
        let audit_calls2 = Arc::clone(&audit_calls);
        let audit: AuditFn = Arc::new(move |provider, _force| {
            audit_calls2.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if provider == ProviderId::Anthropic {
                    let mut r = test_report(provider, OverallStatus::Red, "1.1.1.1", "RU");
                    r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                    r.checks = vec![r.geo_result.clone()];
                    Ok(r)
                } else {
                    Ok(test_report(provider, OverallStatus::Green, "1.1.1.1", "NL"))
                }
            })
        });
        let h = harness(audit, "1.1.1.1").await;
        h.state.set_provider_monitoring("openai", false).await.unwrap();
        h.state.set_provider_monitoring("gemini", false).await.unwrap();
        {
            let mut inner = h.guard.inner.lock().await;
            inner.baseline = Some(Baseline {
                ip: "1.1.1.1".to_string(),
                country: Some("DE".to_string()),
                trusted: true,
            });
            inner.handled_ip = Some("1.1.1.1".to_string());
        }

        // Simulate unbinding Anthropic route on the SAME baseline IP -> must reset handled_ip,
        // arm needs_reaudit, and kick an immediate re-audit so Critical violation is caught!
        h.guard.sync_provider_route_change("anthropic", false);
        let ev = h
            .io
            .wait_for("interceptor://risk-detected", 2000)
            .await
            .expect("reaudit alert after route unbind");
        assert_eq!(ev.0["provider"], "anthropic");
        assert!(audit_calls.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_first_provider_failure_preserves_siblings_and_blocks_failed_provider() {
        // 1. AutoLockSilent: Anthropic fails while OpenAI & Gemini succeed Green.
        //    OpenAI & Gemini stay Gate::Open; ONLY Anthropic is blocked.
        let partial_fail: AuditFn = Arc::new(|provider, _force| {
            Box::pin(async move {
                if provider == ProviderId::Anthropic {
                    Err("anthropic check failed".to_string())
                } else {
                    Ok(test_report(provider, OverallStatus::Green, "9.9.9.9", "NL"))
                }
            })
        });
        let h = harness(partial_fail.clone(), "9.9.9.9").await;
        h.state
            .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
            .await
            .unwrap();
        h.change("9.9.9.9").await;
        h.io.wait_for("network://changed", 2000)
            .await
            .expect("partial fail settled");

        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
        assert!(h.state.is_provider_blocked("anthropic").await);
        assert_eq!(h.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert!(!h.state.is_provider_blocked("openai").await);
        assert_eq!(h.guard.gate_for(ProviderId::Gemini), Gate::Open);
        assert!(!h.state.is_provider_blocked("gemini").await);

        // 2. AskPopup: Anthropic fails while OpenAI & Gemini succeed Green.
        //    OpenAI & Gemini return to Gate::Open; enriched emits PHASE_FAILED for Anthropic (not Green OpenAI).
        let h2 = harness(partial_fail, "9.9.9.9").await;
        h2.change("9.9.9.9").await;
        let ev = h2
            .io
            .wait_for("interceptor://enriched", 2000)
            .await
            .expect("failed enrichment for anthropic");
        assert_eq!(ev.0["phase"], PHASE_FAILED);
        assert!(ev.0["report"].is_null());
        assert_eq!(
            h2.env
                .hold_queue
                .current_alert()
                .expect("held alert")
                .provider,
            ProviderId::Anthropic
        );
        assert_eq!(h2.guard.gate_for(ProviderId::Anthropic), Gate::Pending);
        assert_eq!(h2.guard.gate_for(ProviderId::Openai), Gate::Open);
        assert_eq!(h2.guard.gate_for(ProviderId::Gemini), Gate::Open);

        // 3. AutoLockSilent when ALL enabled unrouted providers fail -> gates MUST be Blocked, never Open!
        let all_fail: AuditFn = Arc::new(|_, _| Box::pin(async { Err("all down".to_string()) }));
        let h3 = harness(all_fail, "9.9.9.9").await;
        h3.state
            .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
            .await
            .unwrap();
        h3.change("9.9.9.9").await;
        h3.io
            .wait_for("network://changed", 2000)
            .await
            .expect("all fail settled");

        for p in KNOWN_PROVIDERS {
            assert!(
                h3.state.is_provider_blocked(p).await,
                "{p} must be blocked when all audits fail under AutoLockSilent"
            );
        }
        assert_eq!(h3.guard.gate(), Gate::Blocked);
        assert_eq!(h3.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
        assert_eq!(h3.guard.gate_for(ProviderId::Openai), Gate::Blocked);
        assert_eq!(h3.guard.gate_for(ProviderId::Gemini), Gate::Blocked);
    }

    #[tokio::test(start_paused = true)]
    async fn test_kick_reaudit_and_route_sync_never_drop_when_inner_is_locked() {
        let audit_calls = Arc::new(AtomicUsize::new(0));
        let audit_calls2 = Arc::clone(&audit_calls);
        let audit: AuditFn = Arc::new(move |provider, _force| {
            audit_calls2.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if provider == ProviderId::Anthropic {
                    let mut r = test_report(provider, OverallStatus::Red, "1.1.1.1", "RU");
                    r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                    r.checks = vec![r.geo_result.clone()];
                    Ok(r)
                } else {
                    Ok(test_report(provider, OverallStatus::Green, "1.1.1.1", "NL"))
                }
            })
        });
        let h = harness(audit, "1.1.1.1").await;
        h.state
            .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
            .await
            .unwrap();
        h.state.set_provider_monitoring("gemini", false).await.unwrap();

        let route = crate::routing::parse_route_key("socks5://10.0.0.1:1080#nl", 1).unwrap();
        let route_id = h.state.upsert_route(route).await.unwrap();
        h.state
            .bind_provider_route("openai", Some(&route_id))
            .await
            .unwrap();

        // Hold `self.inner` so `try_lock()` inside `kick_reaudit` and `sync_provider_route_change`
        // fails, and verify the atomic/lock-free signals are NOT dropped!
        {
            let mut inner = h.guard.inner.lock().await;
            inner.handled_ip = Some("1.1.1.1".to_string());
            inner.last_probe = Some(Instant::now());
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
            inner.pending = Some(Pending {
                id: "p-lock".to_string(),
                epoch: inner.epoch,
                target_ip: "1.1.1.1".to_string(),
                tel: None,
                clear_old_state: None,
                affected_providers: vec!["openai"],
                already_blocked_providers: Vec::new(),
                healthy_providers: Vec::new(),
                alert_emitted: true,
            });

            // `try_lock()` fails here because `inner` is locked.
            h.guard.sync_provider_route_change("openai", true);
            h.guard.kick_reaudit();
        }

        h.guard.check_route_and_tick(&h.env).await;

        assert!(
            audit_calls.load(Ordering::SeqCst) >= 1,
            "kick_reaudit signal must not be dropped when inner was locked"
        );
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);
        assert!(h.state.is_provider_blocked("anthropic").await);
        assert!(
            h.guard.inner.lock().await.pending.is_none(),
            "pending alert containing routed openai must have been pruned"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_confirm_provider_session_routed_does_not_mark_direct_baseline_trusted() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolve_calls2 = Arc::clone(&resolve_calls);
        let h = harness_env(
            slow_audit(Duration::from_millis(10), "5.5.5.5", OverallStatus::Red),
            "5.5.5.5",
            move |env| {
                env.resolve = Some(Arc::new(move || {
                    resolve_calls2.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async move {
                        Ok(test_report(ProviderId::Anthropic, OverallStatus::Red, "5.5.5.5", "RU").telemetry)
                    })
                }));
            },
        )
        .await;

        // Direct baseline is an untrusted RU IP.
        {
            let mut inner = h.guard.inner.lock().await;
            inner.baseline = Some(Baseline {
                ip: "5.5.5.5".to_string(),
                country: Some("RU".to_string()),
                trusted: false,
            });
        }

        // Bind Anthropic to a route (OpenAI remains direct/unrouted), then confirm Anthropic
        // with `tel = None` (as `resolve_exit_ip_for_provider` does for routed providers).
        let route = crate::routing::parse_route_key("socks5://10.0.0.1:1080#nl", 1).unwrap();
        let route_id = h.state.upsert_route(route).await.unwrap();
        h.state
            .bind_provider_route("anthropic", Some(&route_id))
            .await
            .unwrap();

        h.guard.confirm_provider_session("anthropic", None).await;
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
        assert!(
            !h.guard
                .inner
                .lock()
                .await
                .baseline
                .as_ref()
                .unwrap()
                .trusted,
            "confirming a routed provider must NOT trust an untrusted direct baseline"
        );

        // Also when all providers are routed, confirm_provider_session must not resolve direct egress.
        h.state.set_default_route(Some(&route_id)).await.unwrap();
        h.guard.confirm_provider_session("openai", None).await;
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
        assert!(
            !h.guard
                .inner
                .lock()
                .await
                .baseline
                .as_ref()
                .unwrap()
                .trusted
        );
    }

    /// Real-ticker integration test (real wall-clock 250 ms ticker + 1000 ms `PROBE_MIN_GAP_MS`):
    /// proves zero 1-second audit-abort starvation under slow (1.6 s) audits and automatic
    /// silent recovery back to clean pinned VPN without manual intervention.
    #[tokio::test]
    async fn test_real_ticker_vpn_drop_no_1s_starvation_and_clean_return_auto_recovers() {
        let current_ip = Arc::new(std::sync::Mutex::new("185.10.10.10".to_string()));
        let probe_ip = Arc::clone(&current_ip);
        let ru_audit_calls = Arc::new(AtomicUsize::new(0));
        let ru_audit_calls2 = Arc::clone(&ru_audit_calls);
        let audit_ip = Arc::clone(&current_ip);
        let audit: AuditFn = Arc::new(move |provider, _force| {
            let ip = audit_ip.lock().unwrap().clone();
            let calls = Arc::clone(&ru_audit_calls2);
            Box::pin(async move {
                if ip == "5.5.5.5" {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(1600)).await;
                    let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                    r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                    r.checks = vec![r.geo_result.clone()];
                    Ok(r)
                } else {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(test_report(
                        provider,
                        OverallStatus::Green,
                        "185.10.10.10",
                        "DE",
                    ))
                }
            })
        });

        let probe: ProbeFn = Arc::new(move || {
            let ip = probe_ip.lock().unwrap().clone();
            Box::pin(async move { Some(ip) })
        });
        let io = Arc::new(TestIo::default());
        let state = AppState::new_in_memory();
        state
            .set_pinned_ip(Some("185.10.10.10".to_string()))
            .await
            .unwrap();
        let tel_vpn =
            test_report(ProviderId::Anthropic, OverallStatus::Green, "185.10.10.10", "DE")
                .telemetry;
        let resolve_ip = Arc::clone(&current_ip);
        let env = Env {
            auditor: Auditor::new().expect("auditor"),
            state: state.clone(),
            hold_queue: Arc::new(HoldQueue::new()),
            io: io.clone(),
            audit,
            probe: Some(probe),
            resolve: Some(Arc::new(move || {
                let ip = resolve_ip.lock().unwrap().clone();
                let mut tel = tel_vpn.clone();
                if ip == "5.5.5.5" {
                    tel.ip = "5.5.5.5".to_string();
                    tel.country_code = "RU".to_string();
                }
                Box::pin(async move { Ok(tel) })
            })),
            audit_timeout: Duration::from_secs(10),
        };
        let guard = Arc::new(NetworkGuard::new());
        guard.start_with_env(env.clone());

        // 1. Wait for cold-start baseline initialization on pinned clean VPN.
        for _ in 0..80 {
            if guard
                .inner
                .lock()
                .await
                .baseline
                .as_ref()
                .is_some_and(|b| b.ip == "185.10.10.10")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            guard.inner.lock().await.baseline.as_ref().map(|b| b.ip.as_str()),
            Some("185.10.10.10")
        );
        assert_eq!(guard.gate(), Gate::Open);
        assert_eq!(io.count("interceptor://risk-detected"), 0);

        // 2. Sudden VPN drop to RU (`5.5.5.5`) with 1.6 s audit -> real ticker fires probes every
        //    1000 ms (`PROBE_MIN_GAP_MS`); audit must NOT be starved or aborted!
        *current_ip.lock().unwrap() = "5.5.5.5".to_string();
        guard.wake();

        let (detected, detected_at) = io
            .wait_for("interceptor://risk-detected", 1500)
            .await
            .expect("immediate alert_first under real ticker");
        assert_eq!(detected["phase"], PHASE_DETECTING);
        for p in [ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
            assert_eq!(
                guard.gate_for(p),
                Gate::Pending,
                "{p:?} must freeze Pending immediately on sudden IP drop"
            );
        }

        // Sleep past the 1000 ms `PROBE_MIN_GAP_MS` tick while 1.6 s audit is still running.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            ru_audit_calls.load(Ordering::SeqCst),
            3,
            "1s regular probe must NOT abort and restart in-flight audit (only 1 round of 3 providers)"
        );
        assert_eq!(io.count("interceptor://enriched"), 0);
        assert_eq!(guard.gate(), Gate::Pending);

        let (enriched, enriched_at) = io
            .wait_for("interceptor://enriched", 2500)
            .await
            .expect("ready enrichment after 1.6 s slow audit");
        assert_eq!(enriched["phase"], PHASE_READY);
        assert_eq!(enriched["network_change"]["new_country"], "RU");
        assert!(enriched_at.duration_since(detected_at) >= Duration::from_millis(1400));
        assert_eq!(
            ru_audit_calls.load(Ordering::SeqCst),
            3,
            "still only 1 audit round executed"
        );
        assert_eq!(io.shows.load(Ordering::SeqCst), 1);

        let id = enriched["id"].as_str().expect("alert id");
        assert!(env.hold_queue.resolve(id, HoldResolution::Block).await);
        for _ in 0..80 {
            if guard.pause_mode() == PauseMode::UntilNetworkChange
                && KNOWN_PROVIDERS
                    .iter()
                    .all(|p| ProviderId::from_id(p).is_some_and(|pid| guard.gate_for(pid) == Gate::Blocked))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);
        for p in KNOWN_PROVIDERS {
            assert!(state.is_provider_blocked(p).await, "{p} must be blocked");
            assert_eq!(
                guard.gate_for(ProviderId::from_id(p).unwrap()),
                Gate::Blocked
            );
        }

        // 3. Reconnect back to clean pinned VPN IP (`185.10.10.10`) -> auto-recovers silently!
        let shows_before = io.shows.load(Ordering::SeqCst);
        *current_ip.lock().unwrap() = "185.10.10.10".to_string();
        guard.wake();
        for _ in 0..120 {
            if guard.pause_mode() == PauseMode::None
                && state.get_data().await.blocked_providers.is_empty()
                && !guard.any_provider_gate_closed()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(guard.pause_mode(), PauseMode::None);
        assert!(state.get_data().await.blocked_providers.is_empty());
        assert!(!guard.any_provider_gate_closed());
        for p in [ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
            assert_eq!(guard.gate_for(p), Gate::Open);
        }
        assert_eq!(
            io.shows.load(Ordering::SeqCst),
            shows_before,
            "returning to pinned VPN IP must auto-recover without showing a popup"
        );
    }

    #[tokio::test]
    async fn test_real_ticker_auto_lock_silent_no_1s_starvation_and_recovery() {
        let current_ip = Arc::new(std::sync::Mutex::new("185.10.10.10".to_string()));
        let probe_ip = Arc::clone(&current_ip);
        let ru_audit_calls = Arc::new(AtomicUsize::new(0));
        let ru_audit_calls2 = Arc::clone(&ru_audit_calls);
        let audit_ip = Arc::clone(&current_ip);
        let audit: AuditFn = Arc::new(move |provider, _force| {
            let ip = audit_ip.lock().unwrap().clone();
            let calls = Arc::clone(&ru_audit_calls2);
            Box::pin(async move {
                if ip == "5.5.5.5" {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(1600)).await;
                    let mut r = test_report(provider, OverallStatus::Red, "5.5.5.5", "RU");
                    r.geo_result = CheckResult::critical("GEO_BLOCKED", "RU", None);
                    r.checks = vec![r.geo_result.clone()];
                    Ok(r)
                } else {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(test_report(
                        provider,
                        OverallStatus::Green,
                        "185.10.10.10",
                        "DE",
                    ))
                }
            })
        });

        let probe: ProbeFn = Arc::new(move || {
            let ip = probe_ip.lock().unwrap().clone();
            Box::pin(async move { Some(ip) })
        });
        let io = Arc::new(TestIo::default());
        let state = AppState::new_in_memory();
        state
            .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
            .await
            .unwrap();
        let env = Env {
            auditor: Auditor::new().expect("auditor"),
            state: state.clone(),
            hold_queue: Arc::new(HoldQueue::new()),
            io: io.clone(),
            audit,
            probe: Some(probe),
            resolve: None,
            audit_timeout: Duration::from_secs(10),
        };
        let guard = Arc::new(NetworkGuard::new());
        guard.start_with_env(env);

        for _ in 0..80 {
            if guard
                .inner
                .lock()
                .await
                .baseline
                .as_ref()
                .is_some_and(|b| b.ip == "185.10.10.10" && b.trusted)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(guard.inner.lock().await.baseline.as_ref().unwrap().trusted);

        // Drop to RU under AutoLockSilent: Pending at t<400ms, zero popup, zero 1s starvation,
        // then all 3 blocked + PauseMode::UntilNetworkChange once 1.6 s audit completes.
        *current_ip.lock().unwrap() = "5.5.5.5".to_string();
        guard.wake();
        for _ in 0..40 {
            if guard.gate() == Gate::Pending {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(guard.gate(), Gate::Pending);
        assert_eq!(io.shows.load(Ordering::SeqCst), 0);

        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(ru_audit_calls.load(Ordering::SeqCst), 3);
        assert_eq!(guard.gate(), Gate::Pending);

        for _ in 0..80 {
            if guard.pause_mode() == PauseMode::UntilNetworkChange
                && guard.gate() == Gate::Blocked
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(ru_audit_calls.load(Ordering::SeqCst), 3);
        assert_eq!(io.shows.load(Ordering::SeqCst), 0);
        assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);
        for p in KNOWN_PROVIDERS {
            assert!(state.is_provider_blocked(p).await);
        }

        // Return to verified clean baseline (`185.10.10.10`) -> auto-recovers without manual unlock.
        *current_ip.lock().unwrap() = "185.10.10.10".to_string();
        guard.wake();
        for _ in 0..80 {
            if guard.pause_mode() == PauseMode::None
                && state.get_data().await.blocked_providers.is_empty()
                && !guard.any_provider_gate_closed()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(guard.pause_mode(), PauseMode::None);
        assert!(state.get_data().await.blocked_providers.is_empty());
        assert!(!guard.any_provider_gate_closed());
        assert_eq!(io.shows.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_real_ticker_pinned_a_to_vpn2_to_vpn3_to_pinned_a_within_4h_recovers_green_and_never_relapses()
    {
        use crate::auditor::{evaluate_impossible_travel, evaluate_ip_pinning_for_route, score_checks};
        use crate::routing::RouteSelection;

        let pinned_ip = "145.241.193.245";
        let vpn2_ip = "185.10.10.10";
        let vpn3_ip = "195.20.20.20";

        let current_ip = Arc::new(std::sync::Mutex::new(pinned_ip.to_string()));
        let probe_ip = Arc::clone(&current_ip);
        let transient_failures_left = Arc::new(AtomicUsize::new(0));
        let transient_failures_audit = Arc::clone(&transient_failures_left);

        let state = AppState::new_in_memory();
        state
            .set_pinned_ip(Some(pinned_ip.to_string()))
            .await
            .unwrap();
        state.set_strict_pinning_enabled(true).await.unwrap();

        let auditor = Auditor::new().expect("auditor");
        let _ = auditor
            .resolver
            .check_cache()
            .os
            .get_or_compute("tz:init", Duration::from_secs(60), |_| true, async {
                CheckResult::ok("OK", "ok")
            })
            .await;

        let state_for_audit = state.clone();
        let audit_ip = Arc::clone(&current_ip);
        let audit_cache = auditor.resolver.check_cache().clone();
        let audit: AuditFn = Arc::new(move |provider, _force| {
            let ip = audit_ip.lock().unwrap().clone();
            let st_handle = state_for_audit.clone();
            let fail_ctr = Arc::clone(&transient_failures_audit);
            let cache = audit_cache.clone();
            Box::pin(async move {
                // Simulate transient `utun` stabilization failure on the first verification call(s).
                if ip == pinned_ip
                    && fail_ctr
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                            v.checked_sub(1)
                        })
                        .is_ok()
                {
                    return Err("transient utun stabilization timeout".to_string());
                }

                let cc = if ip == pinned_ip {
                    "GB"
                } else if ip == vpn2_ip {
                    "NL"
                } else {
                    "DE"
                };
                let _ = cache
                    .os
                    .get_or_compute("dns:check", Duration::from_secs(60), |_| true, async {
                        CheckResult::ok("DNS_CLEAN", "ok")
                    })
                    .await;
                let st_data = st_handle.get_data().await;
                let history = st_data.ip_history_for_selection(provider.as_str(), &RouteSelection::Direct);
                let now = crate::auditor::network::current_timestamp();
                let geo_res = CheckResult::ok("GEO_ALLOWED", cc);
                let (pin_res, is_pinned) = evaluate_ip_pinning_for_route(
                    st_data.pinned_ips.get(provider.as_str()).map(String::as_str),
                    st_data.pinned_ip.as_deref(),
                    st_data.strict_pinning_enabled,
                    &ip,
                    None,
                );
                let travel_res = evaluate_impossible_travel(&history, cc, now, provider);
                let checks = vec![geo_res.clone(), pin_res.clone(), travel_res.clone()];
                let verdict = score_checks(&checks, is_pinned);
                let mut rep = test_report(provider, verdict.overall_status, &ip, cc);
                rep.trust_score = verdict.trust_score;
                rep.geo_result = geo_res;
                rep.pinning_result = pin_res;
                rep.travel_result = travel_res;
                rep.checks = checks;
                Ok(rep)
            })
        });

        let probe: ProbeFn = Arc::new(move || {
            let ip = probe_ip.lock().unwrap().clone();
            Box::pin(async move { Some(ip) })
        });
        let io = Arc::new(TestIo::default());
        let env = Env {
            auditor: auditor.clone(),
            state: state.clone(),
            hold_queue: Arc::new(HoldQueue::new()),
            io: io.clone(),
            audit,
            probe: Some(probe),
            resolve: None,
            audit_timeout: Duration::from_secs(5),
        };
        let guard = Arc::new(NetworkGuard::new());
        guard.start_with_env(env.clone());

        // 1. Cold-start baseline on Pinned(A) (`GB`) within <4h.
        for _ in 0..80 {
            if guard
                .inner
                .lock()
                .await
                .baseline
                .as_ref()
                .is_some_and(|b| b.ip == pinned_ip && b.trusted)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(guard.gate(), Gate::Open);
        let t0 = crate::auditor::network::current_timestamp();
        for p in KNOWN_PROVIDERS {
            state
                .record_ip_history_for_selection(
                    p,
                    &RouteSelection::Direct,
                    IpHistoryEntry::new(pinned_ip, "GB", Some(31898), t0 - 600),
                )
                .await
                .unwrap();
        }

        // 2. Jump to VPN2(B) (`NL`) -> blocks uniformly and records NL in history (<4h).
        *current_ip.lock().unwrap() = vpn2_ip.to_string();
        guard.wake();
        let enriched_b = io
            .wait_for("interceptor://enriched", 2500)
            .await
            .expect("VPN2 enriched");
        let id_b = enriched_b.0["id"].as_str().unwrap();
        assert!(env.hold_queue.resolve(id_b, HoldResolution::Block).await);
        for _ in 0..80 {
            let st_now = state.get_data().await;
            if guard.pause_mode() == PauseMode::UntilNetworkChange
                && KNOWN_PROVIDERS.iter().all(|p| st_now.blocked_providers.contains(*p))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(guard.pause_mode(), PauseMode::UntilNetworkChange);
        for p in [ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
            assert_eq!(guard.gate_for(p), Gate::Blocked);
            state
                .record_ip_history_for_selection(
                    p.as_str(),
                    &RouteSelection::Direct,
                    IpHistoryEntry::new(vpn2_ip, "NL", Some(1234), t0 - 300),
                )
                .await
                .unwrap();
        }

        // 3. Jump to VPN3(C) (`DE`) -> stays uniformly blocked across all 3 unpinned providers,
        //    and simulate an orphaned per-provider 60s hold + recent DE history (<4h).
        *current_ip.lock().unwrap() = vpn3_ip.to_string();
        guard.wake();
        for _ in 0..80 {
            if guard.current_observed_ip().await.as_deref() == Some(vpn3_ip)
                && guard.pause_mode() == PauseMode::UntilNetworkChange
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        for p in KNOWN_PROVIDERS {
            assert!(state.is_provider_blocked(p).await);
            state
                .record_ip_history_for_selection(
                    p,
                    &RouteSelection::Direct,
                    IpHistoryEntry::new(vpn3_ip, "DE", Some(5678), t0 - 60),
                )
                .await
                .unwrap();
        }
        let (_orphan_id, orphan_rx, _) = env
            .hold_queue
            .register_or_coalesce_provider("orphan-hold-vpn3".to_string(), "anthropic")
            .await;

        // 4. Return to Pinned(A) (`GB`) within <4h, WITH transient `utun` stabilization failures
        //    on the first 2 verification calls -> must recover cleanly without popup or PauseMode!
        let shows_before = io.shows.load(Ordering::SeqCst);
        transient_failures_left.store(6, Ordering::SeqCst);
        *current_ip.lock().unwrap() = pinned_ip.to_string();
        guard.wake();

        // Orphaned hold must resolve immediately as Superseded.
        let orphan_res = tokio::time::timeout(Duration::from_secs(2), orphan_rx)
            .await
            .expect("orphan hold cancelled by restore_locked")
            .unwrap();
        assert_eq!(orphan_res, HoldResolution::Superseded);

        // Wait for recovery AND transient retry to complete and record GB back into ip_history.
        for _ in 0..160 {
            let st_now = state.get_data().await;
            let anthropic_last_ip = st_now
                .ip_history_for_selection("anthropic", &RouteSelection::Direct)
                .last()
                .map(|e| e.ip.clone());
            if guard.pause_mode() == PauseMode::None
                && st_now.blocked_providers.is_empty()
                && !guard.any_provider_gate_closed()
                && anthropic_last_ip.as_deref() == Some(pinned_ip)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(guard.pause_mode(), PauseMode::None);
        assert!(state.get_data().await.blocked_providers.is_empty());
        assert!(!guard.any_provider_gate_closed());
        assert_eq!(io.shows.load(Ordering::SeqCst), shows_before);

        // Even while history still had DE -> GB (<4h), `effective_tray_report` MUST NOT brand
        // Pinned(A) as Red / "СТОП СЕТИ" (must be Green!).
        let st_check = state.get_data().await;
        let mut red_travel_report = test_report(ProviderId::Anthropic, OverallStatus::Red, pinned_ip, "GB");
        let travel_crit = CheckResult::critical("IMPOSSIBLE_TRAVEL_CRITICAL", "DE -> GB in 1m", None);
        red_travel_report.travel_result = travel_crit.clone();
        red_travel_report.checks = vec![
            CheckResult::ok("GEO_ALLOWED", "GB"),
            CheckResult::ok("PINNED_IP_MATCH", "ok"),
            travel_crit,
        ];
        assert_eq!(
            effective_tray_report(&red_travel_report, false, &st_check).overall_status,
            OverallStatus::Green
        );

        // 5. Simulate `CheckCache` expiry + multiple real ticker cycles (>1.3s) -> never relapses!
        env.auditor.resolver.check_cache().clear().await;
        tokio::time::sleep(Duration::from_millis(1350)).await;
        assert_eq!(guard.pause_mode(), PauseMode::None);
        assert!(state.get_data().await.blocked_providers.is_empty());
        assert!(!guard.any_provider_gate_closed());
        assert_eq!(io.shows.load(Ordering::SeqCst), shows_before);
    }

    #[tokio::test(start_paused = true)]
    async fn test_apply_regular_probe_never_traps_pinned_ip_in_pause_mode() {
        let pinned_ip = "145.241.193.245";
        let h = harness(
            slow_audit(Duration::from_millis(10), pinned_ip, OverallStatus::Green),
            pinned_ip,
        )
        .await;
        h.state
            .set_pinned_ip(Some(pinned_ip.to_string()))
            .await
            .unwrap();
        h.state.block_provider("anthropic").await.unwrap();
        h.guard.set_pause_mode_raw(PauseMode::UntilNetworkChange);
        {
            let mut inner = h.guard.inner.lock().await;
            inner.baseline = Some(Baseline {
                ip: pinned_ip.to_string(),
                country: Some("GB".to_string()),
                trusted: true,
            });
            inner.paused_ip = Some(pinned_ip.to_string());
            inner.last_route_fp = Some(compute_local_route_fingerprint(None));
        }
        h.guard.sync_gates_with_state(&h.state).await;
        assert_eq!(h.guard.pause_mode(), PauseMode::UntilNetworkChange);
        assert_eq!(h.guard.gate_for(ProviderId::Anthropic), Gate::Blocked);

        // Next regular probe on the exact same pinned IP must untrap `paused_ip` and recover!
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(h.guard.pause_mode(), PauseMode::None);
        assert!(h.state.get_data().await.blocked_providers.is_empty());
        assert_eq!(h.guard.gate(), Gate::Open);
        assert!(h.guard.inner.lock().await.paused_ip.is_none());
    }

    #[tokio::test]
    async fn superseded_hold_drain_emits_resolved_and_hides_popup_on_disable_and_all_routed() {
        let h = harness(
            slow_audit(Duration::from_millis(10), "1.2.3.4", OverallStatus::Green),
            "1.2.3.4",
        )
        .await;

        // 1. Provider-scoped hold drained by `sync_provider_disabled` hides popup and emits `interceptor://resolved`.
        let rx_prov = h
            .env
            .hold_queue
            .register("prov-hold-1".to_string(), "anthropic")
            .await;
        h.env.hold_queue.set_alert(RiskInterceptPayload {
            id: "prov-hold-1".to_string(),
            provider: ProviderId::Anthropic,
            host: "api.anthropic.com:443".to_string(),
            report: None,
            ttl_seconds: DEFAULT_HOLD_TTL_SECS,
            scope: "provider".to_string(),
            network_change: None,
            is_simulation: false,
            detected_at_ms: 1,
            phase: PHASE_READY.to_string(),
            gate_reason: None,
        });
        let hides_before = h.io.hides.load(Ordering::SeqCst);
        let resolved_before = h.io.count("interceptor://resolved");
        h.guard.sync_provider_disabled("anthropic", &h.state).await;
        assert_eq!(rx_prov.await.unwrap(), HoldResolution::Superseded);
        assert!(h.io.hides.load(Ordering::SeqCst) > hides_before);
        assert!(h.io.count("interceptor://resolved") > resolved_before);

        // 2. Active hold drained in `plan_tick` when `unrouted.is_empty()` hides popup and emits `interceptor://resolved`.
        for p in KNOWN_PROVIDERS {
            h.state.set_provider_monitoring(p, false).await.unwrap();
        }
        let rx_tick = h
            .env
            .hold_queue
            .register("prov-hold-2".to_string(), "openai")
            .await;
        let hides_before2 = h.io.hides.load(Ordering::SeqCst);
        let resolved_before2 = h.io.count("interceptor://resolved");
        h.guard.check_route_and_tick(&h.env).await;
        assert_eq!(rx_tick.await.unwrap(), HoldResolution::Superseded);
        assert!(h.io.hides.load(Ordering::SeqCst) > hides_before2);
        assert!(h.io.count("interceptor://resolved") > resolved_before2);
    }
}
