use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, watch};

use crate::auditor::geo_matrix::ProviderId;
use crate::state::AppState;

use super::fingerprint::compute_local_route_fingerprint;
use super::types::{Gate, GuardPauseStatus, Inner, NetworkGuard, PauseMode, Pending};

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
        let (shutdown_abort_tx, _shutdown_rx) = watch::channel(false);
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(400))
            .timeout(Duration::from_millis(800))
            .tcp_nodelay(true)
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
            shutdown_abort_tx,
            gate_lock: std::sync::Mutex::new(()),
            pause_mode: std::sync::Mutex::new(PauseMode::None),
            gate_reason: std::sync::Mutex::new(None),
            inner: Mutex::new(Inner::default()),
            tick_lock: Mutex::new(()),
            env: OnceLock::new(),
            self_weak: OnceLock::new(),
            wake_notify: Arc::new(tokio::sync::Notify::new()),
            loop_running: AtomicBool::new(false),
            regular_probe_in_flight: AtomicBool::new(false),
            sysproxy_sync_in_flight: AtomicBool::new(false),
            force_reaudit: AtomicBool::new(false),
            pending_route_sync: std::sync::Mutex::new(HashMap::new()),
            restore_epoch: AtomicU64::new(0),
            verify_in_flight: AtomicUsize::new(0),
            client,
            chained_client: std::sync::Mutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            test_fp_fn: std::sync::Mutex::new(None),
        }
    }

    pub(super) fn compute_route_fp(&self, upstream_key: Option<&str>) -> String {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(ref f) = *self.test_fp_fn.lock().unwrap_or_else(|p| p.into_inner()) {
            return f(upstream_key);
        }
        compute_local_route_fingerprint(upstream_key)
    }

    pub fn restore_epoch(&self) -> u64 {
        self.restore_epoch.load(Ordering::SeqCst)
    }

    pub(super) fn register_self_weak(self: &Arc<Self>) {
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

    pub fn is_paused(&self) -> bool {
        self.pause_mode() != PauseMode::None
    }

    pub fn gate_reason(&self) -> Option<String> {
        self.gate_reason
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub(super) fn set_gate_reason(&self, reason: Option<String>) {
        let mut g = self.gate_reason.lock().unwrap_or_else(|p| p.into_inner());
        *g = reason;
    }

    pub(super) fn set_pause_mode_raw(&self, mode: PauseMode) {
        let mut g = self.pause_mode.lock().unwrap_or_else(|p| p.into_inner());
        *g = mode;
    }

    pub fn pause_status(&self) -> GuardPauseStatus {
        let mode = self.pause_mode();
        let manual_killswitch = self.is_manual_killswitch();
        let gate = match self.gate() {
            Gate::Open => "open",
            Gate::Pending => "pending",
            Gate::Blocked => "blocked",
        }
        .to_string();
        let mut pending_providers = Vec::new();
        let mut blocked_providers = Vec::new();
        for (pid, tx) in &self.provider_gates {
            let g = if manual_killswitch {
                Gate::Blocked
            } else {
                *tx.borrow()
            };
            match g {
                Gate::Pending => pending_providers.push(pid.as_str().to_string()),
                Gate::Blocked => blocked_providers.push(pid.as_str().to_string()),
                Gate::Open => {}
            }
        }
        pending_providers.sort();
        blocked_providers.sort();
        let has_active_risk_alert = self
            .env
            .get()
            .and_then(|env| env.hold_queue.current_alert())
            .is_some_and(|a| {
                !a.is_simulation
                    && (a.phase == crate::proxy::hold_queue::PHASE_READY
                        || a.phase == crate::proxy::hold_queue::PHASE_FAILED)
            });
        GuardPauseStatus {
            paused: mode != PauseMode::None,
            mode,
            gate,
            gate_reason: self.gate_reason(),
            manual_killswitch,
            pending_providers,
            blocked_providers,
            has_active_risk_alert,
        }
    }

    pub(super) fn emit_pause_status(&self) {
        if let Some(env) = self.env.get() {
            let status = self.pause_status();
            env.io.tray_guard_status(&status);
            env.emit("guard://pause-status-changed", &status);
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

    /// Subscribes to the process-shutdown tunnel-abort signal (covers routed and transit tunnels).
    pub fn subscribe_shutdown_abort(&self) -> watch::Receiver<bool> {
        self.shutdown_abort_tx.subscribe()
    }

    /// Aborts unrouted tunnels (routed tunnels only obey the manual kill-switch).
    pub fn abort_active_tunnels(&self) {
        self.tunnel_abort_tx
            .send_modify(|val| *val = val.wrapping_add(1));
    }

    /// Aborts ALL active tunnels (`FollowGate`, `KillSwitchOnly`, and `transit_tunnel`) on app shutdown.
    pub fn abort_all_tunnels_on_shutdown(&self) {
        self.shutdown_abort_tx.send_replace(true);
        self.abort_active_tunnels();
    }

    /// Cheap local check used by every CONNECT. On a route change it closes the gate and aborts
    /// the tunnels at once and marks the change `route_dirty`, so the next tick handles it without
    /// waiting for `PROBE_MIN_GAP_MS`.
    pub fn check_route_fingerprint_sync(&self, upstream_key: Option<&str>) -> bool {
        let fp = self.compute_route_fp(upstream_key);
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
                g.last_route_fp = Some(fp.clone());
                g.last_fp_change_at = Some(Instant::now());
                if let Some(abort) = g.verify_abort.take() {
                    abort.abort();
                }
                g.verify_ip = None;
                let settling_pause = !self.is_manual_killswitch()
                    && g.pending_pause_ip_bind
                    && *self.pause_mode.lock().unwrap_or_else(|p| p.into_inner())
                        == PauseMode::UntilNetworkChange;
                if settling_pause {
                    // User paused during `detecting` while the route is still settling:
                    // adopt the updated fingerprint and keep traffic blocked without clearing pause.
                    g.route_dirty = true;
                    g.paused_route_fp = Some(fp);
                    drop(g);
                    self.abort_active_tunnels();
                    return false;
                }
                let in_flight = g.probe_in_flight
                    || (self.any_provider_gate_pending() && g.audit_abort.is_some());
                if in_flight {
                    g.deferred_recheck_fp = Some(fp.clone());
                } else {
                    if !g.route_dirty {
                        g.dirty_since = Some(Instant::now());
                    }
                    g.route_dirty = true;
                }
                let mut pause_active = false;
                if !self.is_manual_killswitch() {
                    let pm = self.pause_mode.lock().unwrap_or_else(|p| p.into_inner());
                    pause_active = *pm == PauseMode::UntilNetworkChange;
                }
                if pause_active {
                    // Keep PauseMode::UntilNetworkChange active while verifying the new network
                    // silently in the background; update paused_route_fp and keep blocked
                    // providers Gate::Blocked.
                    g.paused_route_fp = Some(fp);
                } else {
                    g.paused_ip = None;
                    g.pending_pause_ip_bind = false;
                    g.paused_route_fp = None;
                }
                drop(g);
                self.freeze_open_gates_pending();
                self.abort_active_tunnels();
                return !in_flight;
            }
        } else {
            g.last_route_fp = Some(fp);
        }
        false
    }

    /// Freezes ONLY currently `Gate::Open` providers to `Gate::Pending`, preserving any
    /// already `Gate::Blocked` providers (and coercing all to `Blocked` under manual kill-switch).
    pub(super) fn freeze_open_gates_pending(&self) {
        {
            let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
            if *self.kill_tx.borrow() {
                self.gate_tx.send_replace(Gate::Blocked);
                for tx in self.provider_gates.values() {
                    tx.send_replace(Gate::Blocked);
                }
            } else {
                let mut any_pending = false;
                for tx in self.provider_gates.values() {
                    if *tx.borrow() == Gate::Open {
                        tx.send_replace(Gate::Pending);
                    }
                    if *tx.borrow() == Gate::Pending {
                        any_pending = true;
                    }
                }
                let global = if any_pending {
                    Gate::Pending
                } else {
                    Gate::Blocked
                };
                self.gate_tx.send_replace(global);
            }
        }
        self.emit_pause_status();
    }

    /// Sets the gate for every provider and overall guard state. While the manual kill-switch is
    /// engaged every request is coerced to `Blocked`: `Open` (or `Pending`) cannot be set behind
    /// the kill-switch's back.
    pub(super) fn set_gate(&self, gate: Gate) {
        {
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
        self.emit_pause_status();
    }

    fn apply_provider_gates<F>(&self, emit: bool, mut resolve_gate: F)
    where
        F: FnMut(&str) -> Gate,
    {
        {
            let _g = self.gate_lock.lock().unwrap_or_else(|p| p.into_inner());
            if *self.kill_tx.borrow() {
                self.gate_tx.send_replace(Gate::Blocked);
                for tx in self.provider_gates.values() {
                    tx.send_replace(Gate::Blocked);
                }
                drop(_g);
                if emit {
                    self.emit_pause_status();
                }
                return;
            }
            let mut any_open = false;
            let mut any_pending = false;
            for (pid, tx) in &self.provider_gates {
                let g = resolve_gate(pid.as_str());
                tx.send_replace(g);
                match g {
                    Gate::Open => any_open = true,
                    Gate::Pending => any_pending = true,
                    Gate::Blocked => {}
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
        if emit {
            self.emit_pause_status();
        }
    }

    /// Applies isolated per-provider gates after an audit:
    /// Synchronises per-provider and global gates against full `AppStateData` (respecting
    /// `disabled_providers`, routed providers, `blocked_providers`, and any `Pending` alert).
    pub(super) fn sync_gates_with_state_and_pending(
        &self,
        st: &crate::state::AppStateData,
        pending: Option<&Pending>,
    ) {
        self.sync_gates_with_state_and_pending_inner(st, pending, true);
    }

    pub(super) fn sync_gates_with_state_and_pending_inner(
        &self,
        st: &crate::state::AppStateData,
        pending: Option<&Pending>,
        emit: bool,
    ) {
        self.apply_provider_gates(emit, |name| {
            let is_routed = crate::routing::select_route_id(st, name).is_some();
            if st.is_provider_disabled(name) || is_routed {
                Gate::Open
            } else if st.blocked_providers.contains(name) {
                Gate::Blocked
            } else if pending.is_some_and(|p| p.affected_providers.contains(&name)) {
                Gate::Pending
            } else {
                Gate::Open
            }
        });
    }

    pub async fn sync_gates_with_state(&self, state: &AppState) {
        self.sync_gates_with_state_inner(state, true).await;
    }

    pub(crate) async fn sync_gates_with_state_quiet(&self, state: &AppState) {
        self.sync_gates_with_state_inner(state, false).await;
    }

    async fn sync_gates_with_state_inner(&self, state: &AppState, emit: bool) {
        let mut inner = self.inner.lock().await;
        self.drain_pending_route_sync_locked(self.env.get(), &mut inner)
            .await;
        let st = state.get_data().await;
        self.sync_gates_with_state_and_pending_inner(&st, inner.pending.as_ref(), emit);
    }

    /// Returns enabled unrouted provider IDs currently blocked in either `state` or `provider_gates`.
    pub(super) fn currently_blocked_set(&self, st: &crate::state::AppStateData) -> HashSet<String> {
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
    pub(super) fn freeze_providers_pending(
        &self,
        st: &crate::state::AppStateData,
        freeze_providers: &[&'static str],
        already_blocked: &HashSet<String>,
    ) {
        self.apply_provider_gates(true, |name| {
            let is_routed = crate::routing::select_route_id(st, name).is_some();
            if st.is_provider_disabled(name) || is_routed {
                Gate::Open
            } else if already_blocked.contains(name) || st.blocked_providers.contains(name) {
                Gate::Blocked
            } else if freeze_providers.contains(&name) {
                Gate::Pending
            } else {
                Gate::Open
            }
        });
    }
}
