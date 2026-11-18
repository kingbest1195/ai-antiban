use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, watch};

use crate::auditor::geo_matrix::ProviderId;
use crate::state::AppState;

use super::types::{
    Gate, GuardPauseStatus, Inner, NetworkGuard, PauseMode, Pending, compute_local_route_fingerprint,
};

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
    pub(super) fn set_gate(&self, gate: Gate) {
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
    pub(super) fn sync_gates_with_state_and_pending(
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

}
