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

mod alerts;
mod audit_outcome;
mod audit_summary;
mod baseline_restore;
mod decisions;
mod gates;
mod killswitch;
mod orchestrator;
mod policy;
mod probe_apply;
mod probe_loop;
mod routes_sync;
mod session_confirm;
mod types;
mod waiter;

pub use killswitch::{gate_closed, wait_open};
pub(crate) use policy::{
    effective_tray_report, is_report_pinned_travel_only, report_allowed_for_state,
    report_no_critical_and_geo_ok,
};
pub use types::{
    ALL_PROVIDERS, AUDIT_TIMEOUT_SECS, AuditFn, AuditResults, Gate, GuardCtx, GuardPauseStatus,
    MAX_STALL_SECS, NetworkGuard, PROBE_INTERVAL_MS, PROBE_MIN_GAP_MS, PauseMode, ProbeFn,
    ROUTE_CHECK_INTERVAL_MS, ResolveFn, compute_local_route_fingerprint,
};

#[cfg(test)]
use audit_summary::{audit_all, summarize};
#[cfg(test)]
use crate::auditor::geo_matrix::ProviderId;
#[cfg(test)]
use crate::auditor::{Auditor, NetworkTelemetry, OverallStatus, RiskReport};
#[cfg(test)]
use crate::proxy::allow_error::AllowErrorCode;
#[cfg(test)]
use crate::proxy::hold_queue::{
    DEFAULT_HOLD_TTL_SECS, HoldQueue, HoldResolution, PHASE_DETECTING, PHASE_FAILED, PHASE_READY,
    RiskInterceptPayload,
};
#[cfg(test)]
use crate::state::{AppState, IpHistoryEntry, KNOWN_PROVIDERS};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::time::{Duration, Instant};
#[cfg(test)]
use types::{Baseline, Env, GuardIo, Pending};

#[cfg(test)]
#[path = "../guard_tests/mod.rs"]
mod tests;
