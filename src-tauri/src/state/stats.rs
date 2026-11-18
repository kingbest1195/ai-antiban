//! Lock-free live gateway traffic statistics and RAII tunnel tracking.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Single live event recorded by the gateway interceptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentGatewayEvent {
    pub timestamp: u64,
    pub host: String,
    pub provider: String,
    pub action: String, // "PROTECTED" | "HELD" | "BLOCKED" | "DIRECT"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub country: String,
}

/// Instant snapshot of live traffic counters for the UI and system tray.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GatewayStatsSnapshot {
    pub protected_ai_requests: u64,
    pub intercepted_leaks: u64,
    pub direct_bypassed_requests: u64,
    pub active_ai_tunnels: u64,
    pub uptime_seconds: u64,
    pub last_protected_host: Option<String>,
    pub recent_events: Vec<RecentGatewayEvent>,
}

/// Thread-safe lock-free atomic tracker for live gateway traffic counters.
#[derive(Debug)]
pub struct GatewayStatsTracker {
    pub start_time: std::time::Instant,
    pub protected_ai_requests: AtomicU64,
    pub intercepted_leaks: AtomicU64,
    pub direct_bypassed_requests: AtomicU64,
    pub active_ai_tunnels: AtomicU64,
    pub last_protected_host: std::sync::RwLock<Option<String>>,
    pub recent_events: std::sync::RwLock<VecDeque<RecentGatewayEvent>>,
}

/// RAII guard that tracks the active AI tunnel count.
pub struct TunnelGuard {
    tracker: Arc<GatewayStatsTracker>,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        self.tracker
            .active_ai_tunnels
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl Default for GatewayStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayStatsTracker {
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            protected_ai_requests: AtomicU64::new(0),
            intercepted_leaks: AtomicU64::new(0),
            direct_bypassed_requests: AtomicU64::new(0),
            active_ai_tunnels: AtomicU64::new(0),
            last_protected_host: std::sync::RwLock::new(None),
            recent_events: std::sync::RwLock::new(VecDeque::with_capacity(20)),
        }
    }

    pub fn record_protected(&self, host: &str, provider: &str, country: &str) {
        // Crash-test canary probes must never inflate real user counters.
        if host.starts_with("canary-test.") {
            return;
        }
        self.protected_ai_requests.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut l) = self.last_protected_host.write() {
            *l = Some(host.to_string());
        }
        let event = RecentGatewayEvent {
            timestamp: crate::auditor::network::current_timestamp(),
            host: host.to_string(),
            provider: provider.to_string(),
            action: "PROTECTED".to_string(),
            kind: None,
            country: country.to_string(),
        };
        self.push_event(event);
    }

    pub fn record_intercepted(&self, host: &str, provider: &str, action: &str, country: &str) {
        // Crash-test canary probes must never inflate real user counters.
        if host.starts_with("canary-test.") {
            return;
        }
        self.intercepted_leaks.fetch_add(1, Ordering::SeqCst);
        let event = RecentGatewayEvent {
            timestamp: crate::auditor::network::current_timestamp(),
            host: host.to_string(),
            provider: provider.to_string(),
            action: action.to_string(),
            kind: None,
            country: country.to_string(),
        };
        self.push_event(event);
    }

    pub fn record_direct_bypassed(&self) {
        self.direct_bypassed_requests.fetch_add(1, Ordering::SeqCst);
    }

    pub fn record_direct_bypassed_host(&self, host: &str) {
        self.direct_bypassed_requests.fetch_add(1, Ordering::SeqCst);
        let now = crate::auditor::network::current_timestamp();
        if let Ok(mut g) = self.recent_events.write() {
            if let Some(last) = g.back_mut() {
                let is_direct = last.action.eq_ignore_ascii_case("direct")
                    || last
                        .kind
                        .as_deref()
                        .map(|k| k.eq_ignore_ascii_case("direct"))
                        .unwrap_or(false);
                if is_direct && last.host == host {
                    last.timestamp = now;
                    return;
                }
            }
            if g.len() >= 20 {
                g.pop_front();
            }
            g.push_back(RecentGatewayEvent {
                timestamp: now,
                host: host.to_string(),
                provider: "Non-AI".to_string(),
                action: "DIRECT".to_string(),
                kind: Some("direct".to_string()),
                country: "DIRECT".to_string(),
            });
        }
    }

    pub fn record_direct_bypassed_with_host(&self, host: &str) {
        self.record_direct_bypassed_host(host);
    }

    pub fn enter_tunnel(self: &Arc<Self>) -> TunnelGuard {
        self.active_ai_tunnels.fetch_add(1, Ordering::SeqCst);
        TunnelGuard {
            tracker: Arc::clone(self),
        }
    }

    fn push_event(&self, event: RecentGatewayEvent) {
        if let Ok(mut g) = self.recent_events.write() {
            if g.len() >= 20 {
                g.pop_front();
            }
            g.push_back(event);
        }
    }

    pub async fn snapshot(&self) -> GatewayStatsSnapshot {
        self.snapshot_sync()
    }

    pub fn snapshot_sync(&self) -> GatewayStatsSnapshot {
        let events = self
            .recent_events
            .read()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default();
        let last_host = self.last_protected_host.read().ok().and_then(|h| h.clone());
        GatewayStatsSnapshot {
            protected_ai_requests: self.protected_ai_requests.load(Ordering::SeqCst),
            intercepted_leaks: self.intercepted_leaks.load(Ordering::SeqCst),
            direct_bypassed_requests: self.direct_bypassed_requests.load(Ordering::SeqCst),
            active_ai_tunnels: self.active_ai_tunnels.load(Ordering::SeqCst),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            last_protected_host: last_host,
            recent_events: events,
        }
    }
}
