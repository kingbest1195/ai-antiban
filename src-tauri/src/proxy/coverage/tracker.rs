use super::catalog::{get_known_app_info, resolve_app_identity};
use super::ide_scanners::listing_has_antigravity;
use super::pac_verify::identify_by_user_agent;
use super::process_lookup::lookup_process_with;
use super::types::{
    AppTrafficStats, Clock, ConfigFacts, LOOKUP_CACHE_MAX, LOOKUP_CACHE_TTL_MS,
    LOOKUP_NEGATIVE_TTL_MS, LOOKUP_RATE_MAX, LOOKUP_RATE_WINDOW_MS, Os, PROCESS_CHECK_TTL_MS,
    RealProbe, SystemProbe, TrafficKind, system_clock,
};
use crate::state::CliMode;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct LookupState {
    /// `peer_port -> (process or None for "not found", time of the answer)`.
    cache: HashMap<u16, (Option<String>, u64)>,
    inflight: HashSet<u16>,
    recent: VecDeque<u64>,
}

/// Live process accounting engine tracking incoming local gateway sockets.
pub struct CoverageTracker {
    pub(super) stats: Mutex<HashMap<String, AppTrafficStats>>,
    lookups: Mutex<LookupState>,
    gateway: Mutex<Option<SocketAddr>>,
    pub(super) facts: Mutex<Option<(u64, ConfigFacts)>>,
    /// The CLI mode the facts are computed for (see [`CoverageSnapshot::cli_mode`]).
    cli_mode: Mutex<CliMode>,
    /// Is Antigravity running: `(time of the answer, answer)`, see [`PROCESS_CHECK_TTL_MS`].
    running: Mutex<Option<(u64, bool)>>,
    clock: Clock,
    pub(super) probe: Arc<dyn SystemProbe>,
    pub(super) os: Os,
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// What must happen after the cheap part of an incoming connection was handled.
pub(super) enum Step {
    Done,
    Lookup,
}

impl CoverageTracker {
    pub fn new() -> Self {
        Self::with_parts(system_clock(), Arc::new(RealProbe), Os::current())
    }

    /// A tracker with its own clock (Unix ms), OS probe and OS flavour (tests).
    pub fn with_parts(clock: Clock, probe: Arc<dyn SystemProbe>, os: Os) -> Self {
        Self {
            stats: Mutex::new(HashMap::new()),
            lookups: Mutex::new(LookupState::default()),
            gateway: Mutex::new(None),
            facts: Mutex::new(None),
            cli_mode: Mutex::new(CliMode::default()),
            running: Mutex::new(None),
            clock,
            probe,
            os,
        }
    }

    pub(super) fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    /// The address the gateway really listens on.
    pub fn set_gateway_addr(&self, addr: SocketAddr) {
        if let Ok(mut g) = self.gateway.lock() {
            *g = Some(addr);
        }
        if let Ok(mut f) = self.facts.lock() {
            *f = None;
        }
    }

    pub fn gateway_addr(&self) -> Option<SocketAddr> {
        self.gateway.lock().ok().and_then(|g| *g)
    }

    /// Tells the tracker how command-line tools are covered right now; a change drops the cached
    /// facts so the next snapshot reads them again.
    pub fn set_cli_mode(&self, mode: CliMode) {
        let changed = match self.cli_mode.lock() {
            Ok(mut g) => {
                let changed = *g != mode;
                *g = mode;
                changed
            }
            Err(_) => false,
        };
        if changed && let Ok(mut f) = self.facts.lock() {
            *f = None;
        }
    }

    pub fn cli_mode(&self) -> CliMode {
        self.cli_mode.lock().map(|g| *g).unwrap_or_default()
    }

    /// Clears cached environment facts so the next snapshot re-reads OS, proxy and policy state.
    pub fn invalidate_facts(&self) {
        if let Ok(mut f) = self.facts.lock() {
            *f = None;
        }
    }

    /// Records an incoming connection from `peer_port`. Never blocks the tunnel: the OS lookup
    /// (when needed at all) runs on the blocking pool.
    ///
    /// [`TrafficKind::Direct`] is ignored: transit traffic to non-AI hosts must not cost a single
    /// process lookup.
    pub fn record_incoming(
        self: &Arc<Self>,
        peer_port: u16,
        user_agent: Option<String>,
        kind: TrafficKind,
    ) {
        if let Step::Lookup = self.prepare(peer_port, user_agent.as_deref(), kind) {
            let tracker = Arc::clone(self);
            tokio::task::spawn_blocking(move || {
                tracker.run_lookup(peer_port, user_agent.as_deref(), kind);
            });
        }
    }

    /// Same as [`Self::record_incoming`] but the lookup (if any) runs on the calling thread.
    pub fn record_incoming_blocking(
        &self,
        peer_port: u16,
        user_agent: Option<&str>,
        kind: TrafficKind,
    ) {
        if let Step::Lookup = self.prepare(peer_port, user_agent, kind) {
            self.run_lookup(peer_port, user_agent, kind);
        }
    }

    /// Cheap part: cache, User-Agent, debounce and rate limit. Decides whether an OS lookup is due.
    pub(super) fn prepare(
        &self,
        peer_port: u16,
        user_agent: Option<&str>,
        kind: TrafficKind,
    ) -> Step {
        if kind == TrafficKind::Direct {
            return Step::Done;
        }
        let now = self.now_ms();

        // 1. Recent answer for this port (found or not found).
        let cached = self.lookups.lock().ok().and_then(|l| {
            l.cache.get(&peer_port).and_then(|(name, at)| {
                let ttl = if name.is_some() {
                    LOOKUP_CACHE_TTL_MS
                } else {
                    LOOKUP_NEGATIVE_TTL_MS
                };
                (now.saturating_sub(*at) < ttl).then(|| name.clone())
            })
        });
        if let Some(answer) = cached {
            match answer {
                Some(name) => self.record(kind, &name, user_agent),
                None => self.record_by_user_agent(kind, user_agent),
            }
            return Step::Done;
        }

        // 2. The User-Agent names the client directly.
        if let Some(ua) = user_agent
            && let Some(name) = identify_by_user_agent(ua)
        {
            self.cache_answer(peer_port, Some(name.to_string()), now);
            self.record(kind, name, user_agent);
            return Step::Done;
        }

        // 3. Debounce and rate limit: a lookup for this port is already running / too many
        //    lookups lately -> no new process, attribute by User-Agent only.
        let Ok(mut l) = self.lookups.lock() else {
            return Step::Done;
        };
        if l.inflight.contains(&peer_port) {
            return Step::Done;
        }
        while let Some(front) = l.recent.front() {
            if now.saturating_sub(*front) >= LOOKUP_RATE_WINDOW_MS {
                l.recent.pop_front();
            } else {
                break;
            }
        }
        if l.recent.len() >= LOOKUP_RATE_MAX {
            drop(l);
            self.record_by_user_agent(kind, user_agent);
            return Step::Done;
        }
        l.recent.push_back(now);
        l.inflight.insert(peer_port);
        Step::Lookup
    }

    fn run_lookup(&self, peer_port: u16, user_agent: Option<&str>, kind: TrafficKind) {
        let found = lookup_process_with(&*self.probe, self.os, peer_port, std::process::id());
        let now = self.now_ms();
        if let Ok(mut l) = self.lookups.lock() {
            l.inflight.remove(&peer_port);
        }
        self.cache_answer(peer_port, found.clone(), now);
        match found {
            Some(name) => self.record(kind, &name, user_agent),
            None => self.record_by_user_agent(kind, user_agent),
        }
    }

    fn cache_answer(&self, port: u16, name: Option<String>, now: u64) {
        if let Ok(mut l) = self.lookups.lock() {
            if l.cache.len() >= LOOKUP_CACHE_MAX {
                l.cache
                    .retain(|_, (_, at)| now.saturating_sub(*at) < LOOKUP_CACHE_TTL_MS);
                if l.cache.len() >= LOOKUP_CACHE_MAX {
                    l.cache.clear();
                }
            }
            l.cache.insert(port, (name, now));
        }
    }

    fn record_by_user_agent(&self, kind: TrafficKind, user_agent: Option<&str>) {
        if let Some(ua) = user_agent {
            self.record(kind, ua, None);
        }
    }

    /// Records one AI request from a discovered process name or user-agent.
    pub fn record_hit(&self, raw_process_name: &str, user_agent: Option<&str>) {
        self.record(TrafficKind::AiRequest, raw_process_name, user_agent);
    }

    fn record(&self, kind: TrafficKind, raw_process_name: &str, user_agent: Option<&str>) {
        if kind == TrafficKind::Direct {
            return;
        }
        let (id, display_name, category) = resolve_app_identity(raw_process_name, user_agent);
        let now_ms = self.now_ms();
        let Ok(mut lock) = self.stats.lock() else {
            return;
        };
        match kind {
            TrafficKind::AiRequest => {
                let entry = lock.entry(id).or_insert_with(|| AppTrafficStats {
                    ai_requests: 0,
                    pac_fetches: 0,
                    last_seen_ms: now_ms,
                    detected_name: display_name,
                    category,
                });
                entry.ai_requests = entry.ai_requests.saturating_add(1);
                entry.last_seen_ms = now_ms;
            }
            TrafficKind::PacFetch => {
                // A PAC fetch only counts for apps of the catalog: it must not create an entry
                // for the system's own PAC helper.
                if get_known_app_info(&id).is_none() {
                    return;
                }
                let entry = lock.entry(id).or_insert_with(|| AppTrafficStats {
                    ai_requests: 0,
                    pac_fetches: 0,
                    last_seen_ms: 0,
                    detected_name: display_name,
                    category,
                });
                entry.pac_fetches = entry.pac_fetches.saturating_add(1);
            }
            TrafficKind::Direct => {}
        }
    }

    /// Does a process of Antigravity run now? One process listing (names only) at most every
    /// [`PROCESS_CHECK_TTL_MS`]; a failed listing counts as "not running" (no false alarm).
    pub(super) fn app_is_running(&self, now: u64) -> bool {
        if let Ok(g) = self.running.lock()
            && let Some((at, answer)) = *g
            && now.saturating_sub(at) < PROCESS_CHECK_TTL_MS
        {
            return answer;
        }
        let listing = match self.os {
            Os::Windows => self.probe.run("tasklist", &["/FO", "CSV", "/NH"]),
            _ => self.probe.run("ps", &["-axo", "comm="]),
        };
        let answer = listing.is_some_and(|t| listing_has_antigravity(&t));
        if let Ok(mut g) = self.running.lock() {
            *g = Some((now, answer));
        }
        answer
    }

}
