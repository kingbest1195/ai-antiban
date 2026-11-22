//! Start sequence that runs in the background, so the window, the tray and the IPC answer at once.
//!
//! Everything slow that talks to the OS (journal recovery, `networksetup` for each network
//! service, CLI/IDE files) used to run inside the Tauri `setup` hook, and the window stayed dead
//! until it finished. It runs here instead, on its own thread, in the order that must hold:
//!
//! 1. recovery of the ownership journal (puts back what a previous run changed);
//! 2. protection on (PAC + CLI/IDE), only after the gateway listens (the PAC URL is the proof);
//! 3. the network guard.
//!
//! The interface sees [`Phase::Starting`] until the end and shows "checking" instead of a state
//! it does not know yet. Fail closed: nothing here loosens a guarantee, it only moves work.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Event with the current [`StartupSnapshot`].
pub const STARTUP_EVENT: &str = "startup://phase";

/// Bounded wait for `zastava-startup` to drain when shutdown begins mid-startup.
pub const STARTUP_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

static GLOBAL_SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);
static STARTUP_ACTIVE_LOCK: Mutex<usize> = Mutex::new(0);
static STARTUP_DRAIN_CV: Condvar = Condvar::new();

#[cfg(test)]
pub(crate) static GLOBAL_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Marks globally (lock-free, independent of `AppHandle`) that the application is shutting down.
pub fn note_shutdown_global() {
    GLOBAL_SHUTTING_DOWN.store(true, Ordering::SeqCst);
}

/// Returns `true` once [`note_shutdown_global`] has been called in this process.
pub fn is_shutting_down_global() -> bool {
    GLOBAL_SHUTTING_DOWN.load(Ordering::SeqCst)
}

/// Registers an active startup worker / step. Pair with [`mark_startup_finished`] or prefer
/// [`StartupActivityGuard::enter`].
pub fn mark_startup_started() {
    let mut count = STARTUP_ACTIVE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *count += 1;
}

/// Unregisters an active startup worker / step and wakes any [`wait_for_startup_drain`] waiter
/// once the count drops to zero.
pub fn mark_startup_finished() {
    let mut count = STARTUP_ACTIVE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *count = count.saturating_sub(1);
    if *count == 0 {
        STARTUP_DRAIN_CV.notify_all();
    }
}

/// RAII guard registering startup activity for the lifetime of a startup sequence / thread.
pub struct StartupActivityGuard {
    _private: (),
}

impl StartupActivityGuard {
    pub fn enter() -> Self {
        mark_startup_started();
        Self { _private: () }
    }
}

impl Drop for StartupActivityGuard {
    fn drop(&mut self) {
        mark_startup_finished();
    }
}

/// Waits up to `timeout` for all active startup guards to finish. Returns `true` if drained.
pub fn wait_for_startup_drain(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut count = STARTUP_ACTIVE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    while *count > 0 {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let (guard, wait_res) = STARTUP_DRAIN_CV
            .wait_timeout(count, deadline.saturating_duration_since(now))
            .unwrap_or_else(|e| e.into_inner());
        count = guard;
        if wait_res.timed_out() && *count > 0 {
            return false;
        }
    }
    true
}

#[cfg(test)]
pub(crate) fn reset_global_for_test() {
    GLOBAL_SHUTTING_DOWN.store(false, Ordering::SeqCst);
    let mut count = STARTUP_ACTIVE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *count = 0;
    STARTUP_DRAIN_CV.notify_all();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// The background sequence has not finished: the protection state is not known yet.
    Starting,
    Ready,
}

/// What the interface may know about the start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StartupSnapshot {
    pub phase: Phase,
    /// Current step while starting: `recovery`, `protection`, `guard`.
    pub step: Option<&'static str>,
}

/// Where a change of the snapshot goes (the Tauri event in the app, a recorder in tests).
pub trait StartupSink: Send + Sync {
    fn publish(&self, snapshot: &StartupSnapshot);
}

/// The three steps of the sequence; the real ones touch the OS, tests record the calls.
pub trait StartupSteps: Send + Sync {
    /// Journal recovery (before protection is enabled).
    fn recover(&self);
    /// PAC + CLI/IDE protection on.
    fn enable_protection(&self);
    /// Starts the network guard.
    fn start_guard(&self);
    /// The app began to quit while protection was being enabled: put everything back.
    fn undo_protection(&self);
}

/// Shared start state: phase for the interface plus two flags other code can raise.
pub struct StartupState {
    snapshot: Mutex<StartupSnapshot>,
    shutting_down: AtomicBool,
    user_took_over: AtomicBool,
}

impl Default for StartupState {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupState {
    pub fn new() -> Self {
        Self {
            snapshot: Mutex::new(StartupSnapshot {
                phase: Phase::Starting,
                step: None,
            }),
            shutting_down: AtomicBool::new(false),
            user_took_over: AtomicBool::new(false),
        }
    }

    pub fn snapshot(&self) -> StartupSnapshot {
        self.snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn is_ready(&self) -> bool {
        self.snapshot().phase == Phase::Ready
    }

    /// The app is quitting: the sequence must not (re-)enable protection any more.
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// The user switched protection off (or reset it) by hand while the sequence was still
    /// running: the automatic "protection on" step must not undo that.
    pub fn user_took_over(&self) {
        self.user_took_over.store(true, Ordering::SeqCst);
    }

    fn took_over(&self) -> bool {
        self.user_took_over.load(Ordering::SeqCst)
    }

    fn set(&self, sink: &dyn StartupSink, phase: Phase, step: Option<&'static str>) {
        let snap = StartupSnapshot { phase, step };
        *self.snapshot.lock().unwrap_or_else(|e| e.into_inner()) = snap.clone();
        sink.publish(&snap);
    }
}

/// The app begins to quit: the sequence must not enable protection any more.
pub fn note_shutdown(app: &tauri::AppHandle) {
    use tauri::Manager;
    note_shutdown_global();
    if let Some(state) = app.try_state::<std::sync::Arc<StartupState>>() {
        state.begin_shutdown();
    }
}

/// The user switched protection off by hand (tray or interface).
pub fn note_user_off(app: &tauri::AppHandle) {
    use tauri::Manager;
    if let Some(state) = app.try_state::<std::sync::Arc<StartupState>>() {
        state.user_took_over();
    }
}

/// Runs the sequence on the calling thread. Always ends in [`Phase::Ready`] (even when it stops
/// early) so the interface never waits for ever.
pub fn run_sequence(steps: &dyn StartupSteps, state: &StartupState, sink: &dyn StartupSink) {
    let _activity = StartupActivityGuard::enter();
    sequence(steps, state, sink);
    state.set(sink, Phase::Ready, None);
}

fn sequence(steps: &dyn StartupSteps, state: &StartupState, sink: &dyn StartupSink) {
    state.set(sink, Phase::Starting, Some("recovery"));
    steps.recover();
    if state.is_shutting_down() || is_shutting_down_global() {
        return;
    }

    if state.took_over() {
        eprintln!(
            "Застава: защита выключена вручную до конца запуска, автоматическое включение пропущено"
        );
    } else {
        state.set(sink, Phase::Starting, Some("protection"));
        steps.enable_protection();
        // A quit that began during the writes ran its own restore before they finished: do it again.
        if state.is_shutting_down() || is_shutting_down_global() {
            steps.undo_protection();
            return;
        }
    }

    if state.is_shutting_down() || is_shutting_down_global() {
        return;
    }
    state.set(sink, Phase::Starting, Some("guard"));
    steps.start_guard();
}

/// Starts the sequence on a named background thread and returns at once.
pub fn spawn(
    steps: std::sync::Arc<dyn StartupSteps>,
    state: std::sync::Arc<StartupState>,
    sink: std::sync::Arc<dyn StartupSink>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let guard = StartupActivityGuard::enter();
    std::thread::Builder::new()
        .name("zastava-startup".into())
        .spawn(move || {
            let _guard = guard;
            run_sequence(&*steps, &state, &*sink);
        })
}

#[cfg(test)]
#[path = "startup_tests.rs"]
mod tests;
