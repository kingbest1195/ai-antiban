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
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Event with the current [`StartupSnapshot`].
pub const STARTUP_EVENT: &str = "startup://phase";

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
        self.snapshot.lock().unwrap_or_else(|e| e.into_inner()).clone()
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
    sequence(steps, state, sink);
    state.set(sink, Phase::Ready, None);
}

fn sequence(steps: &dyn StartupSteps, state: &StartupState, sink: &dyn StartupSink) {
    state.set(sink, Phase::Starting, Some("recovery"));
    steps.recover();
    if state.is_shutting_down() {
        return;
    }

    if state.took_over() {
        eprintln!("Застава: защита выключена вручную до конца запуска, автоматическое включение пропущено");
    } else {
        state.set(sink, Phase::Starting, Some("protection"));
        steps.enable_protection();
        // A quit that began during the writes ran its own restore before they finished: do it again.
        if state.is_shutting_down() {
            steps.undo_protection();
            return;
        }
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
    std::thread::Builder::new()
        .name("zastava-startup".into())
        .spawn(move || run_sequence(&*steps, &state, &*sink))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<&'static str>>,
        snaps: Mutex<Vec<StartupSnapshot>>,
    }

    impl Recorder {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl StartupSink for Recorder {
        fn publish(&self, s: &StartupSnapshot) {
            self.snaps.lock().unwrap().push(s.clone());
        }
    }

    /// Fake steps: record the order; `enable` may wait for a go-ahead and may flag a hook.
    struct Fake {
        rec: Arc<Recorder>,
        gate: Mutex<Option<mpsc::Receiver<()>>>,
        on_enable: Option<Box<dyn Fn() + Send + Sync>>,
    }

    impl Fake {
        fn new(rec: &Arc<Recorder>) -> Self {
            Self {
                rec: rec.clone(),
                gate: Mutex::new(None),
                on_enable: None,
            }
        }
    }

    impl StartupSteps for Fake {
        fn recover(&self) {
            self.rec.calls.lock().unwrap().push("recover");
        }
        fn enable_protection(&self) {
            self.rec.calls.lock().unwrap().push("enable");
            if let Some(rx) = self.gate.lock().unwrap().take() {
                let _ = rx.recv();
            }
            if let Some(f) = &self.on_enable {
                f();
            }
        }
        fn start_guard(&self) {
            self.rec.calls.lock().unwrap().push("guard");
        }
        fn undo_protection(&self) {
            self.rec.calls.lock().unwrap().push("undo");
        }
    }

    #[test]
    fn order_is_recovery_then_protection_then_guard_and_ends_ready() {
        let rec = Arc::new(Recorder::default());
        let state = StartupState::new();
        assert_eq!(state.snapshot().phase, Phase::Starting);
        run_sequence(&Fake::new(&rec), &state, &*rec);
        assert_eq!(rec.calls(), ["recover", "enable", "guard"]);
        assert!(state.is_ready());
        let steps: Vec<_> = rec.snaps.lock().unwrap().iter().map(|s| (s.phase, s.step)).collect();
        assert_eq!(
            steps,
            [
                (Phase::Starting, Some("recovery")),
                (Phase::Starting, Some("protection")),
                (Phase::Starting, Some("guard")),
                (Phase::Ready, None),
            ]
        );
    }

    #[test]
    fn spawning_does_not_wait_for_the_slow_step_and_starting_turns_ready() {
        let rec = Arc::new(Recorder::default());
        let (tx, rx) = mpsc::channel();
        let fake = Fake::new(&rec);
        *fake.gate.lock().unwrap() = Some(rx);
        let state = Arc::new(StartupState::new());
        let handle = spawn(Arc::new(fake), state.clone(), rec.clone()).unwrap();
        // The enable step is blocked, yet `spawn` returned and the state answers "starting".
        assert_eq!(state.snapshot().phase, Phase::Starting);
        assert!(!handle.is_finished());
        tx.send(()).unwrap();
        handle.join().unwrap();
        assert!(state.is_ready());
        assert_eq!(rec.calls(), ["recover", "enable", "guard"]);
    }

    #[test]
    fn a_user_who_switched_protection_off_is_not_overridden() {
        let rec = Arc::new(Recorder::default());
        let state = StartupState::new();
        state.user_took_over();
        run_sequence(&Fake::new(&rec), &state, &*rec);
        // Recovery and the guard still run; the automatic enable does not.
        assert_eq!(rec.calls(), ["recover", "guard"]);
        assert!(state.is_ready());
    }

    #[test]
    fn quitting_during_the_start_never_leaves_protection_on() {
        // Quit before anything: nothing is enabled.
        let rec = Arc::new(Recorder::default());
        let state = StartupState::new();
        state.begin_shutdown();
        run_sequence(&Fake::new(&rec), &state, &*rec);
        assert_eq!(rec.calls(), ["recover"]);
        assert!(state.is_ready());

        // Quit while the writes are going on: they are undone and the guard never starts.
        let rec = Arc::new(Recorder::default());
        let state = Arc::new(StartupState::new());
        let mut fake = Fake::new(&rec);
        let s2 = state.clone();
        fake.on_enable = Some(Box::new(move || s2.begin_shutdown()));
        run_sequence(&fake, &state, &*rec);
        assert_eq!(rec.calls(), ["recover", "enable", "undo"]);
        assert!(state.is_ready());
    }

    #[test]
    fn snapshot_serialises_for_the_interface() {
        let json = serde_json::to_value(StartupSnapshot {
            phase: Phase::Starting,
            step: Some("protection"),
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({"phase": "starting", "step": "protection"}));
        let ready = serde_json::to_value(StartupSnapshot { phase: Phase::Ready, step: None }).unwrap();
        assert_eq!(ready, serde_json::json!({"phase": "ready", "step": null}));
    }
}
