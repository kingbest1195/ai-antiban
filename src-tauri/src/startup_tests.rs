use super::*;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

struct GlobalTestReset;
impl Drop for GlobalTestReset {
    fn drop(&mut self) {
        reset_global_for_test();
    }
}

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
    let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = GlobalTestReset;
    reset_global_for_test();

    let rec = Arc::new(Recorder::default());
    let state = StartupState::new();
    assert_eq!(state.snapshot().phase, Phase::Starting);
    run_sequence(&Fake::new(&rec), &state, &*rec);
    assert_eq!(rec.calls(), ["recover", "enable", "guard"]);
    assert!(state.is_ready());
    let steps: Vec<_> = rec
        .snaps
        .lock()
        .unwrap()
        .iter()
        .map(|s| (s.phase, s.step))
        .collect();
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
    let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = GlobalTestReset;
    reset_global_for_test();

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
    let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = GlobalTestReset;
    reset_global_for_test();

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
    let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = GlobalTestReset;
    reset_global_for_test();

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
fn global_shutdown_flag_and_wait_for_startup_drain_coordinate_shutdown() {
    let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = GlobalTestReset;
    reset_global_for_test();

    assert!(!is_shutting_down_global());
    assert!(wait_for_startup_drain(Duration::from_millis(50)));

    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let worker = std::thread::spawn(move || {
        let _guard = StartupActivityGuard::enter();
        started_tx.send(()).unwrap();
        let _ = release_rx.recv();
    });

    started_rx.recv().unwrap();
    // Bounded timeout expires cleanly while startup is still active.
    assert!(!wait_for_startup_drain(Duration::from_millis(30)));

    note_shutdown_global();
    assert!(is_shutting_down_global());

    release_tx.send(()).unwrap();
    assert!(wait_for_startup_drain(Duration::from_secs(1)));
    worker.join().unwrap();
}

#[test]
fn snapshot_serialises_for_the_interface() {
    let json = serde_json::to_value(StartupSnapshot {
        phase: Phase::Starting,
        step: Some("protection"),
    })
    .unwrap();
    assert_eq!(
        json,
        serde_json::json!({"phase": "starting", "step": "protection"})
    );
    let ready = serde_json::to_value(StartupSnapshot {
        phase: Phase::Ready,
        step: None,
    })
    .unwrap();
    assert_eq!(ready, serde_json::json!({"phase": "ready", "step": null}));
}
