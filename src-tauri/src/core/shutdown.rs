//! Layer 0 shutdown notification hook so lower layers can signal app shutdown
//! without importing `crate::startup` or `tauri`.

use std::sync::{Arc, RwLock};
use std::time::Duration;

type ShutdownHook = Arc<dyn Fn() + Send + Sync>;
type StartupDrainHook = Arc<dyn Fn(Duration) -> bool + Send + Sync>;
type TunnelAbortHook = Arc<dyn Fn() + Send + Sync>;
type SandboxExitHook = Arc<dyn Fn() + Send + Sync>;

static SHUTDOWN_HOOK: RwLock<Option<ShutdownHook>> = RwLock::new(None);
static STARTUP_DRAIN_HOOK: RwLock<Option<StartupDrainHook>> = RwLock::new(None);
static TUNNEL_ABORT_HOOK: RwLock<Option<TunnelAbortHook>> = RwLock::new(None);
static SANDBOX_EXIT_HOOK: RwLock<Option<SandboxExitHook>> = RwLock::new(None);

/// Registers the shutdown callback invoked by [`notify_shutdown`].
pub fn register_shutdown_hook<F>(hook: F)
where
    F: Fn() + Send + Sync + 'static,
{
    if let Ok(mut guard) = SHUTDOWN_HOOK.write() {
        *guard = Some(Arc::new(hook));
    }
}

/// Registers the callback used to wait for the background startup sequence to drain.
pub fn register_startup_drain_hook<F>(hook: F)
where
    F: Fn(Duration) -> bool + Send + Sync + 'static,
{
    if let Ok(mut guard) = STARTUP_DRAIN_HOOK.write() {
        *guard = Some(Arc::new(hook));
    }
}

/// Registers the callback that aborts all active proxy tunnels on shutdown.
pub fn register_tunnel_abort_hook<F>(hook: F)
where
    F: Fn() + Send + Sync + 'static,
{
    if let Ok(mut guard) = TUNNEL_ABORT_HOOK.write() {
        *guard = Some(Arc::new(hook));
    }
}

/// Registers the callback that terminates sandboxed browser processes on exit.
pub fn register_sandbox_exit_hook<F>(hook: F)
where
    F: Fn() + Send + Sync + 'static,
{
    if let Ok(mut guard) = SANDBOX_EXIT_HOOK.write() {
        *guard = Some(Arc::new(hook));
    }
}

/// Invokes the registered shutdown callback, if any.
pub fn notify_shutdown() {
    let hook = SHUTDOWN_HOOK.read().ok().and_then(|g| g.clone());
    if let Some(cb) = hook {
        cb();
    }
}

/// Waits up to `timeout` for the startup thread to finish any in-flight step.
/// Returns `true` if startup drained (or no hook is registered).
pub fn wait_for_startup_drain(timeout: Duration) -> bool {
    let hook = STARTUP_DRAIN_HOOK.read().ok().and_then(|g| g.clone());
    match hook {
        Some(cb) => cb(timeout),
        None => true,
    }
}

/// Invokes the registered shutdown tunnel-abort callback, if any.
pub fn abort_tunnels_on_shutdown() {
    let hook = TUNNEL_ABORT_HOOK.read().ok().and_then(|g| g.clone());
    if let Some(cb) = hook {
        cb();
    }
}

/// Invokes the registered sandbox termination callback, if any.
pub fn terminate_sandboxes_on_exit() {
    let hook = SANDBOX_EXIT_HOOK.read().ok().and_then(|g| g.clone());
    if let Some(cb) = hook {
        cb();
    }
}
