//! Layer 0 shutdown notification hook so lower layers can signal app shutdown
//! without importing `crate::startup` or `tauri`.

use std::sync::{Arc, RwLock};

type ShutdownHook = Arc<dyn Fn() + Send + Sync>;

static SHUTDOWN_HOOK: RwLock<Option<ShutdownHook>> = RwLock::new(None);

/// Registers the shutdown callback invoked by [`notify_shutdown`].
pub fn register_shutdown_hook<F>(hook: F)
where
    F: Fn() + Send + Sync + 'static,
{
    if let Ok(mut guard) = SHUTDOWN_HOOK.write() {
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
