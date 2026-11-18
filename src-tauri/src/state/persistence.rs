//! Atomic file persistence (mode 0600 on Unix), v1 backup, and `AppState` lifecycle constructors.

use super::AppState;
use super::schema::{AppStateData, STATE_FILE_NAME, STATE_V1_BACKUP_NAME, StateError};
use super::stats::{GatewayStatsSnapshot, GatewayStatsTracker};
use crate::routing::RouteHealthRegistry;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{RwLock, watch};

impl AppState {
    /// Creates a new in-memory `AppState` with optional persistence file path.
    pub fn new(data: AppStateData, storage_path: Option<PathBuf>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(data)),
            storage_path,
            save_lock: Arc::new(tokio::sync::Mutex::new(())),
            stats: Arc::new(GatewayStatsTracker::new()),
            route_health: Arc::new(RouteHealthRegistry::default()),
            routing_gen: Arc::new(watch::channel(0u64).0),
        }
    }

    /// Receiver that fires after every routing-relevant change (see `routing_gen`).
    pub fn subscribe_routing(&self) -> watch::Receiver<u64> {
        self.routing_gen.subscribe()
    }

    /// Current routing generation.
    pub fn routing_generation(&self) -> u64 {
        *self.routing_gen.borrow()
    }

    pub(super) fn bump_routing(&self) {
        self.routing_gen.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Runtime (not persisted) health of routes.
    pub fn route_health(&self) -> &Arc<RouteHealthRegistry> {
        &self.route_health
    }

    /// Access the live gateway statistics tracker.
    pub fn stats(&self) -> &Arc<GatewayStatsTracker> {
        &self.stats
    }

    /// Returns a live snapshot of gateway statistics.
    pub async fn get_gateway_stats(&self) -> GatewayStatsSnapshot {
        self.stats.snapshot().await
    }

    /// Creates an in-memory `AppState` initialized with default values.
    pub fn new_in_memory() -> Self {
        Self::new(AppStateData::default(), None)
    }

    /// Loads state from `state.json` at `storage_path`. A missing file yields the defaults. A file
    /// that cannot be read at all is first copied to `state.corrupt-<ts>.json` and then replaced by
    /// the defaults; a single unrecognised route never resets the rest of the state.
    pub fn load_or_default(storage_path: PathBuf) -> Self {
        let mut needs_save = false;
        let mut data = if storage_path.exists() {
            Self::restrict_to_owner(&storage_path);
            match Self::read_state_lenient(&storage_path) {
                Ok(mut loaded) => {
                    let now = crate::auditor::network::current_timestamp();
                    if loaded.schema_version < 2 {
                        Self::backup_v1_state_once(&storage_path);
                    }
                    needs_save = loaded.migrate(now);
                    loaded
                }
                Err(err) => {
                    let kept = Self::keep_corrupt_copy(&storage_path);
                    eprintln!(
                        "Warning: Failed to load state from {}: {}. {} Self-healing to default state.",
                        storage_path.display(),
                        err,
                        match kept {
                            Some(p) => format!("The original file was kept as {}.", p.display()),
                            None => "The original file could not be copied.".to_string(),
                        }
                    );
                    needs_save = true;
                    AppStateData::default()
                }
            }
        } else {
            AppStateData::default()
        };

        // Session allowances are ephemeral per app launch and must not carry over across restarts
        data.session_allowed_providers.clear();

        if needs_save && let Err(e) = Self::save_data_to_file(&data, &storage_path) {
            eprintln!("Warning: could not rewrite {}: {e}", storage_path.display());
        }

        Self::new(data, Some(storage_path))
    }

    /// Loads `AppStateData` from a file path, migrated to the current schema.
    pub fn load_from_file(path: &Path) -> Result<AppStateData, StateError> {
        let mut data = Self::read_state_lenient(path)?;
        data.migrate(crate::auditor::network::current_timestamp());
        Ok(data)
    }

    /// Copies the original v1.3.x file next to it, once.
    fn backup_v1_state_once(path: &Path) {
        let backup = path.with_file_name(STATE_V1_BACKUP_NAME);
        if backup.exists() {
            return;
        }
        if let Err(e) = Self::copy_private(path, &backup) {
            eprintln!("Warning: could not back up the v1 state file: {e}");
        }
    }

    /// Creates (truncating) a file that only the owner can read: mode 0600 on unix, default ACLs
    /// on Windows.
    pub(super) fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    }

    /// Tightens an existing file to 0600 on unix (no-op on Windows and on errors).
    pub(super) fn restrict_to_owner(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    /// Copies `src` to `dest` as an owner-only file (unlike `fs::copy`, which keeps the source mode).
    pub(super) fn copy_private(src: &Path, dest: &Path) -> std::io::Result<()> {
        let mut input = std::fs::File::open(src)?;
        let mut out = Self::create_private_file(dest)?;
        // An existing destination keeps its old mode through `create`, so tighten it explicitly.
        Self::restrict_to_owner(dest);
        std::io::copy(&mut input, &mut out)?;
        out.sync_all()
    }

    /// Saves `AppStateData` atomically: temp file + fsync + rename (+ fsync of the directory).
    pub fn save_data_to_file(data: &AppStateData, path: &Path) -> Result<(), StateError> {
        use std::io::Write;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(data)?;
        let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
        {
            let mut f = Self::create_private_file(&tmp_path)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            // Fallback to direct write if cross-device or Windows file lock prevents rename
            let mut f = Self::create_private_file(path).map_err(|_| StateError::Io(e))?;
            Self::restrict_to_owner(path);
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        if let Some(parent) = path.parent()
            && let Ok(dir) = std::fs::File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Synchronously saves the current state to the configured storage path.
    pub fn save_sync(&self) -> Result<(), StateError> {
        if let Some(path) = &self.storage_path {
            let data = self.inner.blocking_read().clone();
            Self::save_data_to_file(&data, path)?;
        }
        Ok(())
    }

    /// Asynchronously saves the current state to the configured storage path.
    pub async fn save_async(&self) -> Result<(), StateError> {
        if let Some(path) = &self.storage_path {
            let _guard = self.save_lock.lock().await;
            let data = self.inner.read().await.clone();
            let path_clone = path.clone();
            tokio::task::spawn_blocking(move || Self::save_data_to_file(&data, &path_clone))
                .await
                .map_err(|e| StateError::PathError(e.to_string()))??;
        }
        Ok(())
    }

    /// Returns a cloned snapshot of current `AppStateData`.
    pub async fn get_data(&self) -> AppStateData {
        self.inner.read().await.clone()
    }

    /// Direct async read lock.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, AppStateData> {
        self.inner.read().await
    }

    /// Direct async write lock.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, AppStateData> {
        self.inner.write().await
    }
}

/// Initializes `AppState` from the standard Tauri app data directory.
pub fn init_app_state<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<AppState, StateError> {
    use tauri::Manager;
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| StateError::PathError(e.to_string()))?;
    std::fs::create_dir_all(&app_data_dir)?;
    let state_file = app_data_dir.join(STATE_FILE_NAME);
    let state = AppState::load_or_default(state_file);
    Ok(state)
}
