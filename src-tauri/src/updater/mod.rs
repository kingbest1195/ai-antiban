//! Native signed updater (tauri-plugin-updater, minisign).
//!
//! There is deliberately no second download path: no GitHub API fallback, no URL taken from the
//! frontend, no platform scripts. The package is fetched from the endpoint pinned in
//! `tauri.conf.json`, verified against the pinned public key, and only then installed. Any error
//! is reported as an [`UpdateFailure`] and nothing is installed.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::{Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterBuilder, UpdaterExt};

pub const GITHUB_REPO: &str = "kingbest1195/ai-antiban";
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release_name: String,
    pub release_notes: String,
    /// Built by the backend from the announced version; never taken from the frontend.
    pub release_url: String,
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProgressPayload {
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub percent: u8,
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStatusPayload {
    pub stage: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallUpdateResult {
    pub success: bool,
    pub message: String,
    pub will_restart: bool,
}

/// Why an update check or installation failed. Serialized for the frontend as
/// `{"kind":"network"}` / `{"kind":"install","message":"..."}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", content = "message", rename_all = "kebab-case")]
pub enum UpdateFailure {
    /// The release server could not be reached or answered with an error status.
    #[error("update server is unreachable")]
    Network,
    /// The downloaded package does not match the pinned minisign public key. Nothing was installed.
    #[error("update signature verification failed")]
    Signature,
    /// No usable release description (latest.json) or no package for this platform.
    #[error("no release information available")]
    NoRelease,
    /// Unpacking or installing the verified package failed.
    #[error("update installation failed: {0}")]
    Install(String),
    /// Installation failed after protection was switched off, and protection was switched back
    /// on (it had been on before the update started).
    #[error("update installation failed, protection restored: {0}")]
    InstallRestored(String),
}

/// Outcome of the "protection_restore" step that runs after a failed installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// Protection was not on before the update, so there was nothing to bring back.
    NotNeeded,
    /// Protection was on before the update and is on again.
    Restored,
    /// Protection was on before the update and could not be brought back.
    Failed,
}

/// Minimal description of an announced update (what the UI needs; no download location).
#[derive(Debug, Clone)]
pub struct UpdateMeta {
    pub version: String,
    pub body: Option<String>,
    pub date: Option<String>,
}

/// Parses a semantic version string (e.g. `"v1.0.4"` -> `(1, 0, 4)`).
pub fn parse_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let clean = ver.trim().trim_start_matches(['v', 'V']);
    let core = clean.split('-').next().unwrap_or(clean);
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    Some((major, minor, patch))
}

/// Returns `true` if `latest` is strictly newer than `current`.
pub fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(cur), Some(lat)) => lat > cur,
        _ => false,
    }
}

/// Release page for a version, always on our own repository.
pub fn release_url_for(version: &str) -> String {
    let clean = version.trim().trim_start_matches(['v', 'V']);
    format!("https://github.com/{GITHUB_REPO}/releases/tag/v{clean}")
}

fn latest_release_url() -> String {
    format!("https://github.com/{GITHUB_REPO}/releases/latest")
}

/// Maps a plugin error to a user-facing failure class. Signature problems are never downgraded
/// to a network or install error: the caller must see that the package was rejected.
pub fn map_error(e: &tauri_plugin_updater::Error) -> UpdateFailure {
    use tauri_plugin_updater::Error as E;
    match e {
        E::Minisign(_)
        | E::Base64(_)
        | E::SignatureUtf8(_)
        | E::SignedVersionMismatch { .. }
        | E::MissingSignedVersion => UpdateFailure::Signature,
        E::Network(_) | E::Reqwest(_) => UpdateFailure::Network,
        E::ReleaseNotFound
        | E::TargetNotFound(_)
        | E::TargetsNotFound(_)
        | E::Serialization(_)
        | E::Semver(_) => UpdateFailure::NoRelease,
        other => UpdateFailure::Install(other.to_string()),
    }
}

/// Builds the check result from an announced update (`None` = already up to date).
pub fn map_update(meta: Option<UpdateMeta>) -> UpdateCheckResult {
    match meta {
        Some(m) => {
            let latest = m.version.trim().trim_start_matches(['v', 'V']).to_string();
            UpdateCheckResult {
                current_version: CURRENT_VERSION.to_string(),
                update_available: is_newer_version(CURRENT_VERSION, &latest),
                release_name: format!("Zastava v{latest}"),
                release_notes: m.body.unwrap_or_else(|| {
                    "Официальная подписанная сборка Zastava (minisign).".to_string()
                }),
                release_url: release_url_for(&latest),
                published_at: m.date,
                latest_version: latest,
            }
        }
        None => UpdateCheckResult {
            current_version: CURRENT_VERSION.to_string(),
            latest_version: CURRENT_VERSION.to_string(),
            update_available: false,
            release_name: format!("Zastava v{CURRENT_VERSION}"),
            release_notes: "У вас установлена актуальная подписанная версия Заставы.".to_string(),
            release_url: latest_release_url(),
            published_at: None,
        },
    }
}

/// Updater builder with the downgrade guard: a release is an update only if its version is
/// strictly greater than the running one, regardless of plugin configuration.
pub fn updater_builder<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> UpdaterBuilder {
    app.updater_builder()
        .version_comparator(|current, release| release.version > current)
}

/// Checks `latest.json` through the signed updater. Errors are returned as is; there is no
/// fallback to another source.
pub async fn check_for_updates(app: &tauri::AppHandle) -> Result<UpdateCheckResult, UpdateFailure> {
    let updater = updater_builder(app).build().map_err(|e| map_error(&e))?;
    let update = updater.check().await.map_err(|e| map_error(&e))?;
    Ok(map_update(update.map(|u| UpdateMeta {
        version: u.version,
        body: u.body,
        date: u.date.map(|d| d.to_string()),
    })))
}

/// Download, verify, then install. Order is the safety contract of this module:
///
/// 1. `update.download` fetches the package and verifies the minisign signature (the plugin
///    calls its own "download finished" callback BEFORE verifying, so it is not used here).
/// 2. Only if that succeeded `protection_off` runs (system proxy is switched off).
/// 3. Only then `install` runs.
/// 4. If `install` fails, `protection_restore` runs once, so the still-running app is not left
///    without protection that was on before the update.
///
/// A rejected signature (or a network error) therefore leaves protection untouched, never calls
/// `protection_restore`, and installs nothing.
pub async fn download_verify_install<C, D, I, R>(
    update: &Update,
    on_chunk: C,
    protection_off: D,
    install: I,
    protection_restore: R,
) -> Result<(), UpdateFailure>
where
    C: FnMut(usize, Option<u64>),
    D: FnOnce(),
    I: FnOnce(&Update, &[u8]) -> tauri_plugin_updater::Result<()>,
    R: FnOnce() -> RestoreOutcome,
{
    let bytes = update
        .download(on_chunk, || {})
        .await
        .map_err(|e| map_error(&e))?;
    protection_off();
    match install(update, &bytes) {
        Ok(()) => Ok(()),
        Err(e) => {
            let failure = map_error(&e);
            match (protection_restore(), failure) {
                (RestoreOutcome::Restored, UpdateFailure::Install(msg)) => {
                    Err(UpdateFailure::InstallRestored(msg))
                }
                (_, failure) => Err(failure),
            }
        }
    }
}

/// What the restore step needs, captured before `protection_off` runs.
struct ProtectionSnapshot {
    sysproxy: bool,
    cli: bool,
}

/// Switches protection back on through the same calls as the `toggle_sysproxy(true)` command:
/// `enable_sysproxy` and `enable_cli_and_ide_protection_with`. Only what was on is restored; a
/// refused CLI / IDE enable (`enabled == false`, e.g. the journal is busy) is a failure.
fn restore_protection(
    snap: Option<ProtectionSnapshot>,
    pac_url: Option<String>,
    mode: crate::state::CliMode,
    tz: Option<String>,
) -> RestoreOutcome {
    let Some(snap) = snap else {
        return RestoreOutcome::NotNeeded;
    };
    if !snap.sysproxy && !snap.cli {
        return RestoreOutcome::NotNeeded;
    }
    let Some(pac_url) = pac_url else {
        return RestoreOutcome::Failed;
    };
    let mut ok = true;
    if snap.sysproxy {
        ok &= crate::sysproxy::enable_sysproxy(&pac_url).is_ok();
    }
    if snap.cli {
        ok &= crate::sysproxy::enable_cli_and_ide_protection_with(&pac_url, mode, tz.as_deref())
            .enabled;
    }
    if ok {
        RestoreOutcome::Restored
    } else {
        RestoreOutcome::Failed
    }
}

fn emit_progress(app: &tauri::AppHandle, downloaded: u64, total: u64, percent: u8, phase: &str) {
    let _ = app.emit(
        "updater://progress",
        UpdateProgressPayload {
            downloaded_bytes: downloaded,
            total_bytes: total,
            percent,
            phase: phase.to_string(),
        },
    );
}

/// Installs the update announced by the pinned endpoint. Takes no parameters from the frontend.
pub async fn install_update(app: &tauri::AppHandle) -> Result<InstallUpdateResult, UpdateFailure> {
    let updater = updater_builder(app).build().map_err(|e| map_error(&e))?;
    let update = updater
        .check()
        .await
        .map_err(|e| map_error(&e))?
        .ok_or(UpdateFailure::NoRelease)?;

    if !is_newer_version(CURRENT_VERSION, &update.version) {
        return Err(UpdateFailure::NoRelease);
    }

    let _ = app.emit(
        "updater://status",
        UpdateStatusPayload {
            stage: "downloading".to_string(),
            message: format!(
                "Скачивание подписанного пакета v{} (minisign)...",
                update.version
            ),
        },
    );
    emit_progress(app, 0, 0, 5, "Подключение к репозиторию релизов...");

    // Inputs of the restore step, read here because the closures below are synchronous.
    let pac_url = app
        .try_state::<crate::proxy::ProxyManager>()
        .map(|pm| format!("http://{}/proxy.pac", pm.server.bound_addr));
    let (mode, tz) = match app.try_state::<crate::state::AppState>() {
        Some(st) => {
            let data = st.get_data().await;
            (data.cli_mode, data.effective_sync_tz())
        }
        None => (crate::state::CliMode::default(), None),
    };
    let snapshot: std::sync::Arc<std::sync::Mutex<Option<ProtectionSnapshot>>> = Default::default();
    let (snap_off, snap_restore) = (snapshot.clone(), snapshot.clone());

    let downloaded = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let total_seen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let app_chunks = app.clone();
    let (dl_c, total_c) = (downloaded.clone(), total_seen.clone());
    let app_off = app.clone();
    let total_off = total_seen.clone();

    download_verify_install(
        &update,
        move |chunk_length, content_length| {
            use std::sync::atomic::Ordering::Relaxed;
            let dl = dl_c.fetch_add(chunk_length as u64, Relaxed) + chunk_length as u64;
            let total = match content_length {
                Some(t) => {
                    total_c.store(t, Relaxed);
                    t
                }
                None => total_c.load(Relaxed),
            };
            let percent = if total > 0 {
                ((dl as f64 / total as f64) * 85.0).clamp(5.0, 90.0) as u8
            } else {
                50
            };
            emit_progress(
                &app_chunks,
                dl,
                total,
                percent,
                "Скачивание и проверка подписи minisign...",
            );
        },
        move || {
            // Reached only after the signature was verified. Remember what was on, then switch off.
            if let Ok(mut g) = snap_off.lock() {
                *g = Some(ProtectionSnapshot {
                    sysproxy: crate::sysproxy::is_sysproxy_active(),
                    cli: crate::sysproxy::is_cli_protection_enabled(),
                });
            }
            crate::sysproxy::cleanup_all_persistent_settings();
            let total = total_off.load(std::sync::atomic::Ordering::Relaxed);
            emit_progress(
                &app_off,
                total,
                total,
                95,
                "Подпись проверена, распаковка и установка...",
            );
        },
        |u, bytes| u.install(bytes),
        move || {
            let snap = snap_restore.lock().ok().and_then(|mut g| g.take());
            restore_protection(snap, pac_url, mode, tz)
        },
    )
    .await?;

    emit_progress(app, 100, 100, 100, "Перезапуск Заставы...");
    let _ = app.emit(
        "updater://status",
        UpdateStatusPayload {
            stage: "installing".to_string(),
            message: "Подписанное обновление проверено и установлено!".to_string(),
        },
    );

    // Windows: `install` hands over to the installer and exits the process, so this is macOS only.
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        crate::sysproxy::cleanup_all_persistent_settings();
        app_clone.restart();
    });

    Ok(InstallUpdateResult {
        success: true,
        message: format!(
            "Подписанное обновление v{} проверено (minisign) и установлено! Застава сейчас перезапустится.",
            update.version
        ),
        will_restart: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_comparison() {
        assert_eq!(CURRENT_VERSION, env!("CARGO_PKG_VERSION"));
        assert!(is_newer_version("1.0.3", "1.0.4"));
        assert!(is_newer_version("v1.0.3", "v1.0.4"));
        assert!(is_newer_version("1.0.3", "1.1.0"));
        assert!(is_newer_version("1.0.3", "2.0.0"));
        assert!(is_newer_version("2.0.0", "2.0.1"));
        assert!(is_newer_version("2.0.0", "2.1.0"));
        assert!(!is_newer_version("2.1.0", "2.0.0"));
        assert!(!is_newer_version("2.0.0", "2.0.0"));
        assert!(!is_newer_version("2.0.0", "1.3.1"));
        assert!(!is_newer_version("1.0.4", "1.0.4"));
        assert!(!is_newer_version("1.0.4", "1.0.3"));
        assert!(is_newer_version("1.0.3", "1.0.10"));
    }

    #[test]
    fn map_error_network_is_failure_not_ok() {
        let err = tauri_plugin_updater::Error::Network("down".into());
        assert_eq!(map_error(&err), UpdateFailure::Network);
        let r: Result<UpdateCheckResult, UpdateFailure> = Err(map_error(&err));
        assert!(matches!(r, Err(UpdateFailure::Network)));
    }

    #[test]
    fn map_error_classes() {
        use tauri_plugin_updater::Error as E;
        assert_eq!(map_error(&E::ReleaseNotFound), UpdateFailure::NoRelease);
        assert_eq!(
            map_error(&E::TargetNotFound("x".into())),
            UpdateFailure::NoRelease
        );
        assert_eq!(
            map_error(&E::SignatureUtf8("x".into())),
            UpdateFailure::Signature
        );
        assert_eq!(
            map_error(&E::MissingSignedVersion),
            UpdateFailure::Signature
        );
        assert!(matches!(
            map_error(&E::InvalidUpdaterFormat),
            UpdateFailure::Install(_)
        ));
    }

    #[test]
    fn update_failure_serde_codes() {
        let v = |f: UpdateFailure| serde_json::to_value(f).unwrap();
        assert_eq!(
            v(UpdateFailure::Network),
            serde_json::json!({"kind": "network"})
        );
        assert_eq!(
            v(UpdateFailure::Signature),
            serde_json::json!({"kind": "signature"})
        );
        assert_eq!(
            v(UpdateFailure::NoRelease),
            serde_json::json!({"kind": "no-release"})
        );
        assert_eq!(
            v(UpdateFailure::Install("boom".into())),
            serde_json::json!({"kind": "install", "message": "boom"})
        );
        assert_eq!(
            v(UpdateFailure::InstallRestored("boom".into())),
            serde_json::json!({"kind": "install-restored", "message": "boom"})
        );
    }

    #[test]
    fn update_check_result_has_no_download_fields() {
        let meta = UpdateMeta {
            version: "v2.1.0".into(),
            body: Some("notes".into()),
            date: None,
        };
        let value = serde_json::to_value(map_update(Some(meta))).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "current_version",
                "latest_version",
                "published_at",
                "release_name",
                "release_notes",
                "release_url",
                "update_available"
            ]
        );
        assert_eq!(value["latest_version"], "2.1.0");
        assert_eq!(
            value["release_url"],
            "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.1.0"
        );
        assert!(value.get("download_url").is_none());
        assert!(value.get("asset_name").is_none());
        assert!(value.get("asset_size").is_none());
    }

    #[test]
    fn map_update_none_points_to_latest_release_page() {
        let r = map_update(None);
        assert!(!r.update_available);
        assert_eq!(r.latest_version, CURRENT_VERSION);
        assert_eq!(
            r.release_url,
            "https://github.com/kingbest1195/ai-antiban/releases/latest"
        );
    }
}
