//! Native signed updater (tauri-plugin-updater, minisign).
//!
//! There is deliberately no second download path: no unsigned fallback, no URL taken from the
//! frontend, no platform scripts. Forward updates fetch from the endpoint pinned in
//! `tauri.conf.json`; signed rollbacks list GitHub releases metadata and fetch `latest.json` from
//! the canonical `github.com/kingbest1195/ai-antiban/releases/download/v{version}/latest.json`
//! endpoint, verified against the pinned [`UPDATER_PUBKEY`] minisign key before anything is
//! installed. Any error is reported as an [`UpdateFailure`] and nothing is installed.

mod github;
mod install;

#[cfg(test)]
use github::ROLLBACK_MAX_RELEASES;
pub use github::{
    is_newer_version, is_older_version, list_rollback_versions, normalize_semver,
    parse_rollback_releases, parse_semver, release_url_for, rollback_manifest_url,
};
pub use install::{
    download_verify_install, install_rollback_version, install_update, rollback_updater_builder,
};

use serde::{Deserialize, Serialize};
use tauri_plugin_updater::{UpdaterBuilder, UpdaterExt};

pub const GITHUB_REPO: &str = "kingbest1195/ai-antiban";
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Pinned minisign public key matching `src-tauri/tauri.conf.json` (`plugins.updater.pubkey`).
pub const UPDATER_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEE0QjJEMDA1QzQ5MjEwNUEKUldSYUVKTEVCZEN5cEE5R1JsaWFnbFVoWi9hRmExZExpTUpiaGdadjZ2ZTJ3a1R3MzUxMy91SkkK";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReleaseInfo {
    pub version: String,
    pub tag: String,
    pub name: String,
    pub published_at: Option<String>,
    pub notes_url: String,
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
            release_url: github::latest_release_url(),
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

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    pub use super::install::{
        WINDOWS_MSI_TARGET, WINDOWS_NSIS_TARGET, WindowsInstallKind, classify_windows_install,
        configure_rollback_builder, validate_windows_rollback_compatibility,
        windows_rollback_target,
    };
}

#[cfg(test)]
mod tests;
