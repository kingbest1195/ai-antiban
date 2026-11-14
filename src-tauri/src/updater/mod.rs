//! Native signed updater (tauri-plugin-updater, minisign).
//!
//! There is deliberately no second download path: no unsigned fallback, no URL taken from the
//! frontend, no platform scripts. Forward updates fetch from the endpoint pinned in
//! `tauri.conf.json`; signed rollbacks list GitHub releases metadata and fetch `latest.json` from
//! the canonical `github.com/kingbest1195/ai-antiban/releases/download/v{version}/latest.json`
//! endpoint, verified against the pinned [`UPDATER_PUBKEY`] minisign key before anything is
//! installed. Any error is reported as an [`UpdateFailure`] and nothing is installed.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::time::Duration;
use tauri::{Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterBuilder, UpdaterExt};

pub const GITHUB_REPO: &str = "kingbest1195/ai-antiban";
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Pinned minisign public key matching `src-tauri/tauri.conf.json` (`plugins.updater.pubkey`).
pub const UPDATER_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEE0QjJEMDA1QzQ5MjEwNUEKUldSYUVKTEVCZEN5cEE5R1JsaWFnbFVoWi9hRmExZExpTUpiaGdadjZ2ZTJ3a1R3MzUxMy91SkkK";
const GITHUB_RELEASES_API_URL: &str =
    "https://api.github.com/repos/kingbest1195/ai-antiban/releases?per_page=15";
const ROLLBACK_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const ROLLBACK_MAX_RELEASES: usize = 8;

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

#[derive(Debug, Clone, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    assets: Vec<GitHubReleaseAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubReleaseAsset {
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    browser_download_url: Option<String>,
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

/// The pre-release tail of a version (`"2.1.0-rc.1"` -> `Some("rc.1")`), if any.
fn pre_release(ver: &str) -> Option<&str> {
    let clean = ver.trim().trim_start_matches(['v', 'V']);
    clean
        .split_once('-')
        .map(|(_, pre)| pre)
        .filter(|p| !p.is_empty())
}

/// Orders two pre-release tails the way semver does: dot-separated identifiers, numbers compare
/// numerically and sort before words, a shorter tail sorts before a longer one it prefixes.
fn compare_pre_release(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (mut a, mut b) = (a.split('.'), b.split('.'));
    loop {
        match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// Returns `true` if `latest` is strictly newer than `current`. A release is newer than its own
/// pre-release (`2.1.0` > `2.1.0-1`), so a trial build can update to the final release.
pub fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(cur), Some(lat)) if cur != lat => lat > cur,
        (Some(_), Some(_)) => match (pre_release(current), pre_release(latest)) {
            (Some(_), None) => true,
            (Some(c), Some(l)) => compare_pre_release(c, l) == Ordering::Less,
            (None, _) => false,
        },
        _ => false,
    }
}

/// Strictly validates and normalizes a SemVer string (`major.minor.patch`, optional `-pre`),
/// stripping at most one leading `v`/`V`. Rejects empty strings, missing/extra dot segments,
/// leading zeros on multi-digit numeric parts, and URL-unsafe characters.
pub fn normalize_semver(ver: &str) -> Option<String> {
    let trimmed = ver.trim();
    let clean = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
    if clean.is_empty() {
        return None;
    }
    let (core, pre) = match clean.split_once('-') {
        Some((c, p)) => {
            if p.is_empty()
                || p.starts_with('.')
                || p.ends_with('.')
                || p.contains("..")
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            {
                return None;
            }
            (c, Some(p))
        }
        None => (clean, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    for part in &parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        part.parse::<u32>().ok()?;
    }
    Some(match pre {
        Some(p) => format!("{core}-{p}"),
        None => core.to_string(),
    })
}

/// Returns `true` if `candidate` is a valid SemVer strictly older than `current`.
pub fn is_older_version(current: &str, candidate: &str) -> bool {
    let (Some(cur), Some(cand)) = (normalize_semver(current), normalize_semver(candidate)) else {
        return false;
    };
    is_newer_version(&cand, &cur)
}

fn compare_semver_desc(a: &str, b: &str) -> Ordering {
    if is_newer_version(b, a) {
        Ordering::Less
    } else if is_newer_version(a, b) {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

/// Parses GitHub Releases API JSON into rollback-eligible releases strictly older than
/// `current_version`, sorted newest-first and capped at [`ROLLBACK_MAX_RELEASES`].
pub fn parse_rollback_releases(
    json_str: &str,
    current_version: &str,
) -> Result<Vec<RollbackReleaseInfo>, UpdateFailure> {
    let releases: Vec<GitHubRelease> =
        serde_json::from_str(json_str).map_err(|_| UpdateFailure::NoRelease)?;
    let repo_prefix = format!("https://github.com/{GITHUB_REPO}/");

    let mut items: Vec<RollbackReleaseInfo> = releases
        .into_iter()
        .filter(|r| !r.draft && !r.prerelease)
        .filter(|r| r.assets.iter().any(|a| a.name == "latest.json"))
        .filter_map(|r| {
            let version = normalize_semver(&r.tag_name)?;
            if !is_older_version(current_version, &version) {
                return None;
            }
            let name = r
                .name
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("Zastava v{version}"));
            let notes_url = r
                .html_url
                .map(|u| u.trim().to_string())
                .filter(|u| u.starts_with(&repo_prefix))
                .unwrap_or_else(|| release_url_for(&version));
            Some(RollbackReleaseInfo {
                version,
                tag: r.tag_name.trim().to_string(),
                name,
                published_at: r.published_at,
                notes_url,
            })
        })
        .collect();

    items.sort_by(|a, b| compare_semver_desc(&a.version, &b.version));
    items.dedup_by(|a, b| a.version == b.version);
    items.truncate(ROLLBACK_MAX_RELEASES);
    Ok(items)
}

/// Validates a target rollback version and builds the canonical `github.com` `latest.json` URL.
pub fn rollback_manifest_url(version: &str) -> Result<(String, url::Url), UpdateFailure> {
    let clean = normalize_semver(version).ok_or(UpdateFailure::NoRelease)?;
    if !is_older_version(CURRENT_VERSION, &clean) {
        return Err(UpdateFailure::NoRelease);
    }
    let raw = format!("https://github.com/{GITHUB_REPO}/releases/download/v{clean}/latest.json");
    let url = url::Url::parse(&raw).map_err(|_| UpdateFailure::NoRelease)?;
    if url.scheme() != "https" || url.host_str() != Some("github.com") {
        return Err(UpdateFailure::NoRelease);
    }
    Ok((clean, url))
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

    run_install_pipeline(app, update, false).await
}

/// Fetches recent GitHub Releases and returns signed releases strictly older than
/// [`CURRENT_VERSION`] (newest-first, up to 8 entries) that include a `latest.json` asset.
pub async fn list_rollback_versions() -> Result<Vec<RollbackReleaseInfo>, UpdateFailure> {
    let client = reqwest::Client::builder()
        .timeout(ROLLBACK_HTTP_TIMEOUT)
        .build()
        .map_err(|_| UpdateFailure::Network)?;

    let resp = client
        .get(GITHUB_RELEASES_API_URL)
        .header(reqwest::header::USER_AGENT, "Zastava-Updater")
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| UpdateFailure::Network)?;

    if !resp.status().is_success() {
        return Err(UpdateFailure::Network);
    }

    let body = resp.text().await.map_err(|_| UpdateFailure::Network)?;
    parse_rollback_releases(&body, CURRENT_VERSION)
}

/// Builds a rollback [`UpdaterBuilder`] pinned to [`UPDATER_PUBKEY`] and the exact target version.
pub fn rollback_updater_builder<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    manifest_url: url::Url,
    target_version: String,
) -> Result<UpdaterBuilder, UpdateFailure> {
    app.updater_builder()
        .pubkey(UPDATER_PUBKEY)
        .endpoints(vec![manifest_url])
        .map_err(|e| map_error(&e))
        .map(|b| {
            b.version_comparator(move |_current, release| {
                let rel_ver = release.version.to_string();
                rel_ver == target_version && is_older_version(CURRENT_VERSION, &rel_ver)
            })
        })
}

/// Downloads, verifies (minisign), and installs a signed older release for rollback.
pub async fn install_rollback_version(
    app: &tauri::AppHandle,
    version: &str,
) -> Result<InstallUpdateResult, UpdateFailure> {
    let (target_version, manifest_url) = rollback_manifest_url(version)?;
    let updater = rollback_updater_builder(app, manifest_url, target_version)?
        .build()
        .map_err(|e| map_error(&e))?;
    let update = updater
        .check()
        .await
        .map_err(|e| map_error(&e))?
        .ok_or(UpdateFailure::NoRelease)?;

    if !is_older_version(CURRENT_VERSION, &update.version) {
        return Err(UpdateFailure::NoRelease);
    }

    run_install_pipeline(app, update, true).await
}

async fn run_install_pipeline(
    app: &tauri::AppHandle,
    update: Update,
    is_rollback: bool,
) -> Result<InstallUpdateResult, UpdateFailure> {
    let status_downloading = if is_rollback {
        format!(
            "Скачивание подписанного отката v{} (minisign)...",
            update.version
        )
    } else {
        format!(
            "Скачивание подписанного пакета v{} (minisign)...",
            update.version
        )
    };
    let _ = app.emit(
        "updater://status",
        UpdateStatusPayload {
            stage: "downloading".to_string(),
            message: status_downloading,
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
            let _ = crate::sysproxy::cleanup_on_shutdown_once(Some(&app_off), "update");
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
            crate::sysproxy::reset_shutdown_cleanup_guard();
            let snap = snap_restore.lock().ok().and_then(|mut g| g.take());
            restore_protection(snap, pac_url, mode, tz)
        },
    )
    .await?;

    emit_progress(app, 100, 100, 100, "Перезапуск Заставы...");
    let status_installed = if is_rollback {
        "Подписанный откат версии проверен и установлен!"
    } else {
        "Подписанное обновление проверено и установлено!"
    };
    let _ = app.emit(
        "updater://status",
        UpdateStatusPayload {
            stage: "installing".to_string(),
            message: status_installed.to_string(),
        },
    );

    // Windows: `install` hands over to the installer and exits the process, so this is macOS only.
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        app_clone.restart();
    });

    let result_message = if is_rollback {
        format!(
            "Подписанный откат на версию v{} проверен (minisign) и установлен! Застава сейчас перезапустится.",
            update.version
        )
    } else {
        format!(
            "Подписанное обновление v{} проверено (minisign) и установлено! Застава сейчас перезапустится.",
            update.version
        )
    };

    Ok(InstallUpdateResult {
        success: true,
        message: result_message,
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
    fn a_trial_build_updates_to_its_final_release_and_never_the_other_way() {
        // The rc is built from the numeric pre-release 2.1.0-1 (MSI needs a number).
        assert!(is_newer_version("2.1.0-1", "2.1.0"));
        assert!(is_newer_version("v2.1.0-1", "v2.1.0"));
        assert!(is_newer_version("2.1.0-rc.1", "2.1.0"));
        assert!(!is_newer_version("2.1.0", "2.1.0-1"));
        assert!(!is_newer_version("2.1.0-1", "2.1.0-1"));
        // Between pre-releases the identifiers decide, numbers numerically.
        assert!(is_newer_version("2.1.0-1", "2.1.0-2"));
        assert!(is_newer_version("2.1.0-2", "2.1.0-10"));
        assert!(!is_newer_version("2.1.0-10", "2.1.0-2"));
        assert!(is_newer_version("2.1.0-rc.1", "2.1.0-rc.2"));
        assert!(
            is_newer_version("2.1.0-1", "2.1.0-rc.1"),
            "a number sorts before a word"
        );
        // A different numeric core always wins.
        assert!(is_newer_version("2.0.0", "2.1.0-1"));
        assert!(!is_newer_version("2.1.0-1", "2.0.9"));
        assert!(is_newer_version("2.1.0-5", "2.1.1"));
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

    #[test]
    fn test_normalize_semver_and_is_older_version() {
        assert_eq!(normalize_semver("2.1.0").as_deref(), Some("2.1.0"));
        assert_eq!(normalize_semver("v2.1.0").as_deref(), Some("2.1.0"));
        assert_eq!(normalize_semver(" V2.1.0 ").as_deref(), Some("2.1.0"));
        assert_eq!(
            normalize_semver("v2.1.0-rc.1").as_deref(),
            Some("2.1.0-rc.1")
        );

        // Reject malformed or URL-unsafe inputs.
        for bad in [
            "",
            "   ",
            "v",
            "vv2.1.0",
            "2.1",
            "2.1.0.4",
            "01.2.3",
            "2.1.0+build1",
            "2.1.0/../../evil",
            "2.1.0?foo=bar",
            "2.1.0-rc..1",
            "2.1.0-",
            "not-a-version",
        ] {
            assert_eq!(normalize_semver(bad), None, "should reject {bad:?}");
            assert!(!is_older_version("2.2.0", bad));
        }

        assert!(is_older_version("2.2.0", "2.1.2"));
        assert!(is_older_version("2.2.0", "v2.1.0"));
        assert!(is_older_version("2.2.0", "1.3.1"));
        assert!(is_older_version("2.2.0", "2.2.0-rc.1"));
        assert!(!is_older_version("2.2.0", "2.2.0"));
        assert!(!is_older_version("2.2.0", "v2.2.0"));
        assert!(!is_older_version("2.2.0", "2.2.1"));
        assert!(!is_older_version("2.2.0", "3.0.0"));
        assert!(!is_older_version("2.2.0-rc.1", "2.2.0"));
    }

    #[test]
    fn test_parse_rollback_releases_filtering_and_sorting() {
        let payload = serde_json::json!([
            {
                "tag_name": "v2.3.0",
                "name": "Future",
                "draft": false,
                "prerelease": false,
                "published_at": "2026-11-15T00:00:00Z",
                "html_url": "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.3.0",
                "assets": [{ "name": "latest.json" }]
            },
            {
                "tag_name": "v2.2.0",
                "name": "Current",
                "draft": false,
                "prerelease": false,
                "published_at": "2026-11-14T00:00:00Z",
                "assets": [{ "name": "latest.json" }]
            },
            {
                "tag_name": "v2.1.9",
                "name": "Draft Release",
                "draft": true,
                "prerelease": false,
                "assets": [{ "name": "latest.json" }]
            },
            {
                "tag_name": "v2.1.8-rc.1",
                "name": "Prerelease",
                "draft": false,
                "prerelease": true,
                "assets": [{ "name": "latest.json" }]
            },
            {
                "tag_name": "v2.1.7",
                "name": "No Manifest",
                "draft": false,
                "prerelease": false,
                "assets": [{ "name": "Zastava_2.1.7_aarch64.dmg" }]
            },
            {
                "tag_name": "bad-tag",
                "name": "Bad Tag",
                "draft": false,
                "prerelease": false,
                "assets": [{ "name": "latest.json" }]
            },
            {
                "tag_name": "v2.0.0",
                "name": "   ",
                "draft": false,
                "prerelease": false,
                "published_at": "2026-09-01T00:00:00Z",
                "html_url": "https://evil.example.com/phish",
                "assets": [{ "name": "latest.json" }]
            },
            {
                "tag_name": "v2.1.2",
                "name": "Zastava 2.1.2",
                "draft": false,
                "prerelease": false,
                "published_at": "2026-10-10T00:00:00Z",
                "html_url": "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.1.2",
                "assets": [{ "name": "latest.json" }]
            },
            {
                "tag_name": "v2.1.0",
                "name": "Zastava 2.1.0",
                "draft": false,
                "prerelease": false,
                "published_at": "2026-10-01T00:00:00Z",
                "assets": [{ "name": "latest.json" }]
            }
        ])
        .to_string();

        let parsed = parse_rollback_releases(&payload, "2.2.0").unwrap();
        let versions: Vec<&str> = parsed.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(versions, ["2.1.2", "2.1.0", "2.0.0"]);

        assert_eq!(parsed[0].tag, "v2.1.2");
        assert_eq!(parsed[0].name, "Zastava 2.1.2");
        assert_eq!(
            parsed[0].notes_url,
            "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.1.2"
        );

        // Fallback name and sanitized notes_url on untrusted html_url:
        assert_eq!(parsed[2].name, "Zastava v2.0.0");
        assert_eq!(
            parsed[2].notes_url,
            "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.0.0"
        );
    }

    #[test]
    fn test_parse_rollback_releases_caps_at_eight_newest_first() {
        let releases: Vec<serde_json::Value> = (1..=12)
            .map(|patch| {
                serde_json::json!({
                    "tag_name": format!("v1.0.{patch}"),
                    "draft": false,
                    "prerelease": false,
                    "assets": [{ "name": "latest.json" }]
                })
            })
            .collect();
        let payload = serde_json::Value::Array(releases).to_string();
        let parsed = parse_rollback_releases(&payload, "2.2.0").unwrap();
        assert_eq!(parsed.len(), ROLLBACK_MAX_RELEASES);
        let versions: Vec<&str> = parsed.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(
            versions,
            [
                "1.0.12", "1.0.11", "1.0.10", "1.0.9", "1.0.8", "1.0.7", "1.0.6", "1.0.5"
            ]
        );
    }

    #[test]
    fn test_rollback_manifest_url_validation() {
        assert_eq!(rollback_manifest_url(""), Err(UpdateFailure::NoRelease));
        assert_eq!(
            rollback_manifest_url("2.1.0/../../bad"),
            Err(UpdateFailure::NoRelease)
        );
        assert_eq!(
            rollback_manifest_url(CURRENT_VERSION),
            Err(UpdateFailure::NoRelease)
        );
        assert_eq!(
            rollback_manifest_url("99.0.0"),
            Err(UpdateFailure::NoRelease)
        );

        let (ver, url) = rollback_manifest_url("v2.1.0").unwrap();
        assert_eq!(ver, "2.1.0");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("github.com"));
        assert_eq!(
            url.as_str(),
            "https://github.com/kingbest1195/ai-antiban/releases/download/v2.1.0/latest.json"
        );

        let (ver2, url2) = rollback_manifest_url("2.0.0").unwrap();
        assert_eq!(ver2, "2.0.0");
        assert_eq!(
            url2.as_str(),
            "https://github.com/kingbest1195/ai-antiban/releases/download/v2.0.0/latest.json"
        );
    }
}
