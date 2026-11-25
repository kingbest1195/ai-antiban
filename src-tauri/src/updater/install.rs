//! Signed package download, verification, protection teardown/restore, and installation pipeline.

use super::{
    CURRENT_VERSION, InstallUpdateResult, RestoreOutcome, UPDATER_PUBKEY, UpdateFailure,
    UpdateProgressPayload, UpdateStatusPayload, is_newer_version, is_older_version, map_error,
    normalize_semver, rollback_manifest_url, updater_builder,
};
use std::path::Path;
use std::time::Duration;
use tauri::utils::config::BundleType;
use tauri::{Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterBuilder, UpdaterExt};

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const WINDOWS_NSIS_TARGET: &str = "windows-x86_64-nsis";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const WINDOWS_MSI_TARGET: &str = "windows-x86_64-msi";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const MSI_ROLLBACK_MIN_VERSION: &str = "3.2.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub enum WindowsInstallKind {
    Nsis,
    Msi,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(super) fn is_program_files_dir(dir: &Path) -> bool {
    dir.to_string_lossy().split(['/', '\\']).any(|seg| {
        seg.eq_ignore_ascii_case("program files") || seg.eq_ignore_ascii_case("program files (x86)")
    })
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn classify_windows_install(
    bundle_type: Option<BundleType>,
    install_dir: Option<&Path>,
    has_nsis_uninstaller: bool,
) -> WindowsInstallKind {
    match bundle_type {
        Some(BundleType::Msi) => WindowsInstallKind::Msi,
        Some(BundleType::Nsis) => WindowsInstallKind::Nsis,
        _ if has_nsis_uninstaller => WindowsInstallKind::Nsis,
        _ if install_dir.is_some_and(is_program_files_dir) => WindowsInstallKind::Msi,
        _ => WindowsInstallKind::Nsis,
    }
}

#[cfg(target_os = "windows")]
fn detect_windows_install_kind() -> WindowsInstallKind {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let has_uninstaller = exe_dir.as_deref().is_some_and(|dir| {
        dir.join("uninstall.exe").is_file() || dir.join("Uninstall.exe").is_file()
    });
    classify_windows_install(
        tauri::utils::platform::bundle_type(),
        exe_dir.as_deref(),
        has_uninstaller,
    )
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn windows_rollback_target(kind: WindowsInstallKind) -> &'static str {
    match kind {
        WindowsInstallKind::Nsis => WINDOWS_NSIS_TARGET,
        WindowsInstallKind::Msi => WINDOWS_MSI_TARGET,
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn validate_windows_rollback_compatibility(
    kind: WindowsInstallKind,
    target_version: &str,
) -> Result<(), UpdateFailure> {
    if kind == WindowsInstallKind::Msi && is_older_version(MSI_ROLLBACK_MIN_VERSION, target_version)
    {
        let clean = normalize_semver(target_version).unwrap_or_else(|| target_version.to_string());
        return Err(UpdateFailure::Install(format!(
            "Встроенный откат с MSI-установки на версию v{clean} (ниже v{MSI_ROLLBACK_MIN_VERSION}) не поддерживается Windows Installer. Защита не отключалась. Скачайте NSIS-установщик (*_x64-setup.exe) или нужный релиз вручную со страницы релизов на GitHub."
        )));
    }
    Ok(())
}

/// Download, verify, then install. Order is the safety contract of this module:
///
/// 1. `update.download` fetches the package and verifies the minisign signature (the plugin
///    calls its own "download finished" callback BEFORE verifying, so it is not used here).
/// 2. Only if that succeeded `protection_off` runs (system proxy is switched off).
/// 3. Only then `install` runs.
/// 4. If `install` fails, `protection_restore` runs once, so the still-running app is not left
///    without protection that was on before the update started.
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

/// Configures a rollback [`UpdaterBuilder`] with `.no_proxy()`, pinned pubkey, version
/// comparator, and (on Windows) an explicit NSIS/MSI target override.
pub fn configure_rollback_builder<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    manifest_url: url::Url,
    target_version: String,
    windows_kind: Option<WindowsInstallKind>,
) -> Result<UpdaterBuilder, UpdateFailure> {
    let mut builder = app
        .updater_builder()
        .no_proxy()
        .pubkey(UPDATER_PUBKEY)
        .endpoints(vec![manifest_url])
        .map_err(|e| map_error(&e))?
        .version_comparator(move |_current, release| {
            let rel_ver = release.version.to_string();
            rel_ver == target_version && is_older_version(CURRENT_VERSION, &rel_ver)
        });
    if let Some(kind) = windows_kind {
        builder = builder.target(windows_rollback_target(kind));
    }
    Ok(builder)
}

/// Builds a rollback [`UpdaterBuilder`] pinned to [`UPDATER_PUBKEY`] and the exact target version.
pub fn rollback_updater_builder<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    manifest_url: url::Url,
    target_version: String,
) -> Result<UpdaterBuilder, UpdateFailure> {
    #[cfg(target_os = "windows")]
    let windows_kind = Some(detect_windows_install_kind());
    #[cfg(not(target_os = "windows"))]
    let windows_kind = None;
    configure_rollback_builder(app, manifest_url, target_version, windows_kind)
}

/// Downloads, verifies (minisign), and installs a signed older release for rollback.
pub async fn install_rollback_version(
    app: &tauri::AppHandle,
    version: &str,
) -> Result<InstallUpdateResult, UpdateFailure> {
    let (target_version, manifest_url) = rollback_manifest_url(version)?;
    #[cfg(target_os = "windows")]
    validate_windows_rollback_compatibility(detect_windows_install_kind(), &target_version)?;
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
    #[cfg(target_os = "windows")]
    if is_rollback {
        validate_windows_rollback_compatibility(detect_windows_install_kind(), &update.version)?;
    }
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
            crate::os_tz::reset_exit_restore_guard();
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
