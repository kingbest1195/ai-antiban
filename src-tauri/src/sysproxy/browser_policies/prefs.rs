//! Chromium profile `Preferences` JSON proxy read/write and profile path discovery.

use super::PROXY_MODE_PAC_SCRIPT;
use super::chromium::{CHROMIUM_BROWSERS, ChromiumBrowserDef, same_pac_url};
use crate::sysproxy::Os;
use crate::sysproxy::FileCtx;
use crate::sysproxy::fs::{Fs, WriteMode};
use crate::sysproxy::platform::{PResult, PlatformError};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Builds the compact JSON string for Chromium's profile `Preferences` `"proxy"` object.
pub fn build_browser_proxy_json_string(pac_url: &str) -> String {
    serde_json::json!({
        "mode": PROXY_MODE_PAC_SCRIPT,
        "pac_url": pac_url,
        "pac_mandatory": false
    })
    .to_string()
}

/// Extracts `pac_url` from a serialized `"proxy"` JSON object when `mode == "pac_script"`.
pub fn extract_pac_url_from_proxy_json(raw_json: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(raw_json).ok()?;
    let obj = val.as_object()?;
    let mode = obj.get("mode")?.as_str()?;
    if !mode.trim().eq_ignore_ascii_case(PROXY_MODE_PAC_SCRIPT) {
        return None;
    }
    obj.get("pac_url")?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Compares two serialized `"proxy"` JSON values structurally (normalizing `pac_url`).
pub fn same_browser_proxy_json(a: &str, b: &str) -> bool {
    let Ok(va) = serde_json::from_str::<serde_json::Value>(a) else {
        return false;
    };
    let Ok(vb) = serde_json::from_str::<serde_json::Value>(b) else {
        return false;
    };
    if let (Some(oa), Some(ob)) = (va.as_object(), vb.as_object()) {
        let mode_a = oa
            .get("mode")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase());
        let mode_b = ob
            .get("mode")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase());
        if mode_a.as_deref() == Some(PROXY_MODE_PAC_SCRIPT)
            && mode_b.as_deref() == Some(PROXY_MODE_PAC_SCRIPT)
        {
            let url_ok = match (
                oa.get("pac_url").and_then(|v| v.as_str()),
                ob.get("pac_url").and_then(|v| v.as_str()),
            ) {
                (Some(ua), Some(ub)) => same_pac_url(ua, ub),
                _ => false,
            };
            let mandatory_a = oa
                .get("pac_mandatory")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mandatory_b = ob
                .get("pac_mandatory")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            return url_ok && mandatory_a == mandatory_b && oa.len() == ob.len();
        }
    }
    va == vb
}

/// Returns `true` iff `url` points to `http://127.0.0.1:<port>/proxy.pac` (any non-zero port).
pub fn is_zastava_local_pac_url(url: &str) -> bool {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("http://127.0.0.1:") else {
        return false;
    };
    let Some((port_str, tail)) = rest.split_once('/') else {
        return false;
    };
    let Ok(port) = port_str.parse::<u16>() else {
        return false;
    };
    if port == 0 {
        return false;
    }
    let path_only = tail.split('?').next().unwrap_or("");
    path_only.trim_end_matches('/') == "proxy.pac"
}

/// Reads the serialized `"proxy"` key from a Chromium `Preferences` JSON file.
/// Returns `Ok(None)` when the file or key does not exist, and logs + errors on invalid JSON.
pub fn read_browser_proxy_pref(fs: &dyn Fs, path: &Path) -> PResult<Option<String>> {
    let bytes = match fs.read(path) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(None),
        Err(_) => return Err(PlatformError::Failed("prefs_read")),
    };
    let root: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "Застава: некорректный JSON в {}, пропуск: {err}",
                path.display()
            );
            return Err(PlatformError::Failed("prefs_invalid_json"));
        }
    };
    let Some(obj) = root.as_object() else {
        eprintln!(
            "Застава: корень {} не является JSON-объектом, пропуск",
            path.display()
        );
        return Err(PlatformError::Failed("prefs_invalid_json"));
    };
    match obj.get("proxy") {
        Some(val) => serde_json::to_string(val)
            .map(Some)
            .map_err(|_| PlatformError::Failed("prefs_serialize")),
        None => Ok(None),
    }
}

/// Atomically updates or removes the `"proxy"` key in a Chromium `Preferences` JSON file
/// while preserving all other JSON keys. Refuses to overwrite non-JSON or missing files.
pub fn write_browser_proxy_pref(fs: &dyn Fs, path: &Path, proxy_json: Option<&str>) -> PResult<()> {
    let bytes = match fs.read(path) {
        Ok(Some(b)) => b,
        Ok(None) => return Err(PlatformError::Failed("prefs_missing")),
        Err(_) => return Err(PlatformError::Failed("prefs_read")),
    };
    let mut root: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "Застава: некорректный JSON в {}, запись отменена: {err}",
                path.display()
            );
            return Err(PlatformError::Failed("prefs_invalid_json"));
        }
    };
    let Some(obj) = root.as_object_mut() else {
        eprintln!(
            "Застава: корень {} не является JSON-объектом, запись отменена",
            path.display()
        );
        return Err(PlatformError::Failed("prefs_invalid_json"));
    };
    match proxy_json {
        Some(raw) => {
            let val: serde_json::Value =
                serde_json::from_str(raw).map_err(|_| PlatformError::Failed("prefs_proxy_json"))?;
            obj.insert("proxy".to_string(), val);
        }
        None => {
            obj.remove("proxy");
        }
    }
    let out = serde_json::to_vec(&root).map_err(|_| PlatformError::Failed("prefs_serialize"))?;
    fs.write_atomic(path, &out, WriteMode::KeepExisting)
        .map_err(|_| PlatformError::Failed("prefs_write"))
}

/// Returns existing User Data directories for `browser` under `ctx` for `os`.
///
/// On Windows, intentionally returns an empty list so Zastava never enumerates Chromium
/// `User Data` / `Profile *` directories or reads `Local State` / `Preferences` (avoids
/// BroPass AV heuristics; Windows enforcement uses `HKCU\Software\Policies\...` and WinINet
/// `AutoConfigURL` instead).
pub fn browser_user_data_dirs(browser: &ChromiumBrowserDef, ctx: &FileCtx, os: Os) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    match os {
        Os::Macos => {
            let base = ctx.home.join("Library").join("Application Support");
            for rel in browser.macos_user_data_rels {
                candidates.push(base.join(rel));
            }
        }
        Os::Windows => return Vec::new(),
        Os::Linux => {
            let base = ctx.home.join(".config");
            for rel in browser.linux_config_rels {
                candidates.push(base.join(rel));
            }
        }
    }
    candidates
        .into_iter()
        .filter(|dir| {
            ctx.fs.exists(dir)
                || ctx.fs.exists(&dir.join("Preferences"))
                || !ctx.fs.list_dir(dir).is_empty()
        })
        .collect()
}

/// Discovers all profile `Preferences` files inside one Chromium User Data directory
/// (direct `Preferences`, `Default`, `Profile *`, `Guest Profile`, `System Profile`, and any
/// profile key listed in `Local State`'s `profile.info_cache`).
///
/// Compiled out on Windows non-test builds so `Local State` / `Profile *` scanning strings are
/// absent from Windows release binaries.
pub fn discover_browser_prefs_files_in(fs: &dyn Fs, user_data_dir: &Path) -> Vec<PathBuf> {
    #[cfg(all(target_os = "windows", not(test)))]
    {
        let _ = (fs, user_data_dir);
        Vec::new()
    }
    #[cfg(any(not(target_os = "windows"), test))]
    {
        let mut found = BTreeSet::new();
        let direct = user_data_dir.join("Preferences");
        if fs.exists(&direct) {
            found.insert(direct);
        }

        for child in fs.list_dir(user_data_dir) {
            let Some(name) = child.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let is_profile_dir = name == "Default"
                || name == "Guest Profile"
                || name == "System Profile"
                || name.starts_with("Profile ");
            if is_profile_dir {
                let prefs = child.join("Preferences");
                if fs.exists(&prefs) {
                    found.insert(prefs);
                }
            }
        }

        // Also inspect Chromium's `Local State` -> `profile.info_cache` for non-standard profile folders.
        let local_state = user_data_dir.join("Local State");
        if let Ok(Some(bytes)) = fs.read(&local_state)
            && let Ok(root) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Some(cache) = root
                .get("profile")
                .and_then(|p| p.get("info_cache"))
                .and_then(|c| c.as_object())
        {
            for key in cache.keys() {
                let prefs = user_data_dir.join(key).join("Preferences");
                if fs.exists(&prefs) {
                    found.insert(prefs);
                }
            }
        }

        found.into_iter().collect()
    }
}

/// Discovers all `Preferences` files for `browser` across all existing User Data dirs.
pub fn browser_prefs_files_in(browser: &ChromiumBrowserDef, ctx: &FileCtx, os: Os) -> Vec<PathBuf> {
    if os == Os::Windows {
        return Vec::new();
    }
    let mut found = BTreeSet::new();
    for dir in browser_user_data_dirs(browser, ctx, os) {
        for prefs in discover_browser_prefs_files_in(&*ctx.fs, &dir) {
            found.insert(prefs);
        }
    }
    found.into_iter().collect()
}

/// Finds the `.app` bundle path on macOS (`/Applications` or `~/Applications`) via `ctx.fs`.
pub fn find_macos_app_bundle_in(browser: &ChromiumBrowserDef, ctx: &FileCtx) -> Option<PathBuf> {
    for app_name in browser.macos_bundles {
        // Build the POSIX `/Applications/<app>` path directly so simulated `Os::Macos` calls on
        // Windows do not insert a `\` separator via `PathBuf::join`.
        let sys_app = PathBuf::from(format!("/Applications/{app_name}"));
        if ctx.fs.exists(&sys_app) {
            return Some(sys_app);
        }
        let user_app = ctx.home.join("Applications").join(app_name);
        if ctx.fs.exists(&user_app) {
            return Some(user_app);
        }
    }
    None
}

pub(super) fn any_chromium_browser_present(ctx: &FileCtx, os: Os) -> bool {
    if os == Os::Windows {
        return false;
    }
    CHROMIUM_BROWSERS.iter().any(|b| {
        !browser_user_data_dirs(b, ctx, os).is_empty()
            || (os == Os::Macos && find_macos_app_bundle_in(b, ctx).is_some())
    })
}
