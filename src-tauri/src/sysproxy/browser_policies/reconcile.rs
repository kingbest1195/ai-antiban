//! PAC enforcement status detection and `Preferences` reconciliation.

use super::{
    BrowserPacStatus, PolicyApplyReport, PolicyStore,
    chromium::{
        CHROMIUM_BROWSERS, ChromiumBrowserDef, WINDOWS_CHROMIUM_POLICY_BROWSERS, clean_pac_url,
        same_pac_url,
    },
    policy_apply::is_pac_policy_active_in,
    prefs::{
        any_chromium_browser_present, browser_prefs_files_in, build_browser_proxy_json_string,
        extract_pac_url_from_proxy_json, is_zastava_local_pac_url, read_browser_proxy_pref,
        write_browser_proxy_pref,
    },
    process::inspect_running_browsers,
    store::RealPolicyStore,
};
use crate::sysproxy::FileCtx;
use crate::sysproxy::fs::Fs;
use crate::sysproxy::journal::{ApplyOutcome, Journal, JournalError, Outcome, Resource, Value};
use crate::sysproxy::platform::{Platform, PlatformError};
use crate::sysproxy::{Os, SystemProbe};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn all_prefs_match_pac(fs: &dyn Fs, prefs_files: &[PathBuf], expected_pac_url: &str) -> bool {
    if prefs_files.is_empty() {
        return false;
    }
    let mut matched = 0usize;
    for path in prefs_files {
        match read_browser_proxy_pref(fs, path) {
            Ok(Some(raw)) => {
                if extract_pac_url_from_proxy_json(&raw)
                    .is_some_and(|u| same_pac_url(&u, expected_pac_url))
                {
                    matched += 1;
                } else {
                    return false;
                }
            }
            Ok(None) | Err(_) => return false,
        }
    }
    matched == prefs_files.len()
}

/// Returns `true` when WinINet's `AutoConfigURL` registry value points to `pac_url`.
pub fn is_wininet_pac_active(platform: &dyn Platform, pac_url: &str) -> bool {
    let Some(expected) = clean_pac_url(Some(pac_url)) else {
        return false;
    };
    matches!(
        platform.get_inet("AutoConfigURL"),
        Ok(Some(val)) if same_pac_url(val.data.trim(), expected)
    )
}

fn detect_windows_browser_pac_status(
    store: &dyn PolicyStore,
    platform: &dyn Platform,
    expected: &str,
) -> BrowserPacStatus {
    let mut status = BrowserPacStatus::default();
    let mut seen = BTreeSet::new();
    for (subkey, display_name) in WINDOWS_CHROMIUM_POLICY_BROWSERS {
        if is_pac_policy_active_in(store, &[subkey], expected) && seen.insert(display_name) {
            status.browsers_pac_active.push(display_name.to_string());
        }
    }
    if status.browsers_pac_active.is_empty() && is_wininet_pac_active(platform, expected) {
        status
            .browsers_pac_active
            .push("Windows Internet Settings (WinINet)".to_string());
    }
    status
}

/// Inspects whether browsers are actively enforcing `pac_url`.
///
/// On Windows, checks `HKCU\Software\Policies\...` (`ProxyMode = "pac_script"` + matching
/// `ProxyPacUrl`) and WinINet `AutoConfigURL` without touching Chromium `User Data` /
/// `Local State` / `Preferences`. On macOS/Linux, checks `Preferences` files and running
/// `--proxy-pac-url=` flags.
pub fn detect_browser_pac_status_with(
    ctx: Option<&FileCtx>,
    os: Os,
    probe: &dyn SystemProbe,
    pac_url: Option<&str>,
    store: &dyn PolicyStore,
    platform: &dyn Platform,
) -> BrowserPacStatus {
    let Some(expected) = clean_pac_url(pac_url) else {
        return BrowserPacStatus::default();
    };
    if os == Os::Windows {
        return detect_windows_browser_pac_status(store, platform, expected);
    }

    let mut status = BrowserPacStatus::default();
    let Some(ctx) = ctx else {
        return status;
    };
    if !any_chromium_browser_present(ctx, os) {
        return status;
    }
    let running_map = inspect_running_browsers(probe, os, Some(expected)).unwrap_or_default();

    for browser in &CHROMIUM_BROWSERS {
        let prefs_files = browser_prefs_files_in(browser, ctx, os);
        let all_prefs_ok = all_prefs_match_pac(&*ctx.fs, &prefs_files, expected);
        let info = running_map.get(browser.id).copied().unwrap_or_default();

        if info.running {
            if info.has_pac_flag || all_prefs_ok {
                status
                    .browsers_pac_active
                    .push(browser.display_name.to_string());
            } else {
                status
                    .browsers_needing_restart
                    .push(browser.display_name.to_string());
            }
        } else if all_prefs_ok {
            status
                .browsers_pac_active
                .push(browser.display_name.to_string());
        }
    }

    status
}

/// Inspects running browsers (`--proxy-pac-url=`) and profile `Preferences` files (or HKCU
/// policies + WinINet on Windows) to classify which Chromium browsers already enforce `pac_url`.
pub fn detect_browser_pac_status_in(
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
    pac_url: Option<&str>,
) -> BrowserPacStatus {
    detect_browser_pac_status_with(
        Some(ctx),
        os,
        probe,
        pac_url,
        &RealPolicyStore,
        &crate::sysproxy::platform::RealPlatform,
    )
}

pub(super) fn apply_browser_prefs_for_browser(
    j: &mut Journal,
    p: &dyn Platform,
    browser: &ChromiumBrowserDef,
    prefs_files: &[PathBuf],
    desired_json: &str,
    report: &mut PolicyApplyReport,
) {
    for path in prefs_files {
        let res = Resource::BrowserPacPref {
            domain: browser.id.to_string(),
            file: path.to_string_lossy().into_owned(),
        };
        let val = Value::Json(Some(desired_json.to_string()));
        match j.apply(p, &res, val) {
            Ok(ApplyOutcome::Applied | ApplyOutcome::Rebased) => report.applied += 1,
            Ok(ApplyOutcome::Unchanged) => report.unchanged += 1,
            Err(JournalError::Platform(PlatformError::DryRun | PlatformError::Unsupported(_))) => {
                report.skipped += 1;
            }
            Err(err) => {
                report.failed += 1;
                eprintln!(
                    "Застава: не удалось применить proxy в {}: {err}",
                    path.display()
                );
            }
        }
    }
}

pub(super) fn apply_browser_prefs_with_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
    report: &mut PolicyApplyReport,
) {
    if os == Os::Windows || !any_chromium_browser_present(ctx, os) {
        return;
    }
    let Some(running_map) = inspect_running_browsers(probe, os, Some(pac_url)) else {
        eprintln!("Застава: список процессов недоступен, Preferences браузеров не изменены");
        return;
    };
    let desired = build_browser_proxy_json_string(pac_url);
    for browser in &CHROMIUM_BROWSERS {
        let prefs_files = browser_prefs_files_in(browser, ctx, os);
        if prefs_files.is_empty() {
            continue;
        }
        if running_map.get(browser.id).is_some_and(|i| i.running) {
            report.skipped += prefs_files.len();
            continue;
        }
        apply_browser_prefs_for_browser(j, p, browser, &prefs_files, &desired, report);
    }
}

/// Fast read-only check whether any non-running browser has a `Preferences` file not yet patched
/// with `pac_url`. Avoids locking the journal during periodic polling when everything is in sync.
pub fn any_non_running_browser_needs_pac_sync_in(
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
    pac_url: &str,
) -> bool {
    if os == Os::Windows {
        return false;
    }
    let Some(expected) = clean_pac_url(Some(pac_url)) else {
        return false;
    };
    if !any_chromium_browser_present(ctx, os) {
        return false;
    }
    let Some(running_map) = inspect_running_browsers(probe, os, Some(expected)) else {
        return false;
    };
    for browser in &CHROMIUM_BROWSERS {
        if running_map.get(browser.id).is_some_and(|i| i.running) {
            continue;
        }
        let prefs_files = browser_prefs_files_in(browser, ctx, os);
        if prefs_files.is_empty() {
            continue;
        }
        for path in prefs_files {
            if let Ok(existing) = read_browser_proxy_pref(&*ctx.fs, &path) {
                let matches = existing
                    .as_deref()
                    .and_then(extract_pac_url_from_proxy_json)
                    .is_some_and(|u| same_pac_url(&u, expected));
                if !matches {
                    return true;
                }
            }
        }
    }
    false
}

/// Reconciles `Preferences` JSON for browsers that have exited since protection was toggled:
/// when `pac_url` is `Some`, injects PAC into newly closed browsers; when `None`, restores any
/// deferred journaled `BrowserPacPref` entries whose browser has exited. Returns `true` if any
/// file changed.
pub fn reconcile_browser_pac_prefs_in(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: Option<&str>,
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
) -> bool {
    if os == Os::Windows {
        return false;
    }
    if let Some(url) = clean_pac_url(pac_url) {
        let mut report = PolicyApplyReport::default();
        apply_browser_prefs_with_pac(j, p, url, ctx, os, probe, &mut report);
        return report.applied > 0;
    }

    let has_prefs = j
        .entries()
        .iter()
        .any(|e| matches!(e.resource, Resource::BrowserPacPref { .. }));
    let mut changed = false;
    if has_prefs && let Some(running_map) = inspect_running_browsers(probe, os, None) {
        let rec = j.restore_where(p, |r| match r {
            Resource::BrowserPacPref { domain, .. } => {
                !running_map.get(domain.as_str()).is_some_and(|i| i.running)
            }
            _ => false,
        });
        if rec
            .items
            .iter()
            .any(|i| matches!(i.outcome, Outcome::Restored))
        {
            changed = true;
        }
    }
    if clear_stale_browser_pac_prefs_in(ctx, os, probe) > 0 {
        changed = true;
    }
    changed
}

/// Removes `"proxy"` from `Preferences` files of non-running browsers ONLY when `proxy.pac_url`
/// points to `http://127.0.0.1:<any>/proxy.pac`. Returns the count of cleaned files.
pub fn clear_stale_browser_pac_prefs_in(ctx: &FileCtx, os: Os, probe: &dyn SystemProbe) -> usize {
    if os == Os::Windows || !any_chromium_browser_present(ctx, os) {
        return 0;
    }
    let Some(running_map) = inspect_running_browsers(probe, os, None) else {
        return 0;
    };
    let mut cleaned = 0usize;
    for browser in &CHROMIUM_BROWSERS {
        if running_map.get(browser.id).is_some_and(|i| i.running) {
            continue;
        }
        for path in browser_prefs_files_in(browser, ctx, os) {
            if let Ok(Some(raw)) = read_browser_proxy_pref(&*ctx.fs, &path)
                && extract_pac_url_from_proxy_json(&raw)
                    .is_some_and(|u| is_zastava_local_pac_url(&u))
                && write_browser_proxy_pref(&*ctx.fs, &path, None).is_ok()
            {
                cleaned += 1;
            }
        }
    }
    cleaned
}
