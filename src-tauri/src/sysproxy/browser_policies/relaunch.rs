//! Graceful browser quit, `Preferences` patching, and relaunch with `--proxy-pac-url`.

use super::{
    PolicyApplyReport, RelaunchSummary,
    chromium::{CHROMIUM_BROWSERS, clean_pac_url},
    prefs::{browser_prefs_files_in, build_browser_proxy_json_string, find_macos_app_bundle_in},
    process::inspect_running_browsers,
    reconcile::{apply_browser_prefs_for_browser, detect_browser_pac_status_in},
};
use crate::sysproxy::{Os, SystemProbe};
use crate::sysproxy::FileCtx;
use crate::sysproxy::journal::Journal;
use crate::sysproxy::platform::Platform;
use crate::sysproxy::relaunch::{AppLauncher, QuitTiming};
use std::time::{Duration, Instant};

fn is_osascript_permission_denied(stderr: &str) -> bool {
    stderr.contains("-1743") || stderr.to_ascii_lowercase().contains("not authorized")
}

/// Default quit wait budget for graceful browser relaunch (~3.5s).
pub const BROWSER_QUIT_TIMEOUT: Duration = Duration::from_millis(3500);
pub const BROWSER_QUIT_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Gracefully quits running Chromium browsers that still need PAC, injects `"proxy"` into all
/// their `Preferences` files (via `Journal`), and relaunches them with `--proxy-pac-url=<pac_url>`.
#[allow(clippy::too_many_arguments)]
pub fn relaunch_browsers_with_pac_with(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    ctx: &FileCtx,
    os: Os,
    probe: &dyn SystemProbe,
    launcher: &dyn AppLauncher,
    timing: QuitTiming,
) -> RelaunchSummary {
    let mut summary = RelaunchSummary::default();
    if os != Os::Macos {
        summary.unsupported = true;
        return summary;
    }
    let Some(url) = clean_pac_url(Some(pac_url)) else {
        return summary;
    };

    let status = detect_browser_pac_status_in(ctx, os, probe, Some(url));
    if status.browsers_needing_restart.is_empty() {
        return summary;
    }

    let desired = build_browser_proxy_json_string(url);

    for browser in &CHROMIUM_BROWSERS {
        if !status
            .browsers_needing_restart
            .iter()
            .any(|name| name == browser.display_name)
        {
            continue;
        }

        let quit_args = vec![
            "-e".to_string(),
            format!("tell application id \"{}\" to quit", browser.id),
        ];
        if let Some(res) = launcher.run("osascript", &quit_args)
            && !res.success
            && is_osascript_permission_denied(&res.stderr)
        {
            summary.needs_automation_permission = true;
            summary.failed.push(browser.display_name.to_string());
            continue;
        }

        let started = Instant::now();
        let mut closed = false;
        loop {
            match inspect_running_browsers(probe, os, Some(url)) {
                Some(map) if !map.get(browser.id).is_some_and(|i| i.running) => {
                    closed = true;
                    break;
                }
                _ => {}
            }
            if started.elapsed() >= timing.timeout {
                break;
            }
            std::thread::sleep(timing.interval);
        }

        if !closed {
            summary.skipped.push(browser.display_name.to_string());
            continue;
        }

        let prefs_files = browser_prefs_files_in(browser, ctx, os);
        let mut pref_report = PolicyApplyReport::default();
        apply_browser_prefs_for_browser(j, p, browser, &prefs_files, &desired, &mut pref_report);
        if pref_report.failed > 0 {
            eprintln!(
                "Застава: частичная ошибка записи Preferences при перезапуске {}",
                browser.display_name
            );
        }

        let mut open_args = if let Some(app_path) = find_macos_app_bundle_in(browser, ctx) {
            let raw = app_path.to_string_lossy().into_owned();
            let posix = if cfg!(windows) {
                raw.replace('\\', "/")
            } else {
                raw
            };
            vec!["-a".to_string(), posix]
        } else {
            vec!["-b".to_string(), browser.id.to_string()]
        };
        open_args.push("--args".to_string());
        open_args.push(format!("--proxy-pac-url={url}"));

        match launcher.run("open", &open_args) {
            Some(res) if res.success => {
                summary.restarted.push(browser.display_name.to_string());
            }
            _ => {
                summary.failed.push(browser.display_name.to_string());
            }
        }
    }

    summary
}
