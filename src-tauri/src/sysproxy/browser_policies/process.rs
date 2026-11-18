//! Process inspection for running Chromium-family browsers (`ps` / `tasklist`).

use super::RunningBrowserInfo;
use super::chromium::{CHROMIUM_BROWSERS, clean_pac_url, same_pac_url};
use crate::sysproxy::{Os, SystemProbe};
use std::collections::BTreeMap;
use std::path::Path;

fn extract_proxy_pac_url_arg(line: &str) -> Option<&str> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find("--proxy-pac-url=")?;
    let after = &line[idx + "--proxy-pac-url=".len()..];
    if let Some(quoted) = after.strip_prefix('"') {
        quoted.split('"').next()
    } else if let Some(quoted) = after.strip_prefix('\'') {
        quoted.split('\'').next()
    } else {
        after.split_whitespace().next()
    }
}

fn linux_exe_basename(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let cmd = if let Some(idx) = trimmed.find(" --") {
        trimmed[..idx].trim()
    } else {
        trimmed.split_whitespace().next().unwrap_or("")
    };
    Path::new(cmd)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
}

fn parse_tasklist_csv_image(line: &str) -> Option<String> {
    let first = line.trim().split(',').next()?;
    let unquoted = first.trim().trim_matches('"').trim().to_ascii_lowercase();
    (!unquoted.is_empty()).then_some(unquoted)
}

/// Inspects running OS processes via `probe` and returns a map keyed by [`ChromiumBrowserDef::id`].
/// Returns `None` when the process listing command itself failed.
pub fn inspect_running_browsers(
    probe: &dyn SystemProbe,
    os: Os,
    expected_pac_url: Option<&str>,
) -> Option<BTreeMap<&'static str, RunningBrowserInfo>> {
    let expected = clean_pac_url(expected_pac_url);
    let mut map = BTreeMap::<&'static str, RunningBrowserInfo>::new();

    match os {
        Os::Macos => {
            let listing = probe.run("ps", &["-axo", "args="])?;
            for line in listing.lines() {
                let lower = line.trim().to_ascii_lowercase();
                if lower.is_empty() {
                    continue;
                }
                for browser in CHROMIUM_BROWSERS {
                    let matched = browser.macos_bundles.iter().any(|bundle| {
                        let needle = format!("/{}/contents/", bundle.to_ascii_lowercase());
                        lower.contains(&needle)
                    });
                    if matched {
                        let entry = map.entry(browser.id).or_default();
                        entry.running = true;
                        if let Some(exp) = expected
                            && extract_proxy_pac_url_arg(line).is_some_and(|u| same_pac_url(u, exp))
                        {
                            entry.has_pac_flag = true;
                        }
                    }
                }
            }
        }
        Os::Linux => {
            let listing = probe.run("ps", &["-axo", "args="])?;
            for line in listing.lines() {
                let Some(exe) = linux_exe_basename(line) else {
                    continue;
                };
                for browser in CHROMIUM_BROWSERS {
                    if browser.process_names.iter().any(|p| *p == exe) {
                        let entry = map.entry(browser.id).or_default();
                        entry.running = true;
                        if let Some(exp) = expected
                            && extract_proxy_pac_url_arg(line).is_some_and(|u| same_pac_url(u, exp))
                        {
                            entry.has_pac_flag = true;
                        }
                    }
                }
            }
        }
        Os::Windows => {
            let listing = probe.run("tasklist", &["/FO", "CSV", "/NH"])?;
            for line in listing.lines() {
                let Some(image) = parse_tasklist_csv_image(line) else {
                    continue;
                };
                for browser in CHROMIUM_BROWSERS {
                    if browser.process_names.iter().any(|p| *p == image) {
                        let entry = map.entry(browser.id).or_default();
                        entry.running = true;
                    }
                }
            }
        }
    }

    Some(map)
}
