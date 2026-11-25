//! Non-blocking runtime detector for unmapped AI/payment companion domains
//! observed on the direct pass-through path.

use std::net::IpAddr;
use std::sync::Mutex;

pub const MAX_DRIFT_HOSTS: usize = 64;

const BENIGN_PA_GOOGLEAPIS: &[&str] = &[
    "people-pa.googleapis.com",
    "footprints-pa.googleapis.com",
    "reminders-pa.googleapis.com",
    "tasks-pa.googleapis.com",
    "calendar-pa.googleapis.com",
    "contacts-pa.googleapis.com",
    "photos-pa.googleapis.com",
    "play-pa.googleapis.com",
    "notifications-pa.googleapis.com",
    "safebrowsing-pa.googleapis.com",
    "android-pa.googleapis.com",
    "maps-pa.googleapis.com",
    "gmail-pa.googleapis.com",
    "drive-pa.googleapis.com",
    "docs-pa.googleapis.com",
    "chrome-pa.googleapis.com",
    "cryptauth-pa.googleapis.com",
    "instantmessaging-pa.googleapis.com",
    "firebaseremoteconfig-pa.googleapis.com",
    "oauthaccountmanager-pa.googleapis.com",
];

const COMPANION_SUBSTRINGS: &[&str] = &[
    "claude",
    "anthropic",
    "openai",
    "chatgpt",
    "oaistatic",
    "oaiusercontent",
    "sora",
    "codex",
    "cloudcode",
    "aicode",
    "antigravity",
    "makersuite",
    "statsig",
    "intercom",
    "stripe",
    "arkoselabs",
];

const COMPANION_SUFFIXES: &[&str] = &[
    "-pa.googleapis.com",
    "sentry.io",
    "paddle.com",
    "livekit.cloud",
];

const BENIGN_NOISE_SUBSTRINGS: &[&str] = &["diaspora", "pinstripe", "broadstripe"];

static DRIFT_HOSTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn normalize_host(raw_host: &str) -> String {
    let without_port = if let Some(bracketed) = raw_host.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or(raw_host)
    } else {
        raw_host.split(':').next().unwrap_or(raw_host)
    };
    without_port
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn matches_suffix_domain(host: &str, suffix: &str) -> bool {
    if let Some(stem) = suffix.strip_prefix('-') {
        host.ends_with(suffix) && host.len() > suffix.len() && !stem.is_empty()
    } else {
        host == suffix
            || (host.len() > suffix.len()
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
    }
}

fn is_benign_noise(host: &str) -> bool {
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.ends_with(".internal")
        || host.ends_with(".arpa")
        || host.parse::<IpAddr>().is_ok()
    {
        return true;
    }
    if BENIGN_PA_GOOGLEAPIS.contains(&host) {
        return true;
    }
    if BENIGN_NOISE_SUBSTRINGS.iter().any(|n| host.contains(n)) {
        return true;
    }
    false
}

/// Returns `true` when `raw_host` looks like an unmapped AI/payment companion host.
pub fn is_companion_drift_candidate(raw_host: &str) -> bool {
    let host = normalize_host(raw_host);
    if is_benign_noise(&host) {
        return false;
    }
    let has_oai_label = host
        .split('.')
        .any(|lbl| lbl == "oai" || lbl.starts_with("oai-"));
    has_oai_label
        || COMPANION_SUBSTRINGS.iter().any(|p| host.contains(p))
        || COMPANION_SUFFIXES
            .iter()
            .any(|s| matches_suffix_domain(&host, s))
}

/// Observes a host on the direct pass-through path without ever blocking or delaying the connection.
/// Deduplicates within a bounded session set (`MAX_DRIFT_HOSTS = 64`) and logs once to `diagnostics`.
pub fn observe_direct_host(raw_host: &str) -> bool {
    let host = normalize_host(raw_host);
    if !is_companion_drift_candidate(&host) {
        return false;
    }
    let inserted = {
        let mut set = DRIFT_HOSTS.lock().unwrap_or_else(|e| e.into_inner());
        if set.len() >= MAX_DRIFT_HOSTS || set.iter().any(|h| h == &host) {
            false
        } else {
            set.push(host.clone());
            true
        }
    };
    if inserted {
        crate::diagnostics::record("domain:drift", &format!("unmapped companion host={host}"));
    }
    inserted
}

/// Returns the deduplicated list of unmapped companion domains observed in this session.
pub fn recorded_unmapped_companion_domains() -> Vec<String> {
    DRIFT_HOSTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[cfg(any(test, feature = "test-support"))]
pub fn clear_for_test() {
    DRIFT_HOSTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

#[cfg(any(test, feature = "test-support"))]
pub static DRIFT_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
#[path = "domain_drift_tests.rs"]
mod tests;
