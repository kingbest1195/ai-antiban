//! Bounded in-memory diagnostic ring buffer and sanitized diagnostic report/bundle builders.
//!
//! Records never store proxy URLs with credentials, passwords, or full home paths: callers pass
//! only operation names, service identifiers, exit codes, and short OS error lines.

pub mod bundle;
pub mod ipconfig;
pub mod preview;

pub use bundle::{
    DiagnosticBundle, DiagnosticCheckSummary, DiagnosticGatewayStats, DiagnosticProviderAudit,
    DiagnosticProviderRoute, build_error_diagnostics_report, build_sanitized_diagnostic_bundle,
    extract_os_version_from_snapshot, mask_ip_address, sanitize_diagnostic_text,
};
pub use ipconfig::{collect_unproxied_os_network_snapshot, parse_windows_ipconfig_snapshot};
pub use preview::{ProtectionChangePreviewItem, build_protection_changes_preview};

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

const MAX_ENTRIES: usize = 120;
const MAX_LINE_LEN: usize = 420;

static STARTED_AT: OnceLock<Instant> = OnceLock::new();
static RING: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

fn uptime_secs() -> u64 {
    STARTED_AT.get_or_init(Instant::now).elapsed().as_secs()
}

fn sanitize_single_line(raw: &str) -> String {
    let collapsed = raw
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .filter(|c| !c.is_control())
        .collect::<String>();
    let trimmed = collapsed.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.chars().count() > MAX_LINE_LEN {
        let mut out: String = trimmed.chars().take(MAX_LINE_LEN - 3).collect();
        out.push_str("...");
        out
    } else {
        trimmed
    }
}

/// Appends one sanitized entry to the ring buffer and mirrors it to `stderr`.
pub fn record(component: &str, message: &str) {
    let clean = sanitize_single_line(message);
    if clean.is_empty() {
        return;
    }
    let secs = uptime_secs();
    let line = format!("[+{secs}s] [{component}] {clean}");
    eprintln!("Застава diag {line}");
    let mut ring = RING.lock().unwrap_or_else(|e| e.into_inner());
    if ring.len() >= MAX_ENTRIES {
        ring.pop_front();
    }
    ring.push_back(line);
}

/// Returns a chronological snapshot of recent diagnostic lines.
pub fn dump() -> Vec<String> {
    let ring = RING.lock().unwrap_or_else(|e| e.into_inner());
    ring.iter().cloned().collect()
}

#[cfg(test)]
pub(crate) fn clear_for_test() {
    let mut ring = RING.lock().unwrap_or_else(|e| e.into_inner());
    ring.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_sanitizes_multiline_and_caps_buffer() {
        clear_for_test();
        for i in 0..(MAX_ENTRIES + 15) {
            record("test", &format!("line\n\t#{i}\r"));
        }
        let entries = dump();
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert!(entries.first().unwrap().contains("line #15"));
        assert!(
            entries
                .last()
                .unwrap()
                .contains(&format!("line #{}", MAX_ENTRIES + 14))
        );
        assert!(!entries.last().unwrap().contains('\n'));
    }
}
