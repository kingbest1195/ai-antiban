//! Rate-limited structured diagnostics for `NetworkGuard`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const RATE_LIMIT_TTL: Duration = Duration::from_secs(5);
const MAX_KEYS: usize = 64;

static LAST_LOGGED: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn should_log(key: &str, now: Instant) -> bool {
    let map_lock = LAST_LOGGED.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map_lock.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(prev) = map.get(key)
        && now.saturating_duration_since(*prev) < RATE_LIMIT_TTL
    {
        return false;
    }
    if map.len() >= MAX_KEYS {
        map.retain(|_, ts| now.saturating_duration_since(*ts) < RATE_LIMIT_TTL);
        if map.len() >= MAX_KEYS {
            map.clear();
        }
    }
    map.insert(key.to_string(), now);
    true
}

fn split_fp_parts(fp: &str) -> Option<(&str, &str, &str, &str)> {
    let (udp, rest) = fp.split_once("|dns:")?;
    let (dns, rest) = rest.split_once("|if:")?;
    let (iface, upstream) = rest.split_once("|upstream:")?;
    Some((udp, dns, iface, upstream))
}

pub(super) fn record_fp_change(old_fp: &str, new_fp: &str) {
    let diff = match (split_fp_parts(old_fp), split_fp_parts(new_fp)) {
        (Some((u1, d1, i1, up1)), Some((u2, d2, i2, up2))) => format!(
            "udp={}({}->{}) dns={} iface={} upstream={}",
            if u1 != u2 { "changed" } else { "same" },
            u1,
            u2,
            if d1 != d2 { "changed" } else { "same" },
            if i1 != i2 { "changed" } else { "same" },
            if up1 != up2 { "changed" } else { "same" }
        ),
        _ => "custom_fp_changed".to_string(),
    };
    let key = format!("fp:{diff}");
    if should_log(&key, Instant::now()) {
        crate::diagnostics::record("guard", &format!("route_fp_changed {diff}"));
    }
}

pub(super) fn record_probe_failure(source: &str, err: &str, elapsed_ms: u128, consecutive: u32) {
    // Group by source alone so incrementing `consecutive=1,2,3...` never bypasses RATE_LIMIT_TTL.
    let key = format!("probe:{source}");
    if should_log(&key, Instant::now()) {
        let clean_err = crate::diagnostics::sanitize_diagnostic_text(err);
        crate::diagnostics::record(
            "guard",
            &format!(
                "probe_failure source={source} ms={elapsed_ms} consecutive={consecutive} err={clean_err}"
            ),
        );
    }
}

pub(super) fn record_gate_freeze(reason: &str, providers: &[&str]) {
    let key = format!("freeze:{reason}");
    if should_log(&key, Instant::now()) {
        crate::diagnostics::record(
            "guard",
            &format!(
                "gate_freeze reason={reason} providers={}",
                providers.join(",")
            ),
        );
    }
}

pub(super) fn record_tunnel_abort(reason: &str) {
    let key = format!("abort:{reason}");
    if should_log(&key, Instant::now()) {
        crate::diagnostics::record("guard", &format!("tunnel_abort reason={reason}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_failure_rate_limits_across_consecutive_counts() {
        for c in 1..=6 {
            record_probe_failure("regular_tick_unit_test", "probe_none", 0, c);
        }
        let matches: Vec<String> = crate::diagnostics::dump()
            .into_iter()
            .filter(|l| l.contains("probe_failure source=regular_tick_unit_test"))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected single rate-limited log: {matches:?}"
        );
    }
}
