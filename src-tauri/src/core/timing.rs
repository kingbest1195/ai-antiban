//! Layer 0 timing log helper (`ZASTAVA_TIMING=1`).

use std::sync::OnceLock;
use std::time::Instant;

/// True when `ZASTAVA_TIMING=1`: the guard logs detect -> emit -> show -> enriched to stderr.
pub fn timing_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("ZASTAVA_TIMING").is_ok_and(|v| v == "1"))
}

/// One stderr line `[zastava-timing] id=<id> <stage> +<ms>ms` (milliseconds since `t0`).
pub fn log_timing(id: &str, stage: &str, t0: Instant) {
    if timing_enabled() {
        eprintln!(
            "[zastava-timing] id={id} {stage} +{:.1}ms",
            t0.elapsed().as_secs_f64() * 1000.0
        );
    }
}
