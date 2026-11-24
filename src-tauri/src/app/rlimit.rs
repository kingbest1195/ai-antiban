//! Raises the soft `RLIMIT_NOFILE` on Unix/macOS at startup so concurrent proxy sockets and
//! child `networksetup` invocations never fail with `EMFILE` (`os error 24`).

/// Desired minimum soft file-descriptor limit on Unix/macOS (`.app` bundles inherit `256`).
#[cfg(unix)]
pub const TARGET_NOFILE_LIMIT: u64 = 8192;

/// Raises the soft `RLIMIT_NOFILE` up to `min(rlim_max, TARGET_NOFILE_LIMIT)` on Unix.
/// Returns `Some((effective_cur, rlim_max))` on Unix, or `None` on non-Unix / `getrlimit` error.
#[cfg(unix)]
pub fn raise_nofile_limit() -> Option<(u64, u64)> {
    // SAFETY: `getrlimit` and `setrlimit` operate on a stack-allocated `libc::rlimit`.
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            let err = std::io::Error::last_os_error();
            crate::diagnostics::record("startup:rlimit", &format!("getrlimit failed: {err}"));
            return None;
        }
        #[allow(clippy::unnecessary_cast)]
        let cur_val = rl.rlim_cur as u64;
        #[allow(clippy::unnecessary_cast)]
        let max_val = rl.rlim_max as u64;
        let target = TARGET_NOFILE_LIMIT.min(max_val);
        if cur_val >= target {
            return Some((cur_val, max_val));
        }
        // macOS `rlim_max` can be `RLIM_INFINITY` while `OPEN_MAX` caps `setrlimit`; fall back to
        // 4096 if 8192 is rejected by the kernel.
        for candidate in [target, 4096u64.min(target)] {
            if candidate <= cur_val {
                continue;
            }
            let next = libc::rlimit {
                rlim_cur: candidate as libc::rlim_t,
                rlim_max: rl.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &next) == 0 {
                crate::diagnostics::record(
                    "startup:rlimit",
                    &format!("RLIMIT_NOFILE raised from {cur_val} to {candidate} (max={max_val})"),
                );
                return Some((candidate, max_val));
            }
        }
        let err = std::io::Error::last_os_error();
        crate::diagnostics::record(
            "startup:rlimit",
            &format!("setrlimit(RLIMIT_NOFILE) failed from {cur_val} (max={max_val}): {err}"),
        );
        eprintln!("Застава: не удалось поднять RLIMIT_NOFILE с {cur_val}: {err}");
        Some((cur_val, max_val))
    }
}

#[cfg(not(unix))]
pub fn raise_nofile_limit() -> Option<(u64, u64)> {
    None
}
