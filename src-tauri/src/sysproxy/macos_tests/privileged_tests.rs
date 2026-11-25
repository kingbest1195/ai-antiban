use super::*;
#[cfg(target_os = "macos")]
use crate::sysproxy::platform::{Platform, RealPlatform};

#[test]
fn privileged_disable_batches_pac_and_chain_and_preserves_journal_on_cancel() {
    let (fs, p) = setup();
    let upstream = ChainState {
        http: ep(true, "127.0.0.1", 10808),
        https: ProxyEndpoint::default(),
        socks: ProxyEndpoint::default(),
    };
    p.seed_chain(&wifi(), upstream);
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();

    let targets = vec![
        Resource::Pac { service: wifi() },
        Resource::Chain { service: wifi() },
    ];

    // Cancelled osascript keeps journal records intact for next startup recovery.
    let denied = disable_pac_privileged_with(&mut j, &p, &targets, |_| {
        Err(JournalError::Platform(PlatformError::AdminAuthRequired(
            "osascript",
        )))
    });
    assert!(
        denied
            .iter()
            .all(|item| item.outcome == Outcome::Failed("admin_auth"))
    );
    assert!(!j.is_empty());

    // Single successful osascript restores both PAC and Chain in one batch and releases journal.
    let mut exec_count = 0usize;
    let restored = disable_pac_privileged_with(&mut j, &p, &targets, |script| {
        exec_count += 1;
        assert!(
            script.contains("-setautoproxystate 'Wi-Fi' off"),
            "{script}"
        );
        assert!(!script.contains("-setautoproxyurl 'Wi-Fi' ''"), "{script}");
        assert!(script.contains("-setwebproxystate 'Wi-Fi' on"), "{script}");
        Ok(())
    });
    assert_eq!(exec_count, 1);
    assert_eq!(restored.len(), 2);
    assert!(
        restored
            .iter()
            .all(|item| item.outcome == Outcome::Restored)
    );
    assert!(j.entry(&Resource::Pac { service: wifi() }).is_none());
    assert!(j.entry(&Resource::Chain { service: wifi() }).is_none());
}

#[cfg(target_os = "macos")]
#[test]
fn real_platform_set_pac_and_set_chain_stay_isolated_in_dry_run_tests() {
    let before = crate::sysproxy::dry_run_blocked_calls();
    RealPlatform
        .set_pac(&wifi(), &pac(None, Some(false)))
        .unwrap();
    RealPlatform
        .set_chain(&wifi(), &ChainState::default())
        .unwrap();
    assert!(crate::sysproxy::dry_run_blocked_calls() >= before + 2);
}

#[test]
fn privileged_script_clears_pac_via_state_off_without_empty_url() {
    let (_fs, p) = setup();
    let script = build_privileged_networksetup_script(
        &p,
        &[(
            Resource::Pac { service: wifi() },
            Value::Pac(PacState {
                url: Some(String::new()),
                enabled: None,
            }),
        )],
    )
    .unwrap();
    assert!(
        script.contains("-setautoproxystate 'Wi-Fi' off"),
        "{script}"
    );
    assert!(!script.contains("-setautoproxyurl"), "{script}");
}

#[test]
fn heal_guard_post_retain_empty_surfaces_error_and_records_state_change_diagnostics() {
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    let (fs, p) = setup();
    let mut j = open(&fs);
    let guard = HealGuard::new();
    let diag_state = Mutex::new(None);
    let summary_state = Mutex::new(None);
    let noted = AtomicBool::new(false);
    let mut logs: Vec<String> = Vec::new();
    let t0 = Instant::now();

    let run = |p: &FakePlatform,
               j: &mut Journal,
               t: Instant,
               logs: &mut Vec<String>|
     -> Result<EnableReport, String> {
        super::super::apply::apply_pac_with_summary(
            j,
            p,
            PAC,
            Some((&guard, t)),
            &diag_state,
            Some(&summary_state),
            &noted,
            false,
            &mut |comp, msg| logs.push(format!("[{comp}] {msg}")),
        )
    };

    // 1. Initial apply logs state once; steady-state repeat logs nothing.
    run(&p, &mut j, t0, &mut logs).unwrap();
    run(&p, &mut j, t0 + Duration::from_secs(5), &mut logs).unwrap();
    assert_eq!(
        logs.len(),
        1,
        "expected deduplicated active state: {logs:?}"
    );
    assert!(logs[0].contains("applied=[Wi-Fi]"));

    // 2. Temp DNS defer logs state transition once, then deduplicates.
    p.set_temp_dns(true);
    let rep_def = run(&p, &mut j, t0 + Duration::from_secs(10), &mut logs).unwrap();
    assert!(rep_def.os_pac_deferred);
    run(&p, &mut j, t0 + Duration::from_secs(15), &mut logs).unwrap();
    assert_eq!(logs.len(), 2, "expected single deferred log: {logs:?}");
    assert!(logs[1].contains("pac deferred"));

    // 3. Clearing temp DNS logs transition back to active.
    p.set_temp_dns(false);
    run(&p, &mut j, t0 + Duration::from_secs(20), &mut logs).unwrap();
    assert_eq!(logs.len(), 3, "{logs:?}");

    // 4. Exhaust HealGuard on sole physical service -> post-retain empty returns Err + diagnostic.
    for step in 1..=HEAL_MAX_REWRITES as u64 {
        p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
        run(&p, &mut j, t0 + Duration::from_secs(20 + step), &mut logs).unwrap();
    }
    let err = run(&p, &mut j, t0 + Duration::from_secs(30), &mut logs).unwrap_err();
    assert!(
        err.contains("приостановлена") && err.contains("Wi-Fi"),
        "{err}"
    );
    let err2 = run(&p, &mut j, t0 + Duration::from_secs(35), &mut logs).unwrap_err();
    assert_eq!(err, err2);
    assert_eq!(
        logs.iter()
            .filter(|l| l.contains("all physical services suspended by HealGuard"))
            .count(),
        1,
        "suspended state should be logged once until state changes: {logs:?}"
    );
}
