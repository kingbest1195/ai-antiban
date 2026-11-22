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
        assert!(script.contains("-setautoproxyurl 'Wi-Fi' ''"), "{script}");
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
