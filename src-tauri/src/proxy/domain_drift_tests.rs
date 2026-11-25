use super::*;

#[test]
fn observes_companion_patterns_deduplicates_and_caps_at_64() {
    let _lock = DRIFT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_for_test();
    crate::diagnostics::clear_for_test();

    // Matches companion patterns and deduplicates identical hosts (ignoring port/case/trailing dot)
    assert!(observe_direct_host("new-edge.claude.example:443"));
    assert!(!observe_direct_host("NEW-EDGE.CLAUDE.EXAMPLE."));
    assert!(observe_direct_host("future-pa.googleapis.com"));
    assert!(observe_direct_host("cdn.sentry.io"));
    assert!(observe_direct_host("checkout.paddle.com"));
    assert!(observe_direct_host("edge.livekit.cloud"));
    assert!(observe_direct_host("cdn.sora-preview.com"));
    assert!(observe_direct_host("api.codex-agent.dev"));
    assert!(observe_direct_host("new.antigravity-sync.net"));
    assert!(observe_direct_host("telemetry.statsig-edge.com"));
    assert!(observe_direct_host("oai.example.com"));
    assert!(observe_direct_host("edge.oai"));
    assert!(observe_direct_host("cdn.oaistatic-new.com"));
    assert!(observe_direct_host("files.oaiusercontent-new.com"));

    // Benign noise and unrelated domains are never recorded
    for noise in [
        "example.com",
        "github.com",
        "moai.com",
        "oaic.gov.au",
        "www.oaic.gov.au",
        "people-pa.googleapis.com",
        "footprints-pa.googleapis.com",
        "diaspora.org",
        "pinstripe.design",
        "localhost",
        "claude.local",
        "127.0.0.1:443",
    ] {
        assert!(
            !observe_direct_host(noise),
            "noise should not record: {noise}"
        );
    }

    let recorded = recorded_unmapped_companion_domains();
    assert_eq!(recorded.len(), 13);
    assert!(recorded.contains(&"new-edge.claude.example".to_string()));
    assert!(recorded.contains(&"future-pa.googleapis.com".to_string()));

    let diag = crate::diagnostics::dump();
    assert!(
        diag.iter()
            .any(|l| l.contains("[domain:drift] unmapped companion host=new-edge.claude.example"))
    );

    // Fill up to MAX_DRIFT_HOSTS (64) and verify bounded cap
    for i in 0..80 {
        let _ = observe_direct_host(&format!("drift-{i}.openai-edge.example"));
    }
    let capped = recorded_unmapped_companion_domains();
    assert_eq!(capped.len(), MAX_DRIFT_HOSTS);

    clear_for_test();
}
