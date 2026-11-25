use super::*;

#[test]
fn dns_diag_dedup_suppresses_repeats_for_300s_and_allows_on_change_or_recovery() {
    let cache = Mutex::new(HashMap::new());
    let t0 = Instant::now();
    let host = "o-o.myaddr.l.google.com";
    let sig_a = nameserver_signature(&["10.8.0.1".parse().unwrap()]);
    let sig_b = nameserver_signature(&["1.1.1.1".parse().unwrap()]);

    assert!(should_record_dns_diag_in(
        &cache,
        "scutil",
        host,
        &TxtOutcome::Failed,
        &sig_a,
        t0,
    ));
    // Same (stage, host, outcome, nameserver_sig) within 300s is suppressed.
    assert!(!should_record_dns_diag_in(
        &cache,
        "scutil",
        host,
        &TxtOutcome::Failed,
        &sig_a,
        t0 + Duration::from_secs(60),
    ));
    assert!(!should_record_dns_diag_in(
        &cache,
        "scutil",
        host,
        &TxtOutcome::Failed,
        &sig_a,
        t0 + Duration::from_secs(299),
    ));
    // Different stage ("system") records once independently, then deduplicates.
    assert!(should_record_dns_diag_in(
        &cache,
        "system",
        host,
        &TxtOutcome::Failed,
        &sig_a,
        t0 + Duration::from_secs(1),
    ));
    assert!(!should_record_dns_diag_in(
        &cache,
        "system",
        host,
        &TxtOutcome::Failed,
        &sig_a,
        t0 + Duration::from_secs(200),
    ));
    // Nameserver change logs immediately even within 300s.
    assert!(should_record_dns_diag_in(
        &cache,
        "scutil",
        host,
        &TxtOutcome::Failed,
        &sig_b,
        t0 + Duration::from_secs(20),
    ));
    // Different outcome logs immediately.
    assert!(should_record_dns_diag_in(
        &cache,
        "scutil",
        host,
        &TxtOutcome::Timeout,
        &sig_a,
        t0 + Duration::from_secs(25),
    ));
    // Recovery clears host entries so a subsequent failure logs immediately.
    clear_dns_diag_for_host(&cache, host);
    assert!(should_record_dns_diag_in(
        &cache,
        "scutil",
        host,
        &TxtOutcome::Failed,
        &sig_a,
        t0 + Duration::from_secs(30),
    ));
    // After 300s TTL expires, identical failure logs again.
    assert!(should_record_dns_diag_in(
        &cache,
        "scutil",
        host,
        &TxtOutcome::Failed,
        &sig_a,
        t0 + Duration::from_secs(330),
    ));
}
