use super::quarantine::{
    POST_PAYMENT_QUARANTINE_SECS, QuarantineActivationInput, activate_quarantine_at,
    get_quarantine_status_at, override_quarantine_at,
};
use crate::state::{AppState, AppStateData, CleanProfileStatus, CleanRoomProfile};

fn make_profile(id: &str) -> CleanRoomProfile {
    CleanRoomProfile {
        id: id.to_string(),
        label: "Test Profile".to_string(),
        provider: "anthropic".to_string(),
        browser_engine: "chrome".to_string(),
        bound_route_id: Some("route-de".to_string()),
        last_exit_ip: Some("185.10.20.30".to_string()),
        last_exit_country: Some("DE".to_string()),
        status: CleanProfileStatus::Ready,
        created_at: 1_700_000_000,
        last_opened_at: None,
        warmup_started_at: Some(1_700_000_000),
        launchpad_step: 4,
        completed_checklist: vec![],
        post_payment_quarantine: None,
    }
}

#[tokio::test]
async fn quarantine_72h_persists_across_disk_restart_and_supports_override() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");

    let mut initial = AppStateData::default();
    initial.clean_room.profiles.push(make_profile("cr-pay1"));
    initial.clean_room.active_profile_id = Some("cr-pay1".to_string());
    AppState::save_data_to_file(&initial, &state_path).unwrap();

    let state = AppState::load_or_default(state_path.clone());
    let t0 = 1_760_000_000u64;
    let status = activate_quarantine_at(
        &state,
        QuarantineActivationInput {
            profile_id: Some("cr-pay1".to_string()),
            route_id: None,
            exit_ip: None,
            exit_asn: Some(24940),
            exit_country: None,
        },
        t0,
    )
    .await
    .unwrap();

    assert!(status.active);
    assert_eq!(status.remaining_hours, 72);
    assert_eq!(status.remaining_secs, POST_PAYMENT_QUARANTINE_SECS);
    let warn = status.warning.as_deref().expect("quarantine warning");
    assert!(warn.contains("Защита маршрута после оплаты: осталось 72 ч"));
    assert_no_banned_jargon(warn);
    let q = status.quarantine.unwrap();
    assert_eq!(q.expires_at, t0 + POST_PAYMENT_QUARANTINE_SECS);
    assert_eq!(q.pinned_route_id.as_deref(), Some("route-de"));
    assert_eq!(q.pinned_exit_ip.as_deref(), Some("185.10.20.30"));
    assert_eq!(q.pinned_asn, Some(24940));
    assert_eq!(q.pinned_country.as_deref(), Some("DE"));

    // Simulate app restart by reloading AppState from disk.
    let reloaded = AppState::load_or_default(state_path.clone());
    let mid = get_quarantine_status_at(&reloaded, Some("cr-pay1"), t0 + 36 * 3600)
        .await
        .unwrap();
    assert!(mid.active);
    assert_eq!(mid.remaining_hours, 36);

    // After 72h, quarantine expires automatically.
    let expired = get_quarantine_status_at(&reloaded, Some("cr-pay1"), t0 + 72 * 3600)
        .await
        .unwrap();
    assert!(!expired.active);
    assert_eq!(expired.remaining_hours, 0);

    // Explicit override deactivates quarantine and persists to disk.
    let overridden = override_quarantine_at(
        &reloaded,
        Some("cr-pay1"),
        Some("user_confirmed"),
        t0 + 1000,
    )
    .await
    .unwrap();
    assert!(!overridden.active);
    assert_eq!(
        overridden.quarantine.unwrap().overridden_at,
        Some(t0 + 1000)
    );

    let reloaded2 = AppState::load_or_default(state_path);
    let after_restart_override = get_quarantine_status_at(&reloaded2, Some("cr-pay1"), t0 + 2000)
        .await
        .unwrap();
    assert!(!after_restart_override.active);
}

fn assert_no_banned_jargon(text: &str) {
    let lower = text.to_lowercase();
    for term in [
        "payshield",
        "stripe",
        "bin-рентген",
        "fail-closed",
        "fallbackunknown",
        "persona",
        "kyc",
        "apple iap",
        "directcard",
        "биллинг",
        "чекаут",
        "split-ip",
        "is_pinned",
        "tainted",
        "webrtc",
        "stun",
        "пост-платёжный карантин",
        "vc.ru",
        "coworkvmservice",
    ] {
        assert!(!lower.contains(term), "banned term '{term}' in: {text}");
    }
    for word in text.split(|c: char| !c.is_alphanumeric() && c != '_') {
        assert!(
            !word.eq_ignore_ascii_case("bin") && !word.eq_ignore_ascii_case("asn"),
            "banned standalone acronym '{word}' in: {text}"
        );
    }
}
