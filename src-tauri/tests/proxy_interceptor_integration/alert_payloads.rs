use zastava_lib::auditor::ProviderId;
use zastava_lib::proxy::RiskInterceptPayload;
use zastava_lib::proxy::hold_queue::{
    EnrichedPayload, HoldQueue, HoldResolution, NetworkChange, PHASE_FAILED, PHASE_READY,
};

use crate::helpers::{detecting_payload, sample_report};

/// Contract of `interceptor://risk-detected` (window-first, phase "detecting") and of
/// `interceptor://enriched`: the exact JSON shape the alert window is written against.
#[test]
fn test_alert_event_payload_shapes() {
    let detecting = serde_json::to_value(detecting_payload("net-1")).unwrap();
    let mut keys: Vec<&str> = detecting
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "detected_at_ms",
            "host",
            "id",
            "is_simulation",
            "network_change",
            "phase",
            "provider",
            "report",
            "scope",
            "ttl_seconds"
        ]
    );
    assert_eq!(detecting["phase"], "detecting");
    assert!(detecting["report"].is_null());
    assert_eq!(detecting["scope"], "network");
    assert_eq!(detecting["network_change"]["old_ip"], "1.1.1.1");
    assert_eq!(detecting["network_change"]["old_country"], "DE");
    assert_eq!(detecting["network_change"]["new_ip"], "9.9.9.9");
    assert!(detecting["network_change"]["new_country"].is_null());

    // Before the new IP is probed both new_* fields are null, never missing.
    let mut unknown = detecting_payload("net-2");
    unknown.network_change.as_mut().unwrap().new_ip = None;
    let unknown = serde_json::to_value(unknown).unwrap();
    assert!(unknown["network_change"]["new_ip"].is_null());
    assert!(
        unknown["network_change"]
            .as_object()
            .unwrap()
            .contains_key("new_country")
    );

    let enriched = EnrichedPayload {
        id: "net-1".to_string(),
        epoch: 7,
        phase: PHASE_READY.to_string(),
        report: Some(sample_report(ProviderId::Anthropic)),
        network_change: NetworkChange {
            old_ip: Some("1.1.1.1".to_string()),
            old_country: Some("DE".to_string()),
            new_ip: Some("9.9.9.9".to_string()),
            new_country: Some("NL".to_string()),
        },
        gate_reason: None,
    };
    let v = serde_json::to_value(&enriched).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["epoch", "id", "network_change", "phase", "report"]);
    assert_eq!(v["epoch"], 7);
    assert_eq!(v["phase"], "ready");
    assert_eq!(v["report"]["telemetry"]["country_code"], "NL");
    assert_eq!(v["network_change"]["new_country"], "NL");

    // A payload written by an older build (no phase / detected_at_ms / nullable fields) still reads.
    let old: RiskInterceptPayload = serde_json::from_value(serde_json::json!({
        "id": "x", "provider": "anthropic", "host": "h", "ttl_seconds": 60,
        "report": serde_json::to_value(sample_report(ProviderId::Anthropic)).unwrap(),
        "network_change": {"old_ip": null, "old_country": null, "new_ip": "9.9.9.9", "new_country": "NL"}
    }))
    .unwrap();
    assert_eq!(old.phase, "ready");
    assert!(old.report.is_some());
}

/// `take_pending_alert` serves the hold queue's alert snapshot: it carries the minimal payload
/// first, picks up `enriched` data, and is gone once the hold is resolved or removed.
#[tokio::test]
async fn test_pending_alert_snapshot_lifecycle() {
    let queue = HoldQueue::new();
    assert!(queue.current_alert().is_none());

    let _rx = queue.register("net-1".into(), "all").await;
    queue.set_alert(detecting_payload("net-1"));
    let snap = queue.current_alert().expect("alert after set");
    assert_eq!(
        (snap.id.as_str(), snap.phase.as_str()),
        ("net-1", "detecting")
    );
    assert!(snap.report.is_none());
    // Reading does not consume it (the window may ask again after a reload).
    assert!(queue.current_alert().is_some());

    let change = NetworkChange {
        old_ip: Some("1.1.1.1".to_string()),
        old_country: Some("DE".to_string()),
        new_ip: Some("9.9.9.9".to_string()),
        new_country: Some("NL".to_string()),
    };
    // Enriched data of another alert is ignored.
    queue.update_alert(&EnrichedPayload {
        id: "other".to_string(),
        epoch: 1,
        phase: PHASE_FAILED.to_string(),
        report: None,
        network_change: change.clone(),
        gate_reason: None,
    });
    assert_eq!(queue.current_alert().unwrap().phase, "detecting");

    queue.update_alert(&EnrichedPayload {
        id: "net-1".to_string(),
        epoch: 1,
        phase: PHASE_READY.to_string(),
        report: Some(sample_report(ProviderId::Anthropic)),
        network_change: change,
        gate_reason: None,
    });
    let snap = queue.current_alert().unwrap();
    assert_eq!(snap.phase, "ready");
    assert!(snap.report.is_some());
    assert_eq!(
        snap.network_change.unwrap().new_country.as_deref(),
        Some("NL")
    );

    // Resolving the hold clears it; so does removing it.
    assert!(queue.resolve("net-1", HoldResolution::Block).await);
    assert!(queue.current_alert().is_none());
    queue.set_alert(detecting_payload("net-2"));
    let _rx2 = queue.register("net-2".into(), "all").await;
    queue.remove("net-2").await;
    assert!(queue.current_alert().is_none());
}

#[tokio::test]
async fn test_gate_reason_folds_and_serializes_when_present() {
    let queue = HoldQueue::new();
    let _rx = queue.register("net-reason".into(), "all").await;
    let mut initial = detecting_payload("net-reason");
    initial.gate_reason = Some("Detected IP change".to_string());
    queue.set_alert(initial);
    assert_eq!(
        queue.current_alert().unwrap().gate_reason.as_deref(),
        Some("Detected IP change")
    );

    let enriched = EnrichedPayload {
        id: "net-reason".to_string(),
        epoch: 2,
        phase: PHASE_READY.to_string(),
        report: Some(sample_report(ProviderId::Anthropic)),
        network_change: NetworkChange {
            old_ip: Some("1.1.1.1".to_string()),
            old_country: Some("DE".to_string()),
            new_ip: Some("9.9.9.9".to_string()),
            new_country: Some("NL".to_string()),
        },
        gate_reason: Some("High risk route".to_string()),
    };
    queue.update_alert(&enriched);
    let snap = queue.current_alert().unwrap();
    assert_eq!(snap.gate_reason.as_deref(), Some("High risk route"));
    let json = serde_json::to_value(&snap).unwrap();
    assert_eq!(json["gate_reason"], "High risk route");
}
