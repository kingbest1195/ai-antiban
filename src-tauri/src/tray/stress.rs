//! Debug-only tray stress test: hammers tray updates from tokio workers to prove that
//! all TrayIcon/MenuItem work is funnelled to the main thread.
//! Enabled by `--features tray-stress` + env `ZASTAVA_TRAY_STRESS=1` (debug builds only).

use crate::auditor::{self, CheckResult, NetworkTelemetry};
use std::time::Duration;

fn fake_report(status: auditor::OverallStatus) -> auditor::RiskReport {
    let c = || CheckResult::ok("stress", "stress");
    auditor::RiskReport {
        provider: auditor::ProviderId::Anthropic,
        overall_status: status,
        trust_score: 50,
        telemetry: NetworkTelemetry {
            ip: "203.0.113.1".to_string(),
            country_code: "NL".to_string(),
            hostname: None,
            asn: None,
            org: None,
            isp: None,
            timezone: None,
            resolved_at: 0,
        },
        geo_result: c(),
        pinning_result: c(),
        travel_result: c(),
        dnsbl_result: c(),
        dnsbl_clean_count: String::new(),
        asn_result: c(),
        ipv6_result: c(),
        timezone_result: c(),
        checks: vec![],
        unknown_count: 0,
        applicable_count: 13,
        incomplete: false,
    }
}

pub(super) fn maybe_start(app: &tauri::AppHandle) {
    if std::env::var("ZASTAVA_TRAY_STRESS").as_deref() != Ok("1") {
        return;
    }
    eprintln!("[tray-stress] starting 8 tasks");
    for n in 0..8u32 {
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            let mut flip = n % 2 == 0;
            loop {
                super::update_tray_status(&handle, if flip { "green" } else { "red" }, None);
                if n % 2 == 0 {
                    let status = if flip {
                        auditor::OverallStatus::Green
                    } else {
                        auditor::OverallStatus::Yellow
                    };
                    super::update_tray_from_report(&handle, &fake_report(status), flip, !flip);
                }
                flip = !flip;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
    }
}
