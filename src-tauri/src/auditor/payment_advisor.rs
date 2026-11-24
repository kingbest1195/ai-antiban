//! Layer 2 Safe Payment Advisor orchestrator: combines `rules/payment_advisor_matrix.json`,
//! Offline-First signed `BinRadarSnapshot` & `ProvidersManifest`, Per-Service Auto-Demote,
//! and local `BinOverlay` metadata.

use std::collections::HashMap;
use std::path::Path;

use crate::auditor::bin_radar_verify::{
    LocalBinRadarReportRecord, load_bin_radar_snapshot, load_local_bin_radar_reports,
    load_providers_manifest,
};
use crate::auditor::network::current_timestamp;
use crate::bin_checker::{BinOverlay, ClaudeWebVerdict};
use crate::core::bin_radar::{
    AiPaymentService, BinRadarEntry, BinRadarLookupStats, BinRadarSnapshot, TimestampedOutcome,
    WINDOW_14D_DAYS, WINDOW_14D_HALF_LIFE_DAYS, WINDOW_30D_DAYS, WINDOW_30D_HALF_LIFE_DAYS,
    lookup_bin_radar_stats, merge_window_stats,
};
use crate::core::payment_advisor::{
    AdvisorBinContext, AdvisorPlan, AdvisorQuery, build_advisor_plan,
};
use crate::core::providers_manifest::{
    EvaluatedProvidersManifest, ProvidersManifest, evaluate_manifest_auto_demote,
};

pub const DEFAULT_PAYMENT_ADVISOR_MATRIX_JSON: &str =
    include_str!("../../../rules/payment_advisor_matrix.json");

fn resolve_overlay_target_bin(
    entries: &[BinRadarEntry],
    bin_prefix: &str,
    service: AiPaymentService,
) -> String {
    if entries
        .iter()
        .any(|e| e.service == service && e.bin_prefix == bin_prefix)
    {
        return bin_prefix.to_string();
    }
    let six = &bin_prefix[..6];
    if let Some(range_entry) = entries.iter().find(|e| {
        e.service == service && e.bin_prefix.starts_with(six) && e.bin_prefix.ends_with("00")
    }) {
        return range_entry.bin_prefix.clone();
    }
    bin_prefix.to_string()
}

/// Merges local opt-in reports into a snapshot with exponential time decay and all statistical floors preserved.
pub fn merge_local_bin_radar_reports_at(
    snapshot: &BinRadarSnapshot,
    local_reports: &[LocalBinRadarReportRecord],
    current_day: u64,
) -> BinRadarSnapshot {
    if local_reports.is_empty() {
        return snapshot.clone();
    }

    let mut grouped: HashMap<(String, AiPaymentService), Vec<TimestampedOutcome>> = HashMap::new();
    for rec in local_reports {
        if rec.report.validate().is_err() {
            continue;
        }
        let target_bin = resolve_overlay_target_bin(
            &snapshot.entries,
            &rec.report.bin_prefix,
            rec.report.service,
        );
        let age_days = current_day.saturating_sub(rec.reported_day) as f64;
        grouped
            .entry((target_bin, rec.report.service))
            .or_default()
            .push(TimestampedOutcome {
                age_days,
                outcome: rec.report.outcome,
                weight_multiplier: 1.0,
            });
    }

    if grouped.is_empty() {
        return snapshot.clone();
    }

    let mut merged = snapshot.clone();
    for entry in &mut merged.entries {
        if let Some(samples) = grouped.remove(&(entry.bin_prefix.clone(), entry.service)) {
            entry.window_14d = merge_window_stats(
                Some(&entry.window_14d),
                &samples,
                WINDOW_14D_DAYS,
                WINDOW_14D_HALF_LIFE_DAYS,
            );
            entry.window_30d = merge_window_stats(
                Some(&entry.window_30d),
                &samples,
                WINDOW_30D_DAYS,
                WINDOW_30D_HALF_LIFE_DAYS,
            );
        }
    }

    let mut remaining: Vec<_> = grouped.into_iter().collect();
    remaining
        .sort_by(|a, b| (a.0.0.as_str(), a.0.1.as_str()).cmp(&(b.0.0.as_str(), b.0.1.as_str())));
    for ((bin_prefix, service), samples) in remaining {
        merged.entries.push(BinRadarEntry {
            bin_prefix,
            service,
            window_14d: merge_window_stats(
                None,
                &samples,
                WINDOW_14D_DAYS,
                WINDOW_14D_HALF_LIFE_DAYS,
            ),
            window_30d: merge_window_stats(
                None,
                &samples,
                WINDOW_30D_DAYS,
                WINDOW_30D_HALF_LIFE_DAYS,
            ),
        });
    }

    merged
}

pub fn load_effective_bin_radar_snapshot(app_data_dir: Option<&Path>) -> BinRadarSnapshot {
    let snapshot = load_bin_radar_snapshot(app_data_dir);
    let Some(dir) = app_data_dir else {
        return snapshot;
    };
    let local_reports = load_local_bin_radar_reports(dir);
    let current_day = current_timestamp() / 86_400;
    merge_local_bin_radar_reports_at(&snapshot, &local_reports, current_day)
}

pub fn get_evaluated_providers_manifest_with(
    manifest: &ProvidersManifest,
    snapshot: &BinRadarSnapshot,
) -> EvaluatedProvidersManifest {
    evaluate_manifest_auto_demote(manifest, snapshot)
}

pub fn get_evaluated_providers_manifest(app_data_dir: Option<&Path>) -> EvaluatedProvidersManifest {
    let manifest = load_providers_manifest(app_data_dir);
    let snapshot = load_effective_bin_radar_snapshot(app_data_dir);
    evaluate_manifest_auto_demote(&manifest, &snapshot)
}

pub fn get_bin_radar_stats_for(
    app_data_dir: Option<&Path>,
    bin_prefix: &str,
    service: AiPaymentService,
) -> BinRadarLookupStats {
    let snapshot = load_effective_bin_radar_snapshot(app_data_dir);
    lookup_bin_radar_stats(&snapshot, bin_prefix, service)
}

pub fn resolve_bin_context_from_overlay(bin_prefix: &str) -> Option<AdvisorBinContext> {
    let overlay = BinOverlay::load_bundled().ok()?;
    let matched = overlay.lookup(bin_prefix)?;
    let r = matched.report;
    let combined = format!(
        "{} {}",
        r.known_fintech_label.as_deref().unwrap_or(""),
        r.issuer_name.as_deref().unwrap_or("")
    )
    .to_ascii_uppercase();
    let is_toxic = matched.high_kyc_risk
        || r.claude_web_verdict == ClaudeWebVerdict::HighKycRisk
        || r.claude_web_verdict == ClaudeWebVerdict::Blocked
        || combined.contains("NIUM")
        || combined.contains("WAYMENT")
        || combined.contains("ANTARCTIC")
        || combined.contains("ALTYN")
        || combined.contains("REDOTPAY");

    Some(AdvisorBinContext {
        bin_prefix: r.bin_prefix,
        country_code: r.country_code,
        is_prepaid: r.is_prepaid.unwrap_or(false),
        is_commercial: r.is_commercial.unwrap_or(false),
        is_sanctioned_or_blocked: r.claude_web_verdict == ClaudeWebVerdict::Blocked,
        is_toxic_sg_or_fintech: is_toxic,
        fintech_label: r.known_fintech_label.or(r.issuer_name),
    })
}

pub fn evaluate_advisor_plan_with(
    query: &AdvisorQuery,
    manifest: &ProvidersManifest,
    snapshot: &BinRadarSnapshot,
    bin_override: Option<&AdvisorBinContext>,
) -> AdvisorPlan {
    let evaluated = evaluate_manifest_auto_demote(manifest, snapshot);
    let overlay_ctx = bin_override.cloned().or_else(|| {
        query
            .available_bin_prefix
            .as_deref()
            .and_then(resolve_bin_context_from_overlay)
    });
    build_advisor_plan(query, &evaluated.providers, snapshot, overlay_ctx.as_ref())
}

pub fn evaluate_advisor_plan(query: &AdvisorQuery, app_data_dir: Option<&Path>) -> AdvisorPlan {
    let manifest = load_providers_manifest(app_data_dir);
    let snapshot = load_effective_bin_radar_snapshot(app_data_dir);
    evaluate_advisor_plan_with(query, &manifest, &snapshot, None)
}
