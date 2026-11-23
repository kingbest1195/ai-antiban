//! Layer 2 Safe Payment Advisor orchestrator: combines `rules/payment_advisor_matrix.json`,
//! Offline-First signed `BinRadarSnapshot` & `ProvidersManifest`, Per-Service Auto-Demote,
//! and local `BinOverlay` metadata.

use std::path::Path;

use crate::auditor::bin_radar_verify::{load_bin_radar_snapshot, load_providers_manifest};
use crate::bin_checker::{BinOverlay, ClaudeWebVerdict};
use crate::core::bin_radar::{
    AiPaymentService, BinRadarLookupStats, BinRadarSnapshot, lookup_bin_radar_stats,
};
use crate::core::payment_advisor::{
    AdvisorBinContext, AdvisorPlan, AdvisorQuery, build_advisor_plan,
};
use crate::core::providers_manifest::{
    EvaluatedProvidersManifest, ProvidersManifest, evaluate_manifest_auto_demote,
};

pub const DEFAULT_PAYMENT_ADVISOR_MATRIX_JSON: &str =
    include_str!("../../../rules/payment_advisor_matrix.json");

pub fn get_evaluated_providers_manifest_with(
    manifest: &ProvidersManifest,
    snapshot: &BinRadarSnapshot,
) -> EvaluatedProvidersManifest {
    evaluate_manifest_auto_demote(manifest, snapshot)
}

pub fn get_evaluated_providers_manifest(app_data_dir: Option<&Path>) -> EvaluatedProvidersManifest {
    let manifest = load_providers_manifest(app_data_dir);
    let snapshot = load_bin_radar_snapshot(app_data_dir);
    evaluate_manifest_auto_demote(&manifest, &snapshot)
}

pub fn get_bin_radar_stats_for(
    app_data_dir: Option<&Path>,
    bin_prefix: &str,
    service: AiPaymentService,
) -> BinRadarLookupStats {
    let snapshot = load_bin_radar_snapshot(app_data_dir);
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
    let snapshot = load_bin_radar_snapshot(app_data_dir);
    evaluate_advisor_plan_with(query, &manifest, &snapshot, None)
}
