use super::super::EnableReport;
use super::super::journal::{ApplyOutcome, EntryState, Journal, JournalError, Resource, Value};
use super::super::platform::{PacState, Platform, PlatformError};
use super::planner::plan_physical_pac;
use super::{HealGuard, MSG_ADMIN_AUTH_REQUIRED};
use std::time::Instant;

pub(super) fn note_changed(outcome: ApplyOutcome, changed: &mut bool) {
    if outcome != ApplyOutcome::Unchanged {
        *changed = true;
    }
}

pub(super) fn apply_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: Option<(&HealGuard, Instant)>,
) -> Result<EnableReport, String> {
    if super::super::os_effects_enabled() {
        super::super::platform::clear_last_os_error();
    }
    let planned = plan_physical_pac(p, pac_url, heal)?;

    // Phase 2: write, service by service; one failure does not stop the others.
    let want = Value::Pac(PacState {
        url: Some(pac_url.to_string()),
        enabled: Some(true),
    });
    let mut report = EnableReport {
        skipped_vpn: planned.vpn_untouched,
        os_pac_deferred: planned.os_pac_deferred,
        ..EnableReport::default()
    };
    let mut failed = 0usize;
    let mut admin_auth_required = planned.chain_admin_auth;
    let mut applied_in_pass: Vec<Resource> = Vec::new();
    for plan in &planned.plans {
        let pac_res = Resource::Pac {
            service: plan.svc.clone(),
        };
        // A service we already had in place that needs a write again was rewritten by somebody.
        let pac_existed = j.entry(&pac_res).is_some();
        let was_in_place = j
            .entry(&pac_res)
            .is_some_and(|e| e.state == EntryState::Applied);
        match j.apply(p, &pac_res, want.clone()) {
            Ok(o) => {
                note_changed(o, &mut report.changed);
                report.configured.push(plan.svc.name.clone());
                if o != ApplyOutcome::Unchanged || !pac_existed {
                    applied_in_pass.push(pac_res.clone());
                }
                if let Some((guard, now)) = heal
                    && was_in_place
                    && o != ApplyOutcome::Unchanged
                    && guard.note_rewrite(&plan.svc.key(), now)
                {
                    // Names only, no values.
                    eprintln!(
                        "Застава: настройки службы «{}» постоянно переписывает другое приложение; самолечение для неё остановлено до смены сети или перезапуска защиты",
                        plan.svc.name
                    );
                }
            }
            Err(JournalError::Platform(PlatformError::AdminAuthRequired(op))) => {
                failed += 1;
                admin_auth_required = true;
                crate::diagnostics::record(
                    "sysproxy:macos",
                    &format!(
                        "{} ({}) requires admin auth on {op}",
                        plan.svc.name,
                        pac_res.id()
                    ),
                );
                continue;
            }
            Err(e) => {
                failed += 1;
                crate::diagnostics::record(
                    "sysproxy:macos",
                    &format!("{} ({}) failed: {e}", plan.svc.name, pac_res.id()),
                );
                continue; // keep the user's explicit proxy while the PAC is not in place
            }
        }
        if let Some(u) = &plan.upstream {
            // The bypass list of this service is recorded before its explicit proxy is touched,
            // so it can be put back exactly. Services without an upstream are not touched at all.
            let bypass_res = Resource::Bypass {
                service: plan.svc.clone(),
            };
            let bypass_existed = j.entry(&bypass_res).is_some();
            match p.get_proxy_bypass_domains(&plan.svc) {
                Ok(list) => match j.apply(p, &bypass_res, Value::Bypass(list)) {
                    Ok(o) => {
                        if o != ApplyOutcome::Unchanged || !bypass_existed {
                            applied_in_pass.push(bypass_res);
                        }
                    }
                    Err(JournalError::Platform(PlatformError::AdminAuthRequired(op))) => {
                        failed += 1;
                        admin_auth_required = true;
                        crate::diagnostics::record(
                            "sysproxy:macos",
                            &format!(
                                "{} ({}) requires admin auth on {op}",
                                plan.svc.name,
                                bypass_res.id()
                            ),
                        );
                    }
                    Err(e) => eprintln!("Застава: {} не записан: {e}", bypass_res.id()),
                },
                Err(_) => eprintln!("Застава: {} не прочитан", bypass_res.id()),
            }
            let chain_res = Resource::Chain {
                service: plan.svc.clone(),
            };
            let chain_existed = j.entry(&chain_res).is_some();
            match j.apply(p, &chain_res, Value::Chain(u.chain_off.clone())) {
                Ok(o) => {
                    note_changed(o, &mut report.changed);
                    if o != ApplyOutcome::Unchanged || !chain_existed {
                        applied_in_pass.push(chain_res);
                    }
                }
                Err(JournalError::Platform(PlatformError::AdminAuthRequired(op))) => {
                    failed += 1;
                    admin_auth_required = true;
                    crate::diagnostics::record(
                        "sysproxy:macos",
                        &format!(
                            "{} ({}) requires admin auth on {op}",
                            plan.svc.name,
                            chain_res.id()
                        ),
                    );
                }
                Err(e) => eprintln!("Застава: {} не изменён: {e}", chain_res.id()),
            }
        }
    }
    if !report.skipped_vpn.is_empty()
        && let Ok(eff) = p.effective_proxy()
        && (eff.pac_enabled != Some(true) || eff.pac_url.as_deref() != Some(pac_url))
    {
        crate::diagnostics::record(
            "sysproxy:macos",
            &format!(
                "effective proxy differs while vpn active ({}): pac_enabled={:?}, url_matches={}",
                report.skipped_vpn.join(","),
                eff.pac_enabled,
                eff.pac_url.as_deref() == Some(pac_url)
            ),
        );
    }
    if admin_auth_required {
        let rolled_back = applied_in_pass.len();
        for res in applied_in_pass.into_iter().rev() {
            let _ = j.restore_one(p, &res);
        }
        crate::diagnostics::record(
            "sysproxy:macos",
            &format!(
                "apply_pac aborted on admin_auth_required (plans={}, configured={}, failed={failed}, unreadable={}, rolled_back={rolled_back})",
                planned.plans.len(),
                report.configured.len(),
                planned.unreadable
            ),
        );
        return Err(MSG_ADMIN_AUTH_REQUIRED.to_string());
    }
    if report.configured.is_empty() && (failed > 0 || planned.unreadable > 0) {
        crate::diagnostics::record(
            "sysproxy:macos",
            &format!(
                "apply_pac failed on all services: plans={}, failed={failed}, unreadable={}, admin_auth_required={admin_auth_required}",
                planned.plans.len(),
                planned.unreadable
            ),
        );
        if super::super::os_effects_enabled()
            && let Some(detail) = super::super::platform::last_os_error()
        {
            return Err(format!(
                "Не удалось включить защиту ни на одной сетевой службе. Детали: {detail}"
            ));
        }
        return Err("Не удалось включить защиту ни на одной сетевой службе.".to_string());
    }
    Ok(report)
}
