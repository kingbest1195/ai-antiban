use super::super::EnableReport;
use super::super::journal::{ApplyOutcome, EntryState, Journal, JournalError, Resource, Value};
use super::super::platform::{PacState, Platform, PlatformError};
use super::planner::{MSG_ALL_HEAL_SUSPENDED_PREFIX, plan_physical_pac};
use super::{HealGuard, MSG_ADMIN_AUTH_REQUIRED};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const DIAG_DEDUP_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub(super) struct MacosDiagState {
    key: String,
    recorded_at: Instant,
}

static LAST_MACOS_DIAG_STATE: Mutex<Option<MacosDiagState>> = Mutex::new(None);
static LAST_MACOS_SUMMARY_STATE: Mutex<Option<String>> = Mutex::new(None);
static VPN_BROWSER_PAC_NOTED: AtomicBool = AtomicBool::new(false);

fn record_state_change(
    summary_state: Option<&Mutex<Option<String>>>,
    key: &str,
    msg: Option<&str>,
    record: &mut dyn FnMut(&str, &str),
) {
    let Some(state) = summary_state else {
        return;
    };
    let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
    if guard.as_deref() == Some(key) {
        return;
    }
    *guard = Some(key.to_string());
    drop(guard);
    if let Some(line) = msg {
        record("sysproxy:macos", line);
    }
}

fn should_record_diag(state: &Mutex<Option<MacosDiagState>>, key: &str, now: Instant) -> bool {
    let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(prev) = guard.as_ref()
        && prev.key == key
        && now.saturating_duration_since(prev.recorded_at) < DIAG_DEDUP_TTL
    {
        return false;
    }
    *guard = Some(MacosDiagState {
        key: key.to_string(),
        recorded_at: now,
    });
    true
}

fn clear_diag_state(state: &Mutex<Option<MacosDiagState>>) {
    let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

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
    let browser_pac_policy_active = super::super::state().browser_pac_policy_active();
    apply_pac_with_summary(
        j,
        p,
        pac_url,
        heal,
        &LAST_MACOS_DIAG_STATE,
        Some(&LAST_MACOS_SUMMARY_STATE),
        &VPN_BROWSER_PAC_NOTED,
        browser_pac_policy_active,
        &mut crate::diagnostics::record,
    )
}

#[allow(dead_code)]
pub(super) fn apply_pac_with(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: Option<(&HealGuard, Instant)>,
    diag_state: &Mutex<Option<MacosDiagState>>,
    record: &mut dyn FnMut(&str, &str),
) -> Result<EnableReport, String> {
    let never_noted = AtomicBool::new(false);
    apply_pac_with_options(j, p, pac_url, heal, diag_state, &never_noted, false, record)
}

#[allow(dead_code, clippy::too_many_arguments)]
pub(super) fn apply_pac_with_options(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: Option<(&HealGuard, Instant)>,
    diag_state: &Mutex<Option<MacosDiagState>>,
    vpn_browser_pac_noted: &AtomicBool,
    browser_pac_policy_active: bool,
    record: &mut dyn FnMut(&str, &str),
) -> Result<EnableReport, String> {
    apply_pac_with_summary(
        j,
        p,
        pac_url,
        heal,
        diag_state,
        None,
        vpn_browser_pac_noted,
        browser_pac_policy_active,
        record,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_pac_with_summary(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: Option<(&HealGuard, Instant)>,
    diag_state: &Mutex<Option<MacosDiagState>>,
    summary_state: Option<&Mutex<Option<String>>>,
    vpn_browser_pac_noted: &AtomicBool,
    browser_pac_policy_active: bool,
    record: &mut dyn FnMut(&str, &str),
) -> Result<EnableReport, String> {
    if super::super::os_effects_enabled() {
        super::super::platform::clear_last_os_error();
    }
    let now = heal.map(|(_, t)| t).unwrap_or_else(Instant::now);
    let planned = match plan_physical_pac(p, pac_url, heal, Some(j)) {
        Ok(planned) => planned,
        Err(err) => {
            let msg = if err.starts_with(MSG_ALL_HEAL_SUSPENDED_PREFIX) {
                format!("all physical services suspended by HealGuard: {err}")
            } else {
                format!("pac plan failed: {err}")
            };
            record_state_change(summary_state, &format!("err:{err}"), Some(&msg), record);
            return Err(err);
        }
    };

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
    let mut admin_auth_msgs: Vec<String> = Vec::new();
    let mut fail_msgs: Vec<String> = Vec::new();
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
                if let Some((guard, t)) = heal
                    && was_in_place
                    && o != ApplyOutcome::Unchanged
                    && guard.note_rewrite(&plan.svc.key(), t)
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
                admin_auth_msgs.push(format!(
                    "{} ({}) requires admin auth on {op}",
                    plan.svc.name,
                    pac_res.id()
                ));
                continue;
            }
            Err(e) => {
                failed += 1;
                fail_msgs.push(format!("{} ({}) failed: {e}", plan.svc.name, pac_res.id()));
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
                        admin_auth_msgs.push(format!(
                            "{} ({}) requires admin auth on {op}",
                            plan.svc.name,
                            bypass_res.id()
                        ));
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
                    admin_auth_msgs.push(format!(
                        "{} ({}) requires admin auth on {op}",
                        plan.svc.name,
                        chain_res.id()
                    ));
                }
                Err(e) => eprintln!("Застава: {} не изменён: {e}", chain_res.id()),
            }
        }
    }
    if admin_auth_required {
        let rolled_back = applied_in_pass.len();
        for res in applied_in_pass.into_iter().rev() {
            let _ = j.restore_one(p, &res);
        }
        let key = format!(
            "admin_auth:{}:plans={}:configured={}:failed={failed}:unreadable={}",
            admin_auth_msgs.join(";"),
            planned.plans.len(),
            report.configured.len(),
            planned.unreadable
        );
        if should_record_diag(diag_state, &key, now) {
            for msg in &admin_auth_msgs {
                record("sysproxy:macos", msg);
            }
            record(
                "sysproxy:macos",
                &format!(
                    "apply_pac aborted on admin_auth_required (plans={}, configured={}, failed={failed}, unreadable={}, rolled_back={rolled_back})",
                    planned.plans.len(),
                    report.configured.len(),
                    planned.unreadable
                ),
            );
        }
        record_state_change(summary_state, "admin_auth", None, record);
        return Err(MSG_ADMIN_AUTH_REQUIRED.to_string());
    }
    if report.configured.is_empty() && (failed > 0 || planned.unreadable > 0) {
        let key = format!(
            "all_failed:{}:plans={}:failed={failed}:unreadable={}",
            fail_msgs.join(";"),
            planned.plans.len(),
            planned.unreadable
        );
        if should_record_diag(diag_state, &key, now) {
            for msg in &fail_msgs {
                record("sysproxy:macos", msg);
            }
            record(
                "sysproxy:macos",
                &format!(
                    "apply_pac failed on all services: plans={}, failed={failed}, unreadable={}, admin_auth_required={admin_auth_required}",
                    planned.plans.len(),
                    planned.unreadable
                ),
            );
        }
        record_state_change(summary_state, "all_failed", None, record);
        if super::super::os_effects_enabled()
            && let Some(detail) = super::super::platform::last_os_error()
        {
            return Err(format!(
                "Не удалось включить защиту ни на одной сетевой службе. Детали: {detail}"
            ));
        }
        return Err("Не удалось включить защиту ни на одной сетевой службе.".to_string());
    }
    if !report.skipped_vpn.is_empty()
        && let Ok(eff) = p.effective_proxy()
        && (eff.pac_enabled != Some(true) || eff.pac_url.as_deref() != Some(pac_url))
    {
        if browser_pac_policy_active {
            if !vpn_browser_pac_noted.swap(true, Ordering::SeqCst) {
                record(
                    "sysproxy:macos",
                    &format!(
                        "vpn active ({}) owns primary effective proxy; browser PAC policies active",
                        report.skipped_vpn.join(","),
                    ),
                );
            }
            if !fail_msgs.is_empty() {
                let key = format!("partial_fail:{}", fail_msgs.join(";"));
                if should_record_diag(diag_state, &key, now) {
                    for msg in &fail_msgs {
                        record("sysproxy:macos", msg);
                    }
                }
            } else {
                clear_diag_state(diag_state);
            }
        } else {
            let url_matches = eff.pac_url.as_deref() == Some(pac_url);
            let key = format!(
                "vpn_eff_diff:{}:pac={:?}:url={url_matches}:fails={}",
                report.skipped_vpn.join(","),
                eff.pac_enabled,
                fail_msgs.join(";")
            );
            if should_record_diag(diag_state, &key, now) {
                for msg in &fail_msgs {
                    record("sysproxy:macos", msg);
                }
                record(
                    "sysproxy:macos",
                    &format!(
                        "effective proxy differs while vpn active ({}): pac_enabled={:?}, url_matches={url_matches}",
                        report.skipped_vpn.join(","),
                        eff.pac_enabled,
                    ),
                );
            }
        }
    } else if !fail_msgs.is_empty() {
        let key = format!("partial_fail:{}", fail_msgs.join(";"));
        if should_record_diag(diag_state, &key, now) {
            for msg in &fail_msgs {
                record("sysproxy:macos", msg);
            }
        }
    } else {
        clear_diag_state(diag_state);
    }
    let summary_key = if report.os_pac_deferred {
        let reason = planned.os_pac_defer_reason.as_deref().unwrap_or("unknown");
        format!("deferred:{reason}:vpn={}", report.skipped_vpn.join(","))
    } else {
        format!(
            "active:applied={}:vpn={}:suspended={}:failed={failed}:unreadable={}",
            report.configured.join(","),
            report.skipped_vpn.join(","),
            planned.suspended_services.join(","),
            planned.unreadable
        )
    };
    let summary_msg = if report.os_pac_deferred {
        let reason = planned.os_pac_defer_reason.as_deref().unwrap_or("unknown");
        format!(
            "pac deferred ({reason}): skipped_vpn=[{}]",
            report.skipped_vpn.join(", ")
        )
    } else {
        format!(
            "pac active: applied=[{}], skipped_vpn=[{}], suspended=[{}]",
            report.configured.join(", "),
            report.skipped_vpn.join(", "),
            planned.suspended_services.join(", ")
        )
    };
    record_state_change(summary_state, &summary_key, Some(&summary_msg), record);
    Ok(report)
}
