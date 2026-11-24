//! Internal resolution and kill-switch helpers for interception commands.

use crate::{auditor, proxy, state};

pub(crate) struct ResolveInterceptionOutcome {
    pub(crate) applied: bool,
    pub(crate) open_guide: bool,
    pub(crate) pause_status: Option<proxy::guard::GuardPauseStatus>,
}

impl ResolveInterceptionOutcome {
    pub(super) fn noop() -> Self {
        Self {
            applied: false,
            open_guide: false,
            pause_status: None,
        }
    }
}

pub(super) struct ResolveInterceptionParams<'a> {
    pub(super) id: &'a str,
    pub(super) action: proxy::InterceptionAction,
    pub(super) provider: &'a str,
    pub(super) scope: Option<&'a str>,
    pub(super) persist_exception: bool,
    pub(super) proxy_manager: &'a proxy::ProxyManager,
    pub(super) state: &'a state::AppState,
    pub(super) auditor: &'a auditor::Auditor,
}

async fn resolve_provider_telemetry_for_allow(
    id: &str,
    provider: &str,
    state: &state::AppState,
    auditor: &auditor::Auditor,
    proxy_manager: &proxy::ProxyManager,
) -> (Option<auditor::NetworkTelemetry>, Option<String>) {
    let alert_tel = proxy_manager
        .hold_queue
        .current_alert()
        .filter(|a| a.id == id)
        .and_then(|a| a.report.map(|r| r.telemetry));

    let pid_opt = auditor::ProviderId::from_id(provider);
    let data = state.get_data().await;
    let selection = pid_opt
        .map(|p| crate::routing::select_route(&data, p.as_str()))
        .unwrap_or(crate::routing::RouteSelection::Direct);
    let is_direct = matches!(selection, crate::routing::RouteSelection::Direct);

    let resolved_tel = if let Some(tel) = alert_tel {
        Some(tel)
    } else if let Some(pid) = pid_opt {
        auditor.resolve_for_provider(pid, state, false).await.ok()
    } else {
        None
    };

    if let Some(ref tel) = resolved_tel {
        if let Some(pid) = pid_opt {
            let entry = state::IpHistoryEntry::new(
                tel.ip.clone(),
                tel.country_code.clone(),
                tel.asn,
                tel.resolved_at,
            );
            let _ = state
                .record_ip_history_for_selection(pid.as_str(), &selection, entry)
                .await;
        }
        let ip = Some(tel.ip.clone());
        let direct_tel = is_direct.then(|| tel.clone());
        return (direct_tel, ip);
    }

    (None, None)
}

async fn expand_risky_block_targets(
    base_targets: &[String],
    state: &state::AppState,
    auditor: &auditor::Auditor,
    proxy_manager: &proxy::ProxyManager,
) -> Vec<String> {
    let st = state.get_data().await;
    let mut out: Vec<String> = base_targets.to_vec();
    let cur_ip = proxy_manager.guard.current_observed_ip().await;
    for p in st.enabled_unrouted_providers() {
        if out.iter().any(|t| t == p) || st.blocked_providers.contains(p) {
            continue;
        }
        if cur_ip
            .as_deref()
            .is_some_and(|ip| st.is_ip_trusted_for_provider(p, ip))
            || st.session_allowed_providers.contains(p)
        {
            continue;
        }
        let is_risky = match auditor::ProviderId::from_id(p) {
            Some(pid) => match auditor.evaluate_all(pid, state, false).await {
                Ok(r) => !proxy::guard::report_allowed_for_state(&r, &st, false),
                Err(_) => true,
            },
            None => true,
        };
        if is_risky {
            out.push(p.to_string());
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
async fn claim_and_block_targets_if_active(
    id: &str,
    targets: &[String],
    is_network_scope: bool,
    network_alert_active: bool,
    epoch_before: u64,
    quiet_sync: bool,
    proxy_manager: &proxy::ProxyManager,
    state: &state::AppState,
) -> Result<bool, proxy::AllowError> {
    let network_alert_stale =
        is_network_scope && proxy_manager.guard.is_env_installed() && !network_alert_active;
    if network_alert_stale || proxy_manager.guard.restore_epoch() != epoch_before {
        return Ok(false);
    }
    let was_active = proxy_manager
        .hold_queue
        .resolve(id, proxy::HoldResolution::Block)
        .await;
    if !was_active || proxy_manager.guard.restore_epoch() != epoch_before {
        return Ok(false);
    }
    for p in targets {
        state.block_provider(p).await.map_err(|e| e.to_string())?;
    }
    if proxy_manager.guard.restore_epoch() != epoch_before {
        if !proxy_manager.guard.is_manual_killswitch() {
            for p in targets {
                let _ = state.unblock_provider(p).await;
            }
        }
        proxy_manager.guard.sync_gates_with_state(state).await;
        return Ok(false);
    }
    if quiet_sync {
        proxy_manager.guard.sync_gates_with_state_quiet(state).await;
    } else {
        proxy_manager.guard.sync_gates_with_state(state).await;
    }
    Ok(true)
}

pub(super) async fn resolve_interception_with_params(
    params: ResolveInterceptionParams<'_>,
) -> Result<ResolveInterceptionOutcome, proxy::AllowError> {
    let ResolveInterceptionParams {
        id,
        action,
        provider,
        scope,
        persist_exception,
        proxy_manager,
        state,
        auditor,
    } = params;
    let epoch_before = proxy_manager.guard.restore_epoch();
    // `all` or scope "network" = network-wide hold created by the network guard after a sudden IP change
    let is_network_scope = scope == Some("network") || provider == proxy::ALL_PROVIDERS;
    let network_targets = if is_network_scope {
        proxy_manager.guard.affected_providers_for_alert(id).await
    } else {
        None
    };
    let network_alert_active = network_targets.is_some();
    let targets: Vec<String> = if is_network_scope {
        match network_targets {
            Some(list) if !list.is_empty() => list,
            _ => state
                .enabled_unrouted_providers()
                .await
                .into_iter()
                .map(|p| p.to_string())
                .collect(),
        }
    } else {
        let canonical = auditor::ProviderId::from_id(provider)
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| provider.to_string());
        vec![canonical]
    };

    let mut open_guide = false;
    let mut pause_status = None;

    match action {
        proxy::InterceptionAction::AllowSession => {
            if is_network_scope {
                // Network-wide allow: only for the alert that is still current and fully audited
                // (checked and applied by the guard under its lock). Persists trusted_exceptions
                // ONLY when `persist_exception == true`, opening ONLY `targets`.
                proxy_manager
                    .guard
                    .allow_network_alert_with(id, &targets, persist_exception)
                    .await?;
            } else {
                if proxy_manager.guard.is_manual_killswitch() {
                    return Err(proxy::AllowError::new(
                        proxy::AllowErrorCode::BlockedByManualKillswitch,
                        "manual kill-switch is engaged",
                    ));
                }
                for p in &targets {
                    let (tel_opt, ip_opt) =
                        resolve_provider_telemetry_for_allow(id, p, state, auditor, proxy_manager)
                            .await;
                    state
                        .allow_provider_for_session(p)
                        .await
                        .map_err(|e| e.to_string())?;
                    state.unblock_provider(p).await.map_err(|e| e.to_string())?;
                    if persist_exception
                        && let Some(ip) = ip_opt
                        && !ip.trim().is_empty()
                    {
                        state
                            .add_trusted_exception(p, &ip)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    proxy_manager
                        .hold_queue
                        .resolve(id, proxy::HoldResolution::Allow)
                        .await;
                    proxy_manager
                        .guard
                        .confirm_provider_session(p, tel_opt.as_ref())
                        .await;
                }
            }
            // Provider holds only: an allow never reaches the network-wide `all` hold.
            for p in targets.iter().map(String::as_str) {
                proxy_manager
                    .hold_queue
                    .resolve_all_for_provider(p, proxy::HoldResolution::Allow)
                    .await;
            }
        }
        proxy::InterceptionAction::BlockUntilNetworkChange => {
            let pause_reason = proxy_manager.guard.gate_reason().or_else(|| {
                proxy_manager
                    .hold_queue
                    .current_alert()
                    .and_then(|alert| alert.gate_reason)
            });
            let block_targets = if is_network_scope {
                targets.clone()
            } else {
                expand_risky_block_targets(&targets, state, auditor, proxy_manager).await
            };
            if !claim_and_block_targets_if_active(
                id,
                &block_targets,
                is_network_scope,
                network_alert_active,
                epoch_before,
                true,
                proxy_manager,
                state,
            )
            .await?
            {
                return Ok(ResolveInterceptionOutcome::noop());
            }
            if !block_targets.is_empty() && !proxy_manager.guard.is_manual_killswitch() {
                proxy_manager
                    .guard
                    .mark_paused_until_network_change(pause_reason)
                    .await;
                if !proxy_manager.guard.is_env_installed() {
                    proxy_manager.guard.sync_gates_with_state_quiet(state).await;
                }
                pause_status = Some(proxy_manager.guard.pause_status());
            } else {
                proxy_manager.guard.sync_gates_with_state(state).await;
            }
            for p in block_targets
                .iter()
                .map(String::as_str)
                .chain([proxy::ALL_PROVIDERS])
            {
                proxy_manager
                    .hold_queue
                    .resolve_all_for_provider(p, proxy::HoldResolution::Block)
                    .await;
            }
        }
        proxy::InterceptionAction::OpenGuideAndBlock => {
            if !claim_and_block_targets_if_active(
                id,
                &targets,
                is_network_scope,
                network_alert_active,
                epoch_before,
                false,
                proxy_manager,
                state,
            )
            .await?
            {
                return Ok(ResolveInterceptionOutcome::noop());
            }
            for p in targets
                .iter()
                .map(String::as_str)
                .chain([proxy::ALL_PROVIDERS])
            {
                proxy_manager
                    .hold_queue
                    .resolve_all_for_provider(p, proxy::HoldResolution::Block)
                    .await;
            }
            open_guide = true;
        }
    }

    Ok(ResolveInterceptionOutcome {
        applied: true,
        open_guide,
        pause_status,
    })
}

#[cfg(test)]
pub(crate) async fn resolve_interception_core(
    id: &str,
    action: proxy::InterceptionAction,
    provider: &str,
    scope: Option<&str>,
    proxy_manager: &proxy::ProxyManager,
    state: &state::AppState,
    auditor: &auditor::Auditor,
) -> Result<ResolveInterceptionOutcome, proxy::AllowError> {
    resolve_interception_core_with(
        id,
        action,
        provider,
        scope,
        false,
        proxy_manager,
        state,
        auditor,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_interception_core_with(
    id: &str,
    action: proxy::InterceptionAction,
    provider: &str,
    scope: Option<&str>,
    persist_exception: bool,
    proxy_manager: &proxy::ProxyManager,
    state: &state::AppState,
    auditor: &auditor::Auditor,
) -> Result<ResolveInterceptionOutcome, proxy::AllowError> {
    resolve_interception_with_params(ResolveInterceptionParams {
        id,
        action,
        provider,
        scope,
        persist_exception,
        proxy_manager,
        state,
        auditor,
    })
    .await
}

pub(crate) async fn toggle_or_clear_stop_core(
    freeze: Option<bool>,
    guard: &std::sync::Arc<proxy::NetworkGuard>,
    state: &state::AppState,
) -> (bool, bool) {
    let is_manual = guard.is_manual_killswitch();
    match freeze {
        Some(true) => (guard.set_manual_killswitch(true, state).await, false),
        Some(false) => {
            if is_manual {
                let frozen = guard.set_manual_killswitch(false, state).await;
                guard.kick_reaudit();
                (frozen, true)
            } else {
                guard.clear_stop_and_reaudit(state).await;
                (false, true)
            }
        }
        None => {
            let st = state.get_data().await;
            let has_any_stop =
                is_manual || guard.any_provider_gate_closed() || !st.blocked_providers.is_empty();
            if has_any_stop {
                if is_manual {
                    let frozen = guard.set_manual_killswitch(false, state).await;
                    guard.kick_reaudit();
                    (frozen, true)
                } else {
                    guard.clear_stop_and_reaudit(state).await;
                    (false, true)
                }
            } else {
                (guard.set_manual_killswitch(true, state).await, false)
            }
        }
    }
}
