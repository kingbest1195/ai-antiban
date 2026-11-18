use crate::auditor::geo_matrix::{CheckResult, GUIDE_PERSONAL_VPN, ProviderId, UnknownReason};
use crate::state::IpHistoryEntry;

pub const IMPOSSIBLE_TRAVEL_WINDOW_SECS: u64 = 4 * 3600; // 4 hours

/// Evaluates IP Pinning rule.
pub fn evaluate_ip_pinning(
    pinned_ip: Option<&str>,
    strict_enabled: bool,
    current_ip: &str,
) -> CheckResult {
    let current_ip = current_ip.trim();

    if strict_enabled {
        match pinned_ip {
            Some(pinned) if pinned.trim() == current_ip => CheckResult::ok(
                "PINNED_IP_MATCH",
                format!("Трафик идет через ваш закрепленный личный VPS ({current_ip})."),
            ),
            Some(pinned) => CheckResult::critical(
                "PINNED_IP_MISMATCH",
                format!(
                    "Нарушение Strict Pinning: текущий IP ({current_ip}) не совпадает с вашим закрепленным VPS ({pinned}). Запрос заблокирован для защиты аккаунта.",
                ),
                Some(GUIDE_PERSONAL_VPN.to_string()),
            ),
            None => CheckResult::warning(
                "PINNED_IP_NOT_CONFIGURED",
                "Строгая привязка IP активна, но эталонный VPS не задан. Нажмите «Закрепить IP», чтобы зафиксировать безопасный сервер.",
                Some(GUIDE_PERSONAL_VPN.to_string()),
            ),
        }
    } else {
        match pinned_ip {
            Some(pinned) if pinned.trim() == current_ip => CheckResult::ok(
                "PINNED_IP_MATCH",
                format!("Подключено через закрепленный личный VPS ({current_ip})."),
            ),
            // Nothing is enforced and nothing was compared: not a "pass", the check just does not apply.
            _ => CheckResult::unknown(
                "STRICT_PINNING_DISABLED",
                "Строгая привязка IP отключена: IP не сверялся с закрепленным (консультативный режим).",
                UnknownReason::NotApplicable,
            ),
        }
    }
}

/// Evaluates IP pinning taking per-provider Zastava key routing into account.
///
/// When `route_label` is `Some(label)` (the provider is routed via a bound Zastava key), the
/// provider's exit IP is NEVER compared against the global/VPN `pinned_ip` (`global_pinned_ip`).
/// Only an explicit per-provider pin (`provider_pinned_ip`) is checked if present; otherwise the
/// active Zastava key itself acts as the IP pin (`PINNED_BY_ZASTAVA_KEY`, `is_pinned = true`).
pub fn evaluate_ip_pinning_for_route(
    provider_pinned_ip: Option<&str>,
    global_pinned_ip: Option<&str>,
    strict_enabled: bool,
    current_ip: &str,
    route_label: Option<&str>,
) -> (CheckResult, bool) {
    let current = current_ip.trim();
    let provider_pin = provider_pinned_ip.map(str::trim).filter(|s| !s.is_empty());

    if let Some(label) = route_label {
        if let Some(pinned) = provider_pin {
            let res = evaluate_ip_pinning(Some(pinned), strict_enabled, current);
            return (res, pinned == current);
        }
        let label_clean = label.trim();
        let msg = if label_clean.is_empty() {
            format!("IP закреплён ключом Заставы ({current}).")
        } else {
            format!("IP закреплён ключом Заставы «{label_clean}» ({current}).")
        };
        return (CheckResult::ok("PINNED_BY_ZASTAVA_KEY", msg), true);
    }

    let effective =
        provider_pin.or_else(|| global_pinned_ip.map(str::trim).filter(|s| !s.is_empty()));
    let res = evaluate_ip_pinning(effective, strict_enabled, current);
    let is_pinned = effective.is_some_and(|p| p == current);
    (res, is_pinned)
}

fn format_elapsed(elapsed_secs: u64) -> String {
    let elapsed_hours = elapsed_secs / 3600;
    let elapsed_mins = (elapsed_secs % 3600) / 60;
    if elapsed_hours > 0 {
        format!("{elapsed_hours}ч {elapsed_mins}м")
    } else {
        format!("{elapsed_mins}м")
    }
}

/// Evaluates impossible geographical travel based on provider's session history.
pub fn evaluate_impossible_travel(
    history: &[IpHistoryEntry],
    current_country_raw: &str,
    current_timestamp: u64,
    provider: ProviderId,
) -> CheckResult {
    evaluate_impossible_travel_with_exit(
        history,
        current_country_raw,
        None,
        None,
        current_timestamp,
        provider,
    )
}

/// Evaluates impossible geographical travel and same-country ASN/datacenter jumps based on
/// provider's session history and the current exit IP / ASN.
pub fn evaluate_impossible_travel_with_exit(
    history: &[IpHistoryEntry],
    current_country_raw: &str,
    current_ip_raw: Option<&str>,
    current_asn: Option<u32>,
    current_timestamp: u64,
    provider: ProviderId,
) -> CheckResult {
    let current_country = current_country_raw.trim().to_uppercase();

    // Look at the most recent historical entry
    let prev = match history.last() {
        Some(entry) => entry,
        None => {
            return CheckResult::unknown(
                "HISTORY_FIRST_SESSION",
                "Первая сессия для этого провайдера: истории стран для сравнения еще нет.",
                UnknownReason::NotApplicable,
            );
        }
    };

    let prev_country = prev.country_code.trim().to_uppercase();
    let elapsed_secs = current_timestamp.saturating_sub(prev.timestamp);

    if prev_country != current_country {
        if elapsed_secs < IMPOSSIBLE_TRAVEL_WINDOW_SECS {
            let time_str = format_elapsed(elapsed_secs);

            let msg = format!(
                "Аномалия Impossible Travel: резкая смена страны ({prev_country} -> {current_country}) за {time_str} ({prev_country} to {current_country}). Антифрод Claude банит за прыжки между странами.",
            );

            // Anthropic is especially strict on rapid location hops
            if provider == ProviderId::Anthropic {
                return CheckResult::critical(
                    "IMPOSSIBLE_TRAVEL_CRITICAL",
                    msg,
                    Some(GUIDE_PERSONAL_VPN.to_string()),
                );
            } else {
                return CheckResult::warning(
                    "IMPOSSIBLE_TRAVEL_WARNING",
                    msg,
                    Some(GUIDE_PERSONAL_VPN.to_string()),
                );
            }
        }
    } else if !current_country.is_empty() && elapsed_secs < IMPOSSIBLE_TRAVEL_WINDOW_SECS {
        let prev_asn = prev.asn.filter(|&a| a > 0);
        let cur_asn = current_asn.filter(|&a| a > 0);
        let prev_ip = prev.ip.trim();
        let cur_ip = current_ip_raw.map(str::trim).unwrap_or("");
        if let (Some(pa), Some(ca)) = (prev_asn, cur_asn)
            && pa != ca
            && !prev_ip.is_empty()
            && !cur_ip.is_empty()
            && prev_ip != cur_ip
        {
            let time_str = format_elapsed(elapsed_secs);
            return CheckResult::warning(
                "TRAVEL_ASN_JUMP_SAME_COUNTRY",
                format!(
                    "Резкая смена дата-центра/ASN внутри {current_country} (AS{pa} -> AS{ca}, {prev_ip} -> {cur_ip}) за {time_str} без 4-часовой паузы. Антифрод отслеживает переходы между разными провайдерами в одной стране."
                ),
                Some(GUIDE_PERSONAL_VPN.to_string()),
            );
        }
    }

    let text = if prev_country == current_country {
        format!("Страна выхода ({current_country}) совпадает со страной последней записи истории.")
    } else {
        format!(
            "Страна сменилась ({prev_country} -> {current_country}), но с последней записи истории прошло больше 4 ч."
        )
    };
    CheckResult::ok("TRAVEL_NORMAL", text)
}

fn is_blocked_country_for_travel_grace(country_raw: &str) -> bool {
    let cc = country_raw.trim();
    crate::is_sanctioned_or_blocked_country(cc)
        || cc.eq_ignore_ascii_case("HK")
        || cc.eq_ignore_ascii_case("CN")
        || cc.eq_ignore_ascii_case("MO")
}

fn is_travel_anomaly_code(code: &str) -> bool {
    matches!(
        code,
        "IMPOSSIBLE_TRAVEL_CRITICAL"
            | "IMPOSSIBLE_TRAVEL_WARNING"
            | "TRAVEL_ASN_JUMP_SAME_COUNTRY"
    )
}

/// Pin-aware variant of [`evaluate_impossible_travel`]: returning to an explicitly pinned IP on
/// a non-sanctioned/non-blocked country within `<4h` does not trigger travel/ASN-jump warnings.
pub fn evaluate_impossible_travel_with_pin(
    history: &[IpHistoryEntry],
    current_country_raw: &str,
    current_timestamp: u64,
    provider: ProviderId,
    is_pinned: bool,
) -> CheckResult {
    evaluate_impossible_travel_with_pin_and_exit(
        history,
        current_country_raw,
        None,
        None,
        current_timestamp,
        provider,
        is_pinned,
    )
}

/// Pin-aware variant of [`evaluate_impossible_travel_with_exit`].
pub fn evaluate_impossible_travel_with_pin_and_exit(
    history: &[IpHistoryEntry],
    current_country_raw: &str,
    current_ip_raw: Option<&str>,
    current_asn: Option<u32>,
    current_timestamp: u64,
    provider: ProviderId,
    is_pinned: bool,
) -> CheckResult {
    let res = evaluate_impossible_travel_with_exit(
        history,
        current_country_raw,
        current_ip_raw,
        current_asn,
        current_timestamp,
        provider,
    );
    if is_pinned
        && !is_blocked_country_for_travel_grace(current_country_raw)
        && is_travel_anomaly_code(&res.code)
    {
        let cc = current_country_raw.trim().to_uppercase();
        return CheckResult::ok(
            "TRAVEL_PINNED_RETURN",
            format!(
                "Возврат на ваш закреплённый IP в {cc}: смена страны или ASN относительно предыдущего VPN допустима."
            ),
        );
    }
    res
}

/// Downgrades `IMPOSSIBLE_TRAVEL_CRITICAL` / `IMPOSSIBLE_TRAVEL_WARNING` in `report` when
/// `is_pinned` is `true`, exit geo is non-sanctioned/non-blocked (neither `Critical` nor `Unknown`),
/// and no other check is `Critical`. Recomputes `overall_status`, `trust_score`, and counts.
pub fn apply_pinned_travel_grace(
    report: &mut crate::auditor::RiskReport,
    is_pinned: bool,
) -> bool {
    if !is_pinned {
        return false;
    }
    let cc = report.telemetry.country_code.trim();
    if cc.is_empty()
        || is_blocked_country_for_travel_grace(cc)
        || report.geo_result.status.is_critical()
        || report.geo_result.status.is_unknown()
    {
        return false;
    }

    let has_other_critical = report
        .checks
        .iter()
        .any(|c| c.status.is_critical() && !is_travel_anomaly_code(&c.code))
        || (report.pinning_result.status.is_critical()
            && !is_travel_anomaly_code(&report.pinning_result.code))
        || report.dnsbl_result.status.is_critical()
        || report.asn_result.status.is_critical()
        || report.ipv6_result.status.is_critical();
    if has_other_critical {
        return false;
    }

    let has_travel_anomaly = is_travel_anomaly_code(&report.travel_result.code)
        || report
            .checks
            .iter()
            .any(|c| is_travel_anomaly_code(&c.code));
    if !has_travel_anomaly {
        return false;
    }

    let grace = CheckResult::ok(
        "TRAVEL_PINNED_RETURN",
        format!(
            "Возврат на ваш закреплённый IP в {}: смена страны относительно предыдущего VPN допустима.",
            cc.to_uppercase()
        ),
    );
    if is_travel_anomaly_code(&report.travel_result.code) {
        report.travel_result = grace.clone();
    }
    for check in &mut report.checks {
        if is_travel_anomaly_code(&check.code) {
            *check = grace.clone();
        }
    }
    if report.checks.is_empty() {
        report.overall_status = crate::auditor::OverallStatus::Green;
        report.trust_score = 100;
    } else {
        let verdict = crate::auditor::score_checks(&report.checks, true);
        report.overall_status = verdict.overall_status;
        report.trust_score = verdict.trust_score;
        report.unknown_count = verdict.unknown_count;
        report.applicable_count = verdict.applicable_count;
        report.incomplete = verdict.incomplete;
    }
    true
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
