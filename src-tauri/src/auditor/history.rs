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

/// Evaluates impossible geographical travel based on provider's session history.
pub fn evaluate_impossible_travel(
    history: &[IpHistoryEntry],
    current_country_raw: &str,
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

    if prev_country != current_country {
        let elapsed_secs = current_timestamp.saturating_sub(prev.timestamp);
        if elapsed_secs < IMPOSSIBLE_TRAVEL_WINDOW_SECS {
            let elapsed_hours = elapsed_secs / 3600;
            let elapsed_mins = (elapsed_secs % 3600) / 60;

            let time_str = if elapsed_hours > 0 {
                format!("{elapsed_hours}ч {elapsed_mins}м")
            } else {
                format!("{elapsed_mins}м")
            };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::geo_matrix::CheckStatus;

    #[test]
    fn test_strict_ip_pinning() {
        // Strict enabled and matches
        let res = evaluate_ip_pinning(Some("185.10.10.10"), true, "185.10.10.10");
        assert_eq!(res.status, CheckStatus::Ok);
        assert_eq!(res.code, "PINNED_IP_MATCH");

        // Strict enabled and mismatches -> Critical
        let res = evaluate_ip_pinning(Some("185.10.10.10"), true, "185.20.20.20");
        assert_eq!(res.status, CheckStatus::Critical);
        assert_eq!(res.code, "PINNED_IP_MISMATCH");

        // Strict disabled and the IP does not match / is not pinned: nothing was checked.
        for pinned in [Some("185.10.10.10"), None] {
            let res = evaluate_ip_pinning(pinned, false, "185.20.20.20");
            assert_eq!(res.status, CheckStatus::Unknown);
            assert!(res.is_not_applicable());
            assert_eq!(res.code, "STRICT_PINNING_DISABLED");
        }

        // Strict disabled, but the IP is the pinned one: a real match.
        let res = evaluate_ip_pinning(Some("185.10.10.10"), false, "185.10.10.10");
        assert_eq!(
            (res.status, res.code.as_str()),
            (CheckStatus::Ok, "PINNED_IP_MATCH")
        );

        // Strict enabled without a pinned IP is a warning, not "not applicable".
        let res = evaluate_ip_pinning(None, true, "185.10.10.10");
        assert_eq!(res.status, CheckStatus::Warning);
    }

    #[test]
    fn first_session_is_not_applicable_and_not_a_pass() {
        let res = evaluate_impossible_travel(&[], "NL", 100_000, ProviderId::Anthropic);
        assert_eq!(res.status, CheckStatus::Unknown);
        assert!(res.is_not_applicable());
        assert_eq!(res.code, "HISTORY_FIRST_SESSION");
    }

    #[test]
    fn travel_ok_text_states_the_compared_fact() {
        let now = 100_000;
        let same = vec![IpHistoryEntry::new("1.1.1.1", "DE", Some(1), now - 600)];
        let r = evaluate_impossible_travel(&same, "DE", now, ProviderId::Openai);
        assert!(r.message.contains("совпадает"), "{}", r.message);
        let old = vec![IpHistoryEntry::new(
            "1.1.1.1",
            "DE",
            Some(1),
            now - 5 * 3600,
        )];
        let r = evaluate_impossible_travel(&old, "US", now, ProviderId::Openai);
        assert!(
            r.message.contains("DE -> US") && r.message.contains("4 ч"),
            "{}",
            r.message
        );
    }

    #[test]
    fn test_impossible_travel_detection() {
        let now = 100000;
        let one_hour_ago = now - 3600;

        let history = vec![IpHistoryEntry::new(
            "1.1.1.1",
            "DE",
            Some(1234),
            one_hour_ago,
        )];

        // Anthropic: DE to US in 1 hour -> Critical
        let res_anthropic = evaluate_impossible_travel(&history, "US", now, ProviderId::Anthropic);
        assert_eq!(res_anthropic.status, CheckStatus::Critical);
        assert!(res_anthropic.message.contains("DE to US"));

        // OpenAI: DE to US in 1 hour -> Warning
        let res_openai = evaluate_impossible_travel(&history, "US", now, ProviderId::Openai);
        assert_eq!(res_openai.status, CheckStatus::Warning);

        // Same country (DE to DE) in 1 hour -> Ok
        let res_same = evaluate_impossible_travel(&history, "DE", now, ProviderId::Anthropic);
        assert_eq!(res_same.status, CheckStatus::Ok);

        // DE to US after 5 hours (>4h) -> Ok
        let five_hours_ago = now - (5 * 3600);
        let history_old = vec![IpHistoryEntry::new(
            "1.1.1.1",
            "DE",
            Some(1234),
            five_hours_ago,
        )];
        let res_old = evaluate_impossible_travel(&history_old, "US", now, ProviderId::Anthropic);
        assert_eq!(res_old.status, CheckStatus::Ok);
    }

    #[test]
    fn route_bound_to_zastava_key_never_mismatches_global_vpn_pin() {
        // Global VPN IP is pinned (145.241.193.245) with strict pinning ON,
        // while Gemini is routed through a France Zastava key (136.244.114.42).
        let (res, is_pinned) = evaluate_ip_pinning_for_route(
            None,
            Some("145.241.193.245"),
            true,
            "136.244.114.42",
            Some("Zastava · Франция"),
        );
        assert_eq!(res.status, CheckStatus::Ok);
        assert_eq!(res.code, "PINNED_BY_ZASTAVA_KEY");
        assert!(res.message.contains("IP закреплён ключом Заставы"));
        assert!(is_pinned);

        // Meanwhile Direct VPN provider (Claude) still validates against global VPN pin.
        let (direct_ok, direct_pinned) = evaluate_ip_pinning_for_route(
            None,
            Some("145.241.193.245"),
            true,
            "145.241.193.245",
            None,
        );
        assert_eq!(
            (direct_ok.status, direct_ok.code.as_str()),
            (CheckStatus::Ok, "PINNED_IP_MATCH")
        );
        assert!(direct_pinned);

        // Explicit per-provider pin on routed key works when matching and warns/criticals on mismatch.
        let (explicit_ok, pinned_ok) = evaluate_ip_pinning_for_route(
            Some("136.244.114.42"),
            Some("145.241.193.245"),
            true,
            "136.244.114.42",
            Some("Zastava · Франция"),
        );
        assert_eq!(
            (explicit_ok.status, explicit_ok.code.as_str()),
            (CheckStatus::Ok, "PINNED_IP_MATCH")
        );
        assert!(pinned_ok);

        let (explicit_bad, pinned_bad) = evaluate_ip_pinning_for_route(
            Some("136.244.114.42"),
            Some("145.241.193.245"),
            true,
            "198.51.100.1",
            Some("Zastava · Франция"),
        );
        assert_eq!(
            (explicit_bad.status, explicit_bad.code.as_str()),
            (CheckStatus::Critical, "PINNED_IP_MISMATCH")
        );
        assert!(!pinned_bad);
    }
}
