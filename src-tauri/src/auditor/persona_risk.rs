//! Proactive Persona Risk Index evaluator combining automated technical signals
//! (from RiskReport, Clean Room traces, and AppState) with user self-check toggles.

use serde::{Deserialize, Serialize};

use super::RiskReport;
use super::geo_matrix::CheckStatus;
use super::ip_type::IpType;
use super::os_env::is_russian_or_belarusian_timezone;
use crate::state::{AppStateData, PersonaSelfCheck};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PersonaRiskLevel {
    Low,
    Medium,
    High,
}

impl PersonaRiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=24 => Self::Low,
            25..=54 => Self::Medium,
            _ => Self::High,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaRiskFactorSource {
    Technical,
    SelfCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonaRiskFactor {
    pub id: String,
    pub source: PersonaRiskFactorSource,
    pub label: String,
    pub detail: String,
    pub weight: u8,
    pub active: bool,
    pub fix_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonaRiskReport {
    pub score: u8,
    pub level: PersonaRiskLevel,
    pub factors: Vec<PersonaRiskFactor>,
    pub self_check: PersonaSelfCheck,
    pub recommended_actions: Vec<String>,
    pub evaluated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PersonaSelfCheckPatch {
    #[serde(default)]
    pub bought_or_grey_account: Option<bool>,
    #[serde(default)]
    pub virtual_sms_used: Option<bool>,
    #[serde(default)]
    pub reseller_payment_used: Option<bool>,
    #[serde(default)]
    pub multi_account_same_browser: Option<bool>,
}

impl PersonaSelfCheckPatch {
    pub fn apply_to(&self, target: &mut PersonaSelfCheck) {
        if let Some(v) = self.bought_or_grey_account {
            target.bought_or_grey_account = v;
        }
        if let Some(v) = self.virtual_sms_used {
            target.virtual_sms_used = v;
        }
        if let Some(v) = self.reseller_payment_used {
            target.reseller_payment_used = v;
        }
        if let Some(v) = self.multi_account_same_browser {
            target.multi_account_same_browser = v;
        }
    }
}

pub struct PersonaRiskInput<'a> {
    pub state_data: &'a AppStateData,
    pub risk_report: Option<&'a RiskReport>,
    pub sysproxy_active: bool,
    pub os_tz: Option<&'a str>,
    pub has_personal_browser_traces: bool,
    pub has_desktop_traces: bool,
    pub now_secs: u64,
}

fn factor(
    id: &str,
    source: PersonaRiskFactorSource,
    label: &str,
    detail: impl Into<String>,
    weight: u8,
    active: bool,
    fix_target: &str,
) -> PersonaRiskFactor {
    PersonaRiskFactor {
        id: id.to_string(),
        source,
        label: label.to_string(),
        detail: detail.into(),
        weight,
        active,
        fix_target: Some(fix_target.to_string()),
    }
}

/// Evaluates the proactive Persona Risk Index (`0..=100`, `"low"` / `"medium"` / `"high"`).
pub fn evaluate_persona_risk(input: &PersonaRiskInput<'_>) -> PersonaRiskReport {
    let sc = input.state_data.persona_self_check.clone();
    let factors = vec![
        build_ip_type_factor(input),
        build_jump_cooldown_factor(input),
        build_network_leak_factor(input.risk_report),
        build_tz_locale_factor(input),
        build_browser_trace_factor(input),
        factor(
            "self_bought_or_grey_account",
            PersonaRiskFactorSource::SelfCheck,
            "Аккаунт куплен с рук / на бирже",
            "Чужие или массово зарегистрированные аккаунты чаще попадают под Persona KYC.",
            45,
            sc.bought_or_grey_account,
            "open_clean_room",
        ),
        factor(
            "self_virtual_sms_used",
            PersonaRiskFactorSource::SelfCheck,
            "Использован одноразовый виртуальный SMS-номер",
            "Дешёвые VoIP/SMS-активаторы массово помечены антифродом.",
            30,
            sc.virtual_sms_used,
            "open_bunker",
        ),
        factor(
            "self_reseller_payment_used",
            PersonaRiskFactorSource::SelfCheck,
            "Оплата через перекупа (Playerok / FunPay / чужой Apple Pay)",
            "Серый биллинг — один из главных триггеров перманентного бана.",
            45,
            sc.reseller_payment_used,
            "open_bunker",
        ),
        factor(
            "self_multi_account_same_browser",
            PersonaRiskFactorSource::SelfCheck,
            "Вход в несколько аккаунтов из одного обычного браузера",
            "Используйте изолированное окно «Чистой комнаты» для каждого нового аккаунта.",
            35,
            sc.multi_account_same_browser,
            "open_clean_room",
        ),
    ];

    let raw_score: u16 = factors
        .iter()
        .filter(|f| f.active)
        .map(|f| u16::from(f.weight))
        .sum();
    let score = raw_score.min(100) as u8;
    let level = PersonaRiskLevel::from_score(score);
    let recommended_actions = build_recommended_actions(level, &factors);

    PersonaRiskReport {
        score,
        level,
        factors,
        self_check: sc,
        recommended_actions,
        evaluated_at: input.now_secs,
    }
}

fn is_ip_pinned_in_state(state_data: &AppStateData, exit_ip: &str) -> bool {
    let trimmed = exit_ip.trim();
    if trimmed.is_empty() {
        return false;
    }
    state_data.pinned_ips.values().any(|p| p.trim() == trimmed)
        || state_data
            .pinned_ip
            .as_deref()
            .is_some_and(|p| p.trim() == trimmed)
}

fn build_ip_type_factor(input: &PersonaRiskInput<'_>) -> PersonaRiskFactor {
    let tech = PersonaRiskFactorSource::Technical;
    let Some(report) = input.risk_report else {
        return factor(
            "tech_ip_reputation",
            tech,
            "Тип выходного IP (Дата-центр, VPN или Tor)",
            "Нет активного отчёта аудита для оценки типа IP.",
            15,
            false,
            "pin_ip",
        );
    };

    let ip_type = report
        .asn_result
        .detail
        .as_ref()
        .and_then(|d| d.ip_type)
        .unwrap_or(IpType::Unknown);
    let code = report.asn_result.code.as_str();
    let pinned = is_ip_pinned_in_state(input.state_data, &report.telemetry.ip)
        || matches!(code, "ASN_VERIFIED_PINNED")
        || matches!(
            report.pinning_result.code.as_str(),
            "PINNED_BY_ZASTAVA_KEY" | "PINNED_IP_MATCH"
        );

    if ip_type == IpType::Tor || code == "IP_TYPE_TOR" {
        return factor(
            "tech_ip_reputation",
            tech,
            "Выход через сеть Tor",
            "Выходные узлы Tor вызывают немедленную блокировку или Persona KYC.",
            60,
            true,
            "switch_route",
        );
    }
    if ip_type == IpType::Vpn || code == "HIGH_RISK_MASS_VPN_ASN" {
        return factor(
            "tech_ip_reputation",
            tech,
            "Массовый VPN-пул",
            "IP принадлежит массовому публичному VPN, который делят тысячи пользователей.",
            35,
            true,
            "switch_route",
        );
    }
    if (ip_type == IpType::Hosting || code == "IP_TYPE_HOSTING") && !pinned {
        return factor(
            "tech_ip_reputation",
            tech,
            "Дата-центр или VPS без закрепления IP",
            "IP дата-центра не закреплён: тихая смена узла повышает риск проверки.",
            15,
            true,
            "pin_ip",
        );
    }
    factor(
        "tech_ip_reputation",
        tech,
        "Тип выходного IP",
        "Выходной адрес стабилен и не относится к Tor или массовым VPN.",
        15,
        false,
        "pin_ip",
    )
}

fn build_jump_cooldown_factor(input: &PersonaRiskInput<'_>) -> PersonaRiskFactor {
    let cooldown_active = input
        .state_data
        .ip_change_cooldown_remaining_secs(input.now_secs as i64)
        .is_some();
    let tainted_ip = input.risk_report.is_some_and(|r| {
        input
            .state_data
            .clean_room
            .tainted_ips
            .contains_key(r.telemetry.ip.trim())
    });
    let travel_jump = input.risk_report.is_some_and(|r| {
        r.travel_result.status != CheckStatus::Ok
            && matches!(
                r.travel_result.code.as_str(),
                "TRAVEL_ASN_JUMP_SAME_COUNTRY"
                    | "IMPOSSIBLE_TRAVEL_CRITICAL"
                    | "IMPOSSIBLE_TRAVEL_WARNING"
            )
    });

    let detail = if tainted_ip {
        "Текущий выходной IP скомпрометирован (отмечен после бана)."
    } else if travel_jump {
        "Зафиксирован прыжок ASN или смена страны менее 4 часов назад."
    } else if cooldown_active {
        "Активен 4-часовой таймер после безопасного выхода из аккаунта."
    } else {
        "Резких смен ASN/страны за последние 4 часа не обнаружено."
    };

    factor(
        "tech_asn_jump_or_cooldown",
        PersonaRiskFactorSource::Technical,
        "Прыжок ASN/страны < 4ч или активный cooldown",
        detail,
        40,
        cooldown_active || tainted_ip || travel_jump,
        "switch_route",
    )
}

fn build_network_leak_factor(report: Option<&RiskReport>) -> PersonaRiskFactor {
    let leak = report.is_some_and(|r| {
        matches!(
            r.ipv6_result.status,
            CheckStatus::Critical | CheckStatus::Warning
        ) || r.checks.iter().any(|c| {
            matches!(c.status, CheckStatus::Critical | CheckStatus::Warning)
                && (c.code.contains("DNS") || c.code.contains("UDP_STUN"))
        })
    });
    let detail = if leak {
        "Обнаружена утечка IPv6, DNS-резолвера или UDP/STUN мимо защищённого маршрута."
    } else {
        "Утечек IPv6, DNS и UDP/STUN не зафиксировано."
    };
    factor(
        "tech_network_leak",
        PersonaRiskFactorSource::Technical,
        "Утечка IPv6 / DNS / WebRTC (STUN)",
        detail,
        25,
        leak,
        "switch_route",
    )
}

fn build_tz_locale_factor(input: &PersonaRiskInput<'_>) -> PersonaRiskFactor {
    let report_tz_ru = input.risk_report.is_some_and(|r| {
        r.timezone_result.code == "TIMEZONE_LEAK_RU" && r.timezone_result.status != CheckStatus::Ok
    });
    let report_locale_ru = input.risk_report.is_some_and(|r| {
        r.checks
            .iter()
            .any(|c| c.code == "LOCALE_ENV_SANCTIONED_MARKER" && c.status != CheckStatus::Ok)
    });
    let fallback_ru = input.risk_report.is_none()
        && !input.state_data.sync_ai_tz_enabled
        && input.os_tz.is_some_and(is_russian_or_belarusian_timezone);

    let active = report_tz_ru || report_locale_ru || fallback_ru;
    let detail = if active {
        "Часовой пояс или локаль ОС указывают на РФ/РБ — синхронизируйте TZ с выходом."
    } else {
        "Часовой пояс и локаль согласованы или изолированы."
    };
    factor(
        "tech_os_tz_locale_ru",
        PersonaRiskFactorSource::Technical,
        "Часовой пояс ОС или локаль РФ/РБ без изоляции",
        detail,
        20,
        active,
        "sync_os_tz",
    )
}

fn build_browser_trace_factor(input: &PersonaRiskInput<'_>) -> PersonaRiskFactor {
    let active =
        !input.sysproxy_active || input.has_personal_browser_traces || input.has_desktop_traces;
    let fix_target = if input.has_desktop_traces && input.sysproxy_active {
        "clean_cache"
    } else {
        "open_clean_room"
    };
    let detail = if !input.sysproxy_active {
        "Системная защита выключена — личный браузер и клиенты выходят незащищённо."
    } else if input.has_desktop_traces || input.has_personal_browser_traces {
        "Найдены следы личного браузера или прошлых desktop-сессий — используйте «Чистую комнату»."
    } else {
        "Системная защита активна, конфликтующие следы не выявлены."
    };
    factor(
        "tech_unprotected_browser_traces",
        PersonaRiskFactorSource::Technical,
        "Незащищённый браузер или следы прошлых сессий",
        detail,
        15,
        active,
        fix_target,
    )
}

fn build_recommended_actions(
    level: PersonaRiskLevel,
    factors: &[PersonaRiskFactor],
) -> Vec<String> {
    match level {
        PersonaRiskLevel::High => vec![
            "Сделайте немедленный локальный бэкап в «Бункере данных».".to_string(),
            "Для нового аккаунта используйте только «Чистую комнату» и чистый IP.".to_string(),
        ],
        PersonaRiskLevel::Medium => vec![
            "Устраните активные факторы риска перед следующей оплатой или сессией.".to_string(),
        ],
        PersonaRiskLevel::Low if factors.iter().any(|f| f.active) => {
            vec!["Риск низкий; при желании закройте оставшиеся мелкие замечания.".to_string()]
        }
        PersonaRiskLevel::Low => Vec::new(),
    }
}

#[cfg(test)]
#[path = "persona_risk_tests.rs"]
mod tests;
