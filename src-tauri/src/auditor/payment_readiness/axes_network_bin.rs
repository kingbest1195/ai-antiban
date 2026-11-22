//! Scoring calculations for Axis 1 (network checkout base) and Axis 2 (card BIN & funding).

use super::{AxisScore, PaymentChannel, PaymentReadinessInput};
use crate::auditor::geo_matrix::CheckStatus;
use crate::bin_checker::{BinReport, BinSource, CardFunding, ClaudeWebVerdict};
use crate::core::country::format_country_ru;

const SANCTIONED_CARD_COUNTRIES: &[&str] = &["RU", "BY"];
const HIGH_KYC_FINTECH_KEYWORDS: &[&str] = &["ANTARCTIC", "ALTYN", "WAYMENT", "NIUM"];

pub(super) fn norm_cc(raw: Option<&str>) -> String {
    let cc = crate::core::country::normalize_country_code(raw.unwrap_or(""));
    if cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_alphabetic()) {
        cc
    } else {
        String::new()
    }
}

pub(super) fn axis_status(score: u8, max: u8, has_blocker: bool) -> CheckStatus {
    if has_blocker || score == 0 {
        CheckStatus::Critical
    } else if score < max.saturating_sub(5) {
        CheckStatus::Warning
    } else {
        CheckStatus::Ok
    }
}

fn funding_label_ru(funding: CardFunding) -> &'static str {
    match funding {
        CardFunding::Credit => "кредитная карта",
        CardFunding::Debit => "дебетовая карта",
        CardFunding::Prepaid => "предоплаченная (виртуальная) карта",
        CardFunding::Charge => "расчётная карта",
        CardFunding::Unknown => "тип карты не определён",
    }
}

fn clean_fintech_display_label(bin: &BinReport) -> String {
    let raw = bin
        .known_fintech_label
        .as_deref()
        .or(bin.issuer_name.as_deref())
        .unwrap_or("виртуальная финтех-карта");
    let upper = raw.to_ascii_uppercase();
    if upper.contains("WAYMENT") || upper.contains("REDOTPAY") || upper.contains("NIUM") {
        if upper.contains("WAYMENT") && upper.contains("REDOTPAY") {
            "RedotPay / Wayment".to_string()
        } else if upper.contains("WAYMENT") {
            "Wayment".to_string()
        } else {
            "RedotPay".to_string()
        }
    } else if upper.contains("ANTARCTIC") {
        "Antarctic Wallet".to_string()
    } else if upper.contains("ALTYN") {
        "Altyn Wallet".to_string()
    } else {
        raw.to_string()
    }
}

pub(super) fn score_network_axis(
    input: &PaymentReadinessInput,
    warnings: &mut Vec<String>,
    blockers: &mut Vec<String>,
) -> AxisScore {
    let mut pts: i32 = 25;
    let mut notes = Vec::new();
    let mut axis_blocker = false;

    let exit_cc = norm_cc(input.exit_country.as_deref());
    let has_ip = input
        .exit_ip
        .as_deref()
        .is_some_and(|ip| !ip.trim().is_empty());

    if !has_ip || exit_cc.is_empty() {
        pts -= 15;
        let msg = "Не удалось определить ваш IP-адрес или страну подключения — стабильность перед оплатой не подтверждена.";
        notes.push(msg.to_string());
        warnings.push(msg.to_string());
    } else if SANCTIONED_CARD_COUNTRIES.contains(&exit_cc.as_str()) {
        pts -= 25;
        axis_blocker = true;
        let exit_label = format_country_ru(&exit_cc);
        let msg = format!(
            "Подключение идёт через неподдерживаемую страну {exit_label} — оплата подписки будет заблокирована."
        );
        notes.push(msg.clone());
        blockers.push(msg);
    }

    if input.is_tor_or_mass_vpn {
        pts -= 25;
        axis_blocker = true;
        let msg = "Адрес подключения относится к Tor или массовому публичному VPN — высокий риск проверки по паспорту и селфи при оплате.";
        notes.push(msg.to_string());
        blockers.push(msg.to_string());
    } else {
        if !input.is_pinned {
            pts -= 15;
            let msg =
                "Адрес подключения не закреплён — он может незаметно смениться перед оплатой.";
            notes.push(msg.to_string());
            warnings.push(msg.to_string());
        }
        if input.is_datacenter_or_vpn {
            let penalty = if input.is_pinned { 5 } else { 10 };
            pts -= penalty;
            let msg = if input.is_pinned {
                "Адрес подключения относится к дата-центру или серверу (закреплён)."
            } else {
                "Незакреплённый адрес дата-центра или сервера повышает риск проверки антифродом оплаты."
            };
            notes.push(msg.to_string());
            warnings.push(msg.to_string());
        }
    }

    if input.has_network_leaks {
        pts -= 15;
        axis_blocker = true;
        let msg =
            "Обнаружена утечка реального IP в браузере, DNS, IPv6 или несовпадение часового пояса.";
        notes.push(msg.to_string());
        blockers.push(msg.to_string());
    }

    if input.has_recent_jump_lt_4h {
        pts -= 15;
        axis_blocker = true;
        let msg = "Менее 4 часов назад сменилась страна или сеть провайдера выхода — оплата сейчас несёт высокий риск запроса паспорта и селфи.";
        notes.push(msg.to_string());
        blockers.push(msg.to_string());
    }

    if input.split_ip_checkout_risk {
        pts -= 15;
        axis_blocker = true;
        let msg = "Разные IP у сайта ИИ и страницы оплаты: форма оплаты может увидеть другой адрес подключения.";
        notes.push(msg.to_string());
        blockers.push(msg.to_string());
    }

    if notes.is_empty() {
        notes.push(
            "Подключение перед оплатой стабильно: адрес закреплён, утечек и недавних смен страны нет."
                .to_string(),
        );
    }

    let score = pts.clamp(0, 25) as u8;
    AxisScore {
        id: "network_base".to_string(),
        label: "Стабильность подключения перед оплатой".to_string(),
        score,
        max_score: 25,
        status: axis_status(score, 25, axis_blocker),
        notes,
    }
}

fn is_high_kyc_fintech_for_ip(bin: &BinReport, exit_cc: &str) -> bool {
    let label = bin
        .known_fintech_label
        .as_deref()
        .unwrap_or("")
        .to_ascii_uppercase();
    let issuer = bin
        .issuer_name
        .as_deref()
        .unwrap_or("")
        .to_ascii_uppercase();
    let combined = format!("{label} {issuer}");

    if combined.contains("ANTARCTIC") || combined.contains("ALTYN") {
        return true;
    }
    if (combined.contains("WAYMENT") || combined.contains("NIUM")) && exit_cc != "SG" {
        return true;
    }
    if HIGH_KYC_FINTECH_KEYWORDS
        .iter()
        .any(|kw| combined.contains(kw))
        && exit_cc != "SG"
    {
        return true;
    }
    bin.claude_web_verdict == ClaudeWebVerdict::HighKycRisk
        && bin.source != BinSource::FallbackUnknown
}

pub(super) fn score_bin_axis(
    input: &PaymentReadinessInput,
    warnings: &mut Vec<String>,
    blockers: &mut Vec<String>,
) -> (AxisScore, bool, bool) {
    let mut notes = Vec::new();
    if matches!(
        input.channel,
        PaymentChannel::AppleIAP | PaymentChannel::Api
    ) {
        let msg = match input.channel {
            PaymentChannel::AppleIAP => {
                "Оплата через App Store (подарочной картой): банковская карта сайту не передаётся, риск проверки по карте исключён."
            }
            _ => "Оплата API-баланса: форма оплаты подписки на сайте claude.ai не используется.",
        };
        notes.push(msg.to_string());
        return (
            AxisScore {
                id: "card_bin".to_string(),
                label: "Карта и её тип".to_string(),
                score: 30,
                max_score: 30,
                status: CheckStatus::Ok,
                notes,
            },
            false,
            false,
        );
    }

    let Some(bin) = input.bin_report.as_ref() else {
        let msg = "Первые 6–8 цифр карты ещё не проверены — без проверки нельзя подтвердить безопасность оплаты.";
        notes.push(msg.to_string());
        warnings.push(msg.to_string());
        return (
            AxisScore {
                id: "card_bin".to_string(),
                label: "Карта и её тип".to_string(),
                score: 15,
                max_score: 30,
                status: CheckStatus::Warning,
                notes,
            },
            true,
            false,
        );
    };

    let card_cc = norm_cc(bin.country_code.as_deref());
    if SANCTIONED_CARD_COUNTRIES.contains(&card_cc.as_str()) {
        let card_label = format_country_ru(&card_cc);
        let msg = format!(
            "Оплата невозможна: карта выпущена в стране {card_label}. Карты России и Беларуси отклоняются платёжной системой сайта и вызывают мгновенную блокировку."
        );
        notes.push(msg.clone());
        blockers.push(msg);
        return (
            AxisScore {
                id: "card_bin".to_string(),
                label: "Карта и её тип".to_string(),
                score: 0,
                max_score: 30,
                status: CheckStatus::Critical,
                notes,
            },
            false,
            true,
        );
    }

    let mut pts: i32 = 30;
    let mut fail_closed = false;
    let mut axis_blocker = false;
    let mut hard_zero_block = false;

    if bin.source == BinSource::FallbackUnknown
        || bin.status == CheckStatus::Unknown
        || card_cc.is_empty()
    {
        pts -= 15;
        fail_closed = true;
        let msg = "Не удалось проверить карту по первым цифрам — без подтверждения оплата не может считаться полностью безопасной.";
        notes.push(msg.to_string());
        warnings.push(msg.to_string());
    }

    if bin.claude_web_verdict == ClaudeWebVerdict::Blocked {
        pts = 0;
        axis_blocker = true;
        hard_zero_block = true;
        let card_label = format_country_ru(&card_cc);
        let msg = format!("Карты страны {card_label} не принимаются для оплаты подписки.");
        notes.push(msg.clone());
        blockers.push(msg);
    }

    if bin.is_prepaid == Some(true) || bin.funding == CardFunding::Prepaid {
        pts -= 15;
        let msg = "Предоплаченная (виртуальная) карта: антифрод оплаты чаще запрашивает по таким картам паспорт и селфи.";
        notes.push(msg.to_string());
        warnings.push(msg.to_string());
    }

    if bin.is_commercial == Some(true) {
        pts -= 10;
        let msg = "Корпоративная карта: требуется строгое совпадение страны карты, подключения и адреса оплаты.";
        notes.push(msg.to_string());
        warnings.push(msg.to_string());
    }

    let exit_cc = norm_cc(input.exit_country.as_deref());
    if is_high_kyc_fintech_for_ip(bin, &exit_cc) {
        pts -= 25;
        axis_blocker = true;
        let label = clean_fintech_display_label(bin);
        let exit_desc = if exit_cc.is_empty() {
            "не определено".to_string()
        } else {
            format_country_ru(&exit_cc)
        };
        let msg = format!(
            "Высокий риск запроса паспорта и селфи для карты «{label}» при текущем подключении ({exit_desc})."
        );
        notes.push(msg.clone());
        blockers.push(msg);
    }

    if notes.is_empty() {
        let country_desc = if card_cc.is_empty() {
            "страна не определена".to_string()
        } else {
            format_country_ru(&card_cc)
        };
        notes.push(format!(
            "Карта {} ({}, {}) подходит для оплаты на сайте.",
            bin.bin_prefix,
            country_desc,
            funding_label_ru(bin.funding)
        ));
    }

    let score = pts.clamp(0, 30) as u8;
    (
        AxisScore {
            id: "card_bin".to_string(),
            label: "Карта и её тип".to_string(),
            score,
            max_score: 30,
            status: axis_status(score, 30, axis_blocker),
            notes,
        },
        fail_closed,
        hard_zero_block,
    )
}
