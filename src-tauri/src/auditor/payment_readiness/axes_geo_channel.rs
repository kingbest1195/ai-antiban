//! Scoring calculations for Axis 3 (IP/BIN/Billing parity), Axis 4 (channel/warmup/plan),
//! Google Pay / Apple Pay trap detector, and final verdict assembly.

use super::axes_network_bin::{axis_status, norm_cc, score_bin_axis, score_network_axis};
use super::{
    AxisScore, PaymentChannel, PaymentReadinessAxes, PaymentReadinessInput, PaymentReadinessReport,
    ReadinessTier, SubscriptionPlan,
};
use crate::auditor::geo_matrix::CheckStatus;
use crate::core::bin_radar::AiPaymentService;
use crate::core::country::format_country_ru;

fn score_geo_billing_axis(
    input: &PaymentReadinessInput,
    warnings: &mut Vec<String>,
    blockers: &mut Vec<String>,
) -> AxisScore {
    let mut notes = Vec::new();
    let exit_cc = norm_cc(input.exit_country.as_deref());

    if input.channel == PaymentChannel::AppleIAP {
        let apple_cc = norm_cc(input.apple_id_country.as_deref());
        let mut pts: i32 = 25;
        let mut axis_blocker = false;
        if !apple_cc.is_empty() && apple_cc != "US" {
            pts -= 20;
            axis_blocker = true;
            let apple_label = format_country_ru(&apple_cc);
            let msg = format!(
                "Аккаунт App Store настроен на регион {apple_label}: для безопасной оплаты подписки нужен отдельный аккаунт США (US)."
            );
            notes.push(msg.clone());
            blockers.push(msg);
        } else if !exit_cc.is_empty() && exit_cc != "US" {
            pts -= 5;
            let exit_label = format_country_ru(&exit_cc);
            let msg = format!(
                "Текущее подключение — {exit_label}. Для привязки аккаунта App Store США (US) и активации подарочной карты предпочтительно подключение через США (US)."
            );
            notes.push(msg.to_string());
            warnings.push(msg.to_string());
        } else {
            notes.push(
                "Аккаунт App Store США (US) и подключение согласованы для оплаты через App Store."
                    .to_string(),
            );
        }
        let score = pts.clamp(0, 25) as u8;
        return AxisScore {
            id: "geo_billing_parity".to_string(),
            label: "Совпадение страны, карты и адреса".to_string(),
            score,
            max_score: 25,
            status: axis_status(score, 25, axis_blocker),
            notes,
        };
    }

    if input.channel == PaymentChannel::GooglePlayIap {
        let gp_cc = norm_cc(input.google_profile_country.as_deref());
        let mut pts: i32 = 25;
        let mut axis_blocker = false;
        if gp_cc == "RU" {
            pts = 0;
            axis_blocker = true;
            let msg = "Платёжный профиль Google привязан к России — оплата зарубежной картой вызовет холд OR-CCSEH-21 / OR-HDT-16.";
            notes.push(msg.to_string());
            blockers.push(msg.to_string());
        } else if !gp_cc.is_empty() && !exit_cc.is_empty() && gp_cc != exit_cc {
            pts -= 15;
            axis_blocker = true;
            let msg = format!(
                "Конфликт стран Google Play: профиль в {} при подключении через {}.",
                format_country_ru(&gp_cc),
                format_country_ru(&exit_cc)
            );
            notes.push(msg.clone());
            blockers.push(msg);
        } else {
            notes.push("Профиль Google Play и подключение согласованы.".to_string());
        }
        let score = pts.clamp(0, 25) as u8;
        return AxisScore {
            id: "geo_billing_parity".to_string(),
            label: "Совпадение страны, карты и адреса".to_string(),
            score,
            max_score: 25,
            status: axis_status(score, 25, axis_blocker),
            notes,
        };
    }

    if input.channel == PaymentChannel::Api {
        notes.push(
            "Для оплаты API-баланса совпадение страны карты, подключения и адреса оплаты не требуется."
                .to_string(),
        );
        return AxisScore {
            id: "geo_billing_parity".to_string(),
            label: "Совпадение страны, карты и адреса".to_string(),
            score: 25,
            max_score: 25,
            status: CheckStatus::Ok,
            notes,
        };
    }

    let mut pts: i32 = 25;
    let mut axis_blocker = false;
    let card_cc = norm_cc(
        input
            .bin_report
            .as_ref()
            .and_then(|b| b.country_code.as_deref()),
    );
    let bill_cc = norm_cc(input.billing_country.as_deref());

    if card_cc.is_empty() {
        pts -= 10;
        let msg = "Страна выпуска карты неизвестна — невозможно проверить совпадение подключения, карты и адреса оплаты.";
        notes.push(msg.to_string());
        warnings.push(msg.to_string());
    } else {
        let card_label = format_country_ru(&card_cc);
        if !exit_cc.is_empty() && card_cc != exit_cc {
            pts -= 20;
            axis_blocker = true;
            let exit_label = format_country_ru(&exit_cc);
            let msg = format!(
                "Конфликт стран: карта выпущена в стране {card_label}, а подключение — {exit_label}."
            );
            notes.push(msg.clone());
            blockers.push(msg);
        }
        if bill_cc.is_empty() {
            pts -= 10;
            let msg = format!(
                "Страна адреса оплаты не указана — обязательно используйте реальный адрес в стране карты: {card_label}."
            );
            notes.push(msg.to_string());
            warnings.push(msg.to_string());
        } else if bill_cc != card_cc {
            pts -= 25;
            axis_blocker = true;
            let bill_label = format_country_ru(&bill_cc);
            let msg = format!(
                "Критическое несовпадение адреса оплаты: выбран адрес в стране {bill_label}, но карта выпущена в стране {card_label}. Это прямой повод для проверки по паспорту и селфи."
            );
            notes.push(msg.clone());
            blockers.push(msg);
        }
    }

    if input.target_service == Some(AiPaymentService::Gemini) {
        let gp_cc = norm_cc(input.google_profile_country.as_deref());
        let card_cc = norm_cc(
            input
                .bin_report
                .as_ref()
                .and_then(|b| b.country_code.as_deref()),
        );
        let exit_cc = norm_cc(input.exit_country.as_deref());
        if gp_cc == "RU"
            || (!gp_cc.is_empty()
                && ((!card_cc.is_empty() && gp_cc != card_cc)
                    || (!exit_cc.is_empty() && gp_cc != exit_cc)))
        {
            pts -= 20;
            axis_blocker = true;
            let msg = "Нарушен Google Payments Profile Lock (страна профиля Google != страна карты/IP): риск холда OR-CCSEH-21 / OR-HDT-16 и 24-часового ограничения смены страны.";
            notes.push(msg.to_string());
            blockers.push(msg.to_string());
        }
    } else if input.target_service == Some(AiPaymentService::Cursor) {
        notes.push("Для Cursor соблюдайте стабильность устройства (machineId) и не используйте цепочки пробных аккаунтов.".to_string());
    }

    if notes.is_empty() {
        let exit_desc = if exit_cc.is_empty() {
            "не определена".to_string()
        } else {
            format_country_ru(&exit_cc)
        };
        notes.push(format!(
            "Полное совпадение стран: подключение ({exit_desc}), карта ({}) и адрес оплаты ({}).",
            format_country_ru(&card_cc),
            format_country_ru(&bill_cc)
        ));
    }

    let score = pts.clamp(0, 25) as u8;
    AxisScore {
        id: "geo_billing_parity".to_string(),
        label: "Совпадение страны, карты и адреса".to_string(),
        score,
        max_score: 25,
        status: axis_status(score, 25, axis_blocker),
        notes,
    }
}

fn score_channel_axis(
    input: &PaymentReadinessInput,
    warnings: &mut Vec<String>,
    blockers: &mut Vec<String>,
) -> (AxisScore, bool) {
    let mut pts: i32 = 20;
    let mut notes = Vec::new();
    let mut axis_blocker = false;
    let mut wallet_trap_triggered = false;

    if matches!(
        input.channel,
        PaymentChannel::AppleIAP | PaymentChannel::GooglePlayIap | PaymentChannel::Api
    ) {
        if input.channel == PaymentChannel::GooglePlayIap {
            let gp_cc = norm_cc(input.google_profile_country.as_deref());
            let exit_cc = norm_cc(input.exit_country.as_deref());
            let gp_conflict =
                gp_cc == "RU" || (!gp_cc.is_empty() && !exit_cc.is_empty() && gp_cc != exit_cc);
            if gp_conflict {
                let msg = "Профиль Google Payments конфликтует с оплатой (риск OR-CCSEH-21 / OR-HDT-16; смена страны блокирует изменения на 24 часа).";
                notes.push(msg.to_string());
                blockers.push(msg.to_string());
                return (
                    AxisScore {
                        id: "channel_env_warmup".to_string(),
                        label: "Способ оплаты, среда и прогрев".to_string(),
                        score: 0,
                        max_score: 20,
                        status: CheckStatus::Critical,
                        notes,
                    },
                    true,
                );
            }
        }
        let msg = match input.channel {
            PaymentChannel::AppleIAP => {
                "Оплата через App Store (подарочной картой США) избавляет от проверок антифрода и паспорта на сайте."
            }
            PaymentChannel::GooglePlayIap => {
                "Оплата через Google Play избавляет от прямой формы карты на сайте, но требует согласованного региона Google Payments (смена страны даёт холд 24 ч)."
            }
            _ => "Оплата API-баланса не использует форму подписки на сайте.",
        };
        notes.push(msg.to_string());
        return (
            AxisScore {
                id: "channel_env_warmup".to_string(),
                label: "Способ оплаты, среда и прогрев".to_string(),
                score: 20,
                max_score: 20,
                status: CheckStatus::Ok,
                notes,
            },
            false,
        );
    }

    let hours = input.warmup_hours.unwrap_or(0);
    let warmup_ok = hours >= 96 || input.account_age_confirmed_96h == Some(true);
    if !warmup_ok {
        pts -= 10;
        let msg = format!(
            "Возраст или прогрев аккаунта {hours} ч (меньше 96 ч) — рекомендуется выдержать 4 дня (96 ч) перед первой оплатой картой."
        );
        notes.push(msg.clone());
        warnings.push(msg);
    }

    if !input.in_clean_room {
        pts -= 10;
        let msg = "Оплата вне «Чистой комнаты»: обычный браузер может передать платёжной системе сайта старые cookie и цифровой след.";
        notes.push(msg.to_string());
        warnings.push(msg.to_string());
    }

    if input.plan == SubscriptionPlan::Max && !warmup_ok {
        pts -= 15;
        axis_blocker = true;
        let msg = format!(
            "Тариф Max ($100/$200) при прогреве {hours} ч (меньше 96 ч): большинство блокировок при первой оплате происходит именно на этом тарифе."
        );
        notes.push(msg.clone());
        blockers.push(msg);
    }

    if matches!(
        input.channel,
        PaymentChannel::GooglePayWeb | PaymentChannel::ApplePayWeb
    ) {
        let wallet_name = match input.channel {
            PaymentChannel::GooglePayWeb => "Google Pay (на сайте)",
            PaymentChannel::ApplePayWeb => "Apple Pay (на сайте)",
            _ => "кошелёк на сайте",
        };
        let trap_notice = format!(
            "Важно про {wallet_name}: кошельки на сайте передают платёжной системе реальную страну и тип карты, а Google Pay дополнительно сверяет страну платёжного профиля Google."
        );
        notes.push(trap_notice.clone());
        warnings.push(trap_notice);

        let card_cc = norm_cc(
            input
                .bin_report
                .as_ref()
                .and_then(|b| b.country_code.as_deref()),
        );
        let exit_cc = norm_cc(input.exit_country.as_deref());
        let gp_cc = norm_cc(input.google_profile_country.as_deref());

        if !card_cc.is_empty() && !exit_cc.is_empty() && card_cc != exit_cc {
            pts -= 20;
            axis_blocker = true;
            wallet_trap_triggered = true;
            let card_label = format_country_ru(&card_cc);
            let exit_label = format_country_ru(&exit_cc);
            let msg = format!(
                "Ловушка при оплате через {wallet_name}: кошелёк передаст сайту страну карты {card_label}, что противоречит подключению {exit_label} — высокий риск мгновенной проверки по паспорту и селфи."
            );
            notes.push(msg.clone());
            blockers.push(msg);
        }

        if input.channel == PaymentChannel::GooglePayWeb
            && !card_cc.is_empty()
            && !gp_cc.is_empty()
            && card_cc != gp_cc
        {
            pts -= 20;
            axis_blocker = true;
            wallet_trap_triggered = true;
            let card_label = format_country_ru(&card_cc);
            let gp_label = format_country_ru(&gp_cc);
            let msg = format!(
                "Конфликт платёжного профиля Google: страна карты ({card_label}) не совпадает со страной профиля Google ({gp_label})."
            );
            notes.push(msg.clone());
            blockers.push(msg);
        }
    }

    if input.target_service == Some(AiPaymentService::Gemini) {
        let gp_cc = norm_cc(input.google_profile_country.as_deref());
        let card_cc = norm_cc(
            input
                .bin_report
                .as_ref()
                .and_then(|b| b.country_code.as_deref()),
        );
        let exit_cc = norm_cc(input.exit_country.as_deref());
        if gp_cc == "RU"
            || (!gp_cc.is_empty()
                && ((!card_cc.is_empty() && gp_cc != card_cc)
                    || (!exit_cc.is_empty() && gp_cc != exit_cc)))
        {
            pts -= 20;
            axis_blocker = true;
            let msg = "Нарушен Google Payments Profile Lock (страна профиля Google != страна карты/IP): риск холда OR-CCSEH-21 / OR-HDT-16 и 24-часового ограничения смены страны.";
            notes.push(msg.to_string());
            blockers.push(msg.to_string());
        }
    } else if input.target_service == Some(AiPaymentService::Cursor) {
        notes.push("Для Cursor соблюдайте стабильность устройства (machineId) и не используйте цепочки пробных аккаунтов.".to_string());
    }

    if notes.is_empty() {
        notes.push("Среда, прогрев (от 96 ч) и способ оплаты полностью подходят.".to_string());
    }

    let score = pts.clamp(0, 20) as u8;
    (
        AxisScore {
            id: "channel_env_warmup".to_string(),
            label: "Способ оплаты, среда и прогрев".to_string(),
            score,
            max_score: 20,
            status: axis_status(score, 20, axis_blocker),
            notes,
        },
        wallet_trap_triggered,
    )
}

/// Evaluates the 4-axis Payment Readiness Report (`0..=100`, `Green | Yellow | Red`).
pub fn evaluate_payment_readiness(input: &PaymentReadinessInput) -> PaymentReadinessReport {
    let mut warnings = Vec::new();
    let mut blockers = Vec::new();

    let network_base = score_network_axis(input, &mut warnings, &mut blockers);
    let (card_bin, fail_closed_bin, hard_zero_block) =
        score_bin_axis(input, &mut warnings, &mut blockers);
    let geo_billing_parity = score_geo_billing_axis(input, &mut warnings, &mut blockers);
    let (channel_env_warmup, wallet_trap_triggered) =
        score_channel_axis(input, &mut warnings, &mut blockers);

    let raw_sum =
        network_base.score + card_bin.score + geo_billing_parity.score + channel_env_warmup.score;

    let (score, tier) = if hard_zero_block {
        (0, ReadinessTier::Red)
    } else if wallet_trap_triggered {
        (raw_sum.min(49), ReadinessTier::Red)
    } else if raw_sum <= 49 {
        (raw_sum, ReadinessTier::Red)
    } else if fail_closed_bin || !blockers.is_empty() || raw_sum <= 79 {
        (raw_sum.min(79), ReadinessTier::Yellow)
    } else {
        (raw_sum, ReadinessTier::Green)
    };

    let requires_matching_billing = !matches!(
        input.channel,
        PaymentChannel::AppleIAP | PaymentChannel::GooglePlayIap | PaymentChannel::Api
    );

    let recommended_action = if hard_zero_block || tier == ReadinessTier::Red {
        Some(
            "Остановите оплату: выберите оплату через App Store (подарочной картой США) или выровняйте страну карты, адреса оплаты и подключения."
                .to_string(),
        )
    } else if fail_closed_bin {
        Some(
            "Проверьте первые 6–8 цифр карты чуть позже или выберите оплату через App Store (подарочной картой США)."
                .to_string(),
        )
    } else if tier == ReadinessTier::Yellow {
        let warmup_ok = input.warmup_hours.unwrap_or(0) >= 96
            || input.account_age_confirmed_96h == Some(true)
            || matches!(
                input.channel,
                PaymentChannel::AppleIAP | PaymentChannel::GooglePlayIap | PaymentChannel::Api
            );
        let msg = if warmup_ok {
            "Устраните предупреждения перед оплатой: откройте «Чистую комнату» и проверьте совпадение стран."
        } else {
            "Устраните предупреждения перед оплатой: выдержите 96 ч прогрева, откройте «Чистую комнату» и проверьте совпадение стран."
        };
        Some(msg.to_string())
    } else {
        Some("Параметры оплаты согласованы — можно безопасно оформлять подписку.".to_string())
    };

    PaymentReadinessReport {
        score,
        tier,
        axes: PaymentReadinessAxes {
            network_base,
            card_bin,
            geo_billing_parity,
            channel_env_warmup,
        },
        warnings,
        blockers,
        recommended_action,
        requires_matching_billing,
        fail_closed_bin,
        channel: input.channel,
        evaluated_at: input.evaluated_at,
    }
}
