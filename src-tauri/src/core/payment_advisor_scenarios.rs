//! Layer 0 scenario helpers for Gemini ecosystem, Rescue Flow, and provider filtering.

use crate::core::bin_radar::{AiPaymentService, BinRadarSnapshot, lookup_bin_radar_stats};
use crate::core::country::{format_country_ru, normalize_country_code};
use crate::core::payment_advisor::{
    AdvisorBinContext, AdvisorQuery, AdvisorRoute, BlockedRouteWarning, KycRiskTier,
};
use crate::core::providers_manifest::{EvaluatedProvider, ProviderStatus};

fn provider_status_for_service(
    provider: &EvaluatedProvider,
    service: AiPaymentService,
) -> (ProviderStatus, Option<String>) {
    if let Some(svc) = provider.per_service.iter().find(|s| s.service == service) {
        return (svc.status, svc.reason_ru.clone());
    }
    (provider.effective_status, provider.demote_reason_ru.clone())
}

pub(crate) fn filter_providers_for_route(
    candidates: &[&str],
    manifest: &[EvaluatedProvider],
    service: AiPaymentService,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut active_ids = Vec::new();
    let mut demoted_ids = Vec::new();
    let mut warnings = Vec::new();

    for id in candidates {
        if let Some(p) = manifest.iter().find(|m| m.entry.id == *id) {
            let (status, reason) = provider_status_for_service(p, service);
            match status {
                ProviderStatus::Active => active_ids.push((*id).to_string()),
                ProviderStatus::DemotedWarning => {
                    demoted_ids.push((*id).to_string());
                    if let Some(r) = reason {
                        warnings.push(format!("{}: {}", p.entry.name, r));
                    }
                }
                ProviderStatus::Blacklist => {
                    demoted_ids.push((*id).to_string());
                    warnings.push(format!(
                        "{}: временно исключён по статистике отказов и проверок за 14 дней",
                        p.entry.name
                    ));
                }
            }
        } else {
            active_ids.push((*id).to_string());
        }
    }
    (active_ids, demoted_ids, warnings)
}

pub(crate) fn build_gemini_route(
    query: &AdvisorQuery,
    manifest: &[EvaluatedProvider],
    bin_ctx: Option<&AdvisorBinContext>,
    blocked: &mut Vec<BlockedRouteWarning>,
) -> AdvisorRoute {
    let (provider_ids, demoted_provider_ids, mut warnings) = filter_providers_for_route(
        &["wanttopay", "platipomiru"],
        manifest,
        query.target_service,
    );

    let exit_cc = query
        .network_state
        .exit_country
        .as_deref()
        .map(normalize_country_code)
        .unwrap_or_default();
    let gp_cc = query
        .google_payments_country
        .as_deref()
        .map(normalize_country_code)
        .unwrap_or_default();
    let card_cc = bin_ctx
        .and_then(|b| b.country_code.as_deref())
        .map(normalize_country_code)
        .unwrap_or_default();

    let mut tier = KycRiskTier::Medium;
    let has_ru_profile = gp_cc == "RU";
    let profile_card_mismatch = !gp_cc.is_empty() && !card_cc.is_empty() && gp_cc != card_cc;
    let profile_exit_mismatch = !gp_cc.is_empty() && !exit_cc.is_empty() && gp_cc != exit_cc;
    let card_exit_mismatch = !card_cc.is_empty() && !exit_cc.is_empty() && card_cc != exit_cc;

    if has_ru_profile || profile_card_mismatch || profile_exit_mismatch || card_exit_mismatch {
        tier = KycRiskTier::Critical;
        let detail = if has_ru_profile {
            "Платёжный профиль Google привязан к России — при добавлении зарубежной карты сработает холд OR-CCSEH-21 / OR-HDT-16 / OR-CBAT-15 с требованием не-РФ документов."
                .to_string()
        } else {
            format!(
                "Нарушено правило совпадения Google Payments (профиль: {}, карта: {}, подключение: {}) — высокий риск кода ошибки OR-CCSEH-21 или OR-HDT-16.",
                if gp_cc.is_empty() {
                    "не указан".to_string()
                } else {
                    format_country_ru(&gp_cc)
                },
                if card_cc.is_empty() {
                    "не указана".to_string()
                } else {
                    format_country_ru(&card_cc)
                },
                if exit_cc.is_empty() {
                    "не определено".to_string()
                } else {
                    format_country_ru(&exit_cc)
                },
            )
        };
        warnings.push(detail.clone());
        blocked.push(BlockedRouteWarning {
            route_id: "google_payments_country_lock".to_string(),
            title: "Конфликт страны платёжного профиля Google (OR-CCSEH-21 / OR-HDT-16)".to_string(),
            kyc_risk_tier: KycRiskTier::Critical,
            reason: detail,
            explanation: "Смена страны в существующем профиле Google Payments требует удаления всех старых карт и накладывает 24-часовой запрет на изменения. Для аккаунта со старой историей входов надёжнее создать новый профиль Google внутри «Чистой комнаты» с постоянным номером (без одноразовых виртуальных SMS)."
                .to_string(),
            rescue_route_id: None,
        });
    }

    if query.is_new_google_account == Some(true)
        && bin_ctx.is_none_or(|b| b.is_prepaid || b.is_toxic_sg_or_fintech)
    {
        tier = tier.max(KycRiskTier::High);
        warnings.push(
            "Свежий аккаунт Google часто замораживается при моментальной привязке предоплаченной карты ещё до первого вызова AI Studio API — лучше использовать именную зарубежную дебетовую/кредитную карту или проверенный маршрут США после прогрева и подтверждения возраста 18+."
                .to_string(),
        );
    }

    let checklist = vec![
        "Запускайте Gemini и AI Studio в отдельном профиле «Чистой комнаты» без российских cookie, чтобы не получить экран «User location is not supported»."
            .to_string(),
        "Соблюдайте правило Google Payments Profile Lock: страна платёжного профиля Google == страна карты == страна подключения."
            .to_string(),
        "Предупреждение о 24-часовом холде: после смены страны в профиле Google Payments нельзя менять платёжные методы 24 часа; старый РФ-аккаунт лучше не смешивать с новой оплатой."
            .to_string(),
        "Для подписки Google One AI Pro / Antigravity подойдёт профиль в «Чистой комнате» или оплата через Google Play с тем же регионом; не покупайте «инвайты в семейные группы» на Plati.market и GGSel."
            .to_string(),
        "Для AI Studio / Vertex AI квоты привязаны к проекту Google Cloud: ограничивайте область действия API-ключа и никогда не делайте банковский возврат платежа (chargeback) без закрытия спора через поддержку Google Cloud."
            .to_string(),
    ];

    AdvisorRoute {
        route_id: "gemini_google_ecosystem".to_string(),
        title: "Экосистема Google: Gemini, AI Studio и Antigravity".to_string(),
        kyc_risk_tier: tier,
        estimated_fees: "Оплата напрямую по тарифу Google (или Google Play в выбранном регионе)"
            .to_string(),
        provider_ids,
        checklist,
        warnings,
        demoted_provider_ids,
    }
}

pub(crate) fn check_rescue_trigger(
    query: &AdvisorQuery,
    snapshot: &BinRadarSnapshot,
    bin_ctx: Option<&AdvisorBinContext>,
) -> Option<BlockedRouteWarning> {
    let bin = bin_ctx?;
    let exit_cc = query
        .network_state
        .exit_country
        .as_deref()
        .map(normalize_country_code)
        .unwrap_or_default();
    let card_cc = bin
        .country_code
        .as_deref()
        .map(normalize_country_code)
        .unwrap_or_default();

    let radar = lookup_bin_radar_stats(snapshot, &bin.bin_prefix, query.target_service);
    let sg_mismatch = card_cc == "SG" && !exit_cc.is_empty() && exit_cc != "SG";
    let is_rescue = bin.is_toxic_sg_or_fintech
        || bin.is_sanctioned_or_blocked
        || sg_mismatch
        || radar.critical_warning;

    if !is_rescue {
        return None;
    }

    let label = bin.fintech_label.as_deref().unwrap_or("указанная карта");
    let card_desc = if card_cc.is_empty() {
        "другой страны".to_string()
    } else {
        format_country_ru(&card_cc)
    };
    let exit_desc = if exit_cc.is_empty() {
        "текущего подключения".to_string()
    } else {
        format_country_ru(&exit_cc)
    };

    let rescue_route_id = if query.target_service == AiPaymentService::Cursor {
        None
    } else {
        Some("apple_iap_us_gift".to_string())
    };

    Some(BlockedRouteWarning {
        route_id: "blocked_web_card_rescue".to_string(),
        title: format!("Опасный путь: оплата на сайте картой «{label}»"),
        kyc_risk_tier: KycRiskTier::Critical,
        reason: format!(
            "Высокий риск мгновенного запроса паспорта или блокировки ({card_desc} при подключении через {exit_desc})."
        ),
        explanation: "Оплата через Google Pay не скрывает карту от платёжной системы сайта: Google Pay передаёт реальную страну карты и её предоплаченный/корпоративный тип. Не пытайтесь повторять оплату этой картой несколько раз на одном аккаунте — используйте безопасный обход через App Store (Т-Банк / СберБанк Онлайн / Kupikod) или смените карту."
            .to_string(),
        rescue_route_id,
    })
}

pub(crate) fn baseline_blacklist_warnings() -> Vec<BlockedRouteWarning> {
    vec![BlockedRouteWarning {
        route_id: "blacklist_grey_cards_and_p2p".to_string(),
        title: "Чёрный список: Antarctic Wallet, Altyn Wallet, Wayment, e.pn, RedotPay, PST.net, FlexCard, Plati.market / Avito / GGSel".to_string(),
        kyc_risk_tier: KycRiskTier::Critical,
        reason: "Массовые отказы, запросы паспорта, заморозки счетов и блокировки аккаунтов Apple/Google."
            .to_string(),
        explanation: "Не используйте карты из чёрного списка и не покупайте подписки/гифт-коды у серых продавцов."
            .to_string(),
        rescue_route_id: Some("apple_iap_us_gift".to_string()),
    }]
}
