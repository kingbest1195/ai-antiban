//! Layer 0 deterministic Multi-AI Safe Payment Advisor engine (Scenarios 1–5 + Auto-Demote).

use crate::core::bin_radar::{AiPaymentService, BinRadarSnapshot};
use crate::core::payment_advisor_scenarios::{
    baseline_blacklist_warnings, build_gemini_route, check_rescue_trigger,
    filter_providers_for_route,
};
use crate::core::providers_manifest::EvaluatedProvider;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisorQuery {
    pub target_service: AiPaymentService,
    #[serde(default)]
    pub has_iphone_apple_id: bool,
    #[serde(default)]
    pub available_bin_prefix: Option<String>,
    #[serde(default)]
    pub payment_rails: Vec<PaymentRail>,
    #[serde(default)]
    pub willing_to_warmup_96h: bool,
    #[serde(default)]
    pub google_payments_country: Option<String>,
    #[serde(default)]
    pub is_new_google_account: Option<bool>,
    #[serde(default)]
    pub network_state: AdvisorNetworkContext,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentRail {
    RubSbp,
    CryptoUsdt,
    ForeignBankCard,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisorNetworkContext {
    #[serde(default)]
    pub exit_country: Option<String>,
    #[serde(default)]
    pub trust_score: u8,
    #[serde(default)]
    pub clean_room_ready: bool,
    #[serde(default)]
    pub is_zastava_key_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisorPlan {
    pub primary: AdvisorRoute,
    pub fallbacks: Vec<AdvisorRoute>,
    pub blocked_red_flags: Vec<BlockedRouteWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisorRoute {
    pub route_id: String,
    pub title: String,
    pub kyc_risk_tier: KycRiskTier,
    pub estimated_fees: String,
    pub provider_ids: Vec<String>,
    pub checklist: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub demoted_provider_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockedRouteWarning {
    pub route_id: String,
    pub title: String,
    pub kyc_risk_tier: KycRiskTier,
    pub reason: String,
    pub explanation: String,
    #[serde(default)]
    pub rescue_route_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KycRiskTier {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Default)]
pub struct AdvisorBinContext {
    pub bin_prefix: String,
    pub country_code: Option<String>,
    pub is_prepaid: bool,
    pub is_commercial: bool,
    pub is_sanctioned_or_blocked: bool,
    pub is_toxic_sg_or_fintech: bool,
    pub fintech_label: Option<String>,
}

const KNOWN_TOXIC_PREFIXES: &[(&str, &str, &str)] = &[
    ("493724", "SG", "Wayment / Nium (SG)"),
    ("220441", "RU", "Antarctic Wallet (Mir)"),
    ("404038", "HK", "RedotPay (HK)"),
    ("474447", "HK", "RedotPay (HK)"),
];

fn infer_bin_context(
    raw_bin: Option<&str>,
    provided: Option<&AdvisorBinContext>,
) -> Option<AdvisorBinContext> {
    if let Some(ctx) = provided {
        return Some(ctx.clone());
    }
    let clean = raw_bin?.trim();
    if clean.len() < 6 || !clean.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let six = &clean[..6];
    if let Some((_, cc, label)) = KNOWN_TOXIC_PREFIXES.iter().find(|(p, _, _)| *p == six) {
        return Some(AdvisorBinContext {
            bin_prefix: clean.to_string(),
            country_code: Some((*cc).to_string()),
            is_prepaid: true,
            is_commercial: *cc == "SG",
            is_sanctioned_or_blocked: matches!(*cc, "RU" | "BY" | "HK"),
            is_toxic_sg_or_fintech: true,
            fintech_label: Some((*label).to_string()),
        });
    }
    None
}

fn build_apple_iap_route(
    query: &AdvisorQuery,
    manifest: &[EvaluatedProvider],
    is_rescue: bool,
) -> AdvisorRoute {
    let (provider_ids, demoted_provider_ids, mut warnings) = filter_providers_for_route(
        &["tbank", "sberbank", "kupikod"],
        manifest,
        query.target_service,
    );

    if !query.has_iphone_apple_id {
        warnings.push(
            "Нужен iPhone или iPad с отдельным аккаунтом Apple (регион США) только для покупок."
                .to_string(),
        );
    }

    let title = if is_rescue {
        "Безопасный обход через App Store (подарочная карта США)".to_string()
    } else {
        "Оплата подписки через App Store (отдельный аккаунт США)".to_string()
    };

    let checklist = vec![
        "Заведите отдельный аккаунт Apple (регион США) только для раздела покупок и подписок, не меняйте основной iCloud."
            .to_string(),
        "Укажите безналоговый адрес США (штат OR 97204, DE 19801 или MT 59101), чтобы не переплачивать налог штата."
            .to_string(),
        "Т-Банк («Платежи → Все / Игры → Apple (США)», номиналы $2–$100): не выбирайте регион «Россия» с наценкой +60%; сервис выступает витриной посредника с возможными задержками возврата — начните с теста $2 или $5."
            .to_string(),
        "СберБанк Онлайн («Платежи → Отдых и развлечения → Онлайн-сервисы / Игры → Apple Card», США, от $2): курс близок к ЦБ РФ, приходит банковский чек."
            .to_string(),
        "Kupikod (если банки недоступны): наценка около 25–34%, возврат падает на баланс Kupicoin, окно претензий строго 2 часа, нужна непрерывная видеозапись экрана от оплаты до активации и снятие галочки «Пропуск Kupikod»."
            .to_string(),
        "Не покупайте коды и подписки на Plati.market, Avito, GGSel, Ozon, WB или в случайных Telegram-ботах — это ведёт к блокировке аккаунта Apple."
            .to_string(),
    ];

    AdvisorRoute {
        route_id: "apple_iap_us_gift".to_string(),
        title,
        kyc_risk_tier: KycRiskTier::Minimal,
        estimated_fees: "Т-Банк и СберБанк Онлайн — близко к курсу банка; Kupikod — наценка 25–34%"
            .to_string(),
        provider_ids,
        checklist,
        warnings,
        demoted_provider_ids,
    }
}

fn build_direct_web_route(
    query: &AdvisorQuery,
    manifest: &[EvaluatedProvider],
    bin_ctx: Option<&AdvisorBinContext>,
) -> AdvisorRoute {
    let has_foreign_card = query.payment_rails.contains(&PaymentRail::ForeignBankCard)
        && bin_ctx.is_some_and(|b| !b.is_prepaid && !b.is_toxic_sg_or_fintech);

    let (provider_ids, demoted_provider_ids, mut warnings) = filter_providers_for_route(
        &["wanttopay", "platipomiru"],
        manifest,
        query.target_service,
    );

    let mut tier = if has_foreign_card {
        KycRiskTier::Low
    } else {
        KycRiskTier::Medium
    };

    if !query.network_state.clean_room_ready {
        tier = tier.max(KycRiskTier::High);
        warnings.push(
            "Оплата вне «Чистой комнаты»: откройте изолированный профиль браузера перед вводом карты."
                .to_string(),
        );
    }
    if !query.network_state.is_zastava_key_active {
        warnings.push(
            "Маршрут Заставы не активен: убедитесь, что страницы оплаты идут по одному стабильному IP с сайтом ИИ."
                .to_string(),
        );
    }
    if !query.willing_to_warmup_96h {
        tier = tier.max(KycRiskTier::High);
        warnings.push(
            "Без 96 часов (4 дней) прогрева на бесплатном тарифе риск проверки документов при оплате резко выше."
                .to_string(),
        );
    }

    let mut checklist = vec![
        "Запустите браузер строго внутри «Чистой комнаты» со стабильным защищённым маршрутом Заставы."
            .to_string(),
        "Выдержите 96 часов (4 дня) обычной работы на бесплатном тарифе перед первой оплатой."
            .to_string(),
        "Обеспечьте тройное совпадение: страна подключения == страна карты == страна адреса оплаты."
            .to_string(),
        "После оплаты включите 72-часовую защиту маршрута: не меняйте страну, IP и профиль браузера 3 дня."
            .to_string(),
        "WantToPay: используйте только тарифы Easy или Smart (избегайте дешёвой предоплаченной карты), строго IP и адрес США; учтите комиссию $0.25–$1.00 за каждую отклонённую попытку."
            .to_string(),
        "Плати по миру: подходит только тариф «Для подписок» (карты для путешествий не проходят), строго IP и адрес США."
            .to_string(),
    ];

    if query.target_service == AiPaymentService::Cursor {
        checklist.push(
            "Для Cursor не создавайте цепочки пробных аккаунтов на одном устройстве: редактор сохраняет локальный идентификатор machineId и devDeviceId."
                .to_string(),
        );
    } else if query.target_service == AiPaymentService::Chatgpt {
        checklist.push(
            "Для ChatGPT не меняйте страну подключения до и в течение 72 часов после оплаты, чтобы не получить отмену подписки."
                .to_string(),
        );
    }

    AdvisorRoute {
        route_id: "direct_web_card".to_string(),
        title: "Прямая оплата картой на сайте (с защищённым маршрутом)".to_string(),
        kyc_risk_tier: tier,
        estimated_fees: "WantToPay: выпуск 25–40%, продление 10–25%, отказ $0.25–$1.00; Плати по миру: по тарифу «Для подписок»".to_string(),
        provider_ids,
        checklist,
        warnings,
        demoted_provider_ids,
    }
}

/// Pure Layer 0 deterministic planner across all 5 scenarios + Per-Service Auto-Demote.
pub fn build_advisor_plan(
    query: &AdvisorQuery,
    manifest: &[EvaluatedProvider],
    snapshot: &BinRadarSnapshot,
    provided_bin: Option<&AdvisorBinContext>,
) -> AdvisorPlan {
    let bin_ctx = infer_bin_context(query.available_bin_prefix.as_deref(), provided_bin);
    let mut blocked_red_flags = Vec::new();

    if let Some(rescue_warn) = check_rescue_trigger(query, snapshot, bin_ctx.as_ref()) {
        blocked_red_flags.push(rescue_warn);
    }

    let rescue_active = !blocked_red_flags.is_empty();
    let mut fallbacks = Vec::new();

    let primary = match query.target_service {
        AiPaymentService::Gemini => {
            let gem = build_gemini_route(query, manifest, bin_ctx.as_ref(), &mut blocked_red_flags);
            fallbacks.push(build_direct_web_route(query, manifest, bin_ctx.as_ref()));
            gem
        }
        AiPaymentService::Cursor => {
            // Cursor supports web payment only (no Apple IAP).
            build_direct_web_route(query, manifest, bin_ctx.as_ref())
        }
        AiPaymentService::ClaudePro | AiPaymentService::ClaudeMax | AiPaymentService::Chatgpt => {
            if rescue_active {
                let rescue_apple = build_apple_iap_route(query, manifest, true);
                fallbacks.push(build_direct_web_route(query, manifest, bin_ctx.as_ref()));
                rescue_apple
            } else if query.has_iphone_apple_id {
                let apple = build_apple_iap_route(query, manifest, false);
                fallbacks.push(build_direct_web_route(query, manifest, bin_ctx.as_ref()));
                apple
            } else {
                let web = build_direct_web_route(query, manifest, bin_ctx.as_ref());
                fallbacks.push(build_apple_iap_route(query, manifest, false));
                web
            }
        }
    };

    blocked_red_flags.extend(baseline_blacklist_warnings());

    AdvisorPlan {
        primary,
        fallbacks,
        blocked_red_flags,
    }
}
