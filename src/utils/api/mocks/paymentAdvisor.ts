import type {
  AdvisorPlan,
  AdvisorQuery,
  AiPaymentService,
  BinRadarLookupStats,
  BinRadarReport,
  BlockedRouteWarning,
  EvaluatedProvider,
  EvaluatedProvidersManifest,
  ProviderStatus,
} from "../../../types";

const MOCK_STATS_DB: Array<{
  prefix6: string;
  service: AiPaymentService;
  n14: number;
  success: number;
  decline: number;
  kyc: number;
  ban: number;
}> = [
  { prefix6: "493724", service: "claude_pro", n14: 34, success: 14.7, decline: 20.6, kyc: 52.9, ban: 11.8 },
  { prefix6: "493724", service: "chatgpt", n14: 21, success: 23.8, decline: 23.8, kyc: 42.9, ban: 9.5 },
  { prefix6: "493724", service: "gemini", n14: 18, success: 27.8, decline: 22.2, kyc: 38.9, ban: 11.1 },
  { prefix6: "220441", service: "claude_pro", n14: 25, success: 0, decline: 28.0, kyc: 48.0, ban: 24.0 },
  { prefix6: "404038", service: "claude_pro", n14: 22, success: 9.1, decline: 18.2, kyc: 54.5, ban: 18.2 },
  { prefix6: "446614", service: "claude_pro", n14: 42, success: 78.6, decline: 9.5, kyc: 9.5, ban: 2.4 },
  { prefix6: "446614", service: "chatgpt", n14: 28, success: 82.1, decline: 7.1, kyc: 7.1, ban: 3.7 },
  { prefix6: "446614", service: "cursor", n14: 19, success: 78.9, decline: 10.5, kyc: 5.3, ban: 5.3 },
  { prefix6: "446614", service: "gemini", n14: 16, success: 75.0, decline: 12.5, kyc: 6.3, ban: 6.2 },
  { prefix6: "483312", service: "claude_pro", n14: 31, success: 74.2, decline: 12.9, kyc: 9.7, ban: 3.2 },
  { prefix6: "485953", service: "claude_pro", n14: 19, success: 68.4, decline: 15.8, kyc: 10.5, ban: 5.3 },
  { prefix6: "440043", service: "claude_pro", n14: 17, success: 64.7, decline: 17.6, kyc: 11.8, ban: 5.9 },
  { prefix6: "537872", service: "cursor", n14: 3, success: 100.0, decline: 0, kyc: 0, ban: 0 },
];

let mockOptIn = false;

export function setMockBinRadarOptIn(enabled: boolean): boolean {
  mockOptIn = enabled;
  return mockOptIn;
}

export function mockGetBinRadarStats(
  binPrefix: string,
  service: AiPaymentService = "claude_pro",
): BinRadarLookupStats {
  const clean = binPrefix.replace(/[\s-]+/g, "").slice(0, 8);
  const six = clean.slice(0, 6);
  const found = MOCK_STATS_DB.find((r) => r.prefix6 === six && r.service === service);
  if (!found || found.n14 < 5) {
    return {
      binPrefix: clean,
      service,
      status: "insufficient_data",
      sampleSize14d: found?.n14 ?? 0,
      sampleSize30d: found?.n14 ?? 0,
      window14d: null,
      window30d: null,
      riskPct14d: null,
      criticalWarning: false,
      summaryRu: "Статистика оплат: недостаточно данных (меньше 5 отзывов)",
    };
  }
  const riskPct = Math.round((found.kyc + found.ban) * 10) / 10;
  const criticalWarning = found.n14 >= 15 && riskPct > 40;
  return {
    binPrefix: clean,
    service,
    status: criticalWarning ? "critical" : "sufficient",
    sampleSize14d: found.n14,
    sampleSize30d: found.n14,
    window14d: {
      n: found.n14,
      success_pct: found.success,
      soft_decline_pct: found.decline,
      instant_kyc_pct: found.kyc,
      instant_ban_pct: found.ban,
    },
    window30d: null,
    riskPct14d: riskPct,
    criticalWarning,
    summaryRu: `Успех ${Math.round(found.success)}% · Проверка паспорта/отказ ${Math.round(riskPct)}% · Отклонено ${Math.round(found.decline)}% · За 14 дн., n=${found.n14}`,
  };
}

export function mockGetProvidersManifest(): EvaluatedProvidersManifest {
  const makeProvider = (
    id: string,
    name: string,
    category: string,
    tier: string,
    prefixes: string[],
    rails: string[],
    services: AiPaymentService[],
    fees: string,
    warnings: string[],
    affiliateUrl: string | null = null,
  ): EvaluatedProvider => ({
    entry: {
      id,
      name,
      category,
      tier,
      status: "active" as ProviderStatus,
      known_bin_prefixes: prefixes,
      supported_rails: rails,
      supported_services: services,
      fees_summary: fees,
      warnings_ru: warnings,
      affiliate_url: affiliateUrl,
    },
    effectiveStatus: "active",
    globalDemoted: false,
    perService: services.map((service) => ({
      service,
      status: "active" as ProviderStatus,
      rate14d: 0.1,
      sampleSize14d: 20,
      reasonRu: null,
    })),
    demoteReasonRu: null,
  });

  return {
    schemaVersion: 1,
    generatedAtUtc: "2026-11-23T12:00:00Z",
    providers: [
      makeProvider("tbank", "Т-Банк (подарочная карта США)", "apple_gift_card", "tier1_iap", [], ["rub_sbp"], ["claude_pro", "claude_max", "chatgpt"], "По курсу банка (номиналы $2–$100)", ["Начинайте с теста $2 или $5 и выбирайте регион США."]),
      makeProvider("sberbank", "СберБанк Онлайн (Apple Card США)", "apple_gift_card", "tier1_iap", [], ["rub_sbp"], ["claude_pro", "claude_max", "chatgpt"], "По курсу, близкому к ЦБ РФ ($2–$500)", ["Отдельный US Apple ID для покупок."]),
      makeProvider("kupikod", "Kupikod", "apple_gift_card", "tier1_iap", [], ["rub_sbp", "crypto_usdt"], ["claude_pro", "claude_max", "chatgpt"], "Наценка 25–34%, возврат в Kupicoin", ["Отключите «Пропуск Kupikod», записывайте видео, окно претензий 2 ч."], "https://kupikod.com/"),
      makeProvider("wanttopay", "WantToPay", "virtual_card", "tier2_conditional", ["48331200"], ["rub_sbp", "crypto_usdt"], ["claude_pro", "claude_max", "chatgpt", "cursor", "gemini"], "25–40% выпуск, 10–25% продление, отказ $0.25–$1.00", ["Только тарифы Easy / Smart с IP и адресом США."], "https://telegram.me/WantToPayBot?start=w17851188--ERIEX"),
      makeProvider("platipomiru", "Плати по миру", "virtual_card", "tier2_conditional", ["44661400"], ["rub_sbp"], ["claude_pro", "claude_max", "chatgpt", "cursor", "gemini"], "По тарифу «Для подписок» через СБП", ["Только тариф «Для подписок» с IP и адресом США."], "https://platipomiru.com/?code=UXCAF1Z9"),
    ],
    blacklist: [
      { id: "antarctic-wallet", name: "Antarctic Wallet", reason_ru: "Частые запросы паспорта и заморозки." },
      { id: "altyn-wallet", name: "Altyn Wallet", reason_ru: "Высокий риск блокировки и проверки документов." },
      { id: "wayment", name: "Wayment", reason_ru: "Конфликт страны карты и подключения." },
      { id: "gray-marketplaces", name: "Plati.market / Avito / GGSel", reason_ru: "Риск блокировки Apple ID и аккаунта Google." },
    ],
  };
}

export function mockGetPaymentAdvice(query: AdvisorQuery): AdvisorPlan {
  const cleanBin = query.available_bin_prefix?.replace(/[\s-]+/g, "") ?? "";
  const radar = cleanBin.length >= 6 ? mockGetBinRadarStats(cleanBin, query.target_service) : null;
  const isToxic =
    cleanBin.startsWith("493724") ||
    cleanBin.startsWith("220441") ||
    cleanBin.startsWith("404038") ||
    Boolean(radar?.criticalWarning);

  const appleRoute = {
    route_id: "apple_iap_us_gift",
    title: isToxic
      ? "Безопасный обход через App Store (подарочная карта США)"
      : "Оплата подписки через App Store (отдельный аккаунт США)",
    kyc_risk_tier: "minimal" as const,
    estimated_fees: "Т-Банк / СберБанк Онлайн по курсу банка; Kupikod +25–34%",
    provider_ids: ["tbank", "sberbank", "kupikod"],
    checklist: [
      "Отдельный аккаунт Apple (США) с безналоговым адресом OR 97204 / DE 19801 / MT 59101.",
      "Т-Банк («Платежи → Все / Игры → Apple (США)») или СберБанк Онлайн — начинайте с теста $2 или $5.",
      "Kupikod: снимите галочку «Пропуск Kupikod», ведите видеозапись экрана, окно претензий 2 ч, возврат в Kupicoin.",
    ],
    warnings: [],
    demoted_provider_ids: [],
  };

  const webRoute = {
    route_id: "direct_web_card",
    title: "Прямая оплата картой на сайте (с защищённым маршрутом)",
    kyc_risk_tier: query.willing_to_warmup_96h && query.network_state.clean_room_ready ? ("medium" as const) : ("high" as const),
    estimated_fees: "WantToPay: 25–40% выпуск, отказ $0.25–$1.00; Плати по миру: тариф «Для подписок»",
    provider_ids: ["wanttopay", "platipomiru"],
    checklist: [
      "Запуск строго внутри «Чистой комнаты» с защищённым маршрутом Заставы.",
      "Прогрев 96 часов на бесплатном тарифе, тройное совпадение (подключение == карта == адрес), 72 часа защиты маршрута после оплаты.",
      ...(query.target_service === "cursor"
        ? ["Для Cursor не создавайте цепочки пробных аккаунтов на одном устройстве (machineId / devDeviceId)."]
        : []),
    ],
    warnings: query.willing_to_warmup_96h ? [] : ["Рекомендуется выдержать 96 часов прогрева до оплаты."],
    demoted_provider_ids: [],
  };

  const blocked: BlockedRouteWarning[] = isToxic
    ? [
        {
          route_id: "blocked_web_card_rescue",
          title: "Опасный путь: оплата на сайте выбранной картой",
          kyc_risk_tier: "critical",
          reason: "Высокий риск мгновенного запроса паспорта или блокировки.",
          explanation:
            "Оплата через Google Pay не скрывает карту от платёжной системы сайта: она передаёт реальную страну и предоплаченный/корпоративный тип карты. Перейдите на оплату через App Store (Т-Банк / СберБанк Онлайн / Kupikod).",
          rescue_route_id: "apple_iap_us_gift",
        },
      ]
    : [];

  if (query.target_service === "gemini") {
    const gpCc = query.google_payments_country?.trim().toUpperCase() ?? "";
    const exitCc = query.network_state.exit_country?.trim().toUpperCase() ?? "";
    const hasConflict = gpCc === "RU" || (gpCc !== "" && exitCc !== "" && gpCc !== exitCc);
    if (hasConflict) {
      blocked.push({
        route_id: "google_payments_country_lock",
        title: "Конфликт страны платёжного профиля Google (OR-CCSEH-21 / OR-HDT-16)",
        kyc_risk_tier: "critical" as const,
        reason: "Страна платёжного профиля Google не совпадает с подключением или привязана к России.",
        explanation:
          "Смена страны в Google Payments накладывает 24-часовой запрет изменений; для старого аккаунта надёжнее завести отдельный профиль в «Чистой комнате» без одноразовых SMS.",
        rescue_route_id: null,
      });
    }
    return {
      primary: {
        route_id: "gemini_google_ecosystem",
        title: "Экосистема Google: Gemini, AI Studio и Antigravity",
        kyc_risk_tier: hasConflict ? ("critical" as const) : ("medium" as const),
        estimated_fees: "По тарифу Google (Google One AI Pro / Google Cloud)",
        provider_ids: ["wanttopay", "platipomiru"],
        checklist: [
          "Профиль в «Чистой комнате» без российских cookie (исключает экран «User location is not supported»).",
          "Google Payments Profile Lock: страна профиля Google == страна карты == страна подключения (смена страны даёт 24-часовой холд).",
          "Для AI Studio квоты привязаны к проекту Google Cloud — не делайте банковский возврат (chargeback) без закрытия спора в поддержке.",
        ],
        warnings: [],
        demoted_provider_ids: [],
      },
      fallbacks: [webRoute],
      blocked_red_flags: blocked,
    };
  }

  if (query.target_service === "cursor") {
    return { primary: webRoute, fallbacks: [], blocked_red_flags: blocked };
  }

  if (isToxic || query.has_iphone_apple_id) {
    return { primary: appleRoute, fallbacks: [webRoute], blocked_red_flags: blocked };
  }
  return { primary: webRoute, fallbacks: [appleRoute], blocked_red_flags: blocked };
}

export function mockSubmitBinRadarReport(raw: Record<string, unknown>): BinRadarReport {
  if (!mockOptIn) {
    throw new Error("Участие в анонимной статистике отключено в настройках.");
  }
  const allowed = new Set([
    "bin_prefix",
    "service",
    "channel",
    "geo_match",
    "warmup_bucket",
    "outcome",
    "client_version",
  ]);
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) {
      throw new Error(`Отклонено лишнее поле: ${key}`);
    }
  }
  const prefix = String(raw.bin_prefix ?? "");
  if (!/^\d{8}$/.test(prefix)) {
    throw new Error("Требуются ровно 8 первых цифр карты без остального номера.");
  }
  return raw as unknown as BinRadarReport;
}
