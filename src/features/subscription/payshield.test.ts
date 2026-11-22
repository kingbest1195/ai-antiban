import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { alertDialog, subscription as copy } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";
import type {
  AppStateData,
  BinReport,
  PaymentPassport,
  PaymentReadinessReport,
  PostPaymentQuarantineStatus,
  RiskInterceptPayload,
} from "../../types";
import {
  activatePostPaymentQuarantine,
  checkCardBin,
  evaluatePaymentReadiness,
  getPaymentPassport,
  getPostPaymentQuarantineStatus,
  overridePostPaymentQuarantine,
  savePaymentPassport,
  verifyPaymentPassport,
} from "../../utils/api";
import { resetMockPaymentState } from "../../utils/api/mocks/payment";
import { setMockScenario } from "../../utils/api/mocks/state";
import { AlertWindow } from "../alert";
import {
  AddressCard,
  CardCheck,
  PaymentPassportCard,
  PaymentReadinessCard,
  PostPaymentQuarantineCard,
  QuarantineOverrideModal,
  SubscriptionScreen,
  Verdict,
  evaluateBinInput,
  shouldShowUsTaxFreeAddresses,
} from "./index";

vi.mock("../../ui/Modal", () => ({
  Modal: ({
    open,
    title,
    children,
    footer,
  }: {
    open: boolean;
    title: string;
    children?: unknown;
    footer?: unknown;
  }) =>
    open
      ? createElement("div", { "data-modal": title }, children as never, footer as never)
      : null,
}));

function makeReport(over: Partial<BinReport> = {}): BinReport {
  return {
    binPrefix: "440043",
    status: "ok",
    scheme: "VISA",
    funding: "debit",
    isPrepaid: false,
    isCommercial: false,
    isReloadable: null,
    cardCategory: "CLASSIC",
    countryCode: "KZ",
    issuerName: "KASPI BANK JSC",
    knownFintechLabel: "Kaspi Gold (KZ)",
    source: "localOverlay",
    claudeWebVerdict: "needsMatchingIpBilling",
    warnings: [],
    ...over,
  };
}

function makeReadiness(over: Partial<PaymentReadinessReport> = {}): PaymentReadinessReport {
  return {
    score: 65,
    tier: "yellow",
    axes: {
      networkBase: {
        id: "network_base",
        label: "Стабильность подключения перед оплатой",
        score: 25,
        maxScore: 25,
        status: "ok",
        notes: ["Адрес подключения закреплён"],
      },
      cardBin: {
        id: "card_bin",
        label: "Проверка карты и типа",
        score: 15,
        maxScore: 30,
        status: "warning",
        notes: ["Карта не подтверждена"],
      },
      geoBillingParity: {
        id: "geo_billing_parity",
        label: "Совпадение страны, карты и адреса",
        score: 15,
        maxScore: 25,
        status: "warning",
        notes: ["Страна карты не подтверждена"],
      },
      channelEnvWarmup: {
        id: "channel_env_warmup",
        label: "Способ оплаты, среда и прогрев",
        score: 10,
        maxScore: 20,
        status: "warning",
        notes: ["Оплата вне Чистой комнаты"],
      },
    },
    warnings: ["Возраст аккаунта меньше 96 ч."],
    blockers: [],
    recommendedAction: "Откройте «Чистую комнату» или выберите оплату через App Store.",
    requiresMatchingBilling: true,
    failClosedBin: true,
    channel: "directCard",
    evaluatedAt: 1_760_000_000,
    ...over,
  };
}

describe("Оплата подписки — Progressive Disclosure, UX и инварианты", () => {
  beforeEach(() => {
    setMockScenario("clean");
    resetMockPaymentState();
  });
  afterEach(() => {
    resetMockPaymentState();
  });

  it("1. Контекстный AddressCard: скрывает US-штаты для KZ/SG/KG/AM, показывает для US и App Store, без AVS и дублирующего переключателя", () => {
    expect(shouldShowUsTaxFreeAddresses({ cardCountry: "KZ", scenario: "card" })).toBe(false);
    expect(shouldShowUsTaxFreeAddresses({ cardCountry: "SG", scenario: "card" })).toBe(false);
    expect(shouldShowUsTaxFreeAddresses({ cardCountry: "US", scenario: "card" })).toBe(true);
    expect(shouldShowUsTaxFreeAddresses({ cardCountry: "SG", scenario: "apple_iap" })).toBe(true);

    const expectedNames: Record<string, string> = {
      KZ: "Казахстан",
      SG: "Сингапур",
      KG: "Киргизия",
      AM: "Армения",
    };

    for (const [cc, ruName] of Object.entries(expectedNames)) {
      const html = renderToStaticMarkup(createElement(AddressCard, { cardCountry: cc }));
      expect(html).not.toContain("subs-state-tab-DE");
      expect(html).not.toContain("19801");
      expect(html).not.toContain("97204");
      expect(html).not.toContain("03801");
      expect(html).not.toContain("59101");
      expect(html).not.toContain("99501");
      expect(html).toContain(copy.address.nonUsTitleBanner(ruName));
      expect(html).not.toContain("AVS");
      expect(html).not.toContain("Apple IAP");
      expect(html).not.toContain("Карта по BIN");
    }

    const usHtml = renderToStaticMarkup(createElement(AddressCard, { cardCountry: "US" }));
    for (const code of ["DE", "OR", "NH", "MT", "AK"]) {
      expect(usHtml).toContain(`subs-state-tab-${code}`);
    }
    expect(usHtml).toContain("19801");
    expect(usHtml).toContain("Скопировать адрес");
    expect(usHtml).not.toContain("Stripe");
    expect(usHtml).not.toContain("AVS");

    const iapWithSgCard = renderToStaticMarkup(
      createElement(AddressCard, { cardCountry: "SG", scenario: "apple_iap" }),
    );
    expect(iapWithSgCard).toContain("19801");
    expect(iapWithSgCard).toContain("Wilmington");
  });

  it("2. Безопасная проверка карты: <=8 цифр без обрезки, без debug-чипов и InfoTip, страна через countryName(), понятный тип без LocalOverlay", () => {
    const tooLong16 = evaluateBinInput("4400431234567890", "440043");
    expect(tooLong16.accepted).toBe(false);
    expect(tooLong16.nextValue).toBe("440043");
    expect(tooLong16.error).toBe(copy.card.errors.tooLong);

    const tooLong9 = evaluateBinInput("493724123", "49372412");
    expect(tooLong9.accepted).toBe(false);
    expect(tooLong9.nextValue).toBe("49372412");
    expect(tooLong9.error).toBe(copy.card.errors.tooLong);

    const valid8 = evaluateBinInput("4937 2412", "");
    expect(valid8.accepted).toBe(true);
    expect(valid8.nextValue).toBe("49372412");
    expect(valid8.error).toBeNull();

    const cardCheckHtml = renderToStaticMarkup(createElement(CardCheck, { exitCountry: "SE" }));
    expect(cardCheckHtml).toContain("Ваш VPN: Швеция");
    expect(cardCheckHtml).not.toContain("Ваш шлюз: SE");
    expect(cardCheckHtml).not.toContain("220024");
    expect(cardCheckHtml).not.toContain("483312");
    expect(cardCheckHtml).not.toContain("493724");
    expect(cardCheckHtml).not.toContain("Wayment SG");
    expect(cardCheckHtml).not.toContain("zs-info-i");

    const noRouteHtml = renderToStaticMarkup(createElement(CardCheck, { exitCountry: "" }));
    expect(noRouteHtml).toContain("Маршрут VPN не выбран");
    expect(noRouteHtml).not.toContain("Нидерланды");

    const dashCountryHtml = renderToStaticMarkup(createElement(CardCheck, { country: "--" }));
    expect(dashCountryHtml).toContain("Маршрут VPN не выбран");
    expect(dashCountryHtml).not.toContain("Нидерланды");

    const undefCountryHtml = renderToStaticMarkup(createElement(CardCheck, {}));
    expect(undefCountryHtml).toContain("Маршрут VPN не выбран");
    expect(undefCountryHtml).not.toContain("Нидерланды");

    const sgPrepaidHtml = renderToStaticMarkup(
      createElement(Verdict, {
        report: makeReport({
          binPrefix: "49372412",
          status: "critical",
          funding: "prepaid",
          isPrepaid: true,
          isCommercial: true,
          countryCode: "SG",
          issuerName: "NIUM PTE. LTD.",
          knownFintechLabel: "Wayment / RedotPay (SG Nium)",
          source: "localOverlay",
          claudeWebVerdict: "highKycRisk",
        }),
      }),
    );
    expect(sgPrepaidHtml).toContain("49372412");
    expect(sgPrepaidHtml).toContain("Сингапур");
    expect(sgPrepaidHtml).toContain("Предоплаченная (виртуальная)");
    expect(sgPrepaidHtml).toContain("корпоративная карта");
    expect(sgPrepaidHtml).toContain("Wayment / RedotPay (SG Nium)");
    expect(sgPrepaidHtml).toContain(copy.card.claudeVerdicts.highKycRisk);
    expect(sgPrepaidHtml).not.toContain("Локальный оверлей");
    expect(sgPrepaidHtml).not.toContain("LocalOverlay");
    expect(sgPrepaidHtml).not.toContain("Prepaid");
    expect(sgPrepaidHtml).not.toContain("Commercial");

    const unknownHtml = renderToStaticMarkup(
      createElement(Verdict, {
        report: makeReport({
          binPrefix: "999999",
          status: "unknown",
          funding: "unknown",
          isPrepaid: null,
          isCommercial: null,
          countryCode: null,
          issuerName: null,
          knownFintechLabel: null,
          source: "fallbackUnknown",
          claudeWebVerdict: "highKycRisk",
        }),
      }),
    );
    expect(unknownHtml).toContain(copy.card.failClosedTitle);
    expect(unknownHtml).not.toContain("FallbackUnknown");
    expect(unknownHtml).not.toContain("Fail-Closed");
  });

  it("3. Progressive Disclosure (App Store vs Картой на сайте), <select> на русском, свёрнутые «Подробности проверки» и скрытый PaymentPassportCard", async () => {
    const unknownReadiness = await evaluatePaymentReadiness({
      bin: "999999",
      channel: "directCard",
      billingCountry: "NL",
    });
    expect(unknownReadiness.failClosedBin).toBe(true);
    expect(unknownReadiness.tier).not.toBe("green");

    const appStoreHtml = renderToStaticMarkup(
      createElement(SubscriptionScreen, {
        vpnCountry: "DE",
        onNavigateToPaymentGuide: vi.fn(),
      }),
    );
    expect(appStoreHtml).toContain("Через App Store (рекомендуем)");
    expect(appStoreHtml).toContain("Картой на сайте");
    expect(appStoreHtml).toContain("США — без налога");
    expect(appStoreHtml).toContain("Турция");
    expect(appStoreHtml).toContain("Казахстан");
    expect(appStoreHtml).toContain("Другая страна");
    expect(appStoreHtml).toContain("Адрес в США без налога");
    expect(appStoreHtml).toContain("Т-Банк, СберБанк, Kupikod");
    expect(appStoreHtml).not.toContain(copy.card.title);
    expect(appStoreHtml).not.toContain(copy.readiness.title);
    expect(appStoreHtml).not.toContain(copy.passport.title);
    expect(appStoreHtml).not.toContain('maxLength="2"');

    const cardFlowHtml = renderToStaticMarkup(
      createElement(SubscriptionScreen, {
        vpnCountry: "SE",
        initialFlow: "card",
      }),
    );
    expect(cardFlowHtml).toContain(copy.card.title);
    expect(cardFlowHtml).toContain("Ваш VPN: Швеция");
    expect(cardFlowHtml).toContain(copy.readiness.title);
    expect(cardFlowHtml).toContain("Меньше 4 дней");
    expect(cardFlowHtml).toContain("4 дня и больше");
    expect(cardFlowHtml).not.toContain("subs-state-tab-DE");
    expect(cardFlowHtml).not.toContain("19801");
    expect(cardFlowHtml).not.toContain('maxLength="2"');
    expect(cardFlowHtml).not.toContain(copy.passport.title);

    const trapReport = makeReadiness({
      score: 45,
      tier: "red",
      channel: "googlePayWeb",
      failClosedBin: false,
      blockers: ["Карта из Сингапура, а подключение из Германии."],
    });
    const readinessHtml = renderToStaticMarkup(
      createElement(PaymentReadinessCard, {
        binReport: makeReport({ binPrefix: "493724", countryCode: "SG" }),
        exitCountry: "DE",
        channel: "googlePayWeb",
        initialReport: trapReport,
      }),
    );
    expect(readinessHtml).toContain(copy.readiness.trapTitle);
    expect(readinessHtml).toContain(copy.readiness.tiers.red);
    expect(readinessHtml).toContain(copy.readiness.actionTitle);
    expect(readinessHtml.split(copy.readiness.tiers.red).length - 1).toBe(2); // только Badge и <h4>, без дубля в Banner
    expect(readinessHtml).toContain("Подробности проверки");
    expect(readinessHtml).not.toMatch(/<details[^>]*\bopen\b/);
    expect(readinessHtml).toContain("<select");
    expect(readinessHtml).toContain("Сингапур");
    expect(readinessHtml).toContain("Германия");
    expect(readinessHtml).not.toContain('maxLength="2"');
    expect(readinessHtml).not.toContain("zs-info-i");
    expect(readinessHtml).not.toContain("margin-top:12px");

    const failClosedHtml = renderToStaticMarkup(
      createElement(PaymentReadinessCard, {
        channel: "directCard",
        initialReport: makeReadiness({ score: 65, tier: "yellow", failClosedBin: true }),
      }),
    );
    expect(failClosedHtml).toContain(copy.readiness.failClosedNote);
    expect(failClosedHtml).not.toContain(copy.readiness.tiers.green);
  });

  it("4. CheckoutAlertView: человеческие заголовки и кнопки без PayShield / Чекаут / Persona KYC / BIN", () => {
    const payload: RiskInterceptPayload = {
      id: "chk-1",
      provider: "anthropic",
      host: "checkout.stripe.com",
      report: null,
      ttl_seconds: 60,
      scope: "checkout",
      network_change: null,
      gate_reason: "Вы открываете страницу оплаты через IP Германии, но карта выпущена в Сингапуре.",
      checkout_risk: {
        domain: "checkout.stripe.com",
        score: 35,
        tier: "red",
        reason: "Вы открываете страницу оплаты через IP Германии, но карта выпущена в Сингапуре.",
        blockers: ["Конфликт стран подключения и карты"],
        warnings: [],
        recommendedAction: "Перейдите на оплату через App Store или выровняйте страну карты и VPN.",
      },
      detected_at_ms: 1_760_000_000_000,
      phase: "ready",
    };

    const html = renderToStaticMarkup(
      createElement(AlertWindow, { initialPayload: payload, hideIpMode: false }),
    );
    expect(html).toContain("Оплата приостановлена для вашей безопасности");
    expect(html).toContain("Отменить и проверить");
    expect(html).toContain("Продолжить на свой риск (15 мин)");
    expect(html).toContain("checkout.stripe.com");
    expect(html).toContain("35 / 100");
    expect(html).toContain("zs-btn--primary");
    expect(html).not.toContain("PayShield");
    expect(html).not.toContain("Чекаут");
    expect(html).not.toContain("Persona KYC");
  });

  it("5. 72ч защита маршрута + Памятка прошлой оплаты: скрыта при null, русские страны при сохранении, модалка override", async () => {
    const emptyPassportHtml = renderToStaticMarkup(
      createElement(PaymentPassportCard, { initialPassport: null }),
    );
    expect(emptyPassportHtml).toBe("");

    const binRes = await checkCardBin("440043", "KZ");
    expect(binRes.countryCode).toBe("KZ");

    const activated = await activatePostPaymentQuarantine({
      exitIp: "185.212.102.40",
      exitCountry: "US",
    });
    expect(activated.active).toBe(true);
    expect(activated.remainingHours).toBe(72);

    const status = await getPostPaymentQuarantineStatus();
    expect(status.active).toBe(true);

    const savedPassport: PaymentPassport = await savePaymentPassport({
      profileId: "default",
      binPrefix: "483312",
      cardCountry: "US",
      channel: "directCard",
      billingCountry: "US",
      exitIp: "185.212.102.40",
      exitAsn: 20473,
      paidAt: 1_760_000_000,
    });
    expect((await getPaymentPassport("default"))?.binPrefix).toBe("483312");

    const mismatch = await verifyPaymentPassport("default", {
      binPrefix: "493724",
      cardCountry: "SG",
      billingCountry: "DE",
      exitIp: "1.2.3.4",
    });
    expect(mismatch.matched).toBe(false);
    expect(mismatch.mismatches.length).toBeGreaterThanOrEqual(3);

    const quarantineStatus: PostPaymentQuarantineStatus = {
      active: true,
      remainingHours: 71,
      remainingSecs: 71 * 3600,
      quarantine: activated.quarantine,
      warning: activated.warning,
    };
    const qHtml = renderToStaticMarkup(
      createElement(PostPaymentQuarantineCard, { initialStatus: quarantineStatus }),
    );
    expect(qHtml).toContain("Защита маршрута после оплаты: осталось 71 ч");
    expect(qHtml).toContain(`Зафиксировано: ${countryName("US")}`);
    expect(qHtml).toContain("subs-quarantine-countdown");
    expect(qHtml).not.toContain("Карантин");
    expect(qHtml).not.toContain("карантин");
    expect(qHtml).not.toContain("Persona KYC");

    const passportHtml = renderToStaticMarkup(
      createElement(PaymentPassportCard, { initialPassport: savedPassport, hideIpMode: false }),
    );
    expect(passportHtml).toContain(copy.passport.title);
    expect(passportHtml).toContain("483312");
    expect(passportHtml).toContain(countryName("US"));
    expect(passportHtml).toContain("185.212.102.40");
    expect(passportHtml).toContain(copy.readiness.channels.directCard);
    expect(passportHtml).not.toContain("directCard");
    expect(passportHtml).not.toContain("ASN");
    expect(passportHtml).not.toContain("BIN");
    expect(passportHtml).not.toContain("Zero-PAN");

    const modalHtml = renderToStaticMarkup(
      createElement(QuarantineOverrideModal, {
        open: true,
        remainingHours: 71,
        onCancel: vi.fn(),
        onConfirm: vi.fn(),
      }),
    );
    expect(modalHtml).toContain(copy.quarantine.modalTitle);
    expect(modalHtml).toContain("71 ч");
    expect(modalHtml).toContain(copy.quarantine.modalConfirm);
    expect(modalHtml).not.toContain("карантин");
    expect(modalHtml).not.toContain("Persona KYC");

    const overridden = await overridePostPaymentQuarantine(null, "test");
    expect(overridden.active).toBe(false);
  });

  it("6. Словарь §8.2 и Дизайн-хартия: 0 жаргона, 0 восклицательных знаков и <=1 primary CTA", () => {
    const stateWithProfile: AppStateData = {
      pinned_ip: "185.212.102.40",
      strict_pinning_enabled: true,
      ip_history: {},
      session_allowed_providers: [],
      blocked_providers: [],
      clean_room: {
        active_profile_id: "p-1",
        tainted_ips: {},
        profiles: [
          {
            id: "p-1",
            label: "Claude Work",
            provider: "anthropic",
            browser_engine: "chrome",
            status: "active",
            bound_route_id: null,
            launchpad_step: 4,
            completed_checklist: [],
            created_at: 1,
            last_exit_ip: null,
            last_exit_country: null,
            last_opened_at: null,
            warmup_started_at: null,
          },
        ],
      },
    };

    const appStoreScreen = renderToStaticMarkup(
      createElement(SubscriptionScreen, { state: stateWithProfile, vpnCountry: "US" }),
    );
    const cardScreen = renderToStaticMarkup(
      createElement(SubscriptionScreen, {
        state: stateWithProfile,
        vpnCountry: "SE",
        initialFlow: "card",
      }),
    );

    for (const screenHtml of [appStoreScreen, cardScreen]) {
      const textOnly = screenHtml.replace(/<[^>]+>/g, " ");
      expect(textOnly).not.toContain("!");
      expect((screenHtml.match(/zs-btn--primary/g) ?? []).length).toBeLessThanOrEqual(1);
    }

    const serializeValues = (val: unknown): string => {
      if (typeof val === "string") return val;
      if (typeof val === "function") return String(val);
      if (Array.isArray(val)) return val.map(serializeValues).join("\n");
      if (val && typeof val === "object") return Object.values(val).map(serializeValues).join("\n");
      return "";
    };
    const stripTags = (html: string) => html.replace(/<[^>]+>/g, " ");

    const allCopyAndText = [
      serializeValues(copy),
      serializeValues(alertDialog.checkout),
      stripTags(appStoreScreen),
      stripTags(cardScreen),
    ].join("\n");

    const forbiddenPhrases = [
      "PayShield",
      "Stripe",
      "Zero PCI-DSS",
      "Zero-PAN",
      "эмитент",
      "Prepaid",
      "Commercial",
      "Business",
      "DirectCard",
      "Apple IAP",
      "Persona KYC",
      "Split-IP",
      "биллинг",
      "чекаут",
      "карантин",
      "Fail-Closed",
      "FallbackUnknown",
      "Tainted",
    ];
    for (const term of forbiddenPhrases) {
      expect(allCopyAndText.toLowerCase(), `Не должно быть «${term}»`).not.toContain(
        term.toLowerCase(),
      );
    }
    for (const acronym of [/\bBIN\b/i, /\bCHD\b/i, /\bAVS\b/i, /\bASN\b/i]) {
      expect(allCopyAndText, `Не должно быть ${acronym}`).not.toMatch(acronym);
    }
  });

  it("7. Мок evaluatePaymentReadiness учитывает accountAgeConfirmed96h и не содержит жаргон §8.2 в ответах моков", async () => {
    const young = await evaluatePaymentReadiness({
      bin: "535456",
      billingCountry: "NL",
      channel: "directCard",
      inCleanRoom: true,
      plan: "max",
      accountAgeConfirmed96h: false,
    });
    expect(young.score).toBeLessThan(80);
    expect(young.tier).not.toBe("green");
    expect(young.warnings.concat(young.blockers).join("\n")).toMatch(/96\s*ч/);

    const confirmed = await evaluatePaymentReadiness({
      bin: "535456",
      billingCountry: "NL",
      channel: "directCard",
      inCleanRoom: true,
      plan: "max",
      accountAgeConfirmed96h: true,
    });
    expect(confirmed.score).toBe(100);
    expect(confirmed.tier).toBe("green");

    const unknownBin = await checkCardBin("999999", "NL");
    const ruBin = await checkCardBin("220024", "NL");
    const sgBin = await checkCardBin("493724", "NL");
    const mockOutputs = [
      ...young.warnings,
      ...young.blockers,
      young.recommendedAction ?? "",
      ...Object.values(young.axes).flatMap((a) => [a.label, ...a.notes]),
      ...unknownBin.warnings,
      ...ruBin.warnings,
      ...sgBin.warnings,
    ].join("\n");

    for (const bad of ["Stripe", "чекаут", "биллинг", "Persona KYC", "FallbackUnknown", "fail-closed", "Apple IAP", "BIN"]) {
      expect(mockOutputs.toLowerCase()).not.toContain(bad.toLowerCase());
    }
  });
});
