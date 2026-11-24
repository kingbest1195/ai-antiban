import type {
  ActivateQuarantineParams,
  AxisScore,
  EvaluatePaymentReadinessParams,
  PassportVerificationResult,
  PaymentChannel,
  PaymentPassport,
  PaymentReadinessReport,
  PostPaymentQuarantine,
  PostPaymentQuarantineStatus,
  ReadinessTier,
  RenewalCheckInput,
} from "../../../types";
import { countryName } from "../../../shared/lib/country";
import { clearMockPendingAlert } from "./alert";
import { mockCheckCardBin, validateMockBinPrefix } from "./paymentBinOverlay";
import { emitMock, mockFlags, mockState } from "./state";

export { mockCheckCardBin, validateMockBinPrefix };

export const MOCK_OPEN_PAYMENT_CHECK_EVENT = "mock-payshield-open-payment-check";
export const POST_PAYMENT_QUARANTINE_SECS = 72 * 3600;

const mockPassports = new Map<string, PaymentPassport>();

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function normCc(cc?: string | null): string {
  return (cc ?? "").trim().toUpperCase();
}

export function resetMockPaymentState(): void {
  mockPassports.clear();
  if (mockState.clean_room) {
    mockState.clean_room.global_post_payment_quarantine = null;
    for (const p of mockState.clean_room.profiles) {
      p.post_payment_quarantine = null;
    }
  }
}

export function mockEvaluatePaymentReadiness(
  params: EvaluatePaymentReadinessParams = {},
): PaymentReadinessReport {
  const channel: PaymentChannel = params.channel ?? "directCard";
  const exitCc =
    normCc(mockFlags.countryOverride) ||
    (mockFlags.scenario === "ru" ? "RU" : mockFlags.scenario === "turkey" ? "TR" : "NL");
  const binReport = params.bin ? mockCheckCardBin(params.bin, exitCc) : null;
  const warnings: string[] = [];
  const blockers: string[] = [];

  const netScore = exitCc === "RU" ? 0 : 25;
  if (exitCc === "RU") blockers.push("Выходное подключение находится в России — оплата недоступна.");
  const networkBase: AxisScore = {
    id: "network_base",
    label: "Стабильность подключения перед оплатой",
    score: netScore,
    maxScore: 25,
    status: exitCc === "RU" ? "critical" : "ok",
    notes: exitCc === "RU" ? ["Выходное подключение находится в России."] : ["Подключение перед оплатой в порядке."],
  };

  let failClosedBin = false;
  let binScore = 30;
  let binStatus: AxisScore["status"] = "ok";
  const binNotes: string[] = [];
  if (channel === "appleIAP" || channel === "googlePlayIap" || channel === "api") {
    binNotes.push("При оплате через магазин приложений или по ключу данные карты на сайт не передаются.");
  } else if (!binReport) {
    binScore = 15;
    binStatus = "warning";
    failClosedBin = true;
    const msg = "Первые 6–8 цифр карты не проверены — зелёный статус недоступен.";
    binNotes.push(msg);
    warnings.push(msg);
  } else if (binReport.source === "fallbackUnknown" || binReport.status === "unknown") {
    binScore = 15;
    binStatus = "warning";
    failClosedBin = true;
    const msg = "Не удалось проверить карту — зелёный статус недоступен.";
    binNotes.push(msg);
    warnings.push(msg);
  } else if (binReport.countryCode === "RU" || binReport.countryCode === "BY") {
    binScore = 0;
    binStatus = "critical";
    const ccLabel = countryName(binReport.countryCode) || binReport.countryCode;
    const msg = `Оплата невозможна: карта выпущена в стране «${ccLabel}».`;
    binNotes.push(msg);
    blockers.push(msg);
  } else {
    if (binReport.isPrepaid) {
      binScore -= 15;
      binStatus = "warning";
      warnings.push("Предоплаченная (виртуальная) карта.");
    }
    if (binReport.isCommercial) {
      binScore -= 10;
      binStatus = "warning";
      warnings.push("Корпоративная карта.");
    }
    if (binReport.claudeWebVerdict === "highKycRisk" || binReport.claudeWebVerdict === "blocked") {
      binScore = Math.max(0, binScore - 20);
      binStatus = "critical";
      blockers.push(binReport.warnings[0] ?? "Высокий риск запроса паспорта и селфи для этой карты.");
    }
    if (binNotes.length === 0) {
      const ccLabel = binReport.countryCode ? countryName(binReport.countryCode) || binReport.countryCode : "страна не определена";
      binNotes.push(`Карта ${binReport.binPrefix}… (${ccLabel}).`);
    }
  }

  let geoScore = 25;
  let geoStatus: AxisScore["status"] = "ok";
  const geoNotes: string[] = [];
  if (channel === "appleIAP") {
    const appleCc = normCc(params.appleIdCountry) || "US";
    if (appleCc !== "US") {
      geoScore = 5;
      geoStatus = "critical";
      const appleLabel = countryName(appleCc) || appleCc;
      blockers.push(`Выбран регион App Store «${appleLabel}»: лучше использовать отдельный аккаунт США.`);
    } else {
      geoNotes.push("Выбран аккаунт App Store США — оплата идёт через Apple без проверки карты на сайте.");
    }
  } else if (channel === "googlePlayIap") {
    const gpCc = normCc(params.googleProfileCountry);
    if (gpCc === "RU") {
      geoScore = 0;
      geoStatus = "critical";
      blockers.push("Платёжный профиль Google привязан к России — оплата зарубежной картой вызовет ошибку OR-CCSEH-21 / OR-HDT-16.");
    } else if (gpCc && exitCc && gpCc !== exitCc) {
      geoScore = 10;
      geoStatus = "critical";
      blockers.push(`Конфликт стран Google Play: профиль в стране ${countryName(gpCc) || gpCc} при подключении из ${countryName(exitCc) || exitCc}.`);
    } else {
      geoNotes.push("Профиль Google Play и подключение согласованы.");
    }
  } else if (channel === "api") {
    geoNotes.push("Для оплаты по ключу совпадение страны карты и адреса не требуется.");
  } else if (binReport?.countryCode) {
    const cardCc = binReport.countryCode;
    const billCc = normCc(params.billingCountry);
    const cardLabel = countryName(cardCc) || cardCc;
    const exitLabel = countryName(exitCc) || exitCc;
    if (cardCc !== exitCc) {
      geoScore -= 20;
      geoStatus = "critical";
      blockers.push(`Конфликт стран: карта из ${cardLabel}, а подключение из ${exitLabel}.`);
    }
    if (!billCc) {
      geoScore -= 10;
      if (geoStatus === "ok") geoStatus = "warning";
      warnings.push(`Укажите реальный адрес в стране карты (${cardLabel}).`);
    } else if (billCc !== cardCc) {
      geoScore = 0;
      geoStatus = "critical";
      const billLabel = countryName(billCc) || billCc;
      blockers.push(`Несовпадение страны адреса оплаты: указана ${billLabel} вместо ${cardLabel}.`);
    } else if (geoNotes.length === 0) {
      geoNotes.push(`Страна подключения, карты и адреса оплаты совпадают (${cardLabel}).`);
    }
  } else {
    geoScore = 15;
    geoStatus = "warning";
    geoNotes.push("Страна карты неизвестна.");
  }

  const crProfile = params.profileId
    ? mockState.clean_room?.profiles.find((p) => p.id === params.profileId)
    : mockState.clean_room?.active_profile_id
      ? mockState.clean_room.profiles.find((p) => p.id === mockState.clean_room?.active_profile_id)
      : undefined;
  const startedRaw = crProfile?.warmup_started_at ?? mockState.warmup_started_at ?? null;
  const startedMs = startedRaw ? (startedRaw < 1e11 ? startedRaw * 1000 : startedRaw) : null;
  const warmupHours = startedMs ? Math.floor(Math.max(0, Date.now() - startedMs) / 3_600_000) : 0;
  const warmupOk = warmupHours >= 96 || params.accountAgeConfirmed96h === true;

  let chanScore = 20;
  let chanStatus: AxisScore["status"] = "ok";
  const chanNotes: string[] = [];
  let walletTrap = false;
  if (channel === "appleIAP" || channel === "googlePlayIap" || channel === "api") {
    if (channel === "googlePlayIap") {
      const gpCc = normCc(params.googleProfileCountry);
      if (gpCc === "RU" || (gpCc && exitCc && gpCc !== exitCc)) {
        chanScore = 0;
        chanStatus = "critical";
        walletTrap = true;
        blockers.push("Профиль Google Payments конфликтует с оплатой (риск OR-CCSEH-21 / OR-HDT-16).");
      } else {
        chanNotes.push("Оплата через Google Play не использует форму карты на сайте.");
      }
    } else {
      chanNotes.push("Этот способ оплаты не использует форму карты на сайте.");
    }
  } else {
    if (!warmupOk) {
      chanScore -= 10;
      chanStatus = "warning";
      const msg = "Возраст аккаунта меньше 4 дней (96 ч) — рекомендуется выдержать 96 ч на бесплатном тарифе перед первой оплатой картой.";
      warnings.push(msg);
      chanNotes.push(msg);
    }
    if (!params.inCleanRoom) {
      chanScore -= 10;
      chanStatus = "warning";
      warnings.push("Оплата вне «Чистой комнаты»: обычный браузер может передать старые следы.");
    }
    if (params.plan === "max" && !warmupOk) {
      chanScore -= 15;
      chanStatus = "critical";
      blockers.push("Тариф Max на аккаунте младше 96 ч повышает риск проверки или отказа.");
    }
    if (channel === "googlePayWeb" || channel === "applePayWeb") {
      const trap =
        "Google Pay и Apple Pay на сайте передают платёжной системе реальную страну и тип карты, а Google Pay сверяет страну платёжного профиля Google.";
      warnings.push(trap);
      chanNotes.push(trap);
      const cardCc = binReport?.countryCode ?? "";
      const gpCc = normCc(params.googleProfileCountry);
      if ((cardCc && cardCc !== exitCc) || (channel === "googlePayWeb" && cardCc && gpCc && cardCc !== gpCc)) {
        chanScore = 0;
        chanStatus = "critical";
        walletTrap = true;
        blockers.push(`${channel === "googlePayWeb" ? "Google Pay" : "Apple Pay"} на сайте: конфликт страны карты со страной профиля или подключения.`);
      }
    }
    if (chanNotes.length === 0) chanNotes.push("Параметры способа оплаты и среды проверены.");
  }

  const raw =
    Math.max(0, networkBase.score) +
    Math.max(0, binScore) +
    Math.max(0, geoScore) +
    Math.max(0, chanScore);
  let score = raw;
  let tier: ReadinessTier = "green";
  if (binReport?.countryCode === "RU" || binReport?.countryCode === "BY") {
    score = 0;
    tier = "red";
  } else if (walletTrap || raw <= 49) {
    score = Math.min(raw, 49);
    tier = "red";
  } else if (failClosedBin || blockers.length > 0 || raw <= 79) {
    score = Math.min(raw, 79);
    tier = "yellow";
  }

  const recommendedAction =
    tier === "green"
      ? null
      : tier === "red"
        ? "Остановите оплату: выберите оплату через App Store (аккаунт США с подарочной картой) или выровняйте страну карты, адреса оплаты и подключения."
        : warmupOk || channel === "appleIAP" || channel === "api"
          ? "Устраните предупреждения перед оплатой: откройте «Чистую комнату» и проверьте совпадение стран."
          : "Выдержите 96 ч прогрева, откройте «Чистую комнату» и проверьте совпадение стран, либо оплатите через App Store.";

  return {
    score,
    tier,
    axes: {
      networkBase,
      cardBin: { id: "card_bin", label: "Проверка карты и типа", score: Math.max(0, binScore), maxScore: 30, status: binStatus, notes: binNotes },
      geoBillingParity: { id: "geo_billing_parity", label: "Совпадение страны, карты и адреса", score: Math.max(0, geoScore), maxScore: 25, status: geoStatus, notes: geoNotes },
      channelEnvWarmup: { id: "channel_env_warmup", label: "Способ оплаты, среда и прогрев", score: Math.max(0, chanScore), maxScore: 20, status: chanStatus, notes: chanNotes },
    },
    warnings,
    blockers,
    recommendedAction,
    requiresMatchingBilling: channel !== "appleIAP" && channel !== "googlePlayIap" && channel !== "api",
    failClosedBin,
    channel,
    evaluatedAt: nowSec(),
  };
}

export function mockCancelAndInspect(id: string, domain: string): boolean {
  clearMockPendingAlert(id);
  emitMock(MOCK_OPEN_PAYMENT_CHECK_EVENT, domain);
  return true;
}

export function mockAllowCheckout15m(id: string, _domain: string): boolean {
  clearMockPendingAlert(id);
  return true;
}

function buildQuarantineStatus(q: PostPaymentQuarantine | null | undefined, now = nowSec()): PostPaymentQuarantineStatus {
  if (!q || q.overriddenAt || now >= q.expiresAt) {
    return { active: false, remainingHours: 0, remainingSecs: 0, quarantine: q ?? null, warning: null };
  }
  const remainingSecs = Math.max(0, q.expiresAt - now);
  const remainingHours = Math.ceil(remainingSecs / 3600);
  return {
    active: true,
    remainingHours,
    remainingSecs,
    quarantine: q,
    warning: `Активна 72-часовая защита маршрута после оплаты (осталось ${remainingHours} ч). Смена страны, сервера или ключа сейчас повышает риск проверки по паспорту и селфи.`,
  };
}

export function mockActivatePostPaymentQuarantine(params: ActivateQuarantineParams = {}): PostPaymentQuarantineStatus {
  const now = nowSec();
  if (!mockState.clean_room) {
    mockState.clean_room = { profiles: [], active_profile_id: null, tainted_ips: {} };
  }
  const pid = params.profileId?.trim() || mockState.clean_room.active_profile_id;
  const target = pid ? mockState.clean_room.profiles.find((p) => p.id === pid) : undefined;
  const q: PostPaymentQuarantine = {
    startedAt: now,
    expiresAt: now + POST_PAYMENT_QUARANTINE_SECS,
    pinnedRouteId: params.routeId ?? target?.bound_route_id ?? null,
    pinnedExitIp: params.exitIp ?? target?.last_exit_ip ?? mockState.pinned_ip ?? "185.212.102.40",
    pinnedAsn: params.exitAsn ?? null,
    pinnedCountry: (params.exitCountry ?? target?.last_exit_country ?? "US").toUpperCase(),
    overriddenAt: null,
  };
  if (target) target.post_payment_quarantine = q;
  else mockState.clean_room.global_post_payment_quarantine = q;
  return buildQuarantineStatus(q, now);
}

export function mockGetPostPaymentQuarantineStatus(profileId?: string | null): PostPaymentQuarantineStatus {
  const cr = mockState.clean_room;
  if (!cr) return buildQuarantineStatus(null);
  const pid = profileId?.trim() || cr.active_profile_id;
  const profile = pid ? cr.profiles.find((p) => p.id === pid) : undefined;
  const q = profile?.post_payment_quarantine ?? cr.global_post_payment_quarantine ?? null;
  return buildQuarantineStatus(q);
}

export function mockOverridePostPaymentQuarantine(profileId?: string | null): PostPaymentQuarantineStatus {
  const now = nowSec();
  const cr = mockState.clean_room;
  if (!cr) return buildQuarantineStatus(null, now);
  const pid = profileId?.trim() || cr.active_profile_id;
  const profile = pid ? cr.profiles.find((p) => p.id === pid) : undefined;
  if (profile?.post_payment_quarantine) {
    profile.post_payment_quarantine.overriddenAt = now;
    return buildQuarantineStatus(profile.post_payment_quarantine, now);
  }
  if (cr.global_post_payment_quarantine) {
    cr.global_post_payment_quarantine.overriddenAt = now;
    return buildQuarantineStatus(cr.global_post_payment_quarantine, now);
  }
  return buildQuarantineStatus(null, now);
}

export function mockGetPaymentPassport(profileId: string): PaymentPassport | null {
  return mockPassports.get(profileId.trim() || "default") ?? null;
}

export function mockSavePaymentPassport(passport: PaymentPassport): PaymentPassport {
  const saved: PaymentPassport = {
    ...passport,
    profileId: passport.profileId.trim() || "default",
    cardCountry: passport.cardCountry.trim().toUpperCase(),
    billingCountry: passport.billingCountry.trim().toUpperCase(),
    paidAt: passport.paidAt || nowSec(),
  };
  mockPassports.set(saved.profileId, saved);
  return saved;
}

export function mockVerifyPaymentPassport(
  profileId: string,
  current: RenewalCheckInput,
): PassportVerificationResult {
  const passport = mockGetPaymentPassport(profileId);
  if (!passport) {
    throw new Error(`Памятка прошлой оплаты для профиля «${profileId}» ещё не сохранена.`);
  }
  const mismatches: string[] = [];
  const warnings: string[] = [];
  if (current.binPrefix && passport.binPrefix && !current.binPrefix.startsWith(passport.binPrefix.slice(0, 6))) {
    mismatches.push(`Первые цифры карты (${current.binPrefix}) не совпадают с памяткой (${passport.binPrefix}).`);
  }
  if (current.cardCountry && current.cardCountry.toUpperCase() !== passport.cardCountry) {
    const curCc = countryName(current.cardCountry.toUpperCase()) || current.cardCountry.toUpperCase();
    const passCc = countryName(passport.cardCountry) || passport.cardCountry;
    mismatches.push(`Страна карты (${curCc}) не совпадает с памяткой (${passCc}).`);
  }
  if (current.billingCountry && current.billingCountry.toUpperCase() !== passport.billingCountry) {
    const curCc = countryName(current.billingCountry.toUpperCase()) || current.billingCountry.toUpperCase();
    const passCc = countryName(passport.billingCountry) || passport.billingCountry;
    mismatches.push(`Страна адреса оплаты (${curCc}) не совпадает с памяткой (${passCc}).`);
  }
  if (current.channel && current.channel !== passport.channel) {
    mismatches.push("Способ оплаты отличается от прошлой оплаты.");
  }
  if (current.exitIp && current.exitIp !== passport.exitIp) {
    warnings.push(`IP подключения изменился (${current.exitIp} вместо ${passport.exitIp}).`);
  }
  return { matched: mismatches.length === 0, mismatches, warnings, passport };
}
