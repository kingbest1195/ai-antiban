import type {
  ActivateQuarantineParams,
  AdvisorPlan,
  AdvisorQuery,
  AiPaymentService,
  BinRadarLookupStats,
  BinRadarReport,
  BinReport,
  EvaluatePaymentReadinessParams,
  EvaluatedProvidersManifest,
  PassportVerificationResult,
  PaymentPassport,
  PaymentReadinessReport,
  PostPaymentQuarantineStatus,
  RenewalCheckInput,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import {
  mockActivatePostPaymentQuarantine,
  mockAllowCheckout15m,
  mockCancelAndInspect,
  mockCheckCardBin,
  mockEvaluatePaymentReadiness,
  mockGetPaymentPassport,
  mockGetPostPaymentQuarantineStatus,
  mockOverridePostPaymentQuarantine,
  mockSavePaymentPassport,
  mockVerifyPaymentPassport,
} from "./mocks/payment";
import {
  mockGetBinRadarStats,
  mockGetPaymentAdvice,
  mockGetProvidersManifest,
  mockSubmitBinRadarReport,
  setMockBinRadarOptIn,
} from "./mocks/paymentAdvisor";

/** 8-значный BIN-рентген (Zero PCI-DSS, строго 6–8 цифр, Fail-Closed). */
export async function checkCardBin(
  bin: string,
  vpnCountry?: string | null,
): Promise<BinReport> {
  if (isTauri()) {
    return await tauriInvoke<BinReport>("check_card_bin", {
      bin,
      vpnCountry: vpnCountry ?? null,
    });
  }
  return mockCheckCardBin(bin, vpnCountry);
}

/** 4-осевая оценка Payment Readiness Score (0–100) и детектор ловушки Google/Apple Pay. */
export async function evaluatePaymentReadiness(
  params: EvaluatePaymentReadinessParams = {},
): Promise<PaymentReadinessReport> {
  if (isTauri()) {
    return await tauriInvoke<PaymentReadinessReport>("evaluate_payment_readiness", {
      params,
    });
  }
  return mockEvaluatePaymentReadiness(params);
}

/** Отклоняет перехваченный чекаут и открывает экран проверки оплаты в главном окне. */
export async function cancelAndInspect(id: string, domain: string): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("cancel_and_inspect", { id, domain });
  }
  return mockCancelAndInspect(id, domain);
}

/** Разрешает перехваченный домен чекаута на 15 минут. */
export async function allowCheckout15m(id: string, domain: string): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("allow_checkout_15m", { id, domain });
  }
  return mockAllowCheckout15m(id, domain);
}

/** Активирует 72-часовой пост-платёжный карантин для профиля или глобально. */
export async function activatePostPaymentQuarantine(
  params: ActivateQuarantineParams = {},
): Promise<PostPaymentQuarantineStatus> {
  if (isTauri()) {
    return await tauriInvoke<PostPaymentQuarantineStatus>("activate_post_payment_quarantine", {
      profileId: params.profileId ?? null,
      routeId: params.routeId ?? null,
      exitIp: params.exitIp ?? null,
      exitAsn: params.exitAsn ?? null,
      exitCountry: params.exitCountry ?? null,
    });
  }
  return mockActivatePostPaymentQuarantine(params);
}

/** Читает текущий статус 72-часового пост-платёжного карантина. */
export async function getPostPaymentQuarantineStatus(
  profileId?: string | null,
): Promise<PostPaymentQuarantineStatus> {
  if (isTauri()) {
    return await tauriInvoke<PostPaymentQuarantineStatus>("get_post_payment_quarantine_status", {
      profileId: profileId ?? null,
    });
  }
  return mockGetPostPaymentQuarantineStatus(profileId);
}

/** Явный override 72-часового карантина («Сменить всё равно»). */
export async function overridePostPaymentQuarantine(
  profileId?: string | null,
  reason?: string | null,
): Promise<PostPaymentQuarantineStatus> {
  if (isTauri()) {
    return await tauriInvoke<PostPaymentQuarantineStatus>("override_post_payment_quarantine", {
      profileId: profileId ?? null,
      reason: reason ?? null,
    });
  }
  return mockOverridePostPaymentQuarantine(profileId);
}

/** Читает Zero-PAN PaymentPassport профиля из локального Бункера. */
export async function getPaymentPassport(profileId: string): Promise<PaymentPassport | null> {
  if (isTauri()) {
    return await tauriInvoke<PaymentPassport | null>("get_payment_passport", { profileId });
  }
  return mockGetPaymentPassport(profileId);
}

/** Сохраняет Zero-PAN PaymentPassport профиля в локальный Бункер. */
export async function savePaymentPassport(passport: PaymentPassport): Promise<PaymentPassport> {
  if (isTauri()) {
    return await tauriInvoke<PaymentPassport>("save_payment_passport", { passport });
  }
  return mockSavePaymentPassport(passport);
}

/** Сверяет текущие параметры продления с сохранённым PaymentPassport. */
export async function verifyPaymentPassport(
  profileId: string,
  current: RenewalCheckInput,
): Promise<PassportVerificationResult> {
  if (isTauri()) {
    return await tauriInvoke<PassportVerificationResult>("verify_payment_passport", {
      profileId,
      current,
    });
  }
  return mockVerifyPaymentPassport(profileId, current);
}

/** Детерминированный Safe Payment Advisor для 5 сценариев оплаты подписок ИИ. */
export async function getPaymentAdvice(query: AdvisorQuery): Promise<AdvisorPlan> {
  if (isTauri()) {
    return await tauriInvoke<AdvisorPlan>("get_payment_advice", { query });
  }
  return mockGetPaymentAdvice(query);
}

/** Локальная статистика BIN Radar (n >= 5 для показа процентов, иначе insufficient_data). */
export async function getBinRadarStats(
  binPrefix: string,
  service: AiPaymentService = "claude_pro",
): Promise<BinRadarLookupStats> {
  if (isTauri()) {
    return await tauriInvoke<BinRadarLookupStats>("get_bin_radar_stats", {
      binPrefix,
      service,
    });
  }
  return mockGetBinRadarStats(binPrefix, service);
}

/** Динамический реестр провайдеров с Per-Service Auto-Demote. */
export async function getProvidersManifest(): Promise<EvaluatedProvidersManifest> {
  if (isTauri()) {
    return await tauriInvoke<EvaluatedProvidersManifest>("get_providers_manifest");
  }
  return mockGetProvidersManifest();
}

/** Локальный opt-in приём Zero-PII/Zero-PCI отчёта (deny_unknown_fields + ^[0-9]{8}$). */
export async function submitBinRadarReport(
  report: Record<string, unknown>,
): Promise<BinRadarReport> {
  if (isTauri()) {
    return await tauriInvoke<BinRadarReport>("submit_bin_radar_report", { report });
  }
  return mockSubmitBinRadarReport(report);
}

/** Переключает добровольное участие в статистике BIN Radar. */
export async function setBinRadarOptIn(enabled: boolean): Promise<boolean> {
  if (isTauri()) {
    return await tauriInvoke<boolean>("set_bin_radar_opt_in", { enabled });
  }
  return setMockBinRadarOptIn(enabled);
}
