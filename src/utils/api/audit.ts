import type {
  BinAuditResult,
  CrashTestStepResult,
  ProviderId,
  RiskReport,
  StartupSnapshot,
} from "../../types";
import { isTauri, tauriInvoke } from "./client";
import { currentMockStartup, runMockAudit } from "./mocks/audit";
import { mockFlags, mockState } from "./mocks/state";

/** Где фоновый запуск шлюза (защита, страж): пока `starting`, состояние защиты не известно. */
export async function getStartupState(): Promise<StartupSnapshot> {
  if (isTauri()) {
    return await tauriInvoke<StartupSnapshot>("get_startup_state");
  }
  return currentMockStartup();
}

/**
 * Аудит. С `runId` шлюз присылает событиями audit://progress адрес выхода и каждую проверку, как только она
 * готова, а итоговый отчёт возвращает в конце; без `runId` приходит только отчёт.
 */
export async function auditConnection(
  provider: ProviderId = "anthropic",
  forceRefresh: boolean = false,
  runId?: string,
): Promise<RiskReport> {
  if (isTauri()) {
    return await tauriInvoke<RiskReport>("audit_connection", {
      provider,
      forceRefresh,
      runId: runId ?? null,
    });
  }
  return await runMockAudit(provider, runId);
}

export async function checkPaymentBin(
  bin: string,
  vpnCountry?: string,
): Promise<BinAuditResult> {
  if (isTauri()) {
    return await tauriInvoke<BinAuditResult>("check_payment_bin", {
      bin,
      vpnCountry,
    });
  }

  const cleanBin = bin.replace(/\s+/g, "").slice(0, 6);
  if (cleanBin.startsWith("489504") || cleanBin.startsWith("414720")) {
    return {
      bin: cleanBin,
      country_code: "US",
      card_type: "Debit",
      bank_name: "JPMorgan Chase Bank, N.A.",
      is_prepaid: false,
      status: "ok",
      advisory: "Карта выпущена в США (US), не является предоплаченной (Credit/Debit). Отличная проходимость в Stripe/Anthropic.",
      guide_ref: "02-safe-payment-cards",
    };
  }

  return {
    bin: cleanBin,
    country_code: "GB",
    card_type: "Debit",
    bank_name: "Barclays Bank UK PLC",
    is_prepaid: false,
    status: "ok",
    advisory: "Регион карты совпадает с гео-политиками большинства ИИ-провайдеров.",
    guide_ref: "02-safe-payment-cards",
  };
}

export async function runVpnCrashTestStep(): Promise<CrashTestStepResult> {
  if (isTauri()) {
    return await tauriInvoke<CrashTestStepResult>("run_vpn_crash_test_step");
  }

  mockFlags.crashTestStep++;
  const isDropped = mockFlags.crashTestDropped || mockFlags.crashTestStep >= 12;

  if (isDropped) {
    const latency_ms = 0.28;
    return {
      passed_through: false,
      intercepted_by_killswitch: true,
      latency_ms,
      current_ip: mockState.pinned_ip ?? "185.212.102.40",
      current_country: "NL",
      status_text: `Мгновенно перехвачено Kill-Switch (${latency_ms.toFixed(1)} мс)`,
    };
  }

  const latency_ms = 0.32 + Math.random() * 0.2;
  return {
    passed_through: true,
    intercepted_by_killswitch: false,
    latency_ms,
    current_ip: mockState.pinned_ip ?? "185.212.102.40",
    current_country: "NL",
    status_text: `Защищено · Маршрут чист (${latency_ms.toFixed(1)} мс)`,
  };
}

export async function triggerCrashTestDrop(): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("trigger_crash_test_drop");
  }
  mockFlags.crashTestDropped = true;
}

export async function resetCrashTestDrop(): Promise<void> {
  if (isTauri()) {
    return await tauriInvoke("reset_crash_test_drop");
  }
  mockFlags.crashTestDropped = false;
  mockFlags.crashTestStep = 0;
}
