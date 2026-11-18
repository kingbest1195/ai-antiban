import type {
  EnrichedPayload,
  ProviderId,
  RiskInterceptPayload,
  RiskReport,
} from "../../../types";
import { emitMock } from "./state";

/** Сценарии мок-эмиттера предупреждения (только в браузере, без Tauri). */
export type MockAlertScenario = "default" | "slow-enrich";

export const MOCK_ALERT_DETECTED_EVENT = "mock-interceptor-risk-detected";
export const MOCK_ALERT_ENRICHED_EVENT = "mock-interceptor-enriched";

let mockPendingAlert: RiskInterceptPayload | null = null;

export function getMockPendingAlert(): RiskInterceptPayload | null {
  return mockPendingAlert;
}

export function clearMockPendingAlert(id: string): void {
  if (mockPendingAlert?.id === id) mockPendingAlert = null;
}

function mockAlertReport(): RiskReport {
  const now = Math.floor(Date.now() / 1000);
  const ok = (code: string, message: string) => ({
    status: "ok" as const,
    code,
    message,
    guide_ref: null,
  });
  return {
    provider: "anthropic",
    overall_status: "red",
    trust_score: 28,
    unknown_count: 1,
    applicable_count: 14,
    incomplete: true,
    telemetry: {
      ip: "185.220.101.5",
      country_code: "RU",
      asn: 9009,
      isp: "M247 Europe SRL",
      org: "M247 Europe SRL",
      timezone: "Europe/Moscow",
      resolved_at: now,
    },
    geo_result: {
      status: "critical",
      code: "GEO_HIGH_RISK_RU",
      message: "Локация RU не поддерживается сервисом ИИ.",
      guide_ref: "01-personal-vpn-15min",
    },
    pinning_result: {
      status: "warning",
      code: "PINNED_IP_NOT_CONFIGURED",
      message: "Трафик идет НЕ через закрепленный VPS.",
      guide_ref: "01-personal-vpn-15min",
    },
    travel_result: ok("TRAVEL_NORMAL", "Конфликтов перемещения за 12ч нет."),
    dnsbl_result: ok("DNSBL_CLEAN", "В спам-базах не числится."),
    dnsbl_clean_count: "4/4 Чисто",
    asn_result: ok("ASN_CLEAN", "Чистая автономная система."),
    ipv6_result: ok("IPV6_SAFE", "Утечек IPv6 нет."),
    timezone_result: ok("TIMEZONE_OK", "Часовой пояс согласован."),
    checks: [],
  };
}

/** Мок-эмиттер: сценарий выбирается аргументом или параметром адреса `?mockAlert=slow-enrich`. */
export function runMockAlert(provider: ProviderId, scenario: MockAlertScenario) {
  const id = "sim-" + Date.now();
  const base: RiskInterceptPayload = {
    id,
    provider,
    host: "api.anthropic.com:443",
    ttl_seconds: 60,
    is_simulation: true,
    scope: "provider",
    gate_reason: "Демо: адрес выхода сменился на неподдерживаемый регион (RU).",
    detected_at_ms: Date.now(),
    phase: "ready",
    network_change: {
      old_ip: "185.212.102.40",
      old_country: "NL",
      new_ip: "185.220.101.5",
      new_country: "RU",
    },
    report: mockAlertReport(),
  };
  if (scenario === "slow-enrich") {
    const detecting: RiskInterceptPayload = {
      ...base,
      phase: "detecting",
      report: null,
      network_change: {
        old_ip: "185.212.102.40",
        old_country: "NL",
        new_ip: "185.220.101.5",
        new_country: null,
      },
    };
    mockPendingAlert = detecting;
    emitMock(MOCK_ALERT_DETECTED_EVENT, detecting);
    window.setTimeout(() => {
      if (mockPendingAlert?.id !== id) return;
      const enriched: EnrichedPayload = {
        id,
        epoch: 1,
        phase: "ready",
        report: base.report,
        network_change: base.network_change!,
        gate_reason: base.gate_reason,
      };
      mockPendingAlert = { ...base };
      emitMock(MOCK_ALERT_ENRICHED_EVENT, enriched);
    }, 2000);
    return;
  }
  mockPendingAlert = base;
  emitMock(MOCK_ALERT_DETECTED_EVENT, base);
}
