import { describe, expect, it } from "vitest";
import type { CheckResult, OverallStatus, ProviderId, RiskReport, RoutesSnapshot } from "../../types";
import {
  invalidateStaleReports,
  mergeProviderReport,
  shouldInvalidateOnPauseStatus,
  shouldSuppressSelfHeal,
} from "./useGatewayState";
import {
  findMissingEnabledProviders,
  isConfirmedIpChange,
  isRedundantNetworkAudit,
  needsStartupSelfHeal,
  pickActiveReport,
  shouldRefreshOnFocus,
} from "./gatewayReports";

const okCheck: CheckResult = {
  status: "ok",
  code: "OK",
  message: "ok",
};

function makeReport(provider: ProviderId, status: OverallStatus, ip: string): RiskReport {
  return {
    provider,
    overall_status: status,
    trust_score: status === "green" ? 100 : 60,
    telemetry: {
      ip,
      country_code: "NL",
      resolved_at: 1,
    },
    geo_result: okCheck,
    pinning_result: okCheck,
    travel_result: okCheck,
    dnsbl_result: okCheck,
    dnsbl_clean_count: "4/4",
    asn_result: okCheck,
    ipv6_result: okCheck,
    timezone_result: okCheck,
    checks: [],
  };
}

describe("mergeProviderReport", () => {
  it("обновляет только выбранный сервис, не сбрасывая и не перезаписывая здоровые отчёты других", () => {
    const anthropicOk = makeReport("anthropic", "green", "1.1.1.1");
    const openaiOk = makeReport("openai", "green", "2.2.2.2");
    const geminiOld = makeReport("gemini", "yellow", "3.3.3.3");
    const geminiNew = makeReport("gemini", "green", "4.4.4.4");

    const prev: Partial<Record<ProviderId, RiskReport>> = {
      anthropic: anthropicOk,
      openai: openaiOk,
      gemini: geminiOld,
    };

    const next = mergeProviderReport(prev, "gemini", geminiNew);

    expect(next.anthropic).toBe(anthropicOk);
    expect(next.openai).toBe(openaiOk);
    expect(next.gemini).toBe(geminiNew);
    expect(prev.gemini).toBe(geminiOld);
  });
});

describe("invalidateStaleReports", () => {
  const routesSnapshot: RoutesSnapshot = {
    routes: [],
    provider_routes: { openai: "route-1" },
    effective: { anthropic: null, openai: "route-1", gemini: null },
    dangling: [],
  };

  it("сбрасывает только unrouted-сервисы при смене сети и сохраняет привязанный к ключу", () => {
    const prev = {
      anthropic: makeReport("anthropic", "green", "1.1.1.1"),
      openai: makeReport("openai", "green", "9.9.9.9"),
      gemini: makeReport("gemini", "green", "1.1.1.1"),
    };
    const next = invalidateStaleReports(prev, routesSnapshot);
    expect(next.anthropic).toBeUndefined();
    expect(next.gemini).toBeUndefined();
    expect(next.openai).toEqual(prev.openai);
  });

  it("при includeAll сбрасывает все отчёты, а при onlyProviders — только перечисленные", () => {
    const prev = {
      anthropic: makeReport("anthropic", "green", "1.1.1.1"),
      openai: makeReport("openai", "green", "9.9.9.9"),
    };
    const targeted = invalidateStaleReports(prev, routesSnapshot, ["openai"]);
    expect(targeted.openai).toBeUndefined();
    expect(targeted.anthropic).toEqual(prev.anthropic);

    const allDropped = invalidateStaleReports(prev, routesSnapshot, undefined, true);
    expect(allDropped).toEqual({});
  });
});

describe("shouldInvalidateOnPauseStatus", () => {
  it("не сбрасывает отчёты при paused === true или gate === 'blocked'", () => {
    expect(
      shouldInvalidateOnPauseStatus({
        paused: true,
        mode: "until_network_change",
        gate: "blocked",
        manual_killswitch: false,
        blocked_providers: ["anthropic"],
      }).invalidate,
    ).toBe(false);

    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "none",
        gate: "blocked",
        manual_killswitch: false,
        blocked_providers: ["anthropic"],
      }).invalidate,
    ).toBe(false);
  });

  it("НЕ сбрасывает отчёты при транзиентном gate === 'pending' (устраняет шторм 11 из 11 -> 0 из 14)", () => {
    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "none",
        gate: "pending",
        manual_killswitch: false,
        pending_providers: ["anthropic"],
      }),
    ).toEqual({ invalidate: false, includeAll: false });

    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "none",
        gate: "open",
        manual_killswitch: false,
        pending_providers: [],
        blocked_providers: [],
      }).invalidate,
    ).toBe(false);
  });

  it("сбрасывает отчёты при включённом ручном kill-switch", () => {
    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "manual",
        gate: "blocked",
        manual_killswitch: true,
        pending_providers: [],
      }).invalidate,
    ).toBe(false);

    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "manual",
        gate: "open",
        manual_killswitch: true,
        pending_providers: ["anthropic"],
      }),
    ).toEqual({ invalidate: true, onlyProviders: ["anthropic"], includeAll: true });
  });
});

describe("isRedundantNetworkAudit & isConfirmedIpChange", () => {
  it("считает network://changed избыточным, если audit://refreshed недавно пришёл для того же IP", () => {
    const now = 100_000;
    expect(isRedundantNetworkAudit({ ip: "178.168.12.86", at: now - 500 }, "178.168.12.86", now)).toBe(true);
    expect(isRedundantNetworkAudit({ ip: "178.168.12.86", at: now - 6000 }, "178.168.12.86", now)).toBe(false);
    expect(isRedundantNetworkAudit({ ip: "178.168.12.86", at: now - 500 }, "185.212.102.40", now)).toBe(false);
    expect(isRedundantNetworkAudit({ ip: "178.168.12.86", at: now - 500 }, null, now)).toBe(false);
  });

  it("распознаёт подтверждённую смену IP только при двух разных валидных IP", () => {
    expect(isConfirmedIpChange("1.1.1.1", "2.2.2.2")).toBe(true);
    expect(isConfirmedIpChange("1.1.1.1", "1.1.1.1")).toBe(false);
    expect(isConfirmedIpChange("--", "2.2.2.2")).toBe(false);
    expect(isConfirmedIpChange("1.1.1.1", null)).toBe(false);
  });
});

describe("shouldSuppressSelfHeal", () => {
  it("подавляет 1.5с self-heal при gate === 'pending' или paused === true", () => {
    expect(shouldSuppressSelfHeal({ paused: true, mode: "until_network_change", gate: "open", manual_killswitch: false })).toBe(true);
    expect(shouldSuppressSelfHeal({ paused: false, mode: "none", gate: "pending", manual_killswitch: false })).toBe(true);
    expect(shouldSuppressSelfHeal({ paused: false, mode: "none", gate: "open", manual_killswitch: false })).toBe(false);
    expect(shouldSuppressSelfHeal(null)).toBe(false);
  });
});

describe("startup/visibility self-heal для всех включённых провайдеров (устранение «Проверить: Gemini»)", () => {
  it("выявляет отсутствующий отчёт у любого включённого провайдера, даже когда activeReport здоров", () => {
    const anthropicOk = {
      ...makeReport("anthropic", "green", "1.1.1.1"),
      telemetry: { ip: "1.1.1.1", country_code: "NL", asn: 13335, resolved_at: 1 },
    };
    const openaiOk = {
      ...makeReport("openai", "green", "1.1.1.1"),
      telemetry: { ip: "1.1.1.1", country_code: "NL", asn: 13335, resolved_at: 1 },
    };

    const reports = { anthropic: anthropicOk, openai: openaiOk };
    expect(findMissingEnabledProviders(reports)).toEqual(["gemini"]);

    const plan = needsStartupSelfHeal(anthropicOk, reports, []);
    expect(plan).toEqual({
      needed: true,
      missingIpOrProvider: false,
      missingProviders: ["gemini"],
    });

    // Отключённый пользователем провайдер не триггерит self-heal.
    expect(findMissingEnabledProviders(reports, ["gemini"])).toEqual([]);
    expect(needsStartupSelfHeal(anthropicOk, reports, ["gemini"])).toEqual({
      needed: false,
      missingIpOrProvider: false,
      missingProviders: [],
    });

    // При наличии всех трёх отчётов self-heal не требуется.
    const full = { ...reports, gemini: openaiOk };
    expect(needsStartupSelfHeal(anthropicOk, full, [])).toEqual({
      needed: false,
      missingIpOrProvider: false,
      missingProviders: [],
    });
  });

  it("pickActiveReport и shouldRefreshOnFocus корректно реагируют на пропущенные отчёты", () => {
    const openaiOk = makeReport("openai", "green", "2.2.2.2");
    expect(pickActiveReport({ openai: openaiOk }, ["anthropic"])).toBe(openaiOk);

    expect(shouldRefreshOnFocus(null, 100_000, true)).toBe(false);
    expect(shouldRefreshOnFocus(99_000, 100_000, true)).toBe(true);
    expect(shouldRefreshOnFocus(99_000, 100_000, false)).toBe(false);
    expect(shouldRefreshOnFocus(1_000, 200_000, false)).toBe(true);
  });
});
