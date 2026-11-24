import { describe, expect, it } from "vitest";
import type { CheckResult, OverallStatus, ProviderId, RiskReport, RoutesSnapshot } from "../../types";
import { invalidateStaleReports, mergeProviderReport } from "./useGatewayState";

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
