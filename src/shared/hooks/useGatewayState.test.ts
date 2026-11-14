import { describe, expect, it } from "vitest";
import type { CheckResult, OverallStatus, ProviderId, RiskReport } from "../../types";
import { mergeProviderReport } from "./useGatewayState";

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
