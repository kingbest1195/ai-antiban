import { describe, expect, it } from "vitest";
import type { CheckResult, ProviderId, RiskReport } from "../../types";
import { pickWorstReport } from "../checks/checksModel";
import { needsForceConfirm, tabBadges } from "./useOverviewModel";

const ok = (): CheckResult => ({ status: "ok", code: "OK", message: "ok" });
const warn = (): CheckResult => ({ status: "warning", code: "W", message: "w" });
const crit = (): CheckResult => ({ status: "critical", code: "C", message: "c" });
const unknown = (): CheckResult => ({ status: "unknown", code: "U", message: "u", reason: "timeout" });
const na = (): CheckResult => ({ status: "unknown", code: "N", message: "n", reason: "not_applicable" });

function rep(provider: ProviderId, overall: RiskReport["overall_status"], checks: CheckResult[], over: Partial<RiskReport> = {}): RiskReport {
  const full = Array.from({ length: 14 }, (_, i) => checks[i] ?? ok());
  return {
    provider,
    overall_status: overall,
    trust_score: 80,
    telemetry: { ip: "1.1.1.1", country_code: "NL", resolved_at: 1 },
    geo_result: full[0],
    pinning_result: full[1],
    travel_result: full[2],
    dnsbl_result: full[3],
    dnsbl_clean_count: "",
    asn_result: full[4],
    ipv6_result: full[5],
    timezone_result: full[7],
    checks: full,
    ...over,
  };
}

describe("pickWorstReport", () => {
  it("красный у Gemini: выбран Gemini", () => {
    const r = pickWorstReport({
      anthropic: rep("anthropic", "green", []),
      openai: rep("openai", "green", []),
      gemini: rep("gemini", "red", [crit()]),
    });
    expect(r?.provider).toBe("gemini");
  });
  it("равенство: Claude", () => {
    const r = pickWorstReport({
      gemini: rep("gemini", "yellow", [warn()]),
      openai: rep("openai", "yellow", [warn()]),
      anthropic: rep("anthropic", "yellow", [warn()]),
    });
    expect(r?.provider).toBe("anthropic");
  });
  it("все зелёные: Claude", () => {
    const r = pickWorstReport({
      anthropic: rep("anthropic", "green", []),
      openai: rep("openai", "green", []),
      gemini: rep("gemini", "green", []),
    });
    expect(r?.provider).toBe("anthropic");
  });
  it("incomplete без красных считается жёлтым", () => {
    const r = pickWorstReport({
      anthropic: rep("anthropic", "green", []),
      openai: rep("openai", "green", [unknown()], { incomplete: true }),
      gemini: rep("gemini", "green", []),
    });
    expect(r?.provider).toBe("openai");
  });
  it("красный выше жёлтого", () => {
    const r = pickWorstReport({
      anthropic: rep("anthropic", "yellow", [warn()]),
      openai: rep("openai", "red", [crit()]),
    });
    expect(r?.provider).toBe("openai");
  });
  it("без отчётов null", () => {
    expect(pickWorstReport({})).toBeNull();
  });
});

describe("tabBadges", () => {
  const clean = { anthropic: rep("anthropic", "green", []) };
  it("точка на «Обзоре» только при stopped и frozen", () => {
    expect(tabBadges("stopped", clean, null).overview).toBe("danger");
    expect(tabBadges("frozen", clean, null).overview).toBe("danger");
    for (const b of ["leak", "timezone", "review", "incomplete", "update", null] as const) {
      expect(tabBadges(b, clean, null).overview).toBeUndefined();
    }
  });
  it("жёлтая точка на «Обзоре» при замечании по покрытию, если красной нет", () => {
    expect(tabBadges(null, clean, null, true).overview).toBe("warn");
    for (const b of ["leak", "timezone", "review", "incomplete", "update"] as const) {
      expect(tabBadges(b, clean, null, true).overview).toBe("warn");
    }
    expect(tabBadges(null, clean, null, false).overview).toBeUndefined();
    expect(tabBadges(null, clean, null).overview).toBeUndefined();
  });
  it("красная точка приоритетнее жёлтой", () => {
    expect(tabBadges("stopped", clean, null, true).overview).toBe("danger");
    expect(tabBadges("frozen", clean, null, true).overview).toBe("danger");
  });
  it("число на «Проверках» считает warning, critical и unknown, но не «не применимо»", () => {
    const reports = { anthropic: rep("anthropic", "red", [crit(), warn(), unknown(), na()]) };
    expect(tabBadges(null, reports, null).checks).toBe(3);
  });
  it("число берётся из худшего отчёта, а не из первого", () => {
    const reports = {
      anthropic: rep("anthropic", "green", []),
      gemini: rep("gemini", "red", [crit(), warn()]),
    };
    expect(tabBadges(null, reports, null).checks).toBe(2);
  });
  it("бейджа нет, если всё пройдено или отчётов нет", () => {
    expect(tabBadges(null, clean, null).checks).toBeUndefined();
    expect(tabBadges(null, {}, null)).toEqual({});
  });
});

describe("needsForceConfirm", () => {
  const nlGreen = rep("openai", "green", []);
  const nlYellow = rep("openai", "yellow", [warn()]);
  const nlRed = rep("openai", "red", [crit()]);
  const ruYellow = rep("openai", "yellow", [warn()], { telemetry: { ip: "1.1.1.1", country_code: "RU", resolved_at: 1 } });
  const byGreen = rep("openai", "green", [], { telemetry: { ip: "1.1.1.1", country_code: "BY", resolved_at: 1 } });

  it("для red, RU, BY или отсутствующего отчёта — да", () => {
    expect(needsForceConfirm("critical", nlRed)).toBe(true);
    expect(needsForceConfirm("warn", ruYellow)).toBe(true);
    expect(needsForceConfirm("ok", byGreen)).toBe(true);
    expect(needsForceConfirm("warn", undefined)).toBe(true);
    expect(needsForceConfirm("critical", null)).toBe(true);
  });

  it("для green/yellow не из РФ/РБ — нет, даже если провайдер был заблокирован (status = critical)", () => {
    expect(needsForceConfirm("warn", nlYellow)).toBe(false);
    expect(needsForceConfirm("critical", nlGreen)).toBe(false);
    expect(needsForceConfirm("critical", nlYellow)).toBe(false);
  });
});
