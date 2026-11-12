import { describe, expect, it } from "vitest";
import type { CheckResult, RiskReport } from "../../types";
import { buildChecks, classify, countChecks, isYellowOnlyUnknown } from "./checksModel";
import { dataAge } from "../../shared/hooks/useGatewayState";
import { evaluateNetwork } from "../onboarding/networkVerdict";

const ok = (code = "OK"): CheckResult => ({ status: "ok", code, message: "ok" });
const warn = (): CheckResult => ({ status: "warning", code: "W", message: "w" });
const crit = (): CheckResult => ({ status: "critical", code: "C", message: "c" });
const unknown = (reason: CheckResult["reason"] = "timeout"): CheckResult => ({ status: "unknown", code: "U", message: "u", reason });

function report(checks: CheckResult[], over: Partial<RiskReport> = {}): RiskReport {
  return {
    provider: "anthropic",
    overall_status: "green",
    trust_score: 90,
    telemetry: { ip: "1.1.1.1", country_code: "NL", resolved_at: 1 },
    geo_result: checks[0],
    pinning_result: checks[1],
    travel_result: checks[2],
    dnsbl_result: checks[3],
    dnsbl_clean_count: "",
    asn_result: checks[4],
    ipv6_result: checks[5],
    timezone_result: checks[7],
    checks,
    ...over,
  };
}

const twelve = (over: Record<number, CheckResult> = {}) =>
  Array.from({ length: 12 }, (_, i) => over[i] ?? ok(`C${i}`));

describe("classify", () => {
  it("unknown никогда не ok", () => {
    expect(classify(unknown())).toBe("unknown");
    expect(classify({ status: "что-то новое" as never, code: "X", message: "" })).toBe("unknown");
    expect(classify(unknown("not_applicable"))).toBe("na");
  });
  it("старые и новые имена статусов", () => {
    expect(classify(ok())).toBe("ok");
    expect(classify({ status: "green", code: "", message: "" })).toBe("ok");
    expect(classify(warn())).toBe("warn");
    expect(classify({ status: "yellow", code: "", message: "" })).toBe("warn");
    expect(classify(crit())).toBe("crit");
    expect(classify({ status: "red", code: "", message: "" })).toBe("crit");
  });
});

describe("buildChecks", () => {
  it("счётчики ok/unknown/na/warn/crit; na вне M", () => {
    const r = report(twelve({ 3: warn(), 5: crit(), 6: unknown(), 8: unknown("not_applicable") }));
    const { counts, total } = buildChecks(r, null);
    expect(counts).toMatchObject({ ok: 8, warn: 1, crit: 1, unknown: 1, na: 1, applicable: 11 });
    expect(total).toBe(11);
  });

  it("«M из M» невозможно при unknown > 0", () => {
    const { counts, total } = buildChecks(report(twelve({ 6: unknown() })), null);
    expect(counts.unknown).toBe(1);
    expect(counts.ok).toBeLessThan(total);
  });

  it("потеря проверки не уменьшает M: показывается «Нет данных»", () => {
    const checks = twelve();
    checks.length = 10; // нет dns_country и locale_hygiene
    const { items, counts, total } = buildChecks(report(checks), null);
    const missing = items.filter((i) => i.missing);
    expect(missing.map((i) => i.id).sort()).toEqual(["dns_country", "locale_hygiene"]);
    expect(counts.unknown).toBe(2);
    expect(total).toBe(12);
  });

  it("проверка сверх известных id не пропадает и входит в M", () => {
    const { items, total, groups } = buildChecks(report([...twelve(), unknown()]), null);
    const extra = items.find((i) => i.id.startsWith("extra_"));
    expect(extra).toBeDefined();
    expect(extra?.group).toBe("leaks");
    expect(groups.find((g) => g.id === "leaks")?.items).toContain(extra);
    expect(total).toBe(13);
  });

  it("M берётся из отчёта, не из константы", () => {
    const { total } = buildChecks(report(twelve(), { applicable_count: 14 }), null);
    expect(total).toBe(14);
  });

  it("число ответивших DNSBL-зон берётся из текста проверки", () => {
    const dnsbl: CheckResult = { status: "ok", code: "DNSBL_CLEAN", message: "Ответили 3 из 5 спам-баз." };
    const { items } = buildChecks(report(twelve({ 3: dnsbl })), null);
    expect(items.find((i) => i.id === "dnsbl")?.data.some((d) => d.value === "3 из 5")).toBe(true);
  });
});

describe("countChecks / isYellowOnlyUnknown", () => {
  it("считает все классы", () => {
    expect(countChecks([ok(), warn(), crit(), unknown(), unknown("not_applicable")])).toEqual({
      ok: 1, warn: 1, crit: 1, unknown: 1, na: 1, applicable: 4,
    });
  });
  it("жёлтый только из-за unknown", () => {
    const r = report(twelve({ 6: unknown() }), { overall_status: "yellow" });
    expect(isYellowOnlyUnknown(r, r.checks)).toBe(true);
    const r2 = report(twelve({ 6: unknown(), 3: warn() }), { overall_status: "yellow" });
    expect(isYellowOnlyUnknown(r2, r2.checks)).toBe(false);
  });
});

describe("evaluateNetwork", () => {
  it("всё зелёное — «ok»", () => {
    const r = report(twelve());
    expect(evaluateNetwork({ anthropic: r }, r)).toMatchObject({ verdict: "ok", passed: 12, total: 12, unknown: 0 });
  });
  it("unknown без замечаний — «Проверено частично», не «ok»", () => {
    const r = report(twelve({ 6: unknown() }), { overall_status: "yellow" });
    const v = evaluateNetwork({ anthropic: r }, r);
    expect(v.verdict).toBe("partial");
    expect(v.unknown).toBe(1);
    expect(v.passed).toBeLessThan(v.total);
  });
  it("реальное замечание остаётся замечанием", () => {
    const r = report(twelve({ 6: unknown(), 5: crit() }), { overall_status: "red" });
    expect(evaluateNetwork({ anthropic: r }, r).verdict).toBe("bad");
  });
});

describe("dataAge", () => {
  it("свежие данные — null, старше 2 минут или упавший аудит — минуты", () => {
    expect(dataAge(60_000, false)).toBeNull();
    expect(dataAge(3 * 60_000, false)).toBe(3);
    expect(dataAge(10_000, true)).toBe(1);
  });
});
