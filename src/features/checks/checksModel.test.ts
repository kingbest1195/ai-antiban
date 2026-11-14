import { describe, expect, it } from "vitest";
import type { CheckResult, IpType, ProviderId, RiskReport } from "../../types";
import { checks as copy } from "../../shared/copy/ru";
import {
  PROVIDER_CHECK_MATRIX,
  buildChecks,
  buildPendingChecks,
  classify,
  countChecks,
  isYellowOnlyUnknown,
  partitionChecksForProvider,
  pickWorstProvider,
  priorityOfCheck,
  progressOf,
} from "./checksModel";
import { checks as checksCopy } from "../../shared/copy/ru";
import { applyProgress, dataAge, emptyPartial } from "../../shared/hooks/useGatewayState";
import { formatOsTzError } from "../../shared/hooks/useTimezoneSync";
import type { AuditProgressEvent, PartialAudit } from "../../types";
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

const fourteen = (over: Record<number, CheckResult> = {}) =>
  Array.from({ length: 14 }, (_, i) => over[i] ?? ok(`C${i}`));

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
    const r = report(fourteen({ 3: warn(), 5: crit(), 6: unknown(), 8: unknown("not_applicable") }));
    const { counts, total } = buildChecks(r, null);
    expect(counts).toMatchObject({ ok: 10, warn: 1, crit: 1, unknown: 1, na: 1, applicable: 13 });
    expect(total).toBe(13);
  });

  it("«M из M» невозможно при unknown > 0", () => {
    const { counts, total } = buildChecks(report(fourteen({ 6: unknown() })), null);
    expect(counts.unknown).toBe(1);
    expect(counts.ok).toBeLessThan(total);
  });

  it("потеря проверки не уменьшает M: показывается «Нет данных»", () => {
    const checks = fourteen();
    checks.length = 10; // нет dns_country, locale_hygiene, udp_stun и claude_exit
    const { items, counts, total } = buildChecks(report(checks), null);
    const missing = items.filter((i) => i.missing);
    expect(missing.map((i) => i.id).sort()).toEqual(["claude_exit", "dns_country", "locale_hygiene", "udp_stun"]);
    expect(counts.unknown).toBe(4);
    expect(total).toBe(14);
  });

  it("проверка сверх известных id не пропадает и входит в M", () => {
    const { items, total, groups } = buildChecks(report([...fourteen(), unknown()]), null);
    const extra = items.find((i) => i.id.startsWith("extra_"));
    expect(extra).toBeDefined();
    expect(extra?.group).toBe("leaks");
    expect(groups.find((g) => g.id === "leaks")?.items).toContain(extra);
    expect(total).toBe(15);
  });

  it("M берётся из отчёта, не из константы", () => {
    const { total } = buildChecks(report(fourteen(), { applicable_count: 15 }), null);
    expect(total).toBe(15);
  });

  it("14 id попадают ровно в одну группу, M берётся из отчёта, а не из константы", () => {
    const { groups, items, total } = buildChecks(report(fourteen()), null);
    const ids = items.map((i) => i.id);
    expect(ids).toHaveLength(14);
    expect(new Set(ids).size).toBe(14);
    expect(ids).toContain("udp_stun");
    expect(ids).toContain("claude_exit");
    // Каждый id встречается в группах ровно один раз.
    const grouped = groups.flatMap((g) => g.items.map((i) => i.id));
    expect(grouped.sort()).toEqual([...ids].sort());
    expect(groups.find((g) => g.items.some((i) => i.id === "udp_stun"))?.id).toBe("leaks");
    expect(groups.find((g) => g.items.some((i) => i.id === "claude_exit"))?.id).toBe("address");
    expect(total).toBe(14);
    expect(buildChecks(report(fourteen(), { applicable_count: 16 }), null).total).toBe(16);
  });

  it("udp_stun: «что делать» только при замечании или «не удалось проверить»; источник доступен для показа", () => {
    const via: CheckResult = { status: "warning", code: "UDP_STUN_MISMATCH", message: "m", measured_via: "stun:cloudflare+google" };
    const warned = buildChecks(report(fourteen({ 12: via })), null).items.find((i) => i.id === "udp_stun");
    expect(warned?.advice).toBeTruthy();
    expect(warned?.result.measured_via).toBe("stun:cloudflare+google");
    const unk = buildChecks(report(fourteen({ 12: unknown() })), null).items.find((i) => i.id === "udp_stun");
    expect(unk?.advice).toBeTruthy();
    const fine = buildChecks(report(fourteen()), null).items.find((i) => i.id === "udp_stun");
    expect(fine?.advice).toBeNull();
  });

  it("claude_exit: measured_via и разбор при PROVIDER_EXIT_SPLIT_MISMATCH", () => {
    const split: CheckResult = {
      status: "warning",
      code: "PROVIDER_EXIT_SPLIT_MISMATCH",
      message: "Расхождение выхода",
      measured_via: "claude.ai (203.0.113.55)",
    };
    const item = buildChecks(report(fourteen({ 13: split })), null).items.find((i) => i.id === "claude_exit")!;
    expect(item.cls).toBe("warn");
    expect(item.result.measured_via).toBe("claude.ai (203.0.113.55)");
    expect(item.advice).toBe(copy.advice.claude_exit.warn);
    expect(item.help?.why).toContain("split tunneling");
    expect(item.help?.steps.some((s) => s.includes("zastava"))).toBe(true);
    expect(item.help?.canOpenNetworkSettings).toBe(false);
  });

  it("число ответивших DNSBL-зон берётся из текста проверки", () => {
    const dnsbl: CheckResult = { status: "ok", code: "DNSBL_CLEAN", message: "Ответили 3 из 5 спам-баз." };
    const { items } = buildChecks(report(fourteen({ 3: dnsbl })), null);
    expect(items.find((i) => i.id === "dnsbl")?.data.some((d) => d.value === "3 из 5")).toBe(true);
  });
});

describe("countChecks / isYellowOnlyUnknown", () => {
  it("считает все классы", () => {
    expect(countChecks([ok(), warn(), crit(), unknown(), unknown("not_applicable")])).toEqual({
      ok: 1, warn: 1, crit: 1, unknown: 1, na: 1, pending: 0, applicable: 4,
    });
  });
  it("жёлтый только из-за unknown", () => {
    const r = report(fourteen({ 6: unknown() }), { overall_status: "yellow" });
    expect(isYellowOnlyUnknown(r, r.checks)).toBe(true);
    const r2 = report(fourteen({ 6: unknown(), 3: warn() }), { overall_status: "yellow" });
    expect(isYellowOnlyUnknown(r2, r2.checks)).toBe(false);
  });
});

describe("evaluateNetwork", () => {
  it("всё зелёное — «ok»", () => {
    const r = report(fourteen());
    expect(evaluateNetwork({ anthropic: r }, r)).toMatchObject({ verdict: "ok", passed: 14, total: 14, unknown: 0 });
  });
  it("unknown без замечаний — «Проверено частично», не «ok»", () => {
    const r = report(fourteen({ 6: unknown() }), { overall_status: "yellow" });
    const v = evaluateNetwork({ anthropic: r }, r);
    expect(v.verdict).toBe("partial");
    expect(v.unknown).toBe(1);
    expect(v.passed).toBeLessThan(v.total);
  });
  it("реальное замечание остаётся замечанием", () => {
    const r = report(fourteen({ 6: unknown(), 5: crit() }), { overall_status: "red" });
    expect(evaluateNetwork({ anthropic: r }, r).verdict).toBe("bad");
  });
});

describe("dataAge", () => {
  it("при активной защите до 15 мин — null; >= 15 мин или при ошибке аудита — минуты", () => {
    expect(dataAge(60_000, false)).toBeNull();
    expect(dataAge(3 * 60_000, false)).toBeNull();
    expect(dataAge(14 * 60_000, false)).toBeNull();
    expect(dataAge(15 * 60_000, false)).toBe(15);
    expect(dataAge(10_000, true)).toBe(1);
    expect(dataAge(5 * 60_000, true)).toBe(5);
  });

  it("текст бейджа различает обычное устаревание и ошибку обновления", () => {
    expect(checksCopy.dataAge(16, false)).toBe("Данные 16 мин назад");
    expect(checksCopy.dataAge(5, true)).toBe("Не удалось обновить · 5 мин назад");
  });
});

describe("ожидание ≠ неизвестно ≠ ошибка", () => {
  const partialWith = (done: Record<number, CheckResult>): PartialAudit => {
    const p = emptyPartial("anthropic", "r1");
    for (const [i, r] of Object.entries(done)) p.checks[Number(i)] = r;
    return p;
  };

  it("без единого результата все 14 строк — ожидание, а не «не удалось проверить»", () => {
    const built = buildPendingChecks(emptyPartial("anthropic", "r1"), null);
    expect(built.items).toHaveLength(14);
    expect(built.items.every((i) => i.pending && i.cls === "pending" && !i.ok && !i.missing)).toBe(true);
    // Ожидание не считается ни пройденным, ни непройденным, ни неизвестным.
    expect(built.counts).toMatchObject({ ok: 0, warn: 0, crit: 0, unknown: 0, na: 0, pending: 14, applicable: 0 });
    expect(progressOf(built)).toEqual({ done: 0, total: 14 });
  });

  it("готовые строки получают результат, остальные ждут; счёт «N из 14» считает только готовые", () => {
    const built = buildPendingChecks(partialWith({ 0: ok("G"), 3: warn(), 6: unknown() }), null);
    expect(progressOf(built)).toEqual({ done: 3, total: 14 });
    expect(built.counts).toMatchObject({ ok: 1, warn: 1, unknown: 1, pending: 11 });
    const geo = built.items.find((i) => i.id === "geo_matrix")!;
    const dnsbl = built.items.find((i) => i.id === "dnsbl")!;
    const dns = built.items.find((i) => i.id === "dns")!;
    const asn = built.items.find((i) => i.id === "asn")!;
    expect([geo.pending, geo.cls]).toEqual([false, "ok"]);
    expect([dnsbl.pending, dnsbl.cls]).toEqual([false, "warn"]);
    // «Не удалось проверить» — это результат, а не ожидание.
    expect([dns.pending, dns.cls]).toEqual([false, "unknown"]);
    expect([asn.pending, asn.cls]).toEqual([true, "pending"]);
  });

  it("пока что-то ждёт, строки не тянут за собой действия и советы", () => {
    const built = buildPendingChecks(partialWith({}), null);
    expect(built.items.every((i) => i.action === null && i.advice === null && i.help === null && i.data.length === 0)).toBe(true);
    const groups = built.groups.flatMap((g) => g.items);
    expect(groups).toHaveLength(14);
  });

  it("полный отчёт: ожидания нет, счёт прежний", () => {
    const built = buildChecks(report(fourteen({ 6: unknown() })), null);
    expect(built.counts.pending).toBe(0);
    expect(built.items.every((i) => !i.pending)).toBe(true);
  });

  it("applyProgress складывает куски своего запуска (включая индекс 13) и игнорирует чужие", () => {
    const prev = emptyPartial("anthropic", "r1");
    const tel: AuditProgressEvent = {
      kind: "telemetry",
      run_id: "r1",
      provider: "anthropic",
      telemetry: { ip: "1.1.1.1", country_code: "NL", resolved_at: 1 },
    };
    const withTel = applyProgress(prev, tel)!;
    expect(withTel.telemetry?.ip).toBe("1.1.1.1");
    const chk: AuditProgressEvent = { kind: "check", run_id: "r1", provider: "anthropic", index: 13, result: ok("CLAUDE_EXIT") };
    const withCheck = applyProgress(withTel, chk)!;
    expect(withCheck.checks[13]?.code).toBe("CLAUDE_EXIT");
    expect(withCheck.checks[3]).toBeNull();
    // Событие устаревшего запуска (самолечение, повтор) состояние не меняет.
    expect(applyProgress(withCheck, { ...chk, run_id: "old", index: 5 })).toBe(withCheck);
    // Индекс вне отчёта и отсутствие запуска тоже безопасны.
    expect(applyProgress(withCheck, { ...chk, index: 99 })).toBe(withCheck);
    expect(applyProgress(undefined, chk)).toBeUndefined();
  });
});

describe("DNS: источники и разбор", () => {
  const dnsUnknown = (code: string, sources: NonNullable<CheckResult["detail"]>["sources"]): CheckResult => ({
    status: "unknown",
    code,
    message: "m",
    reason: "no_data",
    detail: { sources },
  });

  it("расхождение источников даёт пояснение и шаги для строки DNS", () => {
    const r = report(
      fourteen({
        6: dnsUnknown("DNS_WHOAMI_DISAGREE", [
          { source: "Akamai", state: "answered", addr: "203.0.113.10" },
          { source: "Google", state: "answered", addr: "198.51.100.7" },
        ]),
      }),
    );
    const dns = buildChecks(r, null).items.find((i) => i.id === "dns")!;
    expect(dns.cls).toBe("unknown");
    expect(dns.help?.steps.length).toBeGreaterThanOrEqual(2);
    expect(dns.help?.why).toContain("разные");
    expect(dns.help?.canOpenNetworkSettings).toBe(true);
    expect(dns.result.detail?.sources).toHaveLength(2);
  });

  it("fake-IP объяснён как ожидаемое, а не как утечка", () => {
    const r = report(fourteen({ 6: dnsUnknown("DNS_WHOAMI_FAKE_IP", []) }));
    const dns = buildChecks(r, null).items.find((i) => i.id === "dns")!;
    expect(dns.help?.why).toContain("fake-IP");
    expect(dns.help?.why).toContain("не значит, что есть утечка");
  });

  it("другие коды DNS получают общий разбор, не-DNS проверки и результаты «Чисто» — ничего", () => {
    const timeout = buildChecks(report(fourteen({ 6: dnsUnknown("DNS_WHOAMI_TIMEOUT", []) })), null).items.find((i) => i.id === "dns")!;
    expect(timeout.help?.steps.length).toBeGreaterThanOrEqual(2);
    const okDns = buildChecks(report(fourteen()), null).items.find((i) => i.id === "dns")!;
    expect(okDns.help).toBeNull();
    const other = buildChecks(report(fourteen({ 3: dnsUnknown("DNS_WHOAMI_DISAGREE", []) })), null).items.find((i) => i.id === "dnsbl")!;
    expect(other.help).toBeNull();
  });

  it("публичный DNS с двумя адресами одного оператора — «Чисто», источники видны", () => {
    const publicDns: CheckResult = {
      status: "ok",
      code: "DNS_PUBLIC_RESOLVER",
      message: "Резолвер: Cloudflare (публичный DNS).",
      detail: {
        sources: [
          { source: "Akamai", state: "answered", addr: "172.70.161.26", operator: "Cloudflare" },
          { source: "Google", state: "answered", addr: "172.71.240.11", operator: "Cloudflare" },
        ],
      },
    };
    const dns = buildChecks(report(fourteen({ 6: publicDns })), null).items.find((i) => i.id === "dns")!;
    expect(dns.ok).toBe(true);
    expect(dns.help).toBeNull();
    expect(dns.result.detail?.sources.map((s) => s.operator)).toEqual(["Cloudflare", "Cloudflare"]);
  });
});

describe("тип адреса внутри проверки репутации адреса", () => {
  const typed = (type: IpType | null, r: Partial<CheckResult> = {}): CheckResult => ({
    status: "ok",
    code: "IP_TYPE_HOSTING",
    message: "m",
    detail: type ? { sources: [], ip_type: type } : undefined,
    ...r,
  });
  const asnItem = (r: CheckResult, extra: Partial<RiskReport> = {}) =>
    buildChecks(report(withAsn(r), extra), null).items.find((i) => i.id === "asn")!;
  const withAsn = (r: CheckResult) => fourteen({ 4: r });

  it("число проверок не меняется: тип адреса не новая строка", () => {
    const built = buildChecks(report(fourteen({ 4: typed("hosting") })), null);
    expect(built.items.filter((i) => !i.id.startsWith("extra_"))).toHaveLength(14);
    expect(built.items.filter((i) => i.id === "asn")).toHaveLength(1);
  });

  it("хостинг: «Чисто», тип в подписи и в парах, совета нет", () => {
    const item = asnItem(typed("hosting"));
    expect(item.cls).toBe("ok");
    expect(item.what).toContain("Тип адреса: хостинг.");
    expect(item.data[0]).toEqual({ label: "Тип адреса", value: "Хостинг (ожидаемо для личного VPS)", mono: false });
    expect(item.advice).toBeNull();
  });

  it("Tor: замечание и совет про свой сервер", () => {
    const item = asnItem(typed("tor", { status: "warning", code: "IP_TYPE_TOR" }));
    expect(item.cls).toBe("warn");
    expect(item.what).toContain("выход сети Tor");
    expect(item.advice).toBe(copy.advice.asn.tor);
  });

  it("массовый VPN: замечание и свой совет", () => {
    const item = asnItem(typed("vpn", { status: "warning", code: "HIGH_RISK_MASS_VPN_ASN" }));
    expect(item.cls).toBe("warn");
    expect(item.advice).toBe(copy.advice.asn.vpn);
    expect(item.advice).not.toBe(copy.advice.asn.tor);
  });

  it("жилой — «Чисто»; тип «не определён» не добавляется в подпись, но показывается в парах", () => {
    expect(asnItem(typed("residential", { code: "IP_TYPE_RESIDENTIAL" })).what).toContain("жилой или мобильный провайдер");
    const unknownType = asnItem(typed("unknown", { code: "ASN_CLEAN" }));
    expect(unknownType.cls).toBe("ok");
    expect(unknownType.what).not.toContain("Тип адреса");
    expect(unknownType.data[0].value).toBe("Не определён");
  });

  it("список Tor недоступен: «не удалось проверить» с советом повторить, не «Чисто»", () => {
    const item = asnItem(typed("hosting", { status: "unknown", code: "TOR_LIST_UNAVAILABLE", reason: "timeout" }));
    expect(item.cls).toBe("unknown");
    expect(item.ok).toBe(false);
    expect(item.advice).toBe(copy.advice.asn.listUnavailable);
  });

  it("нет данных о провайдере: «не удалось проверить» без совета про Tor", () => {
    const item = asnItem(typed("unknown", { status: "unknown", code: "ASN_NO_DATA", reason: "no_data" }));
    expect(item.cls).toBe("unknown");
    expect(item.advice).toBeNull();
  });

  it("IPv6-выход: «не применимо», вне счёта, тип виден", () => {
    const na = typed("hosting", { status: "unknown", code: "IP_TYPE_IPV6_NOT_APPLICABLE", reason: "not_applicable" });
    const built = buildChecks(report(fourteen({ 4: na }), { ipv6_exit: true }), null);
    const item = built.items.find((i) => i.id === "asn")!;
    expect(item.cls).toBe("na");
    expect(built.counts.na).toBe(1);
    expect(built.counts.applicable).toBe(13);
    expect(item.data[0].label).toBe("Тип адреса");
  });

  it("отчёт старого шлюза без detail.ip_type: ни подписи, ни пары про тип", () => {
    const item = asnItem(typed(null));
    expect(item.what).toBe(copy.items.asn.what);
    expect(item.data.some((d) => d.label === "Тип адреса")).toBe(false);
  });

  it("незнакомый тип от более нового шлюза игнорируется", () => {
    const item = asnItem({ status: "ok", code: "X", message: "m", detail: { sources: [], ip_type: "datacenter" as never } });
    expect(item.what).toBe(copy.items.asn.what);
  });

  it("тексты без жаргона и покрывают все типы", () => {
    const types: IpType[] = ["hosting", "residential", "tor", "vpn", "unknown"];
    for (const t of types) {
      expect(copy.ipType.names[t]).toBeTruthy();
      expect(copy.ipType.short[t]).toBeTruthy();
    }
    const all = JSON.stringify([copy.ipType, copy.advice.asn, copy.ipv6Exit]);
    expect(all).not.toMatch(/ASN|DNSBL|PTR|резолвер/i);
  });

  it("старый отчёт без ipv6_exit читается как IPv4", () => {
    expect(report(fourteen()).ipv6_exit).toBeUndefined();
  });
});

describe("матрица приоритетов по ИИ-провайдерам и группировка", () => {
  const ALL_14_IDS = [
    "geo_matrix",
    "claude_exit",
    "pinning",
    "travel",
    "dnsbl",
    "asn",
    "ipv6",
    "dns",
    "timezone",
    "wifi_geo",
    "reverse_dns",
    "dns_country",
    "locale_hygiene",
    "udp_stun",
  ];

  it("все 14 проверок без повторов и пропусков заданы для Claude, ChatGPT и Gemini", () => {
    for (const provider of ["anthropic", "openai", "gemini"] as ProviderId[]) {
      const spec = PROVIDER_CHECK_MATRIX[provider];
      const all = [...spec.tier1, ...spec.tier2, ...spec.tier3];
      expect(all).toHaveLength(14);
      expect(new Set(all).size).toBe(14);
      expect([...all].sort()).toEqual([...ALL_14_IDS].sort());
    }
    expect(PROVIDER_CHECK_MATRIX.anthropic.tier3Advisory).toBe(false);
    expect(PROVIDER_CHECK_MATRIX.openai.tier3Advisory).toBe(true);
    expect(PROVIDER_CHECK_MATRIX.gemini.tier3Advisory).toBe(true);
  });

  it("приоритет проверок меняется в зависимости от провайдера (Claude vs ChatGPT vs Gemini)", () => {
    // wifi_geo: Tier 3 у Claude/ChatGPT, но Tier 1 у Gemini; travel: Tier 1 у Claude, Tier 2 у ChatGPT/Gemini
    expect(priorityOfCheck("wifi_geo", "anthropic")).toMatchObject({ tier: 3, advisory: false });
    expect(priorityOfCheck("wifi_geo", "openai")).toMatchObject({ tier: 3, advisory: true });
    expect(priorityOfCheck("wifi_geo", "gemini")).toMatchObject({ tier: 1, advisory: false });
    expect(priorityOfCheck("travel", "anthropic").tier).toBe(1);
    expect(priorityOfCheck("travel", "openai").tier).toBe(2);
    expect(priorityOfCheck("udp_stun", "gemini").tier).toBe(1);
    expect(priorityOfCheck("udp_stun", "anthropic").tier).toBe(2);

    // Одинаковые предупреждения по travel (2), dnsbl (3), wifi_geo (8), udp_stun (12) сортируются по-разному
    const items = buildChecks(
      report(fourteen({ 2: warn(), 3: warn(), 8: warn(), 12: warn() })),
      null,
    ).items;

    expect(partitionChecksForProvider(items, "anthropic").actionItems.map((i) => i.id)).toEqual([
      "travel",
      "dnsbl",
      "udp_stun",
      "wifi_geo",
    ]);
    expect(partitionChecksForProvider(items, "openai").actionItems.map((i) => i.id)).toEqual([
      "dnsbl",
      "udp_stun",
      "travel",
      "wifi_geo",
    ]);
    expect(partitionChecksForProvider(items, "gemini").actionItems.map((i) => i.id)).toEqual([
      "udp_stun",
      "wifi_geo",
      "travel",
      "dnsbl",
    ]);
  });

  it("деление на требующие внимания (вверху) и пройденные/na (в «Остальные проверки»)", () => {
    // 0: geo (crit, Tier 1), 6: dns (unknown, Tier 2), 8: wifi_geo (na), 11: locale_hygiene (warn, Tier 3)
    const r = report(fourteen({ 0: crit(), 6: unknown(), 8: unknown("not_applicable"), 11: warn() }));
    const { items } = buildChecks(r, null);
    const { actionItems, passedItems } = partitionChecksForProvider(items, "openai");

    // Подтверждённые замечания отсортированы по Tier, затем unknown, а ok + na уходят в passedItems
    expect(actionItems.map((i) => i.id)).toEqual(["geo_matrix", "locale_hygiene", "dns"]);
    expect(passedItems).toHaveLength(11);
    expect(passedItems.some((i) => i.id === "wifi_geo" && i.cls === "na")).toBe(true);
    expect(passedItems.filter((i) => i.cls === "ok")).toHaveLength(10);
  });

  it("pickWorstProvider выбирает худший отчёт с порядком Claude -> ChatGPT -> Gemini", () => {
    const mk = (provider: ProviderId, overall_status: RiskReport["overall_status"], over: Partial<RiskReport> = {}): RiskReport =>
      report(fourteen(), { provider, overall_status, ...over });

    expect(pickWorstProvider({})).toBe("anthropic");
    expect(
      pickWorstProvider({
        anthropic: mk("anthropic", "green"),
        openai: mk("openai", "yellow"),
        gemini: mk("gemini", "red"),
      }),
    ).toBe("gemini");
    expect(
      pickWorstProvider({
        anthropic: mk("anthropic", "green"),
        openai: mk("openai", "yellow"),
        gemini: mk("gemini", "yellow"),
      }),
    ).toBe("openai");
    expect(
      pickWorstProvider({
        anthropic: mk("anthropic", "red"),
        openai: mk("openai", "red"),
        gemini: mk("gemini", "red"),
      }),
    ).toBe("anthropic");
    expect(
      pickWorstProvider({
        anthropic: mk("anthropic", "green"),
        openai: mk("openai", "green"),
        gemini: mk("gemini", "green", { incomplete: true }),
      }),
    ).toBe("gemini");
  });
});

describe("formatOsTzError", () => {
  it("преобразует отмену запроса прав ОС в дружелюбное сообщение без пугающих кодов", () => {
    expect(formatOsTzError(new Error("OS_TZ_ELEVATION_CANCELLED: user declined UAC"))).toBe(
      "Запрос прав администратора отменён",
    );
    expect(formatOsTzError("network error")).toBe("network error");
  });
});
