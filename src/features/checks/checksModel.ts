import type { AppStateData, CheckResult, ProviderId, RiskReport } from "../../types";
import { checks as copy } from "../../shared/copy/ru";
import type { CheckGroupId, CheckId } from "../../shared/copy/ru";

/** Что можно сделать с непройденной проверкой. */
export type CheckAction = "pin" | "sync-timezone" | "guide";

/** Пара «название — значение» второго уровня. mono — только для IP, доменов и кодов. */
export interface CheckDatum {
  label: string;
  value: string;
  mono: boolean;
}

export interface CheckItem {
  /** Известный id или `extra_<позиция>` для проверки сверх известных. */
  id: string;
  group: CheckGroupId;
  title: string;
  what: string;
  result: CheckResult;
  cls: CheckClass;
  ok: boolean;
  /** Проверки нет в отчёте: строка показывает «Нет данных». */
  missing: boolean;
  data: CheckDatum[];
  /** Главное действие непройденной проверки. */
  action: CheckAction | null;
  /** «Что делать» при замечании или «не удалось проверить»; у проверок без такого текста null. */
  advice: string | null;
}

export interface CheckGroup {
  id: CheckGroupId;
  title: string;
  items: CheckItem[];
}

/** ok — пройдена; warn/crit — замечание; unknown — не удалось проверить; na — не применима (вне счёта). */
export type CheckClass = "ok" | "warn" | "crit" | "unknown" | "na";

/** Единственное место, где статус превращается в класс. Всё незнакомое — unknown, никогда не ok. */
export function classify(c: CheckResult): CheckClass {
  switch (c.status) {
    case "ok":
    case "green":
      return "ok";
    case "warning":
    case "yellow":
      return "warn";
    case "critical":
    case "red":
      return "crit";
    default:
      return c.reason === "not_applicable" ? "na" : "unknown";
  }
}

export const isOkStatus = (c: CheckResult) => classify(c) === "ok";
export const isCriticalStatus = (c: CheckResult) => classify(c) === "crit";

/** Отчёт «жёлтый» только из-за непроверенного: замечаний (warn/crit) в нём нет. */
export function isYellowOnlyUnknown(report: RiskReport | null | undefined, results: CheckResult[]): boolean {
  if (!report || report.overall_status !== "yellow") return false;
  const c = countChecks(results);
  return c.unknown > 0 && c.warn === 0 && c.crit === 0;
}

export interface CheckCounts {
  ok: number;
  warn: number;
  crit: number;
  unknown: number;
  na: number;
  /** M в «N из M»: все проверки, кроме «не применимо». */
  applicable: number;
}

export function countChecks(results: CheckResult[]): CheckCounts {
  const n: CheckCounts = { ok: 0, warn: 0, crit: 0, unknown: 0, na: 0, applicable: 0 };
  for (const r of results) n[classify(r)] += 1;
  n.applicable = n.ok + n.warn + n.crit + n.unknown;
  return n;
}

/** Порядок задан шлюзом: report.checks содержит эти проверки на этих местах; всё, что дальше, показываем обобщённой строкой. */
const ORDER: { id: CheckId; group: CheckGroupId; index: number }[] = [
  { id: "geo_matrix", group: "address", index: 0 },
  { id: "asn", group: "address", index: 4 },
  { id: "dnsbl", group: "address", index: 3 },
  { id: "reverse_dns", group: "address", index: 9 },
  { id: "pinning", group: "stability", index: 1 },
  { id: "travel", group: "stability", index: 2 },
  { id: "ipv6", group: "leaks", index: 5 },
  { id: "dns", group: "leaks", index: 6 },
  { id: "dns_country", group: "leaks", index: 10 },
  { id: "wifi_geo", group: "leaks", index: 8 },
  { id: "timezone", group: "environment", index: 7 },
  { id: "locale_hygiene", group: "environment", index: 11 },
  { id: "udp_stun", group: "leaks", index: 12 },
];

const GROUP_ORDER: CheckGroupId[] = ["address", "stability", "leaks", "environment"];

/** Результат по месту в report.checks; для первых проверок страхуемся именованными полями отчёта. */
function resultAt(report: RiskReport, id: CheckId, index: number): CheckResult | null {
  const named: Partial<Record<CheckId, CheckResult>> = {
    geo_matrix: report.geo_result,
    pinning: report.pinning_result,
    travel: report.travel_result,
    dnsbl: report.dnsbl_result,
    asn: report.asn_result,
    ipv6: report.ipv6_result,
    timezone: report.timezone_result,
  };
  return named[id] ?? report.checks?.[index] ?? null;
}

/** «ответили N из M» из текста проверки: число зон берём из данных, а не из константы. */
function answeredZones(report: RiskReport): string | null {
  const m = /ответили\s+(\d+)\s+из\s+(\d+)/i.exec(report.dnsbl_result?.message ?? "");
  return m ? `${m[1]} из ${m[2]}` : null;
}

function dataFor(id: CheckId, report: RiskReport, state: AppStateData | null): CheckDatum[] {
  const t = report.telemetry;
  const d = copy.data;
  const out: CheckDatum[] = [];
  const add = (label: string, value: string | null | undefined, mono: boolean) => {
    if (value) out.push({ label, value, mono });
  };
  switch (id) {
    case "geo_matrix":
      add(d.country, t.country_code, true);
      add(d.ip, t.ip, true);
      break;
    case "asn":
      add(d.asn, t.asn ? `AS${t.asn}` : null, true);
      add(d.provider, t.isp || t.org, false);
      break;
    case "dnsbl":
      add(d.result, report.dnsbl_clean_count, false);
      add(d.answeredZones, answeredZones(report), false);
      break;
    case "reverse_dns":
      add(d.ip, t.ip, true);
      break;
    case "pinning":
      add(d.pinnedIp, state?.pinned_ip ?? null, true);
      if (!state?.pinned_ip) out.push({ label: d.pinnedIp, value: d.notPinned, mono: false });
      add(d.mode, state?.strict_pinning_enabled ? d.strict : d.notify, false);
      break;
    case "travel":
      add(d.country, t.country_code, true);
      break;
    case "timezone":
      add(d.zoneIp, t.timezone, true);
      add(d.zoneAi, state?.synced_ai_timezone, true);
      break;
    case "locale_hygiene":
      add(d.zoneAi, state?.synced_ai_timezone, true);
      break;
    default:
      break;
  }
  return out;
}

function actionFor(id: string, result: CheckResult, cls: CheckClass): CheckAction | null {
  if (cls === "ok" || cls === "unknown" || cls === "na") return null;
  if (id === "pinning") return "pin";
  if (id === "timezone" || id === "locale_hygiene") return "sync-timezone";
  return result.guide_ref ? "guide" : null;
}

function adviceFor(id: CheckId, cls: CheckClass): string | null {
  const text = (copy.advice as Partial<Record<CheckId, { warn: string; unknown: string }>>)[id];
  if (!text) return null;
  if (cls === "warn" || cls === "crit") return text.warn;
  if (cls === "unknown") return text.unknown;
  return null;
}

/** Заглушка для проверки, которой нет в отчёте: не пропадает из счёта, а считается «не удалось проверить». */
function missingResult(): CheckResult {
  return { status: "unknown", code: "CHECK_MISSING", message: copy.missingMessage, reason: "no_data" };
}

export interface BuiltChecks {
  groups: CheckGroup[];
  items: CheckItem[];
  counts: CheckCounts;
  /** M в «N из M»: из отчёта (applicable_count) или из числа проверок; берётся большее. */
  total: number;
}

/** Проверки отчёта, сгруппированные по смыслу. Без побочных эффектов. */
export function buildChecks(report: RiskReport, state: AppStateData | null): BuiltChecks {
  const items: CheckItem[] = [];
  const push = (id: string, group: CheckGroupId, result: CheckResult, missing: boolean) => {
    const known = id in copy.items;
    const cls = classify(result);
    items.push({
      id,
      group,
      title: known ? copy.items[id as CheckId].title : copy.extra.title,
      what: known ? copy.items[id as CheckId].what : copy.extra.what,
      result,
      cls,
      ok: cls === "ok",
      missing,
      data: known ? dataFor(id as CheckId, report, state) : [],
      action: actionFor(id, result, cls),
      advice: known ? adviceFor(id as CheckId, cls) : null,
    });
  };
  for (const spec of ORDER) {
    const found = resultAt(report, spec.id, spec.index);
    push(spec.id, spec.group, found ?? missingResult(), !found);
  }
  // Проверки сверх известных мест не теряем.
  const known = Math.max(...ORDER.map((o) => o.index)) + 1;
  (report.checks ?? []).slice(known).forEach((result, i) => push(`extra_${known + i}`, "leaks", result, false));

  const groups = GROUP_ORDER.map((id) => ({
    id,
    title: copy.groups[id],
    items: items.filter((i) => i.group === id),
  })).filter((g) => g.items.length > 0);
  const counts = countChecks(items.map((i) => i.result));
  const total = Math.max(counts.applicable, report.applicable_count ?? 0);
  return { groups, items, counts, total };
}

/** Порядок сервисов при равной тяжести отчётов. */
export const PROVIDER_ORDER: ProviderId[] = ["anthropic", "openai", "gemini"];

/** Тяжесть отчёта: 2 — красный, 1 — жёлтый или неполный, 0 — зелёный. */
function reportRank(report: RiskReport): number {
  if (report.overall_status === "red") return 2;
  if (report.overall_status === "yellow" || report.incomplete) return 1;
  return 0;
}

/** Худший отчёт из трёх; при равенстве — первый по порядку Claude, ChatGPT, Gemini. Без отчётов — null. */
export function pickWorstReport(
  reports: Partial<Record<ProviderId, RiskReport>>,
): { provider: ProviderId; report: RiskReport } | null {
  let best: { provider: ProviderId; report: RiskReport } | null = null;
  let bestRank = -1;
  for (const provider of PROVIDER_ORDER) {
    const report = reports[provider];
    if (!report) continue;
    const rank = reportRank(report);
    if (rank > bestRank) {
      best = { provider, report };
      bestRank = rank;
    }
  }
  return best;
}

/** Непройденные проверки отчёта (замечание, критично, не удалось проверить; «не применимо» не считается). Берётся из того же кода, что строит экран. */
export function failedChecks(report: RiskReport, state: AppStateData | null): CheckItem[] {
  return buildChecks(report, state).items.filter((i) => i.cls === "warn" || i.cls === "crit" || i.cls === "unknown");
}
