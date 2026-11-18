import type { ProviderId, RiskReport } from "../../types";
import type { CheckId } from "../../shared/copy/ru";
import type { CheckClass, CheckItem } from "./checksModel";

/** Порядок сервисов при равной тяжести отчётов. */
export const PROVIDER_ORDER: ProviderId[] = ["anthropic", "openai", "gemini"];

/** Тяжесть отчёта: 2 — красный, 1 — жёлтый или неполный, 0 — зелёный. */
function reportRank(report: RiskReport): number {
  if (report.overall_status === "red") return 2;
  if (report.overall_status === "yellow" || report.incomplete) return 1;
  return 0;
}

/** Худший отчёт из трёх; при равенстве — первый по порядку Claude, ChatGPT, Gemini. Отключённые сервисы пропускаются. Без отчётов — null. */
export function pickWorstReport(
  reports: Partial<Record<ProviderId, RiskReport>>,
  disabledProviders?: string[],
): { provider: ProviderId; report: RiskReport } | null {
  const disabled = new Set((disabledProviders ?? []).map((p) => p.toLowerCase()));
  let best: { provider: ProviderId; report: RiskReport } | null = null;
  let bestRank = -1;
  for (const provider of PROVIDER_ORDER) {
    if (disabled.has(provider)) continue;
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

/** Худший провайдер из доступных отчётов; при равенстве — Claude, ChatGPT, Gemini. Отключённые сервисы пропускаются. */
export function pickWorstProvider(
  reports: Partial<Record<ProviderId, RiskReport>>,
  disabledProviders?: string[],
): ProviderId {
  const picked = pickWorstReport(reports, disabledProviders)?.provider;
  if (picked) return picked;
  const disabled = new Set((disabledProviders ?? []).map((p) => p.toLowerCase()));
  return PROVIDER_ORDER.find((p) => !disabled.has(p)) ?? "anthropic";
}

export type CheckPriorityTier = 1 | 2 | 3;

export interface ProviderPrioritySpec {
  tier1: readonly CheckId[];
  tier2: readonly CheckId[];
  tier3: readonly CheckId[];
  tier3Advisory: boolean;
}

/** Приоритет и важность каждой из 13 проверок в разрезе конкретного ИИ-провайдера. */
export const PROVIDER_CHECK_MATRIX: Record<ProviderId, ProviderPrioritySpec> = {
  anthropic: {
    tier1: ["geo_matrix", "claude_exit", "travel", "ipv6", "dnsbl", "asn"],
    tier2: ["pinning", "timezone", "locale_hygiene", "dns", "dns_country", "udp_stun", "reverse_dns"],
    tier3: ["wifi_geo"],
    tier3Advisory: false,
  },
  openai: {
    tier1: ["geo_matrix", "claude_exit", "ipv6", "dnsbl", "asn"],
    tier2: ["dns", "dns_country", "udp_stun", "pinning", "travel", "timezone"],
    tier3: ["locale_hygiene", "reverse_dns", "wifi_geo"],
    tier3Advisory: true,
  },
  gemini: {
    tier1: ["geo_matrix", "ipv6", "udp_stun", "dns", "dns_country", "asn", "wifi_geo"],
    tier2: ["claude_exit", "timezone", "pinning", "travel", "dnsbl"],
    tier3: ["locale_hygiene", "reverse_dns"],
    tier3Advisory: true,
  },
};

export interface CheckPriorityInfo {
  tier: CheckPriorityTier;
  rank: number;
  advisory: boolean;
}

export type PrioritizedCheckItem = CheckItem & CheckPriorityInfo;

/** Определяет уровень важности и порядок сортировки проверки для выбранного провайдера. */
export function priorityOfCheck(id: string, provider: ProviderId): CheckPriorityInfo {
  const spec = PROVIDER_CHECK_MATRIX[provider];
  const i1 = spec.tier1.indexOf(id as CheckId);
  if (i1 >= 0) return { tier: 1, rank: i1, advisory: false };
  const i2 = spec.tier2.indexOf(id as CheckId);
  if (i2 >= 0) return { tier: 2, rank: 100 + i2, advisory: false };
  const i3 = spec.tier3.indexOf(id as CheckId);
  if (i3 >= 0) return { tier: 3, rank: 200 + i3, advisory: spec.tier3Advisory };
  return { tier: 3, rank: 300, advisory: false };
}

function actionBucket(cls: CheckClass): number {
  if (cls === "crit" || cls === "warn") return 0;
  if (cls === "unknown") return 1;
  return 2;
}

/**
 * Делит проверки на требующие внимания (отсортированы по приоритету провайдера)
 * и пройденные (`ok` и `not_applicable`) для сворачивания в «Остальные проверки».
 */
export function partitionChecksForProvider(
  items: CheckItem[],
  provider: ProviderId,
): { actionItems: PrioritizedCheckItem[]; passedItems: PrioritizedCheckItem[] } {
  const actionItems: PrioritizedCheckItem[] = [];
  const passedItems: PrioritizedCheckItem[] = [];

  for (const item of items) {
    const prio = priorityOfCheck(item.id, provider);
    const enriched: PrioritizedCheckItem = { ...item, ...prio };
    if (item.cls === "ok" || item.cls === "na") passedItems.push(enriched);
    else actionItems.push(enriched);
  }

  actionItems.sort((a, b) => {
    const bucketDiff = actionBucket(a.cls) - actionBucket(b.cls);
    if (bucketDiff !== 0) return bucketDiff;
    const tierDiff = a.tier - b.tier;
    if (tierDiff !== 0) return tierDiff;
    if (a.cls !== b.cls) {
      if (a.cls === "crit") return -1;
      if (b.cls === "crit") return 1;
    }
    return a.rank - b.rank;
  });

  passedItems.sort((a, b) => {
    if (a.cls !== b.cls) return a.cls === "ok" ? -1 : 1;
    return a.rank - b.rank;
  });

  return { actionItems, passedItems };
}
