import type {
  AuditProgressEvent,
  PartialAudit,
  ProviderId,
  RiskReport,
  RoutesSnapshot,
} from "../../types";

export type ReportsMap = Partial<Record<ProviderId, RiskReport>>;

const PROVIDER_IDS: ProviderId[] = ["anthropic", "openai", "gemini"];

/** Порог устаревания отчёта без ошибок: 15 минут. */
export const STALE_REPORT_MS = 15 * 60_000;
/** Перепроверка при возврате фокуса окна: если отчёту больше 3 минут. */
export const FOCUS_REFRESH_MS = 3 * 60_000;
/** Число проверок в отчёте шлюза (места 0..13 в `RiskReport.checks`). */
export const CHECK_SLOTS = 14;

/** Возраст отчёта в минутах для подписи или null, если данные свежие и аудит не падал. */
export function dataAge(ageMs: number, auditFailed: boolean): number | null {
  if (!auditFailed && ageMs < STALE_REPORT_MS) return null;
  return Math.max(1, Math.floor(ageMs / 60_000));
}

export function isValidGatewayLatency(gwMs: unknown): gwMs is number {
  return typeof gwMs === "number" && Number.isFinite(gwMs) && gwMs >= 0;
}

/** Новый идущий аудит: ничего ещё не готово. */
export function emptyPartial(provider: ProviderId, runId: string): PartialAudit {
  return {
    runId,
    provider,
    telemetry: null,
    checks: Array.from({ length: CHECK_SLOTS }, () => null),
  };
}

/** Вносит кусок аудита в накопленное; события чужого запуска (устаревшего) игнорируются. */
export function applyProgress(
  prev: PartialAudit | undefined,
  event: AuditProgressEvent,
): PartialAudit | undefined {
  if (!prev || prev.runId !== event.run_id) return prev;
  if (event.kind === "telemetry") return { ...prev, telemetry: event.telemetry };
  if (event.index < 0 || event.index >= prev.checks.length) return prev;
  const checks = prev.checks.slice();
  checks[event.index] = event.result;
  return { ...prev, checks };
}

/** Точечно обновляет отчёт одного сервиса, не затрагивая отчёты остальных. */
export function mergeProviderReport(
  prev: ReportsMap,
  providerId: ProviderId,
  report: RiskReport,
): ReportsMap {
  return { ...prev, [providerId]: report };
}

/**
 * Drops stale reports after a network transition, guard freeze, or interception alert.
 * Key-routed providers (`routesSnapshot.effective[id]` is non-empty) retain their reports
 * unless `onlyProviders` targets them or `includeAll` is set.
 */
export function invalidateStaleReports(
  prev: ReportsMap,
  routesSnapshot?: RoutesSnapshot | null,
  onlyProviders?: string[],
  includeAll = false,
): ReportsMap {
  if (includeAll) return {};
  const targetSet =
    onlyProviders && onlyProviders.length > 0
      ? new Set(onlyProviders.map((p) => p.toLowerCase()))
      : null;

  let changed = false;
  const next: ReportsMap = { ...prev };
  for (const id of PROVIDER_IDS) {
    if (!next[id]) continue;
    if (targetSet) {
      if (targetSet.has(id)) {
        delete next[id];
        changed = true;
      }
      continue;
    }
    const isRouted = Boolean(routesSnapshot?.effective?.[id]);
    if (!isRouted) {
      delete next[id];
      changed = true;
    }
  }
  return changed ? next : prev;
}
