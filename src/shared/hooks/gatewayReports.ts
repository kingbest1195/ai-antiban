import type {
  AuditProgressEvent,
  GuardPauseStatus,
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

export interface RecentAuditRefresh {
  ip: string;
  at: number;
}

/** Окно дедупликации `network://changed` сразу после `audit://refreshed` для того же IP. */
export const AUDIT_REFRESH_DEDUPE_MS = 5_000;

/**
 * При `paused`, `blocked` или транзиентном `pending` отчёты не сбрасываем, чтобы экран не мигал
 * «11 из 11 -> 0 из 14 -> 11 из 11»; UI переходит в статус перепроверки через `guardPauseStatus`.
 */
export function shouldInvalidateOnPauseStatus(snap: GuardPauseStatus): {
  invalidate: boolean;
  onlyProviders?: string[];
  includeAll: boolean;
} {
  if (snap.paused || snap.gate === "blocked") {
    return { invalidate: false, includeAll: false };
  }
  const pending = snap.pending_providers ?? [];
  if (snap.manual_killswitch) {
    return { invalidate: true, onlyProviders: pending.length > 0 ? pending : undefined, includeAll: true };
  }
  return { invalidate: false, includeAll: false };
}

/** Возвращает true, если `audit://refreshed` уже недавно доставил отчёт для того же IP. */
export function isRedundantNetworkAudit(
  recent: RecentAuditRefresh | null | undefined,
  payloadIp: string | null | undefined,
  now: number = Date.now(),
  windowMs: number = AUDIT_REFRESH_DEDUPE_MS,
): boolean {
  const recentIp = recent?.ip?.trim();
  const nextIp = payloadIp?.trim();
  if (!recent || !recentIp || recentIp === "--" || !nextIp || nextIp === "--") return false;
  if (now - recent.at > windowMs) return false;
  return recentIp === nextIp;
}

/** Возвращает true только при подтверждённой смене известного внешнего IP на другой. */
export function isConfirmedIpChange(
  currentIp: string | null | undefined,
  payloadIp: string | null | undefined,
): boolean {
  const prev = currentIp?.trim();
  const next = payloadIp?.trim();
  if (!prev || prev === "--" || !next || next === "--") return false;
  return prev !== next;
}

/** Подавляет фоновый 1.5с self-heal аудит, пока шлюз в pending или на паузе. */
export function shouldSuppressSelfHeal(guardPauseStatus: GuardPauseStatus | null | undefined): boolean {
  return guardPauseStatus?.gate === "pending" || guardPauseStatus?.paused === true;
}

/** Выбирает активный отчёт первого включённого провайдера (с фоллбэком на любой доступный). */
export function pickActiveReport(
  reports: ReportsMap,
  disabledProviders?: string[] | null,
): RiskReport | null {
  const disabled = new Set((disabledProviders ?? []).map((p) => p.toLowerCase()));
  for (const id of PROVIDER_IDS) {
    if (!disabled.has(id) && reports[id]) return reports[id]!;
  }
  return reports.anthropic ?? reports.openai ?? reports.gemini ?? null;
}

/** Возвращает включённых провайдеров, чей отчёт отсутствует (например, упал при холодном старте). */
export function findMissingEnabledProviders(
  reports: ReportsMap,
  disabledProviders?: string[] | null,
): ProviderId[] {
  const disabled = new Set((disabledProviders ?? []).map((p) => p.toLowerCase()));
  return PROVIDER_IDS.filter((id) => !disabled.has(id) && !reports[id]);
}

export interface SelfHealPlan {
  needed: boolean;
  missingIpOrProvider: boolean;
  missingProviders: ProviderId[];
}

/** Определяет, нужен ли повторный self-heal из-за неполного активного отчёта или пропущенных провайдеров. */
export function needsStartupSelfHeal(
  activeReport: RiskReport | null | undefined,
  reports: ReportsMap,
  disabledProviders?: string[] | null,
): SelfHealPlan {
  const missingProviders = findMissingEnabledProviders(reports, disabledProviders);
  const missingIp = !activeReport || !activeReport.telemetry?.ip || activeReport.telemetry.ip === "--";
  const missingProvider = Boolean(
    activeReport &&
      !activeReport.telemetry?.asn &&
      !activeReport.telemetry?.isp &&
      !activeReport.telemetry?.org,
  );
  const missingIpOrProvider = missingIp || missingProvider;
  return {
    needed: missingIpOrProvider || missingProviders.length > 0,
    missingIpOrProvider,
    missingProviders,
  };
}

/** Возвращает true при возврате фокуса, если отчёт устарел ИЛИ у включённого провайдера нет отчёта. */
export function shouldRefreshOnFocus(
  lastReportAt: number | null,
  now: number,
  hasMissingReports: boolean,
): boolean {
  if (lastReportAt == null) return false;
  if (hasMissingReports) return true;
  return now - lastReportAt > FOCUS_REFRESH_MS;
}

/** Запрашивает отчёты только для пропущенных включённых провайдеров и объединяет успешные результаты. */
export async function fetchMissingProviderReports(
  providers: ProviderId[],
  auditFn: (provider: ProviderId, force: boolean) => Promise<RiskReport>,
): Promise<Array<[ProviderId, RiskReport]>> {
  const settled = await Promise.allSettled(
    providers.map(async (id) => [id, await auditFn(id, true)] as [ProviderId, RiskReport]),
  );
  const out: Array<[ProviderId, RiskReport]> = [];
  for (const res of settled) {
    if (res.status === "fulfilled") out.push(res.value);
  }
  return out;
}
