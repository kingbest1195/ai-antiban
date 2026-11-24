import { useMemo } from "react";
import type {
  AppStateData,
  CheckResult,
  GuardPauseStatus,
  ProviderId,
  RiskReport,
  RouteUnavailablePayload,
  UpdateCheckResult,
} from "../../types";
import { checksWord, resolvePinnedIp } from "../../shared/lib/format";
import { classify, countChecks, failedChecks, isYellowOnlyUnknown, pickWorstReport } from "../checks/checksModel";
import { overview as copy } from "../../shared/copy/ru";
import type { HeroTone, TabItem } from "../../ui";

export type ServiceStatus = "ok" | "allowed" | "warn" | "critical" | "missing" | "checking" | "disabled";
export type ServiceAllowReason = "trusted_exception" | "session" | "pinned_travel";

export interface ServiceModel {
  id: ProviderId;
  status: ServiceStatus;
  allowReason?: ServiceAllowReason;
}

export type BannerKind = "stopped" | "frozen" | "leak" | "timezone" | "review" | "incomplete" | "update";
export type PinState = "pinned" | "changed" | "none";

export interface OverviewModel {
  verdict: string;
  tone: HeroTone;
  checksPassed: number;
  checksTotal: number;
  /** Сколько проверок не удалось выполнить (не «применимо» и не «пройдено»). */
  checksUnknown: number;
  checksLabel: string;
  /** Имя провайдера для бейджа (isp или org); без жаргона вроде ASN. */
  providerName: string | null;
  pinState: PinState;
  banner: BannerKind | null;
  services: ServiceModel[];
}

const PROVIDER_IDS: ProviderId[] = ["anthropic", "openai", "gemini"];

/** Позиции проверок DNS-резолвера в `RiskReport.checks` (`dns` = 6, `dns_country` = 10). */
const DNS_RESOLVER_CHECK_INDICES = new Set([6, 10]);

/** Сколько непройденных `unknown`-проверок есть за вычетом сбоя DNS-резолвера (не красим из-за него главную в жёлтый). */
function nonDnsUnknownCount(report: RiskReport | null | undefined, checks: CheckResult[]): number {
  const hasIndexedChecks = Boolean(report?.checks && report.checks.length > 0);
  return checks.filter((c, i) => {
    if (classify(c) !== "unknown") return false;
    if (hasIndexedChecks && DNS_RESOLVER_CHECK_INDICES.has(i)) return false;
    return true;
  }).length;
}

function checksOf(report: RiskReport | null): CheckResult[] {
  if (!report) return [];
  if (report.checks && report.checks.length > 0) return report.checks;
  return [
    report.geo_result,
    report.pinning_result,
    report.travel_result,
    report.dnsbl_result,
    report.asn_result,
    report.ipv6_result,
    report.timezone_result,
  ];
}

interface Input {
  reports: Partial<Record<ProviderId, RiskReport>>;
  activeReport: RiskReport | null;
  state: AppStateData | null;
  currentIp: string;
  sysproxyActive: boolean;
  killswitchFrozen: boolean;
  updateInfo: UpdateCheckResult | null;
  /** Идёт аудит: у сервиса без отчёта показываем «Проверяем», а не «Нужна проверка». */
  refreshing: boolean;
  /** Шлюз ещё запускается в фоне: защита не включена, не объявляем ни «защищены», ни «выключена». */
  startupPending?: boolean;
  /** Текущий снимок паузы/затворов NetworkGuard. */
  guardPauseStatus?: GuardPauseStatus | null;
  /** Активное уведомление о недоступности выбранного маршрута. */
  routeUnavailable?: RouteUnavailablePayload | null;
}

/** Вывод показателей «Обзора» из сырых данных: вердикт, бейджи, баннер и статусы сервисов. Тут нет побочных эффектов. */
export function useOverviewModel({
  reports,
  activeReport,
  state,
  currentIp,
  sysproxyActive,
  killswitchFrozen,
  updateInfo,
  refreshing,
  startupPending = false,
  guardPauseStatus = null,
  routeUnavailable = null,
}: Input): OverviewModel {
  return useMemo(() => {
    const disabledSet = new Set((state?.disabled_providers ?? []).map((p) => p.toLowerCase()));
    const enabledProviderIds = PROVIDER_IDS.filter((id) => !disabledSet.has(id));
    const effectiveActiveReport =
      (activeReport && !disabledSet.has(activeReport.provider) ? activeReport : null) ??
      enabledProviderIds.map((id) => reports[id]).find(Boolean) ??
      null;
    const pendingSet = new Set((guardPauseStatus?.pending_providers ?? []).map((p) => p.toLowerCase()));
    const guardBlockedSet = new Set((guardPauseStatus?.blocked_providers ?? []).map((p) => p.toLowerCase()));
    const hasGlobalPending = guardPauseStatus?.gate === "pending" && pendingSet.size === 0;
    const isProviderPending = (id: ProviderId): boolean =>
      pendingSet.has(id) ||
      (hasGlobalPending &&
        !guardBlockedSet.has(id) &&
        !state?.blocked_providers?.includes(id) &&
        !state?.provider_routes?.[id] &&
        !state?.default_route_id &&
        !state?.profile_route_id);
    const isProviderRouteBroken = (id: ProviderId): boolean =>
      Boolean(routeUnavailable && (routeUnavailable.provider === id || routeUnavailable.provider === "all"));

    const allowReasonFor = (id: ProviderId): ServiceAllowReason | null => {
      if (disabledSet.has(id) || isProviderPending(id) || guardBlockedSet.has(id) || isProviderRouteBroken(id)) {
        return null;
      }
      const exitIp = reports[id]?.telemetry?.ip || (currentIp !== "--" ? currentIp : "");
      const trimmedExit = exitIp.trim();
      if (trimmedExit && state?.trusted_exceptions?.[id]?.some((ip) => ip.trim() === trimmedExit)) {
        return "trusted_exception";
      }
      if (state?.session_allowed_providers?.includes(id)) {
        return "session";
      }
      if (!trimmedExit) return null;
      const pinned = resolvePinnedIp(state, id);
      if (pinned && pinned.trim() === trimmedExit && !state?.blocked_providers?.includes(id)) {
        const list = checksOf(reports[id] ?? null);
        const criticals = list.filter((c) => classify(c) === "crit");
        // Закреплённый IP в разрешённой локации перекрывает только IMPOSSIBLE_TRAVEL_CRITICAL.
        if (criticals.length > 0 && criticals.every((c) => c.code === "IMPOSSIBLE_TRAVEL_CRITICAL")) {
          return "pinned_travel";
        }
      }
      return null;
    };
    const isAllowedFor = (id: ProviderId): boolean => allowReasonFor(id) !== null;

    const anyPending =
      guardPauseStatus?.gate === "pending" ||
      enabledProviderIds.some((id) => isProviderPending(id));
    const anyRed = enabledProviderIds.some(
      (id) =>
        (reports[id]?.overall_status === "red" && !isAllowedFor(id)) ||
        Boolean(state?.blocked_providers?.includes(id)) ||
        guardBlockedSet.has(id) ||
        Boolean(guardPauseStatus?.manual_killswitch) ||
        isProviderRouteBroken(id),
    );
    const anyYellow = enabledProviderIds.some(
      (id) =>
        reports[id]?.overall_status === "yellow" &&
        !isYellowOnlyUnknown(reports[id], checksOf(reports[id] ?? null)) &&
        !isAllowedFor(id),
    );

    const bad = (c?: CheckResult) => {
      if (!c) return false;
      const k = classify(c);
      return k === "warn" || k === "crit";
    };
    const ipv6Leak = bad(effectiveActiveReport?.ipv6_result);
    const tzMismatch = bad(effectiveActiveReport?.timezone_result ?? effectiveActiveReport?.checks?.[7]);
    const dnsblBad = bad(effectiveActiveReport?.dnsbl_result);

    const checks = checksOf(effectiveActiveReport);
    const counts = countChecks(checks);
    const incomplete =
      Boolean(effectiveActiveReport?.incomplete) || nonDnsUnknownCount(effectiveActiveReport, checks) > 0;

    let verdict: string = copy.verdict.ok;
    let tone: HeroTone = "ok";
    if (killswitchFrozen || guardPauseStatus?.manual_killswitch) {
      verdict = copy.verdict.frozen;
      tone = "danger";
    } else if (startupPending) {
      // До конца запуска вывода нет: ни «Вы защищены», ни «Защита выключена».
      verdict = copy.verdict.starting;
      tone = "warn";
    } else if (routeUnavailable) {
      verdict = copy.verdict.routeUnavailable;
      tone = "danger";
    } else if (anyRed) {
      verdict = copy.verdict.stopped;
      tone = "danger";
    } else if (anyPending) {
      verdict = copy.verdict.checking;
      tone = "warn";
    } else if (!sysproxyActive) {
      verdict = copy.verdict.off;
      tone = "warn";
    } else if (anyYellow || ipv6Leak || tzMismatch) {
      verdict = copy.verdict.attention;
      tone = "warn";
    } else if (!effectiveActiveReport) {
      verdict = refreshing ? copy.verdict.checking : copy.verdict.partial;
      tone = "warn";
    } else if (incomplete) {
      verdict = copy.verdict.partial;
      tone = "warn";
    }

    let banner: BannerKind | null = null;
    if (killswitchFrozen || guardPauseStatus?.manual_killswitch) banner = "frozen";
    else if (startupPending) banner = null;
    else if (routeUnavailable) banner = "stopped";
    else if (anyRed) banner = "stopped";
    else if (ipv6Leak) banner = "leak";
    else if (tzMismatch) banner = "timezone";
    else if (anyYellow || dnsblBad) banner = "review";
    else if (incomplete) banner = "incomplete";
    else if (updateInfo?.update_available) banner = "update";

    const checksPassed = counts.ok;
    const checksTotal = Math.max(counts.applicable, effectiveActiveReport?.applicable_count ?? 0);

    const pinned = resolvePinnedIp(state, effectiveActiveReport?.provider);
    const pinState: PinState = pinned ? (pinned === currentIp ? "pinned" : "changed") : "none";

    const providerName = effectiveActiveReport?.telemetry?.isp || effectiveActiveReport?.telemetry?.org || null;

    const services: ServiceModel[] = PROVIDER_IDS.map((id) => {
      if (disabledSet.has(id)) {
        return { id, status: "disabled" };
      }
      const report = reports[id];
      const isBlocked = state?.blocked_providers?.includes(id);
      const allowReason = allowReasonFor(id);
      const isAllowed = allowReason !== null;
      const list = checksOf(report ?? null);
      const hasCritical = list.some((c) => classify(c) === "crit");
      // Непроверенное не считаем чистым (кроме сбоя самого DNS-резолвера): сервис получает статус «Нужна проверка».
      const hasWarning =
        list.some((c) => classify(c) === "warn") ||
        nonDnsUnknownCount(report, list) > 0 ||
        Boolean(report?.incomplete);

      let status: ServiceStatus = "ok";
      const guardBlocked = guardBlockedSet.has(id) || Boolean(guardPauseStatus?.manual_killswitch);
      const guardPending = isProviderPending(id);
      const routeBroken = isProviderRouteBroken(id);
      if (killswitchFrozen || isBlocked || guardBlocked || routeBroken) status = "critical";
      else if (startupPending || guardPending) status = "checking";
      else if (!report) status = refreshing ? "checking" : "missing";
      else if (isAllowed) status = "allowed";
      else if (report.overall_status === "red" || hasCritical) status = "critical";
      else if ((report.overall_status === "yellow" && !isYellowOnlyUnknown(report, list)) || hasWarning) status = "warn";
      return status === "allowed" && allowReason ? { id, status, allowReason } : { id, status };
    });

    return {
      verdict,
      tone,
      checksPassed,
      checksTotal,
      checksUnknown: counts.unknown,
      checksLabel:
        counts.unknown > 0
          ? copy.facts.checksPartial(checksPassed, checksTotal, counts.unknown)
          : copy.facts.checks(checksPassed, checksTotal, checksWord(checksTotal)),
      providerName,
      pinState,
      banner,
      services,
    };
  }, [
    reports,
    activeReport,
    state,
    currentIp,
    sysproxyActive,
    killswitchFrozen,
    updateInfo,
    refreshing,
    startupPending,
    guardPauseStatus,
    routeUnavailable,
  ]);
}

/**
 * Бейджи вкладок. «Обзор»: красная точка, когда трафик не идёт (stopped, frozen); иначе жёлтая, если `overviewNotice`
 * (защита включена, но есть замечание по покрытию); красная приоритетнее жёлтой. «Проверки»: число непройденных
 * проверок худшего отчёта, ноль — без бейджа.
 */
export function tabBadges(
  banner: BannerKind | null,
  reports: Partial<Record<ProviderId, RiskReport>>,
  state: AppStateData | null,
  overviewNotice = false,
): { overview?: TabItem["badge"]; checks?: TabItem["badge"] } {
  const out: { overview?: TabItem["badge"]; checks?: TabItem["badge"] } = {};
  if (banner === "stopped" || banner === "frozen") out.overview = "danger";
  else if (overviewNotice) out.overview = "warn";
  const worst = pickWorstReport(reports, state?.disabled_providers);
  const n = worst ? failedChecks(worst.report, state).length : 0;
  if (n > 0) out.checks = n;
  return out;
}

/** Нужно ли подтверждение перед «Разрешить принудительно»: только по фактическому риску отчёта (red / RU / BY / нет отчёта), не по флагу blocked_providers. */
export function needsForceConfirm(_status: ServiceStatus, report: RiskReport | null | undefined): boolean {
  return (
    !report ||
    report.overall_status === "red" ||
    report.telemetry?.country_code === "RU" ||
    report.telemetry?.country_code === "BY"
  );
}
