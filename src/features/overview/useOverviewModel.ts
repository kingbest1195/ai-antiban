import { useMemo } from "react";
import type { AppStateData, CheckResult, ProviderId, RiskReport, UpdateCheckResult } from "../../types";
import { checksWord } from "../../shared/lib/format";
import { classify, countChecks, failedChecks, isYellowOnlyUnknown, pickWorstReport } from "../checks/checksModel";
import { overview as copy } from "../../shared/copy/ru";
import type { HeroTone, TabItem } from "../../ui";

export type ServiceStatus = "ok" | "allowed" | "warn" | "critical" | "missing" | "checking";

export interface ServiceModel {
  id: ProviderId;
  status: ServiceStatus;
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
}: Input): OverviewModel {
  return useMemo(() => {
    const anyRed = PROVIDER_IDS.some((id) => reports[id]?.overall_status === "red");
    const anyYellow = PROVIDER_IDS.some(
      (id) => reports[id]?.overall_status === "yellow" && !isYellowOnlyUnknown(reports[id], checksOf(reports[id] ?? null)),
    );

    const bad = (c?: CheckResult) => {
      if (!c) return false;
      const k = classify(c);
      return k === "warn" || k === "crit";
    };
    const ipv6Leak = bad(activeReport?.ipv6_result);
    const tzMismatch = bad(activeReport?.timezone_result);
    const dnsblBad = bad(activeReport?.dnsbl_result);

    const checks = checksOf(activeReport);
    const counts = countChecks(checks);
    const incomplete = Boolean(activeReport?.incomplete) || counts.unknown > 0;

    let verdict: string = copy.verdict.ok;
    let tone: HeroTone = "ok";
    if (killswitchFrozen) {
      verdict = copy.verdict.frozen;
      tone = "danger";
    } else if (startupPending) {
      // До конца запуска вывода нет: ни «Вы защищены», ни «Защита выключена».
      verdict = copy.verdict.starting;
      tone = "warn";
    } else if (anyRed) {
      verdict = copy.verdict.stopped;
      tone = "danger";
    } else if (!sysproxyActive) {
      verdict = copy.verdict.off;
      tone = "warn";
    } else if (anyYellow || ipv6Leak || tzMismatch) {
      verdict = copy.verdict.attention;
      tone = "warn";
    } else if (incomplete) {
      verdict = copy.verdict.partial;
      tone = "warn";
    }

    let banner: BannerKind | null = null;
    if (killswitchFrozen) banner = "frozen";
    else if (startupPending) banner = null;
    else if (anyRed) banner = "stopped";
    else if (ipv6Leak) banner = "leak";
    else if (tzMismatch) banner = "timezone";
    else if (anyYellow || dnsblBad) banner = "review";
    else if (incomplete) banner = "incomplete";
    else if (updateInfo?.update_available) banner = "update";

    const checksPassed = counts.ok;
    const checksTotal = Math.max(counts.applicable, activeReport?.applicable_count ?? 0);

    const pinned = state?.pinned_ip ?? null;
    const pinState: PinState = pinned ? (pinned === currentIp ? "pinned" : "changed") : "none";

    const providerName = activeReport?.telemetry?.isp || activeReport?.telemetry?.org || null;

    const services: ServiceModel[] = PROVIDER_IDS.map((id) => {
      const report = reports[id];
      const isBlocked = state?.blocked_providers?.includes(id);
      const isAllowed = state?.session_allowed_providers?.includes(id);
      const list = checksOf(report ?? null);
      const hasCritical = list.some((c) => classify(c) === "crit");
      // Непроверенное не считаем чистым: сервис получает статус «Нужна проверка».
      const hasWarning = list.some((c) => classify(c) === "warn" || classify(c) === "unknown") || Boolean(report?.incomplete);

      let status: ServiceStatus = "ok";
      if (isBlocked) status = "critical";
      else if (isAllowed) status = "allowed";
      else if (startupPending) status = "checking";
      else if (!report) status = refreshing ? "checking" : "missing";
      else if (report.overall_status === "red" || hasCritical) status = "critical";
      else if ((report.overall_status === "yellow" && !isYellowOnlyUnknown(report, list)) || hasWarning) status = "warn";
      return { id, status };
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
  }, [reports, activeReport, state, currentIp, sysproxyActive, killswitchFrozen, updateInfo, refreshing, startupPending]);
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
  const worst = pickWorstReport(reports);
  const n = worst ? failedChecks(worst.report, state).length : 0;
  if (n > 0) out.checks = n;
  return out;
}

/** Нужно ли подтверждение перед «Разрешить принудительно»: только для красного сервиса и для адреса из РФ, где запросы пойдут без проверки. */
export function needsForceConfirm(status: ServiceStatus, report: RiskReport | null | undefined): boolean {
  return status === "critical" || report?.telemetry?.country_code === "RU";
}
