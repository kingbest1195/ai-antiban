import type { CleanRoomAuditReport, CleanRoomFinding } from "../../types";
import { isMacPlatform } from "../mascot";
import type { RadarLayerItem, RadarLayerStatus } from "../mascot";

const SEVERITY_RANK: Record<CleanRoomFinding["severity"], number> = {
  critical: 0,
  warning: 1,
  ok: 2,
};

/** Hard Readiness Gate: запуск разрешён ТОЛЬКО при отсутствии critical и выключенном Kill-Switch. */
export function isCleanRoomReadyToLaunch(
  audit: CleanRoomAuditReport | null | undefined,
  manualKillswitch: boolean = false,
): boolean {
  if (manualKillswitch) return false;
  if (!audit) return false;
  return Boolean(audit.ready_to_launch && audit.critical_count === 0);
}

/** Сортирует находки детектора: critical -> warning -> ok. */
export function sortFindingsBySeverity(findings: readonly CleanRoomFinding[]): CleanRoomFinding[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

function layerStatusFromCategories(
  findings: readonly CleanRoomFinding[],
  categories: readonly string[],
  scanning: boolean,
): RadarLayerStatus {
  if (scanning) return "scanning";
  const matched = findings.filter((f) => categories.includes(f.category));
  if (matched.some((f) => f.severity === "critical")) return "critical";
  if (matched.some((f) => f.severity === "warning")) return "warn";
  if (matched.length > 0 || findings.length > 0) return "ok";
  return "pending";
}

function buildLayerTip(
  findings: readonly CleanRoomFinding[],
  categories: readonly string[],
  status: RadarLayerStatus,
  scanning: boolean,
  overrideTip?: string,
): string {
  if (scanning) return "Идёт проверка…";
  if (overrideTip) return overrideTip;
  const matched = findings.filter((f) => categories.includes(f.category));
  if (matched.length > 0) {
    return matched
      .map((f) => f.title)
      .slice(0, 2)
      .join("; ");
  }
  if (status === "ok") return "Замечаний нет";
  if (status === "warn") return "Требуется внимание";
  if (status === "critical") return "Найдено критическое замечание";
  return "Ожидание проверки";
}

/** Преобразует отчёт аудита в статусы 4 слоёв для CleanRoomRadarAnim. */
export function buildRadarLayers(
  audit: CleanRoomAuditReport | null | undefined,
  scanning: boolean,
): RadarLayerItem[] {
  const list = audit?.findings ?? [];
  const browserStatus = layerStatusFromCategories(list, ["browser"], scanning);
  const desktopStatus = layerStatusFromCategories(list, ["desktop_traces"], scanning);
  const networkStatus = layerStatusFromCategories(list, ["ip_collision", "network_leak"], scanning);
  const baseOsTzStatus = layerStatusFromCategories(list, ["os_tz_locale"], scanning);
  const osTzStatus: RadarLayerStatus =
    !scanning && audit?.requires_os_sync && baseOsTzStatus !== "critical" ? "warn" : baseOsTzStatus;

  const osTzOverrideTip =
    !scanning && audit && !audit.os_tz_matches_exit && !audit.requires_os_sync
      ? "На macOS Застава сама задаёт нужный часовой пояс внутри окна песочницы — менять часы системы не нужно"
      : !scanning && audit?.requires_os_sync
        ? "Часовой пояс системы не совпадает с выходом — синхронизируйте в шаге ниже"
        : undefined;

  return [
    {
      id: "browsers",
      label: "Браузеры",
      status: browserStatus,
      tip: buildLayerTip(list, ["browser"], browserStatus, scanning),
    },
    {
      id: "desktop",
      label: isMacPlatform() ? "Приложения ИИ" : "Приложения ИИ и Store",
      status: desktopStatus,
      tip: buildLayerTip(list, ["desktop_traces"], desktopStatus, scanning),
    },
    {
      id: "network",
      label: "IP и DNS",
      status: networkStatus,
      tip: buildLayerTip(list, ["ip_collision", "network_leak"], networkStatus, scanning),
    },
    {
      id: "os_tz",
      label: "Время и язык",
      status: osTzStatus,
      tip: buildLayerTip(list, ["os_tz_locale"], osTzStatus, scanning, osTzOverrideTip),
    },
  ];
}
