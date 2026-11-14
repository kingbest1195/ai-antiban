import { useCallback, useEffect, useState } from "react";
import type { OsTzSyncStatus, RiskReport } from "../../types";
import {
  getOsTimezoneSyncStatus,
  openOsDatetimeSettings,
  restoreOsTimezone as apiRestoreOsTimezone,
  setSyncAiTzEnabled,
  syncAiAgentsTimezone,
  syncOsTimezone as apiSyncOsTimezone,
} from "../../utils/api";
import { timezone as timezoneCopy, toast as t } from "../copy/ru";
import type { ShowToast } from "./useToasts";

export function formatOsTzError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.includes("OS_TZ_ELEVATION_CANCELLED")) {
    return timezoneCopy.osElevationCancelled;
  }
  return msg;
}

interface SharedOsTzState {
  osTzStatus: OsTzSyncStatus | null;
  osTzLoading: boolean;
  osTzError: string | null;
}

let sharedState: SharedOsTzState = {
  osTzStatus: null,
  osTzLoading: false,
  osTzError: null,
};

let initialFetchStarted = false;
const listeners = new Set<(next: SharedOsTzState) => void>();

let registeredContext: {
  targetTz?: string;
  runFullAudit?: (force?: boolean, silentError?: boolean) => Promise<void>;
  showToast?: ShowToast;
} = {};

function updateSharedState(patch: Partial<SharedOsTzState>) {
  sharedState = { ...sharedState, ...patch };
  for (const listener of listeners) {
    listener(sharedState);
  }
}

export async function refreshSharedOsTzStatus(): Promise<OsTzSyncStatus | null> {
  try {
    const status = await getOsTimezoneSyncStatus();
    updateSharedState({ osTzStatus: status });
    return status;
  } catch {
    return null;
  }
}

export async function runSharedSyncOsTimezone(targetTz?: string): Promise<OsTzSyncStatus | null> {
  updateSharedState({ osTzLoading: true, osTzError: null });
  try {
    const tz = targetTz || registeredContext.targetTz;
    const status = await apiSyncOsTimezone(tz);
    updateSharedState({ osTzStatus: status, osTzLoading: false, osTzError: null });
    registeredContext.showToast?.(
      t.timezone.done,
      timezoneCopy.osRestartHint,
      "success",
    );
    if (registeredContext.runFullAudit) {
      void registeredContext.runFullAudit(true, true);
    }
    return status;
  } catch (err) {
    const message = formatOsTzError(err);
    const isCancelled = (err instanceof Error ? err.message : String(err)).includes("OS_TZ_ELEVATION_CANCELLED");
    updateSharedState({ osTzLoading: false, osTzError: message });
    registeredContext.showToast?.(
      isCancelled ? timezoneCopy.osElevationCancelled : t.timezone.error,
      isCancelled ? timezoneCopy.osText : message,
      isCancelled ? "info" : "error",
    );
    return null;
  }
}

export async function runSharedRestoreOsTimezone(): Promise<OsTzSyncStatus | null> {
  updateSharedState({ osTzLoading: true, osTzError: null });
  try {
    const status = await apiRestoreOsTimezone();
    updateSharedState({ osTzStatus: status, osTzLoading: false, osTzError: null });
    registeredContext.showToast?.(
      "Системный часовой пояс восстановлен",
      status.current_os_tz
        ? `Текущий пояс ОС: ${status.current_os_tz}.`
        : "Исходный часовой пояс ОС восстановлен.",
      "info",
    );
    if (registeredContext.runFullAudit) {
      void registeredContext.runFullAudit(true, true);
    }
    return status;
  } catch (err) {
    const message = formatOsTzError(err);
    const isCancelled = (err instanceof Error ? err.message : String(err)).includes("OS_TZ_ELEVATION_CANCELLED");
    updateSharedState({ osTzLoading: false, osTzError: message });
    registeredContext.showToast?.(
      isCancelled ? timezoneCopy.osElevationCancelled : t.timezone.error,
      message,
      isCancelled ? "info" : "error",
    );
    return null;
  }
}

/** Общее состояние синхронизации системного часового пояса ОС для экранов и модальных окон. */
export function useOsTimezoneSync(defaultTargetTz?: string) {
  const [state, setState] = useState<SharedOsTzState>(sharedState);

  useEffect(() => {
    listeners.add(setState);
    if (!initialFetchStarted) {
      initialFetchStarted = true;
      void refreshSharedOsTzStatus();
    }
    return () => {
      listeners.delete(setState);
    };
  }, []);

  const refreshOsTzStatus = useCallback(() => refreshSharedOsTzStatus(), []);
  const syncOsTimezone = useCallback(
    (targetTz?: string) => runSharedSyncOsTimezone(targetTz ?? defaultTargetTz),
    [defaultTargetTz],
  );
  const restoreOsTimezone = useCallback(() => runSharedRestoreOsTimezone(), []);

  return {
    osTzStatus: state.osTzStatus,
    osTzLoading: state.osTzLoading,
    osTzError: state.osTzError,
    syncOsTimezone,
    restoreOsTimezone,
    refreshOsTzStatus,
  };
}

interface Options {
  activeReport: RiskReport | null;
  runFullAudit: (force?: boolean, silentError?: boolean) => Promise<void>;
  showToast: ShowToast;
}

/** Синхронизация часового пояса ИИ-инструментов и системного пояса ОС с IP. */
export function useTimezoneSync({ activeReport, runFullAudit, showToast }: Options) {
  const [syncingTz, setSyncingTz] = useState<boolean>(false);
  const [tzSyncedNotice, setTzSyncedNotice] = useState<boolean>(false);

  const targetTz = activeReport?.telemetry?.timezone;
  const osTz = useOsTimezoneSync(targetTz);

  useEffect(() => {
    registeredContext = { targetTz, runFullAudit, showToast };
    return () => {
      registeredContext = {};
    };
  }, [targetTz, runFullAudit, showToast]);

  const handleSyncTz = useCallback(
    async (tzOverride?: string) => {
      const tz = tzOverride || activeReport?.telemetry?.timezone || "Europe/Amsterdam";
      setSyncingTz(true);
      try {
        // Явное нажатие кнопки: сначала включаем подмену, иначе зона только сохранится.
        await setSyncAiTzEnabled(true);
        const res = await syncAiAgentsTimezone(tz);
        setTzSyncedNotice(true);
        showToast(t.timezone.done, res, "success");
        await runFullAudit(true);
      } catch (err: unknown) {
        showToast(t.timezone.error, err instanceof Error ? err.message : String(err), "error");
      } finally {
        setSyncingTz(false);
      }
    },
    [activeReport?.telemetry?.timezone, runFullAudit, showToast],
  );

  /** Открывает системные настройки даты и времени; переход к гайду делает вызывающий. */
  const openOsClock = useCallback(async () => {
    try {
      await openOsDatetimeSettings();
    } catch {}
  }, []);

  return {
    syncingTz,
    tzSyncedNotice,
    handleSyncTz,
    openOsClock,
    osTzStatus: osTz.osTzStatus,
    osTzLoading: osTz.osTzLoading,
    osTzError: osTz.osTzError,
    syncOsTimezone: osTz.syncOsTimezone,
    restoreOsTimezone: osTz.restoreOsTimezone,
    refreshOsTzStatus: osTz.refreshOsTzStatus,
  };
}
