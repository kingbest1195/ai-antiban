import { useCallback, useState } from "react";
import type { RiskReport } from "../../types";
import { openOsDatetimeSettings, setSyncAiTzEnabled, syncAiAgentsTimezone } from "../../utils/api";
import { toast as t } from "../copy/ru";
import type { ShowToast } from "./useToasts";

interface Options {
  activeReport: RiskReport | null;
  runFullAudit: (force?: boolean, silentError?: boolean) => Promise<void>;
  showToast: ShowToast;
}

/** Синхронизация часового пояса ИИ-инструментов с IP и переход к настройкам времени ОС. */
export function useTimezoneSync({ activeReport, runFullAudit, showToast }: Options) {
  const [syncingTz, setSyncingTz] = useState<boolean>(false);
  const [tzSyncedNotice, setTzSyncedNotice] = useState<boolean>(false);

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
      } catch (err: any) {
        showToast(t.timezone.error, err?.message || String(err), "error");
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

  return { syncingTz, tzSyncedNotice, handleSyncTz, openOsClock };
}
