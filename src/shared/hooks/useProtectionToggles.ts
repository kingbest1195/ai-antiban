import { useCallback, useEffect, useMemo, useState } from "react";
import {
  checkCliProtectionStatus,
  disableCliProtection,
  enableCliProtection,
  getNetworkKillswitchStatus,
  toggleNetworkKillswitch,
  toggleSysproxy,
} from "../../utils/api";
import type { CliProtectionReport } from "../../types";
import { toast as t } from "../copy/ru";
import type { ShowToast } from "./useToasts";

export interface CliToggleOptions {
  /** Без копирования shell-команды в буфер и без уведомления об успехе (онбординг). Ошибки показываются всегда. */
  quiet?: boolean;
}

/**
 * Явные «включить» и «выключить» защиты для кнопок в «Покрытии»: в отличие от переключателя повторный вызов
 * «включить» ничего не выключает. Ошибку показывают сами (тостом), успех описывает вызывающий по ответу команды.
 */
export interface ProtectionActions {
  /** Возвращает, включён ли системный прокси после команды. */
  enableSysproxy: () => Promise<boolean>;
  /** Возвращает true, если выключен. */
  disableSysproxy: () => Promise<boolean>;
  /** Ответ команды (что записано, заметки, ошибка) или null, если команда не выполнилась. */
  enableCli: () => Promise<CliProtectionReport | null>;
  /** Возвращает true, если выключена. */
  disableCli: () => Promise<boolean>;
}

interface Options {
  sysproxyActive: boolean;
  setSysproxyActive: (value: boolean) => void;
  showToast: ShowToast;
}

/** Тумблеры защиты: системный прокси (PAC), защита редакторов и CLI, kill-switch «Остановить сеть». */
export function useProtectionToggles({ sysproxyActive, setSysproxyActive, showToast }: Options) {
  const [cliProtected, setCliProtected] = useState<boolean>(false);
  const [killswitchFrozen, setKillswitchFrozen] = useState<boolean>(false);

  // Стартовое чтение: kill-switch и статус защиты CLI.
  useEffect(() => {
    getNetworkKillswitchStatus()
      .then((frozen) => setKillswitchFrozen(frozen))
      .catch(() => {});
    checkCliProtectionStatus()
      .then((active) => {
        if (active) setCliProtected(true);
      })
      .catch(() => {});
  }, []);

  const handleToggleSysproxy = useCallback(async () => {
    try {
      const next = !sysproxyActive;
      const res = await toggleSysproxy(next);
      setSysproxyActive(res);
      showToast(res ? t.guard.onTitle : t.guard.offTitle, res ? t.guard.onText : t.guard.offText, res ? "success" : "info");
    } catch (err: any) {
      showToast(t.guard.error, err?.message || String(err), "error");
    }
  }, [sysproxyActive, setSysproxyActive, showToast]);

  const handleToggleCliProtection = useCallback(async (options?: CliToggleOptions) => {
    // Switch.onChange может передать своё значение, поэтому смотрим строго на флаг.
    const quiet = options?.quiet === true;
    try {
      if (cliProtected) {
        await disableCliProtection();
        setCliProtected(false);
        if (!quiet) showToast(t.cli.offTitle, t.cli.offText, "info");
      } else {
        const report = await enableCliProtection();
        if (!quiet) {
          try {
            await navigator.clipboard.writeText(report.shell_command);
          } catch {
            // буфер обмена необязателен
          }
        }
        setCliProtected(true);
        if (!quiet) {
          const targets =
            report.configured_targets.length > 0 ? report.configured_targets.join(", ") : t.cli.onFallbackTargets;
          showToast(t.cli.onTitle, t.cli.onText(targets), "success");
        }
      }
    } catch (err: any) {
      showToast(t.cli.error, err?.message || String(err), "error");
    }
  }, [cliProtected, showToast]);

  const protection = useMemo<ProtectionActions>(
    () => ({
      enableSysproxy: async () => {
        try {
          const res = await toggleSysproxy(true);
          setSysproxyActive(res);
          return res;
        } catch (err: any) {
          showToast(t.guard.error, err?.message || String(err), "error");
          return false;
        }
      },
      disableSysproxy: async () => {
        try {
          const res = await toggleSysproxy(false);
          setSysproxyActive(res);
          return !res;
        } catch (err: any) {
          showToast(t.guard.error, err?.message || String(err), "error");
          return false;
        }
      },
      enableCli: async () => {
        try {
          const report = await enableCliProtection();
          setCliProtected(true);
          return report;
        } catch (err: any) {
          showToast(t.cli.error, err?.message || String(err), "error");
          return null;
        }
      },
      disableCli: async () => {
        try {
          await disableCliProtection();
          setCliProtected(false);
          return true;
        } catch (err: any) {
          showToast(t.cli.error, err?.message || String(err), "error");
          return false;
        }
      },
    }),
    [setSysproxyActive, showToast],
  );

  const handleToggleKillswitch = useCallback(async () => {
    try {
      const next = !killswitchFrozen;
      const isFrozen = await toggleNetworkKillswitch(next);
      setKillswitchFrozen(isFrozen);
      if (isFrozen) {
        showToast(t.killswitch.onTitle, t.killswitch.onText, "warning");
      } else {
        showToast(t.killswitch.offTitle, t.killswitch.offText, "success");
      }
    } catch (err: any) {
      showToast(t.killswitch.error, err?.message || String(err), "error");
    }
  }, [killswitchFrozen, showToast]);

  return {
    cliProtected,
    killswitchFrozen,
    setKillswitchFrozen,
    handleToggleSysproxy,
    handleToggleCliProtection,
    protection,
    handleToggleKillswitch,
  };
}
