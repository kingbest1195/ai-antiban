import { useCallback, useEffect, useState } from "react";
import {
  checkCliProtectionStatus,
  disableCliProtection,
  enableCliProtection,
  getNetworkKillswitchStatus,
  toggleNetworkKillswitch,
  toggleSysproxy,
} from "../../utils/api";
import { toast as t } from "../copy/ru";
import type { ShowToast } from "./useToasts";

export interface CliToggleOptions {
  /** Без копирования shell-команды в буфер и без уведомления об успехе (онбординг). Ошибки показываются всегда. */
  quiet?: boolean;
}

interface Options {
  sysproxyActive: boolean;
  setSysproxyActive: (value: boolean) => void;
  showToast: ShowToast;
  /** Застава ещё запускается в фоне: защита не включена до конца запуска, статус читать рано. */
  startupPending?: boolean;
}

/** Тумблеры защиты: системный прокси (PAC), защита редакторов и CLI, kill-switch «Остановить сеть». */
export function useProtectionToggles({ sysproxyActive, setSysproxyActive, showToast, startupPending = false }: Options) {
  const [cliProtected, setCliProtected] = useState<boolean>(false);
  const [killswitchFrozen, setKillswitchFrozen] = useState<boolean>(false);

  // Стартовое чтение: kill-switch.
  useEffect(() => {
    getNetworkKillswitchStatus()
      .then((frozen) => setKillswitchFrozen(frozen))
      .catch(() => {});
  }, []);

  // Статус защиты CLI читаем, когда фоновый запуск закончен: раньше защита ещё не включена, ответ был бы ложным «выключено».
  useEffect(() => {
    if (startupPending) return;
    checkCliProtectionStatus()
      .then((active) => setCliProtected(active))
      .catch(() => {});
  }, [startupPending]);

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
    handleToggleKillswitch,
  };
}
