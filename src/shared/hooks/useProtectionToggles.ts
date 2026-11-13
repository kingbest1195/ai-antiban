import { useCallback, useEffect, useMemo, useState } from "react";
import {
  checkCliProtectionStatus,
  disableCliProtection,
  enableCliProtection,
  getNetworkKillswitchStatus,
  toggleNetworkKillswitch,
  toggleSysproxy,
  toggleSysproxyPrivileged,
} from "../../utils/api";
import type { CliProtectionReport } from "../../types";
import { toast as t } from "../copy/ru";
import type { ShowToast } from "./useToasts";

export const ADMIN_AUTH_PREFIX = "ADMIN_AUTH_REQUIRED:";

/** Распознаёт ошибку нехватки прав macOS (префикс `ADMIN_AUTH_REQUIRED:`) и возвращает текст для пользователя. */
export function parseAdminAuthError(err: unknown): string | null {
  const raw = typeof err === "string" ? err : (err as { message?: unknown } | null)?.message;
  if (typeof raw !== "string" || !raw.startsWith(ADMIN_AUTH_PREFIX)) return null;
  const msg = raw.slice(ADMIN_AUTH_PREFIX.length).trim();
  return msg || "Для включения системного прокси требуются права администратора macOS.";
}

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
  /** Повторное включение системного прокси через запрос прав администратора macOS. */
  enableSysproxyPrivileged: () => Promise<boolean>;
  /** Возвращает true, если выключен. */
  disableSysproxy: () => Promise<boolean>;
  /** Ответ команды (что записано, заметки, ошибка) или null, если команда не выполнилась. */
  enableCli: () => Promise<CliProtectionReport | null>;
  /** Возвращает true, если выключена. */
  disableCli: () => Promise<boolean>;
  /** Сообщение об ошибке прав администратора macOS, если требуется повтор через osascript. */
  adminAuthMessage: string | null;
  /** Идёт запрос прав администратора macOS. */
  retryingAdminAuth: boolean;
  /** Скрыть баннер запроса прав администратора. */
  dismissAdminAuth: () => void;
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
  const [adminAuthMessage, setAdminAuthMessage] = useState<string | null>(null);
  const [retryingAdminAuth, setRetryingAdminAuth] = useState<boolean>(false);

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
      setAdminAuthMessage(null);
      showToast(res ? t.guard.onTitle : t.guard.offTitle, res ? t.guard.onText : t.guard.offText, res ? "success" : "info");
    } catch (err: any) {
      const adminMsg = parseAdminAuthError(err);
      if (adminMsg !== null) {
        setAdminAuthMessage(adminMsg);
        showToast(t.guard.error, adminMsg, "error");
      } else {
        showToast(t.guard.error, err?.message || String(err), "error");
      }
    }
  }, [sysproxyActive, setSysproxyActive, showToast]);

  const enableSysproxyPrivileged = useCallback(async () => {
    setRetryingAdminAuth(true);
    try {
      const res = await toggleSysproxyPrivileged();
      setSysproxyActive(res);
      if (res) {
        setAdminAuthMessage(null);
        showToast(t.guard.onTitle, t.guard.onText, "success");
      }
      return res;
    } catch (err: any) {
      const adminMsg = parseAdminAuthError(err);
      const msg = adminMsg ?? (err?.message || String(err));
      if (adminMsg !== null) setAdminAuthMessage(adminMsg);
      showToast(t.guard.error, msg, "error");
      return false;
    } finally {
      setRetryingAdminAuth(false);
    }
  }, [setSysproxyActive, showToast]);

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
          setAdminAuthMessage(null);
          return res;
        } catch (err: any) {
          const adminMsg = parseAdminAuthError(err);
          if (adminMsg !== null) {
            setAdminAuthMessage(adminMsg);
            showToast(t.guard.error, adminMsg, "error");
          } else {
            showToast(t.guard.error, err?.message || String(err), "error");
          }
          return false;
        }
      },
      enableSysproxyPrivileged,
      disableSysproxy: async () => {
        try {
          const res = await toggleSysproxy(false);
          setSysproxyActive(res);
          setAdminAuthMessage(null);
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
      adminAuthMessage,
      retryingAdminAuth,
      dismissAdminAuth: () => setAdminAuthMessage(null),
    }),
    [setSysproxyActive, showToast, enableSysproxyPrivileged, adminAuthMessage, retryingAdminAuth],
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
