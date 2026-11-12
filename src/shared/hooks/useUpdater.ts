import { useCallback, useEffect, useState } from "react";
import type {
  UpdateCheckResult,
  UpdateFailureKind,
  UpdateProgressPayload,
  UpdateStatusPayload,
} from "../../types";
import { checkForUpdates, installUpdate, toggleAutoUpdate } from "../../utils/api";
import { toast as t, updates as copy } from "../copy/ru";
import type { ShowToast } from "./useToasts";

const FAILURE_KINDS: readonly UpdateFailureKind[] = ["network", "signature", "no-release", "install", "install-restored"];

/** Rust отдаёт ошибку как { kind, message? }; всё незнакомое считаем ошибкой установки. */
function failureKind(err: unknown): UpdateFailureKind {
  const kind = (err as { kind?: unknown } | null)?.kind;
  return FAILURE_KINDS.find((k) => k === kind) ?? "install";
}

interface Options {
  showToast: ShowToast;
  setAutoUpdateEnabled: (value: boolean) => void;
}

/** Проверка, установка и автообновление. События updater:// подключает useTrayEvents через apply*. */
export function useUpdater({ showToast, setAutoUpdateEnabled }: Options) {
  const [updateInfo, setUpdateInfo] = useState<UpdateCheckResult | null>(null);
  const [checkingUpdate, setCheckingUpdate] = useState<boolean>(false);
  const [installingUpdate, setInstallingUpdate] = useState<boolean>(false);
  const [updateProgress, setUpdateProgress] = useState<UpdateProgressPayload | null>(null);
  const [updaterStatus, setUpdaterStatus] = useState<UpdateStatusPayload | null>(null);
  const [showUpdateModal, setShowUpdateModalRaw] = useState<boolean>(false);

  // При закрытии окна сбрасываем прошлую ошибку, чтобы она не всплыла при следующем открытии.
  const setShowUpdateModal = useCallback((open: boolean) => {
    if (!open) setUpdaterStatus((s) => (s?.stage === "failed" ? null : s));
    setShowUpdateModalRaw(open);
  }, []);

  const handleCheckUpdates = useCallback(
    async (silent: boolean = false) => {
      setCheckingUpdate(true);
      try {
        const info = await checkForUpdates();
        setUpdateInfo(info);
        if (info.update_available) {
          setShowUpdateModal(true);
          showToast(t.updates.available(info.latest_version), info.release_name || t.updates.availableText, "info");
        } else if (!silent) {
          setShowUpdateModal(true);
          showToast(t.updates.none, t.updates.noneText(info.current_version), "success");
        }
      } catch (err: unknown) {
        const kind = failureKind(err);
        // Тихая проверка (старт, трей): ошибка только в лог, без окна и тоста.
        console.warn("[updater] check failed:", err);
        if (!silent) {
          showToast(t.updates.checkError, copy.errors[kind], "error");
        }
      } finally {
        setCheckingUpdate(false);
      }
    },
    [showToast],
  );

  const handleInstallUpdate = useCallback(async () => {
    if (!updateInfo?.update_available) return;

    setInstallingUpdate(true);
    setUpdaterStatus(null);
    setUpdateProgress({
      downloaded_bytes: 0,
      total_bytes: 0,
      percent: 0,
      phase: "starting",
    });

    try {
      const res = await installUpdate();
      showToast(res.will_restart ? t.updates.installed : t.updates.ready, res.message, "success");
      if (!res.will_restart) {
        setShowUpdateModal(false);
      }
    } catch (err: unknown) {
      // Никакого отката на другой источник: показываем причину в окне, пользователь повторяет или открывает релиз.
      const kind = failureKind(err);
      console.error("[updater] install failed:", err);
      setUpdaterStatus({ stage: "failed", message: copy.errors[kind], error: kind });
      setShowUpdateModalRaw(true);
      showToast(t.updates.installError, copy.errors[kind], "error");
    } finally {
      setInstallingUpdate(false);
      setUpdateProgress(null);
    }
  }, [updateInfo, showToast, setShowUpdateModal]);

  const handleToggleAutoUpdate = useCallback(
    async (enabled: boolean) => {
      try {
        await toggleAutoUpdate(enabled);
        setAutoUpdateEnabled(enabled);
        showToast(
          enabled ? t.updates.autoOn : t.updates.autoOff,
          enabled ? t.updates.autoOnText : t.updates.autoOffText,
          "info",
        );
      } catch (err: any) {
        showToast(t.updates.autoError, err?.message || String(err), "error");
      }
    },
    [setAutoUpdateEnabled, showToast],
  );

  // Тихая проверка на старте.
  useEffect(() => {
    handleCheckUpdates(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // События updater:// из Rust.
  const applyUpdateProgress = useCallback((payload: UpdateProgressPayload) => {
    setUpdateProgress(payload);
  }, []);
  const applyUpdateAvailable = useCallback((payload: UpdateCheckResult) => {
    setUpdateInfo(payload);
  }, []);
  const applyUpdateStatus = useCallback((payload: UpdateStatusPayload) => {
    setUpdaterStatus(payload);
    if (payload.stage === "installing" || payload.stage === "restarting") {
      setInstallingUpdate(true);
    }
  }, []);

  return {
    updateInfo,
    checkingUpdate,
    installingUpdate,
    updateProgress,
    updaterStatus,
    showUpdateModal,
    setShowUpdateModal,
    handleCheckUpdates,
    handleInstallUpdate,
    handleToggleAutoUpdate,
    applyUpdateProgress,
    applyUpdateAvailable,
    applyUpdateStatus,
  };
}
