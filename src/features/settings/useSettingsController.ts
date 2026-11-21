import { useEffect, useState } from "react";
import type {
  AutostartStatus,
  CliMode,
  CoworkGuardStatus,
  InterceptionBehavior,
  PopupPosition,
  ProtectionChangePreviewItem,
} from "../../types";
import type { ShowToast } from "../../shared/hooks";
import { parseTempDnsDeferredError } from "../../shared/hooks/useProtectionToggles";
import { useOsTimezoneSync } from "../../shared/hooks/useTimezoneSync";
import { writeClipboard } from "../../shared/lib/clipboard";
import {
  exportDiagnosticBundle,
  fetchAppState,
  forceCleanOsProxy,
  getAutostartStatus,
  getCliSettings,
  getCoworkGuardStatus,
  getCustomAiDomains,
  getInterceptionBehavior,
  getPopupPosition,
  getSplitTunnelMode,
  installOrRepairCoworkGuard,
  onCoworkGuardStatus,
  previewProtectionChanges,
  resetDismissedHints,
  setAutostartEnabled,
  setCliMode,
  setInterceptionBehavior,
  setPopupPosition,
  setSplitTunnelMode,
  setSyncAiTzEnabled,
} from "../../utils/api";
import { settings as copy } from "../../shared/copy/ru";
import { MONITORED_PROVIDERS, useSettingsExceptions } from "./useSettingsExceptions";

export { MONITORED_PROVIDERS };

const errText = (err: unknown) => (err instanceof Error ? err.message : String(err));

export interface UseSettingsControllerParams {
  open: boolean;
  autoUpdateEnabled: boolean;
  onToggleAutoUpdate: (enabled: boolean) => Promise<void>;
  hideIpMode?: boolean;
  propBehavior?: InterceptionBehavior;
  propPosition?: PopupPosition;
  propCustomDomains?: string[];
  propDisabledProviders?: string[];
  propTrustedExceptions?: Record<string, string[]>;
  onStateUpdated?: () => Promise<unknown> | void;
  onToast?: ShowToast;
  rollbackLoaded?: boolean;
  rollbackLoading?: boolean;
  onLoadRollbackVersions?: () => Promise<void>;
}

export function useSettingsController({
  open,
  autoUpdateEnabled,
  onToggleAutoUpdate,
  hideIpMode = false,
  propBehavior,
  propPosition,
  propCustomDomains,
  propDisabledProviders,
  propTrustedExceptions,
  onStateUpdated,
  onToast,
  rollbackLoaded = false,
  rollbackLoading = false,
  onLoadRollbackVersions,
}: UseSettingsControllerParams) {
  const [updatingToggle, setUpdatingToggle] = useState(false);
  const [behavior, setBehavior] = useState<InterceptionBehavior>(propBehavior || "ask_popup");
  const [position, setPosition] = useState<PopupPosition>(propPosition || "top_right");
  const [customDomains, setCustomDomains] = useState<string[]>(propCustomDomains || []);
  const [disabledProviders, setDisabledProviders] = useState<string[]>(propDisabledProviders || []);
  const [trustedExceptions, setTrustedExceptions] = useState<Record<string, string[]>>(propTrustedExceptions || {});
  const [confirmProxy, setConfirmProxy] = useState(false);
  const [cleaningProxy, setCleaningProxy] = useState(false);
  const [cliMode, setCliModeState] = useState<CliMode>("ai_only");
  const [syncTz, setSyncTz] = useState(false);
  const [terminalBusy, setTerminalBusy] = useState(false);
  const [splitTunnelMode, setSplitTunnelModeState] = useState(false);
  const [splitTunnelBusy, setSplitTunnelBusy] = useState(false);
  const osTz = useOsTimezoneSync();
  const [confirmGlobal, setConfirmGlobal] = useState(false);
  const [proxyResult, setProxyResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [autostartStatus, setAutostartStatus] = useState<AutostartStatus | null>(null);
  const [autostartBusy, setAutostartBusy] = useState(false);
  const [coworkStatus, setCoworkStatus] = useState<CoworkGuardStatus | null>(null);
  const [coworkBusy, setCoworkBusy] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);
  const [previewItems, setPreviewItems] = useState<ProtectionChangePreviewItem[]>([]);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [confirmRollbackVersion, setConfirmRollbackVersion] = useState<string | null>(null);
  const [hintsResetBusy, setHintsResetBusy] = useState(false);

  const exceptions = useSettingsExceptions({
    customDomains,
    setCustomDomains,
    disabledProviders,
    setDisabledProviders,
    trustedExceptions,
    setTrustedExceptions,
    hideIpMode,
    onStateUpdated,
    onToast,
  });

  useEffect(() => {
    if (!open) return;
    if (propBehavior) setBehavior(propBehavior);
    if (propPosition) setPosition(propPosition);
    if (propCustomDomains) setCustomDomains(propCustomDomains);
    if (propDisabledProviders) setDisabledProviders(propDisabledProviders);
    if (propTrustedExceptions) setTrustedExceptions(propTrustedExceptions);

    fetchAppState()
      .then((st) => {
        setDisabledProviders(st.disabled_providers ?? []);
        setTrustedExceptions(st.trusted_exceptions ?? {});
      })
      .catch(() => {});
    getInterceptionBehavior().then(setBehavior).catch(() => {});
    getPopupPosition().then(setPosition).catch(() => {});
    getCustomAiDomains().then(setCustomDomains).catch(() => {});
    getCliSettings()
      .then((cli) => {
        setCliModeState(cli.cli_mode);
        setSyncTz(cli.sync_ai_tz_enabled);
      })
      .catch(() => {});
    getSplitTunnelMode().then(setSplitTunnelModeState).catch(() => {});
    void osTz.refreshOsTzStatus();
    getAutostartStatus().then(setAutostartStatus).catch(() => {});
    getCoworkGuardStatus().then(setCoworkStatus).catch(() => {});

    setPreviewLoading(true);
    setPreviewError(null);
    previewProtectionChanges()
      .then((items) => setPreviewItems(items))
      .catch((err) => setPreviewError(errText(err)))
      .finally(() => setPreviewLoading(false));
    setProxyResult(null);
    setConfirmRollbackVersion(null);
    if (!rollbackLoaded && !rollbackLoading && onLoadRollbackVersions) {
      void onLoadRollbackVersions();
    }

    let unlisten: (() => void) | undefined;
    let active = true;
    onCoworkGuardStatus((status) => {
      if (active) setCoworkStatus(status);
    })
      .then((fn) => {
        if (active) unlisten = fn;
        else fn();
      })
      .catch(() => {});

    return () => {
      active = false;
      unlisten?.();
    };
  }, [open, propBehavior, propPosition, propCustomDomains, propDisabledProviders, propTrustedExceptions]);

  const handleExportDiagnostics = async () => {
    if (exportBusy) return;
    setExportBusy(true);
    try {
      const bundle = await exportDiagnosticBundle();
      const copied = await writeClipboard(bundle);
      if (!copied) throw new Error("Clipboard unavailable");
      onToast?.(copy.diagnostics.exportToast, undefined, "success");
    } catch (err) {
      onToast?.(copy.diagnostics.exportError, errText(err), "error");
    } finally {
      setExportBusy(false);
    }
  };

  const handleToggleAutostart = async () => {
    if (autostartBusy) return;
    const next = !(autostartStatus?.active_in_os ?? autostartStatus?.enabled ?? false);
    setAutostartBusy(true);
    try {
      const updated = await setAutostartEnabled(next);
      setAutostartStatus(updated);
      onStateUpdated?.();
      if (updated.active_in_os) onToast?.(copy.autostart.toastOnTitle, copy.autostart.toastOnText, "success");
      else onToast?.(copy.autostart.toastOffTitle, copy.autostart.toastOffText, "info");
    } catch (err) {
      onToast?.(copy.autostart.error, errText(err), "warning");
    } finally {
      setAutostartBusy(false);
    }
  };

  const handleInstallCoworkGuard = async () => {
    if (coworkBusy) return;
    setCoworkBusy(true);
    try {
      const updated = await installOrRepairCoworkGuard();
      setCoworkStatus(updated);
      onStateUpdated?.();
      onToast?.(copy.coworkGuard.toastOkTitle, updated.summary, updated.needs_repair ? "warning" : "success");
    } catch (err) {
      onToast?.(copy.coworkGuard.toastErrTitle, errText(err), "warning");
    } finally {
      setCoworkBusy(false);
    }
  };

  const handleRefreshCoworkGuard = async () => {
    if (coworkBusy) return;
    setCoworkBusy(true);
    try {
      const updated = await getCoworkGuardStatus();
      setCoworkStatus(updated);
    } catch {
      // ignore
    } finally {
      setCoworkBusy(false);
    }
  };

  const handleToggleAutoUpdate = async () => {
    if (updatingToggle) return;
    setUpdatingToggle(true);
    try {
      await onToggleAutoUpdate(!autoUpdateEnabled);
    } finally {
      setUpdatingToggle(false);
    }
  };

  const handleToggleSplitTunnel = async () => {
    if (splitTunnelBusy) return;
    const next = !splitTunnelMode;
    setSplitTunnelBusy(true);
    try {
      await setSplitTunnelMode(next);
      setSplitTunnelModeState(next);
      onStateUpdated?.();
      if (next) onToast?.(copy.splitTunnel.toastOnTitle, copy.splitTunnel.toastOnText, "success");
      else onToast?.(copy.splitTunnel.toastOffTitle, copy.splitTunnel.toastOffText, "info");
    } catch (err) {
      onToast?.(copy.splitTunnel.error, errText(err), "warning");
    } finally {
      setSplitTunnelBusy(false);
    }
  };

  const handleToggleSyncTz = async () => {
    if (terminalBusy) return;
    const next = !syncTz;
    setTerminalBusy(true);
    try {
      const res = await setSyncAiTzEnabled(next);
      setSyncTz(res.sync_ai_tz_enabled);
      onStateUpdated?.();
      if (res.sync_ai_tz_enabled) onToast?.(copy.terminal.tz.toastOnTitle, copy.terminal.tz.toastOnText, "success");
      else onToast?.(copy.terminal.tz.toastOffTitle, copy.terminal.tz.toastOffText, "info");
    } catch (err) {
      onToast?.(copy.terminal.tz.error, errText(err), "warning");
    } finally {
      setTerminalBusy(false);
    }
  };

  const applyCliMode = async (next: CliMode) => {
    setTerminalBusy(true);
    try {
      const res = await setCliMode(next);
      setCliModeState(res.cli_mode);
      onStateUpdated?.();
      onToast?.(copy.terminal.mode.toastTitle, copy.terminal.mode.toastText[res.cli_mode], "success");
    } catch (err) {
      onToast?.(copy.terminal.mode.error, errText(err), "warning");
    } finally {
      setTerminalBusy(false);
    }
  };

  const handleCliModeChange = (next: CliMode) => {
    if (terminalBusy || next === cliMode) return;
    if (next === "global_terminal") setConfirmGlobal(true);
    else void applyCliMode(next);
  };

  const handleBehaviorChange = async (next: InterceptionBehavior) => {
    setBehavior(next);
    try {
      await setInterceptionBehavior(next);
      onStateUpdated?.();
      onToast?.(copy.behavior.toastTitle, copy.behavior.toastText[next], "success");
    } catch (err) {
      onToast?.(copy.behavior.saveError, errText(err), "warning");
    }
  };

  const handlePositionChange = async (next: PopupPosition) => {
    setPosition(next);
    try {
      await setPopupPosition(next);
      onStateUpdated?.();
      onToast?.(copy.position.toastTitle, copy.position.toastText[next], "info");
    } catch (err) {
      onToast?.(copy.behavior.saveError, errText(err), "warning");
    }
  };

  const handleCleanOsProxy = async () => {
    setCleaningProxy(true);
    setProxyResult(null);
    setConfirmRollbackVersion(null);
    if (!rollbackLoaded && !rollbackLoading && onLoadRollbackVersions) {
      void onLoadRollbackVersions();
    }
    try {
      const results = await forceCleanOsProxy();
      setProxyResult({ ok: true, text: results.length > 0 ? results.join(" · ") : copy.proxy.doneDefault });
      onToast?.(copy.proxy.toastTitle, copy.proxy.toastText, "success");
    } catch (err) {
      const deferred = parseTempDnsDeferredError(err);
      if (deferred !== null) {
        setProxyResult({ ok: true, text: deferred });
        onToast?.(copy.proxy.toastTitle, deferred, "info");
        return;
      }
      const message = errText(err);
      setProxyResult({ ok: false, text: message });
      onToast?.(copy.proxy.toastError, message, "warning");
    } finally {
      setCleaningProxy(false);
      setConfirmProxy(false);
    }
  };

  const handleResetDismissedHints = async () => {
    setHintsResetBusy(true);
    try {
      await resetDismissedHints();
      await onStateUpdated?.();
      onToast?.("Подсказки сброшены", "Все контекстные подсказки снова будут показаны в разделах.", "success");
    } catch (err) {
      onToast?.("Не удалось сбросить подсказки", errText(err), "warning");
    } finally {
      setHintsResetBusy(false);
    }
  };

  return {
    ...exceptions,
    updatingToggle,
    behavior,
    position,
    confirmProxy,
    setConfirmProxy,
    cleaningProxy,
    cliMode,
    syncTz,
    terminalBusy,
    splitTunnelMode,
    splitTunnelBusy,
    osTz,
    confirmGlobal,
    setConfirmGlobal,
    proxyResult,
    autostartStatus,
    autostartBusy,
    coworkStatus,
    coworkBusy,
    exportBusy,
    previewItems,
    previewLoading,
    previewError,
    previewOpen,
    setPreviewOpen,
    confirmRollbackVersion,
    setConfirmRollbackVersion,
    hintsResetBusy,
    handleResetDismissedHints,
    handleExportDiagnostics,
    handleToggleAutostart,
    handleInstallCoworkGuard,
    handleRefreshCoworkGuard,
    handleToggleAutoUpdate,
    handleToggleSplitTunnel,
    handleToggleSyncTz,
    applyCliMode,
    handleCliModeChange,
    handleBehaviorChange,
    handlePositionChange,
    handleCleanOsProxy,
  };
}
