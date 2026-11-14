import { useCallback, useEffect, useState } from "react";
import type { RiskInterceptPayload } from "../../types";
import { pauseUntilNetworkChange, resolveInterception, simulateInterception } from "../../utils/api";
import { toast as t } from "../copy/ru";
import { allowErrorText, classifyAllowError } from "../../features/alert/alertState";
import type { ShowToast } from "./useToasts";

interface Options {
  runFullAudit: (force?: boolean, silentError?: boolean) => Promise<void>;
  showToast: ShowToast;
  /** В браузере без Tauri после симуляции показываем окно-диалог поверх страницы. */
  onSimulateInBrowser?: () => void;
}

/** Перехват запроса к ИИ в главном окне: баннер «Снять паузу», ручное разрешение, тест перехвата. */
export function useInterception({ runFullAudit, showToast, onSimulateInBrowser }: Options) {
  const [interceptPayload, setInterceptPayload] = useState<RiskInterceptPayload | null>(null);

  const [allowError, setAllowError] = useState<string | null>(null);
  const payloadId = interceptPayload?.id;
  useEffect(() => {
    setAllowError(null);
  }, [payloadId]);

  const handleAllowInterception = useCallback(async () => {
    if (!interceptPayload) return;
    setAllowError(null);
    try {
      await resolveInterception(interceptPayload.id, "AllowSession", interceptPayload.provider, interceptPayload.scope);
      showToast(t.intercept.allowedTitle, t.intercept.allowedText, "success");
      setInterceptPayload(null);
      runFullAudit(false);
    } catch (err) {
      // Бэкенд отказал: баннер остаётся, запросы остановлены.
      setAllowError(allowErrorText(classifyAllowError(err)));
    }
  }, [interceptPayload, runFullAudit, showToast]);

  const handlePauseUntilNetworkChange = useCallback(async () => {
    if (!interceptPayload) return;
    setAllowError(null);
    try {
      await resolveInterception(
        interceptPayload.id,
        "BlockUntilNetworkChange",
        interceptPayload.provider,
        interceptPayload.scope,
      );
      await pauseUntilNetworkChange(interceptPayload.gate_reason ?? undefined);
      showToast(t.intercept.pausedTitle, t.intercept.pausedText, "info");
      setInterceptPayload(null);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(t.intercept.pauseError, msg, "error");
    }
  }, [interceptPayload, showToast]);

  const handleSimulate = useCallback(async () => {
    try {
      await simulateInterception("anthropic");
      showToast(t.intercept.simulateTitle, t.intercept.simulateText, "info");
      if (onSimulateInBrowser) {
        onSimulateInBrowser();
      }
    } catch (err: any) {
      showToast(t.intercept.simulateError, err?.message || String(err), "error");
    }
  }, [onSimulateInBrowser, showToast]);

  return {
    interceptPayload,
    setInterceptPayload,
    allowError,
    handleAllowInterception,
    handlePauseUntilNetworkChange,
    handleSimulate,
  };
}
