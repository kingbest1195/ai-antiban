import { useCallback, useEffect, useRef, useState } from "react";
import type { AppStateData, ProviderId } from "../../types";
import {
  allowProviderSession,
  pinCurrentIp,
  toggleStrictPinning,
  unblockProvider,
  unpinIp,
  verifyAndUnblockProvider,
} from "../../utils/api";
import { providers, toast as t } from "../copy/ru";
import type { ShowToast } from "./useToasts";

interface Options {
  state: AppStateData | null;
  refreshState: () => Promise<AppStateData>;
  runFullAudit: (force?: boolean, silentError?: boolean) => Promise<void>;
  showToast: ShowToast;
  currentIp: string;
}

/** Закрепление IP, строгий режим, копирование IP и ручное снятие блока с ИИ-сервисов. */
export function usePinning({ state, refreshState, runFullAudit, showToast, currentIp }: Options) {
  const [copiedIp, setCopiedIp] = useState<boolean>(false);
  const copiedTimer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(copiedTimer.current), []);

  const handleCopyIp = useCallback(() => {
    if (currentIp && currentIp !== "--") {
      navigator.clipboard.writeText(currentIp);
      setCopiedIp(true);
      showToast(t.ipCopied, currentIp, "success");
      window.clearTimeout(copiedTimer.current);
      copiedTimer.current = window.setTimeout(() => setCopiedIp(false), 2000);
    }
  }, [currentIp, showToast]);

  const handlePinIp = useCallback(
    async (ip: string) => {
      try {
        await pinCurrentIp(ip);
        await refreshState();
        showToast(t.pinned, t.pinnedText(ip), "success");
        runFullAudit(false);
      } catch (err: any) {
        showToast(t.pinError, err?.message || String(err), "error");
      }
    },
    [refreshState, runFullAudit, showToast],
  );

  const handleUnpinIp = useCallback(async () => {
    try {
      await unpinIp();
      await refreshState();
      showToast(t.unpinned, t.unpinnedText, "info");
      runFullAudit(false);
    } catch (err: any) {
      showToast(t.genericError, err?.message || String(err), "error");
    }
  }, [refreshState, runFullAudit, showToast]);

  const handleToggleStrict = useCallback(async () => {
    if (!state) return;
    try {
      const next = !state.strict_pinning_enabled;
      await toggleStrictPinning(next);
      await refreshState();
      showToast(
        next ? t.strictOn : t.strictOff,
        next ? t.strictOnText : t.strictOffText,
        next ? "warning" : "info",
      );
      runFullAudit(false);
    } catch (err: any) {
      showToast(t.genericError, err?.message || String(err), "error");
    }
  }, [state, refreshState, runFullAudit, showToast]);

  const handleAllowProvider = useCallback(
    async (provider: ProviderId) => {
      try {
        await allowProviderSession(provider);
        showToast(t.accessAllowed, t.accessAllowedText(providers[provider].name), "success");
        await runFullAudit(false);
      } catch (err: any) {
        showToast(t.genericError, err?.message || String(err), "error");
      }
    },
    [runFullAudit, showToast],
  );

  const handleUnblockProvider = useCallback(
    async (provider: ProviderId) => {
      try {
        await unblockProvider(provider);
        await runFullAudit(false);
      } catch (err: any) {
        showToast(t.genericError, err?.message || String(err), "error");
      }
    },
    [runFullAudit, showToast],
  );

  const handleVerifyAndUnblockProvider = useCallback(
    async (provider: ProviderId): Promise<boolean> => {
      try {
        const unblocked = await verifyAndUnblockProvider(provider);
        if (unblocked) {
          showToast(t.accessRestored, t.accessRestoredText(providers[provider].name), "success");
        }
        await runFullAudit(false);
        return unblocked;
      } catch (err: any) {
        showToast(t.genericError, err?.message || String(err), "error");
        return false;
      }
    },
    [runFullAudit, showToast],
  );

  return {
    copiedIp,
    handleCopyIp,
    handlePinIp,
    handleUnpinIp,
    handleToggleStrict,
    handleAllowProvider,
    handleUnblockProvider,
    handleVerifyAndUnblockProvider,
  };
}
