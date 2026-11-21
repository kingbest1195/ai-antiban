import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import type { ProviderId } from "../../types";
import type { ShowToast } from "../../shared/hooks";
import {
  addCustomAiDomain,
  clearTrustedExceptions,
  removeCustomAiDomain,
  removeTrustedException,
  setProviderMonitoring,
} from "../../utils/api";
import { providers as providerCopy, settings as copy } from "../../shared/copy/ru";
import { formatIp } from "../../shared/lib/format";

export const MONITORED_PROVIDERS: ProviderId[] = ["anthropic", "openai", "gemini"];

const errText = (err: unknown) => (err instanceof Error ? err.message : String(err));

export function useSettingsExceptions({
  customDomains,
  setCustomDomains,
  disabledProviders,
  setDisabledProviders,
  trustedExceptions,
  setTrustedExceptions,
  hideIpMode = false,
  onStateUpdated,
  onToast,
}: {
  customDomains: string[];
  setCustomDomains: (domains: string[]) => void;
  disabledProviders: string[];
  setDisabledProviders: (providers: string[]) => void;
  trustedExceptions: Record<string, string[]>;
  setTrustedExceptions: (exceptions: Record<string, string[]>) => void;
  hideIpMode?: boolean;
  onStateUpdated?: () => Promise<unknown> | void;
  onToast?: ShowToast;
}) {
  const [monitoringBusy, setMonitoringBusy] = useState<ProviderId | null>(null);
  const [exceptionsBusy, setExceptionsBusy] = useState(false);
  const [newDomainInput, setNewDomainInput] = useState("");
  const [domainBusy, setDomainBusy] = useState(false);

  const disabledSet = useMemo(() => new Set(disabledProviders.map((p) => p.toLowerCase())), [disabledProviders]);

  const providerLabel = (provider: string): string => {
    const key = provider.toLowerCase() as ProviderId;
    return key in providerCopy ? providerCopy[key].name : provider;
  };

  const exceptionEntries = useMemo(
    () =>
      Object.entries(trustedExceptions)
        .flatMap(([provider, ips]) => (ips ?? []).map((ip) => ({ provider, ip })))
        .sort((a, b) => {
          const ia = MONITORED_PROVIDERS.indexOf(a.provider.toLowerCase() as ProviderId);
          const ib = MONITORED_PROVIDERS.indexOf(b.provider.toLowerCase() as ProviderId);
          const ra = ia >= 0 ? ia : 99;
          const rb = ib >= 0 ? ib : 99;
          if (ra !== rb) return ra - rb;
          if (a.provider !== b.provider) return a.provider.localeCompare(b.provider);
          return a.ip.localeCompare(b.ip);
        }),
    [trustedExceptions],
  );

  const handleAddDomain = async (e: FormEvent) => {
    e.preventDefault();
    const domain = newDomainInput
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//i, "")
      .replace(/\/.*$/, "")
      .replace(/:\d+$/, "")
      .trim();
    if (!domain) return;
    setDomainBusy(true);
    try {
      const updated = await addCustomAiDomain(domain);
      setCustomDomains(updated);
      setNewDomainInput("");
      onStateUpdated?.();
      onToast?.(copy.domains.addedTitle, copy.domains.addedText(domain), "success");
    } catch (err) {
      onToast?.(copy.domains.addError, errText(err), "warning");
    } finally {
      setDomainBusy(false);
    }
  };

  const handleRemoveDomain = async (domain: string) => {
    setDomainBusy(true);
    try {
      const updated = await removeCustomAiDomain(domain);
      setCustomDomains(updated);
      onStateUpdated?.();
      onToast?.(copy.domains.removedTitle, copy.domains.removedText(domain), "info");
    } catch (err) {
      onToast?.(copy.domains.removeError, errText(err), "warning");
    } finally {
      setDomainBusy(false);
    }
  };

  const handleToggleProviderMonitoring = async (providerId: ProviderId, enabled: boolean) => {
    if (monitoringBusy) return;
    setMonitoringBusy(providerId);
    const name = providerCopy[providerId].name;
    try {
      const updated = await setProviderMonitoring(providerId, enabled);
      setDisabledProviders(updated.disabled_providers ?? []);
      if (updated.trusted_exceptions) setTrustedExceptions(updated.trusted_exceptions);
      await onStateUpdated?.();
      if (enabled) onToast?.(copy.monitoring.toastOnTitle(name), copy.monitoring.toastOnText, "success");
      else onToast?.(copy.monitoring.toastOffTitle(name), copy.monitoring.toastOffText, "info");
    } catch (err) {
      onToast?.(copy.monitoring.error, errText(err), "warning");
    } finally {
      setMonitoringBusy(null);
    }
  };

  const handleRemoveTrustedException = async (provider: string, ip: string) => {
    if (exceptionsBusy) return;
    setExceptionsBusy(true);
    const label = providerLabel(provider);
    try {
      const updated = await removeTrustedException(provider, ip);
      setTrustedExceptions(updated.trusted_exceptions ?? {});
      await onStateUpdated?.();
      onToast?.(copy.trustedExceptions.removedTitle, copy.trustedExceptions.removedText(label, formatIp(ip, hideIpMode)), "info");
    } catch (err) {
      onToast?.(copy.trustedExceptions.error, errText(err), "warning");
    } finally {
      setExceptionsBusy(false);
    }
  };

  const handleClearTrustedExceptions = async () => {
    if (exceptionsBusy) return;
    setExceptionsBusy(true);
    try {
      const updated = await clearTrustedExceptions();
      setTrustedExceptions(updated.trusted_exceptions ?? {});
      await onStateUpdated?.();
      onToast?.(copy.trustedExceptions.clearedTitle, copy.trustedExceptions.clearedText, "info");
    } catch (err) {
      onToast?.(copy.trustedExceptions.error, errText(err), "warning");
    } finally {
      setExceptionsBusy(false);
    }
  };

  return {
    customDomains,
    disabledSet,
    exceptionEntries,
    monitoringBusy,
    exceptionsBusy,
    newDomainInput,
    setNewDomainInput,
    domainBusy,
    providerLabel,
    handleAddDomain,
    handleRemoveDomain,
    handleToggleProviderMonitoring,
    handleRemoveTrustedException,
    handleClearTrustedExceptions,
  };
}
