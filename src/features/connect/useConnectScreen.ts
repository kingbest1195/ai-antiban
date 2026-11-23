import { useEffect, useState } from "react";
import type { AppStateData, ProviderId, RoutesSnapshot } from "../../types";
import {
  bindProviderRoute,
  bindRouteToClaudeProfile,
  clearUpstreamProxy,
  getRoutesSnapshot,
  listClaudeProfiles,
  refreshRouteSubscription,
  removeRoute,
  setDefaultRoute,
  setRouteEnabled,
  testRoute,
  toggleUpstreamProxy,
  upsertRoute,
} from "../../utils/api";
import { connect as copy } from "../../shared/copy/ru";
import { formatIp } from "../../shared/lib/format";
import type { ShowToast } from "../../shared/hooks";
import type { AddKeyScope } from "./RouteListSection";
import {
  disableRouteAndSwitchBindingsToDirect,
  getAffectedProvidersForRoute,
  inspectRouteUsageForDisable,
  resetProfileRouteAndDisable,
  type PendingDisableRoute,
} from "./routeDisableModel";
import { useQuarantineGuard } from "../subscription/useQuarantineGuard";

export interface UseConnectScreenOptions {
  state: AppStateData | null;
  propSnapshot?: RoutesSnapshot | null;
  hideIpMode: boolean;
  onRefreshState: () => Promise<unknown>;
  onRefreshRoutes?: () => Promise<unknown>;
  onAuditRefresh?: (providerId?: ProviderId) => Promise<void> | void;
  onToast: ShowToast;
}

export function useConnectScreen({
  state,
  propSnapshot,
  hideIpMode,
  onRefreshState,
  onRefreshRoutes,
  onAuditRefresh,
  onToast,
}: UseConnectScreenOptions) {
  const [localSnapshot, setLocalSnapshot] = useState<RoutesSnapshot | null>(null);
  const [localDismissed, setLocalDismissed] = useState<string[]>(() => state?.dismissed_hints ?? []);
  const [inputKey, setInputKey] = useState<string>("");
  const [addScope, setAddScope] = useState<AddKeyScope>("all");
  const [error, setError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState<boolean>(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [refreshingId, setRefreshingId] = useState<string | null>(null);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [pendingDisable, setPendingDisable] = useState<PendingDisableRoute | null>(null);
  const [confirmProfileReset, setConfirmProfileReset] = useState<PendingDisableRoute | null>(null);
  const [disablingAction, setDisablingAction] = useState<boolean>(false);
  const quarantine = useQuarantineGuard({ profileId: state?.clean_room?.active_profile_id ?? null });

  const snapshot = propSnapshot ?? localSnapshot;

  const refresh = async (auditScope: ProviderId | ProviderId[] | "all" | "none" = "all") => {
    try {
      if (onRefreshRoutes) {
        await onRefreshRoutes();
      } else {
        const snap = await getRoutesSnapshot();
        setLocalSnapshot(snap);
      }
    } catch {
      // Игнорируем ошибки при обновлении снимка
    }
    await onRefreshState();
    if (!onAuditRefresh || auditScope === "none") return;
    if (auditScope === "all") {
      await onAuditRefresh();
    } else if (Array.isArray(auditScope)) {
      for (const providerId of Array.from(new Set(auditScope))) {
        await onAuditRefresh(providerId);
      }
    } else {
      await onAuditRefresh(auditScope);
    }
  };

  useEffect(() => {
    if (state?.dismissed_hints) setLocalDismissed(state.dismissed_hints);
  }, [state?.dismissed_hints]);

  useEffect(() => {
    if (!propSnapshot) {
      getRoutesSnapshot().then(setLocalSnapshot).catch(() => null);
    }
  }, [propSnapshot]);

  const upstream = state?.upstream_proxy ?? null;
  const routes = snapshot?.routes ?? [];

  const handleAddKey = async () => {
    const key = inputKey.trim();
    if (!key) {
      setError(copy.key.empty);
      return;
    }
    setError(null);
    setConnecting(true);
    try {
      const applyToAll = addScope === "all";
      await upsertRoute(key, null, applyToAll);
      await refresh(applyToAll ? "all" : "none");
      setInputKey("");
      onToast(
        copy.key.toast.connected,
        applyToAll ? copy.key.toast.connectedText : copy.key.toast.savedOnlyText,
        "success",
      );
    } catch (err: unknown) {
      const raw = err instanceof Error ? err.message : String(err);
      const msg = /invalid proxy url|invalid port|relative url|parse error|empty host/i.test(raw)
        ? copy.key.invalidKeyFormat
        : raw;
      setError(msg);
      onToast(copy.key.toast.connectError, msg, "error");
    } finally {
      setConnecting(false);
    }
  };

  const performToggleRoute = async (
    routeId: string,
    enabled: boolean,
    affected: "all" | ProviderId[],
  ) => {
    setTogglingId(routeId);
    try {
      await setRouteEnabled(routeId, enabled);
      await refresh(affected);
      onToast(
        enabled ? copy.key.toast.on : copy.key.toast.off,
        enabled ? copy.key.toast.onText : copy.key.toast.offText,
        "info",
      );
    } catch (err: unknown) {
      onToast(copy.key.toast.toggleError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setTogglingId(null);
    }
  };

  const handleToggleRoute = async (routeId: string, enabled: boolean) => {
    const execute = async () => {
      if (!enabled) {
        const usage = inspectRouteUsageForDisable(routeId, snapshot, routes);
        if (usage.inUse) {
          const route = routes.find((r) => r.id === routeId);
          setPendingDisable({ routeId, routeLabel: route?.label || copy.key.defaultLabel, usage });
          return;
        }
      }
      await performToggleRoute(routeId, enabled, getAffectedProvidersForRoute(routeId, snapshot));
    };
    quarantine.guardRouteSwitch(execute);
  };

  const handleChooseStopAndBlock = async () => {
    if (!pendingDisable) return;
    const target = pendingDisable;
    setDisablingAction(true);
    try {
      await performToggleRoute(target.routeId, false, target.usage.affected);
      setPendingDisable(null);
    } finally {
      setDisablingAction(false);
    }
  };

  const handleChooseDirect = async () => {
    if (!pendingDisable) return;
    const target = pendingDisable;
    if (target.usage.isProfileRoute) {
      setPendingDisable(null);
      setConfirmProfileReset(target);
      return;
    }
    setDisablingAction(true);
    try {
      await disableRouteAndSwitchBindingsToDirect(target);
      await refresh(target.usage.affected);
      onToast(copy.routes.disableModal.toastDirectTitle, copy.routes.disableModal.toastDirectText, "info");
      setPendingDisable(null);
    } catch (err: unknown) {
      onToast(copy.key.toast.toggleError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setDisablingAction(false);
    }
  };

  const handleConfirmProfileReset = async () => {
    if (!confirmProfileReset) return;
    const target = confirmProfileReset;
    setDisablingAction(true);
    try {
      await resetProfileRouteAndDisable(target);
      await refresh(target.usage.affected);
      onToast(copy.routes.disableModal.toastDirectTitle, copy.routes.disableModal.toastDirectText, "info");
      setConfirmProfileReset(null);
    } catch (err: unknown) {
      onToast(copy.routes.toast.boundError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setDisablingAction(false);
    }
  };

  const handleTestRoute = async (routeId: string) => {
    setTestingId(routeId);
    try {
      const res = await testRoute(routeId);
      if (res.ok) {
        const ipLabel = res.exit_ip ? formatIp(res.exit_ip, hideIpMode) : "—";
        onToast(
          copy.key.toast.testSuccess,
          res.grace_extended
            ? copy.key.toast.graceExtendedText(ipLabel, res.latency_ms)
            : copy.key.toast.testSuccessText(ipLabel, res.latency_ms),
          "success",
        );
      } else {
        onToast(copy.key.toast.testError, res.error || copy.key.unreachable, "error");
      }
      await refresh("none");
    } catch (err: unknown) {
      onToast(copy.key.toast.testError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setTestingId(null);
    }
  };

  const handleRefreshSubscription = async (routeId: string) => {
    setRefreshingId(routeId);
    try {
      const updated = await refreshRouteSubscription(routeId);
      const dateStr = updated.expires_at ? new Date(updated.expires_at * 1000).toLocaleDateString() : null;
      onToast(copy.key.toast.refreshSubSuccess, copy.key.toast.refreshSubSuccessText(dateStr), "success");
      await refresh("none");
    } catch (err: unknown) {
      onToast(copy.key.toast.refreshSubError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setRefreshingId(null);
    }
  };

  const handleRemoveRoute = async (routeId: string) => {
    quarantine.guardRouteSwitch(async () => {
      setDeletingId(routeId);
      const affected = routes.length <= 1 ? "all" : getAffectedProvidersForRoute(routeId, snapshot);
      try {
        await removeRoute(routeId);
        if (routes.length <= 1) {
          await clearUpstreamProxy().catch(() => {});
        }
        await refresh(affected);
        onToast(copy.key.toast.disconnected, copy.key.toast.disconnectedText, "info");
      } catch (err: unknown) {
        onToast(copy.key.toast.disconnectError, err instanceof Error ? err.message : String(err), "error");
      } finally {
        setDeletingId(null);
      }
    });
  };

  const handleSetDefaultRoute = async (routeId: string) => {
    quarantine.guardRouteSwitch(async () => {
      try {
        await setDefaultRoute(routeId);
        await refresh();
      } catch (err: unknown) {
        onToast(copy.routes.toast.boundError, err instanceof Error ? err.message : String(err), "error");
      }
    });
  };

  const handleBindProvider = async (provider: ProviderId, target: string) => {
    quarantine.guardRouteSwitch(async () => {
      try {
        await bindProviderRoute(provider, target);
        await refresh(provider);
        onToast(
          copy.routes.toast.boundSuccess,
          copy.routes.toast.boundSuccessText(copy.routes.services[provider]),
          "success",
        );
      } catch (err: unknown) {
        onToast(copy.routes.toast.boundError, err instanceof Error ? err.message : String(err), "error");
      }
    });
  };

  const handleResetActiveProfileRoute = async () => {
    try {
      const list = await listClaudeProfiles();
      if (list.active_profile_id) {
        await bindRouteToClaudeProfile(list.active_profile_id, null);
      }
      await refresh(["anthropic"]);
      onToast(copy.routes.toast.resetSuccess, copy.routes.toast.resetSuccessText, "info");
    } catch (err: unknown) {
      onToast(copy.routes.toast.boundError, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const handleResetAllDangling = async () => {
    try {
      const dangling = snapshot?.dangling || [];
      let clearedDefault = false;
      const affectedProviders: ProviderId[] = [];
      for (const item of dangling) {
        if (item.kind === "default" && !clearedDefault) {
          await setDefaultRoute(null);
          clearedDefault = true;
        } else if (item.kind === "profile") {
          const list = await listClaudeProfiles();
          if (list.active_profile_id) {
            await bindRouteToClaudeProfile(list.active_profile_id, null);
          }
          affectedProviders.push("anthropic");
        } else if (item.provider) {
          await bindProviderRoute(item.provider as ProviderId, "direct");
          affectedProviders.push(item.provider as ProviderId);
        }
      }
      await refresh(clearedDefault ? "all" : affectedProviders.length > 0 ? affectedProviders : "none");
      onToast(copy.routes.toast.resetSuccess, copy.routes.toast.resetSuccessText, "info");
    } catch (err: unknown) {
      onToast(copy.routes.toast.boundError, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const handleLegacyToggle = () => {
    if (!upstream) return;
    quarantine.guardRouteSwitch(async () => {
      try {
        const next = !upstream.enabled;
        await toggleUpstreamProxy(next);
        await refresh();
        onToast(
          next ? copy.key.toast.on : copy.key.toast.off,
          next ? copy.key.toast.onText : copy.key.toast.offText,
          "info",
        );
      } catch (err: unknown) {
        onToast(copy.key.toast.toggleError, err instanceof Error ? err.message : String(err), "error");
      }
    });
  };

  const handleLegacyDisconnect = () => {
    quarantine.guardRouteSwitch(async () => {
      try {
        await clearUpstreamProxy();
        await refresh();
        onToast(copy.key.toast.disconnected, copy.key.toast.disconnectedText, "info");
      } catch (err: unknown) {
        onToast(copy.key.toast.disconnectError, err instanceof Error ? err.message : String(err), "error");
      }
    });
  };

  return {
    snapshot,
    upstream,
    routes,
    localDismissed,
    setLocalDismissed,
    inputKey,
    setInputKey,
    addScope,
    setAddScope,
    error,
    setError,
    connecting,
    testingId,
    refreshingId,
    togglingId,
    deletingId,
    pendingDisable,
    setPendingDisable,
    confirmProfileReset,
    setConfirmProfileReset,
    disablingAction,
    quarantine,
    handleAddKey,
    handleToggleRoute,
    handleChooseStopAndBlock,
    handleChooseDirect,
    handleConfirmProfileReset,
    handleTestRoute,
    handleRefreshSubscription,
    handleRemoveRoute,
    handleSetDefaultRoute,
    handleBindProvider,
    handleResetActiveProfileRoute,
    handleResetAllDangling,
    handleLegacyToggle,
    handleLegacyDisconnect,
  };
}
