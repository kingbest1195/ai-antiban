import { useEffect, useState } from "react";
import type { AppStateData, ProviderId, RouteView, RoutesSnapshot } from "../../types";
import {
  DIRECT_ROUTE_ID,
  bindProviderRoute,
  bindRouteToClaudeProfile,
  clearUpstreamProxy,
  getRoutesSnapshot,
  listClaudeProfiles,
  removeRoute,
  setDefaultRoute,
  setRouteEnabled,
  testRoute,
  toggleUpstreamProxy,
  upsertRoute,
} from "../../utils/api";
import { Banner, Button, HintCard } from "../../ui";
import { connect as copy } from "../../shared/copy/ru";
import { formatIp } from "../../shared/lib/format";
import type { ShowToast } from "../../shared/hooks";
import { ConnectDefaultVpnCard, ConnectSalesCards } from "./ConnectSalesCards";
import { ProviderRoutesSection } from "./ProviderRoutesSection";
import { RouteDisableModals } from "./RouteDisableModals";
import { type AddKeyScope, RouteListSection } from "./RouteListSection";
import {
  disableRouteAndSwitchBindingsToDirect,
  getAffectedProvidersForRoute,
  inspectRouteUsageForDisable,
  resetProfileRouteAndDisable,
  type PendingDisableRoute,
} from "./routeDisableModel";

export { getAffectedProvidersForRoute };

export interface ConnectScreenProps {
  state: AppStateData | null;
  routesSnapshot?: RoutesSnapshot | null;
  currentIp: string;
  currentCountry: string;
  hideIpMode?: boolean;
  onRefreshState: () => Promise<unknown>;
  onRefreshRoutes?: () => Promise<unknown>;
  onAuditRefresh?: (providerId?: ProviderId) => Promise<void> | void;
  onOpenGuide: (guideId: string) => void;
  onToast: ShowToast;
  onDismissHint?: (hintId: string) => Promise<unknown> | void;
  /** default — классический порядок; sales — карточка «ВПН Заставы» первой, «Свой сервер» второй. */
  layout?: "default" | "sales";
}

/** Определяет страну выхода для сервиса по выбранной привязке маршрута или текущему VPN. */
export function resolveProviderExitCountry(
  providerId: ProviderId,
  snapshot: RoutesSnapshot | null | undefined,
  routes: RouteView[],
  currentCountry: string,
): string {
  const explicitBinding = snapshot?.provider_routes[providerId];
  if (explicitBinding === DIRECT_ROUTE_ID) return currentCountry;
  const routeId = explicitBinding || snapshot?.default_route_id || "";
  if (routeId) {
    const bound = routes.find((r) => r.id === routeId);
    if (bound) return bound.country ?? "";
  }
  return currentCountry;
}

/** Экран «Подключение»: личный VPN, ключ Заставы, маршруты и привязки по сервисам. */
export function ConnectScreen({
  state,
  routesSnapshot: propSnapshot,
  currentIp,
  currentCountry,
  hideIpMode = false,
  onRefreshState,
  onRefreshRoutes,
  onAuditRefresh,
  onOpenGuide,
  onToast,
  onDismissHint,
  layout = "default",
}: ConnectScreenProps) {
  const [localSnapshot, setLocalSnapshot] = useState<RoutesSnapshot | null>(null);
  const [localDismissed, setLocalDismissed] = useState<string[]>(() => state?.dismissed_hints ?? []);
  const [inputKey, setInputKey] = useState<string>("");
  const [addScope, setAddScope] = useState<AddKeyScope>("all");
  const [error, setError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState<boolean>(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [pendingDisable, setPendingDisable] = useState<PendingDisableRoute | null>(null);
  const [confirmProfileReset, setConfirmProfileReset] = useState<PendingDisableRoute | null>(null);
  const [disablingAction, setDisablingAction] = useState<boolean>(false);

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
  const hasRoutes = routes.length > 0;
  const isLegacyConfigured = Boolean(upstream);

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
    if (!enabled) {
      const usage = inspectRouteUsageForDisable(routeId, snapshot, routes);
      if (usage.inUse) {
        const route = routes.find((r) => r.id === routeId);
        setPendingDisable({
          routeId,
          routeLabel: route?.label || copy.key.defaultLabel,
          usage,
        });
        return;
      }
    }
    await performToggleRoute(routeId, enabled, getAffectedProvidersForRoute(routeId, snapshot));
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
        onToast(
          copy.key.toast.testSuccess,
          copy.key.toast.testSuccessText(res.exit_ip ? formatIp(res.exit_ip, hideIpMode) : "—", res.latency_ms),
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

  const handleRemoveRoute = async (routeId: string) => {
    setDeletingId(routeId);
    const affected = routes.length <= 1 ? "all" : getAffectedProvidersForRoute(routeId, snapshot);
    try {
      await removeRoute(routeId);
      if (routes.length <= 1) {
        try {
          await clearUpstreamProxy();
        } catch {
          // Игнорируем
        }
      }
      await refresh(affected);
      onToast(copy.key.toast.disconnected, copy.key.toast.disconnectedText, "info");
    } catch (err: unknown) {
      onToast(copy.key.toast.disconnectError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setDeletingId(null);
    }
  };

  const handleSetDefaultRoute = async (routeId: string) => {
    try {
      await setDefaultRoute(routeId);
      await refresh();
    } catch (err: unknown) {
      onToast(copy.routes.toast.boundError, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const handleBindProvider = async (provider: ProviderId, target: string) => {
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

  const handleLegacyToggle = async () => {
    if (!upstream) return;
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
  };

  const handleLegacyDisconnect = async () => {
    try {
      await clearUpstreamProxy();
      await refresh();
      onToast(copy.key.toast.disconnected, copy.key.toast.disconnectedText, "info");
    } catch (err: unknown) {
      onToast(copy.key.toast.disconnectError, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const hasDangling = Boolean(snapshot?.dangling && snapshot.dangling.length > 0);
  const hasProfileError = Boolean(snapshot?.profile_route_error);

  return (
    <>
      <HintCard
        hintId="connect_intro"
        body="Подключите ключ Заставы или свой сервер (VPS) — отдельные маршруты для каждого ИИ."
        dismissedHints={localDismissed}
        onDismiss={(id) => { setLocalDismissed((p) => (p.includes(id) ? p : [...p, id])); void onDismissHint?.(id); }}
      />
      {hasDangling && (
        <Banner
          tone="danger"
          title={copy.routes.danglingTitle}
          action={
            <Button variant="secondary" size="sm" onClick={handleResetAllDangling}>
              {copy.routes.resetToDirect}
            </Button>
          }
        >
          {copy.routes.danglingText}
        </Banner>
      )}

      {hasProfileError && (
        <Banner
          tone="danger"
          title={copy.routes.profileErrorTitle}
          action={
            <Button variant="secondary" size="sm" onClick={handleResetActiveProfileRoute}>
              {copy.routes.resetToDirect}
            </Button>
          }
        >
          {snapshot?.profile_route_error || copy.routes.profileErrorText}
        </Banner>
      )}

      {layout === "sales" ? (
        <ConnectSalesCards
          routes={routes}
          hasRoutes={hasRoutes}
          isLegacyConfigured={isLegacyConfigured}
          inputKey={inputKey}
          addScope={addScope}
          error={error}
          connecting={connecting}
          onInputKeyChange={(val) => {
            setInputKey(val);
            if (error) setError(null);
          }}
          onAddScopeChange={setAddScope}
          onAddKey={handleAddKey}
          onOpenGuide={onOpenGuide}
        />
      ) : (
        <ConnectDefaultVpnCard
          hasRoutes={hasRoutes}
          isLegacyConfigured={isLegacyConfigured}
          onOpenGuide={onOpenGuide}
        />
      )}

      {(layout !== "sales" || hasRoutes || isLegacyConfigured) && (
        <RouteListSection
          routes={routes}
          upstream={upstream}
          currentIp={currentIp}
          currentCountry={currentCountry}
          hideIpMode={hideIpMode}
          addScope={addScope}
          setAddScope={setAddScope}
          inputKey={inputKey}
          onInputKeyChange={(val) => {
            setInputKey(val);
            if (error) setError(null);
          }}
          error={error}
          connecting={connecting}
          testingId={testingId}
          togglingId={togglingId}
          deletingId={deletingId}
          onAddKey={handleAddKey}
          onToggleRoute={handleToggleRoute}
          onTestRoute={handleTestRoute}
          onSetDefaultRoute={handleSetDefaultRoute}
          onRemoveRoute={handleRemoveRoute}
          onLegacyToggle={handleLegacyToggle}
          onLegacyDisconnect={handleLegacyDisconnect}
          suppressPrimaryCta={layout === "sales"}
        />
      )}

      {hasRoutes && (
        <ProviderRoutesSection
          snapshot={snapshot}
          routes={routes}
          currentCountry={currentCountry}
          hideIpMode={hideIpMode}
          onBindProvider={handleBindProvider}
        />
      )}

      <RouteDisableModals
        pendingDisable={pendingDisable}
        confirmProfileReset={confirmProfileReset}
        busy={disablingAction}
        onCancelDisable={() => setPendingDisable(null)}
        onChooseDirect={() => void handleChooseDirect()}
        onChooseStopAndBlock={() => void handleChooseStopAndBlock()}
        onCancelProfileReset={() => setConfirmProfileReset(null)}
        onConfirmProfileReset={() => void handleConfirmProfileReset()}
      />
    </>
  );
}
