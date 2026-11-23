import type { AppStateData, ProviderId, RoutesSnapshot } from "../../types";
import { Banner, Button, HintCard } from "../../ui";
import { connect as copy } from "../../shared/copy/ru";
import type { ShowToast } from "../../shared/hooks";
import { ConnectDefaultVpnCard, ConnectSalesCards } from "./ConnectSalesCards";
import { ProviderRoutesSection } from "./ProviderRoutesSection";
import { RouteDisableModals } from "./RouteDisableModals";
import { RouteListSection } from "./RouteListSection";
import {
  getAffectedProvidersForRoute,
  resolveProviderExitCountry,
} from "./routeDisableModel";
import { useConnectScreen } from "./useConnectScreen";
import { QuarantineBanner, QuarantineOverrideModal } from "../subscription/QuarantineOverrideModal";

export { getAffectedProvidersForRoute, resolveProviderExitCountry };

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
  const c = useConnectScreen({
    state,
    propSnapshot,
    hideIpMode,
    onRefreshState,
    onRefreshRoutes,
    onAuditRefresh,
    onToast,
  });

  const hasRoutes = c.routes.length > 0;
  const isLegacyConfigured = Boolean(c.upstream);
  const hasDangling = Boolean(c.snapshot?.dangling && c.snapshot.dangling.length > 0);
  const hasProfileError = Boolean(c.snapshot?.profile_route_error);

  return (
    <>
      <QuarantineBanner status={c.quarantine.quarantineStatus} />
      <HintCard
        hintId="connect_intro"
        body="Подключите ключ Заставы или свой сервер (VPS) — отдельные маршруты для каждого ИИ."
        dismissedHints={c.localDismissed}
        onDismiss={(id) => {
          c.setLocalDismissed((p) => (p.includes(id) ? p : [...p, id]));
          void onDismissHint?.(id);
        }}
      />
      {hasDangling && (
        <Banner
          tone="danger"
          title={copy.routes.danglingTitle}
          action={
            <Button variant="secondary" size="sm" onClick={c.handleResetAllDangling}>
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
            <Button variant="secondary" size="sm" onClick={c.handleResetActiveProfileRoute}>
              {copy.routes.resetToDirect}
            </Button>
          }
        >
          {c.snapshot?.profile_route_error || copy.routes.profileErrorText}
        </Banner>
      )}

      {layout === "sales" ? (
        <ConnectSalesCards
          routes={c.routes}
          hasRoutes={hasRoutes}
          isLegacyConfigured={isLegacyConfigured}
          inputKey={c.inputKey}
          addScope={c.addScope}
          error={c.error}
          connecting={c.connecting}
          onInputKeyChange={(val) => {
            c.setInputKey(val);
            if (c.error) c.setError(null);
          }}
          onAddScopeChange={c.setAddScope}
          onAddKey={c.handleAddKey}
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
          routes={c.routes}
          upstream={c.upstream}
          currentIp={currentIp}
          currentCountry={currentCountry}
          hideIpMode={hideIpMode}
          addScope={c.addScope}
          setAddScope={c.setAddScope}
          inputKey={c.inputKey}
          onInputKeyChange={(val) => {
            c.setInputKey(val);
            if (c.error) c.setError(null);
          }}
          error={c.error}
          connecting={c.connecting}
          testingId={c.testingId}
          refreshingId={c.refreshingId}
          togglingId={c.togglingId}
          deletingId={c.deletingId}
          onAddKey={c.handleAddKey}
          onToggleRoute={c.handleToggleRoute}
          onTestRoute={c.handleTestRoute}
          onRefreshSubscription={c.handleRefreshSubscription}
          onSetDefaultRoute={c.handleSetDefaultRoute}
          onRemoveRoute={c.handleRemoveRoute}
          onLegacyToggle={c.handleLegacyToggle}
          onLegacyDisconnect={c.handleLegacyDisconnect}
          suppressPrimaryCta={layout === "sales"}
        />
      )}

      {hasRoutes && (
        <ProviderRoutesSection
          snapshot={c.snapshot}
          routes={c.routes}
          currentCountry={currentCountry}
          hideIpMode={hideIpMode}
          onBindProvider={c.handleBindProvider}
        />
      )}

      <RouteDisableModals
        pendingDisable={c.pendingDisable}
        confirmProfileReset={c.confirmProfileReset}
        busy={c.disablingAction}
        onCancelDisable={() => c.setPendingDisable(null)}
        onChooseDirect={() => void c.handleChooseDirect()}
        onChooseStopAndBlock={() => void c.handleChooseStopAndBlock()}
        onCancelProfileReset={() => c.setConfirmProfileReset(null)}
        onConfirmProfileReset={() => void c.handleConfirmProfileReset()}
      />
      <QuarantineOverrideModal
        open={c.quarantine.overrideModalOpen}
        remainingHours={c.quarantine.quarantineStatus?.remainingHours ?? 72}
        busy={c.quarantine.overriding}
        onCancel={c.quarantine.cancelOverride}
        onConfirm={() => void c.quarantine.confirmOverrideAndRun()}
      />
    </>
  );
}
