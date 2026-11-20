import { Banner, Button, Segmented, Stat, Stats } from "../ui";
import { overview as overviewCopy, shell as copy } from "../shared/copy/ru";
import { formatCountryWithCode } from "../shared/lib/country";
import { formatIp, formatNumber } from "../shared/lib/format";
import { isTauri } from "../utils/api/client";
import { buildPendingChecks, progressOf } from "../features/checks/checksModel";
import type { OverviewScreenProps } from "../features/overview/OverviewScreen";
import { useOverviewModel } from "../features/overview/useOverviewModel";
import type { OverviewView } from "../features/shell-v3/types";
import type { PersonaRiskFixTarget } from "../types";
import { ConnectScreen } from "../features/connect/ConnectScreen";
import { BackupScreen } from "../features/backup";
import { ChecksScreen } from "../features/checks";
import { CleanRoomScreen } from "../features/clean-room";
import { GuidesScreen } from "../features/guides";
import {
  HeaderBar,
  HomeHub,
  NotificationStack,
  PageHead,
  ServicesPage,
} from "../features/shell-v3";
import "../features/shell-v3/shellV3.css";
import "../features/shell-v3/shellV3Extras.css";
import { AppShellDialogs } from "./AppShellDialogs";
import { useAppShellController } from "./useAppShellController";
import "./shell.css";

const PAGE_TITLES: Record<string, string> = {
  services: "Нейросети и защита",
  "clean-room": "Чистая комната",
  backup: "Аккаунты, Бункер и SOS",
  connect: "VPN и ключи",
  checks: "Проверки и гайды",
  guides: "Гайды",
  stats: "Статистика шлюза",
};

export interface PersonaFixActions {
  currentIp: string;
  openCleanRoom: () => void;
  openConnect: () => void;
  openChecks: () => void;
  pinIp: (ip: string) => void;
  openTimezone: () => void;
  scrollToElement: (...ids: string[]) => void;
}

/** Маршрутизирует все 6 значений `fix_target` из `persona_risk.rs` к реальным действиям оболочки. */
export function routePersonaFixTarget(target: PersonaRiskFixTarget, actions: PersonaFixActions): void {
  switch (target) {
    case "open_clean_room":
      actions.openCleanRoom();
      return;
    case "switch_route":
      actions.openConnect();
      return;
    case "pin_ip":
      if (actions.currentIp && actions.currentIp !== "--") actions.pinIp(actions.currentIp);
      else actions.openChecks();
      return;
    case "sync_os_tz":
      actions.openTimezone();
      return;
    case "clean_cache":
      actions.scrollToElement("claude-cache-section", "claude-profiles-section");
      return;
    case "open_bunker":
      actions.scrollToElement("bunker-section");
      return;
  }
}

function scrollToFirstElement(...ids: string[]): void {
  if (typeof document === "undefined") return;
  for (const id of ids) {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView?.({ behavior: "smooth", block: "start" });
      return;
    }
  }
}

/** Оболочка главного окна v3 («Разделы»): шапка, Home Hub 460×660, стек навигации и диалоги. */
export function AppShell() {
  const ctrl = useAppShellController();
  const {
    nav,
    toasts,
    showToast,
    dismissToast,
    setCrashTestOpen,
    setTimezoneOpen,
    routeUnavailableBanner,
    setRouteUnavailableBanner,
    profileRefreshKey,
    stats,
    gw,
    toggles,
    coworkGuard,
    personaRisk,
    pinning,
    tz,
    updater,
    hideIpMode,
    intercept,
    backup,
    version,
    menuItems,
    handleToggleHideIp,
    handleDismissHint,
  } = ctrl;

  const { runFullAudit, refreshState } = gw;
  const payload = intercept.interceptPayload;
  const page = nav.currentRoute.page;

  const overviewProps: OverviewScreenProps = {
    reports: gw.reports,
    activeReport: gw.activeReport,
    state: gw.state,
    refreshing: gw.refreshing,
    auditError: gw.auditError,
    startupPending: gw.startupPending,
    partial: gw.partialAudit,
    currentIp: gw.currentIp,
    trustScore: gw.trustScore,
    gatewayStats: stats.gatewayStats,
    updateInfo: updater.updateInfo,
    coverageSnapshot: gw.coverageSnapshot,
    routesSnapshot: gw.routesSnapshot,
    hideIpMode,
    dataAgeMinutes: gw.dataAgeMinutes,
    sysproxyActive: gw.sysproxyActive,
    cliProtected: toggles.cliProtected,
    killswitchFrozen: toggles.killswitchFrozen,
    onToggleSysproxy: toggles.handleToggleSysproxy,
    onToggleCli: toggles.handleToggleCliProtection,
    protection: toggles.protection,
    onToggleKillswitch: toggles.handleToggleKillswitch,
    onToast: showToast,
    onCopyIp: pinning.handleCopyIp,
    onPinIp: pinning.handlePinIp,
    onUnpinIp: pinning.handleUnpinIp,
    onToggleStrict: pinning.handleToggleStrict,
    onAllowProvider: pinning.handleAllowProvider,
    onUnblockProvider: pinning.handleUnblockProvider,
    onVerifyAndUnblockProvider: pinning.handleVerifyAndUnblockProvider,
    onRetry: () => runFullAudit(true),
    onOpenChecks: () => nav.push({ page: "checks" }),
    onFixService: (provider) => nav.push({ page: "checks", checksProvider: provider }),
    onOpenTimezone: () => setTimezoneOpen(true),
    onOpenUpdate: () => updater.setShowUpdateModal(true),
    onOpenCrashTest: () => setCrashTestOpen(true),
    onOpenConnect: () => nav.push({ page: "connect" }),
  };

  const model = useOverviewModel({
    reports: gw.reports,
    activeReport: gw.activeReport,
    state: gw.state,
    currentIp: gw.currentIp,
    sysproxyActive: gw.sysproxyActive,
    killswitchFrozen: toggles.killswitchFrozen,
    updateInfo: updater.updateInfo,
    refreshing: gw.refreshing,
    startupPending: gw.startupPending,
  });

  const overviewView: OverviewView = {
    loading: !gw.activeReport && !gw.auditError,
    failed: !gw.activeReport && Boolean(gw.auditError),
    progress: progressOf(buildPendingChecks(gw.partialAudit ?? null, gw.state)),
    model,
  };

  const checksSubTab = nav.currentRoute.checksSubTab ?? (page === "guides" ? "guides" : "checks");

  return (
    <div className="zs-root zs-shell-page">
      <div className="zs-app zs-shell zs-v3-app">
        <HeaderBar
          pingMs={gw.activeReport ? gw.scanLatencyMs : null}
          refreshing={gw.refreshing}
          onRescan={() => void runFullAudit(true)}
          hideIpMode={hideIpMode}
          onToggleHideIp={() => void handleToggleHideIp()}
          updateInfo={updater.updateInfo}
          onOpenUpdate={() => updater.setShowUpdateModal(true)}
          menuItems={menuItems}
        />

        {page !== "home" && (
          <PageHead
            title={PAGE_TITLES[page] ?? "Раздел"}
            onBack={nav.pop}
            onHome={nav.goHome}
            showHome={nav.navStack.length > 2}
          />
        )}

        {isTauri() && payload && (
          <Banner
            tone="danger"
            role="alert"
            title={copy.intercept.title(payload.provider.toUpperCase())}
            action={
              <div className="zs-banner__actions">
                <Button size="sm" disabled={payload.phase !== "ready"} onClick={intercept.handleAllowInterception}>
                  {copy.intercept.allow}
                </Button>
                <Button size="sm" variant="secondary" onClick={intercept.handlePauseUntilNetworkChange}>
                  {copy.intercept.pauseUntilNetworkChange}
                </Button>
                <Button size="sm" variant="quiet" onClick={() => intercept.setInterceptPayload(null)}>
                  {copy.intercept.dismiss}
                </Button>
              </div>
            }
          >
            {intercept.allowError ?? (
              <>
                {payload.gate_reason && (
                  <strong className="zs-intercept-reason">
                    {copy.intercept.gateReasonLabel} {payload.gate_reason}{" "}
                  </strong>
                )}
                {payload.network_change?.new_country === "RU"
                  ? copy.intercept.ruText
                  : copy.intercept.ipText(
                      formatIp(payload.report?.telemetry?.ip, hideIpMode),
                      formatCountryWithCode(payload.report?.telemetry?.country_code) ||
                        payload.report?.telemetry?.country_code ||
                        "--",
                    )}
              </>
            )}
          </Banner>
        )}

        <div className="zs-stack" hidden={page !== "home"}>
          <HomeHub
            overview={overviewProps}
            view={overviewView}
            togglingSysproxy={toggles.togglingSysproxy}
            coworkGuard={coworkGuard}
            personaRisk={personaRisk}
            gatewayStats={stats.gatewayStats}
            state={gw.state}
            routeUnavailableBanner={routeUnavailableBanner}
            onPushRoute={nav.push}
            onDismissRouteUnavailable={() => setRouteUnavailableBanner(null)}
            onRefreshRoutes={gw.refreshRoutes}
            onRefreshState={refreshState}
            onAuditRefresh={(providerId) =>
              providerId ? gw.runProviderAudit(providerId, true) : runFullAudit(true)
            }
            version={version}
          />
        </div>

        <div className="zs-stack" hidden={page !== "services"}>
          <ServicesPage overview={overviewProps} view={overviewView} onDismissHint={handleDismissHint} />
        </div>

        <div className="zs-stack" hidden={page !== "clean-room"}>
          <CleanRoomScreen
            state={gw.state}
            report={gw.activeReport}
            routesSnapshot={gw.routesSnapshot}
            initialTab={nav.currentRoute.cleanRoomTab}
            initialStep={nav.currentRoute.cleanRoomStep}
            navKey={nav.cleanRoomNavKey}
            manualKillswitch={toggles.killswitchFrozen}
            onNavigateToGuide={(guideRef) => nav.openGuide(guideRef)}
            onNavigateToConnect={() => nav.push({ page: "connect" })}
            onStateUpdated={refreshState}
            onDismissHint={handleDismissHint}
            toast={showToast}
          />
        </div>

        <div className="zs-stack" hidden={page !== "backup"}>
          <BackupScreen
            backup={backup}
            currentIp={gw.currentIp}
            currentCountry={gw.currentCountry}
            activeUpstreamKey={gw.state?.upstream_proxy?.raw_key}
            routesSnapshot={gw.routesSnapshot}
            profileRefreshTrigger={profileRefreshKey}
            ipChangeCooldownUntil={gw.state?.ip_change_cooldown_until}
            dismissedHints={gw.state?.dismissed_hints}
            initialSosBranch={nav.currentRoute.sosBranch}
            sosNavKey={nav.sosNavKey}
            visible={page === "backup"}
            personaRefreshKey={personaRisk?.evaluated_at}
            onCooldownCleared={() => runFullAudit(false)}
            onDismissHint={(id) => void handleDismissHint(id)}
            onNavigateToCleanRoom={(step) =>
              nav.push({ page: "clean-room", cleanRoomTab: "launchpad", cleanRoomStep: step })
            }
            onNavigateToPaymentGuide={() => nav.openGuide("02-safe-payment-cards")}
            onPersonaFixTarget={(target) =>
              routePersonaFixTarget(target, {
                currentIp: gw.currentIp,
                openCleanRoom: () => nav.push({ page: "clean-room", cleanRoomTab: "launchpad", cleanRoomStep: 1 }),
                openConnect: () => nav.push({ page: "connect" }),
                openChecks: () => nav.push({ page: "checks" }),
                pinIp: (ip) => void pinning.handlePinIp(ip),
                openTimezone: () => setTimezoneOpen(true),
                scrollToElement: scrollToFirstElement,
              })
            }
            onRoutesUpdated={() => gw.refreshRoutes()}
            onProfileSwitched={async () => {
              await Promise.all([refreshState(), gw.refreshRoutes()]);
              await runFullAudit(false);
            }}
            onToast={showToast}
          />
        </div>

        <div className="zs-stack" hidden={page !== "connect"}>
          <ConnectScreen
            state={gw.state}
            routesSnapshot={gw.routesSnapshot}
            currentIp={gw.currentIp}
            currentCountry={gw.currentCountry}
            hideIpMode={hideIpMode}
            onRefreshState={refreshState}
            onRefreshRoutes={gw.refreshRoutes}
            onAuditRefresh={(providerId) =>
              providerId ? gw.runProviderAudit(providerId, true) : runFullAudit(true)
            }
            onOpenGuide={nav.openGuide}
            onToast={showToast}
            onDismissHint={handleDismissHint}
            layout="sales"
          />
        </div>

        <div className="zs-stack" hidden={page !== "checks" && page !== "guides"}>
          {page === "checks" && (
            <Segmented
              aria-label="Проверки и гайды"
              value={checksSubTab}
              onChange={(next) =>
                nav.push({ page: "checks", checksProvider: nav.checksProvider, checksSubTab: next })
              }
              options={[
                { value: "checks", label: "Проверки сети" },
                { value: "guides", label: "Гайды" },
              ]}
            />
          )}
          <div className="zs-stack" hidden={checksSubTab !== "checks"}>
            <ChecksScreen
              report={(nav.checksProvider && gw.reports[nav.checksProvider]) || gw.checksReport}
              reports={gw.reports}
              partial={gw.partialAudit}
              auditError={gw.auditError}
              startupPending={gw.startupPending}
              provider={nav.checksProvider}
              state={gw.state}
              coverageSnapshot={gw.coverageSnapshot}
              hideIpMode={hideIpMode}
              protection={toggles.protection}
              onToast={showToast}
              onNavigateToGuide={nav.openGuide}
              onSimulate={intercept.handleSimulate}
              onPinCurrentIp={pinning.handlePinIp}
              onSyncTimezone={() => tz.handleSyncTz()}
              onOpenCrashTest={() => setCrashTestOpen(true)}
              onRecheck={() => runFullAudit(true)}
              rechecking={gw.refreshing}
              dataAgeMinutes={gw.dataAgeMinutes}
              showCoverage={false}
              onDismissHint={handleDismissHint}
            />
          </div>
          <div className="zs-stack" hidden={checksSubTab !== "guides"}>
            <GuidesScreen
              initialGuide={nav.guideTarget}
              navKey={nav.guideNavKey}
              currentIp={gw.currentIp}
              currentCountry={
                gw.currentCountry && gw.currentCountry !== "--"
                  ? gw.currentCountry
                  : gw.activeReport?.telemetry.country_code || "NL"
              }
              currentTimezone={gw.activeReport?.telemetry?.timezone}
              onPinIp={pinning.handlePinIp}
              onOpenPaymentTools={() => nav.push({ page: "clean-room", cleanRoomTab: "payment" })}
              onToast={showToast}
            />
          </div>
        </div>

        <div className="zs-stack" hidden={page !== "stats"}>
          <Stats>
            <Stat
              layer={1}
              value={stats.gatewayStats ? formatNumber(stats.gatewayStats.protected_ai_requests) : "—"}
              label={overviewCopy.stats.requests}
            />
            <Stat
              layer={1}
              tone={(stats.gatewayStats?.intercepted_leaks ?? 0) > 0 ? "danger" : "neutral"}
              value={stats.gatewayStats ? formatNumber(stats.gatewayStats.intercepted_leaks) : "—"}
              label={overviewCopy.stats.leaks}
            />
            <Stat
              layer={1}
              value={stats.gatewayStats ? formatNumber(stats.gatewayStats.direct_bypassed_requests) : "—"}
              label={overviewCopy.stats.direct}
            />
          </Stats>
        </div>
      </div>

      <NotificationStack toasts={toasts} onDismiss={dismissToast} />
      <AppShellDialogs ctrl={ctrl} />
    </div>
  );
}
