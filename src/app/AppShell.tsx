import { AppHeader, Banner, Button, Icon, Mono, TabPanel, Tabs, Tip, Toast, ToastViewport } from "../ui";
import { overview as overviewCopy, shell as copy, tabs as tabCopy } from "../shared/copy/ru";
import { formatCountryWithCode } from "../shared/lib/country";
import { formatIp } from "../shared/lib/format";
import { isTauri } from "../utils/api/client";
import { OverviewScreen } from "../features/overview/OverviewScreen";
import { ConnectScreen } from "../features/connect/ConnectScreen";
import { CopyErrorLogButton } from "../shared/components/CopyErrorLogButton";
import { BackupScreen } from "../features/backup";
import { ChecksScreen } from "../features/checks";
import { GuidesScreen } from "../features/guides";
import { SubscriptionScreen } from "../features/subscription";
import { AppShellDialogs } from "./AppShellDialogs";
import { useAppShellController } from "./useAppShellController";
import "./shell.css";

const TAB_PREFIX = "app";

/** Оболочка главного окна: шапка с меню «Ещё», вкладки, активный экран, футер и все общие диалоги. */
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
    pinning,
    tz,
    updater,
    hideIpMode,
    intercept,
    backup,
    tabItems,
    version,
    menuItems,
    handleToggleHideIp,
  } = ctrl;

  const { runFullAudit, refreshState } = gw;
  const payload = intercept.interceptPayload;

  return (
    <div className="zs-root zs-shell-page">
      <div className="zs-app zs-shell">
        <AppHeader
          ping={gw.activeReport ? copy.pingLabel(gw.scanLatencyMs) : undefined}
          menuItems={menuItems}
          menuLabel={copy.menuLabel}
          menuDot={Boolean(updater.updateInfo?.update_available)}
        >
          {updater.updateInfo?.update_available && (
            <Tip
              title={overviewCopy.banner.update.title(updater.updateInfo.latest_version)}
              text="Нажмите, чтобы посмотреть, что нового, и установить обновление."
            >
              <button
                type="button"
                className="zs-update-pill"
                onClick={() => updater.setShowUpdateModal(true)}
              >
                <Icon name="download" size={13} />
                Обновить
              </button>
            </Tip>
          )}
          <Button
            variant={hideIpMode ? "secondary" : "quiet"}
            size="sm"
            icon={hideIpMode ? "lock" : "globe"}
            className="zs-hide-ip-btn"
            aria-pressed={hideIpMode}
            title={hideIpMode ? copy.hideIp.hideTooltip : copy.hideIp.showTooltip}
            onClick={() => void handleToggleHideIp()}
          >
            {copy.hideIp.button}
          </Button>
        </AppHeader>

        {nav.subscriptionOpen ? (
          <div className="zs-stack">
            <div className="zs-shell__subhead">
              <Button variant="quiet" size="sm" onClick={nav.closeSubscription}>
                {copy.back}
              </Button>
              <h2 className="zs-t-heading">{copy.subscriptionTitle}</h2>
            </div>
            <SubscriptionScreen
              vpnCountry={gw.currentCountry}
              activeReport={gw.activeReport}
              state={gw.state}
              onStateChange={() => runFullAudit(false)}
              onNavigateToPaymentGuide={() => nav.openGuide("02-safe-payment-cards")}
              onToast={showToast}
            />
          </div>
        ) : (
          <>
            <Tabs
              items={tabItems}
              value={nav.tab}
              onChange={(id) => nav.goTab(id)}
              badgeLabel={tabCopy.badgeLabel}
              warnBadgeLabel={tabCopy.badgeLabelWarn}
              idPrefix={TAB_PREFIX}
              aria-label={tabCopy.label}
            />

            {gw.activeReport?.incomplete && nav.tab !== "overview" && (
              <Banner
                tone="neutral"
                title={overviewCopy.banner.incomplete.title}
                action={
                  <Button size="sm" onClick={() => runFullAudit(true)} disabled={gw.refreshing}>
                    {overviewCopy.banner.incomplete.action}
                  </Button>
                }
              >
                {overviewCopy.banner.incomplete.text}
              </Banner>
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

            {routeUnavailableBanner && (
              <Banner
                tone="danger"
                role="alert"
                title={`Маршрут для ${routeUnavailableBanner.provider.toUpperCase()} недоступен`}
                action={
                  <div className="zs-banner__actions">
                    <Button
                      size="sm"
                      onClick={() => {
                        nav.goTab("connect");
                        setRouteUnavailableBanner(null);
                      }}
                    >
                      Открыть подключение
                    </Button>
                    <CopyErrorLogButton
                      title={`Маршрут для ${routeUnavailableBanner.provider.toUpperCase()} недоступен`}
                      message={routeUnavailableBanner.message}
                      variant="secondary"
                    />
                    <Button size="sm" variant="quiet" onClick={() => setRouteUnavailableBanner(null)}>
                      {copy.intercept.dismiss}
                    </Button>
                  </div>
                }
              >
                {routeUnavailableBanner.message}
              </Banner>
            )}

            <TabPanel idPrefix={TAB_PREFIX} id="overview" selected={nav.tab === "overview"} className="zs-stack">
              <OverviewScreen
                reports={gw.reports}
                activeReport={gw.activeReport}
                state={gw.state}
                refreshing={gw.refreshing}
                auditError={gw.auditError}
                startupPending={gw.startupPending}
                partial={gw.partialAudit}
                currentIp={gw.currentIp}
                trustScore={gw.trustScore}
                gatewayStats={stats.gatewayStats}
                updateInfo={updater.updateInfo}
                coverageSnapshot={gw.coverageSnapshot}
                routesSnapshot={gw.routesSnapshot}
                hideIpMode={hideIpMode}
                dataAgeMinutes={gw.dataAgeMinutes}
                sysproxyActive={gw.sysproxyActive}
                cliProtected={toggles.cliProtected}
                killswitchFrozen={toggles.killswitchFrozen}
                onToggleSysproxy={toggles.handleToggleSysproxy}
                onToggleCli={toggles.handleToggleCliProtection}
                protection={toggles.protection}
                onToggleKillswitch={toggles.handleToggleKillswitch}
                onToast={showToast}
                onCopyIp={pinning.handleCopyIp}
                onPinIp={pinning.handlePinIp}
                onUnpinIp={pinning.handleUnpinIp}
                onToggleStrict={pinning.handleToggleStrict}
                onAllowProvider={pinning.handleAllowProvider}
                onUnblockProvider={pinning.handleUnblockProvider}
                onVerifyAndUnblockProvider={pinning.handleVerifyAndUnblockProvider}
                onRetry={() => runFullAudit(true)}
                onOpenChecks={() => nav.goTab("checks")}
                onFixService={(provider) => nav.goTab("checks", { provider })}
                onOpenTimezone={() => setTimezoneOpen(true)}
                onOpenUpdate={() => updater.setShowUpdateModal(true)}
                onOpenCrashTest={() => setCrashTestOpen(true)}
                onOpenConnect={() => nav.goTab("connect")}
              />
            </TabPanel>

            <TabPanel idPrefix={TAB_PREFIX} id="connect" selected={nav.tab === "connect"} className="zs-stack">
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
              />
            </TabPanel>

            <TabPanel idPrefix={TAB_PREFIX} id="checks" selected={nav.tab === "checks"}>
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
              />
            </TabPanel>

            <TabPanel idPrefix={TAB_PREFIX} id="backup" selected={nav.tab === "backup"}>
              <BackupScreen
                backup={backup}
                currentIp={gw.currentIp}
                currentCountry={gw.currentCountry}
                activeUpstreamKey={gw.state?.upstream_proxy?.raw_key}
                routesSnapshot={gw.routesSnapshot}
                profileRefreshTrigger={profileRefreshKey}
                onRoutesUpdated={() => gw.refreshRoutes()}
                onProfileSwitched={async () => {
                  await Promise.all([refreshState(), gw.refreshRoutes()]);
                  await runFullAudit(false);
                }}
                onToast={showToast}
              />
            </TabPanel>

            <TabPanel idPrefix={TAB_PREFIX} id="guides" selected={nav.tab === "guides"}>
              <GuidesScreen
                initialGuide={nav.guideTarget}
                currentIp={gw.currentIp}
                currentCountry={
                  gw.currentCountry && gw.currentCountry !== "--"
                    ? gw.currentCountry
                    : gw.activeReport?.telemetry.country_code || "NL"
                }
                currentTimezone={gw.activeReport?.telemetry?.timezone}
                onPinIp={pinning.handlePinIp}
                onToast={showToast}
              />
            </TabPanel>
          </>
        )}

        <footer className="zs-app__foot">
          <span>{copy.footer}</span>
          <Mono>v{version}</Mono>
        </footer>

        <ToastViewport>
          {toasts.map((t) => (
            <Toast
              key={t.id}
              tone={t.tone}
              title={t.title}
              duration={t.tone === "danger" ? undefined : 4500}
              action={t.tone === "danger" ? <CopyErrorLogButton title={t.title} message={t.description} variant="secondary" /> : undefined}
              onClose={() => dismissToast(t.id)}
            >
              {t.description}
            </Toast>
          ))}
        </ToastViewport>
      </div>

      <AppShellDialogs ctrl={ctrl} />
    </div>
  );
}
