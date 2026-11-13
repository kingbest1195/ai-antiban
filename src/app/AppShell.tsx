import { useEffect, useMemo, useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { AppHeader, Banner, Button, Mono, TabPanel, Tabs, Toast, ToastViewport } from "../ui";
import type { MenuEntry, TabItem } from "../ui";
import { overview as overviewCopy, shell as copy, tabs as tabCopy } from "../shared/copy/ru";
import { APP_VERSION } from "../shared/version";
import { tabBadges, useOverviewModel } from "../features/overview/useOverviewModel";
import { coverageNeedsAttention } from "../features/coverage/coverageModel";
import {
  useClaudeBackup,
  useGatewayState,
  useGatewayStats,
  useInterception,
  useMockScenario,
  useNavigation,
  usePinning,
  useProtectionToggles,
  useTimezoneSync,
  useToasts,
  useTrayEvents,
  useUpdater,
} from "../shared/hooks";
import type { TabId } from "../shared/hooks";
import type { RouteUnavailablePayload } from "../types";
import { openTelegramSupport } from "../utils/opener";
import { bindUpstreamToClaudeProfile, onRouteUnavailable, takePendingDeepLink, upsertRoute } from "../utils/api";
import { OverviewScreen } from "../features/overview/OverviewScreen";
import { ConnectScreen } from "../features/connect/ConnectScreen";
import { AlertOverlay } from "../features/alert";
import { OnboardingFlow, useOnboarding } from "../features/onboarding";
import { BackupScreen } from "../features/backup";
import { ChecksScreen } from "../features/checks";
import { CrashTestModal } from "../features/crash-test";
import { GuidesScreen } from "../features/guides";
import { SettingsModal } from "../features/settings";
import { SubscriptionScreen } from "../features/subscription";
import { AboutModal } from "./AboutModal";
import { DeepLinkModal } from "./DeepLinkModal";
import type { DeepLinkConfirmOptions } from "./DeepLinkModal";
import { EventsModal } from "./EventsModal";
import { TimezoneModal } from "./TimezoneModal";
import { UpdateModal } from "./UpdateModal";
import "./shell.css";

const TAB_ITEMS: TabItem<TabId>[] = [
  { id: "overview", label: tabCopy.overview },
  { id: "connect", label: tabCopy.connect },
  { id: "checks", label: tabCopy.checks },
  { id: "backup", label: tabCopy.backup },
  { id: "guides", label: tabCopy.guides },
];

/** Вкладки с бейджами: подмешивает их к неизменной основе. */
function withBadges(badges: ReturnType<typeof tabBadges>): TabItem<TabId>[] {
  return TAB_ITEMS.map((item) =>
    item.id === "overview" && badges.overview !== undefined
      ? { ...item, badge: badges.overview }
      : item.id === "checks" && badges.checks !== undefined
        ? { ...item, badge: badges.checks }
        : item,
  );
}

const TAB_PREFIX = "app";

/** Оболочка главного окна: шапка с меню «Ещё», вкладки, активный экран, футер и все общие диалоги. */
export function AppShell() {
  const nav = useNavigation();
  const onboarding = useOnboarding();
  const { toasts, showToast, dismissToast } = useToasts();

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [crashTestOpen, setCrashTestOpen] = useState(false);
  const [timezoneOpen, setTimezoneOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [eventsOpen, setEventsOpen] = useState(false);
  const [browserSimulation, setBrowserSimulation] = useState(false);
  const [pendingDeepLinkKey, setPendingDeepLinkKey] = useState<string | null>(null);
  const [submittingDeepLink, setSubmittingDeepLink] = useState(false);
  const [routeUnavailableBanner, setRouteUnavailableBanner] = useState<RouteUnavailablePayload | null>(null);

  // ---- Состояние и действия, вынесенные из старого Dashboard ----
  const stats = useGatewayStats(nav.tab === "overview" && !nav.subscriptionOpen);
  const gw = useGatewayState({ showToast, refreshGatewayStats: stats.refreshGatewayStats });
  const { runFullAudit, refreshState } = gw;
  const toggles = useProtectionToggles({
    sysproxyActive: gw.sysproxyActive,
    setSysproxyActive: gw.setSysproxyActive,
    showToast,
    startupPending: gw.startupPending,
  });
  const pinning = usePinning({
    state: gw.state,
    refreshState,
    runFullAudit,
    showToast,
    currentIp: gw.currentIp,
  });
  const tz = useTimezoneSync({ activeReport: gw.activeReport, runFullAudit, showToast });
  const updater = useUpdater({ showToast, setAutoUpdateEnabled: gw.setAutoUpdateEnabled });
  const intercept = useInterception({
    runFullAudit,
    showToast,
    onSimulateInBrowser: () => setBrowserSimulation(true),
  });
  const backup = useClaudeBackup(showToast);
  const overviewModel = useOverviewModel({
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
  // Жёлтая точка: защита включена и запуск закончен, но часть ИИ-приложений не покрыта (красное её перекрывает).
  const coverageNotice = !gw.startupPending && gw.sysproxyActive && coverageNeedsAttention(gw.coverageSnapshot);
  const tabItems = useMemo(
    () => withBadges(tabBadges(overviewModel.banner, gw.reports, gw.state, coverageNotice)),
    [overviewModel.banner, gw.reports, gw.state, coverageNotice],
  );
  const mock = useMockScenario(runFullAudit);

  useTrayEvents({
    showToast,
    openGuide: nav.openGuide,
    openBackup: () => nav.goTab("backup"),
    runFullAudit,
    refreshState,
    checkUpdates: updater.handleCheckUpdates,
    syncTimezone: () => tz.handleSyncTz(),
    exportClaude: backup.handleExportClaude,
    openCrashTest: () => setCrashTestOpen(true),
    setKillswitchFrozen: toggles.setKillswitchFrozen,
    setInterceptPayload: intercept.setInterceptPayload,
    applyUpdateProgress: updater.applyUpdateProgress,
    applyUpdateAvailable: updater.applyUpdateAvailable,
    applyUpdateStatus: updater.applyUpdateStatus,
  });

  // Ленивая загрузка вкладок: «Бэкап» сканирует ~/.claude, «Проверки» ждут первый отчёт.
  useEffect(() => {
    if (nav.tab === "backup" && !backup.claudeSummary) {
      backup.loadClaudeSummary();
    }
    if (nav.tab === "checks" && !gw.reports.anthropic && !gw.refreshing) {
      runFullAudit(true, true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nav.tab, backup.claudeSummary, gw.reports.anthropic, gw.refreshing]);

  // В Tauri версию отдаёт бэкенд; в браузере его ответ — мок, поэтому берём package.json.
  const version = (isTauri() && updater.updateInfo?.current_version) || APP_VERSION;

  useEffect(() => {
    takePendingDeepLink()
      .then((key) => {
        if (key) setPendingDeepLinkKey(key);
      })
      .catch((err) => {
        console.warn("Could not check pending deep link:", err);
      });

    let unlisten: (() => void) | undefined;
    if (isTauri()) {
      listen<string>("zastava://deep-link", (event) => {
        if (event.payload) {
          setPendingDeepLinkKey(event.payload);
        }
      })
        .then((fn) => {
          unlisten = fn;
        })
        .catch((err) => {
          console.warn("Failed to listen for deep link events:", err);
        });
    }

    const onHashChange = () => {
      takePendingDeepLink()
        .then((key) => {
          if (key) setPendingDeepLinkKey(key);
        })
        .catch(() => {});
    };
    if (typeof window !== "undefined") {
      window.addEventListener("hashchange", onHashChange);
    }

    return () => {
      unlisten?.();
      if (typeof window !== "undefined") {
        window.removeEventListener("hashchange", onHashChange);
      }
    };
  }, []);

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | undefined;
    onRouteUnavailable((info) => {
      if (!active) return;
      setRouteUnavailableBanner(info);
      showToast(
        `Маршрут недоступен (${info.provider.toUpperCase()})`,
        info.message || "Подключение через выбранный ключ остановлено для защиты IP.",
        "error",
      );
      gw.refreshRoutes().catch(() => {});
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleConfirmDeepLink = async ({ scope, profileId }: DeepLinkConfirmOptions) => {
    if (!pendingDeepLinkKey) return;
    const key = pendingDeepLinkKey;
    setSubmittingDeepLink(true);
    try {
      if (scope === "profile") {
        await bindUpstreamToClaudeProfile(profileId || "default", key);
        nav.goTab("backup");
        showToast("Ключ привязан к профилю", "Ключ Заставы привязан только к выбранному профилю Claude.", "success");
      } else {
        const setAsDefault = scope === "all";
        await upsertRoute(key, null, setAsDefault);
        nav.goTab("connect");
        showToast(
          "Ключ подключён",
          setAsDefault
            ? "Маршрут Заставы добавлен и назначен основным для всех ИИ-сервисов."
            : "Маршрут Заставы сохранён в списке без изменения текущего подключения.",
          "success",
        );
      }
      await gw.refreshRoutes();
      await refreshState();
      setPendingDeepLinkKey(null);
    } catch (err: any) {
      console.error("Failed to add deep-link route:", err);
      showToast("Ошибка подключения ключа", err?.message || String(err), "error");
    } finally {
      setSubmittingDeepLink(false);
    }
  };

  const handleCancelDeepLink = () => {
    setPendingDeepLinkKey(null);
  };

  const handleOpenSupport = async () => {
    showToast(copy.toast.supportTitle, copy.toast.supportText, "info");
    await openTelegramSupport();
  };

  const handleOpenOsClock = async () => {
    await tz.openOsClock();
    setTimezoneOpen(false);
    nav.openGuide("03-os-privacy-setup");
  };

  // ---- Меню «Ещё» ----
  const menuItems = useMemo<MenuEntry[]>(() => {
    const items: MenuEntry[] = [
      { id: "subscription", label: copy.menu.subscription, onSelect: nav.openSubscription },
      { id: "settings", label: copy.menu.settings, onSelect: () => setSettingsOpen(true) },
      { id: "sep-1", type: "separator" },
      { id: "events", label: copy.menu.events, onSelect: () => setEventsOpen(true) },
      {
        id: "rescan",
        label: copy.menu.rescan,
        disabled: gw.refreshing,
        onSelect: () => runFullAudit(true),
      },
      { id: "timezone", label: copy.menu.syncTimezone, onSelect: () => setTimezoneOpen(true) },
      {
        id: "updates",
        label: updater.checkingUpdate
          ? copy.menu.checkingUpdates
          : updater.updateInfo?.update_available
            ? copy.menu.updateTo(updater.updateInfo.latest_version)
            : copy.menu.checkUpdates,
        disabled: updater.checkingUpdate,
        onSelect: () => {
          if (updater.updateInfo?.update_available) updater.setShowUpdateModal(true);
          else updater.handleCheckUpdates(false);
        },
      },
      { id: "sep-2", type: "separator" },
      {
        id: "onboarding",
        label: copy.menu.onboarding,
        onSelect: onboarding.start,
      },
      { id: "support", label: copy.menu.support, onSelect: handleOpenSupport },
      { id: "about", label: copy.menu.about, onSelect: () => setAboutOpen(true) },
    ];
    if (!isTauri()) {
      items.push(
        { id: "sep-3", type: "separator" },
        {
          id: "sc-clean",
          label: copy.menu.scenarioNl,
          disabled: mock.scenario === "clean",
          onSelect: () => mock.handleSwitchScenario("clean"),
        },
        {
          id: "sc-turkey",
          label: copy.menu.scenarioTr,
          disabled: mock.scenario === "turkey",
          onSelect: () => mock.handleSwitchScenario("turkey"),
        },
        {
          id: "sc-ru",
          label: copy.menu.scenarioRu,
          disabled: mock.scenario === "ru",
          onSelect: () => mock.handleSwitchScenario("ru"),
        },
      );
    }
    return items;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gw.refreshing, updater.checkingUpdate, updater.updateInfo, mock.scenario, runFullAudit, nav.openSubscription, onboarding.start]);

  const payload = intercept.interceptPayload;

  return (
    <div className="zs-root zs-shell-page">
      <div className="zs-app zs-shell">
        <AppHeader ping={gw.activeReport ? copy.pingLabel(gw.scanLatencyMs) : undefined} menuItems={menuItems} menuLabel={copy.menuLabel} />

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

            {/* Отчёт неполный: на «Обзоре» то же говорит его собственный баннер, поэтому там не дублируем */}
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

            {/* Перехват запроса в главном окне (Tauri): неблокирующий баннер */}
            {isTauri() && payload && (
              <Banner
                tone="danger"
                role="alert"
                title={copy.intercept.title(payload.provider.toUpperCase())}
                action={
                  <>
                    <Button size="sm" disabled={payload.phase !== "ready"} onClick={intercept.handleAllowInterception}>
                      {copy.intercept.allow}
                    </Button>{" "}
                    <Button size="sm" variant="quiet" onClick={() => intercept.setInterceptPayload(null)}>
                      {copy.intercept.dismiss}
                    </Button>
                  </>
                }
              >
                {intercept.allowError ??
                  (payload.network_change?.new_country === "RU"
                    ? copy.intercept.ruText
                    : copy.intercept.ipText(
                        payload.report?.telemetry?.ip || "--",
                        payload.report?.telemetry?.country_code || "--",
                      ))}
              </Banner>
            )}

            {routeUnavailableBanner && (
              <Banner
                tone="danger"
                role="alert"
                title={`Маршрут для ${routeUnavailableBanner.provider.toUpperCase()} недоступен`}
                action={
                  <>
                    <Button
                      size="sm"
                      onClick={() => {
                        nav.goTab("connect");
                        setRouteUnavailableBanner(null);
                      }}
                    >
                      Открыть подключение
                    </Button>{" "}
                    <Button size="sm" variant="quiet" onClick={() => setRouteUnavailableBanner(null)}>
                      {copy.intercept.dismiss}
                    </Button>
                  </>
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
                onRefreshState={refreshState}
                onRefreshRoutes={gw.refreshRoutes}
                onAuditRefresh={() => runFullAudit(true)}
                onOpenGuide={nav.openGuide}
                onToast={showToast}
              />
            </TabPanel>

            <TabPanel idPrefix={TAB_PREFIX} id="checks" selected={nav.tab === "checks"}>
              <ChecksScreen
                report={(nav.checksProvider && gw.reports[nav.checksProvider]) || gw.checksReport}
                partial={gw.partialAudit}
                auditError={gw.auditError}
                startupPending={gw.startupPending}
                provider={nav.checksProvider && gw.reports[nav.checksProvider] ? nav.checksProvider : undefined}
                state={gw.state}
                coverageSnapshot={gw.coverageSnapshot}
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
                onRoutesUpdated={() => gw.refreshRoutes()}
                onProfileSwitched={(_name, pin) => {
                  if (pin) pinning.handlePinIp(pin);
                  else runFullAudit(false);
                }}
                onToast={showToast}
              />
            </TabPanel>

            <TabPanel idPrefix={TAB_PREFIX} id="guides" selected={nav.tab === "guides"}>
              <GuidesScreen
                initialGuide={nav.guideTarget}
                currentIp={gw.currentIp}
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

        {/* Уведомления */}
        <ToastViewport>
          {toasts.map((t) => (
            <Toast key={t.id} tone={t.tone} title={t.title} duration={3500} onClose={() => dismissToast(t.id)}>
              {t.description}
            </Toast>
          ))}
        </ToastViewport>
      </div>

      {/* Диалоги */}
      <SettingsModal
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        autoUpdateEnabled={gw.autoUpdateEnabled}
        onToggleAutoUpdate={updater.handleToggleAutoUpdate}
        interceptionBehavior={gw.state?.interception_behavior}
        popupPosition={gw.state?.popup_position}
        customAiDomains={gw.state?.custom_ai_domains}
        onStateUpdated={() => refreshState().catch(() => {})}
        onToast={showToast}
      />
      <CrashTestModal open={crashTestOpen} onClose={() => setCrashTestOpen(false)} onToast={showToast} />
      <TimezoneModal
        open={timezoneOpen}
        onClose={() => setTimezoneOpen(false)}
        syncing={tz.syncingTz}
        synced={tz.tzSyncedNotice}
        onSync={() => tz.handleSyncTz()}
        onOpenOsClock={handleOpenOsClock}
      />
      <UpdateModal
        open={updater.showUpdateModal}
        onClose={() => updater.setShowUpdateModal(false)}
        info={updater.updateInfo}
        installing={updater.installingUpdate}
        progress={updater.updateProgress}
        status={updater.updaterStatus}
        onInstall={updater.handleInstallUpdate}
      />
      <AboutModal open={aboutOpen} onClose={() => setAboutOpen(false)} version={version} onSupport={handleOpenSupport} />
      <EventsModal open={eventsOpen} onClose={() => setEventsOpen(false)} stats={stats.gatewayStats} />
      <DeepLinkModal
        deepLinkKey={pendingDeepLinkKey}
        onClose={handleCancelDeepLink}
        onConfirm={handleConfirmDeepLink}
        submitting={submittingDeepLink}
      />

      {/* Знакомство с Заставой: первый запуск новой версии или «Ещё» → «Пройти знакомство заново» */}
      {onboarding.open && (
        <OnboardingFlow
          key={onboarding.run}
          initialStep={onboarding.initialStep}
          reports={gw.reports}
          activeReport={gw.activeReport}
          refreshing={gw.refreshing}
          auditError={gw.auditError}
          currentIp={gw.currentIp}
          trustScore={gw.trustScore}
          sysproxyActive={gw.sysproxyActive}
          cliProtected={toggles.cliProtected}
          onToggleSysproxy={toggles.handleToggleSysproxy}
          onToggleCli={() => toggles.handleToggleCliProtection({ quiet: true })}
          onRecheck={() => runFullAudit(true, true)}
          onClose={(to) => {
            onboarding.finish();
            if (to) nav.goTab(to);
          }}
        />
      )}

      {/* Превью диалога обрыва в браузере (без Tauri) */}
      {!isTauri() && (browserSimulation || payload) && (
        <AlertOverlay
          initialPayload={payload ?? undefined}
          onResolved={() => {
            const hadPayload = Boolean(payload);
            setBrowserSimulation(false);
            if (hadPayload) {
              intercept.setInterceptPayload(null);
              runFullAudit(false);
            }
          }}
        />
      )}
    </div>
  );
}
