import { useEffect, useMemo, useRef, useState } from "react";
import type { MenuEntry } from "../ui";
import { shell as copy, toast as toastCopy } from "../shared/copy/ru";
import { APP_VERSION } from "../shared/version";
import { useCoworkGuardWatcher } from "../shared/hooks/useCoworkGuardWatcher";
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
import type { PersonaRiskReport, RouteUnavailablePayload, ShutdownProgressPayload } from "../types";
import { openTelegramSupport } from "../utils/opener";
import {
  bindUpstreamToClaudeProfile,
  dismissHint,
  getHideIpMode,
  getPersonaRiskReport,
  markWhatsNewV3Seen,
  onDeepLink,
  onOpenPaymentCheck,
  onRouteUnavailable,
  onShutdownProgress,
  setHideIpMode,
  takePendingDeepLink,
  upsertRoute,
} from "../utils/api";
import { isTauri } from "../utils/api/client";
import { useOnboarding } from "../features/onboarding";
import type { OnboardingGoal } from "../features/onboarding";
import type { DeepLinkConfirmOptions } from "./DeepLinkModal";

export function useAppShellController() {
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
  const [shutdownProgress, setShutdownProgress] = useState<ShutdownProgressPayload | null>(null);
  const [hideIpPref, setHideIpPref] = useState<boolean>(false);
  const [profileRefreshKey, setProfileRefreshKey] = useState(0);
  const [personaRisk, setPersonaRisk] = useState<PersonaRiskReport | null>(null);
  const [whatsNewBusy, setWhatsNewBusy] = useState(false);
  const checksAuditAttemptedRef = useRef(false);

  const coworkGuard = useCoworkGuardWatcher();
  const stats = useGatewayStats(nav.currentRoute.page === "home" || nav.currentRoute.page === "stats");
  const gw = useGatewayState({ showToast, refreshGatewayStats: stats.refreshGatewayStats });
  const { runFullAudit, refreshState } = gw;
  const toggles = useProtectionToggles({
    sysproxyActive: gw.sysproxyActive,
    setSysproxyActive: gw.setSysproxyActive,
    showToast,
    startupPending: gw.startupPending,
  });
  const hideIpMode = gw.state?.hide_ip_mode ?? hideIpPref;
  const pinning = usePinning({
    state: gw.state,
    refreshState,
    runFullAudit,
    showToast,
    currentIp: gw.currentIp,
    hideIpMode,
  });
  const tz = useTimezoneSync({ activeReport: gw.activeReport, runFullAudit, showToast });
  const updater = useUpdater({ showToast, setAutoUpdateEnabled: gw.setAutoUpdateEnabled });
  const intercept = useInterception({
    runFullAudit,
    showToast,
    onSimulateInBrowser: () => setBrowserSimulation(true),
  });
  const backup = useClaudeBackup(showToast);
  const mock = useMockScenario(runFullAudit);

  useTrayEvents({
    showToast,
    openGuide: nav.openGuide,
    openBackup: () => nav.push({ page: "backup" }),
    runFullAudit,
    refreshState,
    refreshRoutes: gw.refreshRoutes,
    syncProtectionStatus: toggles.syncProtectionStatus,
    refreshProfiles: () => setProfileRefreshKey((n) => n + 1),
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

  useEffect(() => {
    if (nav.currentRoute.page === "backup" && !backup.claudeSummary) {
      backup.loadClaudeSummary();
    }
    if (nav.currentRoute.page !== "checks") {
      checksAuditAttemptedRef.current = false;
    } else if (!gw.reports.anthropic && !gw.refreshing && !gw.auditError && !checksAuditAttemptedRef.current) {
      checksAuditAttemptedRef.current = true;
      runFullAudit(true, true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nav.currentRoute.page, backup.claudeSummary, gw.reports.anthropic, gw.refreshing, gw.auditError]);

  useEffect(() => {
    if (gw.startupPending) return;
    getPersonaRiskReport()
      .then(setPersonaRisk)
      .catch(() => {});
  }, [
    gw.startupPending,
    gw.state?.ip_change_cooldown_until,
    gw.state?.pinned_ip,
    gw.state?.sync_ai_tz_enabled,
    gw.activeReport?.telemetry?.ip,
    nav.currentRoute.page,
  ]);

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
    onDeepLink((link) => {
      if (link) setPendingDeepLinkKey(link);
    })
      .then((fn) => {
        unlisten = fn;
      })
      .catch((err) => {
        console.warn("Failed to listen for deep link events:", err);
      });

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

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | undefined;
    getHideIpMode()
      .then((enabled) => {
        if (active) setHideIpPref(enabled);
      })
      .catch(() => {});

    onShutdownProgress((payload) => {
      if (active) setShutdownProgress(payload);
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
  }, []);

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | undefined;
    onOpenPaymentCheck((domain) => {
      if (!active) return;
      nav.push({ page: "clean-room", cleanRoomTab: "payment" });
      if (domain) {
        showToast("Проверка оплаты", `Домен ${domain} приостановлен для проверки готовности.`, "info");
      }
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

  useEffect(() => {
    if (updater.updaterStatus?.stage === "failed") {
      setShutdownProgress(null);
    }
  }, [updater.updaterStatus?.stage]);

  const handleToggleHideIp = async () => {
    const next = !hideIpMode;
    setHideIpPref(next);
    try {
      await setHideIpMode(next);
      await refreshState();
      showToast(next ? copy.hideIp.onToast : copy.hideIp.offToast, undefined, "info");
    } catch (err: unknown) {
      setHideIpPref(!next);
      showToast(toastCopy.genericError, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const handleConfirmDeepLink = async ({ scope, profileId }: DeepLinkConfirmOptions) => {
    if (!pendingDeepLinkKey) return;
    const key = pendingDeepLinkKey;
    setSubmittingDeepLink(true);
    try {
      if (scope === "profile") {
        await bindUpstreamToClaudeProfile(profileId || "default", key);
        nav.goTab("backup");
        showToast("ВПН привязан к профилю", "ВПН Заставы привязан только к выбранному профилю Claude.", "success");
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

  const handleCancelDeepLink = () => setPendingDeepLinkKey(null);

  const handleOpenSupport = async () => {
    showToast(copy.toast.supportTitle, copy.toast.supportText, "info");
    await openTelegramSupport();
  };

  const handleOpenOsClock = async () => {
    await tz.openOsClock();
    setTimezoneOpen(false);
    nav.openGuide("03-os-privacy-setup");
  };

  const handleAcknowledgeWhatsNew = async () => {
    setWhatsNewBusy(true);
    try {
      await markWhatsNewV3Seen();
      await refreshState();
    } catch {
      // ignore
    } finally {
      setWhatsNewBusy(false);
    }
  };

  const handleRestartOnboardingFromWhatsNew = async () => {
    await handleAcknowledgeWhatsNew();
    onboarding.start();
  };

  const handleDismissHint = async (hintId: string) => {
    try {
      await dismissHint(hintId);
      await refreshState();
    } catch {
      // ignore
    }
  };

  const handleOnboardingGoal = (goal?: OnboardingGoal) => {
    if (goal === "clean_room") {
      nav.reset({ page: "clean-room", cleanRoomTab: "launchpad" });
    } else if (goal === "sos") {
      nav.reset({ page: "backup" });
    } else {
      nav.goHome();
    }
  };

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
        badge: updater.updateInfo?.update_available ? "Доступно" : undefined,
        disabled: updater.checkingUpdate,
        onSelect: () => {
          if (updater.updateInfo?.update_available) updater.setShowUpdateModal(true);
          else updater.handleCheckUpdates(false);
        },
      },
      { id: "sep-2", type: "separator" },
      { id: "onboarding", label: copy.menu.onboarding, onSelect: onboarding.start },
      { id: "support", label: copy.menu.support, onSelect: handleOpenSupport },
      { id: "about", label: copy.menu.about, onSelect: () => setAboutOpen(true) },
    ];
    if (!isTauri()) {
      items.push(
        { id: "sep-3", type: "separator" },
        { id: "sc-clean", label: copy.menu.scenarioNl, disabled: mock.scenario === "clean", onSelect: () => mock.handleSwitchScenario("clean") },
        { id: "sc-turkey", label: copy.menu.scenarioTr, disabled: mock.scenario === "turkey", onSelect: () => mock.handleSwitchScenario("turkey") },
        { id: "sc-ru", label: copy.menu.scenarioRu, disabled: mock.scenario === "ru", onSelect: () => mock.handleSwitchScenario("ru") },
      );
    }
    return items;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gw.refreshing, updater.checkingUpdate, updater.updateInfo, mock.scenario, runFullAudit, nav.openSubscription, onboarding.start]);

  return {
    nav,
    onboarding,
    toasts,
    showToast,
    dismissToast,
    settingsOpen,
    setSettingsOpen,
    crashTestOpen,
    setCrashTestOpen,
    timezoneOpen,
    setTimezoneOpen,
    aboutOpen,
    setAboutOpen,
    eventsOpen,
    setEventsOpen,
    browserSimulation,
    setBrowserSimulation,
    pendingDeepLinkKey,
    submittingDeepLink,
    routeUnavailableBanner,
    setRouteUnavailableBanner,
    shutdownProgress,
    profileRefreshKey,
    stats,
    gw,
    toggles,
    coworkGuard,
    personaRisk,
    whatsNewBusy,
    pinning,
    tz,
    updater,
    hideIpMode,
    intercept,
    backup,
    version,
    menuItems,
    handleToggleHideIp,
    handleConfirmDeepLink,
    handleCancelDeepLink,
    handleOpenSupport,
    handleOpenOsClock,
    handleAcknowledgeWhatsNew,
    handleRestartOnboardingFromWhatsNew,
    handleDismissHint,
    handleOnboardingGoal,
  };
}
