import { isTauri } from "../utils/api/client";
import { AlertOverlay } from "../features/alert";
import { CrashTestModal } from "../features/crash-test";
import { hasBrowserTraffic } from "../features/coverage/coverageModel";
import { OnboardingFlow } from "../features/onboarding";
import { SettingsModal } from "../features/settings";
import { WhatsNewSheet, shouldShowWhatsNew } from "../features/shell-v3";
import { AboutModal } from "./AboutModal";
import { DeepLinkModal } from "./DeepLinkModal";
import { EventsModal } from "./EventsModal";
import { ShutdownOverlay } from "./ShutdownOverlay";
import { TimezoneModal } from "./TimezoneModal";
import { UpdateModal } from "./UpdateModal";
import type { useAppShellController } from "./useAppShellController";

interface AppShellDialogsProps {
  ctrl: ReturnType<typeof useAppShellController>;
}

/** Завершает онбординг и только после записи в state.json обновляет состояние оболочки. */
export async function completeAndRefreshOnboarding(
  finish: () => Promise<unknown> | void,
  refreshState: () => Promise<unknown>,
): Promise<void> {
  await finish();
  await refreshState().catch(() => {});
}

export function AppShellDialogs({ ctrl }: AppShellDialogsProps) {
  const {
    nav,
    onboarding,
    showToast,
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
    shutdownProgress,
    stats,
    gw,
    toggles,
    tz,
    updater,
    intercept,
    version,
    whatsNewBusy,
    handleConfirmDeepLink,
    handleCancelDeepLink,
    handleOpenSupport,
    handleOpenOsClock,
    handleAcknowledgeWhatsNew,
    handleRestartOnboardingFromWhatsNew,
    handleOnboardingGoal,
  } = ctrl;
  const payload = intercept.interceptPayload;

  return (
    <>
      <SettingsModal
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        autoUpdateEnabled={gw.autoUpdateEnabled}
        onToggleAutoUpdate={updater.handleToggleAutoUpdate}
        interceptionBehavior={gw.state?.interception_behavior}
        popupPosition={gw.state?.popup_position}
        customAiDomains={gw.state?.custom_ai_domains}
        disabledProviders={gw.state?.disabled_providers}
        trustedExceptions={gw.state?.trusted_exceptions}
        onStateUpdated={() => gw.refreshState().catch(() => {})}
        onToast={showToast}
        appVersion={version}
        rollbackReleases={updater.rollbackReleases}
        rollbackLoading={updater.rollbackLoading}
        rollbackLoaded={updater.rollbackLoaded}
        rollbackError={updater.rollbackError}
        rollingBackVersion={updater.rollingBackVersion}
        installingUpdate={updater.installingUpdate}
        updateProgress={updater.updateProgress}
        updaterStatus={updater.updaterStatus}
        onLoadRollbackVersions={updater.handleLoadRollbackVersions}
        onInstallRollback={updater.handleInstallRollback}
        onReplayOnboarding={onboarding.start}
      />
      <CrashTestModal open={crashTestOpen} onClose={() => setCrashTestOpen(false)} onToast={showToast} />
      <TimezoneModal
        open={timezoneOpen}
        onClose={() => setTimezoneOpen(false)}
        syncing={tz.syncingTz}
        synced={tz.tzSyncedNotice}
        onSync={() => tz.handleSyncTz()}
        onOpenOsClock={handleOpenOsClock}
        hasBrowserTraffic={hasBrowserTraffic(gw.coverageSnapshot?.apps)}
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
          onRecheck={() => gw.runFullAudit(true, true)}
          onComplete={handleOnboardingGoal}
          onClose={async (to) => {
            if (to && to !== "overview") nav.goTab(to);
            await completeAndRefreshOnboarding(onboarding.finish, gw.refreshState);
          }}
        />
      )}

      <WhatsNewSheet
        open={shouldShowWhatsNew(gw.state) && !onboarding.open}
        busy={whatsNewBusy}
        onAcknowledge={() => void handleAcknowledgeWhatsNew()}
        onRestartOnboarding={() => void handleRestartOnboardingFromWhatsNew()}
      />

      {!isTauri() && (browserSimulation || payload) && (
        <AlertOverlay
          initialPayload={payload ?? undefined}
          onResolved={() => {
            const hadPayload = Boolean(payload);
            setBrowserSimulation(false);
            if (hadPayload) {
              intercept.setInterceptPayload(null);
              gw.runFullAudit(false);
            }
          }}
        />
      )}

      <ShutdownOverlay progress={shutdownProgress} />
    </>
  );
}
