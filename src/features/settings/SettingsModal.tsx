import type {
  InterceptionBehavior,
  PopupPosition,
  RollbackReleaseInfo,
  UpdateProgressPayload,
  UpdateStatusPayload,
} from "../../types";
import type { ShowToast } from "../../shared/hooks";
import { APP_VERSION } from "../../shared/version";
import { Button, ConfirmModal, Modal } from "../../ui";
import { settings as copy } from "../../shared/copy/ru";
import { BehaviorSection } from "./sections/BehaviorSection";
import { MonitoringSection } from "./sections/MonitoringSection";
import { SystemGuardSection } from "./sections/SystemGuardSection";
import { TerminalSection } from "./sections/TerminalSection";
import { UpdatesSection } from "./sections/UpdatesSection";
import { useSettingsController } from "./useSettingsController";

import "./settings.css";

export interface SettingsModalProps {
  open: boolean;
  onClose: () => void;
  autoUpdateEnabled: boolean;
  onToggleAutoUpdate: (enabled: boolean) => Promise<void>;
  interceptionBehavior?: InterceptionBehavior;
  popupPosition?: PopupPosition;
  customAiDomains?: string[];
  disabledProviders?: string[];
  trustedExceptions?: Record<string, string[]>;
  onStateUpdated?: () => Promise<unknown> | void;
  onToast?: ShowToast;
  appVersion?: string;
  rollbackReleases?: RollbackReleaseInfo[];
  rollbackLoading?: boolean;
  rollbackLoaded?: boolean;
  rollbackError?: string | null;
  rollingBackVersion?: string | null;
  installingUpdate?: boolean;
  updateProgress?: UpdateProgressPayload | null;
  updaterStatus?: UpdateStatusPayload | null;
  onLoadRollbackVersions?: () => Promise<void>;
  onInstallRollback?: (version: string) => Promise<void>;
}

/** Настройки: поведение при обрыве VPN, домены ИИ, автообновление, приватность, сброс системного прокси. */
export function SettingsModal({
  open,
  onClose,
  autoUpdateEnabled,
  onToggleAutoUpdate,
  interceptionBehavior: propBehavior,
  popupPosition: propPosition,
  customAiDomains: propCustomDomains,
  disabledProviders: propDisabledProviders,
  trustedExceptions: propTrustedExceptions,
  onStateUpdated,
  onToast,
  appVersion = APP_VERSION,
  rollbackReleases = [],
  rollbackLoading = false,
  rollbackLoaded = false,
  rollbackError = null,
  rollingBackVersion = null,
  installingUpdate = false,
  updateProgress = null,
  updaterStatus = null,
  onLoadRollbackVersions,
  onInstallRollback,
}: SettingsModalProps) {
  const ctrl = useSettingsController({
    open,
    autoUpdateEnabled,
    onToggleAutoUpdate,
    propBehavior,
    propPosition,
    propCustomDomains,
    propDisabledProviders,
    propTrustedExceptions,
    onStateUpdated,
    onToast,
    rollbackLoaded,
    rollbackLoading,
    onLoadRollbackVersions,
  });

  return (
    <>
      <Modal
        open={open}
        onClose={onClose}
        title={copy.title}
        footer={<Button onClick={onClose}>{copy.close}</Button>}
      >
        <div className="zs-settings">
          <BehaviorSection
            behavior={ctrl.behavior}
            position={ctrl.position}
            splitTunnelMode={ctrl.splitTunnelMode}
            splitTunnelBusy={ctrl.splitTunnelBusy}
            onBehaviorChange={ctrl.handleBehaviorChange}
            onPositionChange={ctrl.handlePositionChange}
            onToggleSplitTunnel={ctrl.handleToggleSplitTunnel}
          />

          <TerminalSection
            cliMode={ctrl.cliMode}
            syncTz={ctrl.syncTz}
            terminalBusy={ctrl.terminalBusy}
            osTzStatus={ctrl.osTz.osTzStatus}
            osTzLoading={ctrl.osTz.osTzLoading}
            osTzError={ctrl.osTz.osTzError}
            onCliModeChange={ctrl.handleCliModeChange}
            onToggleSyncTz={ctrl.handleToggleSyncTz}
            onSyncOsTimezone={ctrl.osTz.syncOsTimezone}
            onRestoreOsTimezone={ctrl.osTz.restoreOsTimezone}
          />

          <MonitoringSection
            disabledSet={ctrl.disabledSet}
            monitoringBusy={ctrl.monitoringBusy}
            exceptionEntries={ctrl.exceptionEntries}
            exceptionsBusy={ctrl.exceptionsBusy}
            customDomains={ctrl.customDomains}
            newDomainInput={ctrl.newDomainInput}
            domainBusy={ctrl.domainBusy}
            providerLabel={ctrl.providerLabel}
            onToggleProviderMonitoring={ctrl.handleToggleProviderMonitoring}
            onRemoveTrustedException={ctrl.handleRemoveTrustedException}
            onClearTrustedExceptions={ctrl.handleClearTrustedExceptions}
            onNewDomainInputChange={ctrl.setNewDomainInput}
            onAddDomain={ctrl.handleAddDomain}
            onRemoveDomain={ctrl.handleRemoveDomain}
          />

          <UpdatesSection
            appVersion={appVersion}
            autoUpdateEnabled={autoUpdateEnabled}
            updatingToggle={ctrl.updatingToggle}
            onToggleAutoUpdate={ctrl.handleToggleAutoUpdate}
            rollbackReleases={rollbackReleases}
            rollbackLoading={rollbackLoading}
            rollbackLoaded={rollbackLoaded}
            rollbackError={rollbackError}
            rollingBackVersion={rollingBackVersion}
            installingUpdate={installingUpdate}
            updateProgress={updateProgress}
            updaterStatus={updaterStatus}
            confirmRollbackVersion={ctrl.confirmRollbackVersion}
            setConfirmRollbackVersion={ctrl.setConfirmRollbackVersion}
            onLoadRollbackVersions={onLoadRollbackVersions}
            onInstallRollback={onInstallRollback}
            autostartStatus={ctrl.autostartStatus}
            autostartBusy={ctrl.autostartBusy}
            onToggleAutostart={ctrl.handleToggleAutostart}
          />

          <SystemGuardSection
            coworkStatus={ctrl.coworkStatus}
            coworkBusy={ctrl.coworkBusy}
            onInstallCoworkGuard={ctrl.handleInstallCoworkGuard}
            onRefreshCoworkGuard={ctrl.handleRefreshCoworkGuard}
            exportBusy={ctrl.exportBusy}
            onExportDiagnostics={ctrl.handleExportDiagnostics}
            previewItems={ctrl.previewItems}
            previewLoading={ctrl.previewLoading}
            previewError={ctrl.previewError}
            previewOpen={ctrl.previewOpen}
            onTogglePreview={() => ctrl.setPreviewOpen((v) => !v)}
            cleaningProxy={ctrl.cleaningProxy}
            proxyResult={ctrl.proxyResult}
            onRequestCleanProxy={() => ctrl.setConfirmProxy(true)}
          />
        </div>
      </Modal>

      <ConfirmModal
        open={open && ctrl.confirmGlobal}
        title={copy.terminal.mode.confirmTitle}
        confirmLabel={copy.terminal.mode.confirmAction}
        busy={ctrl.terminalBusy}
        onConfirm={async () => {
          await ctrl.applyCliMode("global_terminal");
          ctrl.setConfirmGlobal(false);
        }}
        onCancel={() => ctrl.setConfirmGlobal(false)}
      >
        {copy.terminal.mode.confirmText}
      </ConfirmModal>

      <ConfirmModal
        open={open && ctrl.confirmProxy}
        title={copy.proxy.confirmTitle}
        confirmLabel={copy.proxy.confirmAction}
        busy={ctrl.cleaningProxy}
        busyLabel={copy.proxy.working}
        onConfirm={ctrl.handleCleanOsProxy}
        onCancel={() => ctrl.setConfirmProxy(false)}
      >
        {copy.proxy.confirmText}
      </ConfirmModal>
    </>
  );
}
