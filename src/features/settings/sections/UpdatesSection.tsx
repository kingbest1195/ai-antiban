import type {
  AutostartStatus,
  RollbackReleaseInfo,
  UpdateProgressPayload,
  UpdateStatusPayload,
} from "../../../types";
import { openExternal } from "../../../utils/opener";
import { Banner, Button, Mono, Progress, Row, Rows, Section, Switch } from "../../../ui";
import { settings as copy } from "../../../shared/copy/ru";

interface UpdatesSectionProps {
  appVersion: string;
  autoUpdateEnabled: boolean;
  updatingToggle: boolean;
  onToggleAutoUpdate: () => void;
  rollbackReleases: RollbackReleaseInfo[];
  rollbackLoading: boolean;
  rollbackLoaded: boolean;
  rollbackError: string | null;
  rollingBackVersion: string | null;
  installingUpdate: boolean;
  updateProgress: UpdateProgressPayload | null;
  updaterStatus: UpdateStatusPayload | null;
  confirmRollbackVersion: string | null;
  setConfirmRollbackVersion: (version: string | null) => void;
  onLoadRollbackVersions?: () => Promise<void>;
  onInstallRollback?: (version: string) => Promise<void>;
  autostartStatus: AutostartStatus | null;
  autostartBusy: boolean;
  onToggleAutostart: () => void;
}

const formatReleaseDate = (iso: string | null) => {
  if (!iso) return "";
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleDateString("ru-RU", { day: "numeric", month: "short", year: "numeric" });
};

export function UpdatesSection({
  appVersion,
  autoUpdateEnabled,
  updatingToggle,
  onToggleAutoUpdate,
  rollbackReleases,
  rollbackLoading,
  rollbackLoaded,
  rollbackError,
  rollingBackVersion,
  installingUpdate,
  updateProgress,
  updaterStatus,
  confirmRollbackVersion,
  setConfirmRollbackVersion,
  onLoadRollbackVersions,
  onInstallRollback,
  autostartStatus,
  autostartBusy,
  onToggleAutostart,
}: UpdatesSectionProps) {
  return (
    <>
      <Section title={copy.updates.section}>
        <Rows>
          <Row
            icon="refresh"
            title={copy.updates.title}
            sub={autoUpdateEnabled ? copy.updates.on : copy.updates.off}
            trail={
              <Switch
                checked={autoUpdateEnabled}
                disabled={updatingToggle}
                onChange={onToggleAutoUpdate}
                aria-label={copy.updates.label}
              />
            }
          />
        </Rows>
      </Section>

      <Section title={copy.rollback.section}>
        <Rows>
          <Row
            icon="info"
            title={
              <>
                {copy.rollback.currentTitle}: <Mono>v{appVersion}</Mono>
              </>
            }
            sub={copy.rollback.currentSub}
            trail={
              onLoadRollbackVersions ? (
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={rollbackLoading || installingUpdate}
                  onClick={() => {
                    setConfirmRollbackVersion(null);
                    void onLoadRollbackVersions();
                  }}
                >
                  {rollbackLoading
                    ? copy.rollback.loadingAction
                    : rollbackLoaded
                      ? copy.rollback.refreshAction
                      : copy.rollback.loadAction}
                </Button>
              ) : undefined
            }
          />
        </Rows>

        {installingUpdate && rollingBackVersion && (
          <div className="zs-settings__rows">
            <Progress
              label={
                updaterStatus?.message ||
                updateProgress?.phase ||
                copy.rollback.installing(rollingBackVersion)
              }
              value={updateProgress && updateProgress.total_bytes > 0 ? updateProgress.percent : undefined}
            />
          </div>
        )}

        {rollbackError && (
          <div className="zs-settings__result">
            <Banner tone="warn" title={copy.rollback.errorTitle}>
              {rollbackError}
            </Banner>
          </div>
        )}

        {rollbackLoading && rollbackReleases.length === 0 && (
          <p className="zs-settings__hint">{copy.rollback.loading}</p>
        )}

        {rollbackLoaded && !rollbackLoading && rollbackReleases.length === 0 && !rollbackError && (
          <p className="zs-settings__empty">{copy.rollback.empty}</p>
        )}

        {rollbackReleases.length > 0 && (
          <Rows className="zs-settings__rows">
            {rollbackReleases.map((rel) => {
              const isConfirming = confirmRollbackVersion === rel.version;
              const isActiveRollback = installingUpdate && rollingBackVersion === rel.version;
              const dateLabel = formatReleaseDate(rel.published_at);
              const subParts = [dateLabel, rel.name && rel.name !== rel.tag ? rel.name : null].filter(Boolean);
              return (
                <Row
                  key={rel.version}
                  icon="refresh"
                  title={
                    <span className="zs-settings__rollback-title">
                      <Mono>{rel.tag || `v${rel.version}`}</Mono>
                      {rel.notes_url && (
                        <Button size="sm" variant="quiet" onClick={() => openExternal(rel.notes_url!)}>
                          {copy.rollback.releaseNotes}
                        </Button>
                      )}
                    </span>
                  }
                  sub={isConfirming ? copy.rollback.confirmQuestion(rel.version) : subParts.join(" · ") || undefined}
                  trail={
                    isConfirming ? (
                      <div className="zs-settings__rollback-actions">
                        <Button
                          size="sm"
                          variant="primary"
                          disabled={installingUpdate}
                          onClick={() => {
                            if (!onInstallRollback) return;
                            setConfirmRollbackVersion(null);
                            void onInstallRollback(rel.version);
                          }}
                        >
                          {isActiveRollback
                            ? copy.rollback.installing(rel.version)
                            : copy.rollback.confirmAction(rel.version)}
                        </Button>
                        <Button
                          size="sm"
                          variant="quiet"
                          disabled={installingUpdate}
                          onClick={() => setConfirmRollbackVersion(null)}
                        >
                          {copy.rollback.cancelAction}
                        </Button>
                      </div>
                    ) : (
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={installingUpdate}
                        onClick={() => setConfirmRollbackVersion(rel.version)}
                      >
                        {isActiveRollback ? copy.rollback.installing(rel.version) : copy.rollback.rollbackAction}
                      </Button>
                    )
                  }
                />
              );
            })}
          </Rows>
        )}
      </Section>

      <Section title={copy.autostart.section}>
        <Rows>
          <Row
            icon="power"
            title={copy.autostart.title}
            sub={
              (autostartStatus?.active_in_os ?? autostartStatus?.enabled)
                ? copy.autostart.subOn
                : copy.autostart.subOff
            }
            trail={
              <Switch
                checked={Boolean(autostartStatus?.active_in_os ?? autostartStatus?.enabled)}
                disabled={autostartBusy || (autostartStatus !== null && !autostartStatus.supported)}
                onChange={onToggleAutostart}
                aria-label={copy.autostart.label}
              />
            }
          />
        </Rows>
        {autostartStatus?.target && (
          <p className="zs-settings__hint">
            <Mono>{autostartStatus.target}</Mono>
          </p>
        )}
      </Section>
    </>
  );
}
