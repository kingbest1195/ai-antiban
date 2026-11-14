import { useEffect } from "react";
import type { OsTzSyncStatus } from "../types";
import { Badge, Banner, Button, Modal, Mono, Section } from "../ui";
import { timezone as copy } from "../shared/copy/ru";
import { useOsTimezoneSync } from "../shared/hooks/useTimezoneSync";

interface TimezoneModalProps {
  open: boolean;
  onClose: () => void;
  syncing: boolean;
  synced: boolean;
  onSync: () => Promise<void>;
  /** Открыть настройки времени ОС и перейти к гайду. */
  onOpenOsClock: () => void;
  targetTz?: string;
  osTzStatus?: OsTzSyncStatus | null;
  osTzLoading?: boolean;
  osTzError?: string | null;
  onSyncOsTz?: () => Promise<OsTzSyncStatus | null | void>;
  onRestoreOsTz?: () => Promise<OsTzSyncStatus | null | void>;
}

/** «Настроить часовой пояс»: отдельно CLI/IDE (`TZ`) и системный пояс ОС. */
export function TimezoneModal({
  open,
  onClose,
  syncing,
  synced,
  onSync,
  onOpenOsClock,
  targetTz,
  osTzStatus: propOsStatus,
  osTzLoading: propOsLoading,
  osTzError: propOsError,
  onSyncOsTz,
  onRestoreOsTz,
}: TimezoneModalProps) {
  const shared = useOsTimezoneSync(targetTz);
  const osStatus = propOsStatus !== undefined ? propOsStatus : shared.osTzStatus;
  const osLoading = propOsLoading ?? shared.osTzLoading;
  const osError = propOsError !== undefined ? propOsError : shared.osTzError;
  const syncOs = onSyncOsTz ?? (() => shared.syncOsTimezone(targetTz));
  const restoreOs = onRestoreOsTz ?? shared.restoreOsTimezone;

  useEffect(() => {
    if (open) {
      void shared.refreshOsTzStatus();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={copy.title}
      footer={
        <>
          <Button variant="quiet" onClick={onOpenOsClock}>
            {copy.osClock}
          </Button>
          <Button variant="secondary" onClick={onClose}>
            {copy.close}
          </Button>
        </>
      }
    >
      <div className="zs-stack">
        <p className="zs-modal-text">{copy.text}</p>

        <Section title={copy.cliTitle}>
          <p className="zs-modal-text">{copy.cliText}</p>
          {synced && (
            <p className="zs-modal-text">
              <Badge tone="ok" icon="check">
                {copy.done}
              </Badge>
            </p>
          )}
          <Button
            variant="secondary"
            disabled={syncing}
            onClick={() => void onSync()}
          >
            {syncing ? copy.syncing : copy.sync}
          </Button>
        </Section>

        <Section title={copy.osTitle}>
          <p className="zs-modal-text">{copy.osText}</p>
          {osStatus?.current_os_tz && (
            <p className="zs-modal-text">
              {copy.osCurrent}: <Mono>{osStatus.current_os_tz}</Mono>
            </p>
          )}

          {osStatus?.synced && (
            <>
              <p className="zs-modal-text">
                <Badge tone="ok" icon="check">
                  {copy.osSyncedBadge(osStatus.original_os_tz, osStatus.synced_target_tz)}
                </Badge>
              </p>
              <Banner tone="info" title={copy.osRestartHint} />
            </>
          )}

          {osError && (
            <Banner tone="warn" title={copy.osErrorTitle}>
              {osError}
            </Banner>
          )}

          <div className="zs-banner__actions">
            {osStatus?.synced ? (
              <Button
                variant="secondary"
                disabled={osLoading}
                onClick={() => void restoreOs()}
              >
                {osLoading ? copy.restoringOs : copy.restoreOs}
              </Button>
            ) : (
              <Button
                variant="primary"
                disabled={osLoading}
                onClick={() => void syncOs()}
              >
                {osLoading ? copy.syncingOs : copy.syncOs}
              </Button>
            )}
          </div>
        </Section>
      </div>
    </Modal>
  );
}
