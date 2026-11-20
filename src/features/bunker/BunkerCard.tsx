import { useCallback, useEffect, useState } from "react";
import {
  Badge,
  Banner,
  Button,
  Card,
  Mono,
  Row,
  Rows,
  Section,
  Select,
  Skeleton,
  Stat,
  Stats,
  Switch,
} from "../../ui";
import { bunkerCopy as copy } from "../../shared/copy/ru/bunker";
import type { ShowToast } from "../../shared/hooks";
import { writeClipboard } from "../../shared/lib/clipboard";
import { formatNumber } from "../../shared/lib/format";
import {
  generateBunkerRestorePrompt,
  getBunkerStatus,
  listBunkerSnapshots,
  openBunkerFolder,
  runBunkerBackupNow,
  updateBunkerSettings,
} from "../../utils/api/bunker";
import type { BunkerSnapshotMeta, BunkerStatus } from "../../types";
import { WebExportHelper } from "./WebExportHelper";
import "./bunker.css";

export interface BunkerCardProps {
  onToast?: ShowToast;
  /** Внешний триггер перезагрузки (например, после экстренного бэкапа из SOS). */
  refreshTrigger?: number;
}

export function formatBytesCompact(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 МБ";
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} КБ`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`;
}

export function formatSnapshotTime(tsSec: number | null | undefined): string {
  if (!tsSec || !Number.isFinite(tsSec)) return copy.status.never;
  try {
    return new Date(tsSec * 1000).toLocaleString("ru-RU", {
      day: "2-digit",
      month: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return String(tsSec);
  }
}

/** Локальный «Бункер данных»: расписание, ротация, 1-click снапшот, RESTORE_PROMPT.md и WebExportHelper. */
export function BunkerCard({ onToast, refreshTrigger }: BunkerCardProps) {
  const [status, setStatus] = useState<BunkerStatus | null>(null);
  const [snapshots, setSnapshots] = useState<BunkerSnapshotMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [backingUp, setBackingUp] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [showWebHelper, setShowWebHelper] = useState(false);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [nextStatus, nextSnapshots] = await Promise.all([
        getBunkerStatus(),
        listBunkerSnapshots(),
      ]);
      setStatus(nextStatus);
      setSnapshots(nextSnapshots);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll, refreshTrigger]);

  const handleToggleAuto = async (enabled: boolean) => {
    try {
      const updated = await updateBunkerSettings({ auto_backup_enabled: enabled });
      setStatus((prev) => (prev ? { ...prev, settings: updated } : prev));
    } catch (err) {
      onToast?.(copy.toasts.settingsErrTitle, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const handleIntervalChange = async (value: string) => {
    const interval = Number(value);
    if (!Number.isFinite(interval) || interval <= 0) return;
    try {
      const updated = await updateBunkerSettings({ interval_hours: interval });
      setStatus((prev) => (prev ? { ...prev, settings: updated } : prev));
    } catch (err) {
      onToast?.(copy.toasts.settingsErrTitle, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const handleRetentionChange = async (value: string) => {
    const retention = Number(value);
    if (!Number.isFinite(retention) || retention <= 0) return;
    try {
      const updated = await updateBunkerSettings({ retention_count: retention });
      setStatus((prev) => (prev ? { ...prev, settings: updated } : prev));
    } catch (err) {
      onToast?.(copy.toasts.settingsErrTitle, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const handleBackupNow = async () => {
    if (backingUp) return;
    setBackingUp(true);
    try {
      const res = await runBunkerBackupNow();
      onToast?.(
        copy.toasts.backupOkTitle,
        copy.toasts.backupOkText(res.snapshot.files_count),
        "success",
      );
      await loadAll();
    } catch (err) {
      onToast?.(copy.toasts.backupErrTitle, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setBackingUp(false);
    }
  };

  const handleOpenFolder = async () => {
    try {
      await openBunkerFolder();
    } catch (err) {
      onToast?.(copy.toasts.folderErrTitle, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const handleCopyPrompt = async () => {
    try {
      const text = await generateBunkerRestorePrompt();
      const ok = await writeClipboard(text);
      if (ok) {
        setCopiedPrompt(true);
        onToast?.(copy.toasts.promptCopiedTitle, copy.toasts.promptCopiedText, "success");
      }
    } catch (err) {
      onToast?.(copy.toasts.promptErrTitle, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const showEmbeddedWebHelper = Boolean(status && !status.has_any_local_data) || showWebHelper;

  return (
    <Section title={copy.section}>
      <Card
        title={copy.title}
        aside={
          <Button
            variant="quiet"
            size="sm"
            iconOnly
            icon="refresh"
            aria-label={copy.loading}
            disabled={loading}
            onClick={() => void loadAll()}
          />
        }
      >
        <p className="zs-t-body zs-bunker__subtitle">{copy.subtitle}</p>

        {loading && !status ? (
          <div role="status" aria-label={copy.loading}>
            <Skeleton variant="text" lines={2} />
            <Skeleton variant="block" height={72} className="zs-bunker__block" />
          </div>
        ) : loadError && !status ? (
          <Banner tone="danger" icon="alert" title={copy.loadError}>
            {loadError}
          </Banner>
        ) : status ? (
          <>
            <Stats>
              <Stat value={formatNumber(status.snapshots_count)} label={copy.status.snapshots} />
              <Stat value={formatBytesCompact(status.total_snapshots_bytes)} label={copy.status.totalSize} />
              <Stat
                value={formatSnapshotTime(status.settings.last_backup_at)}
                label={copy.status.lastBackup}
              />
            </Stats>

            <Rows className="zs-bunker__block">
              <Row
                icon="folder"
                title={copy.status.folder}
                sub={<Mono>{status.bunker_dir}</Mono>}
              />
            </Rows>

            <div className="zs-bunker__controls">
              <Switch
                checked={status.settings.auto_backup_enabled}
                onChange={(checked) => void handleToggleAuto(checked)}
              >
                <span>{copy.controls.autoBackup}</span>
              </Switch>

              <div className="zs-bunker__selects">
                <Select
                  label={copy.controls.intervalLabel}
                  value={String(status.settings.interval_hours)}
                  options={[...copy.controls.intervalOptions]}
                  onChange={(e) => void handleIntervalChange(e.target.value)}
                />
                <Select
                  label={copy.controls.retentionLabel}
                  value={String(status.settings.retention_count)}
                  options={[...copy.controls.retentionOptions]}
                  onChange={(e) => void handleRetentionChange(e.target.value)}
                />
              </div>
            </div>

            <div className="zs-bunker__actions">
              <Button
                variant="primary"
                block
                icon="shield"
                disabled={backingUp}
                onClick={() => void handleBackupNow()}
              >
                {backingUp ? copy.actions.backingUp : copy.actions.backupNow}
              </Button>
              <div className="zs-bunker__row-actions">
                <Button size="sm" icon="folder" onClick={() => void handleOpenFolder()}>
                  {copy.actions.openFolder}
                </Button>
                <Button
                  size="sm"
                  icon={copiedPrompt ? "check" : "copy"}
                  onClick={() => void handleCopyPrompt()}
                >
                  {copiedPrompt ? copy.actions.copiedPrompt : copy.actions.copyPrompt}
                </Button>
                {status.has_any_local_data && (
                  <Button
                    size="sm"
                    variant="quiet"
                    onClick={() => setShowWebHelper((v) => !v)}
                  >
                    {showWebHelper ? copy.actions.toggleWebHelperHide : copy.actions.toggleWebHelperShow}
                  </Button>
                )}
              </div>
            </div>

            {status.sources.length > 0 && (
              <div className="zs-bunker__block">
                <p className="zs-t-caption zs-bunker__section-label">{copy.sourcesTitle}</p>
                <Rows>
                  {status.sources.map((src) => (
                    <Row
                      key={src.kind}
                      icon={src.available ? "check" : "folder"}
                      title={src.label}
                      sub={src.path_hint ? <Mono>{src.path_hint}</Mono> : undefined}
                      trail={
                        <Badge tone={src.available ? "ok" : "neutral"}>
                          {src.available ? copy.sourceAvailable : copy.sourceMissing}
                        </Badge>
                      }
                    />
                  ))}
                </Rows>
              </div>
            )}

            <div className="zs-bunker__block">
              <p className="zs-t-caption zs-bunker__section-label">{copy.historyTitle}</p>
              {snapshots.length === 0 ? (
                <p className="zs-t-caption zs-bunker__subtitle">{copy.historyEmpty}</p>
              ) : (
                <Rows>
                  {snapshots.slice(0, 5).map((snap) => (
                    <Row
                      key={snap.id}
                      icon="lock"
                      title={formatSnapshotTime(snap.created_at)}
                      sub={`${snap.files_count} ф. · ${formatBytesCompact(snap.total_bytes)}`}
                      trail={
                        <Badge tone="neutral">
                          {copy.triggerLabels[snap.trigger] ?? snap.trigger}
                        </Badge>
                      }
                    />
                  ))}
                </Rows>
              )}
            </div>

            {showEmbeddedWebHelper && (
              <div className="zs-bunker__block">
                <WebExportHelper onConverted={() => void loadAll()} onToast={onToast} />
              </div>
            )}
          </>
        ) : null}
      </Card>
    </Section>
  );
}
