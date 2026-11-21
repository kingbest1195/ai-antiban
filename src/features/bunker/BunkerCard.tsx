import { useCallback, useEffect, useState } from "react";
import {
  Badge,
  Banner,
  Button,
  Card,
  ExpandRow,
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
import type { ClaudeBackup, ShowToast } from "../../shared/hooks";
import { writeClipboard } from "../../shared/lib/clipboard";
import { formatNumber } from "../../shared/lib/format";
import {
  clearBunkerSnapshots,
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
  backup?: ClaudeBackup;
  onToast?: ShowToast;
  /** Внешний триггер перезагрузки (например, после экстренного бэкапа из SOS). */
  refreshTrigger?: number;
  /** Начальное состояние (для SSR/тестов). */
  initialStatus?: BunkerStatus;
}

export function formatBytesCompact(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 МБ";
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} КБ`;
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} ГБ`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`;
}

export function formatSnapshotTime(tsSec: number | null | undefined): string {
  if (!tsSec || !Number.isFinite(tsSec)) return copy.status.never;
  try {
    return new Date(tsSec * 1000)
      .toLocaleString("ru-RU", {
        day: "2-digit",
        month: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      })
      .replace(", ", " ");
  } catch {
    return String(tsSec);
  }
}

/** Локальный «Бункер данных»: расписание, ротация, 1-click копия, промпт переноса и веб-экспорт. */
export function BunkerCard({ backup, onToast, refreshTrigger, initialStatus }: BunkerCardProps) {
  const [status, setStatus] = useState<BunkerStatus | null>(initialStatus ?? null);
  const [snapshots, setSnapshots] = useState<BunkerSnapshotMeta[]>([]);
  const [loading, setLoading] = useState(!initialStatus);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [backingUp, setBackingUp] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [showWebHelper, setShowWebHelper] = useState(false);
  const [sourcesOpen, setSourcesOpen] = useState(false);

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

  const handleMaxTotalMbChange = async (value: string) => {
    const maxMb = Number(value);
    if (!Number.isFinite(maxMb) || maxMb <= 0) return;
    try {
      const updated = await updateBunkerSettings({ max_total_mb: maxMb });
      setStatus((prev) => (prev ? { ...prev, settings: updated } : prev));
    } catch (err) {
      onToast?.(copy.toasts.settingsErrTitle, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const handleClearSnapshots = async () => {
    if (clearing) return;
    setClearing(true);
    try {
      const nextStatus = await clearBunkerSnapshots();
      setStatus(nextStatus);
      const nextSnapshots = await listBunkerSnapshots();
      setSnapshots(nextSnapshots);
      onToast?.(copy.toasts.clearedTitle, copy.toasts.clearedText, "success");
    } catch (err) {
      onToast?.(copy.toasts.clearErrTitle, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setClearing(false);
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
            <Stats className="zs-bunker__stats">
              <Stat value={formatNumber(status.snapshots_count)} label={copy.status.snapshots} />
              <Stat
                value={formatBytesCompact(status.total_snapshots_bytes)}
                label={copy.status.totalSizeQuota(status.settings.max_total_mb ?? 500)}
              />
              <Stat
                value={
                  status.settings.last_backup_at
                    ? formatSnapshotTime(status.settings.last_backup_at)
                    : copy.status.neverShort
                }
                label={copy.status.lastBackup}
              />
            </Stats>

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
                <Select
                  label={copy.controls.maxTotalMbLabel}
                  value={String(status.settings.max_total_mb ?? 500)}
                  options={[...copy.controls.maxTotalMbOptions]}
                  onChange={(e) => void handleMaxTotalMbChange(e.target.value)}
                />
                <Button
                  variant="secondary"
                  block
                  disabled={clearing || snapshots.length === 0}
                  onClick={() => void handleClearSnapshots()}
                >
                  {clearing ? copy.actions.clearingOld : copy.actions.clearOld}
                </Button>
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
              <div className="zs-bunker__two-col">
                <Button size="sm" icon="folder" onClick={() => void handleOpenFolder()}>
                  {copy.actions.openFolder}
                </Button>
                {backup ? (
                  <Button
                    size="sm"
                    icon="download"
                    title={copy.actions.saveZipTitle}
                    disabled={backup.claudeExporting}
                    onClick={() => void backup.handleExportClaude()}
                  >
                    {backup.claudeExporting ? copy.actions.savingZip : copy.actions.saveZip}
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    icon={copiedPrompt ? "check" : "copy"}
                    onClick={() => void handleCopyPrompt()}
                  >
                    {copiedPrompt ? copy.actions.copiedPromptBtn : copy.actions.copyPromptBtn}
                  </Button>
                )}
              </div>
            </div>

            <div className="zs-bunker__prompt-box zs-bunker__block">
              <p className="zs-bunker__prompt-title">{copy.actions.promptBoxTitle}</p>
              <p className="zs-bunker__prompt-sub">{copy.actions.copyPromptSub}</p>
              <Button
                size="sm"
                variant="secondary"
                icon={copiedPrompt ? "check" : "copy"}
                className="zs-bunker__prompt-btn"
                onClick={() => void handleCopyPrompt()}
              >
                {copiedPrompt ? copy.actions.copiedPromptBtn : copy.actions.copyPromptBtn}
              </Button>
            </div>

            <Rows className="zs-bunker__block">
              {status.has_any_local_data && (
                <ExpandRow
                  icon="globe"
                  title={copy.actions.toggleWebHelperShow}
                  sub={copy.actions.webExportSub}
                  open={showWebHelper}
                  onToggle={() => setShowWebHelper((v) => !v)}
                >
                  <WebExportHelper ctaVariant="secondary" onConverted={() => void loadAll()} onToast={onToast} />
                </ExpandRow>
              )}
              {status.sources.length > 0 && (
                <ExpandRow
                  icon="folder"
                  title={copy.sourcesSummaryTitle(
                    status.sources.filter((s) => s.available).length,
                    status.sources.length,
                  )}
                  sub={copy.sourcesSummarySub}
                  open={sourcesOpen}
                  onToggle={() => setSourcesOpen((v) => !v)}
                >
                  <Rows>
                    {status.sources.map((src) => (
                      <Row
                        key={src.kind}
                        icon={src.available ? "check" : "folder"}
                        title={src.label}
                        trail={
                          <span className="zs-bunker__source-status">
                            {src.available ? copy.sourceAvailable : copy.sourceMissing}
                          </span>
                        }
                      />
                    ))}
                  </Rows>
                </ExpandRow>
              )}
            </Rows>

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

            {!status.has_any_local_data && (
              <div className="zs-bunker__block">
                <WebExportHelper ctaVariant="secondary" onConverted={() => void loadAll()} onToast={onToast} />
              </div>
            )}
          </>
        ) : null}
      </Card>
    </Section>
  );
}
