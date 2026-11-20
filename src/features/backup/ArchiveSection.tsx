import { Banner, Button, Card, Mono, Progress, Row, Rows, Section, Skeleton, Stat, Stats } from "../../ui";
import type { ClaudeBackup, ShowToast } from "../../shared/hooks";
import { backup as copy } from "../../shared/copy/ru";
import { formatNumber } from "../../shared/lib/format";
import { WebExportHelper } from "../bunker";

/** Блок «Архив Claude»: сводка найденного, одна brand-кнопка, прогресс и результат. */
export function ArchiveSection({ backup, onToast }: { backup: ClaudeBackup; onToast?: ShowToast }) {
  const { claudeSummary, loadingClaudeSummary, claudeExporting, claudeExportResult, copiedPrompt } = backup;
  const t = copy.archive;
  const missing = Boolean(claudeSummary) && !claudeSummary?.exists;
  const resultPath = claudeExportResult?.zip_archive_path || claudeExportResult?.export_dir_path;

  return (
    <Section title={t.section}>
      <Card
        title={t.title}
        aside={
          <Button
            variant="quiet"
            size="sm"
            iconOnly
            icon="refresh"
            aria-label={t.rescan}
            disabled={loadingClaudeSummary}
            onClick={backup.loadClaudeSummary}
          />
        }
      >
        {!claudeSummary && loadingClaudeSummary ? (
          <div role="status" aria-label={t.loading}>
            <Skeleton variant="text" lines={2} />
            <Skeleton variant="block" height={72} className="zs-backup__block" />
          </div>
        ) : missing ? (
          <WebExportHelper title={t.emptyTitle} onToast={onToast} />
        ) : (
          <>
            <p className="zs-t-body zs-backup__text">{t.text}</p>
            <Stats>
              <Stat value={formatNumber(claudeSummary?.projects_count ?? 0)} label={t.stats.projects} />
              <Stat value={formatNumber(claudeSummary?.sessions_count ?? 0)} label={t.stats.sessions} />
              <Stat value={((claudeSummary?.total_size_bytes ?? 0) / (1024 * 1024)).toFixed(1)} label={t.stats.size} />
            </Stats>
            <Rows className="zs-backup__block">
              <Row
                icon="folder"
                title={t.folder}
                sub={<Mono>{claudeSummary?.claude_dir_path ?? "~/.claude"}</Mono>}
              />
              <Row icon="lock" title={t.stats.memory} sub={t.stats.memoryCount(claudeSummary?.memory_files_count ?? 0)} />
            </Rows>

            {claudeExporting && <Progress className="zs-backup__block" label={t.exportProgress} />}

            <div className="zs-backup__actions">
              <Button variant="primary" block icon="folder" disabled={claudeExporting} onClick={backup.handleExportClaude}>
                {claudeExporting ? t.saving : t.save}
              </Button>
              <Button
                block
                icon={copiedPrompt ? "check" : "copy"}
                disabled={claudeExporting}
                onClick={backup.handleCopyRestorePrompt}
              >
                {copiedPrompt ? t.copiedPrompt : t.copyPrompt}
              </Button>
            </div>

            {claudeExportResult && resultPath && !claudeExporting && (
              <Banner tone="ok" icon="check" title={t.resultTitle} className="zs-backup__block">
                {t.resultText}
                <Mono className="zs-path">{resultPath}</Mono>
              </Banner>
            )}
          </>
        )}
      </Card>
    </Section>
  );
}
