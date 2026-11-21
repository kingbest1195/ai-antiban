import { useState } from "react";
import type { CoworkGuardStatus, ProtectionChangePreviewItem } from "../../../types";
import { openExternal } from "../../../utils/opener";
import { Badge, Banner, Button, ExpandRow, Link, Mono, Row, Rows, Section } from "../../../ui";
import { settings as copy } from "../../../shared/copy/ru";

const SOURCE_URL = "https://github.com/kingbest1195/ai-antiban";

interface SystemGuardSectionProps {
  autoUpdateEnabled?: boolean;
  coworkStatus: CoworkGuardStatus | null;
  coworkBusy: boolean;
  onInstallCoworkGuard: () => void;
  onRefreshCoworkGuard: () => void;
  exportBusy: boolean;
  onExportDiagnostics: () => Promise<void>;
  previewItems: ProtectionChangePreviewItem[];
  previewLoading: boolean;
  previewError: string | null;
  previewOpen: boolean;
  onTogglePreview: () => void;
  cleaningProxy: boolean;
  proxyResult: { ok: boolean; text: string } | null;
  onRequestCleanProxy: () => void;
  hintsResetBusy?: boolean;
  onResetDismissedHints?: () => Promise<void>;
  onReplayOnboarding?: () => void;
}

export function SystemGuardSection({
  autoUpdateEnabled = true,
  coworkStatus,
  coworkBusy,
  onInstallCoworkGuard,
  onRefreshCoworkGuard,
  exportBusy,
  onExportDiagnostics,
  previewItems,
  previewLoading,
  previewError,
  previewOpen,
  onTogglePreview,
  cleaningProxy,
  proxyResult,
  onRequestCleanProxy,
  hintsResetBusy = false,
  onResetDismissedHints,
  onReplayOnboarding,
}: SystemGuardSectionProps) {
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const handleToggleAdvanced = () => {
    const next = !advancedOpen;
    setAdvancedOpen(next);
    if (next && !previewOpen) {
      onTogglePreview();
    }
  };

  return (
    <>
      <Section title={copy.coworkGuard.section}>
        {!coworkStatus ? (
          <p className="zs-settings__hint">{copy.coworkGuard.loading}</p>
        ) : (
          <>
            <Banner
              tone={
                coworkStatus.needs_repair
                  ? "warn"
                  : coworkStatus.platform === "windows" && coworkStatus.task_healthy
                  ? "ok"
                  : "info"
              }
              title={
                coworkStatus.needs_repair
                  ? copy.coworkGuard.statusNeedsRepair
                  : coworkStatus.platform === "windows" && coworkStatus.task_healthy
                  ? copy.coworkGuard.statusHealthy
                  : copy.coworkGuard.statusInfo
              }
            >
              {coworkStatus.summary}
            </Banner>

            {coworkStatus.platform === "windows" && (
              <div className="zs-settings__badges">
                {coworkStatus.service_present && coworkStatus.start_type !== null && (
                  <Badge
                    tone={
                      coworkStatus.start_type === 3
                        ? "ok"
                        : coworkStatus.start_type === 2
                        ? "warn"
                        : "danger"
                    }
                  >
                    {coworkStatus.start_type === 2
                      ? copy.coworkGuard.startAutoBadge
                      : coworkStatus.start_type === 3
                      ? copy.coworkGuard.startManualBadge
                      : copy.coworkGuard.startDisabledBadge}
                  </Badge>
                )}
                {coworkStatus.service_present && (
                  <Badge tone={coworkStatus.service_running ? "warn" : "ok"}>
                    {coworkStatus.service_running
                      ? copy.coworkGuard.serviceRunningBadge
                      : copy.coworkGuard.serviceStoppedBadge}
                  </Badge>
                )}
                <Badge tone={coworkStatus.task_healthy ? "ok" : "warn"}>
                  {coworkStatus.task_healthy
                    ? copy.coworkGuard.taskHealthyBadge
                    : copy.coworkGuard.taskMissingBadge}
                </Badge>
              </div>
            )}

            {coworkStatus.detected_ai_apps.length > 0 && (
              <>
                <p className="zs-settings__sub">{copy.coworkGuard.macosDetectedTitle}</p>
                <Rows>
                  {coworkStatus.detected_ai_apps.map((item) => (
                    <Row
                      key={`${item.kind}:${item.name}:${item.detail}`}
                      icon="shield"
                      title={item.name}
                      sub={<Mono>{item.detail}</Mono>}
                      trail={<Badge tone="info">{item.kind === "process" ? "Процесс" : "Автозапуск"}</Badge>}
                    />
                  ))}
                </Rows>
              </>
            )}

            <div className="zs-settings__form">
              {coworkStatus.platform === "windows" && coworkStatus.supported && (
                <Button
                  variant={coworkStatus.needs_repair ? "primary" : "secondary"}
                  size="sm"
                  disabled={coworkBusy}
                  onClick={onInstallCoworkGuard}
                >
                  {coworkBusy ? copy.coworkGuard.actionRepairing : copy.coworkGuard.actionInstall}
                </Button>
              )}
              <Button variant="quiet" size="sm" disabled={coworkBusy} onClick={onRefreshCoworkGuard}>
                {copy.coworkGuard.actionRecheck}
              </Button>
            </div>
          </>
        )}
      </Section>

      {(onResetDismissedHints || onReplayOnboarding) && (
        <Section title="Подсказки и обучение">
          <p className="zs-t-body zs-settings__lead">
            Вернуть закрытые подсказки в разделах или пройти знакомство заново.
          </p>
          <div className="zs-settings__form">
            {onResetDismissedHints && (
              <Button variant="secondary" disabled={hintsResetBusy} onClick={() => void onResetDismissedHints()}>
                {hintsResetBusy ? "Сбрасываем…" : "Показать все подсказки снова"}
              </Button>
            )}
            {onReplayOnboarding && (
              <Button variant="secondary" onClick={onReplayOnboarding}>
                Пройти знакомство заново
              </Button>
            )}
          </div>
        </Section>
      )}

      <Section title={copy.proxy.section}>
        <p className="zs-t-body zs-settings__lead">{copy.proxy.text}</p>
        <div className="zs-settings__danger">
          <Button variant="danger" icon="power" disabled={cleaningProxy} onClick={onRequestCleanProxy}>
            {cleaningProxy ? copy.proxy.working : copy.proxy.action}
          </Button>
        </div>
        {proxyResult && (
          <Banner
            className="zs-settings__result"
            tone={proxyResult.ok ? "ok" : "danger"}
            role={proxyResult.ok ? "status" : "alert"}
            title={proxyResult.ok ? copy.proxy.done : copy.proxy.failed}
          >
            {proxyResult.text}
          </Banner>
        )}
      </Section>

      <Section title={copy.advanced.section}>
        <Rows className="zs-settings__rows">
          <ExpandRow
            icon="term"
            title={copy.advanced.title}
            sub={copy.advanced.sub}
            open={advancedOpen}
            onToggle={handleToggleAdvanced}
            detailLabel={copy.advanced.title}
          >
            <p className="zs-settings__sub">{copy.diagnostics.previewTitle}</p>
            {previewLoading ? (
              <p className="zs-settings__hint">{copy.diagnostics.previewSubLoading}</p>
            ) : previewError ? (
              <Banner tone="warn" title={copy.diagnostics.previewError}>
                {previewError}
              </Banner>
            ) : previewItems.length === 0 ? (
              <p className="zs-settings__empty">{copy.diagnostics.previewEmpty}</p>
            ) : (
              <ul className="zs-settings__preview-list">
                {previewItems.map((item) => (
                  <li key={`${item.category}:${item.target}`} className="zs-settings__preview-item">
                    <div className="zs-settings__preview-head">
                      <p className="zs-settings__preview-title">{item.action}</p>
                      {item.reversible && <Badge tone="ok">{copy.diagnostics.reversibleBadge}</Badge>}
                    </div>
                    <p className="zs-settings__preview-desc">{item.description}</p>
                    <Mono className="zs-settings__preview-detail">{item.target}</Mono>
                  </li>
                ))}
              </ul>
            )}

            <p className="zs-settings__sub">{copy.privacy.networkTitle}</p>
            <ul className="zs-settings__preview-list">
              {copy.privacy.network.map((n) => {
                const dynamicNote =
                  n.where === "api.github.com"
                    ? `${n.note} (сейчас ${autoUpdateEnabled ? "включено" : "отключено"})`
                    : n.note;
                return (
                  <li key={n.what} className="zs-settings__preview-item">
                    <div className="zs-settings__preview-head">
                      <p className="zs-settings__preview-title">{n.what}</p>
                    </div>
                    <p className="zs-settings__preview-desc">{dynamicNote}</p>
                    <Mono className="zs-settings__preview-detail">{n.where}</Mono>
                  </li>
                );
              })}
            </ul>

            <p className="zs-settings__sub">{copy.privacy.section}</p>
            <ul className="zs-settings__preview-list">
              <li className="zs-settings__preview-item">
                <p className="zs-settings__preview-title">{copy.privacy.local}</p>
                <p className="zs-settings__preview-desc">{copy.privacy.localText}</p>
              </li>
              <li className="zs-settings__preview-item">
                <p className="zs-settings__preview-title">{copy.privacy.selectiveTitle}</p>
                <p className="zs-settings__preview-desc">{copy.privacy.selectiveText}</p>
              </li>
            </ul>

            <div className="zs-settings__form">
              <Button variant="secondary" size="sm" disabled={exportBusy} onClick={() => void onExportDiagnostics()}>
                {exportBusy ? copy.diagnostics.exportBusy : copy.diagnostics.exportAction}
              </Button>
              <span className="zs-settings__sub">{copy.diagnostics.exportHint}</span>
            </div>

            <p className="zs-settings__source">
              <Link
                href={SOURCE_URL}
                chevron
                onClick={(e) => {
                  e.preventDefault();
                  openExternal(SOURCE_URL);
                }}
              >
                {copy.privacy.source}
              </Link>
            </p>
          </ExpandRow>
        </Rows>
      </Section>
    </>
  );
}
