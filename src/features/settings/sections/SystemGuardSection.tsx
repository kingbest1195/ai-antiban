import type { CoworkGuardStatus, ProtectionChangePreviewItem } from "../../../types";
import { openExternal } from "../../../utils/opener";
import { Badge, Banner, Button, ExpandRow, Link, Mono, Row, Rows, Section } from "../../../ui";
import { settings as copy } from "../../../shared/copy/ru";

const SOURCE_URL = "https://github.com/kingbest1195/ai-antiban";

interface SystemGuardSectionProps {
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
}

export function SystemGuardSection({
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
}: SystemGuardSectionProps) {
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
              <div className="zs-settings__form" style={{ marginTop: "var(--space-2)", gap: "var(--space-2)", flexWrap: "wrap" }}>
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
                      trail={<Badge tone="info">{item.kind === "process" ? "Процесс" : "LaunchAgent"}</Badge>}
                    />
                  ))}
                </Rows>
              </>
            )}

            <div className="zs-settings__form" style={{ marginTop: "var(--space-2)", flexWrap: "wrap" }}>
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

      <Section title={copy.diagnostics.section}>
        <p className="zs-t-body zs-settings__lead">{copy.diagnostics.text}</p>
        <div className="zs-settings__form">
          <Button variant="secondary" disabled={exportBusy} onClick={() => void onExportDiagnostics()}>
            {exportBusy ? copy.diagnostics.exportBusy : copy.diagnostics.exportAction}
          </Button>
        </div>
        <Rows className="zs-settings__rows">
          <ExpandRow
            icon="shield"
            title={copy.diagnostics.previewTitle}
            sub={previewLoading ? copy.diagnostics.previewSubLoading : copy.diagnostics.previewSub(previewItems.length)}
            open={previewOpen}
            onToggle={onTogglePreview}
            detailLabel={copy.diagnostics.previewTitle}
          >
            {previewError ? (
              <Banner tone="warn" title={copy.diagnostics.previewError}>
                {previewError}
              </Banner>
            ) : previewItems.length === 0 ? (
              <p className="zs-settings__empty">{copy.diagnostics.previewEmpty}</p>
            ) : (
              <Rows>
                {previewItems.map((item) => (
                  <Row
                    key={`${item.category}:${item.target}`}
                    icon="term"
                    title={item.target}
                    sub={`${item.action} — ${item.description}`}
                    trail={item.reversible ? <Badge tone="ok">{copy.diagnostics.reversibleBadge}</Badge> : undefined}
                  />
                ))}
              </Rows>
            )}
          </ExpandRow>
        </Rows>
      </Section>

      <Section title={copy.privacy.section}>
        <Rows>
          <Row icon="lock" title={copy.privacy.local} sub={copy.privacy.localText} />
          <Row icon="shield" title={copy.privacy.selectiveTitle} sub={copy.privacy.selectiveText} />
        </Rows>
        <p className="zs-settings__sub">{copy.privacy.networkTitle}</p>
        <Rows>
          {copy.privacy.network.map((n) => (
            <Row
              key={n.what}
              icon="globe"
              title={n.what}
              sub={
                <>
                  <Mono>{n.where}</Mono>: {n.note}
                </>
              }
            />
          ))}
        </Rows>
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
      </Section>

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
    </>
  );
}
