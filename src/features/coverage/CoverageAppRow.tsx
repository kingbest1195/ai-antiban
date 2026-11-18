import { useMemo } from "react";
import type { AppCoverageItem, CoverageSnapshot } from "../../types";
import { Badge, Banner, Button, CopyBlock, ExpandRow, Row, Spinner, Steps } from "../../ui";
import { coverage as copy } from "../../shared/copy/ru";
import { buildManualSetup } from "./manualSetup";
import { isProtectionOn, protectionControl, sinceLastSeen, viewOf } from "./coverageModel";
import type { ProtectionKind, WaitingMap } from "./coverageModel";
import { COVERAGE_BADGES, COVERAGE_ICONS, coverageRowTone } from "./CoverageBadges";

interface CoverageAppRowProps {
  app: AppCoverageItem;
  snapshot: CoverageSnapshot;
  waiting: WaitingMap;
  now: number;
  open: boolean;
  onToggle: () => void;
  copiedId: string | null;
  onCopy: (id: string, value: string) => void;
  onConfirm: () => void;
  busy: { kind: ProtectionKind; action: "enable" | "disable" } | null;
  onEnable: (kind: ProtectionKind) => void;
  onAskDisable: (kind: ProtectionKind) => void;
  canControl: boolean;
  canRestart: boolean;
  restarting: boolean;
  onAskRestart: () => void;
}

export function CoverageAppRow({
  app,
  snapshot,
  waiting,
  now,
  open,
  onToggle,
  copiedId,
  onCopy,
  onConfirm,
  busy,
  onEnable,
  onAskDisable,
  canControl,
  canRestart,
  restarting,
  onAskRestart,
}: CoverageAppRowProps) {
  const setup = useMemo(() => buildManualSetup(app, snapshot), [app, snapshot]);
  const view = viewOf(app, waiting, now, snapshot.cli_mode);
  if (view === "not_installed") return null;
  const badge = COVERAGE_BADGES[view];
  const since = sinceLastSeen(app, now);
  const sub =
    view === "confirmed" && app.ai_requests > 0
      ? copy.seen(app.ai_requests, since)
      : view === "waiting"
        ? copy.statusSub.waiting
        : view === "waiting_timeout"
          ? copy.statusSub.waitingTimeout
          : view === "configured"
            ? app.detail || copy.statusSub.configured
            : view === "direct"
              ? app.detail || copy.statusSub.direct
              : app.detail;
  const trail = (
    <Badge tone={badge.tone} icon={badge.icon}>
      {badge.label}
    </Badge>
  );

  if (setup.steps.length === 0) {
    return (
      <Row
        className="zs-cov__row"
        icon={COVERAGE_ICONS[app.category]}
        tone={coverageRowTone(view)}
        title={app.name}
        sub={sub}
        trail={trail}
      />
    );
  }

  const kind = setup.protection;
  const control = kind ? protectionControl(isProtectionOn(kind, snapshot), busy?.kind === kind) : null;

  return (
    <ExpandRow
      className="zs-cov__row"
      icon={COVERAGE_ICONS[app.category]}
      tone={coverageRowTone(view)}
      title={app.name}
      sub={sub}
      trail={trail}
      open={open}
      onToggle={onToggle}
      detailLabel={copy.howToLabel(app.name)}
    >
      <div className="zs-cov__detail">
        <p className="zs-cov__label">{copy.howTo}</p>
        {setup.warning && (
          <Banner tone="warn" title={setup.warning.title}>
            {setup.warning.text}
          </Banner>
        )}
        {canRestart && (
          <div className="zs-cov__actions">
            <Button
              size="sm"
              variant="primary"
              icon="refresh"
              disabled={restarting || busy !== null}
              aria-busy={restarting}
              onClick={onAskRestart}
            >
              {restarting ? (
                <>
                  <Spinner /> {copy.restart.busy}
                </>
              ) : (
                copy.restart.button
              )}
            </Button>
          </div>
        )}
        {canRestart && <p className="zs-cov__hint">{copy.restart.manualFallback}</p>}
        {kind && !canControl && <p className="zs-cov__hint">{copy.hints.protectionOnOverview}</p>}
        {kind && control && canControl && control.mode === "enable" && (
          <div className="zs-cov__actions">
            <Button
              size="sm"
              variant="primary"
              icon="power"
              disabled={control.busy || busy !== null}
              aria-busy={control.busy}
              onClick={() => onEnable(kind)}
            >
              {control.busy ? copy.protection.busy[kind] : copy.protection.enable[kind]}
            </Button>
          </div>
        )}
        {kind && control && canControl && control.mode === "on" && (
          <>
            <div className="zs-cov__actions">
              <Badge tone="ok" icon="check">
                {copy.protection.on[kind]}
              </Badge>
              <Button
                size="sm"
                variant="quiet"
                disabled={busy !== null}
                aria-label={copy.protection.disableAria(copy.protection.on[kind])}
                onClick={() => onAskDisable(kind)}
              >
                {control.busy && busy?.action === "disable" ? copy.protection.disableBusy : copy.protection.disable}
              </Button>
            </div>
            <p className="zs-cov__hint">{copy.protection.onButNotHere}</p>
          </>
        )}
        <Steps items={setup.steps.map((s) => ({ title: s.title, text: s.text }))} />
        {setup.addressPending ? (
          <p className="zs-cov__pending" role="status">
            {copy.gatewayPending}
          </p>
        ) : (
          <div className="zs-cov__blocks">
            {setup.blocks.map((b) => {
              const id = `${app.id}:${b.id}`;
              return (
                <div key={id}>
                  <p className="zs-cov__label">{b.label}</p>
                  <CopyBlock
                    lines={b.lines}
                    label={b.label}
                    copied={copiedId === id}
                    copyLabel={b.kind === "address" ? copy.copyAddress : copy.copyCommand}
                    copiedLabel={copy.copied}
                    copyAriaLabel={b.kind === "address" ? copy.copyAddressAria(b.label) : copy.copyCommandAria(b.label)}
                    onCopy={(text) => onCopy(id, text)}
                  />
                </div>
              );
            })}
          </div>
        )}
        {setup.hints.map((h) => (
          <p key={h} className="zs-cov__hint">
            {h}
          </p>
        ))}
        {view === "waiting_timeout" && (
          <p className="zs-cov__hint" role="status">
            {copy.hints.waitingTimeout}
          </p>
        )}
        <div className="zs-cov__actions">
          <Button size="sm" onClick={onConfirm} disabled={view === "waiting"}>
            {copy.iSetUp}
          </Button>
        </div>
      </div>
    </ExpandRow>
  );
}
