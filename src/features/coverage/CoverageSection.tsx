import { useEffect, useMemo, useState } from "react";
import type { AppCoverageItem, CoverageSnapshot } from "../../types";
import { Badge, Banner, Button, Card, CopyBlock, ExpandRow, Row, Rows, Section, Skeleton, Spinner, Steps } from "../../ui";
import type { BadgeTone, IconName, RowTone } from "../../ui";
import { common, coverage as copy } from "../../shared/copy/ru";
import type { ShowToast } from "../../shared/hooks";
import { useCopy } from "../guides/useCopy";
import { buildManualSetup } from "./manualSetup";
import { isListed, sinceLastSeen, viewOf, vpnNotice } from "./coverageModel";
import type { CoverageView, WaitingMap } from "./coverageModel";
import { useCoverage } from "./useCoverage";
import "./coverage.css";

export interface CoverageSectionProps {
  /** overview — только установленные или с трафиком; checks — все приложения шлюза. */
  variant: "overview" | "checks";
  /** Снимок, который экран уже знает: показывается, пока не пришёл свежий. */
  initialSnapshot?: CoverageSnapshot | null;
  /** Застава ещё запускается в фоне: статусы приложений пока не определены, вместо них «Проверяем…». */
  pending?: boolean;
  /** Переключатели защиты со вкладки «Обзор»; без них кнопка «Включить защиту» не показывается. */
  onToggleSysproxy?: () => void | Promise<void>;
  onToggleCli?: () => void | Promise<void>;
  onToast?: ShowToast;
}

interface BadgeView {
  tone: BadgeTone;
  icon?: IconName;
  label: string;
}

const BADGES: Record<Exclude<CoverageView, "not_installed">, BadgeView> = {
  confirmed: { tone: "ok", icon: "check", label: copy.status.confirmed },
  configured: { tone: "info", label: copy.status.configured },
  waiting: { tone: "info", icon: "refresh", label: copy.status.waiting },
  waiting_timeout: { tone: "neutral", icon: "help", label: copy.status.waitingTimeout },
  unknown: { tone: "neutral", icon: "help", label: copy.status.unknown },
  off: { tone: "warn", icon: "alert", label: copy.status.off },
  direct: { tone: "neutral", label: copy.status.direct },
};

const ICONS: Record<AppCoverageItem["category"], IconName> = { browser: "globe", desktop: "shield", ide: "term", cli: "term" };

const rowTone = (view: CoverageView): RowTone => (view === "confirmed" ? "ok" : view === "off" ? "warn" : "neutral");

/** Секция «Покрытие приложений»: одна реализация для «Обзора» и «Проверок». */
export function CoverageSection({ variant, initialSnapshot, pending, onToggleSysproxy, onToggleCli, onToast }: CoverageSectionProps) {
  const { snapshot, failed, checking, waiting, now, refresh, recheck, confirmSetup } = useCoverage(initialSnapshot);
  const { copiedId, copy: copyText } = useCopy(onToast);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [enabling, setEnabling] = useState<string | null>(null);

  // Как только запуск закончился, читаем состояние заново: снимок до этого описывал выключенную защиту.
  useEffect(() => {
    if (!pending) void refresh();
  }, [pending, refresh]);

  const showPending = pending || (!snapshot && !failed);

  const apps = useMemo(() => (snapshot?.apps ?? []).filter((a) => isListed(a, variant)), [snapshot, variant]);
  const vpn = useMemo(() => (snapshot ? vpnNotice(snapshot) : null), [snapshot]);

  const enable = async (app: AppCoverageItem, kind: "sysproxy" | "cli") => {
    const toggle = kind === "sysproxy" ? onToggleSysproxy : onToggleCli;
    if (!toggle) return;
    setEnabling(app.id);
    try {
      await toggle();
    } finally {
      setEnabling(null);
      void refresh();
    }
  };

  return (
    <Section title={copy.section}>
      <Card>
        <div className="zs-cov__head">
          <p className="zs-cov__lead">{copy.lead}</p>
          <Button size="sm" icon="refresh" onClick={() => void recheck()} disabled={checking || showPending}>
            {checking ? copy.rechecking : copy.recheck}
          </Button>
        </div>
        {showPending ? (
          <div role="status" aria-busy="true">
            <p className="zs-cov__pending">
              <Spinner /> {copy.checking}
            </p>
            <Skeleton variant="text" lines={2} />
          </div>
        ) : !snapshot ? (
          <p className="zs-cov__empty" role="status">
            {copy.loadFailed}
          </p>
        ) : (
          <>
          {vpn?.overridden && (
            <Banner tone="warn" title={copy.vpn.overridden.title(vpn.names)} className="zs-cov__vpn">
              {copy.vpn.overridden.text}
            </Banner>
          )}
          {vpn && <p className="zs-cov__hint zs-cov__vpn-line">{copy.vpn.untouched(vpn.names)}</p>}
          <Rows>
            {snapshot.chained_proxy && (
              <Row
                icon="pulse"
                title={copy.chain.title(snapshot.chained_proxy)}
                sub={copy.chain.sub}
                trail={<Badge tone="info">{copy.chain.badge}</Badge>}
              />
            )}
            {apps.length === 0 && !snapshot.chained_proxy && (
              <li className="zs-cov__empty">{copy.empty}</li>
            )}
            {apps.map((app) => (
              <AppRow
                key={app.id}
                app={app}
                snapshot={snapshot}
                waiting={waiting}
                now={now}
                open={open[app.id] ?? false}
                onToggle={() => setOpen((prev) => ({ ...prev, [app.id]: !prev[app.id] }))}
                copiedId={copiedId}
                onCopy={copyText}
                onConfirm={() => void confirmSetup(app.id)}
                enabling={enabling === app.id}
                onEnable={(kind) => void enable(app, kind)}
                canEnable={{ sysproxy: Boolean(onToggleSysproxy), cli: Boolean(onToggleCli) }}
              />
            ))}
          </Rows>
          </>
        )}
      </Card>
    </Section>
  );
}

interface AppRowProps {
  app: AppCoverageItem;
  snapshot: CoverageSnapshot;
  waiting: WaitingMap;
  now: number;
  open: boolean;
  onToggle: () => void;
  copiedId: string | null;
  onCopy: (id: string, value: string) => void;
  onConfirm: () => void;
  enabling: boolean;
  onEnable: (kind: "sysproxy" | "cli") => void;
  canEnable: { sysproxy: boolean; cli: boolean };
}

function AppRow({ app, snapshot, waiting, now, open, onToggle, copiedId, onCopy, onConfirm, enabling, onEnable, canEnable }: AppRowProps) {
  const setup = useMemo(() => buildManualSetup(app, snapshot), [app, snapshot]);
  const view = viewOf(app, waiting, now, snapshot.cli_mode);
  if (view === "not_installed") return null;
  const badge = BADGES[view];
  const since = sinceLastSeen(app, now);
  const sub = view === "confirmed" && app.ai_requests > 0 ? copy.seen(app.ai_requests, since) : app.detail;
  const trail = (
    <Badge tone={badge.tone} icon={badge.icon}>
      {badge.label}
    </Badge>
  );

  // Без шагов раскрывать нечего: обычная строка.
  if (setup.steps.length === 0) {
    return <Row icon={ICONS[app.category]} tone={rowTone(view)} title={app.name} sub={sub} trail={trail} />;
  }

  const canToggleProtection = setup.protection ? canEnable[setup.protection] : false;

  return (
    <ExpandRow
      icon={ICONS[app.category]}
      tone={rowTone(view)}
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
        {setup.protection && !canToggleProtection && <p className="zs-cov__hint">{copy.hints.protectionOnOverview}</p>}
        {setup.protection && canToggleProtection && (
          <div className="zs-cov__actions">
            <Button size="sm" variant="primary" icon="power" disabled={enabling} onClick={() => onEnable(setup.protection!)}>
              {enabling ? copy.enableProtectionBusy : copy.enableProtection}
            </Button>
          </div>
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
                  copyLabel={b.kind === "address" ? copy.copyAddress : common.copy}
                  copiedLabel={copy.copied}
                  copyAriaLabel={b.kind === "address" ? copy.copyAddressAria(b.label) : undefined}
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
