import { useEffect, useMemo, useState } from "react";
import type { AppCoverageItem, CoverageSnapshot } from "../../types";
import { restartAppWithGateway } from "../../utils/api";
import { Badge, Banner, Button, Card, ConfirmModal, CopyBlock, ExpandRow, Progress, Row, Rows, Section, Skeleton, Spinner, Steps } from "../../ui";
import type { BadgeTone, IconName, RowTone } from "../../ui";
import { coverage as copy } from "../../shared/copy/ru";
import type { ProtectionActions, ShowToast } from "../../shared/hooks";
import { useCopy } from "../guides/useCopy";
import { buildManualSetup } from "./manualSetup";
import { canRestartAntigravity, enableResult, isListed, isProtectionOn, protectedAppNames, protectionControl, restartResult, sinceLastSeen, viewOf, vpnNotice } from "./coverageModel";
import type { CoverageView, ProtectionKind, ProtectionResult, WaitingMap } from "./coverageModel";
import { useCoverage } from "./useCoverage";
import "./coverage.css";

/** Перезапуск через шлюз есть только на macOS; на Windows и Linux остаётся ручная команда. */
const IS_MAC = typeof navigator !== "undefined" && /Mac/i.test(navigator.platform || navigator.userAgent || "");

export interface CoverageSectionProps {
  /** overview — только установленные или с трафиком; checks — все приложения шлюза. */
  variant: "overview" | "checks";
  /** Снимок, который экран уже знает: показывается, пока не пришёл свежий. */
  initialSnapshot?: CoverageSnapshot | null;
  /** Застава ещё запускается в фоне: статусы приложений пока не определены, вместо них «Проверяем…». */
  pending?: boolean;
  /** Явные «включить» и «выключить» защиты; без них кнопка защиты в карточке не показывается. */
  protection?: ProtectionActions;
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
export function CoverageSection({ variant, initialSnapshot, pending, protection, onToast }: CoverageSectionProps) {
  const { snapshot, failed, checking, waiting, now, refresh, recheck, confirmSetup } = useCoverage(initialSnapshot);
  const { copiedId, copy: copyText } = useCopy(onToast);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  /** Какая защита сейчас применяется: кнопки этой группы заблокированы, показан индикатор. */
  const [busy, setBusy] = useState<{ kind: ProtectionKind; action: "enable" | "disable" } | null>(null);
  const [confirmOff, setConfirmOff] = useState<ProtectionKind | null>(null);
  const [result, setResult] = useState<ProtectionResult | null>(null);
  /** Подтверждение перезапуска Antigravity открыто / перезапуск идёт (до 15 секунд ожидания закрытия). */
  const [confirmRestart, setConfirmRestart] = useState(false);
  const [restarting, setRestarting] = useState(false);

  // Как только запуск закончился, читаем состояние заново: снимок до этого описывал выключенную защиту.
  useEffect(() => {
    if (!pending) void refresh();
  }, [pending, refresh]);

  const showPending = pending || (!snapshot && !failed);

  const apps = useMemo(() => (snapshot?.apps ?? []).filter((a) => isListed(a, variant)), [snapshot, variant]);
  const vpn = useMemo(() => (snapshot ? vpnNotice(snapshot) : null), [snapshot]);

  /** «Включить»: только включает; итог берётся из ответа команды и показывается строкой и тостом. */
  const enable = async (kind: ProtectionKind) => {
    if (!protection || busy) return;
    setBusy({ kind, action: "enable" });
    setResult(null);
    try {
      let outcome: ProtectionResult;
      if (kind === "sysproxy") {
        const on = await protection.enableSysproxy();
        outcome = on ? enableResult(kind, null, snapshot?.apps ?? []) : { tone: "danger", title: copy.protection.result.failedTitle, text: "" };
      } else {
        outcome = enableResult(kind, await protection.enableCli(), snapshot?.apps ?? []);
      }
      setResult(outcome);
      // Ошибку команды уже показал обработчик защиты; успех и предупреждения объявляем здесь.
      if (outcome.tone !== "danger" || outcome.text) onToast?.(outcome.title, outcome.text || undefined, outcome.tone === "ok" ? "success" : outcome.tone === "warn" ? "warning" : "error");
    } finally {
      setBusy(null);
      void refresh();
    }
  };

  /** «Выключить»: только после подтверждения. */
  const disable = async (kind: ProtectionKind) => {
    if (!protection || busy) return;
    setBusy({ kind, action: "disable" });
    setResult(null);
    try {
      const off = kind === "sysproxy" ? await protection.disableSysproxy() : await protection.disableCli();
      if (off) {
        const out: ProtectionResult = { tone: "ok", title: copy.protection.result.disabledTitle[kind], text: copy.protection.result.disabledText };
        setResult(out);
        onToast?.(out.title, out.text, "info");
      } else {
        setResult({ tone: "danger", title: copy.protection.result.failedTitleOff, text: "" });
      }
    } finally {
      setBusy(null);
      setConfirmOff(null);
      void refresh();
    }
  };

  /** «Перезапустить»: после подтверждения; итог — строкой и тостом, статус перечитывается. */
  const restart = async () => {
    if (restarting) return;
    setConfirmRestart(false);
    setRestarting(true);
    setResult(null);
    try {
      const outcome = await restartAppWithGateway("antigravity");
      const out = restartResult(outcome);
      setResult(out);
      onToast?.(out.title, out.text, out.tone === "ok" ? "success" : out.tone === "warn" ? "warning" : "error");
    } finally {
      setRestarting(false);
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
          {result && (
            <Banner tone={result.tone} title={result.title} className="zs-cov__vpn" action={<Button size="sm" variant="quiet" onClick={() => setResult(null)}>{copy.protection.dismiss}</Button>}>
              {result.text}
            </Banner>
          )}
          {variant === "checks" && protection?.adminAuthMessage && (
            <Banner
              tone="warn"
              title={copy.protection.adminAuthTitle}
              className="zs-cov__vpn"
              action={
                <Button
                  size="sm"
                  variant="primary"
                  disabled={busy !== null || protection.retryingAdminAuth}
                  onClick={() => {
                    void protection.enableSysproxyPrivileged().then((ok) => {
                      if (ok) void refresh();
                    });
                  }}
                >
                  {protection.retryingAdminAuth ? copy.protection.adminAuthBusy : copy.protection.adminAuthRetry}
                </Button>
              }
            >
              {protection.adminAuthMessage}
            </Banner>
          )}
          {restarting && <Progress label={copy.restart.progress} className="zs-cov__vpn" />}
          {busy && <Progress label={busy.action === "enable" ? copy.protection.inProgress : copy.protection.inProgressOff} className="zs-cov__vpn" />}
          <Rows>
            {snapshot.chained_proxy && (
              <Row
                className="zs-cov__row"
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
                busy={busy}
                onEnable={(kind) => void enable(kind)}
                onAskDisable={(kind) => setConfirmOff(kind)}
                canControl={Boolean(protection)}
                canRestart={canRestartAntigravity(app, viewOf(app, waiting, now, snapshot.cli_mode), snapshot, IS_MAC)}
                restarting={restarting}
                onAskRestart={() => setConfirmRestart(true)}
              />
            ))}
          </Rows>
          <ConfirmModal
            open={confirmOff !== null}
            title={confirmOff ? copy.protection.confirm.title[confirmOff] : ""}
            confirmLabel={copy.protection.confirm.confirm}
            busy={busy?.action === "disable"}
            busyLabel={copy.protection.disableBusy}
            onConfirm={() => confirmOff && void disable(confirmOff)}
            onCancel={() => setConfirmOff(null)}
          >
            {confirmOff ? copy.protection.confirm.text(protectedAppNames(confirmOff, snapshot.apps), confirmOff) : ""}
          </ConfirmModal>
          <ConfirmModal
            open={confirmRestart}
            title={copy.restart.confirm.title}
            confirmLabel={copy.restart.confirm.confirm}
            onConfirm={() => void restart()}
            onCancel={() => setConfirmRestart(false)}
          >
            {copy.restart.confirm.text}
          </ConfirmModal>
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
  busy: { kind: ProtectionKind; action: "enable" | "disable" } | null;
  onEnable: (kind: ProtectionKind) => void;
  onAskDisable: (kind: ProtectionKind) => void;
  /** Есть ли у экрана команды включения и выключения защиты. */
  canControl: boolean;
  /** Показать «Перезапустить Antigravity с защитой» (macOS, не подтверждено трафиком). */
  canRestart: boolean;
  restarting: boolean;
  onAskRestart: () => void;
}

function AppRow({ app, snapshot, waiting, now, open, onToggle, copiedId, onCopy, onConfirm, busy, onEnable, onAskDisable, canControl, canRestart, restarting, onAskRestart }: AppRowProps) {
  const setup = useMemo(() => buildManualSetup(app, snapshot), [app, snapshot]);
  const view = viewOf(app, waiting, now, snapshot.cli_mode);
  if (view === "not_installed") return null;
  const badge = BADGES[view];
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

  // Без шагов раскрывать нечего: обычная строка.
  if (setup.steps.length === 0) {
    return <Row className="zs-cov__row" icon={ICONS[app.category]} tone={rowTone(view)} title={app.name} sub={sub} trail={trail} />;
  }

  const kind = setup.protection;
  const control = kind ? protectionControl(isProtectionOn(kind, snapshot), busy?.kind === kind) : null;

  return (
    <ExpandRow
      className="zs-cov__row"
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
        {canRestart && (
          <div className="zs-cov__actions">
            <Button size="sm" variant="primary" icon="refresh" disabled={restarting || busy !== null} aria-busy={restarting} onClick={onAskRestart}>
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
            <Button size="sm" variant="primary" icon="power" disabled={control.busy || busy !== null} aria-busy={control.busy} onClick={() => onEnable(kind)}>
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
              <Button size="sm" variant="quiet" disabled={busy !== null} aria-label={copy.protection.disableAria(copy.protection.on[kind])} onClick={() => onAskDisable(kind)}>
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
