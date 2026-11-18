import { useEffect, useMemo, useState } from "react";
import type { CoverageSnapshot } from "../../types";
import { reapplyBrowserPolicies, relaunchBrowsersWithPac, restartAppWithGateway } from "../../utils/api";
import { Badge, Banner, Button, Card, ConfirmModal, Progress, Row, Rows, Section, Skeleton, Spinner } from "../../ui";
import { CopyErrorLogButton } from "../../shared/components/CopyErrorLogButton";
import { coverage as copy } from "../../shared/copy/ru";
import type { ProtectionActions, ShowToast } from "../../shared/hooks";
import { useOsTimezoneSync } from "../../shared/hooks/useTimezoneSync";
import { useCopy } from "../guides/useCopy";
import {
  browserPacStatus,
  canRestartAntigravity,
  enableResult,
  isListed,
  protectedAppNames,
  relaunchBrowsersResult,
  restartResult,
  shouldShowBrowserTimezoneHint,
  viewOf,
  vpnNotice,
} from "./coverageModel";
import type { ProtectionKind, ProtectionResult } from "./coverageModel";
import { CoverageAppRow } from "./CoverageAppRow";
import { CoverageLegend } from "./CoverageBadges";
import { CoverageVpnBanner } from "./CoverageVpnBanner";
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
  /** Показать сворачиваемую расшифровку статусов под заголовком. */
  legend?: boolean;
}

/** Секция «Покрытие приложений»: одна реализация для «Обзора» и «Проверок». */
export function CoverageSection({
  variant,
  initialSnapshot,
  pending,
  protection,
  onToast,
  legend = true,
}: CoverageSectionProps) {
  const { snapshot, failed, checking, waiting, now, refresh, recheck, confirmSetup, applySnapshot } = useCoverage(initialSnapshot);
  const { copiedId, copy: copyText } = useCopy(onToast);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState<{ kind: ProtectionKind; action: "enable" | "disable" } | null>(null);
  const [confirmOff, setConfirmOff] = useState<ProtectionKind | null>(null);
  const [result, setResult] = useState<ProtectionResult | null>(null);
  const [confirmRestart, setConfirmRestart] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [linkingBrowsers, setLinkingBrowsers] = useState(false);
  const [relaunchingBrowsers, setRelaunchingBrowsers] = useState(false);
  const { osTzStatus, osTzLoading, syncOsTimezone } = useOsTimezoneSync();

  useEffect(() => {
    if (!pending) void refresh();
  }, [pending, refresh]);

  const showPending = pending || (!snapshot && !failed);
  const apps = useMemo(() => (snapshot?.apps ?? []).filter((a) => isListed(a, variant)), [snapshot, variant]);
  const vpn = useMemo(() => (snapshot ? vpnNotice(snapshot) : null), [snapshot]);
  const browserPac = useMemo(() => (snapshot ? browserPacStatus(snapshot) : null), [snapshot]);
  const showBrowserTzHint = useMemo(
    () => shouldShowBrowserTimezoneHint(snapshot?.apps, osTzStatus),
    [snapshot?.apps, osTzStatus],
  );

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
      if (outcome.tone !== "danger" || outcome.text) {
        onToast?.(outcome.title, outcome.text || undefined, outcome.tone === "ok" ? "success" : outcome.tone === "warn" ? "warning" : "error");
      }
    } finally {
      setBusy(null);
      void refresh();
    }
  };

  const disable = async (kind: ProtectionKind) => {
    if (!protection || busy) return;
    setBusy({ kind, action: "disable" });
    setResult(null);
    try {
      const off = kind === "sysproxy" ? await protection.disableSysproxy() : await protection.disableCli();
      if (off) {
        const deferredText = typeof off === "object" ? off.deferred : undefined;
        const out: ProtectionResult = {
          tone: deferredText ? "warn" : "ok",
          title: copy.protection.result.disabledTitle[kind],
          text: deferredText ?? copy.protection.result.disabledText,
        };
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

  const linkBrowsers = async () => {
    if (linkingBrowsers) return;
    setLinkingBrowsers(true);
    try {
      await reapplyBrowserPolicies();
      onToast?.(copy.vpn.actions.policyToastTitle, undefined, "success");
      await recheck();
    } catch (err: unknown) {
      onToast?.(copy.vpn.actions.policyToastError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setLinkingBrowsers(false);
    }
  };

  const relaunchBrowsers = async () => {
    if (relaunchingBrowsers) return;
    setRelaunchingBrowsers(true);
    setResult(null);
    try {
      const res = await relaunchBrowsersWithPac();
      applySnapshot(res.snapshot);
      const out = relaunchBrowsersResult(res);
      setResult(out);
      onToast?.(out.title, out.text, out.tone === "ok" ? "success" : out.tone === "warn" ? "warning" : "error");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      const out: ProtectionResult = { tone: "danger", title: copy.vpn.restartNeeded.relaunchErrorTitle, text: msg };
      setResult(out);
      onToast?.(out.title, msg, "error");
    } finally {
      setRelaunchingBrowsers(false);
    }
  };

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
        {legend && <CoverageLegend />}
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
            <CoverageVpnBanner
              vpn={vpn}
              browserPac={browserPac}
              relaunchingBrowsers={relaunchingBrowsers}
              linkingBrowsers={linkingBrowsers}
              checking={checking}
              onRelaunchBrowsers={() => void relaunchBrowsers()}
              onLinkBrowsers={() => void linkBrowsers()}
              onRecheck={() => void recheck()}
            />
            {vpn && !vpn.overridden && <p className="zs-cov__hint zs-cov__vpn-line">{copy.vpn.untouched(vpn.names)}</p>}
            {result && (
              <Banner
                tone={result.tone}
                title={result.title}
                className="zs-cov__vpn"
                action={
                  <div className="zs-banner__actions">
                    {result.tone === "danger" && <CopyErrorLogButton title={result.title} message={result.text} />}
                    <Button size="sm" variant="quiet" onClick={() => setResult(null)}>
                      {copy.protection.dismiss}
                    </Button>
                  </div>
                }
              >
                {result.text}
              </Banner>
            )}
            {variant === "checks" && protection?.adminAuthMessage && (
              <Banner
                tone="warn"
                title={copy.protection.adminAuthTitle}
                className="zs-cov__vpn"
                action={
                  <div className="zs-banner__actions">
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
                    <CopyErrorLogButton title={copy.protection.adminAuthTitle} message={protection.adminAuthMessage} />
                  </div>
                }
              >
                {protection.adminAuthMessage}
              </Banner>
            )}
            {restarting && <Progress label={copy.restart.progress} className="zs-cov__vpn" />}
            {busy && (
              <Progress
                label={busy.action === "enable" ? copy.protection.inProgress : copy.protection.inProgressOff}
                className="zs-cov__vpn"
              />
            )}
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
              {apps.length === 0 && !snapshot.chained_proxy && <li className="zs-cov__empty">{copy.empty}</li>}
              {apps.map((app) => (
                <CoverageAppRow
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
            {showBrowserTzHint && (
              <div className="zs-cov__tz-hint" role="note">
                <p className="zs-cov__tz-hint-text">{copy.browserTz.hint}</p>
                <Button size="sm" variant="secondary" disabled={osTzLoading} onClick={() => void syncOsTimezone()}>
                  {osTzLoading ? copy.browserTz.syncing : copy.browserTz.sync}
                </Button>
              </div>
            )}
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
