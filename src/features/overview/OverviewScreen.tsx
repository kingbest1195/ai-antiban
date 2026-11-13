import { useState } from "react";
import type { ReactNode } from "react";
import type {
  AppStateData,
  CoverageSnapshot,
  GatewayStatsSnapshot,
  PartialAudit,
  ProviderId,
  RiskReport,
  UpdateCheckResult,
} from "../../types";
import {
  Badge,
  Banner,
  Button,
  Card,
  ConfirmModal,
  EmptyState,
  ExpandRow,
  Menu,
  Row,
  Rows,
  Section,
  Spinner,
  Stat,
  Stats,
  StatusHero,
  Switch,
} from "../../ui";
import type { MenuEntry } from "../../ui";
import { checks as checksCopy, coverage as coverageCopy, overview as copy, providers as providerCopy, status as words } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";
import { formatNumber } from "../../shared/lib/format";
import type { ProtectionActions, ShowToast } from "../../shared/hooks";
import { CoverageSection } from "../coverage/CoverageSection";
import { buildPendingChecks, failedChecks, progressOf } from "../checks/checksModel";
import { needsForceConfirm, useOverviewModel } from "./useOverviewModel";
import type { ServiceModel } from "./useOverviewModel";

export interface OverviewScreenProps {
  reports: Partial<Record<ProviderId, RiskReport>>;
  activeReport: RiskReport | null;
  state: AppStateData | null;
  refreshing: boolean;
  auditError: string | null;
  /** Шлюз ещё запускается в фоне: защита не включена, состояние не известно. */
  startupPending?: boolean;
  /** Что уже готово в первом аудите, пока отчёта нет. */
  partial?: PartialAudit | null;
  currentIp: string;
  trustScore: number;
  gatewayStats: GatewayStatsSnapshot | null;
  updateInfo: UpdateCheckResult | null;
  coverageSnapshot?: CoverageSnapshot | null;
  /** Возраст данных в минутах, если отчёт устарел или аудит упал; иначе null. */
  dataAgeMinutes?: number | null;

  sysproxyActive: boolean;
  cliProtected: boolean;
  killswitchFrozen: boolean;
  onToggleSysproxy: () => void;
  onToggleCli: () => void;
  onToggleKillswitch: () => void;
  /** Явные «включить» и «выключить» защиты для карточек «Покрытия» (кнопка не переключатель). */
  protection?: ProtectionActions;
  /** Тосты секции покрытия (например, ошибка копирования адреса). */
  onToast?: ShowToast;

  onCopyIp: () => void;
  onPinIp: (ip: string) => void;
  onUnpinIp: () => void;
  onToggleStrict: () => void;
  onAllowProvider: (provider: ProviderId) => void;
  onUnblockProvider: (provider: ProviderId) => void;
  onVerifyAndUnblockProvider?: (provider: ProviderId) => Promise<boolean>;

  onRetry: () => void;
  /** «Что исправить» у сервиса: открыть «Проверки» с его отчётом. */
  onFixService: (provider: ProviderId) => void;
  onOpenChecks: () => void;
  onOpenTimezone: () => void;
  onOpenUpdate: () => void;
  onOpenCrashTest: () => void;
}

/** Цифры дня, пока данных нет: прочерк, а не «0» (ноль — это уже известный ответ). */
const EMPTY_STAT = "—";

/** Экран «Обзор»: вердикт, сервисы ИИ, что под защитой, цифры за день, два действия. */
export function OverviewScreen(props: OverviewScreenProps) {
  const {
    reports,
    activeReport,
    state,
    refreshing,
    auditError,
    startupPending = false,
    partial,
    currentIp,
    trustScore,
    gatewayStats,
    updateInfo,
    coverageSnapshot,
    sysproxyActive,
    cliProtected,
    killswitchFrozen,
  } = props;

  // Ожидание данных: отчёта ещё нет (и это не окончательная ошибка) либо шлюз ещё запускается.
  const loading = (!activeReport && (!auditError || startupPending)) || (startupPending && !killswitchFrozen);
  const failed = !loading && !activeReport && Boolean(auditError);

  const model = useOverviewModel({
    reports,
    activeReport,
    state,
    currentIp,
    sysproxyActive,
    killswitchFrozen,
    updateInfo,
    refreshing: refreshing || loading,
    startupPending,
  });

  // Подтверждение «Разрешить принудительно»: только когда сеть действительно красная / RU / BY.
  const [pendingAllow, setPendingAllow] = useState<ProviderId | null>(null);
  const [verifyingAllow, setVerifyingAllow] = useState<ProviderId | null>(null);
  const runAllow = (provider: ProviderId, blockedByUser: boolean) => {
    if (blockedByUser) props.onUnblockProvider(provider);
    props.onAllowProvider(provider);
  };
  const requestAllow = async (service: ServiceModel, report: RiskReport | undefined, blockedByUser: boolean) => {
    if (blockedByUser && !needsForceConfirm(service.status, report) && props.onVerifyAndUnblockProvider) {
      setVerifyingAllow(service.id);
      try {
        const unblocked = await props.onVerifyAndUnblockProvider(service.id);
        if (!unblocked) {
          setPendingAllow(service.id);
        }
      } finally {
        setVerifyingAllow(null);
      }
      return;
    }
    if (needsForceConfirm(service.status, report)) setPendingAllow(service.id);
    else runAllow(service.id, blockedByUser);
  };

  const progress = progressOf(buildPendingChecks(partial ?? null, state));

  return (
    <>
      {!loading && !failed && <ProblemBanner kind={model.banner} {...props} />}

      {loading ? (
        <HeroChecking startup={startupPending} done={progress.done} total={progress.total} />
      ) : failed ? (
        <Card>
          <EmptyState
            icon="alert"
            title={copy.error.title}
            action={
              <Button variant="primary" icon="refresh" onClick={props.onRetry} disabled={refreshing}>
                {copy.error.action}
              </Button>
            }
          >
            {copy.error.text}
          </EmptyState>
        </Card>
      ) : (
        <StatusHero
          score={trustScore}
          tone={model.tone}
          title={model.verdict}
          ip={currentIp !== "--" ? currentIp : undefined}
          country={currentIp !== "--" ? countryName(activeReport?.telemetry.country_code) || undefined : undefined}
          facts={<HeroFacts model={model} {...props} />}
        >
          <Row
            as="div"
            className="zs-hero__switch"
            title={copy.guard.title}
            sub={startupPending ? copy.guard.startingText : sysproxyActive ? copy.guard.onText : copy.guard.offText}
            trail={<Switch checked={sysproxyActive} onChange={props.onToggleSysproxy} aria-label={copy.guard.label} />}
          />
        </StatusHero>
      )}

      {!failed && (
        <Section title={copy.sectionServices}>
          <Card>
            <Rows>
              {model.services.map((service) => (
                <ServiceRow
                  key={service.id}
                  service={service}
                  report={reports[service.id]}
                  state={state}
                  onFix={props.onFixService}
                  onAllow={requestAllow}
                  blockedByUser={Boolean(state?.blocked_providers?.includes(service.id))}
                  verifying={verifyingAllow === service.id}
                />
              ))}
            </Rows>
          </Card>
        </Section>
      )}

      <ConfirmModal
        open={pendingAllow !== null}
        title={pendingAllow ? copy.service.confirm.title(providerCopy[pendingAllow].name) : ""}
        confirmLabel={copy.service.confirm.action}
        onCancel={() => setPendingAllow(null)}
        onConfirm={() => {
          if (pendingAllow) runAllow(pendingAllow, Boolean(state?.blocked_providers?.includes(pendingAllow)));
          setPendingAllow(null);
        }}
      >
        {pendingAllow ? copy.service.confirm.text(providerCopy[pendingAllow].name) : ""}
      </ConfirmModal>

      <Section title={copy.sectionProtected}>
        {props.protection?.adminAuthMessage && (
          <Banner
            tone="warn"
            title={coverageCopy.protection.adminAuthTitle}
            action={
              <Button
                size="sm"
                variant="primary"
                disabled={props.protection.retryingAdminAuth}
                onClick={() => void props.protection?.enableSysproxyPrivileged()}
              >
                {props.protection.retryingAdminAuth
                  ? coverageCopy.protection.adminAuthBusy
                  : coverageCopy.protection.adminAuthRetry}
              </Button>
            }
          >
            {props.protection.adminAuthMessage}
          </Banner>
        )}
        <Card>
          <Rows>
            <Row
              icon="globe"
              title={copy.browsers.title}
              sub={copy.browsers.sub}
              trail={startupPending ? <PendingBadge /> : <Switch checked={sysproxyActive} onChange={props.onToggleSysproxy} aria-label={copy.browsers.title} />}
            />
            <Row
              icon="shield"
              title={copy.desktopApps.title}
              sub={copy.desktopApps.sub}
              trail={startupPending ? <PendingBadge /> : <Switch checked={sysproxyActive} onChange={props.onToggleSysproxy} aria-label={copy.desktopApps.title} />}
            />
            <Row
              icon="term"
              title={copy.editors.title}
              sub={copy.editors.sub}
              trail={startupPending ? <PendingBadge /> : <Switch checked={cliProtected} onChange={props.onToggleCli} aria-label={copy.editors.title} />}
            />
          </Rows>
        </Card>
      </Section>

      <CoverageSection
        variant="overview"
        initialSnapshot={coverageSnapshot}
        pending={startupPending}
        protection={props.protection}
        onToast={props.onToast}
      />

      <Section title={copy.sectionToday}>
        <Stats>
          <Stat layer={1} value={gatewayStats ? formatNumber(gatewayStats.protected_ai_requests) : EMPTY_STAT} label={copy.stats.requests} />
          <Stat
            layer={1}
            tone={(gatewayStats?.intercepted_leaks ?? 0) > 0 ? "danger" : "neutral"}
            value={gatewayStats ? formatNumber(gatewayStats.intercepted_leaks) : EMPTY_STAT}
            label={copy.stats.leaks}
          />
          <Stat layer={1} value={gatewayStats ? formatNumber(gatewayStats.direct_bypassed_requests) : EMPTY_STAT} label={copy.stats.direct} />
        </Stats>
      </Section>

      <div className="zs-app__actions">
        <Button icon="pulse" onClick={props.onOpenCrashTest}>
          {copy.actions.crashTest}
        </Button>
        {killswitchFrozen ? (
          <Button variant="primary" icon="refresh" onClick={props.onToggleKillswitch}>
            {copy.actions.resumeNetwork}
          </Button>
        ) : (
          <Button variant="danger" icon="power" onClick={props.onToggleKillswitch}>
            {copy.actions.stopNetwork}
          </Button>
        )}
      </div>
    </>
  );
}

/* ---------- Баннер: один на экран, одно действие ---------- */

function ProblemBanner({ kind, ...props }: { kind: ReturnType<typeof useOverviewModel>["banner"] } & OverviewScreenProps) {
  if (!kind) return null;
  const openChecks = (
    <Button size="sm" onClick={props.onOpenChecks}>
      {copy.banner.openChecks}
    </Button>
  );
  switch (kind) {
    case "frozen":
      return (
        <Banner tone="warn" title={copy.banner.frozen.title}>
          {copy.banner.frozen.text}
        </Banner>
      );
    case "stopped":
      return (
        <Banner tone="danger" role="alert" title={copy.banner.stopped.title} action={openChecks}>
          {copy.banner.stopped.text}
        </Banner>
      );
    case "leak":
      return (
        <Banner tone="danger" title={copy.banner.leak.title} action={openChecks}>
          {copy.banner.leak.text}
        </Banner>
      );
    case "timezone":
      return (
        <Banner
          tone="warn"
          title={copy.banner.timezone.title}
          action={
            <Button size="sm" onClick={props.onOpenTimezone}>
              {copy.banner.timezone.action}
            </Button>
          }
        >
          {copy.banner.timezone.text}
        </Banner>
      );
    case "review":
      return (
        <Banner tone="warn" title={copy.banner.review.title} action={openChecks}>
          {copy.banner.review.text}
        </Banner>
      );
    case "incomplete":
      return (
        <Banner
          tone="neutral"
          title={copy.banner.incomplete.title}
          action={
            <Button size="sm" onClick={props.onRetry}>
              {copy.banner.incomplete.action}
            </Button>
          }
        >
          {copy.banner.incomplete.text}
        </Banner>
      );
    case "update":
      return (
        <Banner
          tone="info"
          icon="zap"
          title={copy.banner.update.title(props.updateInfo?.latest_version ?? "")}
          action={
            <Button size="sm" onClick={props.onOpenUpdate}>
              {copy.banner.update.action}
            </Button>
          }
        >
          {copy.banner.update.text}
        </Banner>
      );
  }
}

/* ---------- Бейджи под вердиктом ---------- */

function HeroFacts({ model, ...props }: { model: ReturnType<typeof useOverviewModel> } & OverviewScreenProps) {
  const allPassed = model.checksTotal > 0 && model.checksPassed === model.checksTotal;
  const pinned = props.state?.pinned_ip != null;
  const strict = Boolean(props.state?.strict_pinning_enabled);

  const menu: MenuEntry[] = [
    { id: "copy", label: copy.ipMenu.copy, icon: "copy", onSelect: props.onCopyIp },
    ...(pinned
      ? ([
          {
            id: "strict",
            label: strict ? copy.ipMenu.strictOff : copy.ipMenu.strictOn,
            icon: "lock",
            onSelect: props.onToggleStrict,
          },
          { id: "unpin", label: copy.ipMenu.unpin, icon: "x", onSelect: props.onUnpinIp },
        ] as MenuEntry[])
      : ([
          {
            id: "pin",
            label: copy.ipMenu.pin,
            icon: "lock",
            disabled: props.currentIp === "--",
            onSelect: () => props.onPinIp(props.currentIp),
          },
        ] as MenuEntry[])),
  ];

  const extra: ReactNode =
    model.pinState === "pinned" ? (
      <Badge icon="lock">{copy.facts.pinned}</Badge>
    ) : model.pinState === "changed" ? (
      <Badge tone="warn" icon="alert">
        {copy.facts.pinChanged}
      </Badge>
    ) : props.state?.upstream_proxy?.enabled ? (
      <Badge icon="key">{copy.facts.key}</Badge>
    ) : null;

  return (
    <>
      <Badge tone={allPassed ? "ok" : "warn"} icon={allPassed ? "check" : "alert"}>
        {model.checksLabel}
      </Badge>
      {props.dataAgeMinutes != null && (
        <Badge tone={props.auditError ? "warn" : "neutral"} icon={props.auditError ? "alert" : undefined}>
          {checksCopy.dataAge(props.dataAgeMinutes, Boolean(props.auditError))}
        </Badge>
      )}
      {model.providerName && <Badge>{model.providerName}</Badge>}
      {extra}
      <Menu items={menu} label={copy.ipMenu.label} align="end" className="-my-1" />
    </>
  );
}

/* ---------- Строка сервиса ---------- */

function ServiceRow({
  service,
  report,
  state,
  blockedByUser,
  verifying,
  onFix,
  onAllow,
}: {
  service: ServiceModel;
  report: RiskReport | undefined;
  state: AppStateData | null;
  blockedByUser: boolean;
  verifying?: boolean;
  onFix: (provider: ProviderId) => void;
  onAllow: (service: ServiceModel, report: RiskReport | undefined, blockedByUser: boolean) => void;
}) {
  const [open, setOpen] = useState(false);
  const meta = providerCopy[service.id];
  const { status } = service;

  let badge: ReactNode;
  let note: string | null = null;
  let tone: "neutral" | "ok" | "warn" | "danger" = "ok";

  switch (status) {
    case "ok":
      badge = <Badge tone="ok">{words.available}</Badge>;
      break;
    case "allowed":
      badge = <Badge tone="ok">{words.available}</Badge>;
      note = copy.service.session;
      break;
    case "warn":
      badge = (
        <Badge tone="warn" icon="alert">
          {words.review}
        </Badge>
      );
      tone = "warn";
      break;
    case "critical":
      badge = (
        <Badge tone="danger" icon="alert">
          {words.blocked}
        </Badge>
      );
      tone = "danger";
      break;
    case "checking":
      badge = <Badge busy>{copy.service.checking}</Badge>;
      tone = "neutral";
      break;
    case "missing":
      badge = (
        <Badge tone="warn" icon="alert">
          {words.review}
        </Badge>
      );
      note = copy.service.missing;
      tone = "warn";
      break;
  }

  const sub = (
    <>
      <span className="block">{meta.domains}</span>
      {note && <span className="block">{note}</span>}
    </>
  );

  // Решение по сервису принимается здесь: раскрываем только строки, где есть проблема.
  if (status !== "warn" && status !== "critical") {
    return (
      <Row
        icon={status === "ok" || status === "allowed" || status === "checking" ? "shield" : "alert"}
        tone={tone}
        title={meta.name}
        sub={sub}
        trail={badge}
      />
    );
  }

  const first = report ? failedChecks(report, state)[0] : undefined;
  const reason = first ? `${first.title}. ${first.result.message}` : status === "critical" ? copy.service.blocked : copy.service.noReason;

  return (
    <ExpandRow
      icon="alert"
      tone={tone}
      title={meta.name}
      sub={sub}
      trail={badge}
      open={open}
      onToggle={() => setOpen((v) => !v)}
      detailLabel={copy.service.detailLabel}
    >
      <p className="zs-t-body">{reason}</p>
      <div className="flex flex-wrap gap-2">
        {report && (
          <Button size="sm" onClick={() => onFix(service.id)}>
            {copy.service.fix}
          </Button>
        )}
        <Button variant="quiet" size="sm" disabled={verifying} onClick={() => onAllow(service, report, blockedByUser)}>
          {blockedByUser ? copy.service.unblock : copy.service.forceAllow}
        </Button>
      </div>
      <p className="zs-t-caption">
        {blockedByUser && !needsForceConfirm(service.status, report) ? copy.service.unblockHint : copy.service.forceHint}
      </p>
    </ExpandRow>
  );
}

/* ---------- Загрузка ---------- */

/** Герой, пока данных нет: не «Опасно» и не «Защищены», а ожидание с прогрессом проверок. */
function HeroChecking({ startup, done, total }: { startup: boolean; done: number; total: number }) {
  return (
    <Card aria-label={copy.checking.title}>
      <div className="zs-hero" role="status" aria-busy="true">
        <Spinner size={40} />
        <div className="zs-hero__body">
          <h2 className="zs-hero__title">{startup ? copy.checking.startingTitle : copy.checking.title}</h2>
          <p className="zs-hero__meta">{startup ? copy.checking.startingText : copy.checking.text}</p>
          {done > 0 && <p className="zs-hero__meta">{copy.checking.progress(done, total)}</p>}
        </div>
      </div>
    </Card>
  );
}

/** Вместо тумблера, пока защита запускается: состояние ещё не известно. */
function PendingBadge() {
  return <Badge busy>{copy.service.checking}</Badge>;
}
