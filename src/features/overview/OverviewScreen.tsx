import { useState } from "react";
import type { ReactNode } from "react";
import type { AppStateData, CoverageSnapshot, GatewayStatsSnapshot, ProviderId, RiskReport, UpdateCheckResult } from "../../types";
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
  Skeleton,
  Stat,
  Stats,
  StatusHero,
  Switch,
} from "../../ui";
import type { MenuEntry } from "../../ui";
import { checks as checksCopy, overview as copy, providers as providerCopy, status as words } from "../../shared/copy/ru";
import { countryName } from "../../shared/lib/country";
import { formatNumber } from "../../shared/lib/format";
import type { ProtectionActions, ShowToast } from "../../shared/hooks";
import { CoverageSection } from "../coverage/CoverageSection";
import { failedChecks } from "../checks/checksModel";
import { needsForceConfirm, useOverviewModel } from "./useOverviewModel";
import type { ServiceModel } from "./useOverviewModel";

export interface OverviewScreenProps {
  reports: Partial<Record<ProviderId, RiskReport>>;
  activeReport: RiskReport | null;
  state: AppStateData | null;
  refreshing: boolean;
  auditError: string | null;
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

  onRetry: () => void;
  /** «Что исправить» у сервиса: открыть «Проверки» с его отчётом. */
  onFixService: (provider: ProviderId) => void;
  onOpenChecks: () => void;
  onOpenTimezone: () => void;
  onOpenUpdate: () => void;
  onOpenCrashTest: () => void;
}

/** Экран «Обзор»: вердикт, сервисы ИИ, что под защитой, цифры за день, два действия. */
export function OverviewScreen(props: OverviewScreenProps) {
  const {
    reports,
    activeReport,
    state,
    refreshing,
    auditError,
    currentIp,
    trustScore,
    gatewayStats,
    updateInfo,
    coverageSnapshot,
    sysproxyActive,
    cliProtected,
    killswitchFrozen,
  } = props;

  const model = useOverviewModel({
    reports,
    activeReport,
    state,
    currentIp,
    sysproxyActive,
    killswitchFrozen,
    updateInfo,
    refreshing,
  });

  // Подтверждение «Разрешить принудительно»: только для красных сервисов и адреса из РФ.
  const [pendingAllow, setPendingAllow] = useState<ProviderId | null>(null);
  const runAllow = (provider: ProviderId, blockedByUser: boolean) => {
    // Как раньше: снятие блока — сначала unblock (если блок поставлен вручную), затем разрешение на сессию.
    if (blockedByUser) props.onUnblockProvider(provider);
    props.onAllowProvider(provider);
  };
  const requestAllow = (service: ServiceModel, report: RiskReport | undefined, blockedByUser: boolean) => {
    if (needsForceConfirm(service.status, report)) setPendingAllow(service.id);
    else runAllow(service.id, blockedByUser);
  };

  const loading = !activeReport && !auditError;
  const failed = !activeReport && Boolean(auditError);

  return (
    <>
      {!loading && !failed && <ProblemBanner kind={model.banner} {...props} />}

      {loading ? (
        <HeroSkeleton />
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
            sub={sysproxyActive ? copy.guard.onText : copy.guard.offText}
            trail={<Switch checked={sysproxyActive} onChange={props.onToggleSysproxy} aria-label={copy.guard.label} />}
          />
        </StatusHero>
      )}

      {!failed && (
        <Section title={copy.sectionServices}>
          <Card>
            {loading ? (
              <ServicesSkeleton />
            ) : (
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
                  />
                ))}
              </Rows>
            )}
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
        <Card>
          <Rows>
            <Row
              icon="globe"
              title={copy.browsers.title}
              sub={copy.browsers.sub}
              trail={<Switch checked={sysproxyActive} onChange={props.onToggleSysproxy} aria-label={copy.browsers.title} />}
            />
            <Row
              icon="shield"
              title={copy.desktopApps.title}
              sub={copy.desktopApps.sub}
              trail={<Switch checked={sysproxyActive} onChange={props.onToggleSysproxy} aria-label={copy.desktopApps.title} />}
            />
            <Row
              icon="term"
              title={copy.editors.title}
              sub={copy.editors.sub}
              trail={<Switch checked={cliProtected} onChange={props.onToggleCli} aria-label={copy.editors.title} />}
            />
          </Rows>
        </Card>
      </Section>

      <CoverageSection
        variant="overview"
        initialSnapshot={coverageSnapshot}
        protection={props.protection}
        onToast={props.onToast}
      />

      <Section title={copy.sectionToday}>
        <Stats>
          <Stat layer={1} value={formatNumber(gatewayStats?.protected_ai_requests ?? 0)} label={copy.stats.requests} />
          <Stat
            layer={1}
            tone={(gatewayStats?.intercepted_leaks ?? 0) > 0 ? "danger" : "neutral"}
            value={formatNumber(gatewayStats?.intercepted_leaks ?? 0)}
            label={copy.stats.leaks}
          />
          <Stat layer={1} value={formatNumber(gatewayStats?.direct_bypassed_requests ?? 0)} label={copy.stats.direct} />
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
      {props.dataAgeMinutes != null && <Badge>{checksCopy.dataAge(props.dataAgeMinutes)}</Badge>}
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
  onFix,
  onAllow,
}: {
  service: ServiceModel;
  report: RiskReport | undefined;
  state: AppStateData | null;
  blockedByUser: boolean;
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
      badge = <Badge>{copy.service.checking}</Badge>;
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
        <Button variant="quiet" size="sm" onClick={() => onAllow(service, report, blockedByUser)}>
          {blockedByUser ? copy.service.unblock : copy.service.forceAllow}
        </Button>
      </div>
      <p className="zs-t-caption">{copy.service.forceHint}</p>
    </ExpandRow>
  );
}

/* ---------- Загрузка ---------- */

function HeroSkeleton() {
  return (
    <Card aria-label="Загрузка">
      <div className="zs-hero">
        <Skeleton variant="circle" width={64} />
        <div className="zs-hero__body">
          <Skeleton width="70%" height={22} />
          <Skeleton width="50%" className="mt-2" />
        </div>
      </div>
      <Skeleton variant="block" height={24} className="mt-3" />
      <Skeleton variant="block" height={40} className="mt-4" />
    </Card>
  );
}

function ServicesSkeleton() {
  return (
    <Rows>
      {[0, 1, 2].map((i) => (
        <li key={i} className="zs-row">
          <Skeleton variant="circle" width={32} />
          <div className="zs-row__body">
            <Skeleton width="40%" />
            <Skeleton width="70%" className="mt-1" />
          </div>
          <Skeleton width={72} height={24} />
        </li>
      ))}
    </Rows>
  );
}
