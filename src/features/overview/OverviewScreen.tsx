import { useState } from "react";
import type {
  AppStateData,
  CoverageSnapshot,
  GatewayStatsSnapshot,
  GuardPauseStatus,
  PartialAudit,
  ProviderId,
  RiskReport,
  RouteUnavailablePayload,
  RoutesSnapshot,
  UpdateCheckResult,
} from "../../types";
import {
  Badge,
  Banner,
  Button,
  Card,
  ConfirmModal,
  EmptyState,
  InfoTip,
  Row,
  Rows,
  Section,
  Spinner,
  Stat,
  Stats,
  StatusHero,
  Switch,
} from "../../ui";
import { CopyErrorLogButton } from "../../shared/components/CopyErrorLogButton";
import { overview as copy, providers as providerCopy } from "../../shared/copy/ru";
import { formatCountryWithCode } from "../../shared/lib/country";
import { formatIp, formatNumber } from "../../shared/lib/format";
import { formatRemainingTimeRu, getRouteExpiryUrgency } from "../../shared/lib/zastavaKey";
import { openZastavaBot } from "../../utils/opener";
import type { ProtectionActions, ShowToast } from "../../shared/hooks";
import { useOsTimezoneSync } from "../../shared/hooks/useTimezoneSync";
import { CoverageSection } from "../coverage/CoverageSection";
import { buildPendingChecks, progressOf } from "../checks/checksModel";
import { CooldownBanner } from "./CooldownBanner";
import { HeroFacts } from "./HeroFacts";
import { ProblemBanner } from "./ProblemBanner";
import { ProtectedSection } from "./ProtectedSection";
import { ServiceRow } from "./ServiceRow";
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
  onCoverageSnapshot?: (snapshot: CoverageSnapshot) => void;
  routesSnapshot?: RoutesSnapshot | null;
  guardPauseStatus?: GuardPauseStatus | null;
  routeUnavailableBanner?: RouteUnavailablePayload | null;
  /** Скрывать ли реальный IP-адрес на экране для безопасных скриншотов. */
  hideIpMode?: boolean;
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
  onPinIp: (ip: string, provider?: ProviderId) => void;
  onUnpinIp: (provider?: ProviderId) => void;
  onToggleStrict: () => void;
  onAllowProvider: (provider: ProviderId, persistException?: boolean) => Promise<unknown> | void;
  onUnblockProvider: (provider: ProviderId) => Promise<unknown> | void;
  onVerifyAndUnblockProvider?: (provider: ProviderId) => Promise<boolean>;

  onRetry: () => void;
  /** «Что исправить» у сервиса: открыть «Проверки» с его отчётом. */
  onFixService: (provider: ProviderId) => void;
  onOpenChecks: () => void;
  onOpenTimezone: () => void;
  onOpenUpdate: () => void;
  onOpenCrashTest: () => void;
  onOpenConnect?: () => void;
}

/** Цифры дня, пока данных нет: прочерк, а не «0» (ноль — это уже известный ответ). */
const EMPTY_STAT = "—";

/** Последовательно снимает ручной блок (если был) и разрешает провайдера, без параллельной гонки. */
export async function executeAllowSequence(
  provider: ProviderId,
  blockedByUser: boolean,
  onUnblockProvider: (provider: ProviderId) => Promise<unknown> | void,
  onAllowProvider: (provider: ProviderId) => Promise<unknown> | void,
): Promise<void> {
  if (blockedByUser) {
    await onUnblockProvider(provider);
  }
  await onAllowProvider(provider);
}

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
    guardPauseStatus: props.guardPauseStatus,
    routeUnavailable: props.routeUnavailableBanner,
  });

  const [pendingAllow, setPendingAllow] = useState<ProviderId | null>(null);
  const [persistForceException, setPersistForceException] = useState<boolean>(false);
  const [verifyingAllow, setVerifyingAllow] = useState<ProviderId | null>(null);
  const runAllow = async (provider: ProviderId, blockedByUser: boolean, persistException = false) => {
    setVerifyingAllow(provider);
    try {
      await executeAllowSequence(
        provider,
        blockedByUser,
        props.onUnblockProvider,
        (p) => props.onAllowProvider(p, persistException),
      );
    } finally {
      setVerifyingAllow(null);
    }
  };
  const requestAllow = async (service: ServiceModel, report: RiskReport | undefined, blockedByUser: boolean) => {
    if (blockedByUser && !needsForceConfirm(service.status, report) && props.onVerifyAndUnblockProvider) {
      setVerifyingAllow(service.id);
      try {
        const unblocked = await props.onVerifyAndUnblockProvider(service.id);
        if (!unblocked) {
          setPersistForceException(false);
          setPendingAllow(service.id);
        }
      } finally {
        setVerifyingAllow(null);
      }
      return;
    }
    if (needsForceConfirm(service.status, report)) {
      setPersistForceException(false);
      setPendingAllow(service.id);
    } else {
      await runAllow(service.id, blockedByUser, false);
    }
  };

  const progress = progressOf(buildPendingChecks(partial ?? null, state));
  const { osTzStatus, osTzLoading, syncOsTimezone, restoreOsTimezone } = useOsTimezoneSync(
    activeReport?.telemetry?.timezone,
  );

  const expiringRoute = (() => {
    const routes = props.routesSnapshot?.routes;
    if (!routes || routes.length === 0) return null;
    return (
      routes.find((r) => {
        if (!r.enabled || !r.expires_at) return false;
        const urgency = getRouteExpiryUrgency(r.expires_at);
        return urgency === "expired" || urgency === "critical" || urgency === "soon";
      }) ?? null
    );
  })();
  const expiringUrgency = expiringRoute?.expires_at ? getRouteExpiryUrgency(expiringRoute.expires_at) : "none";

  return (
    <>
      {!loading && !failed && (
        <ProblemBanner
          kind={model.banner}
          targetTz={activeReport?.telemetry?.timezone}
          tzCode={activeReport?.timezone_result?.code}
          osTzStatus={osTzStatus}
          osTzLoading={osTzLoading}
          onSyncOsTimezone={() => void syncOsTimezone(activeReport?.telemetry?.timezone)}
          onRestoreOsTimezone={() => void restoreOsTimezone()}
          {...props}
        />
      )}

      {!loading && !failed && !model.banner && osTzStatus?.synced && (
        <Banner
          tone="info"
          title={copy.banner.timezone.syncedBannerTitle}
          action={
            <Button size="sm" variant="secondary" disabled={osTzLoading} onClick={() => void restoreOsTimezone()}>
              {copy.banner.timezone.restoreOs}
            </Button>
          }
        >
          {copy.banner.timezone.syncedBannerText(osTzStatus.original_os_tz, osTzStatus.synced_target_tz)}
        </Banner>
      )}

      <CooldownBanner
        cooldownUntil={state?.ip_change_cooldown_until}
        onCleared={props.onRetry}
        onToast={props.onToast}
      />

      {expiringRoute && expiringRoute.expires_at && (
        <Banner
          tone={expiringUrgency === "critical" || expiringUrgency === "expired" ? "danger" : "warn"}
          title={
            expiringUrgency === "expired"
              ? copy.banner.expiringKey.titleExpired
              : copy.banner.expiringKey.titleSoon
          }
          action={
            <>
              <Button size="sm" variant="secondary" onClick={() => openZastavaBot(expiringRoute.id)}>
                {copy.banner.expiringKey.renew}
              </Button>{" "}
              {props.onOpenConnect && (
                <Button size="sm" variant="quiet" onClick={props.onOpenConnect}>
                  {copy.banner.expiringKey.openConnect}
                </Button>
              )}
            </>
          }
        >
          {copy.banner.expiringKey.text(
            expiringRoute.label || copy.facts.key,
            formatRemainingTimeRu(expiringRoute.expires_at),
          )}
        </Banner>
      )}

      {loading ? (
        <HeroChecking startup={startupPending} done={progress.done} total={progress.total} />
      ) : failed ? (
        <Card>
          <EmptyState
            icon="alert"
            title={copy.error.title}
            action={
              <div className="zs-banner__actions">
                <Button variant="primary" icon="refresh" onClick={props.onRetry} disabled={refreshing}>
                  {copy.error.action}
                </Button>
                <CopyErrorLogButton
                  title={copy.error.title}
                  message={auditError ?? undefined}
                  variant="secondary"
                />
              </div>
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
          ip={currentIp !== "--" ? formatIp(currentIp, props.hideIpMode) : undefined}
          country={currentIp !== "--" ? formatCountryWithCode(activeReport?.telemetry.country_code) || undefined : undefined}
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
            {killswitchFrozen ? (
              <Rows>
                {model.services.map((service) => {
                  const isDisabled = service.status === "disabled";
                  return (
                    <Row
                      key={service.id}
                      icon={isDisabled ? "shield" : "alert"}
                      tone={isDisabled ? "neutral" : "danger"}
                      title={providerCopy[service.id].name}
                      sub={providerCopy[service.id].domains}
                      trail={
                        isDisabled ? (
                          <Badge tone="neutral">{copy.service.monitoringDisabled}</Badge>
                        ) : (
                          <Badge tone="danger" icon="alert">
                            {copy.service.stopped}
                          </Badge>
                        )
                      }
                    />
                  );
                })}
              </Rows>
            ) : !startupPending && !sysproxyActive ? (
              <>
                <p className="zs-services-off-note" role="status">
                  {copy.service.unprotectedNote}
                </p>
                <Rows>
                  {model.services.map((service) => {
                    const isDisabled = service.status === "disabled";
                    return (
                      <Row
                        key={service.id}
                        icon="shield"
                        tone="neutral"
                        title={providerCopy[service.id].name}
                        sub={providerCopy[service.id].domains}
                        trail={
                          <Badge tone="neutral">
                            {isDisabled ? copy.service.monitoringDisabled : copy.service.unprotected}
                          </Badge>
                        }
                      />
                    );
                  })}
                </Rows>
              </>
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
                    verifying={verifyingAllow === service.id}
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
        busy={verifyingAllow !== null}
        onCancel={() => {
          setPendingAllow(null);
          setPersistForceException(false);
        }}
        onConfirm={async () => {
          if (pendingAllow) {
            const target = pendingAllow;
            const persist = persistForceException;
            setPendingAllow(null);
            setPersistForceException(false);
            await runAllow(target, Boolean(state?.blocked_providers?.includes(target)), persist);
          } else {
            setPendingAllow(null);
            setPersistForceException(false);
          }
        }}
      >
        {pendingAllow ? (
          <>
            <p>{copy.service.confirm.text(providerCopy[pendingAllow].name)}</p>
            <label className="zs-t-caption mt-2 flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={persistForceException}
                onChange={(e) => setPersistForceException(e.target.checked)}
              />
              <span>{copy.service.confirm.persistLabel}</span>
            </label>
          </>
        ) : ""}
      </ConfirmModal>

      <ProtectedSection
        startupPending={startupPending}
        sysproxyActive={sysproxyActive}
        cliProtected={cliProtected}
        protection={props.protection}
        onToggleSysproxy={props.onToggleSysproxy}
        onToggleCli={props.onToggleCli}
      />

      <CoverageSection
        variant="overview"
        initialSnapshot={coverageSnapshot}
        pending={startupPending}
        protection={props.protection}
        onToast={props.onToast}
        onSnapshotChange={props.onCoverageSnapshot}
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
        <div className="zs-app__action-stop">
          {killswitchFrozen ? (
            <Button variant="primary" icon="refresh" onClick={props.onToggleKillswitch}>
              {copy.actions.resumeNetwork}
            </Button>
          ) : (
            <Button variant="danger" icon="power" onClick={props.onToggleKillswitch}>
              {copy.actions.stopNetwork}
            </Button>
          )}
          <InfoTip
            title={killswitchFrozen ? copy.actions.resumeTooltipTitle : copy.actions.stopTooltipTitle}
            text={killswitchFrozen ? copy.actions.resumeTooltipText : copy.actions.stopTooltipText}
          />
        </div>
      </div>
    </>
  );
}

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
