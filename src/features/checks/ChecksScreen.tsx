import { useEffect, useState } from "react";
import type { AppStateData, CoverageSnapshot, OsTzSyncStatus, PartialAudit, ProviderId, RiskReport } from "../../types";
import { Badge, Banner, Button, Card, EmptyState, ExpandRow, HintCard, Row, Rows, Section, Segmented, cx } from "../../ui";
import type { Tone } from "../../ui";
import { checks as copy, providers as providerCopy, status as words } from "../../shared/copy/ru";
import type { ProtectionActions, ShowToast } from "../../shared/hooks";
import { useOsTimezoneSync } from "../../shared/hooks/useTimezoneSync";
import { CoverageSection } from "../coverage/CoverageSection";
import { CheckRow, LEAK_CHECKS, UNKNOWN_ICON, needsLook, statusOf } from "./CheckRow";
import {
  PROVIDER_ORDER,
  buildChecks,
  buildPendingChecks,
  partitionChecksForProvider,
  pickWorstProvider,
  progressOf,
} from "./checksModel";
import type { CheckItem } from "./checksModel";
import "./checks.css";

export interface ChecksScreenProps {
  report: RiskReport | null;
  /** Отчёты по всем ИИ-провайдерам для переключения без повторного аудита. */
  reports?: Partial<Record<ProviderId, RiskReport>>;
  /** Что уже известно о идущем аудите (пока отчёта нет): готовые проверки и адрес выхода. */
  partial?: PartialAudit | null;
  /** Текст ошибки аудита: без отчёта и без идущей проверки показывается «Повторить». */
  auditError?: string | null;
  /** Шлюз ещё запускается в фоне: данных нет не потому, что проверка сломалась. */
  startupPending?: boolean;
  /** Сервис, чей отчёт показан (переход из «Обзора»); без него показывается худший отчёт. */
  provider?: ProviderId;
  state: AppStateData | null;
  coverageSnapshot?: CoverageSnapshot | null;
  hideIpMode?: boolean;
  /** Явные «включить» и «выключить» защиты для карточек «Покрытия»; без них кнопка скрыта. */
  protection?: ProtectionActions;
  /** Тосты секции покрытия (например, ошибка копирования адреса). */
  onToast?: ShowToast;
  onNavigateToGuide: (guideId?: string) => void;
  onSimulate: () => void;
  onPinCurrentIp: (ip: string, provider?: ProviderId) => void;
  onSyncTimezone: () => void;
  onOpenCrashTest: () => void;
  /** Повторный аудит сети. Без обработчика кнопка «Перепроверить» не показывается. */
  onRecheck?: () => void;
  /** Идёт повторный аудит. */
  rechecking?: boolean;
  /** Возраст данных в минутах, если отчёт устарел или последний аудит упал; иначе null. */
  dataAgeMinutes?: number | null;
  /** Показывать ли секцию «Покрытие приложений» внизу экрана (в Shell v3 она живёт в «Нейросети и защита»). */
  showCoverage?: boolean;
  onDismissHint?: (hintId: string) => Promise<unknown> | void;
  syncingTimezone?: boolean;
  osTzStatus?: OsTzSyncStatus | null;
  osTzLoading?: boolean;
  osTzError?: string | null;
  onSyncOsTimezone?: () => Promise<unknown> | void;
  onRestoreOsTimezone?: () => Promise<unknown> | void;
}

const IS_MAC = typeof navigator !== "undefined" && /Mac/i.test(navigator.platform || navigator.userAgent || "");

/** Экран «Проверки»: переключатель провайдеров, вердикт, приоритетные проверки, тесты защиты. */
export function ChecksScreen({
  report,
  reports,
  partial,
  auditError,
  startupPending,
  provider,
  state,
  coverageSnapshot,
  hideIpMode = false,
  protection,
  onToast,
  onNavigateToGuide,
  onSimulate,
  onPinCurrentIp,
  onSyncTimezone,
  onOpenCrashTest,
  onRecheck,
  rechecking,
  dataAgeMinutes,
  showCoverage = true,
  onDismissHint,
  syncingTimezone,
  osTzStatus: propOsTzStatus,
  osTzLoading: propOsTzLoading,
  osTzError: propOsTzError,
  onSyncOsTimezone,
  onRestoreOsTimezone,
}: ChecksScreenProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [passedOpen, setPassedOpen] = useState(false);
  const [manualProvider, setManualProvider] = useState<ProviderId | null>(null);
  const [localDismissed, setLocalDismissed] = useState<string[]>(() => state?.dismissed_hints ?? []);

  useEffect(() => {
    setManualProvider(null);
  }, [provider]);

  useEffect(() => {
    if (state?.dismissed_hints) setLocalDismissed(state.dismissed_hints);
  }, [state?.dismissed_hints]);

  const handleDismissHint = (id: string) => {
    setLocalDismissed((prev) => (prev.includes(id) ? prev : [...prev, id]));
    void onDismissHint?.(id);
  };

  const resolvedReports = reports ?? (report ? { [report.provider]: report } : undefined);
  const defaultProvider =
    provider ??
    (resolvedReports ? pickWorstProvider(resolvedReports, state?.disabled_providers) : undefined) ??
    report?.provider ??
    "anthropic";
  const activeProvider: ProviderId = manualProvider ?? defaultProvider;
  const isProviderDisabled = Boolean(
    state?.disabled_providers?.some((p) => p.toLowerCase() === activeProvider),
  );
  const activeReport: RiskReport | null = resolvedReports
    ? (resolvedReports[activeProvider] ?? (report?.provider === activeProvider ? report : null))
    : (report ?? null);
  const providerName = providerCopy[activeProvider].name;
  const targetTz = activeReport?.telemetry?.timezone ?? null;
  const sharedOsTz = useOsTimezoneSync(targetTz ?? undefined);
  const resolvedOsTzStatus = propOsTzStatus !== undefined ? propOsTzStatus : sharedOsTz.osTzStatus;
  const resolvedOsTzLoading = propOsTzLoading ?? sharedOsTz.osTzLoading;
  const resolvedOsTzError = propOsTzError !== undefined ? propOsTzError : sharedOsTz.osTzError;
  const handleSyncOsTz = () => {
    if (onSyncOsTimezone) void onSyncOsTimezone();
    else void sharedOsTz.syncOsTimezone(targetTz ?? undefined);
  };
  const handleRestoreOsTz = () => {
    if (onRestoreOsTimezone) void onRestoreOsTimezone();
    else void sharedOsTz.restoreOsTimezone();
  };

  const switcher = (
    <Segmented
      aria-label={copy.providerSwitchLabel}
      value={activeProvider}
      onChange={(next) => setManualProvider(next)}
      options={PROVIDER_ORDER.map((id) => ({ value: id, label: providerCopy[id].name }))}
    />
  );

  if (isProviderDisabled) {
    return (
      <div className="zs-stack">
        {switcher}
        <Card>
          <EmptyState icon="shield" title="Мониторинг отключён">
            Перехват, проверки и уведомления для {providerName} отключены в Настройках. Включите сервис в Настройках, чтобы снова проверять его.
          </EmptyState>
        </Card>
      </div>
    );
  }

  const missingAfterFinish =
    !activeReport &&
    !rechecking &&
    !startupPending &&
    (Boolean(auditError) || Boolean(resolvedReports && Object.keys(resolvedReports).length > 0));
  if (missingAfterFinish) {
    return (
      <div className="zs-stack">
        {switcher}
        <Card>
          <EmptyState
            icon="alert"
            title={copy.failed.title}
            action={
              onRecheck && (
                <Button variant="primary" icon="refresh" onClick={onRecheck}>
                  {copy.recheck}
                </Button>
              )
            }
          >
            {copy.failed.text}
          </EmptyState>
        </Card>
      </div>
    );
  }

  const activePartial = partial?.provider === activeProvider ? partial : null;
  const built = activeReport ? buildChecks(activeReport, state) : buildPendingChecks(activePartial, state);
  const { items, counts, total } = built;
  const { actionItems: rawActionItems, passedItems: rawPassedItems } = partitionChecksForProvider(items, activeProvider);
  const hideWifiGeo = (item: CheckItem) =>
    IS_MAC && item.id === "wifi_geo" && item.result.code === "OS_LOCATION_NOT_APPLICABLE";
  const actionItems = rawActionItems.filter((i) => !hideWifiGeo(i));
  const passedItems = rawPassedItems.filter((i) => !hideWifiGeo(i));
  const waiting = counts.pending > 0;
  const progress = progressOf(built);
  const passed = counts.ok;
  const failed = counts.warn + counts.crit;
  const unknown = counts.unknown;
  const dnsOnlyUnknown =
    unknown > 0 &&
    failed === 0 &&
    Boolean(activeReport && activeReport.overall_status === "green" && !activeReport.incomplete) &&
    items
      .filter((i) => i.cls === "unknown")
      .every((i) => (i.id === "dns" || i.id === "dns_country") && i.result.code !== "DNS_WHOAMI_FAKE_IP");
  const worst: Tone | "neutral" =
    counts.crit > 0 ? "danger" : failed > 0 ? "warn" : unknown > 0 && !dnsOnlyUnknown ? "neutral" : "ok";
  const leak = items.some((i) => LEAK_CHECKS.includes(i.id) && i.cls === "crit");
  const ip = activeReport?.telemetry.ip ?? activePartial?.telemetry?.ip ?? "";
  const ipv6Exit = activeReport ? Boolean(activeReport.ipv6_exit) : ip.includes(":");
  const ratioPassed = waiting ? progress.done : passed;
  const ratioTotal = waiting ? progress.total : total;

  const runAction = (item: CheckItem) => {
    if (item.action === "pin") onPinCurrentIp(ip, activeProvider);
    else if (item.action === "sync-timezone" || item.id === "timezone") onSyncTimezone();
    else if (item.action === "guide") onNavigateToGuide(item.result.guide_ref || undefined);
  };
  const cliTzSynced =
    state?.sync_ai_tz_enabled === false
      ? false
      : Boolean(
          state?.synced_ai_timezone ||
            activeReport?.timezone_result?.code === "TIMEZONE_SYNCED_CLI_ONLY" ||
            activeReport?.timezone_result?.code === "TIMEZONE_SYNCED_AI",
        );

  return (
    <div className="zs-stack">
      <HintCard
        hintId="checks_intro"
        body="14 проверок сети и окружения: сначала исправьте страну, IPv6, DNS и часовой пояс."
        dismissedHints={localDismissed}
        onDismiss={handleDismissHint}
      />
      {switcher}
      <Card aria-label={waiting ? copy.pending.busyLabel : undefined}>
        <div className="zs-verdict__head" aria-busy={waiting || undefined} role={waiting ? "status" : undefined}>
          <div className="zs-verdict__body">
            <div className="zs-verdict__meta">
              <span className="zs-verdict__provider">{providerName}</span>
              {waiting ? (
                <Badge busy>{copy.pending.badge}</Badge>
              ) : worst === "ok" ? (
                <Badge tone="ok" icon="check">
                  {words.clean}
                </Badge>
              ) : worst === "neutral" ? (
                <Badge icon={UNKNOWN_ICON}>{words.partial}</Badge>
              ) : (
                <Badge tone={worst} icon="alert">
                  {leak ? words.leak : words.review}
                </Badge>
              )}
            </div>
            {waiting ? (
              <>
                <h2 className="zs-verdict__title">{copy.pending.progress(progress.done, progress.total)}</h2>
                <p className="zs-verdict__text">{copy.pending.text}</p>
              </>
            ) : (
              <>
                <h2 className="zs-verdict__title">
                  {failed > 0
                    ? copy.fixHeadline(failed)
                    : unknown > 0 && !dnsOnlyUnknown
                      ? copy.partialHeadline
                      : copy.allPassedHeadline}
                </h2>
                <p className="zs-verdict__text">{copy.providerGuidance[activeProvider]}</p>
                {dnsOnlyUnknown ? (
                  <p className="zs-verdict__text">{copy.verdictDnsUnknownNote}</p>
                ) : (
                  unknown > 0 && <p className="zs-verdict__text">{copy.verdictUnknown(unknown)}</p>
                )}
                {failed === 0 && unknown === 0 && <p className="zs-verdict__text">{copy.verdictDisclaimer}</p>}
              </>
            )}
            {dataAgeMinutes != null && <p className="zs-verdict__text">{copy.dataAge(dataAgeMinutes, Boolean(auditError))}</p>}
            {!waiting && (
              <div className="zs-verdict__actions">
                {onRecheck && (
                  <Button size="sm" icon="refresh" onClick={onRecheck} disabled={rechecking}>
                    {rechecking ? copy.rechecking : copy.recheck}
                  </Button>
                )}
                <Button size="sm" variant="secondary" icon="pulse" onClick={onOpenCrashTest}>
                  {copy.tests.crashTitle}
                </Button>
              </div>
            )}
          </div>
          <div
            className={cx("zs-verdict__ratio", !waiting && `zs-verdict__ratio--${worst}`)}
            aria-label={copy.verdict(ratioPassed, ratioTotal)}
          >
            <span className="zs-verdict__count">{ratioPassed}</span>
            <span className="zs-verdict__of">{copy.ratioOf(ratioTotal)}</span>
          </div>
        </div>
      </Card>

      {ipv6Exit && (
        <Banner tone="info" title={copy.ipv6Exit.title}>
          {copy.ipv6Exit.text}
        </Banner>
      )}

      <Card>
        <Rows>
          {actionItems.map((item) => (
            <CheckRow
              key={item.id}
              item={item}
              providerName={providerName}
              showPriority
              hideIpMode={hideIpMode}
              view={statusOf(item, state, activeProvider)}
              open={expanded[item.id] ?? needsLook(item)}
              onToggle={() => setExpanded((prev) => ({ ...prev, [item.id]: !(prev[item.id] ?? needsLook(item)) }))}
              onAction={() => runAction(item)}
              onRetry={onRecheck}
              retrying={rechecking}
              onGuide={() => onNavigateToGuide(item.result.guide_ref || undefined)}
              targetTz={targetTz}
              cliTzSynced={cliTzSynced}
              cliSyncedZone={state?.synced_ai_timezone}
              syncingCliTz={syncingTimezone}
              osTzStatus={resolvedOsTzStatus}
              osTzLoading={resolvedOsTzLoading}
              osTzError={resolvedOsTzError}
              onSyncOsTimezone={handleSyncOsTz}
              onRestoreOsTimezone={handleRestoreOsTz}
            />
          ))}
          {passedItems.length > 0 && (
            <ExpandRow
              icon="check"
              tone="ok"
              title={copy.passedGroup.title}
              trail={
                <Badge tone="ok" icon="check">
                  {copy.passedGroup.badge(counts.ok, passedItems.length)}
                </Badge>
              }
              open={passedOpen}
              onToggle={() => setPassedOpen((prev) => !prev)}
              detailLabel={copy.passedGroup.title}
            >
              <Rows className="zs-checks__passed-list">
                {passedItems.map((item) => (
                  <CheckRow
                    key={item.id}
                    item={item}
                    providerName={providerName}
                    showPriority={false}
                    hideIpMode={hideIpMode}
                    view={statusOf(item, state, activeProvider)}
                    open={Boolean(expanded[item.id])}
                    onToggle={() => setExpanded((prev) => ({ ...prev, [item.id]: !prev[item.id] }))}
                    onAction={() => runAction(item)}
                    onRetry={onRecheck}
                    retrying={rechecking}
                    onGuide={() => onNavigateToGuide(item.result.guide_ref || undefined)}
                    targetTz={targetTz}
                    cliTzSynced={cliTzSynced}
                    cliSyncedZone={state?.synced_ai_timezone}
                    syncingCliTz={syncingTimezone}
                    osTzStatus={resolvedOsTzStatus}
                    osTzLoading={resolvedOsTzLoading}
                    osTzError={resolvedOsTzError}
                    onSyncOsTimezone={handleSyncOsTz}
                    onRestoreOsTimezone={handleRestoreOsTz}
                  />
                ))}
              </Rows>
            </ExpandRow>
          )}
        </Rows>
      </Card>

      {showCoverage && (
        <CoverageSection
          variant="checks"
          initialSnapshot={coverageSnapshot}
          pending={startupPending}
          protection={protection}
          onToast={onToast}
        />
      )}

      <Section title={copy.tests.title}>
        <Card>
          <Rows>
            <Row icon="pulse" title={copy.tests.crashTitle} sub={copy.tests.crashSub} onClick={onOpenCrashTest} />
            <Row icon="shield" title={copy.tests.demoTitle} sub={copy.tests.demoSub} onClick={onSimulate} />
          </Rows>
        </Card>
      </Section>
    </div>
  );
}
