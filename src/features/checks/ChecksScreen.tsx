import { useEffect, useState } from "react";
import type { AppStateData, CoverageSnapshot, PartialAudit, ProviderId, RiskReport, SourceView } from "../../types";
import { Badge, Banner, Button, Card, EmptyState, ExpandRow, Link, Mono, Row, Rows, Section, Segmented, cx } from "../../ui";
import type { IconName, Tone } from "../../ui";
import { providers as providerCopy, status as words } from "../../shared/copy/ru";
import { checks as copy } from "../../shared/copy/ru";
import type { CheckId } from "../../shared/copy/ru";
import type { ProtectionActions, ShowToast } from "../../shared/hooks";
import { CoverageSection } from "../coverage/CoverageSection";
import { openOsNetworkSettings } from "../../utils/api";
import {
  PROVIDER_ORDER,
  buildChecks,
  buildPendingChecks,
  isCriticalStatus,
  partitionChecksForProvider,
  pickWorstProvider,
  progressOf,
} from "./checksModel";
import type { CheckItem, PrioritizedCheckItem } from "./checksModel";
import "./checks.css";

export interface ChecksScreenProps {
  report: RiskReport | null;
  /** Отчёты по всем ИИ-провайдерам для переключения без повторного аудита. */
  reports?: Partial<Record<ProviderId, RiskReport>>;
  /** Что уже известно о идущем аудите (пока отчёта нет): готовые проверки и адрес выхода. */
  partial?: PartialAudit | null;
  /** Текст ошибки аудита: без отчёта и без идущего повтора показывается «Повторить». */
  auditError?: string | null;
  /** Шлюз ещё запускается в фоне: данных нет не потому, что проверка сломалась. */
  startupPending?: boolean;
  /** Сервис, чей отчёт показан (переход из «Обзора»); без него показывается худший отчёт. */
  provider?: ProviderId;
  state: AppStateData | null;
  coverageSnapshot?: CoverageSnapshot | null;
  /** Явные «включить» и «выключить» защиты для карточек «Покрытия»; без них кнопка скрыта. */
  protection?: ProtectionActions;
  /** Тосты секции покрытия (например, ошибка копирования адреса). */
  onToast?: ShowToast;
  onNavigateToGuide: (guideId?: string) => void;
  onSimulate: () => void;
  onPinCurrentIp: (ip: string) => void;
  onSyncTimezone: () => void;
  onOpenCrashTest: () => void;
  /** Повторный аудит сети. Без обработчика кнопка «Перепроверить» не показывается. */
  onRecheck?: () => void;
  /** Идёт повторный аудит. */
  rechecking?: boolean;
  /** Возраст данных в минутах, если отчёт устарел или последний аудит упал; иначе null. */
  dataAgeMinutes?: number | null;
}

/** Значок строки: только украшение, статус говорит бейдж. */
const ICONS: Record<CheckId, IconName> = {
  geo_matrix: "globe",
  claude_exit: "shield",
  asn: "pulse",
  dnsbl: "shield",
  reverse_dns: "term",
  pinning: "lock",
  travel: "arrow",
  ipv6: "zap",
  dns: "pulse",
  dns_country: "globe",
  wifi_geo: "shield",
  timezone: "refresh",
  locale_hygiene: "term",
  udp_stun: "zap",
};

/** Значок «не удалось проверить». */
const UNKNOWN_ICON: IconName = "help";

const LEAK_CHECKS: string[] = ["ipv6", "dns", "dns_country", "wifi_geo", "udp_stun"];

interface StatusView {
  tone: Tone | "neutral";
  word: string;
  icon?: IconName;
  /** Результата ещё нет: на бейдже вращается индикатор. */
  busy?: boolean;
}

/** Ссылка на настройки сети есть только на macOS и Windows; на остальных системах кнопку не показываем. */
const CAN_OPEN_NETWORK_SETTINGS =
  typeof navigator !== "undefined" && /Mac|Win/i.test(navigator.platform || navigator.userAgent || "");

/** Единый словарь: Чисто / Нужна проверка / Утечка / Выключено. */
function statusOf(item: CheckItem, state: AppStateData | null): StatusView {
  if (item.pending) return { tone: "neutral", word: copy.pending.badge, busy: true };
  if (item.ok) return { tone: "ok", word: words.clean, icon: "check" };
  if (item.missing) return { tone: "neutral", word: words.noData, icon: UNKNOWN_ICON };
  if (item.cls === "unknown") return { tone: "neutral", word: words.unknown, icon: UNKNOWN_ICON };
  if (item.cls === "na") return { tone: "neutral", word: words.notApplicable };
  if (isCriticalStatus(item.result)) {
    return { tone: "danger", word: LEAK_CHECKS.includes(item.id) ? words.leak : words.review, icon: "alert" };
  }
  if (item.id === "pinning" && !state?.pinned_ip) return { tone: "neutral", word: words.off };
  return { tone: "warn", word: words.review, icon: "alert" };
}

/** Строку раскрываем сразу, если по ней есть что делать. */
const needsLook = (item: CheckItem) => item.cls !== "ok" && item.cls !== "na" && item.cls !== "pending";

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
}: ChecksScreenProps) {
  // Явный выбор пользователя; без него раскрыты только непройденные проверки.
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [passedOpen, setPassedOpen] = useState(false);
  const [manualProvider, setManualProvider] = useState<ProviderId | null>(null);

  useEffect(() => {
    setManualProvider(null);
  }, [provider]);

  const resolvedReports = reports ?? (report ? { [report.provider]: report } : undefined);
  const defaultProvider =
    provider ?? (resolvedReports ? pickWorstProvider(resolvedReports) : undefined) ?? report?.provider ?? "anthropic";
  const activeProvider: ProviderId = manualProvider ?? defaultProvider;
  const activeReport: RiskReport | null = resolvedReports
    ? (resolvedReports[activeProvider] ?? (report?.provider === activeProvider ? report : null))
    : (report ?? null);
  const providerName = providerCopy[activeProvider].name;

  const switcher = (
    <Segmented
      aria-label={copy.providerSwitchLabel}
      value={activeProvider}
      onChange={(next) => setManualProvider(next)}
      options={PROVIDER_ORDER.map((id) => ({ value: id, label: providerCopy[id].name }))}
    />
  );

  // Ни отчёта, ни идущей проверки, а аудит упал (или не вернул отчёт для выбранного провайдера): понятная ошибка с повтором.
  const missingAfterFinish = !activeReport && !rechecking && !startupPending && (Boolean(auditError) || Boolean(resolvedReports && Object.keys(resolvedReports).length > 0));
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

  // Пока отчёта нет, строки рисуются сразу: готовые — с результатом, остальные — «Проверяем…».
  const activePartial = partial?.provider === activeProvider ? partial : null;
  const built = activeReport ? buildChecks(activeReport, state) : buildPendingChecks(activePartial, state);
  const { items, counts, total } = built;
  const { actionItems, passedItems } = partitionChecksForProvider(items, activeProvider);
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
  // Пока отчёта нет, судим по адресу выхода из частичного аудита.
  const ipv6Exit = activeReport ? Boolean(activeReport.ipv6_exit) : ip.includes(":");
  const ratioPassed = waiting ? progress.done : passed;
  const ratioTotal = waiting ? progress.total : total;

  const runAction = (item: CheckItem) => {
    if (item.action === "pin") onPinCurrentIp(ip);
    else if (item.action === "sync-timezone") onSyncTimezone();
    else if (item.action === "guide") onNavigateToGuide(item.result.guide_ref || undefined);
  };

  return (
    <div className="zs-stack">
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
            {onRecheck && !waiting && (
              <div className="zs-verdict__actions">
                <Button size="sm" icon="refresh" onClick={onRecheck} disabled={rechecking}>
                  {rechecking ? copy.rechecking : copy.recheck}
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
              view={statusOf(item, state)}
              open={expanded[item.id] ?? needsLook(item)}
              onToggle={() => setExpanded((prev) => ({ ...prev, [item.id]: !(prev[item.id] ?? needsLook(item)) }))}
              onAction={() => runAction(item)}
              onRetry={onRecheck}
              retrying={rechecking}
              onGuide={() => onNavigateToGuide(item.result.guide_ref || undefined)}
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
                    view={statusOf(item, state)}
                    open={Boolean(expanded[item.id])}
                    onToggle={() => setExpanded((prev) => ({ ...prev, [item.id]: !prev[item.id] }))}
                    onAction={() => runAction(item)}
                    onRetry={onRecheck}
                    retrying={rechecking}
                    onGuide={() => onNavigateToGuide(item.result.guide_ref || undefined)}
                  />
                ))}
              </Rows>
            </ExpandRow>
          )}
        </Rows>
      </Card>

      <CoverageSection
        variant="checks"
        initialSnapshot={coverageSnapshot}
        pending={startupPending}
        protection={protection}
        onToast={onToast}
      />

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

/* ---------- Строка проверки: ExpandRow с подробностями ---------- */

function priorityLabel(item: PrioritizedCheckItem, providerName: string): string {
  if (item.tier === 1) return copy.priority.tier1(providerName);
  if (item.tier === 2) return copy.priority.tier2(providerName);
  return item.advisory ? copy.priority.tier3Advisory(providerName) : copy.priority.tier3Required(providerName);
}

interface CheckRowProps {
  item: PrioritizedCheckItem;
  providerName: string;
  showPriority: boolean;
  view: StatusView;
  open: boolean;
  onToggle: () => void;
  onAction: () => void;
  onGuide: () => void;
  /** Повторный прогон через общий аудит; без обработчика кнопка не показывается. */
  onRetry?: () => void;
  retrying?: boolean;
}

function CheckRow({ item, providerName, showPriority, view, open, onToggle, onAction, onGuide, onRetry, retrying }: CheckRowProps) {
  const actionLabel =
    item.action === "pin" ? copy.actions.pin : item.action === "sync-timezone" ? copy.actions.syncTimezone : copy.actions.openGuide;
  // Инструкция отдельной ссылкой — только если главное действие другое.
  const showGuideLink = item.result.guide_ref && item.action !== "guide";
  const sources = item.pending ? [] : (item.result.detail?.sources ?? []);
  const showNetworkSettings = Boolean(item.help?.canOpenNetworkSettings) && CAN_OPEN_NETWORK_SETTINGS;
  const priorityTone = item.tier === 1 ? "tier1" : item.tier === 2 ? "tier2" : item.advisory ? "advisory" : "tier3";

  return (
    <ExpandRow
      icon={ICONS[item.id as CheckId] ?? "pulse"}
      tone={view.tone === "ok" || view.tone === "warn" || view.tone === "danger" ? view.tone : "neutral"}
      title={item.title}
      sub={
        showPriority ? (
          <>
            <span className={cx("zs-check__priority", `zs-check__priority--${priorityTone}`)}>{priorityLabel(item, providerName)}</span>
            {" · "}
            {item.what}
          </>
        ) : (
          item.what
        )
      }
      trail={
        <Badge tone={view.tone} icon={view.icon} busy={view.busy}>
          {view.word}
        </Badge>
      }
      open={open}
      onToggle={onToggle}
      detailLabel={item.title}
    >
      {item.pending ? (
        <p className="zs-check__message" role="status" aria-busy="true">
          {copy.pending.row}
        </p>
      ) : (
        <div>
          <p className="zs-check__label">{copy.detail.result}</p>
          {item.cls === "unknown" && !item.help && (
            <p className="zs-check__message">{copy.reasons[item.missing ? "no_data" : (item.result.reason ?? "unknown")]}</p>
          )}
          <p className="zs-check__message">{item.result.message}</p>
          {(item.id === "dns" || item.id === "dns_country") &&
            item.cls === "unknown" &&
            item.result.code !== "DNS_WHOAMI_FAKE_IP" && <p className="zs-check__label">{copy.dnsHelp.mutedNote}</p>}
          {item.result.measured_via && (
            <p className="zs-check__label">
              {copy.measuredViaLabel} <Mono>{item.result.measured_via}</Mono>
            </p>
          )}
        </div>
      )}
      {sources.length > 0 && (
        <div>
          <p className="zs-check__label">{copy.detail.sources}</p>
          <ul className="zs-check__sources">
            {sources.map((src) => (
              <li key={src.source} className="zs-check__message">
                {copy.sources.line(src.source, describeSource(src))}
              </li>
            ))}
          </ul>
        </div>
      )}
      {item.help && (
        <>
          <div>
            <p className="zs-check__label">{copy.detail.why}</p>
            {item.help.intro && <p className="zs-check__message">{item.help.intro}</p>}
            <p className="zs-check__message">{item.help.why}</p>
          </div>
          <div>
            <p className="zs-check__label">{copy.detail.steps}</p>
            <ol className="zs-check__steps">
              {item.help.steps.map((step) => (
                <li key={step} className="zs-check__message">
                  {step}
                </li>
              ))}
            </ol>
          </div>
        </>
      )}
      {item.advice && (
        <div>
          <p className="zs-check__label">{copy.detail.todo}</p>
          <p className="zs-check__message">{item.advice}</p>
        </div>
      )}
      {item.data.length > 0 && (
        <dl className="zs-check__data">
          {item.data.map((d) => (
            <div key={d.label} className="zs-check__pair">
              <dt>{d.label}</dt>
              <dd>{d.mono ? <Mono>{d.value}</Mono> : d.value}</dd>
            </div>
          ))}
        </dl>
      )}
      {(item.action || showGuideLink || (item.cls === "unknown" && onRetry) || showNetworkSettings) && (
        <div className="zs-check__actions">
          {item.cls === "unknown" && onRetry && (
            <Button size="sm" icon="refresh" onClick={onRetry} disabled={retrying}>
              {copy.retry}
            </Button>
          )}
          {showNetworkSettings && (
            <Button size="sm" onClick={() => void openOsNetworkSettings().catch(() => {})}>
              {copy.dnsHelp.openSettings}
            </Button>
          )}
          {item.action && (
            <Button size="sm" icon={item.action === "guide" ? undefined : item.action === "pin" ? "lock" : "refresh"} onClick={onAction}>
              {actionLabel}
            </Button>
          )}
          {showGuideLink && (
            <Link
              href="#"
              chevron
              onClick={(e) => {
                e.preventDefault();
                onGuide();
              }}
            >
              {copy.actions.openGuide}
            </Link>
          )}
        </div>
      )}
    </ExpandRow>
  );
}

/** «172.70.161.26 · Cloudflare (публичный DNS)», «вернул служебный адрес 198.18.0.7», «не ответил вовремя». */
function describeSource(src: SourceView): string {
  const state = copy.sources.state[src.state] ?? copy.sources.state.empty;
  if (!src.addr) return state;
  const operator = src.operator ? ` · ${copy.sources.operator(src.operator)}` : "";
  return src.state === "answered" ? `${src.addr}${operator}` : `${state} ${src.addr}${operator}`;
}
