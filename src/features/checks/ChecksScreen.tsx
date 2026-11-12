import { useState } from "react";
import type { AppStateData, CoverageSnapshot, ProviderId, RiskReport } from "../../types";
import { Badge, Button, Card, ExpandRow, Link, Mono, Row, Rows, Section, Skeleton } from "../../ui";
import type { IconName, Tone } from "../../ui";
import { providers as providerCopy, status as words } from "../../shared/copy/ru";
import { checks as copy } from "../../shared/copy/ru";
import type { CheckId } from "../../shared/copy/ru";
import type { ProtectionActions, ShowToast } from "../../shared/hooks";
import { CoverageSection } from "../coverage/CoverageSection";
import { buildChecks, isCriticalStatus } from "./checksModel";
import type { CheckItem } from "./checksModel";
import "./checks.css";

export interface ChecksScreenProps {
  report: RiskReport | null;
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
}

/** Единый словарь: Чисто / Нужна проверка / Утечка / Выключено. */
function statusOf(item: CheckItem, state: AppStateData | null): StatusView {
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
const needsLook = (item: CheckItem) => item.cls !== "ok" && item.cls !== "na";

/** Экран «Проверки»: вердикт, проверки по смыслу, тесты защиты. */
export function ChecksScreen({
  report,
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

  if (!report) {
    return (
      <div className="zs-stack" role="status" aria-live="polite">
        <Card>
          <h2 className="zs-verdict__title">{copy.loadingTitle}</h2>
          <p className="zs-verdict__text">{copy.loadingText}</p>
        </Card>
        <Card>
          <Skeleton variant="text" lines={8} />
        </Card>
      </div>
    );
  }

  const { groups, items, counts, total } = buildChecks(report, state);
  const passed = counts.ok;
  const failed = counts.warn + counts.crit;
  const unknown = counts.unknown;
  const worst: Tone | "neutral" = counts.crit > 0 ? "danger" : failed > 0 ? "warn" : unknown > 0 ? "neutral" : "ok";
  const leak = items.some((i) => LEAK_CHECKS.includes(i.id) && i.cls === "crit");

  const runAction = (item: CheckItem) => {
    if (item.action === "pin") onPinCurrentIp(report.telemetry.ip);
    else if (item.action === "sync-timezone") onSyncTimezone();
    else if (item.action === "guide") onNavigateToGuide(item.result.guide_ref || undefined);
  };

  return (
    <div className="zs-stack">
      {provider && <p className="zs-t-caption">{copy.forService(providerCopy[provider].name)}</p>}
      <Card>
        <div className="zs-verdict__head">
          <div className="zs-verdict__body">
            {worst === "ok" ? (
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
            <h2 className="zs-verdict__title">{copy.verdict(passed, total)}</h2>
            <p className="zs-verdict__text">{copy.summary(passed, total, unknown, failed)}</p>
            {failed > 0 && <p className="zs-verdict__text">{copy.verdictIssues(failed)}</p>}
            {unknown > 0 && <p className="zs-verdict__text">{copy.verdictUnknown(unknown)}</p>}
            {failed === 0 && unknown === 0 && (
              <p className="zs-verdict__text">
                {copy.verdictOk} {copy.verdictDisclaimer}
              </p>
            )}
            {dataAgeMinutes != null && <p className="zs-verdict__text">{copy.dataAge(dataAgeMinutes)}</p>}
          </div>
          {onRecheck && (
            <div className="zs-verdict__action">
              <Button icon="refresh" onClick={onRecheck} disabled={rechecking}>
                {rechecking ? copy.rechecking : copy.recheck}
              </Button>
            </div>
          )}
        </div>
      </Card>

      {groups.map((group) => (
        <Section key={group.id} title={group.title}>
          <Card>
            <Rows>
              {group.items.map((item) => (
                <CheckRow
                  key={item.id}
                  item={item}
                  view={statusOf(item, state)}
                  open={expanded[item.id] ?? needsLook(item)}
                  onToggle={() => setExpanded((prev) => ({ ...prev, [item.id]: !(prev[item.id] ?? needsLook(item)) }))}
                  onAction={() => runAction(item)}
                  onRetry={onRecheck}
                  retrying={rechecking}
                  onGuide={() => onNavigateToGuide(item.result.guide_ref || undefined)}
                />
              ))}
            </Rows>
          </Card>
        </Section>
      ))}

      <CoverageSection
        variant="checks"
        initialSnapshot={coverageSnapshot}
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

interface CheckRowProps {
  item: CheckItem;
  view: StatusView;
  open: boolean;
  onToggle: () => void;
  onAction: () => void;
  onGuide: () => void;
  /** Повторный прогон через общий аудит; без обработчика кнопка не показывается. */
  onRetry?: () => void;
  retrying?: boolean;
}

function CheckRow({ item, view, open, onToggle, onAction, onGuide, onRetry, retrying }: CheckRowProps) {
  const actionLabel =
    item.action === "pin" ? copy.actions.pin : item.action === "sync-timezone" ? copy.actions.syncTimezone : copy.actions.openGuide;
  // Инструкция отдельной ссылкой — только если главное действие другое.
  const showGuideLink = item.result.guide_ref && item.action !== "guide";

  return (
    <ExpandRow
      icon={ICONS[item.id as CheckId] ?? "pulse"}
      tone={view.tone === "ok" || view.tone === "warn" || view.tone === "danger" ? view.tone : "neutral"}
      title={item.title}
      sub={item.what}
      trail={
        <Badge tone={view.tone} icon={view.icon}>
          {view.word}
        </Badge>
      }
      open={open}
      onToggle={onToggle}
      detailLabel={item.title}
    >
      <div>
        <p className="zs-check__label">{copy.detail.result}</p>
        {item.cls === "unknown" && (
          <p className="zs-check__message">{copy.reasons[item.missing ? "no_data" : (item.result.reason ?? "unknown")]}</p>
        )}
        <p className="zs-check__message">{item.result.message}</p>
        {item.result.measured_via && <p className="zs-check__label">{copy.source(item.result.measured_via)}</p>}
      </div>
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
      {(item.action || showGuideLink || (item.cls === "unknown" && onRetry)) && (
        <div className="zs-check__actions">
          {item.cls === "unknown" && onRetry && (
            <Button size="sm" icon="refresh" onClick={onRetry} disabled={retrying}>
              {copy.retry}
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
