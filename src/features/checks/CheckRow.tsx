import type { AppStateData, OsTzSyncStatus, ProviderId, SourceView } from "../../types";
import { Badge, Button, ExpandRow, Link, Mono, cx } from "../../ui";
import type { IconName, Tone } from "../../ui";
import { checks as copy, status as words } from "../../shared/copy/ru";
import type { CheckId } from "../../shared/copy/ru";
import { formatIp, maskIpsInText, resolvePinnedIp } from "../../shared/lib/format";
import { openOsNetworkSettings } from "../../utils/api";
import { isCriticalStatus } from "./checksModel";
import type { CheckItem, PrioritizedCheckItem } from "./checksModel";

export const CHECK_ICONS: Record<CheckId, IconName> = {
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

export const UNKNOWN_ICON: IconName = "help";
export const LEAK_CHECKS: string[] = ["ipv6", "dns", "dns_country", "wifi_geo", "udp_stun"];

export interface StatusView {
  tone: Tone | "neutral";
  word: string;
  icon?: IconName;
  busy?: boolean;
}

const CAN_OPEN_NETWORK_SETTINGS =
  typeof navigator !== "undefined" && /Mac|Win/i.test(navigator.platform || navigator.userAgent || "");

export function statusOf(item: CheckItem, state: AppStateData | null, provider: ProviderId): StatusView {
  if (item.pending) return { tone: "neutral", word: copy.pending.badge, busy: true };
  if (item.ok) return { tone: "ok", word: words.clean, icon: "check" };
  if (item.missing) return { tone: "neutral", word: words.noData, icon: UNKNOWN_ICON };
  if (item.cls === "unknown") return { tone: "neutral", word: words.unknown, icon: UNKNOWN_ICON };
  if (item.cls === "na") return { tone: "neutral", word: words.notApplicable };
  if (isCriticalStatus(item.result)) {
    return { tone: "danger", word: LEAK_CHECKS.includes(item.id) ? words.leak : words.review, icon: "alert" };
  }
  if (item.id === "pinning" && !resolvePinnedIp(state, provider)) return { tone: "neutral", word: words.off };
  return { tone: "warn", word: words.review, icon: "alert" };
}

export const needsLook = (item: CheckItem) => item.cls !== "ok" && item.cls !== "na" && item.cls !== "pending";

function priorityLabel(item: PrioritizedCheckItem, providerName: string): string {
  if (item.tier === 1) return copy.priority.tier1(providerName);
  if (item.tier === 2) return copy.priority.tier2(providerName);
  return item.advisory ? copy.priority.tier3Advisory(providerName) : copy.priority.tier3Required(providerName);
}

function describeSource(src: SourceView, hideIpMode: boolean): string {
  const state = copy.sources.state[src.state] ?? copy.sources.state.empty;
  if (!src.addr) return state;
  const addr = formatIp(src.addr, hideIpMode);
  const operator = src.operator ? ` · ${copy.sources.operator(src.operator)}` : "";
  return src.state === "answered" ? `${addr}${operator}` : `${state} ${addr}${operator}`;
}

interface CheckRowProps {
  item: PrioritizedCheckItem;
  providerName: string;
  showPriority: boolean;
  hideIpMode: boolean;
  view: StatusView;
  open: boolean;
  onToggle: () => void;
  onAction: () => void;
  onGuide: () => void;
  onRetry?: () => void;
  retrying?: boolean;
  targetTz?: string | null;
  cliTzSynced?: boolean;
  cliSyncedZone?: string | null;
  syncingCliTz?: boolean;
  osTzStatus?: OsTzSyncStatus | null;
  osTzLoading?: boolean;
  osTzError?: string | null;
  onSyncOsTimezone?: () => void;
  onRestoreOsTimezone?: () => void;
}

export function CheckRow({
  item,
  providerName,
  showPriority,
  hideIpMode,
  view,
  open,
  onToggle,
  onAction,
  onGuide,
  onRetry,
  retrying,
  targetTz,
  cliTzSynced,
  cliSyncedZone,
  syncingCliTz,
  osTzStatus,
  osTzLoading,
  osTzError,
  onSyncOsTimezone,
  onRestoreOsTimezone,
}: CheckRowProps) {
  const isTimezoneRow = item.id === "timezone";

  const actionLabel =
    item.action === "pin" ? copy.actions.pin : item.action === "sync-timezone" ? copy.actions.syncTimezone : copy.actions.openGuide;
  const showGuideLink = item.result.guide_ref && item.action !== "guide";
  const sources = item.pending ? [] : (item.result.detail?.sources ?? []);
  const showNetworkSettings = Boolean(item.help?.canOpenNetworkSettings) && CAN_OPEN_NETWORK_SETTINGS;
  const priorityTone = item.tier === 1 ? "tier1" : item.tier === 2 ? "tier2" : item.advisory ? "advisory" : "tier3";
  const showGenericAction = Boolean(item.action) && !isTimezoneRow;

  return (
    <ExpandRow
      icon={CHECK_ICONS[item.id as CheckId] ?? "pulse"}
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
          <p className="zs-check__message">{maskIpsInText(item.result.message, hideIpMode)}</p>
          {(item.id === "dns" || item.id === "dns_country") &&
            item.cls === "unknown" &&
            item.result.code !== "DNS_WHOAMI_FAKE_IP" && <p className="zs-check__label">{copy.dnsHelp.mutedNote}</p>}
          {item.result.measured_via && (
            <p className="zs-check__label">
              {copy.measuredViaLabel} <Mono>{maskIpsInText(item.result.measured_via, hideIpMode)}</Mono>
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
                {copy.sources.line(src.source, describeSource(src, hideIpMode))}
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
          {item.data.map((d) => {
            const val =
              d.label === copy.data.ip || d.label === copy.data.pinnedIp ? formatIp(d.value, hideIpMode) : d.value;
            return (
              <div key={d.label} className="zs-check__pair">
                <dt>{d.label}</dt>
                <dd>{d.mono ? <Mono>{val}</Mono> : val}</dd>
              </div>
            );
          })}
        </dl>
      )}
      {isTimezoneRow && !item.pending && (
        <div className="zs-check__tz-split">
          <div className="zs-check__tz-row">
            <div className="zs-check__tz-info">
              <p className="zs-check__tz-title">Редакторы и терминал</p>
              <p className="zs-check__tz-sub">
                {cliTzSynced && (cliSyncedZone || targetTz) ? (
                  <>
                    Синхронизирован: <Mono>{cliSyncedZone || targetTz}</Mono>
                  </>
                ) : cliTzSynced === false ? (
                  "Отключено в настройках"
                ) : (
                  "Не синхронизирован"
                )}
              </p>
            </div>
            <Button
              size="sm"
              variant="secondary"
              icon="refresh"
              disabled={Boolean(syncingCliTz)}
              onClick={onAction}
            >
              {syncingCliTz ? "Синхронизируем…" : "Синхронизировать редакторы"}
            </Button>
          </div>
          <div className="zs-check__tz-row">
            <div className="zs-check__tz-info">
              <p className="zs-check__tz-title">Часовой пояс системы</p>
              <p className="zs-check__tz-sub">
                {osTzStatus?.synced ? (
                  <>
                    Синхронизирован:{" "}
                    {osTzStatus.original_os_tz ? (
                      <>
                        <Mono>{osTzStatus.original_os_tz}</Mono>
                        {" → "}
                      </>
                    ) : null}
                    <Mono>{osTzStatus.synced_target_tz || osTzStatus.current_os_tz}</Mono>
                  </>
                ) : osTzStatus?.current_os_tz ? (
                  <>
                    Текущий пояс системы: <Mono>{osTzStatus.current_os_tz}</Mono>
                    {targetTz && osTzStatus.current_os_tz !== targetTz ? (
                      <>
                        {" · для IP: "}
                        <Mono>{targetTz}</Mono>
                      </>
                    ) : null}
                  </>
                ) : (
                  "Часовой пояс системы не синхронизирован"
                )}
              </p>
              {osTzError && (
                <p className="zs-check__tz-err" role="alert">
                  {osTzError}
                </p>
              )}
            </div>
            {osTzStatus?.synced ? (
              <Button
                size="sm"
                variant="secondary"
                disabled={Boolean(osTzLoading)}
                onClick={() => onRestoreOsTimezone?.()}
              >
                {osTzLoading ? "Возвращаем…" : "Вернуть пояс"}
              </Button>
            ) : (
              <Button
                size="sm"
                variant="secondary"
                disabled={Boolean(osTzLoading)}
                onClick={() => onSyncOsTimezone?.()}
              >
                {osTzLoading ? "Синхронизируем…" : "Синхронизировать пояс"}
              </Button>
            )}
          </div>
        </div>
      )}
      {(showGenericAction || showGuideLink || (item.cls === "unknown" && onRetry) || showNetworkSettings) && (
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
          {showGenericAction && item.action && (
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
