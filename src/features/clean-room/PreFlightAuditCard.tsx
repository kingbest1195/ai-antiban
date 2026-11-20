import { useCallback, useEffect, useState } from "react";
import type {
  CleanRoomAuditReport,
  CleanRoomFinding,
  CleanRoomFixAction,
  ProviderId,
} from "../../types";
import { cleanAppCache, runCleanRoomAudit, syncOsTimezone } from "../../utils/api";
import { Badge, Banner, Button, Card, EmptyState, InfoTip, Mono } from "../../ui";
import type { BadgeTone } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";
import { formatCountryWithCode } from "../../shared/lib/country";
import { CleanRoomRadarAnim } from "../mascot";
import type { RadarLayerItem, RadarLayerStatus } from "../mascot";

export interface PreFlightAuditCardProps {
  activeProfileId?: string | null;
  manualKillswitch?: boolean;
  /** Предзагруженный отчёт (синхронизируется с родителем и используется для SSR/тестов). */
  audit?: CleanRoomAuditReport | null;
  onAuditUpdated?: (report: CleanRoomAuditReport) => void;
  onNavigateToConnect?: () => void;
  onAcknowledgeIsolation?: () => void;
  onStateUpdated?: () => Promise<unknown> | void;
  toast?: ShowToast;
}

const SEVERITY_RANK: Record<CleanRoomFinding["severity"], number> = {
  critical: 0,
  warning: 1,
  ok: 2,
};

const SEVERITY_TONE: Record<CleanRoomFinding["severity"], BadgeTone> = {
  critical: "danger",
  warning: "warn",
  ok: "ok",
};

/** Hard Readiness Gate: запуск разрешён ТОЛЬКО при отсутствии critical и выключенном Kill-Switch. */
export function isCleanRoomReadyToLaunch(
  audit: CleanRoomAuditReport | null | undefined,
  manualKillswitch: boolean = false,
): boolean {
  if (manualKillswitch) return false;
  if (!audit) return false;
  return Boolean(audit.ready_to_launch && audit.critical_count === 0);
}

/** Сортирует находки детектора: critical -> warning -> ok. */
export function sortFindingsBySeverity(findings: readonly CleanRoomFinding[]): CleanRoomFinding[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

function layerStatusFromCategories(
  findings: readonly CleanRoomFinding[],
  categories: readonly string[],
  scanning: boolean,
): RadarLayerStatus {
  if (scanning) return "scanning";
  const matched = findings.filter((f) => categories.includes(f.category));
  if (matched.some((f) => f.severity === "critical")) return "critical";
  if (matched.some((f) => f.severity === "warning")) return "warn";
  if (matched.length > 0 || findings.length > 0) return "ok";
  return "pending";
}

/** Преобразует отчёт аудита в статусы 4 слоёв для CleanRoomRadarAnim. */
export function buildRadarLayers(
  audit: CleanRoomAuditReport | null | undefined,
  scanning: boolean,
): RadarLayerItem[] {
  const list = audit?.findings ?? [];
  return [
    { id: "browsers", label: "Браузеры", status: layerStatusFromCategories(list, ["browser"], scanning) },
    { id: "desktop", label: "Desktop / MSIX", status: layerStatusFromCategories(list, ["desktop_traces"], scanning) },
    {
      id: "network",
      label: "IP / DNS",
      status: layerStatusFromCategories(list, ["ip_collision", "network_leak"], scanning),
    },
    { id: "os_tz", label: "TZ / Locale", status: layerStatusFromCategories(list, ["os_tz_locale"], scanning) },
  ];
}

function fixButtonLabel(action: CleanRoomFixAction): string {
  switch (action.kind) {
    case "clean_app_cache":
      return copy.audit.fix.cleanCache(action.provider);
    case "sync_os_timezone":
      return copy.audit.fix.syncTz(action.target_iana);
    case "switch_route_or_vpn":
      return copy.audit.fix.switchRoute;
    case "close_running_app":
      return copy.audit.fix.closeApp(action.process_name);
    case "acknowledge_sandbox_isolation":
      return copy.audit.fix.ackIsolation;
  }
}

function toProviderId(raw: string): ProviderId | null {
  const lower = raw.toLowerCase();
  if (lower.includes("claude") || lower === "anthropic") return "anthropic";
  if (lower.includes("chatgpt") || lower === "openai") return "openai";
  if (lower.includes("gemini")) return "gemini";
  return null;
}

/** Карточка «Детектор хвостов» с CleanRoomRadarAnim, Hard Readiness Gate и 1-click fix действиями. */
export function PreFlightAuditCard({
  activeProfileId,
  manualKillswitch = false,
  audit: externalAudit,
  onAuditUpdated,
  onNavigateToConnect,
  onAcknowledgeIsolation,
  onStateUpdated,
  toast,
}: PreFlightAuditCardProps) {
  const [localAudit, setLocalAudit] = useState<CleanRoomAuditReport | null>(externalAudit ?? null);
  const [scanning, setScanning] = useState<boolean>(false);
  const [fixingId, setFixingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const audit = externalAudit !== undefined ? externalAudit : localAudit;

  const runScan = useCallback(async () => {
    setScanning(true);
    setError(null);
    try {
      const next = await runCleanRoomAudit(activeProfileId ?? undefined);
      setLocalAudit(next);
      onAuditUpdated?.(next);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      toast?.(copy.audit.toast.error, msg, "error");
    } finally {
      setScanning(false);
    }
  }, [activeProfileId, onAuditUpdated, toast]);

  useEffect(() => {
    if (externalAudit === undefined) {
      void runScan();
    }
  }, [activeProfileId, externalAudit, runScan]);

  const handleFix = async (finding: CleanRoomFinding) => {
    const action = finding.fix_action;
    if (!action || fixingId) return;
    setFixingId(finding.id);
    try {
      if (action.kind === "clean_app_cache") {
        const provider = toProviderId(action.provider) ?? "anthropic";
        const res = await cleanAppCache(provider);
        if (res.locked_targets && res.locked_targets.length > 0) {
          toast?.(copy.audit.toast.error, copy.audit.toast.cacheLocked(res.locked_targets), "warning");
        } else if (!res.found_dir || res.files_removed === 0) {
          toast?.(copy.audit.toast.cacheCleaned, copy.audit.toast.cacheCleanEmpty, "info");
        } else {
          toast?.(copy.audit.toast.cacheCleaned, res.message, "success");
        }
        await onStateUpdated?.();
        await runScan();
      } else if (action.kind === "sync_os_timezone") {
        await syncOsTimezone(action.target_iana);
        toast?.(copy.audit.toast.tzSynced, copy.audit.toast.tzSyncedText(action.target_iana), "success");
        await onStateUpdated?.();
        await runScan();
      } else if (action.kind === "switch_route_or_vpn") {
        onNavigateToConnect?.();
      } else if (action.kind === "close_running_app") {
        const provider = toProviderId(action.process_name);
        if (provider) {
          const res = await cleanAppCache(provider);
          if (res.locked_targets && res.locked_targets.length > 0) {
            toast?.(copy.audit.toast.error, copy.audit.toast.closeAppHint(action.process_name), "warning");
          } else {
            toast?.(copy.audit.toast.cacheCleaned, res.message, "success");
          }
          await onStateUpdated?.();
        } else {
          toast?.(copy.audit.fix.closeApp(action.process_name), copy.audit.toast.closeAppHint(action.process_name), "info");
        }
        await runScan();
      } else if (action.kind === "acknowledge_sandbox_isolation") {
        onAcknowledgeIsolation?.();
        toast?.(copy.audit.toast.isolationAck, copy.audit.toast.isolationAckText, "info");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast?.(copy.audit.toast.error, msg, "error");
    } finally {
      setFixingId(null);
    }
  };

  const ready = isCleanRoomReadyToLaunch(audit, manualKillswitch);
  const findings = audit ? sortFindingsBySeverity(audit.findings) : [];

  const gateBadge = manualKillswitch ? (
    <Badge tone="danger" icon="lock">
      {copy.audit.gate.blockedKillswitch}
    </Badge>
  ) : !audit ? (
    <Badge tone="neutral" busy={scanning}>
      {copy.audit.gate.pending}
    </Badge>
  ) : ready ? (
    <Badge tone="ok" icon="check">
      {copy.audit.gate.ready}
    </Badge>
  ) : (
    <Badge tone="danger" icon="alert">
      {copy.audit.gate.blockedCritical(audit.critical_count)}
    </Badge>
  );

  return (
    <Card
      title={
        <span className="cr-row-inline">
          <span>{copy.audit.title}</span>
          <InfoTip title={copy.audit.tips.readiness.title} text={copy.audit.tips.readiness.text} />
        </span>
      }
      aside={copy.audit.aside}
    >
      <div className="cr-row-between">
        {gateBadge}
        <Button size="sm" icon="refresh" disabled={scanning} onClick={() => void runScan()}>
          {scanning ? copy.audit.scanningBtn : copy.audit.scanBtn}
        </Button>
      </div>

      <div style={{ marginTop: "var(--space-3)" }}>
        <CleanRoomRadarAnim scanning={scanning} layers={buildRadarLayers(audit, scanning)} />
      </div>

      {error && (
        <div style={{ marginTop: "var(--space-3)" }}>
          <Banner tone="danger" role="alert" title={copy.audit.toast.error}>
            {error}
          </Banner>
        </div>
      )}

      {audit ? (
        <>
          <div className="cr-meta-grid">
            <div className="cr-meta-item">
              <span className="cr-meta-item__label">
                {copy.audit.meta.exitIp}
                <InfoTip title={copy.audit.tips.tainted.title} text={copy.audit.tips.tainted.text} />
              </span>
              <span className="cr-meta-item__value">
                <Mono>{audit.exit_ip ?? copy.audit.meta.unknown}</Mono>
              </span>
            </div>
            <div className="cr-meta-item">
              <span className="cr-meta-item__label">{copy.audit.meta.country}</span>
              <span className="cr-meta-item__value">
                {audit.exit_country ? formatCountryWithCode(audit.exit_country) : copy.audit.meta.unknown}
              </span>
            </div>
            <div className="cr-meta-item">
              <span className="cr-meta-item__label">
                {copy.audit.meta.timezone}
                <InfoTip title={copy.audit.tips.osTz.title} text={copy.audit.tips.osTz.text} />
              </span>
              <span className="cr-meta-item__value">
                <Mono>{audit.exit_timezone ?? copy.audit.meta.unknown}</Mono>
              </span>
            </div>
            <div className="cr-meta-item">
              <span className="cr-meta-item__label">{copy.audit.meta.osTz}</span>
              <span className="cr-meta-item__value">
                <Badge tone={audit.os_tz_matches_exit ? "ok" : "warn"} icon={audit.os_tz_matches_exit ? "check" : "alert"}>
                  {audit.os_tz_matches_exit ? copy.audit.meta.tzMatch : copy.audit.meta.tzMismatch}
                </Badge>
              </span>
            </div>
          </div>

          {audit.ip_is_tainted && (
            <Banner
              tone="danger"
              role="alert"
              title={copy.audit.taintedBannerTitle}
              action={
                onNavigateToConnect ? (
                  <Button size="sm" variant="secondary" onClick={onNavigateToConnect}>
                    {copy.audit.fix.switchRoute}
                  </Button>
                ) : undefined
              }
            >
              {copy.audit.taintedBannerText}
            </Banner>
          )}

          <ul className="cr-findings">
            {findings.map((finding) => (
              <li key={finding.id} className={`cr-finding cr-finding--${finding.severity}`}>
                <div className="cr-row-between">
                  <p className="cr-finding__title">{finding.title}</p>
                  <Badge
                    tone={SEVERITY_TONE[finding.severity]}
                    icon={finding.severity === "ok" ? "check" : "alert"}
                  >
                    {copy.audit.severity[finding.severity]}
                  </Badge>
                </div>
                <p className="cr-finding__detail">{finding.detail}</p>
                {finding.path_hint && <span className="cr-finding__path">{finding.path_hint}</span>}
                {finding.fix_action && (
                  <div>
                    <Button
                      size="sm"
                      variant={finding.severity === "critical" ? "danger" : "secondary"}
                      disabled={fixingId !== null}
                      onClick={() => void handleFix(finding)}
                    >
                      {fixingId === finding.id ? copy.audit.fix.fixing : fixButtonLabel(finding.fix_action)}
                    </Button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </>
      ) : (
        <EmptyState
          icon="shield"
          title={copy.audit.emptyTitle}
          description={copy.audit.emptyText}
          primaryAction={
            <Button variant="primary" disabled={scanning} onClick={() => void runScan()}>
              {copy.audit.scanBtn}
            </Button>
          }
        />
      )}
    </Card>
  );
}
