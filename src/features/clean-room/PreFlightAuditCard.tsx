import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  CleanRoomAuditReport,
  CleanRoomFinding,
  CleanRoomFixAction,
  CleanRoomState,
  ProviderId,
  RouteView,
} from "../../types";
import { cleanAppCache, runCleanRoomAudit, syncOsTimezone, untaintCleanRoomIp } from "../../utils/api";
import { Badge, Banner, Button, Card, EmptyState, ExpandRow, InfoTip, Mono, Rows, Select } from "../../ui";
import type { BadgeTone } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";
import { formatCountryWithCode, formatRouteOptionLabel } from "../../shared/lib/country";
import { formatIp, maskIpsInText } from "../../shared/lib/format";
import { CleanRoomRadarAnim } from "../mascot";
import { buildRadarLayers, isCleanRoomReadyToLaunch, sortFindingsBySeverity } from "./auditRadarModel";

export { buildRadarLayers, isCleanRoomReadyToLaunch, sortFindingsBySeverity };

const DIRECT_VALUE = "__direct__";

export interface PreFlightAuditCardProps {
  activeProfileId?: string | null;
  activeProfileRouteId?: string | null;
  routes?: readonly RouteView[];
  defaultRouteId?: string | null;
  taintedIps?: Record<string, number>;
  hideIpMode?: boolean;
  manualKillswitch?: boolean;
  /** Предзагруженный отчёт (синхронизируется с родителем и используется для SSR/тестов). */
  audit?: CleanRoomAuditReport | null;
  onAuditUpdated?: (report: CleanRoomAuditReport) => void;
  onTaintedStateUpdated?: (nextState: CleanRoomState) => Promise<unknown> | void;
  onNavigateToConnect?: () => void;
  onAcknowledgeIsolation?: () => void;
  onStateUpdated?: () => Promise<unknown> | void;
  toast?: ShowToast;
}

const SEVERITY_TONE: Record<CleanRoomFinding["severity"], BadgeTone> = {
  critical: "danger",
  warning: "warn",
  ok: "ok",
};

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

/** Карточка «Детектор хвостов» с CleanRoomRadarAnim, выбором маршрута и 1-click действиями. */
export function PreFlightAuditCard({
  activeProfileId,
  activeProfileRouteId,
  routes = [],
  defaultRouteId = null,
  taintedIps,
  hideIpMode = false,
  manualKillswitch = false,
  audit: externalAudit,
  onAuditUpdated,
  onTaintedStateUpdated,
  onNavigateToConnect,
  onAcknowledgeIsolation,
  onStateUpdated,
  toast,
}: PreFlightAuditCardProps) {
  const [localAudit, setLocalAudit] = useState<CleanRoomAuditReport | null>(externalAudit ?? null);
  const [scanning, setScanning] = useState<boolean>(false);
  const [fixingId, setFixingId] = useState<string | null>(null);
  const [untainting, setUntainting] = useState<boolean>(false);
  const [detailsOpen, setDetailsOpen] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [manualRouteChoice, setManualRouteChoice] = useState<string | null>(null);

  const audit = externalAudit !== undefined ? externalAudit : localAudit;

  const autoRouteId = useMemo(() => {
    if (activeProfileId && activeProfileRouteId) return activeProfileRouteId;
    if (activeProfileId && activeProfileRouteId === null) return DIRECT_VALUE;
    if (defaultRouteId && routes.some((r) => r.id === defaultRouteId && r.enabled)) return defaultRouteId;
    const firstEnabled = routes.find((r) => r.enabled);
    return firstEnabled?.id ?? DIRECT_VALUE;
  }, [activeProfileId, activeProfileRouteId, defaultRouteId, routes]);

  const effectiveRouteChoice = useMemo(() => {
    if (manualRouteChoice === DIRECT_VALUE) return DIRECT_VALUE;
    if (manualRouteChoice && routes.some((r) => r.id === manualRouteChoice)) return manualRouteChoice;
    return autoRouteId;
  }, [manualRouteChoice, routes, autoRouteId]);

  const resolvedRouteId = effectiveRouteChoice === DIRECT_VALUE ? null : effectiveRouteChoice;
  const routesSignature = useMemo(
    () => routes.map((r) => `${r.id}:${r.enabled}:${r.exit_ip ?? ""}`).join("|"),
    [routes],
  );
  const taintedSignature = useMemo(
    () => (taintedIps ? Object.keys(taintedIps).sort().join("|") : ""),
    [taintedIps],
  );

  useEffect(() => {
    setManualRouteChoice(null);
  }, [activeProfileId, activeProfileRouteId]);

  const scanSeqRef = useRef(0);

  const runScan = useCallback(async () => {
    const seq = ++scanSeqRef.current;
    setScanning(true);
    setError(null);
    try {
      const next = await runCleanRoomAudit(activeProfileId ?? null, resolvedRouteId);
      if (seq !== scanSeqRef.current) return;
      setLocalAudit(next);
      onAuditUpdated?.(next);
    } catch (err) {
      if (seq !== scanSeqRef.current) return;
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      toast?.(copy.audit.toast.error, msg, "error");
    } finally {
      if (seq === scanSeqRef.current) {
        setScanning(false);
      }
    }
  }, [activeProfileId, resolvedRouteId, onAuditUpdated, toast]);

  useEffect(() => {
    if (externalAudit === undefined) {
      void runScan();
    }
  }, [activeProfileId, resolvedRouteId, routesSignature, defaultRouteId, taintedSignature, externalAudit, runScan]);

  const handleUntaintCurrentIp = async () => {
    if (!audit?.exit_ip || untainting) return;
    setUntainting(true);
    try {
      const nextState = await untaintCleanRoomIp(audit.exit_ip);
      await onTaintedStateUpdated?.(nextState);
      toast?.(
        copy.audit.untaintToastTitle,
        copy.audit.untaintToastText(formatIp(audit.exit_ip, hideIpMode)),
        "success",
      );
      await onStateUpdated?.();
      await runScan();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast?.(copy.audit.toast.error, msg, "error");
    } finally {
      setUntainting(false);
    }
  };

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
  const rawFindings = audit ? sortFindingsBySeverity(audit.findings) : [];
  // Дедупликация (photo_348): если показан баннер tainted-IP, убираем дубль exit_ip_tainted из списка карточек.
  const findings = audit?.ip_is_tainted
    ? rawFindings.filter((f) => f.id !== "exit_ip_tainted" && f.id !== "ip_tainted")
    : rawFindings;

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
        <span className="cr-title-inline">
          <span>{copy.audit.title}</span>
          <InfoTip title={copy.audit.tips.readiness.title} text={copy.audit.tips.readiness.text} />
        </span>
      }
    >
      <p className="zs-t-caption cr-lead">{copy.audit.aside}</p>

      <div className="cr-row-between">
        {gateBadge}
        <Button size="sm" icon="refresh" disabled={scanning} onClick={() => void runScan()}>
          {scanning ? copy.audit.scanningBtn : copy.audit.scanBtn}
        </Button>
      </div>

      <div style={{ marginTop: "var(--space-3)" }}>
        <Select
          label={copy.audit.routeField}
          value={effectiveRouteChoice}
          onChange={(e) => setManualRouteChoice(e.target.value)}
          options={[
            ...routes.map((r) => ({
              value: r.id,
              label: formatRouteOptionLabel({
                label: r.label,
                country: r.country,
                ipOrHost: r.exit_ip ? formatIp(r.exit_ip, hideIpMode) : null,
              }),
            })),
            { value: DIRECT_VALUE, label: copy.audit.routeDirect },
          ]}
        />
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
                <Mono>{audit.exit_ip ? formatIp(audit.exit_ip, hideIpMode) : copy.audit.meta.unknown}</Mono>
              </span>
            </div>
            <div className="cr-meta-item">
              <span className="cr-meta-item__label">{copy.audit.meta.country}</span>
              <span className="cr-meta-item__value">
                {audit.exit_country ? formatCountryWithCode(audit.exit_country) : copy.audit.meta.unknown}
              </span>
            </div>
            <div className="cr-meta-item">
              <span className="cr-meta-item__label">{copy.audit.meta.timezone}</span>
              <span className="cr-meta-item__value">
                <Mono>{audit.exit_timezone ?? copy.audit.meta.unknown}</Mono>
              </span>
            </div>
            <div className="cr-meta-item">
              <span className="cr-meta-item__label">
                {copy.audit.meta.osTz}
                <InfoTip title={copy.audit.tips.osTz.title} text={copy.audit.tips.osTz.text} />
              </span>
              <span className="cr-meta-item__value">
                <Badge
                  tone={audit.os_tz_matches_exit || !audit.requires_os_sync ? "ok" : "warn"}
                  icon={audit.os_tz_matches_exit || !audit.requires_os_sync ? "check" : "alert"}
                >
                  {audit.os_tz_matches_exit
                    ? copy.audit.meta.tzMatch
                    : !audit.requires_os_sync
                      ? copy.audit.meta.tzAutoSandbox
                      : copy.audit.meta.tzMismatch}
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
                <div className="zs-banner__actions">
                  {onNavigateToConnect && (
                    <Button size="sm" variant="secondary" onClick={onNavigateToConnect}>
                      {copy.audit.fix.switchRoute}
                    </Button>
                  )}
                  {audit.exit_ip && (
                    <Button
                      size="sm"
                      variant="quiet"
                      disabled={untainting}
                      onClick={() => void handleUntaintCurrentIp()}
                    >
                      {untainting ? copy.audit.untaintingBtn : copy.audit.untaintBtn}
                    </Button>
                  )}
                </div>
              }
            >
              {copy.audit.taintedBannerText}
            </Banner>
          )}

          {findings.length > 0 && (() => {
            const listEl = (showPaths: boolean) => (
              <ul className="cr-findings">
                {findings.map((finding) => {
                  const isBenignBrowserNote =
                    finding.severity !== "critical" &&
                    (finding.id === "personal_browsers_present" ||
                      finding.id === "personal_browser_profiles" ||
                      finding.fix_action?.kind === "acknowledge_sandbox_isolation");
                  if (isBenignBrowserNote) {
                    return (
                      <li key={finding.id} className="cr-finding cr-finding--info">
                        <div className="cr-row-between">
                          <p className="cr-finding__title">{maskIpsInText(finding.title, hideIpMode)}</p>
                          <Badge tone="info" icon="info">
                            {copy.audit.severity.info}
                          </Badge>
                        </div>
                        <p className="cr-finding__detail">{copy.audit.personalBrowserNote}</p>
                      </li>
                    );
                  }
                  return (
                    <li key={finding.id} className={`cr-finding cr-finding--${finding.severity}`}>
                      <div className="cr-row-between">
                        <p className="cr-finding__title">{maskIpsInText(finding.title, hideIpMode)}</p>
                        <Badge
                          tone={SEVERITY_TONE[finding.severity]}
                          icon={finding.severity === "ok" ? "check" : "alert"}
                        >
                          {copy.audit.severity[finding.severity]}
                        </Badge>
                      </div>
                      <p className="cr-finding__detail">{maskIpsInText(finding.detail, hideIpMode)}</p>
                      {showPaths && finding.path_hint && (
                        <span className="cr-finding__path">{finding.path_hint}</span>
                      )}
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
                  );
                })}
              </ul>
            );
            if (ready) {
              return (
                <Rows className="cr-findings-collapse">
                  <ExpandRow
                    icon="info"
                    title={copy.audit.detailsTitle(findings.length)}
                    sub={copy.audit.detailsSub}
                    open={detailsOpen}
                    onToggle={() => setDetailsOpen((v) => !v)}
                  >
                    {listEl(true)}
                  </ExpandRow>
                </Rows>
              );
            }
            return listEl(false);
          })()}
        </>
      ) : (
        <EmptyState
          icon="shield"
          title={copy.audit.emptyTitle}
          description={copy.audit.emptyText}
          primaryAction={
            <Button variant="secondary" disabled={scanning} onClick={() => void runScan()}>
              {copy.audit.scanBtn}
            </Button>
          }
        />
      )}
    </Card>
  );
}
